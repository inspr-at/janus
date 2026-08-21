//! Private local subject registry and non-authorizing identity-shadow broker.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use fs2::FileExt;
use janus_core::{
    ActorObservationV1, ActorSubjectClass, ActorSubjectRef, IdentityBindingMigrationManifestV1,
    IdentityTransportManifestV1, JanusError, JanusResult, ScopeRef, TrustAdapterKind,
    ACTOR_OBSERVATION_SCHEMA, MAX_ACTOR_ASSERTION_TTL,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::time::timeout;

use crate::{
    denied_runtime_authority_reply, RoleBindingRegistry, RuntimeAuthorityBroker,
    RuntimeAuthorityRequestV1,
};

const SUBJECT_SCHEMA: u8 = 1;
const MAX_SUBJECT_RECORDS: usize = 4_096;
const MAX_REQUEST_BYTES: usize = 16 * 1024;
const STALE_SOCKET_PROBES: u32 = 10;
const STALE_SOCKET_PROBE_PAUSE: Duration = Duration::from_millis(50);

/// Private durable enrollment. The local UID never appears in public output.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SubjectEnrollmentV1 {
    schema_version: u8,
    subject_ref: String,
    subject_class: String,
    trust_adapter: String,
    trust_domain_fingerprint: String,
    local_uid: u32,
    enrolled_at_unix_secs: u64,
    review_fingerprint: String,
}

impl std::fmt::Debug for SubjectEnrollmentV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubjectEnrollmentV1")
            .field("subject_ref", &self.subject_ref)
            .field("subject_class", &self.subject_class)
            .field("trust_adapter", &self.trust_adapter)
            .field("trust_domain_fingerprint", &self.trust_domain_fingerprint)
            .field("local_uid", &"<redacted>")
            .field("enrolled_at_unix_secs", &self.enrolled_at_unix_secs)
            .field("review_fingerprint", &self.review_fingerprint)
            .finish()
    }
}

/// Immutable revocation record for an enrolled subject.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SubjectRevocationV1 {
    schema_version: u8,
    subject_ref: String,
    revoked_at_unix_secs: u64,
    review_fingerprint: String,
}

/// Value-free registry state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubjectRegistryStatus {
    Active,
    Revoked,
}

/// Value-free subject inventory entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubjectRegistryEntry {
    pub subject_ref: ActorSubjectRef,
    pub subject_class: ActorSubjectClass,
    pub status: SubjectRegistryStatus,
}

/// Strict private, append-only local accountable-subject registry.
#[derive(Clone, Debug)]
pub struct FileSubjectRegistry {
    root: PathBuf,
    trust_domain: String,
}

impl FileSubjectRegistry {
    pub fn new(root: impl Into<PathBuf>, trust_domain: impl Into<String>) -> Self {
        Self {
            root: root.into(),
            trust_domain: trust_domain.into(),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn trust_domain_fingerprint(&self) -> String {
        fingerprint(
            "janus-identity-trust-domain-v1",
            self.trust_domain.as_bytes(),
        )
    }

    /// Enroll one kernel identity after an operator-reviewed decision.
    pub fn enroll_local(
        &self,
        local_uid: u32,
        subject_class: ActorSubjectClass,
        review: &[u8],
        now: SystemTime,
    ) -> JanusResult<ActorSubjectRef> {
        if review.is_empty() || review.len() > 64 * 1024 {
            return Err(identity_error(
                "subject_review_invalid",
                "subject review evidence is invalid",
            ));
        }
        self.enroll_reviewed(
            local_uid,
            subject_class,
            &fingerprint("janus-subject-review-v1", review),
            now,
        )
    }

    /// Enroll with a precomputed review fingerprint (signed review evidence,
    /// JANUS-453). Evidence is single-use: a fingerprint already present in
    /// any enrollment or revocation record is rejected as replayed.
    pub(crate) fn enroll_reviewed(
        &self,
        local_uid: u32,
        subject_class: ActorSubjectClass,
        review_fingerprint: &str,
        now: SystemTime,
    ) -> JanusResult<ActorSubjectRef> {
        if !valid_sha256(review_fingerprint) {
            return Err(identity_error(
                "subject_review_invalid",
                "subject review fingerprint is invalid",
            ));
        }
        self.ensure_root()?;
        let _lock = self.lock()?;
        if self
            .review_fingerprints_unlocked()?
            .contains(review_fingerprint)
        {
            return Err(identity_error(
                "identity_review_replayed",
                "review evidence was already consumed",
            ));
        }
        if self.records_unlocked()?.into_values().any(|record| {
            record.local_uid == local_uid && record.entry.status == SubjectRegistryStatus::Active
        }) {
            return Err(identity_error(
                "subject_already_enrolled",
                "local subject is already enrolled",
            ));
        }
        let seed = random_bytes::<32>()?;
        let subject_ref = ActorSubjectRef::derive(
            TrustAdapterKind::LocalPeer,
            &self.trust_domain,
            &format!("enrollment:{}", hex::encode(seed)),
        )?;
        let record = SubjectEnrollmentV1 {
            schema_version: SUBJECT_SCHEMA,
            subject_ref: subject_ref.as_str().to_string(),
            subject_class: subject_class.as_str().to_string(),
            trust_adapter: TrustAdapterKind::LocalPeer.as_str().to_string(),
            trust_domain_fingerprint: fingerprint(
                "janus-identity-trust-domain-v1",
                self.trust_domain.as_bytes(),
            ),
            local_uid,
            enrolled_at_unix_secs: unix_secs(now)?,
            review_fingerprint: review_fingerprint.to_string(),
        };
        write_new_private_json(
            &self.enrollment_path(&subject_ref),
            &record,
            "subject enrollment",
        )?;
        Ok(subject_ref)
    }

    /// Add immutable revocation evidence. Re-enrollment can only mint a new ref.
    pub fn revoke(
        &self,
        subject_ref: &ActorSubjectRef,
        review: &[u8],
        now: SystemTime,
    ) -> JanusResult<()> {
        if review.is_empty() || review.len() > 64 * 1024 {
            return Err(identity_error(
                "subject_review_invalid",
                "subject review evidence is invalid",
            ));
        }
        self.revoke_reviewed(
            subject_ref,
            &fingerprint("janus-subject-revocation-review-v1", review),
            now,
        )
    }

    /// Revoke with a precomputed, single-use review fingerprint (JANUS-453).
    pub(crate) fn revoke_reviewed(
        &self,
        subject_ref: &ActorSubjectRef,
        review_fingerprint: &str,
        now: SystemTime,
    ) -> JanusResult<()> {
        if !valid_sha256(review_fingerprint) {
            return Err(identity_error(
                "subject_review_invalid",
                "subject review fingerprint is invalid",
            ));
        }
        self.ensure_root()?;
        let _lock = self.lock()?;
        if self
            .review_fingerprints_unlocked()?
            .contains(review_fingerprint)
        {
            return Err(identity_error(
                "identity_review_replayed",
                "review evidence was already consumed",
            ));
        }
        let record = self
            .records_unlocked()?
            .get(subject_ref.as_str())
            .map(|record| record.entry.clone())
            .ok_or_else(|| identity_error("subject_not_enrolled", "subject is not enrolled"))?;
        if record.status == SubjectRegistryStatus::Revoked {
            return Err(identity_error(
                "subject_already_revoked",
                "subject is already revoked",
            ));
        }
        let revocation = SubjectRevocationV1 {
            schema_version: SUBJECT_SCHEMA,
            subject_ref: subject_ref.as_str().to_string(),
            revoked_at_unix_secs: unix_secs(now)?,
            review_fingerprint: review_fingerprint.to_string(),
        };
        write_new_private_json(
            &self.revocation_path(subject_ref),
            &revocation,
            "subject revocation",
        )
    }

    pub fn get(&self, subject_ref: &ActorSubjectRef) -> JanusResult<SubjectRegistryEntry> {
        let records = self.records()?;
        records
            .get(subject_ref.as_str())
            .map(|record| record.entry.clone())
            .ok_or_else(|| identity_error("subject_not_enrolled", "subject is not enrolled"))
    }

    pub fn list(&self) -> JanusResult<Vec<SubjectRegistryEntry>> {
        Ok(self
            .records()?
            .into_values()
            .map(|record| record.entry)
            .collect())
    }

    /// Resolve only the kernel-observed UID; no request field participates.
    pub fn resolve_local_uid(&self, local_uid: u32) -> JanusResult<SubjectRegistryEntry> {
        let matches = self
            .records()?
            .into_values()
            .filter(|record| {
                record.local_uid == local_uid
                    && record.entry.status == SubjectRegistryStatus::Active
            })
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(identity_error(
                "subject_not_enrolled",
                "kernel peer subject is not uniquely enrolled",
            ));
        }
        Ok(matches[0].entry.clone())
    }

    fn enrollment_path(&self, subject_ref: &ActorSubjectRef) -> PathBuf {
        self.root.join(format!("{}.json", subject_ref.as_str()))
    }
    fn revocation_path(&self, subject_ref: &ActorSubjectRef) -> PathBuf {
        self.root
            .join(format!("{}.revoked.json", subject_ref.as_str()))
    }

    fn ensure_root(&self) -> JanusResult<()> {
        match fs::symlink_metadata(&self.root) {
            Ok(metadata) => validate_private_dir(&metadata),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir_all(&self.root)
                    .map_err(|_| unavailable("subject registry unavailable"))?;
                fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700))
                    .map_err(|_| unavailable("subject registry permissions unavailable"))?;
                validate_private_dir(
                    &fs::symlink_metadata(&self.root)
                        .map_err(|_| unavailable("subject registry unavailable"))?,
                )
            }
            Err(_) => Err(unavailable("subject registry unavailable")),
        }
    }

    fn records(&self) -> JanusResult<BTreeMap<String, PrivateSubjectRecord>> {
        self.ensure_root()?;
        let _lock = self.lock()?;
        self.records_unlocked()
    }

    fn records_unlocked(&self) -> JanusResult<BTreeMap<String, PrivateSubjectRecord>> {
        let mut enrollments = BTreeMap::new();
        let mut revocations = BTreeMap::new();
        for (index, entry) in fs::read_dir(&self.root)
            .map_err(|_| unavailable("subject registry unavailable"))?
            .enumerate()
        {
            if index >= MAX_SUBJECT_RECORDS * 2 {
                return Err(unavailable("subject registry limit exceeded"));
            }
            let entry = entry.map_err(|_| unavailable("subject registry unavailable"))?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| unavailable("subject registry entry malformed"))?;
            if name == ".registry.lock" {
                validate_private_empty_file(&entry.path(), "subject registry lock")?;
            } else if let Some(raw) = name.strip_suffix(".revoked.json") {
                let subject_ref = ActorSubjectRef::from_opaque(raw.to_string())?;
                let record: SubjectRevocationV1 =
                    read_private_json(&entry.path(), "subject revocation")?;
                validate_revocation(&record, &subject_ref)?;
                if revocations.insert(raw.to_string(), record).is_some() {
                    return Err(unavailable("duplicate subject revocation"));
                }
            } else if let Some(raw) = name.strip_suffix(".json") {
                let subject_ref = ActorSubjectRef::from_opaque(raw.to_string())?;
                let record: SubjectEnrollmentV1 =
                    read_private_json(&entry.path(), "subject enrollment")?;
                validate_enrollment(&record, &subject_ref, &self.trust_domain)?;
                if enrollments.insert(raw.to_string(), record).is_some() {
                    return Err(unavailable("duplicate subject enrollment"));
                }
            } else {
                return Err(unavailable("subject registry contains unsupported entry"));
            }
        }
        if revocations.keys().any(|key| !enrollments.contains_key(key)) {
            return Err(identity_error(
                "subject_orphan_revocation",
                "subject registry contains orphan revocation",
            ));
        }
        let mut active_uids = BTreeSet::new();
        let records = enrollments
            .into_iter()
            .map(|(key, record)| {
                let status = if revocations.contains_key(&key) {
                    SubjectRegistryStatus::Revoked
                } else {
                    SubjectRegistryStatus::Active
                };
                if status == SubjectRegistryStatus::Active && !active_uids.insert(record.local_uid)
                {
                    return Err(identity_error(
                        "subject_uid_ambiguous",
                        "multiple active subjects share one kernel identity",
                    ));
                }
                Ok((
                    key,
                    PrivateSubjectRecord {
                        local_uid: record.local_uid,
                        entry: SubjectRegistryEntry {
                            subject_ref: ActorSubjectRef::from_opaque(record.subject_ref)?,
                            subject_class: ActorSubjectClass::parse(&record.subject_class)?,
                            status,
                        },
                    },
                ))
            })
            .collect::<JanusResult<BTreeMap<_, _>>>()?;
        Ok(records)
    }

    /// Every review fingerprint already consumed by an enrollment or a
    /// revocation. Used to make signed review evidence single-use.
    fn review_fingerprints_unlocked(&self) -> JanusResult<BTreeSet<String>> {
        let mut fingerprints = BTreeSet::new();
        for entry in
            fs::read_dir(&self.root).map_err(|_| unavailable("subject registry unavailable"))?
        {
            let entry = entry.map_err(|_| unavailable("subject registry unavailable"))?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| unavailable("subject registry entry malformed"))?;
            if name == ".registry.lock" || !name.ends_with(".json") {
                continue;
            }
            let record: serde_json::Value = read_private_json(&entry.path(), "subject record")?;
            if let Some(value) = record
                .get("review_fingerprint")
                .and_then(serde_json::Value::as_str)
            {
                fingerprints.insert(value.to_string());
            }
        }
        Ok(fingerprints)
    }

    fn lock(&self) -> JanusResult<File> {
        let path = self.root.join(".registry.lock");
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(crate::identity_admin::private_open_flags());
        let file = options
            .open(&path)
            .map_err(|_| unavailable("subject registry lock unavailable"))?;
        // Validate the opened descriptor, never the path again (TOCTOU).
        let metadata = file
            .metadata()
            .map_err(|_| unavailable("subject registry lock unavailable"))?;
        if !metadata.is_file()
            || metadata.len() != 0
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.uid() != crate::identity_admin::current_euid()
            || metadata.nlink() != 1
        {
            return Err(unavailable("subject registry lock invalid"));
        }
        file.lock_exclusive()
            .map_err(|_| unavailable("subject registry lock unavailable"))?;
        Ok(file)
    }
}

struct PrivateSubjectRecord {
    local_uid: u32,
    entry: SubjectRegistryEntry,
}

/// Client request intentionally contains no actor, UID, session, or principal field.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityShadowRequestV1 {
    pub schema_version: u8,
    pub scope_ref: String,
    pub surface: String,
}

/// Stable value-free broker reply.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityShadowReplyV1 {
    pub schema_version: u8,
    pub ok: bool,
    pub observation: Option<ActorObservationV1>,
    pub reason_code: Option<String>,
    pub authority: String,
    pub value_returned: bool,
}

/// Peer credentials captured from the connected Unix socket by the kernel.
#[derive(Clone, Copy, Debug)]
struct LocalPeerCredentials {
    uid: u32,
    gid: u32,
    pid: Option<i32>,
}

/// Broker-internal authenticated actor. Public consumers can name the type but
/// cannot construct or deserialize it; only the kernel-peer broker creates it.
pub struct BrokerAuthenticatedActorV1 {
    subject: SubjectRegistryEntry,
    scope: ScopeRef,
    release_digest: String,
    peer_binding_ref: String,
    channel_binding_ref: String,
}

impl std::fmt::Debug for BrokerAuthenticatedActorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerAuthenticatedActorV1")
            .field("subject_ref", &self.subject.subject_ref)
            .field("scope", &self.scope)
            .field("release_digest", &self.release_digest)
            .field("peer_binding_ref", &self.peer_binding_ref)
            .field("channel_binding_ref", &self.channel_binding_ref)
            .finish()
    }
}

impl BrokerAuthenticatedActorV1 {
    pub(crate) fn subject_ref(&self) -> &ActorSubjectRef {
        &self.subject.subject_ref
    }
    pub(crate) fn scope(&self) -> &ScopeRef {
        &self.scope
    }
    pub(crate) fn release_digest(&self) -> &str {
        &self.release_digest
    }

    #[cfg(test)]
    pub(crate) fn fixture(
        subject_ref: ActorSubjectRef,
        scope: ScopeRef,
        release_digest: &str,
    ) -> Self {
        Self {
            subject: SubjectRegistryEntry {
                subject_ref,
                subject_class: ActorSubjectClass::Human,
                status: SubjectRegistryStatus::Active,
            },
            scope,
            release_digest: release_digest.to_string(),
            peer_binding_ref: "pbr_fixture".to_string(),
            channel_binding_ref: "cbr_fixture".to_string(),
        }
    }
}

impl FileSubjectRegistry {
    pub(crate) fn authenticate_local_uid(
        &self,
        uid: u32,
        scope: ScopeRef,
        release_digest: &str,
        peer_binding_ref: String,
        channel_binding_ref: String,
    ) -> JanusResult<BrokerAuthenticatedActorV1> {
        Ok(BrokerAuthenticatedActorV1 {
            subject: self.resolve_local_uid(uid)?,
            scope,
            release_digest: release_digest.to_string(),
            peer_binding_ref,
            channel_binding_ref,
        })
    }
}

/// Non-authorizing local identity broker.
#[derive(Clone)]
pub struct IdentityShadowBroker {
    registry: FileSubjectRegistry,
    manifest: IdentityTransportManifestV1,
    signing_key: SigningKey,
    audience_fingerprint: String,
    release_digest: String,
    ttl: Duration,
    connection_budget: Arc<tokio::sync::Semaphore>,
    runtime_authority: Option<Arc<RuntimeAuthorityBroker>>,
}

impl IdentityShadowBroker {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        registry: FileSubjectRegistry,
        manifest: IdentityTransportManifestV1,
        signing_key: SigningKey,
        audience: &str,
        release_digest: String,
        ttl: Duration,
    ) -> JanusResult<Self> {
        if audience.is_empty()
            || ttl.is_zero()
            || ttl > MAX_ACTOR_ASSERTION_TTL
            || !valid_sha256(&release_digest)
        {
            return Err(identity_error(
                "identity_broker_config_invalid",
                "identity broker configuration is invalid",
            ));
        }
        Ok(Self {
            registry,
            manifest,
            signing_key,
            audience_fingerprint: fingerprint("janus-identity-audience-v1", audience.as_bytes()),
            release_digest,
            ttl,
            connection_budget: Arc::new(tokio::sync::Semaphore::new(64)),
            runtime_authority: None,
        })
    }

    /// Activate broker-owned authorization on the same authenticated socket.
    pub fn with_runtime_authority(
        mut self,
        authority: RuntimeAuthorityBroker,
    ) -> JanusResult<Self> {
        if authority.verifying_key() != self.signing_key.verifying_key() {
            return Err(identity_error(
                "runtime_authority_signer_mismatch",
                "runtime authority must share the configured broker identity",
            ));
        }
        self.runtime_authority = Some(Arc::new(authority));
        Ok(self)
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Serve requests forever. Each accepted channel gets a random binding and
    /// each request is reauthenticated and gets a fresh single-use nonce.
    pub async fn serve(self, listener: UnixListener) -> io::Result<()> {
        loop {
            let (stream, _) = listener.accept().await?;
            let Ok(permit) = self.connection_budget.clone().try_acquire_owned() else {
                drop(stream);
                continue;
            };
            let broker = self.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let _ = broker.serve_connection(stream).await;
            });
        }
    }

    pub async fn serve_connection(&self, stream: UnixStream) -> io::Result<()> {
        let peer = stream.peer_cred()?;
        let credentials = LocalPeerCredentials {
            uid: peer.uid(),
            gid: peer.gid(),
            pid: peer.pid(),
        };
        let channel_seed = random_bytes::<32>().map_err(janus_to_io)?;
        let channel_binding_ref =
            opaque_ref("cbr_", "janus-identity-channel-v1", &channel_seed, 12);
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        for _ in 0..1_024 {
            let frame =
                match timeout(Duration::from_secs(30), read_bounded_frame(&mut reader)).await {
                    Ok(Ok(Some(frame))) => frame,
                    Ok(Ok(None)) => return Ok(()),
                    Ok(Err(())) => {
                        let encoded = serde_json::to_vec(&denied_reply("identity_request_invalid"))
                            .map_err(io::Error::other)?;
                        writer.write_all(&encoded).await?;
                        writer.write_all(b"\n").await?;
                        return Ok(());
                    }
                    Err(_) => return Ok(()),
                };
            let is_runtime_authority = serde_json::from_slice::<serde_json::Value>(&frame)
                .ok()
                .and_then(|value| value.get("action").cloned())
                .is_some();
            let encoded = if is_runtime_authority {
                // Every denial answers with the specific value-free reason code
                // and is audited by the broker; a generic code is reserved for
                // the cases where no authority is attached or the frame never
                // became a request (JANUS-450).
                let reply = match self.runtime_authority.as_ref() {
                    None => denied_runtime_authority_reply("runtime_authority_request_denied"),
                    Some(authority) => {
                        match serde_json::from_slice::<RuntimeAuthorityRequestV1>(&frame) {
                            Err(_) => {
                                let reason_code = "runtime_authority_request_invalid";
                                match authority.record_unparsed_denial(reason_code) {
                                    Ok(()) => denied_runtime_authority_reply(reason_code),
                                    Err(_) => denied_runtime_authority_reply(
                                        "runtime_authority_unavailable",
                                    ),
                                }
                            }
                            Ok(request) => match authority.authorize_peer(
                                crate::authority::RuntimePeerCredentials {
                                    uid: credentials.uid,
                                    gid: credentials.gid,
                                    pid: credentials.pid,
                                },
                                &channel_binding_ref,
                                request,
                                SystemTime::now(),
                            ) {
                                Ok(reply) => reply,
                                Err(error) => denied_runtime_authority_reply(
                                    crate::authority::denial_reason_code(&error),
                                ),
                            },
                        }
                    }
                };
                serde_json::to_vec(&reply).map_err(io::Error::other)?
            } else {
                let reply = serde_json::from_slice::<IdentityShadowRequestV1>(&frame)
                    .map_err(|_| ())
                    .and_then(|request| {
                        self.observe(
                            credentials,
                            &channel_binding_ref,
                            request,
                            SystemTime::now(),
                        )
                        .map_err(|_| ())
                    })
                    .unwrap_or_else(|_| denied_reply("identity_request_denied"));
                serde_json::to_vec(&reply).map_err(io::Error::other)?
            };
            writer.write_all(&encoded).await?;
            writer.write_all(b"\n").await?;
        }
        Ok(())
    }

    fn observe(
        &self,
        peer: LocalPeerCredentials,
        channel_binding_ref: &str,
        request: IdentityShadowRequestV1,
        now: SystemTime,
    ) -> JanusResult<IdentityShadowReplyV1> {
        if request.schema_version != 1 {
            return Err(identity_error(
                "identity_request_invalid",
                "identity request schema is invalid",
            ));
        }
        let scope = ScopeRef::from_opaque(request.scope_ref)?;
        let surface = self.manifest.surface(&request.surface)?;
        if surface.adapter() != TrustAdapterKind::LocalPeer {
            return Err(identity_error(
                "identity_adapter_mismatch",
                "identity adapter is not locally supported",
            ));
        }
        let authenticated = BrokerAuthenticatedActorV1 {
            subject: self.registry.resolve_local_uid(peer.uid)?,
            scope: scope.clone(),
            release_digest: self.release_digest.clone(),
            peer_binding_ref: peer_binding_ref(peer),
            channel_binding_ref: channel_binding_ref.to_string(),
        };
        let issued_at = unix_secs(now)?;
        let expires_at = issued_at
            .checked_add(self.ttl.as_secs())
            .ok_or_else(|| unavailable("identity time overflow"))?;
        let random = random_bytes::<32>()?;
        let mut observation = ActorObservationV1 {
            schema_version: ACTOR_OBSERVATION_SCHEMA,
            observation_id: opaque_ref("obs_", "janus-identity-observation-v1", &random, 12),
            subject_ref: authenticated.subject.subject_ref.as_str().to_string(),
            subject_class: authenticated.subject.subject_class.as_str().to_string(),
            trust_adapter: TrustAdapterKind::LocalPeer.as_str().to_string(),
            scope_ref: scope.as_str().to_string(),
            surface: surface.surface().to_string(),
            transport: surface.transport().as_str().to_string(),
            peer_binding_ref: authenticated.peer_binding_ref,
            channel_binding_ref: authenticated.channel_binding_ref,
            issued_at_unix_secs: issued_at,
            expires_at_unix_secs: expires_at,
            nonce_ref: opaque_ref("nce_", "janus-identity-request-nonce-v1", &random, 12),
            audience_fingerprint: self.audience_fingerprint.clone(),
            release_digest: self.release_digest.clone(),
            posture: "identity_shadow_only".to_string(),
            authority: "none".to_string(),
            value_returned: false,
            signature: "0".repeat(128),
        };
        let signature = self.signing_key.sign(&observation.signing_bytes()?);
        observation.signature = hex::encode(signature.to_bytes());
        Ok(IdentityShadowReplyV1 {
            schema_version: 1,
            ok: true,
            observation: Some(observation),
            reason_code: None,
            authority: "none".to_string(),
            value_returned: false,
        })
    }
}

/// Verify shape, exact audience/release, signature, and freshness. This still
/// yields observation evidence only and grants no Janus authority.
pub fn verify_actor_observation(
    observation: &ActorObservationV1,
    verifying_key: &VerifyingKey,
    expected_audience: &str,
    expected_release_digest: &str,
    now: SystemTime,
) -> JanusResult<()> {
    observation.validate_shape()?;
    if observation.audience_fingerprint
        != fingerprint("janus-identity-audience-v1", expected_audience.as_bytes())
        || observation.release_digest != expected_release_digest
        || !observation.is_fresh_at(now)
    {
        return Err(identity_error(
            "actor_observation_context_mismatch",
            "actor observation context is invalid",
        ));
    }
    let bytes = hex::decode(&observation.signature).map_err(|_| {
        identity_error(
            "actor_observation_signature_invalid",
            "actor observation signature is invalid",
        )
    })?;
    let signature = Signature::from_slice(&bytes).map_err(|_| {
        identity_error(
            "actor_observation_signature_invalid",
            "actor observation signature is invalid",
        )
    })?;
    verifying_key
        .verify(&observation.signing_bytes()?, &signature)
        .map_err(|_| {
            identity_error(
                "actor_observation_signature_invalid",
                "actor observation signature is invalid",
            )
        })
}

/// Stateful verification boundary that consumes nonces exactly once.
pub struct IdentityObservationVerifier {
    manifest: IdentityTransportManifestV1,
    verifying_key: VerifyingKey,
    expected_audience: String,
    expected_release_digest: String,
    consumed_nonces: Mutex<BTreeMap<String, u64>>,
}

impl IdentityObservationVerifier {
    pub fn new(
        manifest: IdentityTransportManifestV1,
        verifying_key: VerifyingKey,
        expected_audience: impl Into<String>,
        expected_release_digest: impl Into<String>,
    ) -> JanusResult<Self> {
        let expected_audience = expected_audience.into();
        let expected_release_digest = expected_release_digest.into();
        if expected_audience.is_empty() || !valid_sha256(&expected_release_digest) {
            return Err(identity_error(
                "actor_verifier_config_invalid",
                "actor verifier configuration is invalid",
            ));
        }
        Ok(Self {
            manifest,
            verifying_key,
            expected_audience,
            expected_release_digest,
            consumed_nonces: Mutex::new(BTreeMap::new()),
        })
    }

    /// Verify the full context and consume the request nonce. Replay, stale
    /// release/audience, unknown surface, and adapter/transport substitution
    /// all fail closed.
    pub fn verify_once(
        &self,
        observation: &ActorObservationV1,
        now: SystemTime,
    ) -> JanusResult<ActorSubjectRef> {
        verify_actor_observation(
            observation,
            &self.verifying_key,
            &self.expected_audience,
            &self.expected_release_digest,
            now,
        )?;
        let surface = self.manifest.surface(&observation.surface)?;
        if surface.adapter().as_str() != observation.trust_adapter
            || surface.transport().as_str() != observation.transport
        {
            return Err(identity_error(
                "actor_observation_surface_mismatch",
                "actor observation surface context is invalid",
            ));
        }
        let now_secs = unix_secs(now)?;
        let mut consumed = self
            .consumed_nonces
            .lock()
            .map_err(|_| unavailable("actor replay cache unavailable"))?;
        consumed.retain(|_, expiry| *expiry > now_secs);
        if consumed.contains_key(&observation.nonce_ref) || consumed.len() >= 65_536 {
            return Err(identity_error(
                "actor_observation_replay_denied",
                "actor observation nonce is not admissible",
            ));
        }
        consumed.insert(
            observation.nonce_ref.clone(),
            observation.expires_at_unix_secs,
        );
        observation.actor_subject_ref()
    }
}

/// Create or load a private raw Ed25519 broker key without exposing its bytes.
pub fn load_or_create_identity_signing_key(path: &Path) -> JanusResult<SigningKey> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            let bytes = read_private_bytes(path, "identity signing key", 32)?;
            let raw: [u8; 32] = bytes
                .try_into()
                .map_err(|_| unavailable("identity signing key malformed"))?;
            Ok(SigningKey::from_bytes(&raw))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .ok_or_else(|| unavailable("identity signing key path invalid"))?;
            ensure_private_directory(parent)?;
            let key = SigningKey::from_bytes(&random_bytes::<32>()?);
            write_new_private_bytes(path, &key.to_bytes(), "identity signing key")?;
            Ok(key)
        }
        Err(_) => Err(unavailable("identity signing key unavailable")),
    }
}

/// Bind one new private identity socket; occupied paths fail closed.
/// Bind the private identity socket. An absent path binds directly. A socket
/// file left behind by a previous broker (sidecar torn down, host crash) is
/// reclaimed only when it is a real socket, owned like its private parent, and
/// refuses connections. A live broker, symlink, non-socket entry, or foreign
/// owner fails closed with `identity_socket_occupied` (JANUS-451).
pub fn bind_private_identity_socket(path: &Path) -> JanusResult<UnixListener> {
    let parent = path
        .parent()
        .ok_or_else(|| unavailable("identity socket path invalid"))?;
    ensure_private_directory(parent)?;
    if let Ok(existing) = fs::symlink_metadata(path) {
        reclaim_dead_identity_socket(path, parent, &existing)?;
    }
    let listener =
        UnixListener::bind(path).map_err(|_| unavailable("identity socket bind failed"))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|_| unavailable("identity socket permissions failed"))?;
    Ok(listener)
}

fn reclaim_dead_identity_socket(
    path: &Path,
    parent: &Path,
    existing: &fs::Metadata,
) -> JanusResult<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let occupied = |detail: &'static str| identity_error("identity_socket_occupied", detail);
    if existing.file_type().is_symlink() || !existing.file_type().is_socket() {
        return Err(occupied(
            "identity socket path is occupied by a non-socket entry",
        ));
    }
    let parent_metadata = fs::symlink_metadata(parent)
        .map_err(|_| unavailable("private identity directory unavailable"))?;
    if existing.uid() != parent_metadata.uid() {
        return Err(occupied("identity socket path is owned by another user"));
    }
    // A broker that just exited can leave a socket the kernel still reports as
    // connectable for a moment; a live broker stays connectable. Probe a few
    // times with short pauses and reclaim on the first refusal, so a
    // restart-immediately lifecycle does not fail closed on a dying predecessor.
    for attempt in 0..STALE_SOCKET_PROBES {
        match std::os::unix::net::UnixStream::connect(path) {
            Ok(_) if attempt + 1 < STALE_SOCKET_PROBES => {
                std::thread::sleep(STALE_SOCKET_PROBE_PAUSE);
            }
            Ok(_) => return Err(occupied("identity socket is served by a live broker")),
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                return fs::remove_file(path)
                    .map_err(|_| unavailable("stale identity socket removal failed"));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(occupied("identity socket liveness could not be determined")),
        }
    }
    Err(occupied("identity socket is served by a live broker"))
}

/// Remove the broker's socket on shutdown. Only a socket is removed; a file
/// another process placed at the path is left untouched.
pub fn unlink_identity_socket(path: &Path) {
    use std::os::unix::fs::FileTypeExt;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_socket() && !metadata.file_type().is_symlink() {
            let _ = fs::remove_file(path);
        }
    }
}

/// Value-free migration preflight result. It never mutates role bindings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IdentityBindingMigrationPreflightV1 {
    pub schema_version: u8,
    pub migration_id: String,
    pub manifest_fingerprint: String,
    pub mapping_count: usize,
    pub posture: String,
    pub authority_imported: bool,
    pub value_returned: bool,
}

pub fn preflight_identity_binding_migration(
    manifest: &IdentityBindingMigrationManifestV1,
    subjects: &FileSubjectRegistry,
    roles: &dyn RoleBindingRegistry,
) -> JanusResult<IdentityBindingMigrationPreflightV1> {
    if manifest.trust_domain_fingerprint() != subjects.trust_domain_fingerprint() {
        return Err(identity_error(
            "identity_migration_trust_domain_mismatch",
            "migration trust domain does not match the subject registry",
        ));
    }
    let bindings = roles.bindings()?;
    if bindings.len() != manifest.mappings().len() {
        return Err(identity_error(
            "identity_migration_incomplete",
            "migration must map every current role binding exactly once",
        ));
    }
    let by_id = bindings
        .iter()
        .map(|binding| (binding.id().as_str(), binding))
        .collect::<BTreeMap<_, _>>();
    for mapping in manifest.mappings() {
        let binding = by_id.get(mapping.binding_id.as_str()).ok_or_else(|| {
            identity_error(
                "identity_migration_binding_unknown",
                "migration references an unknown role binding",
            )
        })?;
        let subject = subjects.get(&mapping.subject_ref)?;
        if subject.status != SubjectRegistryStatus::Active
            || technical_binding_fingerprint(binding.principal_binding())
                != mapping.technical_binding_fingerprint
        {
            return Err(identity_error(
                "identity_migration_mapping_denied",
                "migration mapping is inactive or mismatched",
            ));
        }
    }
    Ok(IdentityBindingMigrationPreflightV1 {
        schema_version: 1,
        migration_id: manifest.migration_id().to_string(),
        manifest_fingerprint: manifest.fingerprint().to_string(),
        mapping_count: manifest.mappings().len(),
        posture: "identity_shadow_only".to_string(),
        authority_imported: false,
        value_returned: false,
    })
}

pub fn technical_binding_fingerprint(principal_binding: &str) -> String {
    fingerprint(
        "janus-identity-technical-binding-v1",
        principal_binding.as_bytes(),
    )
}

fn validate_enrollment(
    record: &SubjectEnrollmentV1,
    expected: &ActorSubjectRef,
    trust_domain: &str,
) -> JanusResult<()> {
    if record.schema_version != SUBJECT_SCHEMA
        || record.subject_ref != expected.as_str()
        || ActorSubjectClass::parse(&record.subject_class).is_err()
        || record.trust_adapter != TrustAdapterKind::LocalPeer.as_str()
        || record.trust_domain_fingerprint
            != fingerprint("janus-identity-trust-domain-v1", trust_domain.as_bytes())
        || !valid_sha256(&record.review_fingerprint)
    {
        return Err(identity_error(
            "subject_enrollment_malformed",
            "subject enrollment is malformed",
        ));
    }
    Ok(())
}

fn validate_revocation(
    record: &SubjectRevocationV1,
    expected: &ActorSubjectRef,
) -> JanusResult<()> {
    if record.schema_version != SUBJECT_SCHEMA
        || record.subject_ref != expected.as_str()
        || !valid_sha256(&record.review_fingerprint)
    {
        return Err(identity_error(
            "subject_revocation_malformed",
            "subject revocation is malformed",
        ));
    }
    Ok(())
}

fn validate_private_dir(metadata: &fs::Metadata) -> JanusResult<()> {
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != crate::identity_admin::current_euid()
    {
        return Err(unavailable("private identity directory invalid"));
    }
    Ok(())
}

fn ensure_private_directory(path: &Path) -> JanusResult<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_private_dir(&metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(path)
                .map_err(|_| unavailable("private identity directory unavailable"))?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .map_err(|_| unavailable("private identity directory permissions unavailable"))?;
            validate_private_dir(
                &fs::symlink_metadata(path)
                    .map_err(|_| unavailable("private identity directory unavailable"))?,
            )
        }
        Err(_) => Err(unavailable("private identity directory unavailable")),
    }
}

fn read_private_json<T: for<'de> Deserialize<'de>>(
    path: &Path,
    kind: &'static str,
) -> JanusResult<T> {
    let bytes = read_private_bytes(path, kind, 128 * 1024)?;
    serde_json::from_slice(&bytes).map_err(|_| unavailable(format!("{kind} malformed")))
}

fn read_private_bytes(path: &Path, kind: &'static str, maximum: usize) -> JanusResult<Vec<u8>> {
    // Open without following symlinks and validate the descriptor (fstat), so
    // the file that is read is the file that was checked.
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(crate::identity_admin::private_open_flags());
    let mut file = options
        .open(path)
        .map_err(|_| unavailable(format!("{kind} unavailable")))?;
    let metadata = file
        .metadata()
        .map_err(|_| unavailable(format!("{kind} unavailable")))?;
    if !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > maximum as u64
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != crate::identity_admin::current_euid()
        || metadata.nlink() != 1
    {
        return Err(unavailable(format!("{kind} invalid")));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|_| unavailable(format!("{kind} unavailable")))?;
    Ok(bytes)
}

fn validate_private_empty_file(path: &Path, kind: &'static str) -> JanusResult<()> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| unavailable(format!("{kind} unavailable")))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() != 0
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != crate::identity_admin::current_euid()
    {
        return Err(unavailable(format!("{kind} invalid")));
    }
    Ok(())
}

fn write_new_private_json<T: Serialize>(
    path: &Path,
    value: &T,
    kind: &'static str,
) -> JanusResult<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| unavailable(format!("{kind} malformed")))?;
    write_new_private_bytes(path, &bytes, kind)
}

fn write_new_private_bytes(path: &Path, bytes: &[u8], kind: &'static str) -> JanusResult<()> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(crate::identity_admin::private_open_flags());
    let mut file = options
        .open(path)
        .map_err(|_| unavailable(format!("{kind} already exists or is unavailable")))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| unavailable(format!("{kind} persistence failed")))?;
    // The directory entry must be durable too, not only the file contents.
    let parent = path
        .parent()
        .ok_or_else(|| unavailable(format!("{kind} path invalid")))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| unavailable(format!("{kind} directory persistence failed")))
}

pub(crate) fn random_bytes<const N: usize>() -> JanusResult<[u8; N]> {
    let mut bytes = [0u8; N];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|_| unavailable("operating system randomness unavailable"))?;
    Ok(bytes)
}

fn peer_binding_ref(peer: LocalPeerCredentials) -> String {
    let mut bytes = Vec::with_capacity(12);
    bytes.extend_from_slice(&peer.uid.to_be_bytes());
    bytes.extend_from_slice(&peer.gid.to_be_bytes());
    bytes.extend_from_slice(&peer.pid.unwrap_or_default().to_be_bytes());
    opaque_ref("pbr_", "janus-identity-peer-binding-v1", &bytes, 12)
}

pub(crate) fn opaque_ref(prefix: &str, domain: &str, bytes: &[u8], length: usize) -> String {
    let digest = digest(domain, bytes);
    format!("{prefix}{}", hex::encode(&digest[..length]))
}

pub(crate) fn fingerprint(domain: &str, bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(digest(domain, bytes)))
}

fn digest(domain: &str, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain.as_bytes());
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

fn valid_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|suffix| {
        suffix.len() == 64
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

pub(crate) fn unix_secs(time: SystemTime) -> JanusResult<u64> {
    time.duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| unavailable("identity time invalid"))
}

fn denied_reply(reason: &str) -> IdentityShadowReplyV1 {
    IdentityShadowReplyV1 {
        schema_version: 1,
        ok: false,
        observation: None,
        reason_code: Some(reason.to_string()),
        authority: "none".to_string(),
        value_returned: false,
    }
}

async fn read_bounded_frame<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
) -> Result<Option<Vec<u8>>, ()> {
    let mut frame = Vec::new();
    loop {
        let available = reader.fill_buf().await.map_err(|_| ())?;
        if available.is_empty() {
            return if frame.is_empty() { Ok(None) } else { Err(()) };
        }
        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        if frame.len().saturating_add(take) > MAX_REQUEST_BYTES {
            return Err(());
        }
        frame.extend_from_slice(&available[..take]);
        reader.consume(take);
        if frame.ends_with(b"\n") {
            return Ok(Some(frame));
        }
    }
}

fn identity_error(reason_code: &'static str, detail: impl Into<String>) -> JanusError {
    JanusError::policy_denied(reason_code, detail)
}

fn unavailable(detail: impl Into<String>) -> JanusError {
    JanusError::policy_denied("identity_foundation_unavailable", detail)
}

fn janus_to_io(error: JanusError) -> io::Error {
    io::Error::other(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::sync::{Arc, Barrier};

    use janus_core::{
        EnvironmentId, OrganizationId, ProjectId, RepositoryId, Role, RoleBinding,
        RoleBindingSource, RoleBindingSourceKind, ScopePathV1,
    };
    use tempfile::TempDir;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    use crate::FileRoleBindingRegistry;

    fn private_tempdir() -> TempDir {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    fn reason_of(error: JanusError) -> String {
        match error {
            JanusError::PolicyDenied { reason_code, .. } => reason_code.to_string(),
            other => format!("{other}"),
        }
    }

    #[tokio::test]
    async fn bind_takes_over_only_dead_sockets_and_fails_closed_otherwise() {
        let directory = private_tempdir();
        let socket = directory.path().join("identity.sock");

        // A fresh path binds; a dead leftover from a previous broker is reclaimed.
        drop(bind_private_identity_socket(&socket).unwrap());
        assert!(
            socket.exists(),
            "socket file must outlive the listener here"
        );
        let reclaimed = bind_private_identity_socket(&socket).unwrap();

        // A live broker is never displaced.
        let occupied = bind_private_identity_socket(&socket).unwrap_err();
        assert_eq!(reason_of(occupied), "identity_socket_occupied");
        assert!(socket.exists());
        drop(reclaimed);

        // Non-socket entries are never removed.
        let regular = directory.path().join("regular.sock");
        fs::write(&regular, b"not a socket").unwrap();
        assert_eq!(
            reason_of(bind_private_identity_socket(&regular).unwrap_err()),
            "identity_socket_occupied"
        );
        assert!(regular.exists());

        let target = directory.path().join("target");
        fs::write(&target, b"").unwrap();
        let link = directory.path().join("link.sock");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(
            reason_of(bind_private_identity_socket(&link).unwrap_err()),
            "identity_socket_occupied"
        );
        assert!(link.exists() && target.exists());

        // Shutdown cleanup removes only a socket.
        unlink_identity_socket(&socket);
        assert!(!socket.exists());
        unlink_identity_socket(&regular);
        assert!(regular.exists());
    }

    fn scope() -> ScopeRef {
        ScopePathV1::new(
            OrganizationId::new("fixture-org").unwrap(),
            ProjectId::new("janus").unwrap(),
            RepositoryId::new("janus").unwrap(),
            EnvironmentId::new("test").unwrap(),
        )
        .scope_ref()
    }

    fn current_uid() -> u32 {
        String::from_utf8(Command::new("id").arg("-u").output().unwrap().stdout)
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    }

    fn manifest() -> IdentityTransportManifestV1 {
        IdentityTransportManifestV1::parse_json(include_str!(
            "../../../config/identity/transport-manifest-v1.json"
        ))
        .unwrap()
    }

    #[test]
    fn registry_is_immutable_private_and_never_reuses_revoked_refs() {
        let temp = TempDir::new().unwrap();
        let registry = FileSubjectRegistry::new(temp.path().join("subjects"), "fixture-host");
        let first = registry
            .enroll_local(
                501,
                ActorSubjectClass::Human,
                b"review-one",
                SystemTime::now(),
            )
            .unwrap();
        assert_eq!(registry.resolve_local_uid(501).unwrap().subject_ref, first);
        let public_debug = format!("{:?}", registry.list().unwrap());
        assert!(!public_debug.contains("local_uid"));
        let private: SubjectEnrollmentV1 =
            read_private_json(&registry.enrollment_path(&first), "subject enrollment").unwrap();
        assert!(format!("{private:?}").contains("local_uid: \"<redacted>\""));
        assert!(registry
            .enroll_local(
                501,
                ActorSubjectClass::Human,
                b"duplicate",
                SystemTime::now()
            )
            .is_err());
        registry
            .revoke(&first, b"review-revoke", SystemTime::now())
            .unwrap();
        assert!(registry.resolve_local_uid(501).is_err());
        let second = registry
            .enroll_local(
                501,
                ActorSubjectClass::Human,
                b"review-two",
                SystemTime::now(),
            )
            .unwrap();
        assert_ne!(first, second);
        assert_eq!(registry.list().unwrap().len(), 2);

        let record = registry.enrollment_path(&second);
        fs::set_permissions(&record, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(registry.list().is_err());
    }

    #[test]
    fn distinct_kernel_subjects_are_distinct_and_shared_accounts_are_not_split() {
        let temp = TempDir::new().unwrap();
        let registry = FileSubjectRegistry::new(temp.path().join("subjects"), "fixture-host");
        let left = registry
            .enroll_local(
                1001,
                ActorSubjectClass::Human,
                b"review-left",
                SystemTime::now(),
            )
            .unwrap();
        let right = registry
            .enroll_local(
                1002,
                ActorSubjectClass::Human,
                b"review-right",
                SystemTime::now(),
            )
            .unwrap();
        assert_ne!(left, right);
        assert_eq!(registry.resolve_local_uid(1001).unwrap().subject_ref, left);
        assert!(registry
            .enroll_local(
                1001,
                ActorSubjectClass::Workload,
                b"alias",
                SystemTime::now()
            )
            .is_err());
    }

    #[test]
    fn concurrent_enrollment_cannot_create_two_active_refs_for_one_uid() {
        let temp = TempDir::new().unwrap();
        let registry = Arc::new(FileSubjectRegistry::new(
            temp.path().join("subjects"),
            "fixture-host",
        ));
        let barrier = Arc::new(Barrier::new(3));
        let handles = (0..2)
            .map(|index| {
                let registry = registry.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    registry.enroll_local(
                        1501,
                        ActorSubjectClass::Human,
                        format!("review-{index}").as_bytes(),
                        SystemTime::now(),
                    )
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        let outcomes = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
        assert_eq!(registry.list().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn broker_uses_connected_peer_reauthenticates_and_signs_value_free_observations() {
        let temp = TempDir::new().unwrap();
        let registry = FileSubjectRegistry::new(temp.path().join("subjects"), "fixture-host");
        let subject = registry
            .enroll_local(
                current_uid(),
                ActorSubjectClass::Human,
                b"review",
                SystemTime::now(),
            )
            .unwrap();
        let signing_key = SigningKey::from_bytes(&[9; 32]);
        let verifying_key = signing_key.verifying_key();
        let release = format!("sha256:{}", "a".repeat(64));
        let broker = IdentityShadowBroker::new(
            registry.clone(),
            manifest(),
            signing_key,
            "fixture-audience",
            release.clone(),
            Duration::from_secs(60),
        )
        .unwrap();
        let socket = temp.path().join("broker/identity.sock");
        let listener = bind_private_identity_socket(&socket).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            broker.serve_connection(stream).await.unwrap();
        });
        let stream = UnixStream::connect(&socket).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let request = IdentityShadowRequestV1 {
            schema_version: 1,
            scope_ref: scope().as_str().to_string(),
            surface: "janusd-use".to_string(),
        };
        let encoded = serde_json::to_vec(&request).unwrap();
        writer.write_all(&encoded).await.unwrap();
        writer.write_all(b"\n").await.unwrap();
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let first: IdentityShadowReplyV1 = serde_json::from_str(&line).unwrap();
        let first_observation = first.observation.unwrap();
        assert_eq!(first_observation.subject_ref, subject.as_str());
        assert_eq!(first_observation.authority, "none");
        assert!(!first_observation.value_returned);
        verify_actor_observation(
            &first_observation,
            &verifying_key,
            "fixture-audience",
            &release,
            SystemTime::now(),
        )
        .unwrap();
        let verifier = IdentityObservationVerifier::new(
            manifest(),
            verifying_key,
            "fixture-audience",
            release.clone(),
        )
        .unwrap();
        assert_eq!(
            verifier
                .verify_once(&first_observation, SystemTime::now())
                .unwrap(),
            subject
        );
        assert!(verifier
            .verify_once(&first_observation, SystemTime::now())
            .is_err());

        writer.write_all(&encoded).await.unwrap();
        writer.write_all(b"\n").await.unwrap();
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        let second: IdentityShadowReplyV1 = serde_json::from_str(&line).unwrap();
        let second_observation = second.observation.unwrap();
        assert_eq!(
            first_observation.subject_ref,
            second_observation.subject_ref
        );
        assert_ne!(first_observation.nonce_ref, second_observation.nonce_ref);
        assert_eq!(
            first_observation.channel_binding_ref,
            second_observation.channel_binding_ref
        );

        let mut copied = second_observation.clone();
        copied.surface = "janusd-admin".to_string();
        assert!(verify_actor_observation(
            &copied,
            &verifying_key,
            "fixture-audience",
            &release,
            SystemTime::now()
        )
        .is_err());

        registry
            .revoke(&subject, b"review revoke", SystemTime::now())
            .unwrap();
        writer.write_all(&encoded).await.unwrap();
        writer.write_all(b"\n").await.unwrap();
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        let denied: IdentityShadowReplyV1 = serde_json::from_str(&line).unwrap();
        assert!(!denied.ok);
        assert!(denied.observation.is_none());
        assert_eq!(denied.authority, "none");
        drop(writer);
        drop(reader);
        server.await.unwrap();
    }

    #[test]
    fn migration_preflight_is_exact_value_free_and_imports_no_authority() {
        let temp = TempDir::new().unwrap();
        let subjects = FileSubjectRegistry::new(temp.path().join("subjects"), "fixture-host");
        let subject = subjects
            .enroll_local(501, ActorSubjectClass::Human, b"review", SystemTime::now())
            .unwrap();
        let roles = FileRoleBindingRegistry::new(temp.path().join("roles"));
        let now = SystemTime::now();
        let binding = RoleBinding::issue(
            "legacy-principal",
            scope(),
            Role::Approver,
            None,
            now,
            now + Duration::from_secs(600),
            RoleBindingSource::new(RoleBindingSourceKind::LocalReviewed, "review-source").unwrap(),
        )
        .unwrap();
        roles.store(&binding).unwrap();
        let text = serde_json::json!({
            "schema_version": 1,
            "migration_id": "idm_111111111111111111111111",
            "trust_domain_fingerprint": subjects.trust_domain_fingerprint(),
            "mappings": [{
                "binding_id": binding.id().as_str(),
                "subject_ref": subject.as_str(),
                "technical_binding_fingerprint": technical_binding_fingerprint(binding.principal_binding())
            }]
        }).to_string();
        let manifest = IdentityBindingMigrationManifestV1::parse_json(&text).unwrap();
        let result = preflight_identity_binding_migration(&manifest, &subjects, &roles).unwrap();
        assert_eq!(result.posture, "identity_shadow_only");
        assert!(!result.authority_imported);
        assert!(!result.value_returned);
        let stored = roles.bindings().unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].id(), binding.id());
    }
}
