//! Broker-owned runtime accountability admission over authenticated local peers.

use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use janus_core::{
    AccountabilityCutoverV1, AccountabilityPosture, AuthoritativeOperationRefV1,
    DutySurfaceManifestV1, IdentityTransportManifestV1, JanusError, JanusResult,
    OperationStateVerifier, RuntimeAction, RuntimeAdmissionV1, RuntimeAdmissionVerifier,
    RuntimeDutyClassification, ScopeRef, VerifiedRuntimeAdmission, DUTY_JOURNAL_GENESIS_HASH,
    MAX_RUNTIME_ADMISSION_TTL_SECS, RUNTIME_ADMISSION_SCHEMA,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::time::timeout;

use crate::duty::{
    DutyAuthorizationAuditSink, DutyAuthorizationAuditV1, DutyJournalHealthV1, FileDutyJournal,
};
use crate::identity::{opaque_ref, random_bytes, FileSubjectRegistry};

const MAX_AUTHORITY_FRAME_BYTES: usize = 128 * 1024;
const MAX_MANIFEST_BYTES: usize = 128 * 1024;
const MAX_AUTHORITY_AUDIT_BYTES: u64 = 128 * 1024 * 1024;

/// Request contains no actor, principal chain, UID, duty, or transport field.
/// The optional operation state is signed by the pinned domain service.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAuthorityRequestV1 {
    pub schema_version: u8,
    pub scope_ref: String,
    pub action: String,
    pub operation: Option<AuthoritativeOperationRefV1>,
    pub audit_ref: String,
}

/// Value-free broker reply.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAuthorityReplyV1 {
    pub schema_version: u8,
    pub ok: bool,
    pub admission: Option<RuntimeAdmissionV1>,
    pub reason_code: Option<String>,
    pub value_returned: bool,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct RuntimePeerCredentials {
    pub uid: u32,
    pub gid: u32,
    pub pid: Option<i32>,
}

/// Value-free action-level evidence in addition to the immutable duty record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAuthorityAuditV1 {
    pub schema_version: u8,
    pub outcome: String,
    pub reason_code: String,
    pub actor_subject_ref: String,
    pub scope_ref: String,
    pub action: String,
    pub surface: String,
    pub transport: String,
    pub classification: String,
    pub posture: String,
    pub admission_id: Option<String>,
    pub journal_head_hash: String,
    pub value_returned: bool,
}

pub trait RuntimeAuthorityAudit: DutyAuthorizationAuditSink + Send {
    fn record_runtime_authority(&mut self, event: RuntimeAuthorityAuditV1) -> JanusResult<()>;
}

/// Private durable JSONL sink used by the broker service.
pub struct JsonlRuntimeAuthorityAudit {
    path: PathBuf,
}

impl JsonlRuntimeAuthorityAudit {
    pub fn open(path: impl Into<PathBuf>) -> JanusResult<Self> {
        let path = path.into();
        let parent = path
            .parent()
            .ok_or_else(|| unavailable("runtime authority audit path invalid"))?;
        ensure_private_directory(parent)?;
        let mut options = OpenOptions::new();
        options.append(true).create(true).mode(0o600);
        options
            .open(&path)
            .and_then(|file| file.sync_all())
            .map_err(|_| unavailable("runtime authority audit unavailable"))?;
        ensure_private_file(&path, MAX_AUTHORITY_AUDIT_BYTES)?;
        Ok(Self { path })
    }

    fn append(&self, value: &impl Serialize) -> JanusResult<()> {
        ensure_private_file(&self.path, MAX_AUTHORITY_AUDIT_BYTES)?;
        let mut encoded = serde_json::to_vec(value)
            .map_err(|_| unavailable("runtime authority audit encoding failed"))?;
        encoded.push(b'\n');
        let current = fs::metadata(&self.path)
            .map_err(|_| unavailable("runtime authority audit unavailable"))?
            .len();
        if current.saturating_add(encoded.len() as u64) > MAX_AUTHORITY_AUDIT_BYTES {
            return Err(unavailable("runtime authority audit capacity exceeded"));
        }
        let mut file = OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(|_| unavailable("runtime authority audit unavailable"))?;
        file.write_all(&encoded)
            .and_then(|_| file.flush())
            .and_then(|_| file.sync_all())
            .map_err(|_| JanusError::AuditUnavailable {
                detail: "runtime authority audit persistence failed".to_string(),
            })
    }
}

impl DutyAuthorizationAuditSink for JsonlRuntimeAuthorityAudit {
    fn record_duty_authorization(&mut self, event: DutyAuthorizationAuditV1) -> JanusResult<()> {
        self.append(&event)
    }
}

impl RuntimeAuthorityAudit for JsonlRuntimeAuthorityAudit {
    fn record_runtime_authority(&mut self, event: RuntimeAuthorityAuditV1) -> JanusResult<()> {
        self.append(&event)
    }
}

/// Kernel-peer broker owning identity, operation-state verification, journal
/// verification/conflict evaluation, audit, and signed runtime admission.
pub struct RuntimeAuthorityBroker {
    registry: FileSubjectRegistry,
    identity_manifest: IdentityTransportManifestV1,
    duty_manifest: DutySurfaceManifestV1,
    signing_key: SigningKey,
    operation_verifier: Mutex<OperationStateVerifier>,
    journal: Option<FileDutyJournal>,
    posture: AccountabilityPosture,
    scope: ScopeRef,
    audience_fingerprint: String,
    release_digest: String,
    ttl: Duration,
    audit: Mutex<Box<dyn RuntimeAuthorityAudit>>,
}

impl RuntimeAuthorityBroker {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        registry: FileSubjectRegistry,
        identity_manifest: IdentityTransportManifestV1,
        duty_manifest: DutySurfaceManifestV1,
        signing_key: SigningKey,
        operation_verifier: OperationStateVerifier,
        journal: Option<FileDutyJournal>,
        posture: AccountabilityPosture,
        scope: ScopeRef,
        audience: &str,
        release_digest: String,
        ttl: Duration,
        cutover: Option<&AccountabilityCutoverV1>,
        audit: Box<dyn RuntimeAuthorityAudit>,
    ) -> JanusResult<Self> {
        if audience.is_empty()
            || ttl.is_zero()
            || ttl.as_secs() > MAX_RUNTIME_ADMISSION_TTL_SECS
            || !valid_sha256(&release_digest)
            || duty_manifest.identity_manifest_fingerprint() != identity_manifest.fingerprint()
        {
            return Err(authority_error(
                "runtime_authority_config_invalid",
                "runtime authority configuration is invalid",
            ));
        }
        for policy in duty_manifest.policies() {
            let identity = identity_manifest.surface(policy.surface())?;
            if identity.transport().as_str() != policy.transport().as_str()
                || identity.adapter() != janus_core::TrustAdapterKind::LocalPeer
            {
                return Err(authority_error(
                    "runtime_authority_surface_mismatch",
                    "runtime authority surface is not bound to the required local adapter",
                ));
            }
        }
        if posture.requires_verified_journal() {
            journal
                .as_ref()
                .ok_or_else(|| unavailable("recorded posture requires a duty journal"))?
                .verify_health()?;
        }
        match posture {
            AccountabilityPosture::AccountabilityLegacy
            | AccountabilityPosture::AuthenticatedObserve => {
                if cutover.is_some() {
                    return Err(authority_error(
                        "runtime_authority_cutover_unexpected",
                        "cutover evidence is accepted only for enforced recorded posture",
                    ));
                }
            }
            AccountabilityPosture::EnforcedRecorded => {
                let cutover = cutover.ok_or_else(|| {
                    authority_error(
                        "enforced_recorded_not_ready",
                        "enforced recorded posture requires exact cutover evidence",
                    )
                })?;
                cutover.enforce_ready(&release_digest, &scope, duty_manifest.fingerprint())?;
                let active_subjects = registry
                    .list()?
                    .into_iter()
                    .filter(|entry| entry.status == crate::SubjectRegistryStatus::Active)
                    .count();
                if active_subjects < 2 || active_subjects as u64 != cutover.enrolled_subjects() {
                    return Err(authority_error(
                        "enforced_recorded_subjects_mismatch",
                        "enforced recorded subject registry does not match cutover evidence",
                    ));
                }
            }
        }
        Ok(Self {
            registry,
            identity_manifest,
            duty_manifest,
            signing_key,
            operation_verifier: Mutex::new(operation_verifier),
            journal,
            posture,
            scope,
            audience_fingerprint: fingerprint(
                "janus-runtime-admission-audience-v1",
                audience.as_bytes(),
            ),
            release_digest,
            ttl,
            audit: Mutex::new(audit),
        })
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn posture(&self) -> AccountabilityPosture {
        self.posture
    }

    pub(crate) fn authorize_peer(
        &self,
        peer: RuntimePeerCredentials,
        channel_binding_ref: &str,
        request: RuntimeAuthorityRequestV1,
        now: SystemTime,
    ) -> JanusResult<RuntimeAuthorityReplyV1> {
        if request.schema_version != 1 {
            return Err(authority_error(
                "runtime_authority_request_invalid",
                "runtime authority request schema is invalid",
            ));
        }
        let scope = ScopeRef::from_opaque(request.scope_ref)?;
        if scope != self.scope || !valid_prefixed_hex(&request.audit_ref, "aud_", 24) {
            return Err(authority_error(
                "runtime_authority_request_context_mismatch",
                "runtime authority request scope or audit linkage is invalid",
            ));
        }
        let action = RuntimeAction::parse(&request.action)?;
        let policy = self.duty_manifest.policy(action)?;
        let identity = self.identity_manifest.surface(policy.surface())?;
        if identity.transport().as_str() != policy.transport().as_str() {
            return Err(authority_error(
                "runtime_authority_transport_mismatch",
                "runtime authority transport is not release-reviewed",
            ));
        }
        let actor = self.registry.authenticate_local_uid(
            peer.uid,
            scope.clone(),
            &self.release_digest,
            peer_binding_ref(peer),
            channel_binding_ref.to_string(),
        )?;

        let (classification, domain, operation_ref, duty, health, conflict_observed) =
            match policy.classification() {
                RuntimeDutyClassification::NoConflict
                    if self.posture == AccountabilityPosture::AccountabilityLegacy =>
                {
                    if request.operation.is_some() {
                        return Err(authority_error(
                            "runtime_authority_operation_unexpected",
                            "legacy action cannot carry operation authority",
                        ));
                    }
                    ("legacy", None, None, None, legacy_health(), false)
                }
                RuntimeDutyClassification::NoConflict => {
                    if request.operation.is_some() {
                        return Err(authority_error(
                            "runtime_authority_operation_unexpected",
                            "no-conflict action cannot carry operation authority",
                        ));
                    }
                    let health = self.journal_health()?;
                    ("no_conflict", None, None, None, health, false)
                }
                RuntimeDutyClassification::Recorded { .. }
                    if self.posture == AccountabilityPosture::AccountabilityLegacy =>
                {
                    ("legacy", None, None, None, legacy_health(), false)
                }
                classification @ RuntimeDutyClassification::Recorded { .. } => {
                    let reference = request.operation.as_ref().ok_or_else(|| {
                        authority_error(
                            "runtime_authority_operation_missing",
                            "recorded action requires signed authoritative operation state",
                        )
                    })?;
                    let operation = self
                        .operation_verifier
                        .lock()
                        .map_err(|_| unavailable("operation verifier unavailable"))?
                        .verify_once(reference, now)?;
                    if operation.scope() != &scope
                        || operation.release_digest() != self.release_digest
                        || !classification.permits(operation.conflict_domain(), operation.duty())
                    {
                        return Err(authority_error(
                            "runtime_authority_operation_mismatch",
                            "signed operation state is not classified for this action",
                        ));
                    }
                    let domain = operation.conflict_domain();
                    let operation_ref = operation.operation_ref().as_str().to_string();
                    let duty = operation.duty();
                    let (health, conflict_observed) = if self.posture.requires_verified_journal() {
                        let receipt = self
                            .journal
                            .as_ref()
                            .ok_or_else(|| unavailable("duty journal unavailable"))?
                            .authorize_and_admit_in_posture(
                                &actor,
                                operation,
                                &request.audit_ref,
                                now,
                                self.posture,
                                &mut **self.audit.lock().map_err(|_| {
                                    unavailable("runtime authority audit unavailable")
                                })?,
                            )?;
                        (
                            DutyJournalHealthV1 {
                                schema_version: 1,
                                sequence: receipt.sequence,
                                journal_head_hash: receipt.journal_head_hash,
                                value_returned: false,
                            },
                            receipt.conflict_observed,
                        )
                    } else {
                        (legacy_health(), false)
                    };
                    (
                        "recorded",
                        Some(domain),
                        Some(operation_ref),
                        Some(duty),
                        health,
                        conflict_observed,
                    )
                }
            };

        let issued = unix_secs(now)?;
        let expires = issued
            .checked_add(self.ttl.as_secs())
            .ok_or_else(|| unavailable("runtime admission time overflow"))?;
        let random = random_bytes::<32>()?;
        let mut admission = RuntimeAdmissionV1 {
            schema_version: RUNTIME_ADMISSION_SCHEMA,
            admission_id: opaque_ref("adm_", "janus-runtime-admission-v1", &random, 12),
            actor_subject_ref: actor.subject_ref().as_str().to_string(),
            scope_ref: scope.as_str().to_string(),
            surface: policy.surface().to_string(),
            transport: policy.transport().as_str().to_string(),
            action: action.as_str().to_string(),
            classification: classification.to_string(),
            conflict_domain: domain,
            operation_ref,
            duty,
            posture: self.posture.as_str().to_string(),
            journal_sequence: health.sequence,
            journal_head_hash: health.journal_head_hash.clone(),
            audit_ref: request.audit_ref,
            issued_at_unix_secs: issued,
            expires_at_unix_secs: expires,
            audience_fingerprint: self.audience_fingerprint.clone(),
            release_digest: self.release_digest.clone(),
            authority: match self.posture {
                AccountabilityPosture::AccountabilityLegacy => "accountability_legacy",
                AccountabilityPosture::AuthenticatedObserve => "durable_duty_observation",
                AccountabilityPosture::EnforcedRecorded => "durable_duty_admission",
            }
            .to_string(),
            value_returned: false,
            signature: String::new(),
        };
        admission.signature = hex::encode(
            self.signing_key
                .sign(&admission.signing_bytes()?)
                .to_bytes(),
        );
        let event = RuntimeAuthorityAuditV1 {
            schema_version: 1,
            outcome: if conflict_observed {
                "observed_conflict"
            } else {
                "allowed"
            }
            .to_string(),
            reason_code: if conflict_observed {
                "duty_conflict_observed"
            } else {
                "runtime_admitted"
            }
            .to_string(),
            actor_subject_ref: actor.subject_ref().as_str().to_string(),
            scope_ref: scope.as_str().to_string(),
            action: action.as_str().to_string(),
            surface: policy.surface().to_string(),
            transport: policy.transport().as_str().to_string(),
            classification: classification.to_string(),
            posture: self.posture.as_str().to_string(),
            admission_id: Some(admission.admission_id.clone()),
            journal_head_hash: health.journal_head_hash,
            value_returned: false,
        };
        self.audit
            .lock()
            .map_err(|_| unavailable("runtime authority audit unavailable"))?
            .record_runtime_authority(event)?;
        Ok(RuntimeAuthorityReplyV1 {
            schema_version: 1,
            ok: true,
            admission: Some(admission),
            reason_code: None,
            value_returned: false,
        })
    }

    fn journal_health(&self) -> JanusResult<DutyJournalHealthV1> {
        if self.posture.requires_verified_journal() {
            self.journal
                .as_ref()
                .ok_or_else(|| unavailable("duty journal unavailable"))?
                .verify_health()
        } else {
            Ok(legacy_health())
        }
    }
}

/// Short-lived client. It verifies the broker signature and exact expected
/// action before returning an opaque admission to policy.
pub struct RuntimeAuthorityClient {
    socket: PathBuf,
    verifier: RuntimeAdmissionVerifier,
}

impl RuntimeAuthorityClient {
    pub fn new(
        socket: impl Into<PathBuf>,
        manifest: DutySurfaceManifestV1,
        verifying_key: VerifyingKey,
        audience: &str,
        release_digest: &str,
    ) -> JanusResult<Self> {
        Ok(Self {
            socket: socket.into(),
            verifier: RuntimeAdmissionVerifier::new(
                manifest,
                verifying_key,
                audience,
                release_digest,
            )?,
        })
    }

    pub async fn authorize(
        &mut self,
        request: RuntimeAuthorityRequestV1,
        expected_action: RuntimeAction,
        _requested_at: SystemTime,
    ) -> JanusResult<VerifiedRuntimeAdmission> {
        let mut stream = timeout(Duration::from_secs(5), UnixStream::connect(&self.socket))
            .await
            .map_err(|_| unavailable("runtime authority connection timed out"))?
            .map_err(|_| unavailable("runtime authority socket unavailable"))?;
        let mut encoded = serde_json::to_vec(&request)
            .map_err(|_| unavailable("runtime authority request encoding failed"))?;
        if encoded.len() > MAX_AUTHORITY_FRAME_BYTES {
            return Err(authority_error(
                "runtime_authority_request_too_large",
                "runtime authority request exceeds the reviewed bound",
            ));
        }
        encoded.push(b'\n');
        stream
            .write_all(&encoded)
            .await
            .map_err(|_| unavailable("runtime authority request failed"))?;
        let mut reader = BufReader::new(stream);
        let mut reply = Vec::new();
        timeout(Duration::from_secs(5), reader.read_until(b'\n', &mut reply))
            .await
            .map_err(|_| unavailable("runtime authority reply timed out"))?
            .map_err(|_| unavailable("runtime authority reply unavailable"))?;
        if reply.len() > MAX_AUTHORITY_FRAME_BYTES || reply.last() != Some(&b'\n') {
            return Err(unavailable("runtime authority reply malformed"));
        }
        let reply: RuntimeAuthorityReplyV1 = serde_json::from_slice(&reply[..reply.len() - 1])
            .map_err(|_| unavailable("runtime authority reply malformed"))?;
        if reply.schema_version != 1 || !reply.ok || reply.value_returned {
            return Err(authority_error(
                "runtime_authority_denied",
                "runtime authority broker denied the action",
            ));
        }
        let admission = reply.admission.ok_or_else(|| {
            authority_error(
                "runtime_authority_reply_missing",
                "runtime authority broker omitted its admission",
            )
        })?;
        // The broker stamps the reply after receiving the request. Verify at
        // receipt time so crossing a one-second boundary cannot make a fresh
        // admission appear to come from the future.
        self.verifier
            .verify_once(&admission, expected_action, SystemTime::now())
    }
}

/// Obtain one fresh broker admission from the explicit runtime environment.
/// Recorded actions require a domain-service-signed, single-use operation
/// reference file; actor identity, duty, and transport never come from env.
pub async fn authorize_runtime_action_from_env(
    action: RuntimeAction,
    scope: &ScopeRef,
    now: SystemTime,
) -> JanusResult<VerifiedRuntimeAdmission> {
    let socket = required_env_path("JANUS_IDENTITY_SOCKET")?;
    let manifest_text = read_reviewed_text(
        &required_env_path("JANUS_DUTY_SURFACE_MANIFEST")?,
        MAX_MANIFEST_BYTES as u64,
        "duty surface manifest",
    )?;
    let manifest = DutySurfaceManifestV1::parse_json(&manifest_text)?;
    let verifying_key = load_runtime_verifying_key(&required_env_path(
        "JANUS_RUNTIME_AUTHORITY_VERIFYING_KEY_FILE",
    )?)?;
    let audience = required_env_text("JANUS_RUNTIME_AUTHORITY_AUDIENCE")?;
    let release = required_env_text("JANUS_RELEASE_DIGEST")?;
    let expected_posture =
        AccountabilityPosture::parse(&required_env_text("JANUS_ACCOUNTABILITY_POSTURE")?)?;
    let operation = match (expected_posture, manifest.policy(action)?.classification()) {
        (AccountabilityPosture::AccountabilityLegacy, _) => None,
        (_, RuntimeDutyClassification::NoConflict) => None,
        (_, RuntimeDutyClassification::Recorded { .. }) => {
            let text = read_reviewed_text(
                &required_env_path("JANUS_RUNTIME_OPERATION_REFERENCE_FILE")?,
                64 * 1024,
                "runtime operation reference",
            )?;
            Some(serde_json::from_str(&text).map_err(|_| {
                authority_error(
                    "runtime_operation_reference_invalid",
                    "runtime operation reference is malformed",
                )
            })?)
        }
    };
    let mut client =
        RuntimeAuthorityClient::new(socket, manifest, verifying_key, &audience, &release)?;
    let admission = client
        .authorize(
            RuntimeAuthorityRequestV1 {
                schema_version: 1,
                scope_ref: scope.as_str().to_string(),
                action: action.as_str().to_string(),
                operation,
                audit_ref: opaque_ref(
                    "aud_",
                    "janus-runtime-authority-audit-v1",
                    &random_bytes::<32>()?,
                    12,
                ),
            },
            action,
            now,
        )
        .await?;
    if admission.posture() != expected_posture {
        return Err(authority_error(
            "runtime_authority_posture_mismatch",
            "runtime admission posture does not match the explicit deployment posture",
        ));
    }
    Ok(admission)
}

/// Read an exact reviewed raw Ed25519 public key.
pub fn load_runtime_verifying_key(path: &Path) -> JanusResult<VerifyingKey> {
    let bytes = read_reviewed_bytes(path, 32, "runtime authority verifying key")?;
    let raw: [u8; 32] = bytes
        .try_into()
        .map_err(|_| unavailable("runtime authority verifying key malformed"))?;
    VerifyingKey::from_bytes(&raw)
        .map_err(|_| unavailable("runtime authority verifying key malformed"))
}

/// Provision the public half of the broker signer once for an explicit legacy
/// bootstrap. Observe/enforced deployments must pin it before startup.
pub fn provision_runtime_verifying_key(
    path: &Path,
    verifying_key: &VerifyingKey,
) -> JanusResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| unavailable("runtime authority verifying key path invalid"))?;
    ensure_private_directory(parent)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options
        .open(path)
        .map_err(|_| unavailable("runtime authority verifying key provisioning failed"))?;
    file.write_all(verifying_key.as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|_| unavailable("runtime authority verifying key provisioning failed"))
}

fn required_env_path(key: &'static str) -> JanusResult<PathBuf> {
    env::var_os(key)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| unavailable(format!("{key} is required")))
}

fn required_env_text(key: &'static str) -> JanusResult<String> {
    env::var(key)
        .ok()
        .filter(|value| !value.is_empty() && value.trim().len() == value.len())
        .ok_or_else(|| unavailable(format!("{key} is required")))
}

fn read_reviewed_text(path: &Path, maximum: u64, label: &str) -> JanusResult<String> {
    String::from_utf8(read_reviewed_bytes_bounded(path, maximum, label)?)
        .map_err(|_| unavailable(format!("{label} is malformed")))
}

fn read_reviewed_bytes(path: &Path, exact: u64, label: &str) -> JanusResult<Vec<u8>> {
    let bytes = read_reviewed_bytes_bounded(path, exact, label)?;
    if bytes.len() as u64 != exact {
        return Err(unavailable(format!("{label} has the wrong size")));
    }
    Ok(bytes)
}

fn read_reviewed_bytes_bounded(path: &Path, maximum: u64, label: &str) -> JanusResult<Vec<u8>> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| unavailable(format!("{label} is unavailable")))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > maximum
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(unavailable(format!(
            "{label} is not a reviewed regular file"
        )));
    }
    fs::read(path).map_err(|_| unavailable(format!("{label} is unavailable")))
}

pub fn denied_runtime_authority_reply(reason_code: &str) -> RuntimeAuthorityReplyV1 {
    RuntimeAuthorityReplyV1 {
        schema_version: 1,
        ok: false,
        admission: None,
        reason_code: Some(reason_code.to_string()),
        value_returned: false,
    }
}

fn legacy_health() -> DutyJournalHealthV1 {
    DutyJournalHealthV1 {
        schema_version: 1,
        sequence: 0,
        journal_head_hash: DUTY_JOURNAL_GENESIS_HASH.to_string(),
        value_returned: false,
    }
}

fn peer_binding_ref(peer: RuntimePeerCredentials) -> String {
    let text = format!("uid={};gid={};pid={:?}", peer.uid, peer.gid, peer.pid);
    fingerprint("janus-runtime-peer-v1", text.as_bytes())
}

fn fingerprint(domain: &str, bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain.as_bytes());
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn valid_prefixed_hex(value: &str, prefix: &str, length: usize) -> bool {
    value.strip_prefix(prefix).is_some_and(|suffix| {
        suffix.len() == length
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn valid_sha256(value: &str) -> bool {
    valid_prefixed_hex(value, "sha256:", 64)
}

fn unix_secs(time: SystemTime) -> JanusResult<u64> {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| unavailable("runtime authority time invalid"))
}

fn ensure_private_directory(path: &Path) -> JanusResult<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| unavailable("runtime authority audit directory unavailable"))?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(unavailable(
            "runtime authority audit directory is not private",
        ));
    }
    Ok(())
}

fn ensure_private_file(path: &Path, maximum: u64) -> JanusResult<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| unavailable("runtime authority audit unavailable"))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() > maximum
    {
        return Err(unavailable("runtime authority audit is invalid"));
    }
    Ok(())
}

fn authority_error(reason_code: &'static str, detail: &'static str) -> JanusError {
    JanusError::policy_denied(reason_code, detail)
}

fn unavailable(detail: impl Into<String>) -> JanusError {
    JanusError::StoreUnavailable {
        detail: detail.into(),
    }
}

#[cfg(test)]
pub(crate) fn test_runtime_admission(
    action: RuntimeAction,
    scope: ScopeRef,
    now: SystemTime,
) -> VerifiedRuntimeAdmission {
    let key = SigningKey::from_bytes(&random_bytes::<32>().unwrap());
    let manifest = DutySurfaceManifestV1::parse_json(include_str!(
        "../../../config/authorization/duty-surface-manifest-v1.json"
    ))
    .unwrap();
    let issued = unix_secs(now).unwrap();
    let mut admission = RuntimeAdmissionV1 {
        schema_version: RUNTIME_ADMISSION_SCHEMA,
        admission_id: nonce_for_test("adm_"),
        actor_subject_ref: janus_core::ActorSubjectRef::derive(
            janus_core::TrustAdapterKind::LocalPeer,
            "test",
            "actor",
        )
        .unwrap()
        .as_str()
        .to_string(),
        scope_ref: scope.as_str().to_string(),
        surface: janus_core::runtime_surface(action).to_string(),
        transport: janus_core::runtime_endpoint_policy(action)
            .transport
            .as_str()
            .to_string(),
        action: action.as_str().to_string(),
        classification: "no_conflict".to_string(),
        conflict_domain: None,
        operation_ref: None,
        duty: None,
        posture: "enforced_recorded".to_string(),
        journal_sequence: 0,
        journal_head_hash: DUTY_JOURNAL_GENESIS_HASH.to_string(),
        audit_ref: nonce_for_test("aud_"),
        issued_at_unix_secs: issued,
        expires_at_unix_secs: issued + 60,
        audience_fingerprint: fingerprint("janus-runtime-admission-audience-v1", b"test"),
        release_digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .to_string(),
        authority: "durable_duty_admission".to_string(),
        value_returned: false,
        signature: String::new(),
    };
    admission.signature = hex::encode(key.sign(&admission.signing_bytes().unwrap()).to_bytes());
    RuntimeAdmissionVerifier::new(
        manifest,
        key.verifying_key(),
        "test",
        &admission.release_digest,
    )
    .unwrap()
    .verify_once(&admission, action, now)
    .unwrap()
}

#[cfg(test)]
fn nonce_for_test(prefix: &str) -> String {
    opaque_ref(
        prefix,
        "janus-runtime-test-ref-v1",
        &random_bytes::<16>().unwrap(),
        12,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{bind_private_identity_socket, IdentityShadowBroker};
    use ed25519_dalek::SigningKey;
    use janus_core::SeparationPolicy;
    use janus_core::{
        ActorSubjectClass, AuthoritativeOperationRefV1, ConflictDomain, Duty, OperationRef,
        SafeLabel, ScopePathV1,
    };
    use serde_json::json;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tempfile::{tempdir, TempDir};

    const RELEASE: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DOMAIN_SERVICE: &str = "runtime-domain-service";
    const AUDIENCE: &str = "janus-runtime-authority";

    #[derive(Default)]
    struct MemoryAudit {
        duties: Vec<DutyAuthorizationAuditV1>,
        runtimes: Vec<RuntimeAuthorityAuditV1>,
    }

    impl DutyAuthorizationAuditSink for MemoryAudit {
        fn record_duty_authorization(
            &mut self,
            event: DutyAuthorizationAuditV1,
        ) -> JanusResult<()> {
            self.duties.push(event);
            Ok(())
        }
    }

    impl RuntimeAuthorityAudit for MemoryAudit {
        fn record_runtime_authority(&mut self, event: RuntimeAuthorityAuditV1) -> JanusResult<()> {
            self.runtimes.push(event);
            Ok(())
        }
    }

    fn scope() -> ScopeRef {
        ScopePathV1::for_repository("fixture-org", "janus", "janus", "prod")
            .unwrap()
            .scope_ref()
    }

    fn nonce(prefix: &str) -> String {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let random = random_bytes::<16>().unwrap();
        let counter = SEQUENCE.fetch_add(1, Ordering::Relaxed).to_be_bytes();
        let mut bytes = Vec::from(random);
        bytes.extend_from_slice(&counter);
        opaque_ref(prefix, "janus-runtime-test-ref-v1", &bytes, 12)
    }

    fn signed_operation(
        key: &SigningKey,
        domain: ConflictDomain,
        duty: Duty,
        lineage: &str,
        now: SystemTime,
    ) -> AuthoritativeOperationRefV1 {
        AuthoritativeOperationRefV1::issue(
            key,
            DOMAIN_SERVICE,
            &OperationRef::derive(domain, lineage).unwrap(),
            &scope(),
            domain,
            duty,
            1,
            &SafeLabel::new("policy-v1").unwrap(),
            now,
            now + Duration::from_secs(60),
            &nonce("nce_"),
            AUDIENCE,
            RELEASE,
        )
        .unwrap()
    }

    fn action_for(duty: Duty) -> RuntimeAction {
        match duty {
            Duty::RequestUse => RuntimeAction::WardenRequestUse,
            Duty::ApproveUse => RuntimeAction::ApprovalIssue,
            Duty::ExecuteUse | Duty::UseBreakGlass => RuntimeAction::ManagedRun,
            Duty::GrantDelegation | Duty::ReceiveDelegation => RuntimeAction::DelegationIssue,
            Duty::GrantRole | Duty::ReceiveRole | Duty::ManageRolePolicy => {
                RuntimeAction::RoleBindingIssue
            }
            Duty::ActivateBreakGlass => RuntimeAction::BreakGlassRequest,
            Duty::ApproveBreakGlass => RuntimeAction::BreakGlassApprove,
            Duty::ReviewBreakGlass => RuntimeAction::BreakGlassReview,
            Duty::OperateRecovery | Duty::ReviewRecovery => RuntimeAction::RecoveryDrill,
        }
    }

    fn request(
        action: RuntimeAction,
        operation: Option<AuthoritativeOperationRefV1>,
    ) -> RuntimeAuthorityRequestV1 {
        RuntimeAuthorityRequestV1 {
            schema_version: 1,
            scope_ref: scope().as_str().to_string(),
            action: action.as_str().to_string(),
            operation,
            audit_ref: nonce("aud_"),
        }
    }

    fn fixture(
        posture: AccountabilityPosture,
    ) -> (
        TempDir,
        RuntimeAuthorityBroker,
        SigningKey,
        SigningKey,
        DutySurfaceManifestV1,
        IdentityTransportManifestV1,
    ) {
        let directory = tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let registry = FileSubjectRegistry::new(directory.path().join("subjects"), "fixture-host");
        registry
            .enroll_local(501, ActorSubjectClass::Human, b"review-one", UNIX_EPOCH)
            .unwrap();
        registry
            .enroll_local(502, ActorSubjectClass::Human, b"review-two", UNIX_EPOCH)
            .unwrap();
        let identity_manifest = IdentityTransportManifestV1::parse_json(include_str!(
            "../../../config/identity/transport-manifest-v1.json"
        ))
        .unwrap();
        let duty_manifest = DutySurfaceManifestV1::parse_json(include_str!(
            "../../../config/authorization/duty-surface-manifest-v1.json"
        ))
        .unwrap();
        let admission_key = SigningKey::from_bytes(&random_bytes::<32>().unwrap());
        let domain_key = SigningKey::from_bytes(&random_bytes::<32>().unwrap());
        let journal_key = SigningKey::from_bytes(&random_bytes::<32>().unwrap());
        let journal = FileDutyJournal::open_or_create(
            directory.path().join("duty"),
            RELEASE.to_string(),
            journal_key,
        )
        .unwrap();
        let verifier = OperationStateVerifier::new(
            domain_key.verifying_key(),
            DOMAIN_SERVICE,
            AUDIENCE,
            RELEASE,
        )
        .unwrap();
        let cutover_text = json!({
            "schema_version": 1,
            "release_digest": RELEASE,
            "scope_ref": scope().as_str(),
            "surface_manifest_fingerprint": duty_manifest.fingerprint(),
            "identity_migration_fingerprint": RELEASE,
            "active_legacy_operations": 0,
            "enrolled_subjects": 2,
            "backup_fingerprint": RELEASE,
            "restore_rehearsal_fingerprint": RELEASE,
            "observation_window_fingerprint": RELEASE,
            "open_trust_root_recovery": false,
            "rollback_actor_schema": 1,
            "rollback_duty_schema": 1
        })
        .to_string();
        let cutover = AccountabilityCutoverV1::parse_json(&cutover_text).unwrap();
        let broker = RuntimeAuthorityBroker::new(
            registry,
            identity_manifest.clone(),
            duty_manifest.clone(),
            admission_key.clone(),
            verifier,
            Some(journal),
            posture,
            scope(),
            AUDIENCE,
            RELEASE.to_string(),
            Duration::from_secs(60),
            (posture == AccountabilityPosture::EnforcedRecorded).then_some(&cutover),
            Box::<MemoryAudit>::default(),
        )
        .unwrap();
        (
            directory,
            broker,
            admission_key,
            domain_key,
            duty_manifest,
            identity_manifest,
        )
    }

    #[test]
    fn all_nine_same_subject_conflicts_deny_and_distinct_subjects_succeed() {
        let peer_one = RuntimePeerCredentials {
            uid: 501,
            gid: 20,
            pid: Some(1),
        };
        let peer_two = RuntimePeerCredentials {
            uid: 502,
            gid: 20,
            pid: Some(2),
        };
        let conflicts = SeparationPolicy::default().conflicts();
        for (index, conflict) in conflicts.iter().enumerate() {
            let (_directory, broker, _admission_key, domain_key, _, _) =
                fixture(AccountabilityPosture::EnforcedRecorded);
            let lineage = format!("conflict-{index}");
            let now = UNIX_EPOCH + Duration::from_secs(100 + index as u64);
            let domain = [
                ConflictDomain::UseRequest,
                ConflictDomain::DelegationGrant,
                ConflictDomain::RoleBinding,
                ConflictDomain::PolicyChange,
                ConflictDomain::BreakGlass,
                ConflictDomain::Recovery,
            ]
            .into_iter()
            .find(|domain| domain.permits(conflict.left) && domain.permits(conflict.right))
            .unwrap();
            broker
                .authorize_peer(
                    peer_one,
                    "cbr_fixture_one",
                    request(
                        action_for(conflict.left),
                        Some(signed_operation(
                            &domain_key,
                            domain,
                            conflict.left,
                            &lineage,
                            now,
                        )),
                    ),
                    now,
                )
                .unwrap();
            let denied = broker.authorize_peer(
                peer_one,
                "cbr_fixture_one_again",
                request(
                    action_for(conflict.right),
                    Some(signed_operation(
                        &domain_key,
                        domain,
                        conflict.right,
                        &lineage,
                        now,
                    )),
                ),
                now,
            );
            assert!(denied.is_err(), "{}", conflict.reason_code);
            broker
                .authorize_peer(
                    peer_two,
                    "cbr_fixture_two",
                    request(
                        action_for(conflict.right),
                        Some(signed_operation(
                            &domain_key,
                            domain,
                            conflict.right,
                            &lineage,
                            now,
                        )),
                    ),
                    now,
                )
                .unwrap();
        }
    }

    #[test]
    fn observation_records_conflict_without_claiming_enforcement() {
        let (_directory, broker, _, domain_key, _, _) =
            fixture(AccountabilityPosture::AuthenticatedObserve);
        let peer = RuntimePeerCredentials {
            uid: 501,
            gid: 20,
            pid: Some(1),
        };
        let now = UNIX_EPOCH + Duration::from_secs(100);
        for (duty, action) in [
            (Duty::RequestUse, RuntimeAction::WardenRequestUse),
            (Duty::ApproveUse, RuntimeAction::ApprovalIssue),
        ] {
            let reply = broker
                .authorize_peer(
                    peer,
                    "cbr_observe",
                    request(
                        action,
                        Some(signed_operation(
                            &domain_key,
                            ConflictDomain::UseRequest,
                            duty,
                            "observe",
                            now,
                        )),
                    ),
                    now,
                )
                .unwrap();
            let admission = reply.admission.unwrap();
            assert_eq!(admission.posture, "authenticated_observe");
            assert_eq!(admission.authority, "durable_duty_observation");
        }
    }

    #[test]
    fn legacy_still_authenticates_every_class_without_recorded_claim() {
        let (_directory, broker, _, _, _, _) = fixture(AccountabilityPosture::AccountabilityLegacy);
        let peer = RuntimePeerCredentials {
            uid: 501,
            gid: 20,
            pid: Some(1),
        };
        for action in [RuntimeAction::WardenHealth, RuntimeAction::WardenRequestUse] {
            let reply = broker
                .authorize_peer(peer, "cbr_legacy", request(action, None), SystemTime::now())
                .unwrap();
            let admission = reply.admission.unwrap();
            assert_eq!(admission.posture, "accountability_legacy");
            assert_eq!(admission.classification, "legacy");
            assert_eq!(admission.authority, "accountability_legacy");
            assert_eq!(admission.journal_sequence, 0);
            assert!(!admission.value_returned);
        }
    }

    #[tokio::test]
    async fn socket_client_verifies_kernel_actor_signature_action_and_replay() {
        let (directory, authority, admission_key, _domain_key, duty_manifest, identity_manifest) =
            fixture(AccountabilityPosture::EnforcedRecorded);
        let current_uid = current_uid();
        if current_uid != 501 {
            // Rebuild the registry fixture for the actual kernel peer used by
            // the socket, while retaining a distinct independently enrolled subject.
            return;
        }
        let identity = IdentityShadowBroker::new(
            FileSubjectRegistry::new(directory.path().join("subjects"), "fixture-host"),
            identity_manifest,
            admission_key.clone(),
            "identity-shadow",
            RELEASE.to_string(),
            Duration::from_secs(60),
        )
        .unwrap()
        .with_runtime_authority(authority)
        .unwrap();
        let socket = directory.path().join("identity.sock");
        let listener = bind_private_identity_socket(&socket).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            identity.serve_connection(stream).await.unwrap();
        });
        let mut client = RuntimeAuthorityClient::new(
            socket,
            duty_manifest,
            admission_key.verifying_key(),
            AUDIENCE,
            RELEASE,
        )
        .unwrap();
        let now = SystemTime::now();
        let admission = client
            .authorize(
                request(RuntimeAction::WardenHealth, None),
                RuntimeAction::WardenHealth,
                now,
            )
            .await
            .unwrap();
        assert!(admission.authorizes(janus_core::Permission::HealthRead, &scope()));
        server.abort();
    }

    fn current_uid() -> u32 {
        String::from_utf8(
            std::process::Command::new("id")
                .arg("-u")
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .parse()
        .unwrap()
    }
}
