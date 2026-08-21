//! Offline, authority-side administration of the private subject registry
//! (JANUS-453). `janusd-identity-admin` is the reviewed replacement for
//! hand-written enrollment records: it runs as the registry owner while the
//! broker is stopped, consumes signed operation-bound review evidence, writes
//! a fail-closed write-ahead audit, and lets `FileSubjectRegistry` own ref
//! generation, validation, locking, and immutable writes.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use fs2::FileExt;
use janus_core::{
    AccountabilityPosture, ActorSubjectClass, ActorSubjectRef, JanusError, JanusResult,
};
use serde::{Deserialize, Serialize};

use crate::authority::load_runtime_verifying_key;
use crate::identity::{
    fingerprint, load_or_create_identity_signing_key, opaque_ref, random_bytes, unix_secs,
    FileSubjectRegistry, SubjectRegistryStatus,
};

const REVIEW_SCHEMA: u8 = 1;
const REVIEW_SIGNING_DOMAIN: &[u8] = b"janus-identity-review-envelope-v1\0";
const MAX_REVIEW_TTL: Duration = Duration::from_secs(7 * 24 * 3600);
const MAX_REVIEW_SKEW: Duration = Duration::from_secs(300);
const MAX_EVIDENCE_BYTES: usize = 16 * 1024;
const MAX_REVIEWER_LABEL: usize = 256;
const MAX_ADMIN_AUDIT_BYTES: u64 = 128 * 1024 * 1024;

/// Posture source for the offline administrator. A pinned configuration file
/// is preferred because the administrator's own environment is not trusted to
/// describe the deployment; the explicit variable is the compatibility path.
#[derive(Clone, Debug)]
pub enum PostureSource {
    ConfigFile(PathBuf),
    Explicit(String),
}

/// Pinned accountability configuration consumed by both the broker and the
/// offline administrator.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AccountabilityConfigV1 {
    pub schema_version: u8,
    pub posture: String,
}

/// Reviewer-side request. It never travels to the host; the signed envelope
/// derived from it does.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReviewRequestV1 {
    pub schema_version: u8,
    pub verb: String,
    pub trust_domain: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_uid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_ref: Option<String>,
    pub ttl_seconds: u64,
    pub reviewer: String,
}

/// Signed, operation-bound review evidence. Field order is the canonical
/// signing order; `signature` is the hex Ed25519 signature over the domain
/// prefix plus this structure serialized with an empty signature.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReviewEnvelopeV1 {
    pub schema_version: u8,
    pub verb: String,
    pub trust_domain_fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_uid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_ref: Option<String>,
    pub reviewer_key_ref: String,
    pub review_ref: String,
    pub nonce: String,
    pub issued_at_unix_secs: u64,
    pub expires_at_unix_secs: u64,
    pub signature: String,
}

impl ReviewEnvelopeV1 {
    fn signing_bytes(&self) -> JanusResult<Vec<u8>> {
        let mut unsigned = self.clone();
        unsigned.signature = String::new();
        let mut bytes = REVIEW_SIGNING_DOMAIN.to_vec();
        bytes.extend(
            serde_json::to_vec(&unsigned).map_err(|_| {
                identity_error("identity_review_invalid", "review envelope encoding")
            })?,
        );
        Ok(bytes)
    }

    fn canonical_bytes(&self) -> JanusResult<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|_| identity_error("identity_review_invalid", "review envelope encoding"))
    }
}

/// Value-free result of a successful administrative command.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityAdminOutcomeV1 {
    pub schema_version: u8,
    pub ok: bool,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub review_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entries: Option<Vec<IdentityAdminEntryV1>>,
    pub value_returned: bool,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityAdminEntryV1 {
    pub subject_ref: String,
    pub subject_class: String,
    pub status: String,
}

/// Value-free administrative audit event. `authorized` is written and synced
/// before any mutation; `applied` or `denied` follows.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityAdminAuditV1 {
    pub schema_version: u8,
    pub event_id: String,
    pub outcome: String,
    pub reason_code: String,
    pub action: String,
    pub executor_class: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_subject_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewer_key_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub review_fingerprint: Option<String>,
    pub posture: String,
    pub registry_fingerprint: String,
    pub value_returned: bool,
}

/// Outcome of signing a review request on the reviewer's machine.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReviewSignOutcomeV1 {
    pub schema_version: u8,
    pub ok: bool,
    pub verb: String,
    pub reviewer_key_ref: String,
    pub nonce: String,
    pub expires_at_unix_secs: u64,
    pub value_returned: bool,
}

/// Derived location of the owner-checked lifecycle lock shared by the broker
/// and the administrator. It lives beside the registry, never inside it, so
/// the registry's foreign-entry rule stays intact.
pub fn lifecycle_lock_path(registry_root: &Path) -> JanusResult<PathBuf> {
    let parent = registry_root
        .parent()
        .ok_or_else(|| unavailable("subject registry path invalid"))?;
    let name = registry_root
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| unavailable("subject registry path invalid"))?;
    Ok(parent.join(format!("{name}.lifecycle.lock")))
}

fn open_lifecycle_lock(registry_root: &Path) -> JanusResult<File> {
    let path = lifecycle_lock_path(registry_root)?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(private_open_flags());
    let file = options
        .open(&path)
        .map_err(|_| unavailable("identity lifecycle lock unavailable"))?;
    let metadata = file
        .metadata()
        .map_err(|_| unavailable("identity lifecycle lock unavailable"))?;
    if !metadata.is_file()
        || metadata.len() != 0
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != current_euid()
        || metadata.nlink() != 1
    {
        return Err(identity_error(
            "identity_registry_security_invalid",
            "identity lifecycle lock is not a private owner file",
        ));
    }
    Ok(file)
}

/// Broker side: hold a shared lifecycle lock for the broker's lifetime so the
/// administrator's exclusive mutation lock fails closed while the broker runs.
pub fn hold_shared_lifecycle_lock(registry_root: &Path) -> JanusResult<File> {
    let file = open_lifecycle_lock(registry_root)?;
    file.try_lock_shared().map_err(|_| {
        identity_error(
            "identity_admin_running",
            "an identity administration mutation holds the lifecycle lock",
        )
    })?;
    Ok(file)
}

/// Load the pinned accountability configuration file (regular, non-symlink,
/// owned by the caller or root, not group/world writable).
pub fn load_accountability_config(path: &Path) -> JanusResult<AccountabilityPosture> {
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(private_open_flags());
    let mut file = options.open(path).map_err(|_| {
        identity_error(
            "identity_posture_unknown",
            "accountability config unavailable",
        )
    })?;
    let metadata = file.metadata().map_err(|_| {
        identity_error(
            "identity_posture_unknown",
            "accountability config unavailable",
        )
    })?;
    if !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > 4096
        || metadata.permissions().mode() & 0o022 != 0
        || (metadata.uid() != 0 && metadata.uid() != current_euid())
    {
        return Err(identity_error(
            "identity_posture_unknown",
            "accountability config is not a pinned read-only file",
        ));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|_| {
        identity_error(
            "identity_posture_unknown",
            "accountability config unavailable",
        )
    })?;
    let config: AccountabilityConfigV1 = serde_json::from_slice(&bytes).map_err(|_| {
        identity_error(
            "identity_posture_unknown",
            "accountability config malformed",
        )
    })?;
    if config.schema_version != 1 {
        return Err(identity_error(
            "identity_posture_unknown",
            "accountability config schema is not supported",
        ));
    }
    AccountabilityPosture::parse(&config.posture).map_err(|_| {
        identity_error(
            "identity_posture_unknown",
            "accountability posture malformed",
        )
    })
}

fn resolve_posture(source: &PostureSource) -> JanusResult<AccountabilityPosture> {
    match source {
        PostureSource::ConfigFile(path) => load_accountability_config(path),
        PostureSource::Explicit(value) => AccountabilityPosture::parse(value).map_err(|_| {
            identity_error(
                "identity_posture_unknown",
                "accountability posture malformed",
            )
        }),
    }
}

/// Offline administrator bound to one registry, trust domain, reviewer key,
/// audit file, and posture source.
pub struct IdentityAdmin {
    registry: FileSubjectRegistry,
    registry_root: PathBuf,
    trust_domain: String,
    review_verifying_key: VerifyingKey,
    audit_file: PathBuf,
    posture: PostureSource,
}

impl IdentityAdmin {
    pub fn new(
        registry_root: impl Into<PathBuf>,
        trust_domain: impl Into<String>,
        review_verifying_key_file: &Path,
        audit_file: impl Into<PathBuf>,
        posture: PostureSource,
    ) -> JanusResult<Self> {
        let registry_root = registry_root.into();
        let trust_domain = trust_domain.into();
        let review_verifying_key =
            load_runtime_verifying_key(review_verifying_key_file).map_err(|_| {
                identity_error(
                    "identity_review_invalid",
                    "review verifying key unavailable",
                )
            })?;
        Ok(Self {
            registry: FileSubjectRegistry::new(registry_root.clone(), trust_domain.clone()),
            registry_root,
            trust_domain,
            review_verifying_key,
            audit_file: audit_file.into(),
            posture,
        })
    }

    /// Enroll the subject named by signed review evidence.
    pub fn enroll(
        &self,
        evidence_file: &Path,
        now: SystemTime,
    ) -> JanusResult<IdentityAdminOutcomeV1> {
        self.mutate("enroll", evidence_file, now)
    }

    /// Revoke the subject named by signed review evidence (immutable record).
    pub fn revoke(
        &self,
        evidence_file: &Path,
        now: SystemTime,
    ) -> JanusResult<IdentityAdminOutcomeV1> {
        self.mutate("revoke", evidence_file, now)
    }

    /// Value-free inventory. Allowed while the broker runs.
    pub fn list(&self) -> JanusResult<IdentityAdminOutcomeV1> {
        check_caller()?;
        self.check_registry_root()?;
        let lock = open_lifecycle_lock(&self.registry_root)?;
        lock.try_lock_shared().map_err(|_| {
            identity_error(
                "identity_admin_running",
                "an identity administration mutation is running",
            )
        })?;
        let entries = self
            .registry
            .list()?
            .into_iter()
            .map(|entry| IdentityAdminEntryV1 {
                subject_ref: entry.subject_ref.as_str().to_string(),
                subject_class: entry.subject_class.as_str().to_string(),
                status: status_str(entry.status).to_string(),
            })
            .collect();
        Ok(IdentityAdminOutcomeV1 {
            schema_version: 1,
            ok: true,
            action: "list".to_string(),
            subject_ref: None,
            subject_class: None,
            status: None,
            review_fingerprint: None,
            entries: Some(entries),
            value_returned: false,
        })
    }

    fn mutate(
        &self,
        verb: &'static str,
        evidence_file: &Path,
        now: SystemTime,
    ) -> JanusResult<IdentityAdminOutcomeV1> {
        check_caller()?;
        self.check_registry_root()?;
        let lock = open_lifecycle_lock(&self.registry_root)?;
        lock.try_lock_exclusive().map_err(|_| {
            identity_error(
                "identity_broker_running",
                "the identity broker or another administrator holds the lifecycle lock",
            )
        })?;
        let posture = resolve_posture(&self.posture)?;
        if posture == AccountabilityPosture::EnforcedRecorded {
            return Err(identity_error(
                "identity_posture_mutation_forbidden",
                "registry mutations under enforced posture require a new cutover",
            ));
        }
        let envelope = read_review_evidence(evidence_file)?;
        let verified = verify_review_envelope(
            &envelope,
            &self.review_verifying_key,
            verb,
            &self.trust_domain,
            now,
        )?;
        let registry_fingerprint = self.registry_fingerprint()?;
        let event_id = opaque_ref(
            "iae_",
            "janus-identity-admin-event-v1",
            &random_bytes::<32>()?,
            12,
        );
        let base = IdentityAdminAuditV1 {
            schema_version: 1,
            event_id,
            outcome: "authorized".to_string(),
            reason_code: "identity_admin_authorized".to_string(),
            action: verb.to_string(),
            executor_class: "registry_owner".to_string(),
            target_subject_ref: verified.subject_ref.clone(),
            subject_class: verified
                .subject_class
                .map(|class| class.as_str().to_string()),
            reviewer_key_ref: Some(envelope.reviewer_key_ref.clone()),
            review_fingerprint: Some(verified.review_fingerprint.clone()),
            posture: posture.as_str().to_string(),
            registry_fingerprint,
            value_returned: false,
        };
        // Write-ahead: the authorization is durable before the record exists.
        self.append_audit(&base)?;
        let result = match verb {
            "enroll" => self
                .registry
                .enroll_reviewed(
                    verified.local_uid.unwrap_or_default(),
                    verified.subject_class.unwrap_or(ActorSubjectClass::System),
                    &verified.review_fingerprint,
                    now,
                )
                .map(|subject_ref| (subject_ref, "active")),
            _ => {
                let subject_ref = verified
                    .subject_ref
                    .as_deref()
                    .map(|value| ActorSubjectRef::from_opaque(value.to_string()))
                    .transpose()?
                    .ok_or_else(|| {
                        identity_error("identity_review_invalid", "revocation target missing")
                    })?;
                self.registry
                    .revoke_reviewed(&subject_ref, &verified.review_fingerprint, now)
                    .map(|_| (subject_ref, "revoked"))
            }
        };
        match result {
            Ok((subject_ref, status)) => {
                let mut applied = base.clone();
                applied.outcome = "applied".to_string();
                applied.reason_code = "identity_admin_applied".to_string();
                applied.target_subject_ref = Some(subject_ref.as_str().to_string());
                applied.registry_fingerprint = self.registry_fingerprint()?;
                self.append_audit(&applied)?;
                Ok(IdentityAdminOutcomeV1 {
                    schema_version: 1,
                    ok: true,
                    action: verb.to_string(),
                    subject_ref: Some(subject_ref.as_str().to_string()),
                    subject_class: base.subject_class,
                    status: Some(status.to_string()),
                    review_fingerprint: Some(verified.review_fingerprint),
                    entries: None,
                    value_returned: false,
                })
            }
            Err(error) => {
                let mut denied = base.clone();
                denied.outcome = "denied".to_string();
                denied.reason_code = crate::authority::denial_reason_code(&error).to_string();
                // Best effort: the denial itself is already the safe outcome.
                let _ = self.append_audit(&denied);
                Err(error)
            }
        }
    }

    fn check_registry_root(&self) -> JanusResult<()> {
        let metadata = fs::symlink_metadata(&self.registry_root).map_err(|_| {
            identity_error(
                "identity_registry_security_invalid",
                "subject registry root does not exist",
            )
        })?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.permissions().mode() & 0o777 != 0o700
            || metadata.uid() != current_euid()
        {
            return Err(identity_error(
                "identity_registry_security_invalid",
                "subject registry root must be a pre-owned 0700 directory",
            ));
        }
        Ok(())
    }

    fn registry_fingerprint(&self) -> JanusResult<String> {
        let mut lines = self
            .registry
            .list()?
            .into_iter()
            .map(|entry| {
                format!(
                    "{}:{}",
                    entry.subject_ref.as_str(),
                    status_str(entry.status)
                )
            })
            .collect::<Vec<_>>();
        lines.sort();
        Ok(fingerprint(
            "janus-identity-registry-state-v1",
            lines.join("\n").as_bytes(),
        ))
    }

    fn append_audit(&self, event: &IdentityAdminAuditV1) -> JanusResult<()> {
        let parent = self
            .audit_file
            .parent()
            .ok_or_else(|| audit_unavailable())?;
        let parent_metadata = fs::symlink_metadata(parent).map_err(|_| audit_unavailable())?;
        if !parent_metadata.is_dir()
            || parent_metadata.file_type().is_symlink()
            || parent_metadata.permissions().mode() & 0o077 != 0
            || parent_metadata.uid() != current_euid()
        {
            return Err(audit_unavailable());
        }
        let mut options = OpenOptions::new();
        options
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(private_open_flags());
        let mut file = options
            .open(&self.audit_file)
            .map_err(|_| audit_unavailable())?;
        let metadata = file.metadata().map_err(|_| audit_unavailable())?;
        if !metadata.is_file()
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.uid() != current_euid()
            || metadata.nlink() != 1
        {
            return Err(audit_unavailable());
        }
        let mut encoded = serde_json::to_vec(event).map_err(|_| audit_unavailable())?;
        encoded.push(b'\n');
        if metadata.len().saturating_add(encoded.len() as u64) > MAX_ADMIN_AUDIT_BYTES {
            return Err(audit_unavailable());
        }
        file.write_all(&encoded)
            .and_then(|_| file.sync_all())
            .map_err(|_| audit_unavailable())
    }
}

fn audit_unavailable() -> JanusError {
    identity_error(
        "identity_admin_audit_unavailable",
        "identity administration audit is unavailable",
    )
}

struct VerifiedReview {
    local_uid: Option<u32>,
    subject_class: Option<ActorSubjectClass>,
    subject_ref: Option<String>,
    review_fingerprint: String,
}

fn read_review_evidence(path: &Path) -> JanusResult<ReviewEnvelopeV1> {
    let invalid = || {
        identity_error(
            "identity_review_invalid",
            "review evidence is not a bounded regular file",
        )
    };
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(private_open_flags());
    let mut file = options.open(path).map_err(|_| invalid())?;
    let metadata = file.metadata().map_err(|_| invalid())?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_EVIDENCE_BYTES as u64 {
        return Err(invalid());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes).map_err(|_| invalid())?;
    serde_json::from_slice(&bytes)
        .map_err(|_| identity_error("identity_review_invalid", "review evidence is malformed"))
}

fn verify_review_envelope(
    envelope: &ReviewEnvelopeV1,
    verifying_key: &VerifyingKey,
    expected_verb: &str,
    trust_domain: &str,
    now: SystemTime,
) -> JanusResult<VerifiedReview> {
    let invalid = |detail: &'static str| identity_error("identity_review_invalid", detail);
    if envelope.schema_version != REVIEW_SCHEMA {
        return Err(invalid("review envelope schema is not supported"));
    }
    if envelope.verb != "enroll" && envelope.verb != "revoke" {
        return Err(invalid("review envelope verb is unknown"));
    }
    if envelope.verb != expected_verb {
        return Err(identity_error(
            "identity_review_context_mismatch",
            "review envelope authorizes a different verb",
        ));
    }
    if envelope.trust_domain_fingerprint
        != fingerprint("janus-identity-trust-domain-v1", trust_domain.as_bytes())
    {
        return Err(identity_error(
            "identity_review_context_mismatch",
            "review envelope is bound to a different trust domain",
        ));
    }
    if envelope.reviewer_key_ref != reviewer_key_ref(verifying_key) {
        return Err(identity_error(
            "identity_review_context_mismatch",
            "review envelope names a different reviewer key",
        ));
    }
    if !valid_prefixed_hex(&envelope.nonce, "rvn_", 24)
        || !valid_sha256(&envelope.review_ref)
        || envelope.signature.len() != 128
    {
        return Err(invalid("review envelope fields are malformed"));
    }
    let now_secs = unix_secs(now)?;
    if envelope.expires_at_unix_secs <= envelope.issued_at_unix_secs
        || envelope.expires_at_unix_secs - envelope.issued_at_unix_secs > MAX_REVIEW_TTL.as_secs()
        || envelope.issued_at_unix_secs > now_secs + MAX_REVIEW_SKEW.as_secs()
    {
        return Err(invalid("review envelope validity window is malformed"));
    }
    if envelope.expires_at_unix_secs <= now_secs {
        return Err(identity_error(
            "identity_review_expired",
            "review envelope has expired",
        ));
    }
    let (local_uid, subject_class, subject_ref) = match envelope.verb.as_str() {
        "enroll" => {
            let uid = envelope
                .local_uid
                .ok_or_else(|| invalid("enrollment review lacks a local uid"))?;
            let class = envelope
                .subject_class
                .as_deref()
                .map(ActorSubjectClass::parse)
                .transpose()
                .map_err(|_| invalid("enrollment review class is malformed"))?
                .ok_or_else(|| invalid("enrollment review lacks a subject class"))?;
            if envelope.subject_ref.is_some() {
                return Err(invalid("enrollment review must not name a subject ref"));
            }
            (Some(uid), Some(class), None)
        }
        _ => {
            let subject_ref = envelope
                .subject_ref
                .clone()
                .ok_or_else(|| invalid("revocation review lacks a subject ref"))?;
            ActorSubjectRef::from_opaque(subject_ref.clone())
                .map_err(|_| invalid("revocation review subject ref is malformed"))?;
            if envelope.local_uid.is_some() || envelope.subject_class.is_some() {
                return Err(invalid(
                    "revocation review must not carry enrollment fields",
                ));
            }
            (None, None, Some(subject_ref))
        }
    };
    let signature_bytes = hex::decode(&envelope.signature)
        .map_err(|_| invalid("review envelope signature is malformed"))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| invalid("review envelope signature is malformed"))?;
    verifying_key
        .verify(&envelope.signing_bytes()?, &signature)
        .map_err(|_| {
            identity_error(
                "identity_review_signature_invalid",
                "review envelope signature does not verify under the pinned reviewer key",
            )
        })?;
    let domain = if envelope.verb == "enroll" {
        "janus-identity-review-enrollment-v1"
    } else {
        "janus-identity-review-revocation-v1"
    };
    Ok(VerifiedReview {
        local_uid,
        subject_class,
        subject_ref,
        review_fingerprint: fingerprint(domain, &envelope.canonical_bytes()?),
    })
}

/// Opaque reference of a reviewer verifying key.
pub fn reviewer_key_ref(verifying_key: &VerifyingKey) -> String {
    fingerprint("janus-identity-review-key-v1", verifying_key.as_bytes())
}

/// Reviewer side: sign one request with the reviewer's private key and write
/// the envelope as a private file. The request may name a UID; it never goes
/// on argv.
pub fn sign_review_request(
    request_file: &Path,
    signing_key_file: &Path,
    out_file: &Path,
    now: SystemTime,
) -> JanusResult<ReviewSignOutcomeV1> {
    let invalid = |detail: &'static str| identity_error("identity_review_request_invalid", detail);
    let metadata =
        fs::symlink_metadata(request_file).map_err(|_| invalid("review request unavailable"))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > MAX_EVIDENCE_BYTES as u64
    {
        return Err(invalid("review request is not a bounded regular file"));
    }
    let mut bytes = Vec::new();
    File::open(request_file)
        .and_then(|mut file| file.read_to_end(&mut bytes))
        .map_err(|_| invalid("review request unavailable"))?;
    let request: ReviewRequestV1 =
        serde_json::from_slice(&bytes).map_err(|_| invalid("review request is malformed"))?;
    if request.schema_version != REVIEW_SCHEMA
        || (request.verb != "enroll" && request.verb != "revoke")
        || request.trust_domain.is_empty()
        || request.trust_domain.len() > 256
        || request.reviewer.is_empty()
        || request.reviewer.len() > MAX_REVIEWER_LABEL
        || request.ttl_seconds == 0
        || request.ttl_seconds > MAX_REVIEW_TTL.as_secs()
    {
        return Err(invalid("review request fields are malformed"));
    }
    match request.verb.as_str() {
        "enroll" => {
            if request.local_uid.is_none() || request.subject_ref.is_some() {
                return Err(invalid(
                    "enrollment request needs local_uid and no subject_ref",
                ));
            }
            request
                .subject_class
                .as_deref()
                .map(ActorSubjectClass::parse)
                .transpose()
                .map_err(|_| invalid("enrollment request class is malformed"))?
                .ok_or_else(|| invalid("enrollment request needs subject_class"))?;
        }
        _ => {
            if request.local_uid.is_some() || request.subject_class.is_some() {
                return Err(invalid(
                    "revocation request must not carry enrollment fields",
                ));
            }
            let subject_ref = request
                .subject_ref
                .clone()
                .ok_or_else(|| invalid("revocation request needs subject_ref"))?;
            ActorSubjectRef::from_opaque(subject_ref)
                .map_err(|_| invalid("revocation request subject ref is malformed"))?;
        }
    }
    let signing_key = load_or_create_identity_signing_key(signing_key_file)?;
    let issued = unix_secs(now)?;
    let mut envelope = ReviewEnvelopeV1 {
        schema_version: REVIEW_SCHEMA,
        verb: request.verb.clone(),
        trust_domain_fingerprint: fingerprint(
            "janus-identity-trust-domain-v1",
            request.trust_domain.as_bytes(),
        ),
        local_uid: request.local_uid,
        subject_class: request.subject_class.clone(),
        subject_ref: request.subject_ref.clone(),
        reviewer_key_ref: reviewer_key_ref(&signing_key.verifying_key()),
        review_ref: fingerprint(
            "janus-identity-review-label-v1",
            request.reviewer.as_bytes(),
        ),
        nonce: opaque_ref(
            "rvn_",
            "janus-identity-review-nonce-v1",
            &random_bytes::<32>()?,
            12,
        ),
        issued_at_unix_secs: issued,
        expires_at_unix_secs: issued + request.ttl_seconds,
        signature: String::new(),
    };
    envelope.signature = hex::encode(signing_key.sign(&envelope.signing_bytes()?).to_bytes());
    let encoded = envelope.canonical_bytes()?;
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(private_open_flags());
    let mut file = options
        .open(out_file)
        .map_err(|_| invalid("review evidence output already exists or is unavailable"))?;
    file.write_all(&encoded)
        .and_then(|_| file.sync_all())
        .map_err(|_| invalid("review evidence output persistence failed"))?;
    Ok(ReviewSignOutcomeV1 {
        schema_version: 1,
        ok: true,
        verb: request.verb,
        reviewer_key_ref: envelope.reviewer_key_ref,
        nonce: envelope.nonce,
        expires_at_unix_secs: envelope.expires_at_unix_secs,
        value_returned: false,
    })
}

/// Reviewer side: create the signing key if absent and publish its raw
/// verifying key for pinning on the host.
pub fn provision_review_keys(
    signing_key_file: &Path,
    verifying_key_file: &Path,
) -> JanusResult<String> {
    let signing_key = load_or_create_identity_signing_key(signing_key_file)?;
    crate::authority::provision_runtime_verifying_key(
        verifying_key_file,
        &signing_key.verifying_key(),
    )?;
    Ok(reviewer_key_ref(&signing_key.verifying_key()))
}

fn check_caller() -> JanusResult<()> {
    if rustix::process::getuid() != rustix::process::geteuid() {
        return Err(identity_error(
            "identity_admin_caller_invalid",
            "identity administration must not run with elevated effective credentials",
        ));
    }
    Ok(())
}

pub(crate) fn current_euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// `O_NOFOLLOW | O_CLOEXEC` for `OpenOptions::custom_flags`.
pub(crate) fn private_open_flags() -> i32 {
    (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC).bits() as i32
}

fn status_str(status: SubjectRegistryStatus) -> &'static str {
    match status {
        SubjectRegistryStatus::Active => "active",
        SubjectRegistryStatus::Revoked => "revoked",
    }
}

fn valid_prefixed_hex(value: &str, prefix: &str, length: usize) -> bool {
    value
        .strip_prefix(prefix)
        .is_some_and(|hex| hex.len() == length && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn valid_sha256(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn identity_error(reason_code: &'static str, detail: impl Into<String>) -> JanusError {
    JanusError::policy_denied(reason_code, detail)
}

fn unavailable(detail: impl Into<String>) -> JanusError {
    JanusError::StoreUnavailable {
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;
    use tempfile::TempDir;

    fn private_dir() -> TempDir {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    struct Fixture {
        _directory: TempDir,
        registry_root: PathBuf,
        signing_key: PathBuf,
        verifying_key: PathBuf,
        audit: PathBuf,
        scratch: PathBuf,
    }

    fn fixture() -> Fixture {
        let directory = private_dir();
        let registry_root = directory.path().join("registry");
        fs::create_dir(&registry_root).unwrap();
        fs::set_permissions(&registry_root, fs::Permissions::from_mode(0o700)).unwrap();
        let keys = directory.path().join("keys");
        fs::create_dir(&keys).unwrap();
        fs::set_permissions(&keys, fs::Permissions::from_mode(0o700)).unwrap();
        let signing_key = keys.join("review.key");
        let verifying_key = keys.join("review.pub");
        provision_review_keys(&signing_key, &verifying_key).unwrap();
        let scratch = directory.path().join("scratch");
        fs::create_dir(&scratch).unwrap();
        fs::set_permissions(&scratch, fs::Permissions::from_mode(0o700)).unwrap();
        Fixture {
            audit: directory.path().join("identity-admin.jsonl"),
            _directory: directory,
            registry_root,
            signing_key,
            verifying_key,
            scratch,
        }
    }

    fn admin(fixture: &Fixture, posture: &str) -> IdentityAdmin {
        IdentityAdmin::new(
            &fixture.registry_root,
            "fixture-host",
            &fixture.verifying_key,
            &fixture.audit,
            PostureSource::Explicit(posture.to_string()),
        )
        .unwrap()
    }

    fn evidence(
        fixture: &Fixture,
        name: &str,
        request: serde_json::Value,
        now: SystemTime,
    ) -> PathBuf {
        let request_file = fixture.scratch.join(format!("{name}.request.json"));
        fs::write(&request_file, serde_json::to_vec(&request).unwrap()).unwrap();
        let out = fixture.scratch.join(format!("{name}.evidence.json"));
        sign_review_request(&request_file, &fixture.signing_key, &out, now).unwrap();
        out
    }

    fn enroll_request(uid: u32, class: &str, trust_domain: &str) -> serde_json::Value {
        serde_json::json!({
            "schema_version": 1,
            "verb": "enroll",
            "trust_domain": trust_domain,
            "local_uid": uid,
            "subject_class": class,
            "ttl_seconds": 600,
            "reviewer": "NIX-377 synthetic review"
        })
    }

    fn reason(error: JanusError) -> String {
        match error {
            JanusError::PolicyDenied { reason_code, .. } => reason_code.to_string(),
            other => format!("{other}"),
        }
    }

    fn audit_lines(fixture: &Fixture) -> Vec<serde_json::Value> {
        fs::read_to_string(&fixture.audit)
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[test]
    fn enroll_revoke_list_round_trip_is_audited_and_value_free() {
        let fixture = fixture();
        let admin = admin(&fixture, "accountability_legacy");
        let now = SystemTime::now();

        let outcome = admin
            .enroll(
                &evidence(
                    &fixture,
                    "e1",
                    enroll_request(65532, "system", "fixture-host"),
                    now,
                ),
                now,
            )
            .unwrap();
        assert!(outcome.ok && !outcome.value_returned);
        let subject_ref = outcome.subject_ref.clone().unwrap();
        assert!(subject_ref.starts_with("act_"));
        assert_eq!(outcome.status.as_deref(), Some("active"));
        let rendered = serde_json::to_string(&outcome).unwrap();
        assert!(!rendered.contains("65532"));

        let listed = admin.list().unwrap();
        let entries = listed.entries.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].subject_ref, subject_ref);
        assert_eq!(entries[0].status, "active");
        assert_eq!(entries[0].subject_class, "system");

        let revoke = serde_json::json!({
            "schema_version": 1,
            "verb": "revoke",
            "trust_domain": "fixture-host",
            "subject_ref": subject_ref,
            "ttl_seconds": 600,
            "reviewer": "NIX-377 synthetic revocation"
        });
        let outcome = admin
            .revoke(&evidence(&fixture, "r1", revoke, now), now)
            .unwrap();
        assert_eq!(outcome.status.as_deref(), Some("revoked"));
        let entries = admin.list().unwrap().entries.unwrap();
        assert_eq!(entries[0].status, "revoked");
        assert!(fixture
            .registry_root
            .join(format!("{subject_ref}.json"))
            .exists());
        assert!(fixture
            .registry_root
            .join(format!("{subject_ref}.revoked.json"))
            .exists());

        let lines = audit_lines(&fixture);
        assert_eq!(lines.len(), 4);
        assert_eq!(lines[0]["outcome"], "authorized");
        assert_eq!(lines[1]["outcome"], "applied");
        assert_eq!(lines[2]["outcome"], "authorized");
        assert_eq!(lines[3]["outcome"], "applied");
        assert_eq!(lines[1]["target_subject_ref"], subject_ref);
        let audit_text = fs::read_to_string(&fixture.audit).unwrap();
        assert!(!audit_text.contains("65532") && !audit_text.contains("synthetic"));
        assert!(lines.iter().all(|line| line["value_returned"] == false));
    }

    #[test]
    fn tampered_replayed_expired_and_foreign_evidence_mutate_nothing() {
        let fixture = fixture();
        let admin = admin(&fixture, "accountability_legacy");
        let now = SystemTime::now();
        let good = evidence(
            &fixture,
            "good",
            enroll_request(1001, "workload", "fixture-host"),
            now,
        );

        // Tampered payload: signature no longer verifies.
        let mut envelope: ReviewEnvelopeV1 =
            serde_json::from_slice(&fs::read(&good).unwrap()).unwrap();
        envelope.local_uid = Some(1002);
        let tampered = fixture.scratch.join("tampered.json");
        fs::write(&tampered, serde_json::to_vec(&envelope).unwrap()).unwrap();
        assert_eq!(
            reason(admin.enroll(&tampered, now).unwrap_err()),
            "identity_review_signature_invalid"
        );

        // Wrong trust domain and wrong verb are context mismatches.
        let other_domain = evidence(
            &fixture,
            "domain",
            enroll_request(1001, "workload", "other-host"),
            now,
        );
        assert_eq!(
            reason(admin.enroll(&other_domain, now).unwrap_err()),
            "identity_review_context_mismatch"
        );
        assert_eq!(
            reason(admin.revoke(&good, now).unwrap_err()),
            "identity_review_context_mismatch"
        );

        // Foreign reviewer key.
        let foreign_key = fixture.scratch.join("foreign.key");
        let request_file = fixture.scratch.join("foreign.request.json");
        fs::write(
            &request_file,
            serde_json::to_vec(&enroll_request(1001, "workload", "fixture-host")).unwrap(),
        )
        .unwrap();
        let foreign = fixture.scratch.join("foreign.evidence.json");
        sign_review_request(&request_file, &foreign_key, &foreign, now).unwrap();
        assert_eq!(
            reason(admin.enroll(&foreign, now).unwrap_err()),
            "identity_review_context_mismatch"
        );

        // Expired.
        assert_eq!(
            reason(
                admin
                    .enroll(&good, now + Duration::from_secs(601))
                    .unwrap_err()
            ),
            "identity_review_expired"
        );

        // Enforced posture refuses mutations but still lists.
        let enforced = admin_with(&fixture, "enforced_recorded");
        assert_eq!(
            reason(enforced.enroll(&good, now).unwrap_err()),
            "identity_posture_mutation_forbidden"
        );
        assert!(enforced.list().is_ok());

        assert!(admin.list().unwrap().entries.unwrap().is_empty());
        let denied_only = audit_lines(&fixture);
        assert!(denied_only.iter().all(|line| line["outcome"] != "applied"));

        // The good evidence works once and is then replayed.
        admin.enroll(&good, now).unwrap();
        assert_eq!(
            reason(admin.enroll(&good, now).unwrap_err()),
            "identity_review_replayed"
        );
        assert_eq!(admin.list().unwrap().entries.unwrap().len(), 1);
    }

    fn admin_with(fixture: &Fixture, posture: &str) -> IdentityAdmin {
        admin(fixture, posture)
    }

    #[test]
    fn lifecycle_lock_blocks_mutation_while_broker_runs_but_not_list() {
        let fixture = fixture();
        let admin = admin(&fixture, "accountability_legacy");
        let now = SystemTime::now();
        let broker = hold_shared_lifecycle_lock(&fixture.registry_root).unwrap();
        let good = evidence(
            &fixture,
            "locked",
            enroll_request(2001, "system", "fixture-host"),
            now,
        );
        assert_eq!(
            reason(admin.enroll(&good, now).unwrap_err()),
            "identity_broker_running"
        );
        assert!(admin.list().is_ok());
        assert!(
            audit_lines(&fixture).is_empty(),
            "no write-ahead event before the lock is held"
        );
        drop(broker);
        admin.enroll(&good, now).unwrap();
        assert!(hold_shared_lifecycle_lock(&fixture.registry_root).is_ok());
    }

    #[test]
    fn registry_and_audit_security_are_prerequisites() {
        let fixture = fixture();
        let now = SystemTime::now();
        let good = evidence(
            &fixture,
            "sec",
            enroll_request(3001, "system", "fixture-host"),
            now,
        );

        fs::set_permissions(&fixture.registry_root, fs::Permissions::from_mode(0o750)).unwrap();
        let admin = admin(&fixture, "accountability_legacy");
        assert_eq!(
            reason(admin.enroll(&good, now).unwrap_err()),
            "identity_registry_security_invalid"
        );
        fs::set_permissions(&fixture.registry_root, fs::Permissions::from_mode(0o700)).unwrap();

        let missing = IdentityAdmin::new(
            fixture.registry_root.join("missing"),
            "fixture-host",
            &fixture.verifying_key,
            &fixture.audit,
            PostureSource::Explicit("accountability_legacy".to_string()),
        )
        .unwrap();
        assert_eq!(
            reason(missing.enroll(&good, now).unwrap_err()),
            "identity_registry_security_invalid"
        );

        let unwritable_audit = IdentityAdmin::new(
            &fixture.registry_root,
            "fixture-host",
            &fixture.verifying_key,
            fixture.scratch.join("nope").join("audit.jsonl"),
            PostureSource::Explicit("accountability_legacy".to_string()),
        )
        .unwrap();
        assert_eq!(
            reason(unwritable_audit.enroll(&good, now).unwrap_err()),
            "identity_admin_audit_unavailable"
        );
        assert!(admin.list().unwrap().entries.unwrap().is_empty());

        let symlinked = fixture.scratch.join("link.json");
        std::os::unix::fs::symlink(&good, &symlinked).unwrap();
        assert_eq!(
            reason(admin.enroll(&symlinked, now).unwrap_err()),
            "identity_review_invalid"
        );
    }

    #[test]
    fn accountability_config_file_is_pinned_and_parsed() {
        let fixture = fixture();
        let config = fixture.scratch.join("accountability.json");
        fs::write(
            &config,
            br#"{"schema_version":1,"posture":"authenticated_observe"}"#,
        )
        .unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            load_accountability_config(&config).unwrap(),
            AccountabilityPosture::AuthenticatedObserve
        );
        fs::set_permissions(&config, fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(
            reason(load_accountability_config(&config).unwrap_err()),
            "identity_posture_unknown"
        );
        let _ = UNIX_EPOCH;
    }
}
