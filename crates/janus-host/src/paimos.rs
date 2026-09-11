//! One-shot Paimos external-stage dependency reporting.
//!
//! This adapter has no listener, daemon loop, command execution, callback, or
//! value-bearing evidence surface. A root-owned fixed configuration binds one
//! Janus dependency handoff to one positive authorization or credential-handoff
//! fact. Exact request bytes are journaled before each mutation and replayed
//! unchanged after an ambiguous transport failure.

use std::collections::HashSet;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use fs2::FileExt;
use serde::de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;
use zeroize::Zeroizing;

use super::{atomic_write, read_private_regular};

/// Frozen Paimos external-stage contract major.
pub const PAIMOS_EXTERNAL_STAGE_SCHEMA_MAJOR: u8 = 1;
/// Frozen Paimos release carrying the external-stage v1 contract.
pub const PAIMOS_EXTERNAL_STAGE_RELEASE: &str = "v5.11.0";
/// Certified Paimos commit for the frozen external-stage v1 contract.
pub const PAIMOS_EXTERNAL_STAGE_COMMIT: &str = "e5f4c86bc061775c853d5847e8fb8bb7e3a31c34";
/// Domain-separated canonical owner/dependency fixture-set digest.
pub const PAIMOS_EXTERNAL_STAGE_FIXTURE_DIGEST: &str =
    "sha256:0318f4025902c9d5dd790384950cc9daebb16e02e79a4a90ce7dddc673e68bed";

const MEDIA_TYPE: &str = "application/vnd.paimos.external-stage.v1+json";
const HANDOFF_SECRET_HEADER: &str = "X-PAIMOS-Handoff-Secret";
const CONFIG_SCHEMA: &str = "inspr.janus.paimos-dependency-reporter-config.v1";
const BINDING_SCHEMA: &str = "inspr.janus.paimos-dependency-reporter-binding.v1";
const MANAGED_CONFIG_SCHEMA: &str = "inspr.janus.paimos-managed-completion-reporter-config.v1";
const MANAGED_BINDING_SCHEMA: &str = "inspr.janus.paimos-managed-completion-reporter-binding.v1";
const JOURNAL_SCHEMA: &str = "inspr.janus.paimos-dependency-reporter-journal.v1";
pub(crate) const SYSTEM_CONFIG_PATH: &str = "/run/janus-paimos-dependency-reporter/config.json";
const MAX_CONFIG_BYTES: usize = 32 * 1024;
const MAX_API_KEY_BYTES: usize = 4 * 1024;
const MAX_CA_BUNDLE_BYTES: usize = 256 * 1024;
const MAX_CA_CERTIFICATES: usize = 32;
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_JOURNAL_BYTES: usize = 128 * 1024;
const IDEMPOTENCY_DOMAIN: &[u8] = b"inspr.janus.paimos-external-stage.idempotency.v1\0";

/// Stable value-free adapter failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaimosReporterError {
    reason_code: &'static str,
}

impl PaimosReporterError {
    fn new(reason_code: &'static str) -> Self {
        Self { reason_code }
    }

    /// Stable reason code that never contains a path, credential, URL, or body.
    pub fn reason_code(self) -> &'static str {
        self.reason_code
    }
}

impl fmt::Display for PaimosReporterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code)
    }
}

impl std::error::Error for PaimosReporterError {}

type ReporterResult<T> = Result<T, PaimosReporterError>;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReporterConfigV1 {
    schema: String,
    schema_version: u8,
    paimos_origin: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    paimos_ca_file: Option<String>,
    handoff_id: String,
    api_key_file: String,
    handoff_secret_file: String,
    journal_directory: String,
    expected: ExpectedBindingV1,
    evidence: DependencyEvidenceV1,
}

/// Root-owned authority for the managed-transaction completion mode. Unlike
/// the legacy static config, this never predicts an evidence timestamp. The
/// timestamp is supplied later by the separately validated durable record.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedReporterConfigV1 {
    schema: String,
    schema_version: u8,
    paimos_origin: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    paimos_ca_file: Option<String>,
    handoff_id: String,
    api_key_file: String,
    handoff_secret_file: String,
    journal_directory: String,
    expected: ExpectedBindingV1,
    evidence: ManagedEvidencePolicyV1,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ManagedEvidencePolicyV1 {
    kind: String,
    source: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ExpectedBindingV1 {
    dependency_key: String,
    stage_key: StageKey,
    execution_number: i64,
    plan_digest: String,
    predecessor_digest: String,
    authority_epoch: i64,
    context_digest: String,
    credential_epoch: i64,
    expires_at: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum StageKey {
    Specification,
    Implementation,
    Qa,
    Deployment,
    Verification,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum DependencyEvidenceV1 {
    Authorization { observed_at: String },
    CredentialHandoff { observed_at: String },
}

impl DependencyEvidenceV1 {
    fn kind(&self) -> EvidenceKind {
        match self {
            Self::Authorization { .. } => EvidenceKind::Authorization,
            Self::CredentialHandoff { .. } => EvidenceKind::CredentialHandoff,
        }
    }

    fn observed_at(&self) -> &str {
        match self {
            Self::Authorization { observed_at } | Self::CredentialHandoff { observed_at } => {
                observed_at
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ReporterClass {
    Pharos,
    Janus,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ReporterRole {
    Owner,
    Dependency,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum HandoffState {
    Issued,
    Accepted,
    Active,
    Waiting,
    Blocked,
    Succeeded,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum EvidenceKind {
    Deployment,
    Verification,
    Authorization,
    CredentialHandoff,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PullResponseV1 {
    handoff_id: String,
    contract_major: u8,
    fixture_digest: String,
    credential_epoch: i64,
    expires_at: String,
    state: HandoffState,
    reporter_class: ReporterClass,
    reporter_role: ReporterRole,
    dependency_key: String,
    evidence_ceiling: Vec<EvidenceKind>,
    stage_key: StageKey,
    execution_number: i64,
    plan_digest: String,
    predecessor_digest: String,
    authority_epoch: i64,
    context_digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AcceptRequestV1 {
    sequence: i64,
    observed_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReportRequestV1 {
    sequence: i64,
    state: HandoffState,
    observed_at: String,
    heartbeat: bool,
    janus_evidence: JanusEvidenceV1,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct JanusEvidenceV1 {
    kind: EvidenceKind,
    result: EvidenceResult,
    #[serde(skip_serializing_if = "Option::is_none")]
    authorized: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    credential_ready: Option<bool>,
    observed_at: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum EvidenceResult {
    Satisfied,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReportReceiptV1 {
    handoff_id: String,
    sequence: i64,
    state: HandoffState,
    credential_epoch: i64,
    duplicate: bool,
    server_received_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RequestJournalV1 {
    sequence: i64,
    request_digest: String,
    idempotency_key: String,
    body: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReporterJournalV1 {
    schema: String,
    schema_version: u8,
    contract_major: u8,
    fixture_digest: String,
    paimos_commit: String,
    paimos_release: String,
    handoff_id: String,
    config_digest: String,
    accept: RequestJournalV1,
    accepted: Option<ReportReceiptV1>,
    report: Option<RequestJournalV1>,
    completed: Option<ReportReceiptV1>,
}

/// Value-free fingerprint and expected tuple for one already-installed
/// reporter configuration. This grants no Paimos authority: execution still
/// reads the fixed root-owned config and Paimos validates the live handoff.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PaimosReporterBindingV1 {
    schema: String,
    schema_version: u8,
    config_digest: String,
    handoff_id: String,
    dependency_key: String,
    stage_key: String,
    execution_number: i64,
    plan_digest: String,
    predecessor_digest: String,
    authority_epoch: i64,
    context_digest: String,
    credential_epoch: i64,
    expires_at: String,
    evidence_kind: String,
    evidence_observed_at: String,
}

/// Value-free fingerprint and exact Paimos tuple for one immutable managed
/// completion configuration. It carries no timestamp and grants no Paimos
/// authority without the protected config, credentials, and live handoff.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PaimosManagedCompletionBindingV1 {
    pub(crate) schema: String,
    pub(crate) schema_version: u8,
    pub(crate) config_digest: String,
    pub(crate) handoff_id: String,
    pub(crate) dependency_key: String,
    pub(crate) stage_key: String,
    pub(crate) execution_number: i64,
    pub(crate) plan_digest: String,
    pub(crate) predecessor_digest: String,
    pub(crate) authority_epoch: i64,
    pub(crate) context_digest: String,
    pub(crate) credential_epoch: i64,
    pub(crate) expires_at: String,
    pub(crate) evidence_kind: String,
    pub(crate) evidence_source: String,
}

struct Credentials {
    authorization: Zeroizing<String>,
    handoff_header: Zeroizing<String>,
}

struct Reporter {
    config: ReporterConfigV1,
    config_digest: String,
    credentials: Credentials,
    http: ureq::Agent,
    origin: String,
    journal_path: PathBuf,
    owner_uid: u32,
    _lock: File,
}

/// Read the fixed root-owned request and execute at most one dependency report.
pub fn run_from_system() -> ReporterResult<()> {
    let config = load_system_config()?;
    Reporter::new(config, 0, false)?.run()
}

/// Confirm that the fixed root-owned reporter config is exactly the reviewed
/// value-free binding. Credentials are not opened and no network call occurs.
pub fn validate_system_binding(binding: &PaimosReporterBindingV1) -> ReporterResult<()> {
    let config = load_system_config()?;
    validate_config(&config, false)?;
    validate_reporter_binding(&config, binding, false)
}

/// Run the existing one-shot reporter only if its fixed root-owned config is
/// byte-semantically identical to the reviewed value-free binding.
pub fn run_from_system_if_bound(binding: &PaimosReporterBindingV1) -> ReporterResult<()> {
    let config = load_system_config()?;
    run_bound_config(config, binding, 0, false)
}

pub(crate) fn run_managed_completion_from_path(
    path: &Path,
    binding: &PaimosManagedCompletionBindingV1,
    observed_at: String,
    owner_uid: u32,
    allow_loopback_http: bool,
) -> ReporterResult<()> {
    let config = load_managed_config(path, owner_uid)?;
    run_managed_bound_config(config, binding, observed_at, owner_uid, allow_loopback_http)
}

fn load_system_config() -> ReporterResult<ReporterConfigV1> {
    let raw = read_private_regular(
        Path::new(SYSTEM_CONFIG_PATH),
        MAX_CONFIG_BYTES,
        Some(0),
        "paimos_reporter_config_unavailable",
    )
    .map_err(|_| PaimosReporterError::new("paimos_reporter_config_unavailable"))?;
    decode_strict::<ReporterConfigV1>(&raw, "paimos_reporter_config_invalid")
}

fn load_managed_config(path: &Path, owner_uid: u32) -> ReporterResult<ManagedReporterConfigV1> {
    let raw = read_private_regular(
        path,
        MAX_CONFIG_BYTES,
        Some(owner_uid),
        "paimos_reporter_config_unavailable",
    )
    .map_err(|_| PaimosReporterError::new("paimos_reporter_config_unavailable"))?;
    decode_strict::<ManagedReporterConfigV1>(&raw, "paimos_reporter_config_invalid")
}

fn reporter_binding(
    config: &ReporterConfigV1,
    allow_loopback_http: bool,
) -> ReporterResult<PaimosReporterBindingV1> {
    validate_config(config, allow_loopback_http)?;
    let canonical = serde_json::to_vec(config)
        .map_err(|_| PaimosReporterError::new("paimos_reporter_config_invalid"))?;
    Ok(PaimosReporterBindingV1 {
        schema: BINDING_SCHEMA.to_string(),
        schema_version: 1,
        config_digest: wire_digest(&canonical),
        handoff_id: config.handoff_id.clone(),
        dependency_key: config.expected.dependency_key.clone(),
        stage_key: stage_key_name(config.expected.stage_key).to_string(),
        execution_number: config.expected.execution_number,
        plan_digest: config.expected.plan_digest.clone(),
        predecessor_digest: config.expected.predecessor_digest.clone(),
        authority_epoch: config.expected.authority_epoch,
        context_digest: config.expected.context_digest.clone(),
        credential_epoch: config.expected.credential_epoch,
        expires_at: config.expected.expires_at.clone(),
        evidence_kind: evidence_kind_name(config.evidence.kind()).to_string(),
        evidence_observed_at: config.evidence.observed_at().to_string(),
    })
}

pub(crate) fn managed_reporter_binding(
    config: &ManagedReporterConfigV1,
    allow_loopback_http: bool,
) -> ReporterResult<PaimosManagedCompletionBindingV1> {
    validate_managed_config(config, allow_loopback_http)?;
    let canonical = canonical_json_bytes(config)?;
    Ok(PaimosManagedCompletionBindingV1 {
        schema: MANAGED_BINDING_SCHEMA.to_string(),
        schema_version: 1,
        config_digest: wire_digest(&canonical),
        handoff_id: config.handoff_id.clone(),
        dependency_key: config.expected.dependency_key.clone(),
        stage_key: stage_key_name(config.expected.stage_key).to_string(),
        execution_number: config.expected.execution_number,
        plan_digest: config.expected.plan_digest.clone(),
        predecessor_digest: config.expected.predecessor_digest.clone(),
        authority_epoch: config.expected.authority_epoch,
        context_digest: config.expected.context_digest.clone(),
        credential_epoch: config.expected.credential_epoch,
        expires_at: config.expected.expires_at.clone(),
        evidence_kind: config.evidence.kind.clone(),
        evidence_source: config.evidence.source.clone(),
    })
}

/// Serialize the managed-completion authority with recursively sorted object
/// keys and no insignificant whitespace. This is deliberately the same byte
/// shape as Nix `builtins.toJSON` for this closed schema (strings, booleans,
/// non-negative integers, arrays, objects, and null; no floating-point data).
pub(crate) fn canonical_json_bytes<T: Serialize>(value: &T) -> ReporterResult<Vec<u8>> {
    let value = serde_json::to_value(value)
        .map_err(|_| PaimosReporterError::new("paimos_reporter_config_invalid"))?;
    let mut output = Vec::new();
    write_canonical_json(&value, &mut output)?;
    Ok(output)
}

fn write_canonical_json(value: &serde_json::Value, output: &mut Vec<u8>) -> ReporterResult<()> {
    match value {
        serde_json::Value::Null => output.extend_from_slice(b"null"),
        serde_json::Value::Bool(value) => {
            output.extend_from_slice(if *value { &b"true"[..] } else { &b"false"[..] })
        }
        serde_json::Value::Number(value) => {
            if !value.is_i64() && !value.is_u64() {
                return Err(PaimosReporterError::new("paimos_reporter_config_invalid"));
            }
            output.extend_from_slice(value.to_string().as_bytes());
        }
        serde_json::Value::String(value) => {
            let encoded = serde_json::to_string(value)
                .map_err(|_| PaimosReporterError::new("paimos_reporter_config_invalid"))?;
            output.extend_from_slice(encoded.as_bytes());
        }
        serde_json::Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_json(value, output)?;
            }
            output.push(b']');
        }
        serde_json::Value::Object(values) => {
            output.push(b'{');
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                let encoded = serde_json::to_string(key)
                    .map_err(|_| PaimosReporterError::new("paimos_reporter_config_invalid"))?;
                output.extend_from_slice(encoded.as_bytes());
                output.push(b':');
                write_canonical_json(&values[key], output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn validate_managed_reporter_binding(
    config: &ManagedReporterConfigV1,
    binding: &PaimosManagedCompletionBindingV1,
    allow_loopback_http: bool,
) -> ReporterResult<()> {
    if managed_reporter_binding(config, allow_loopback_http)? != *binding {
        return Err(PaimosReporterError::new("paimos_reporter_binding_refused"));
    }
    Ok(())
}

pub(crate) fn validate_managed_reporter_binding_shape(
    binding: &PaimosManagedCompletionBindingV1,
) -> ReporterResult<()> {
    if binding.schema != MANAGED_BINDING_SCHEMA
        || binding.schema_version != 1
        || !valid_wire_digest(&binding.config_digest)
        || !valid_handoff_id(&binding.handoff_id)
        || !valid_symbol(&binding.dependency_key)
        || binding.stage_key != "deployment"
        || binding.execution_number <= 0
        || !valid_wire_digest(&binding.plan_digest)
        || !valid_wire_digest(&binding.predecessor_digest)
        || binding.authority_epoch <= 0
        || !valid_wire_digest(&binding.context_digest)
        || binding.credential_epoch <= 0
        || !valid_timestamp(&binding.expires_at)
        || binding.evidence_kind != "credential_handoff"
        || binding.evidence_source != "managed_completion_record"
    {
        return Err(PaimosReporterError::new("paimos_reporter_binding_refused"));
    }
    Ok(())
}

fn validate_reporter_binding(
    config: &ReporterConfigV1,
    binding: &PaimosReporterBindingV1,
    allow_loopback_http: bool,
) -> ReporterResult<()> {
    if reporter_binding(config, allow_loopback_http)? != *binding {
        return Err(PaimosReporterError::new("paimos_reporter_binding_refused"));
    }
    Ok(())
}

fn run_bound_config(
    config: ReporterConfigV1,
    binding: &PaimosReporterBindingV1,
    owner_uid: u32,
    allow_loopback_http: bool,
) -> ReporterResult<()> {
    validate_reporter_binding(&config, binding, allow_loopback_http)?;
    Reporter::new(config, owner_uid, allow_loopback_http)?.run()
}

fn run_managed_bound_config(
    config: ManagedReporterConfigV1,
    binding: &PaimosManagedCompletionBindingV1,
    observed_at: String,
    owner_uid: u32,
    allow_loopback_http: bool,
) -> ReporterResult<()> {
    validate_managed_reporter_binding(&config, binding, allow_loopback_http)?;
    if !valid_timestamp(&observed_at) {
        return Err(PaimosReporterError::new("paimos_reporter_evidence_invalid"));
    }
    let runtime = ReporterConfigV1 {
        schema: CONFIG_SCHEMA.to_string(),
        schema_version: 1,
        paimos_origin: config.paimos_origin,
        paimos_ca_file: config.paimos_ca_file,
        handoff_id: config.handoff_id,
        api_key_file: config.api_key_file,
        handoff_secret_file: config.handoff_secret_file,
        journal_directory: config.journal_directory,
        expected: config.expected,
        evidence: DependencyEvidenceV1::CredentialHandoff { observed_at },
    };
    Reporter::new(runtime, owner_uid, allow_loopback_http)?.run()
}

fn stage_key_name(stage: StageKey) -> &'static str {
    match stage {
        StageKey::Specification => "specification",
        StageKey::Implementation => "implementation",
        StageKey::Qa => "qa",
        StageKey::Deployment => "deployment",
        StageKey::Verification => "verification",
    }
}

fn evidence_kind_name(kind: EvidenceKind) -> &'static str {
    match kind {
        EvidenceKind::Deployment => "deployment",
        EvidenceKind::Verification => "verification",
        EvidenceKind::Authorization => "authorization",
        EvidenceKind::CredentialHandoff => "credential_handoff",
    }
}

impl Reporter {
    fn new(
        config: ReporterConfigV1,
        owner_uid: u32,
        allow_loopback_http: bool,
    ) -> ReporterResult<Self> {
        validate_config(&config, allow_loopback_http)?;
        let origin = normalized_origin(&config.paimos_origin, allow_loopback_http)?;
        let config_digest = wire_digest(
            &serde_json::to_vec(&config)
                .map_err(|_| PaimosReporterError::new("paimos_reporter_config_invalid"))?,
        );
        let credentials = read_credentials(&config, owner_uid)?;
        let journal_directory = Path::new(&config.journal_directory);
        validate_private_directory(journal_directory, owner_uid)?;
        let journal_path = journal_directory.join(format!("{}.json", config.handoff_id));
        let lock = acquire_lock(journal_directory, &config.handoff_id, owner_uid)?;
        let http = build_http_agent(config.paimos_ca_file.as_deref(), owner_uid)?;
        Ok(Self {
            config,
            config_digest,
            credentials,
            http,
            origin,
            journal_path,
            owner_uid,
            _lock: lock,
        })
    }

    fn run(&self) -> ReporterResult<()> {
        let mut journal = match self.load_journal()? {
            Some(journal) => journal,
            None => {
                let pulled = self.pull()?;
                self.validate_pull(&pulled)?;
                if pulled.state != HandoffState::Issued {
                    return Err(PaimosReporterError::new("paimos_reporter_sequence_refused"));
                }
                let journal = self.initial_journal()?;
                self.persist_journal(&journal)?;
                journal
            }
        };
        self.validate_journal(&journal)?;

        if journal.accepted.is_none() {
            let receipt = self.send_mutation("accept", &journal.accept, &[200, 201])?;
            self.validate_receipt(&receipt, 1, HandoffState::Accepted)?;
            journal.accepted = Some(receipt);
            self.persist_journal(&journal)?;
        }

        if journal.report.is_none() {
            journal.report = Some(self.report_journal()?);
            self.persist_journal(&journal)?;
        }

        if journal.completed.is_none() {
            let report = journal
                .report
                .as_ref()
                .ok_or_else(|| PaimosReporterError::new("paimos_reporter_journal_invalid"))?;
            let receipt = self.send_mutation("reports", report, &[200, 201])?;
            self.validate_receipt(&receipt, 2, HandoffState::Succeeded)?;
            journal.completed = Some(receipt);
            self.persist_journal(&journal)?;
        }
        Ok(())
    }

    fn pull(&self) -> ReporterResult<PullResponseV1> {
        let url = format!(
            "{}/api/external-stage/handoffs/{}",
            self.origin, self.config.handoff_id
        );
        let response = self
            .http
            .get(&url)
            .set("Accept", MEDIA_TYPE)
            .set("Accept-Encoding", "identity")
            .set("Authorization", self.credentials.authorization.as_str())
            .set(
                HANDOFF_SECRET_HEADER,
                self.credentials.handoff_header.as_str(),
            )
            .call();
        let response = accept_http_status(response, &[200])?;
        decode_response(response)
    }

    fn send_mutation(
        &self,
        action: &str,
        request: &RequestJournalV1,
        statuses: &[u16],
    ) -> ReporterResult<ReportReceiptV1> {
        let url = format!(
            "{}/api/external-stage/handoffs/{}/{}",
            self.origin, self.config.handoff_id, action
        );
        let response = self
            .http
            .post(&url)
            .set("Accept", MEDIA_TYPE)
            .set("Accept-Encoding", "identity")
            .set("Content-Type", MEDIA_TYPE)
            .set("Authorization", self.credentials.authorization.as_str())
            .set(
                HANDOFF_SECRET_HEADER,
                self.credentials.handoff_header.as_str(),
            )
            .set("Idempotency-Key", &request.idempotency_key)
            .send_bytes(request.body.as_bytes());
        let response = accept_http_status(response, statuses)?;
        let status = response.status();
        let receipt: ReportReceiptV1 = decode_response(response)?;
        if (status == 200) != receipt.duplicate || (status == 201) == receipt.duplicate {
            return Err(PaimosReporterError::new("paimos_reporter_receipt_invalid"));
        }
        Ok(receipt)
    }

    fn validate_pull(&self, response: &PullResponseV1) -> ReporterResult<()> {
        let expected = &self.config.expected;
        if response.handoff_id != self.config.handoff_id
            || response.contract_major != PAIMOS_EXTERNAL_STAGE_SCHEMA_MAJOR
            || response.fixture_digest != PAIMOS_EXTERNAL_STAGE_FIXTURE_DIGEST
            || response.credential_epoch != expected.credential_epoch
            || response.expires_at != expected.expires_at
            || response.reporter_class != ReporterClass::Janus
            || response.reporter_role != ReporterRole::Dependency
            || response.dependency_key != expected.dependency_key
            || response.evidence_ceiling != [self.config.evidence.kind()]
            || response.stage_key != expected.stage_key
            || response.execution_number != expected.execution_number
            || response.plan_digest != expected.plan_digest
            || response.predecessor_digest != expected.predecessor_digest
            || response.authority_epoch != expected.authority_epoch
            || response.context_digest != expected.context_digest
        {
            return Err(PaimosReporterError::new("paimos_reporter_binding_refused"));
        }
        Ok(())
    }

    fn initial_journal(&self) -> ReporterResult<ReporterJournalV1> {
        let accept = AcceptRequestV1 {
            sequence: 1,
            observed_at: self.config.evidence.observed_at().to_string(),
        };
        Ok(ReporterJournalV1 {
            schema: JOURNAL_SCHEMA.to_string(),
            schema_version: 1,
            contract_major: PAIMOS_EXTERNAL_STAGE_SCHEMA_MAJOR,
            fixture_digest: PAIMOS_EXTERNAL_STAGE_FIXTURE_DIGEST.to_string(),
            paimos_commit: PAIMOS_EXTERNAL_STAGE_COMMIT.to_string(),
            paimos_release: PAIMOS_EXTERNAL_STAGE_RELEASE.to_string(),
            handoff_id: self.config.handoff_id.clone(),
            config_digest: self.config_digest.clone(),
            accept: journal_request(&self.config.handoff_id, 1, &accept)?,
            accepted: None,
            report: None,
            completed: None,
        })
    }

    fn report_journal(&self) -> ReporterResult<RequestJournalV1> {
        let observed_at = self.config.evidence.observed_at().to_string();
        let (authorized, credential_ready) = match self.config.evidence.kind() {
            EvidenceKind::Authorization => (Some(true), None),
            EvidenceKind::CredentialHandoff => (None, Some(true)),
            _ => return Err(PaimosReporterError::new("paimos_reporter_evidence_refused")),
        };
        let report = ReportRequestV1 {
            sequence: 2,
            state: HandoffState::Succeeded,
            observed_at: observed_at.clone(),
            heartbeat: false,
            janus_evidence: JanusEvidenceV1 {
                kind: self.config.evidence.kind(),
                result: EvidenceResult::Satisfied,
                authorized,
                credential_ready,
                observed_at,
            },
        };
        journal_request(&self.config.handoff_id, 2, &report)
    }

    fn load_journal(&self) -> ReporterResult<Option<ReporterJournalV1>> {
        match fs::symlink_metadata(&self.journal_path) {
            Ok(_) => {
                let raw = read_private_regular(
                    &self.journal_path,
                    MAX_JOURNAL_BYTES,
                    Some(self.owner_uid),
                    "paimos_reporter_journal_invalid",
                )
                .map_err(|_| PaimosReporterError::new("paimos_reporter_journal_invalid"))?;
                decode_strict(&raw, "paimos_reporter_journal_invalid").map(Some)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(PaimosReporterError::new("paimos_reporter_journal_invalid")),
        }
    }

    fn validate_journal(&self, journal: &ReporterJournalV1) -> ReporterResult<()> {
        let expected = self.initial_journal()?;
        if journal.schema != JOURNAL_SCHEMA
            || journal.schema_version != 1
            || journal.contract_major != PAIMOS_EXTERNAL_STAGE_SCHEMA_MAJOR
            || journal.fixture_digest != PAIMOS_EXTERNAL_STAGE_FIXTURE_DIGEST
            || journal.paimos_commit != PAIMOS_EXTERNAL_STAGE_COMMIT
            || journal.paimos_release != PAIMOS_EXTERNAL_STAGE_RELEASE
            || journal.handoff_id != self.config.handoff_id
            || journal.config_digest != self.config_digest
            || journal.accept != expected.accept
        {
            return Err(PaimosReporterError::new("paimos_reporter_journal_invalid"));
        }
        validate_journal_request(&journal.accept, &self.config.handoff_id, 1)?;
        if let Some(receipt) = journal.accepted.as_ref() {
            self.validate_receipt(receipt, 1, HandoffState::Accepted)?;
        }
        if let Some(report) = journal.report.as_ref() {
            if journal.accepted.is_none() || *report != self.report_journal()? {
                return Err(PaimosReporterError::new("paimos_reporter_journal_invalid"));
            }
            validate_journal_request(report, &self.config.handoff_id, 2)?;
        }
        if let Some(receipt) = journal.completed.as_ref() {
            if journal.report.is_none() {
                return Err(PaimosReporterError::new("paimos_reporter_journal_invalid"));
            }
            self.validate_receipt(receipt, 2, HandoffState::Succeeded)?;
        }
        Ok(())
    }

    fn validate_receipt(
        &self,
        receipt: &ReportReceiptV1,
        sequence: i64,
        state: HandoffState,
    ) -> ReporterResult<()> {
        if receipt.handoff_id != self.config.handoff_id
            || receipt.sequence != sequence
            || receipt.state != state
            || receipt.credential_epoch != self.config.expected.credential_epoch
            || !valid_timestamp(&receipt.server_received_at)
        {
            return Err(PaimosReporterError::new("paimos_reporter_receipt_invalid"));
        }
        Ok(())
    }

    fn persist_journal(&self, journal: &ReporterJournalV1) -> ReporterResult<()> {
        let mut raw = serde_json::to_vec(journal)
            .map_err(|_| PaimosReporterError::new("paimos_reporter_journal_invalid"))?;
        raw.push(b'\n');
        atomic_write(
            &self.journal_path,
            &raw,
            0o600,
            self.owner_uid,
            "paimos_reporter_journal_unavailable",
        )
        .map_err(|_| PaimosReporterError::new("paimos_reporter_journal_unavailable"))
    }
}

fn validate_config(config: &ReporterConfigV1, allow_loopback_http: bool) -> ReporterResult<()> {
    normalized_origin(&config.paimos_origin, allow_loopback_http)?;
    if config.schema != CONFIG_SCHEMA
        || config.schema_version != 1
        || config
            .paimos_ca_file
            .as_deref()
            .is_some_and(|path| !absolute_path(path))
        || !valid_handoff_id(&config.handoff_id)
        || config.api_key_file == config.handoff_secret_file
        || !absolute_path(&config.api_key_file)
        || !absolute_path(&config.handoff_secret_file)
        || !absolute_path(&config.journal_directory)
        || !valid_symbol(&config.expected.dependency_key)
        || config.expected.execution_number <= 0
        || config.expected.authority_epoch <= 0
        || config.expected.credential_epoch <= 0
        || !valid_wire_digest(&config.expected.plan_digest)
        || !valid_wire_digest(&config.expected.predecessor_digest)
        || !valid_wire_digest(&config.expected.context_digest)
        || !valid_timestamp(&config.expected.expires_at)
        || !valid_timestamp(config.evidence.observed_at())
    {
        return Err(PaimosReporterError::new("paimos_reporter_config_invalid"));
    }
    Ok(())
}

fn validate_managed_config(
    config: &ManagedReporterConfigV1,
    allow_loopback_http: bool,
) -> ReporterResult<()> {
    normalized_origin(&config.paimos_origin, allow_loopback_http)?;
    if config.schema != MANAGED_CONFIG_SCHEMA
        || config.schema_version != 1
        || config
            .paimos_ca_file
            .as_deref()
            .is_some_and(|path| !absolute_path(path))
        || !valid_handoff_id(&config.handoff_id)
        || config.api_key_file == config.handoff_secret_file
        || !absolute_path(&config.api_key_file)
        || !absolute_path(&config.handoff_secret_file)
        || !absolute_path(&config.journal_directory)
        || !valid_symbol(&config.expected.dependency_key)
        || config.expected.stage_key != StageKey::Deployment
        || config.expected.execution_number <= 0
        || config.expected.authority_epoch <= 0
        || config.expected.credential_epoch <= 0
        || !valid_wire_digest(&config.expected.plan_digest)
        || !valid_wire_digest(&config.expected.predecessor_digest)
        || !valid_wire_digest(&config.expected.context_digest)
        || !valid_timestamp(&config.expected.expires_at)
        || config.evidence.kind != "credential_handoff"
        || config.evidence.source != "managed_completion_record"
    {
        return Err(PaimosReporterError::new("paimos_reporter_config_invalid"));
    }
    Ok(())
}

fn build_http_agent(ca_file: Option<&str>, owner_uid: u32) -> ReporterResult<ureq::Agent> {
    let mut builder = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(3))
        .timeout_read(Duration::from_secs(8))
        .timeout_write(Duration::from_secs(8))
        .redirects(0);
    if let Some(path) = ca_file {
        let certificates = load_ca_certificates(Path::new(path), owner_uid)?;
        let mut roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        for certificate in certificates {
            roots
                .add(certificate)
                .map_err(|_| PaimosReporterError::new("paimos_reporter_ca_invalid"))?;
        }
        let tls = rustls::ClientConfig::builder_with_provider(
            rustls::crypto::ring::default_provider().into(),
        )
        .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
        .map_err(|_| PaimosReporterError::new("paimos_reporter_ca_invalid"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
        builder = builder.tls_config(Arc::new(tls));
    }
    Ok(builder.build())
}

fn load_ca_certificates(
    path: &Path,
    owner_uid: u32,
) -> ReporterResult<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let mut bytes = Zeroizing::new(
        read_private_regular(
            path,
            MAX_CA_BUNDLE_BYTES,
            Some(owner_uid),
            "paimos_reporter_ca_file_refused",
        )
        .map_err(|_| PaimosReporterError::new("paimos_reporter_ca_file_refused"))?,
    );
    parse_ca_certificates(bytes.as_mut_slice())
}

fn parse_ca_certificates(
    bytes: &[u8],
) -> ReporterResult<Vec<rustls::pki_types::CertificateDer<'static>>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";

    let text = std::str::from_utf8(bytes)
        .map_err(|_| PaimosReporterError::new("paimos_reporter_ca_invalid"))?;
    if !text.is_ascii() {
        return Err(PaimosReporterError::new("paimos_reporter_ca_invalid"));
    }
    let mut in_certificate = false;
    let mut payload_line_seen = false;
    let mut block_count = 0usize;
    for line in text.lines() {
        if !in_certificate {
            if line.is_empty() {
                continue;
            }
            if line != BEGIN {
                return Err(PaimosReporterError::new("paimos_reporter_ca_invalid"));
            }
            in_certificate = true;
            payload_line_seen = false;
            continue;
        }
        if line == END {
            if !payload_line_seen {
                return Err(PaimosReporterError::new("paimos_reporter_ca_invalid"));
            }
            block_count += 1;
            if block_count > MAX_CA_CERTIFICATES {
                return Err(PaimosReporterError::new("paimos_reporter_ca_invalid"));
            }
            in_certificate = false;
            continue;
        }
        if line.is_empty()
            || line.len() > 76
            || !line
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
        {
            return Err(PaimosReporterError::new("paimos_reporter_ca_invalid"));
        }
        payload_line_seen = true;
    }
    if in_certificate || block_count == 0 {
        return Err(PaimosReporterError::new("paimos_reporter_ca_invalid"));
    }

    use rustls::pki_types::pem::PemObject as _;
    let certificates = rustls::pki_types::CertificateDer::pem_slice_iter(bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| PaimosReporterError::new("paimos_reporter_ca_invalid"))?;
    if certificates.len() != block_count {
        return Err(PaimosReporterError::new("paimos_reporter_ca_invalid"));
    }
    let mut parsed_roots = rustls::RootCertStore::empty();
    for certificate in &certificates {
        parsed_roots
            .add(certificate.clone())
            .map_err(|_| PaimosReporterError::new("paimos_reporter_ca_invalid"))?;
    }
    Ok(certificates)
}

fn normalized_origin(raw: &str, allow_loopback_http: bool) -> ReporterResult<String> {
    let parsed =
        Url::parse(raw).map_err(|_| PaimosReporterError::new("paimos_reporter_origin_refused"))?;
    let loopback_http = allow_loopback_http
        && parsed.scheme() == "http"
        && parsed
            .host_str()
            .is_some_and(|host| host == "127.0.0.1" || host == "::1");
    if (parsed.scheme() != "https" && !loopback_http)
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
    {
        return Err(PaimosReporterError::new("paimos_reporter_origin_refused"));
    }
    Ok(parsed.as_str().trim_end_matches('/').to_string())
}

fn read_credentials(config: &ReporterConfigV1, owner_uid: u32) -> ReporterResult<Credentials> {
    let api_path = Path::new(&config.api_key_file);
    let secret_path = Path::new(&config.handoff_secret_file);
    let api_metadata = fs::symlink_metadata(api_path)
        .map_err(|_| PaimosReporterError::new("paimos_reporter_api_key_unavailable"))?;
    let secret_metadata = fs::symlink_metadata(secret_path)
        .map_err(|_| PaimosReporterError::new("paimos_reporter_handoff_secret_unavailable"))?;
    if api_metadata.dev() == secret_metadata.dev() && api_metadata.ino() == secret_metadata.ino() {
        return Err(PaimosReporterError::new(
            "paimos_reporter_credential_custody_refused",
        ));
    }
    let api_raw = Zeroizing::new(
        read_private_regular(
            api_path,
            MAX_API_KEY_BYTES,
            Some(owner_uid),
            "paimos_reporter_api_key_unavailable",
        )
        .map_err(|_| PaimosReporterError::new("paimos_reporter_api_key_unavailable"))?,
    );
    let api_key = Zeroizing::new(
        String::from_utf8(api_raw.to_vec())
            .map_err(|_| PaimosReporterError::new("paimos_reporter_api_key_invalid"))?,
    );
    if !api_key.starts_with("paimos_")
        || api_key.len() < 32
        || !api_key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(PaimosReporterError::new("paimos_reporter_api_key_invalid"));
    }
    let secret = Zeroizing::new(
        read_private_regular(
            secret_path,
            32,
            Some(owner_uid),
            "paimos_reporter_handoff_secret_unavailable",
        )
        .map_err(|_| PaimosReporterError::new("paimos_reporter_handoff_secret_unavailable"))?,
    );
    if secret.len() != 32 {
        return Err(PaimosReporterError::new(
            "paimos_reporter_handoff_secret_invalid",
        ));
    }
    Ok(Credentials {
        authorization: Zeroizing::new(format!("Bearer {}", api_key.as_str())),
        handoff_header: Zeroizing::new(URL_SAFE_NO_PAD.encode(secret.as_slice())),
    })
}

fn validate_private_directory(path: &Path, owner_uid: u32) -> ReporterResult<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| PaimosReporterError::new("paimos_reporter_journal_directory_unavailable"))?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(PaimosReporterError::new(
            "paimos_reporter_journal_directory_refused",
        ));
    }
    Ok(())
}

fn acquire_lock(directory: &Path, handoff_id: &str, owner_uid: u32) -> ReporterResult<File> {
    let path = directory.join(format!(".{handoff_id}.lock"));
    if let Ok(metadata) = fs::symlink_metadata(&path) {
        if !metadata.file_type().is_file()
            || metadata.uid() != owner_uid
            || metadata.nlink() != 1
            || metadata.mode() & 0o777 != 0o600
        {
            return Err(PaimosReporterError::new("paimos_reporter_lock_refused"));
        }
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .map_err(|_| PaimosReporterError::new("paimos_reporter_lock_unavailable"))?;
    let metadata = file
        .metadata()
        .map_err(|_| PaimosReporterError::new("paimos_reporter_lock_unavailable"))?;
    if metadata.uid() != owner_uid || metadata.nlink() != 1 || metadata.mode() & 0o777 != 0o600 {
        return Err(PaimosReporterError::new("paimos_reporter_lock_refused"));
    }
    file.try_lock_exclusive()
        .map_err(|_| PaimosReporterError::new("paimos_reporter_busy"))?;
    Ok(file)
}

fn journal_request<T: Serialize>(
    handoff_id: &str,
    sequence: i64,
    request: &T,
) -> ReporterResult<RequestJournalV1> {
    let body = serde_json::to_vec(request)
        .map_err(|_| PaimosReporterError::new("paimos_reporter_request_invalid"))?;
    let request_digest = Sha256::digest(&body);
    Ok(RequestJournalV1 {
        sequence,
        request_digest: format!("sha256:{request_digest:x}"),
        idempotency_key: derive_idempotency_key(handoff_id, sequence, request_digest.as_slice()),
        body: String::from_utf8(body)
            .map_err(|_| PaimosReporterError::new("paimos_reporter_request_invalid"))?,
    })
}

fn validate_journal_request(
    request: &RequestJournalV1,
    handoff_id: &str,
    sequence: i64,
) -> ReporterResult<()> {
    let digest = Sha256::digest(request.body.as_bytes());
    if request.sequence != sequence
        || request.request_digest != format!("sha256:{digest:x}")
        || request.idempotency_key
            != derive_idempotency_key(handoff_id, sequence, digest.as_slice())
    {
        return Err(PaimosReporterError::new("paimos_reporter_journal_invalid"));
    }
    Ok(())
}

fn derive_idempotency_key(handoff_id: &str, sequence: i64, request_digest: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(IDEMPOTENCY_DOMAIN);
    hash.update(handoff_id.as_bytes());
    hash.update([0]);
    hash.update(sequence.to_be_bytes());
    hash.update(request_digest);
    let digest = hash.finalize();
    let mut uuid = [0_u8; 16];
    uuid.copy_from_slice(&digest[..16]);
    uuid[6] = (uuid[6] & 0x0f) | 0x40;
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7],
        uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]
    )
}

fn accept_http_status(
    response: Result<ureq::Response, ureq::Error>,
    expected: &[u16],
) -> ReporterResult<ureq::Response> {
    match response {
        Ok(response) if expected.contains(&response.status()) => Ok(response),
        Ok(_) | Err(ureq::Error::Status(_, _)) => {
            Err(PaimosReporterError::new("paimos_reporter_remote_refused"))
        }
        Err(ureq::Error::Transport(_)) => Err(PaimosReporterError::new(
            "paimos_reporter_transport_unavailable",
        )),
    }
}

fn decode_response<T: for<'de> Deserialize<'de>>(response: ureq::Response) -> ReporterResult<T> {
    if response.all("Content-Type") != [MEDIA_TYPE] || !response.all("Content-Encoding").is_empty()
    {
        return Err(PaimosReporterError::new("paimos_reporter_media_refused"));
    }
    let mut raw = Vec::new();
    response
        .into_reader()
        .take(MAX_RESPONSE_BYTES as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|_| PaimosReporterError::new("paimos_reporter_response_invalid"))?;
    if raw.is_empty() || raw.len() > MAX_RESPONSE_BYTES {
        return Err(PaimosReporterError::new("paimos_reporter_response_invalid"));
    }
    decode_strict(&raw, "paimos_reporter_response_invalid")
}

pub(crate) fn decode_strict<T: for<'de> Deserialize<'de>>(
    raw: &[u8],
    reason: &'static str,
) -> ReporterResult<T> {
    let mut duplicate_decoder = serde_json::Deserializer::from_slice(raw);
    DuplicateChecked
        .deserialize(&mut duplicate_decoder)
        .and_then(|()| duplicate_decoder.end())
        .map_err(|_| PaimosReporterError::new(reason))?;
    let mut decoder = serde_json::Deserializer::from_slice(raw);
    let value = T::deserialize(&mut decoder).map_err(|_| PaimosReporterError::new(reason))?;
    decoder
        .end()
        .map_err(|_| PaimosReporterError::new(reason))?;
    Ok(value)
}

struct DuplicateChecked;

impl<'de> DeserializeSeed<'de> for DuplicateChecked {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateVisitor)
    }
}

struct DuplicateVisitor;

impl<'de> Visitor<'de> for DuplicateVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON without duplicate object names")
    }

    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut names = HashSet::new();
        while let Some(name) = map.next_key::<String>()? {
            if !names.insert(name) {
                return Err(M::Error::custom("duplicate object name"));
            }
            map.next_value_seed(DuplicateChecked)?;
        }
        Ok(())
    }

    fn visit_seq<S>(self, mut sequence: S) -> Result<Self::Value, S::Error>
    where
        S: SeqAccess<'de>,
    {
        while sequence.next_element_seed(DuplicateChecked)?.is_some() {}
        Ok(())
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }
    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        DuplicateChecked.deserialize(deserializer)
    }
}

fn wire_digest(raw: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(raw))
}

fn valid_handoff_id(value: &str) -> bool {
    value.len() == 26
        && value.as_bytes()[0] <= b'7'
        && value.bytes().all(|byte| {
            byte.is_ascii_digit()
                || matches!(
                    byte,
                    b'A'..=b'H' | b'J' | b'K' | b'M' | b'N' | b'P'..=b'T' | b'V'..=b'Z'
                )
        })
}

fn valid_symbol(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_lowercase()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn valid_wire_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 20 || bytes.len() > 30 || bytes.last() != Some(&b'Z') {
        return false;
    }
    for index in [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18] {
        if !bytes.get(index).is_some_and(u8::is_ascii_digit) {
            return false;
        }
    }
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return false;
    }
    if bytes.len() > 20
        && (bytes[19] != b'.'
            || bytes[20..bytes.len() - 1].is_empty()
            || !bytes[20..bytes.len() - 1].iter().all(u8::is_ascii_digit))
    {
        return false;
    }
    let number = |start: usize, end: usize| {
        std::str::from_utf8(&bytes[start..end])
            .ok()
            .and_then(|raw| raw.parse::<u32>().ok())
    };
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        number(0, 4),
        number(5, 7),
        number(8, 10),
        number(11, 13),
        number(14, 16),
        number(17, 19),
    ) else {
        return false;
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    day > 0 && day <= days && hour <= 23 && minute <= 59 && second <= 59
}

fn absolute_path(value: &str) -> bool {
    let path = Path::new(value);
    path.is_absolute()
        && !value.as_bytes().contains(&0)
        && path.components().all(|component| {
            !matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::io::{BufRead, BufReader, Write as _};
    use std::net::{TcpListener, TcpStream};
    use std::os::unix::fs::PermissionsExt as _;
    use std::process::{Command, Stdio};
    use std::sync::{Arc, Mutex};
    use std::thread;

    use serde_json::{json, Value};
    use tempfile::TempDir;

    use super::*;

    const HANDOFF_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
    const OBSERVED_AT: &str = "2026-08-20T09:56:00Z";
    const EXPIRES_AT: &str = "2026-08-22T12:00:00Z";

    #[derive(Clone)]
    struct FakeStep {
        method: &'static str,
        path: &'static str,
        status: u16,
        media_type: &'static str,
        body: String,
        disconnect: bool,
    }

    #[derive(Clone, Debug)]
    struct CapturedRequest {
        method: String,
        path: String,
        content_type: Option<String>,
        accept: Vec<String>,
        idempotency_key: Option<String>,
        body: Vec<u8>,
        authorization_valid: bool,
        handoff_secret_valid: bool,
    }

    struct FakeServer {
        origin: String,
        captured: Arc<Mutex<Vec<CapturedRequest>>>,
        handle: thread::JoinHandle<()>,
    }

    impl FakeServer {
        fn start(steps: Vec<FakeStep>, authorization: String, handoff_header: String) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake Paimos");
            let origin = format!("http://{}", listener.local_addr().expect("fake address"));
            let captured = Arc::new(Mutex::new(Vec::new()));
            let captured_for_thread = Arc::clone(&captured);
            let handle = thread::spawn(move || {
                for step in steps {
                    let (stream, _) = listener.accept().expect("accept fake request");
                    let request = read_request(stream, &authorization, &handoff_header);
                    assert!(
                        request.method == step.method,
                        "unexpected fake request method"
                    );
                    assert!(request.path == step.path, "unexpected fake request path");
                    captured_for_thread
                        .lock()
                        .expect("capture lock")
                        .push(request.captured.clone());
                    if step.disconnect {
                        continue;
                    }
                    write_response(request.stream(), &step);
                }
            });
            Self {
                origin,
                captured,
                handle,
            }
        }

        fn finish(self) -> Vec<CapturedRequest> {
            self.handle.join().expect("fake Paimos thread");
            Arc::try_unwrap(self.captured)
                .expect("capture owner")
                .into_inner()
                .expect("capture mutex")
        }
    }

    #[derive(Debug)]
    struct ParsedRequest {
        captured: CapturedRequest,
        stream: TcpStream,
    }

    impl ParsedRequest {
        fn stream(self) -> TcpStream {
            self.stream
        }
    }

    impl std::ops::Deref for ParsedRequest {
        type Target = CapturedRequest;

        fn deref(&self) -> &Self::Target {
            &self.captured
        }
    }

    impl Clone for ParsedRequest {
        fn clone(&self) -> Self {
            Self {
                captured: self.captured.clone(),
                stream: self.stream.try_clone().expect("clone fake stream"),
            }
        }
    }

    struct Fixture {
        _temporary: TempDir,
        config: ReporterConfigV1,
        owner_uid: u32,
        authorization: String,
        handoff_header: String,
    }

    fn fixture(evidence: DependencyEvidenceV1) -> Fixture {
        let temporary = tempfile::tempdir().expect("temporary reporter root");
        let api_key_path = temporary.path().join("api-key");
        let handoff_secret_path = temporary.path().join("handoff-secret");
        let journal_directory = temporary.path().join("journal");
        let api_key = format!("paimos_{}", "a".repeat(40));
        let handoff_secret = (0_u8..32).collect::<Vec<_>>();
        fs::write(&api_key_path, api_key.as_bytes()).expect("write API key");
        fs::write(&handoff_secret_path, &handoff_secret).expect("write handoff secret");
        fs::create_dir(&journal_directory).expect("create journal directory");
        fs::set_permissions(&api_key_path, fs::Permissions::from_mode(0o600))
            .expect("protect API key");
        fs::set_permissions(&handoff_secret_path, fs::Permissions::from_mode(0o600))
            .expect("protect handoff secret");
        fs::set_permissions(&journal_directory, fs::Permissions::from_mode(0o700))
            .expect("protect journal directory");
        let owner_uid = fs::metadata(&api_key_path).expect("API key metadata").uid();
        Fixture {
            config: ReporterConfigV1 {
                schema: CONFIG_SCHEMA.to_string(),
                schema_version: 1,
                paimos_origin: String::new(),
                paimos_ca_file: None,
                handoff_id: HANDOFF_ID.to_string(),
                api_key_file: api_key_path.to_string_lossy().into_owned(),
                handoff_secret_file: handoff_secret_path.to_string_lossy().into_owned(),
                journal_directory: journal_directory.to_string_lossy().into_owned(),
                expected: ExpectedBindingV1 {
                    dependency_key: "privileged-handoff".to_string(),
                    stage_key: StageKey::Deployment,
                    execution_number: 1,
                    plan_digest: format!("sha256:{}", "1".repeat(64)),
                    predecessor_digest: format!("sha256:{}", "2".repeat(64)),
                    authority_epoch: 3,
                    context_digest: format!("sha256:{}", "3".repeat(64)),
                    credential_epoch: 1,
                    expires_at: EXPIRES_AT.to_string(),
                },
                evidence,
            },
            owner_uid,
            authorization: format!("Bearer {api_key}"),
            handoff_header: URL_SAFE_NO_PAD.encode(handoff_secret),
            _temporary: temporary,
        }
    }

    struct TestCa {
        certificate: PathBuf,
        private_key: PathBuf,
    }

    struct TestServerCertificate {
        certificate: PathBuf,
        private_key: PathBuf,
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).expect("write private test file");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("protect private test file");
    }

    fn run_test_openssl(directory: &Path, arguments: &[&str]) {
        let status = Command::new("openssl")
            .current_dir(directory)
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("run openssl for ephemeral test certificate");
        assert!(status.success(), "ephemeral openssl command failed");
    }

    fn generate_test_ca(directory: &Path, name: &str) -> TestCa {
        let ca_directory = directory.join(name);
        fs::create_dir(&ca_directory).expect("create ephemeral CA directory");
        run_test_openssl(
            &ca_directory,
            &[
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                "ca.key",
                "-out",
                "ca.pem",
                "-days",
                "2",
                "-sha256",
                "-subj",
                "/CN=Janus ephemeral test CA",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
            ],
        );
        let certificate = ca_directory.join("ca.pem");
        let private_key = ca_directory.join("ca.key");
        fs::set_permissions(&certificate, fs::Permissions::from_mode(0o600))
            .expect("protect ephemeral CA certificate");
        fs::set_permissions(&private_key, fs::Permissions::from_mode(0o600))
            .expect("protect ephemeral CA key");
        TestCa {
            certificate,
            private_key,
        }
    }

    fn generate_server_certificate(
        directory: &Path,
        ca: &TestCa,
        name: &str,
        subject_alt_name: &str,
    ) -> TestServerCertificate {
        let server_directory = directory.join(name);
        fs::create_dir(&server_directory).expect("create ephemeral server certificate directory");
        run_test_openssl(
            &server_directory,
            &[
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                "server.key",
                "-out",
                "server.csr",
                "-subj",
                "/CN=Janus ephemeral test server",
            ],
        );
        fs::write(
            server_directory.join("server.ext"),
            format!(
                "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName={subject_alt_name}\n"
            ),
        )
        .expect("write ephemeral certificate extensions");
        let ca_certificate = ca.certificate.to_str().expect("UTF-8 CA certificate path");
        let ca_private_key = ca.private_key.to_str().expect("UTF-8 CA key path");
        run_test_openssl(
            &server_directory,
            &[
                "x509",
                "-req",
                "-in",
                "server.csr",
                "-CA",
                ca_certificate,
                "-CAkey",
                ca_private_key,
                "-CAcreateserial",
                "-out",
                "server.pem",
                "-days",
                "2",
                "-sha256",
                "-extfile",
                "server.ext",
            ],
        );
        TestServerCertificate {
            certificate: server_directory.join("server.pem"),
            private_key: server_directory.join("server.key"),
        }
    }

    fn start_test_https_server(
        material: &TestServerCertificate,
    ) -> (String, thread::JoinHandle<()>) {
        use rustls::pki_types::pem::PemObject as _;

        let certificate = rustls::pki_types::CertificateDer::from_pem_file(&material.certificate)
            .expect("read ephemeral server certificate");
        let private_key = rustls::pki_types::PrivateKeyDer::from_pem_file(&material.private_key)
            .expect("read ephemeral server private key");
        let server_config = rustls::ServerConfig::builder_with_provider(
            rustls::crypto::ring::default_provider().into(),
        )
        .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
        .expect("ephemeral TLS protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![certificate], private_key)
        .expect("ephemeral TLS server configuration");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral HTTPS server");
        let port = listener
            .local_addr()
            .expect("ephemeral HTTPS address")
            .port();
        let handle = thread::spawn(move || {
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            let Ok(connection) = rustls::ServerConnection::new(Arc::new(server_config)) else {
                return;
            };
            let mut stream = rustls::StreamOwned::new(connection, stream);
            let mut request = [0u8; 4096];
            if std::io::Read::read(&mut stream, &mut request).is_ok() {
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                );
            }
        });
        (format!("https://127.0.0.1:{port}"), handle)
    }

    fn read_request(stream: TcpStream, authorization: &str, handoff_header: &str) -> ParsedRequest {
        let reader_stream = stream.try_clone().expect("clone request stream");
        let mut reader = BufReader::new(reader_stream);
        let mut first = String::new();
        reader.read_line(&mut first).expect("read request line");
        let mut parts = first.split_whitespace();
        let method = parts.next().expect("request method").to_string();
        let path = parts.next().expect("request path").to_string();
        let mut headers = BTreeMap::<String, Vec<String>>::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).expect("read request header");
            if line == "\r\n" {
                break;
            }
            let (name, value) = line.split_once(':').expect("request header shape");
            headers
                .entry(name.to_ascii_lowercase())
                .or_default()
                .push(value.trim().to_string());
        }
        let content_length = headers
            .get("content-length")
            .and_then(|values| values.first())
            .map_or(0, |raw| raw.parse::<usize>().expect("content length"));
        let mut body = vec![0; content_length];
        reader.read_exact(&mut body).expect("read request body");
        let one = |name: &str| {
            headers
                .get(name)
                .filter(|values| values.len() == 1)
                .and_then(|values| values.first())
                .cloned()
        };
        ParsedRequest {
            captured: CapturedRequest {
                method,
                path,
                content_type: one("content-type"),
                accept: headers.get("accept").cloned().unwrap_or_default(),
                idempotency_key: one("idempotency-key"),
                body,
                authorization_valid: one("authorization").as_deref() == Some(authorization),
                handoff_secret_valid: one(&HANDOFF_SECRET_HEADER.to_ascii_lowercase()).as_deref()
                    == Some(handoff_header),
            },
            stream,
        }
    }

    fn write_response(mut stream: TcpStream, step: &FakeStep) {
        let reason = match step.status {
            200 => "OK",
            201 => "Created",
            404 => "Not Found",
            409 => "Conflict",
            _ => "Refused",
        };
        let response = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: private, no-store\r\nConnection: close\r\n\r\n{}",
            step.status,
            reason,
            step.media_type,
            step.body.len(),
            step.body
        );
        stream
            .write_all(response.as_bytes())
            .expect("write fake response");
        stream.flush().expect("flush fake response");
    }

    fn pull_body(config: &ReporterConfigV1, state: &str) -> Value {
        json!({
            "handoff_id": config.handoff_id,
            "contract_major": PAIMOS_EXTERNAL_STAGE_SCHEMA_MAJOR,
            "fixture_digest": PAIMOS_EXTERNAL_STAGE_FIXTURE_DIGEST,
            "credential_epoch": config.expected.credential_epoch,
            "expires_at": config.expected.expires_at,
            "state": state,
            "reporter_class": "janus",
            "reporter_role": "dependency",
            "dependency_key": config.expected.dependency_key,
            "evidence_ceiling": [match config.evidence.kind() {
                EvidenceKind::Authorization => "authorization",
                EvidenceKind::CredentialHandoff => "credential_handoff",
                _ => unreachable!("closed Janus test evidence"),
            }],
            "stage_key": "deployment",
            "execution_number": config.expected.execution_number,
            "plan_digest": config.expected.plan_digest,
            "predecessor_digest": config.expected.predecessor_digest,
            "authority_epoch": config.expected.authority_epoch,
            "context_digest": config.expected.context_digest,
        })
    }

    fn receipt_body(
        config: &ReporterConfigV1,
        sequence: i64,
        state: &str,
        duplicate: bool,
    ) -> String {
        serde_json::to_string(&json!({
            "handoff_id": config.handoff_id,
            "sequence": sequence,
            "state": state,
            "credential_epoch": config.expected.credential_epoch,
            "duplicate": duplicate,
            "server_received_at": "2026-08-20T09:56:01Z",
        }))
        .expect("serialize receipt")
    }

    fn success_steps(config: &ReporterConfigV1) -> Vec<FakeStep> {
        vec![
            FakeStep {
                method: "GET",
                path: "/api/external-stage/handoffs/01ARZ3NDEKTSV4RRFFQ69G5FAV",
                status: 200,
                media_type: MEDIA_TYPE,
                body: pull_body(config, "issued").to_string(),
                disconnect: false,
            },
            FakeStep {
                method: "POST",
                path: "/api/external-stage/handoffs/01ARZ3NDEKTSV4RRFFQ69G5FAV/accept",
                status: 201,
                media_type: MEDIA_TYPE,
                body: receipt_body(config, 1, "accepted", false),
                disconnect: false,
            },
            FakeStep {
                method: "POST",
                path: "/api/external-stage/handoffs/01ARZ3NDEKTSV4RRFFQ69G5FAV/reports",
                status: 201,
                media_type: MEDIA_TYPE,
                body: receipt_body(config, 2, "succeeded", false),
                disconnect: false,
            },
        ]
    }

    fn run_success(mut fixture: Fixture) -> (Fixture, Vec<CapturedRequest>) {
        let fake = FakeServer::start(
            success_steps(&fixture.config),
            fixture.authorization.clone(),
            fixture.handoff_header.clone(),
        );
        fixture.config.paimos_origin = fake.origin.clone();
        Reporter::new(fixture.config.clone(), fixture.owner_uid, true)
            .expect("construct reporter")
            .run()
            .expect("run reporter");
        (fixture, fake.finish())
    }

    fn assert_transport_contract(requests: &[CapturedRequest]) {
        assert_eq!(requests.len(), 3);
        for request in requests {
            assert!(
                request.authorization_valid,
                "API-key authentication missing"
            );
            assert!(
                request.handoff_secret_valid,
                "handoff authentication missing"
            );
            assert_eq!(request.accept, [MEDIA_TYPE]);
            assert!(!request.path.contains('?'));
        }
        assert_eq!(requests[0].method, "GET");
        assert!(requests[0].content_type.is_none());
        assert!(requests[0].idempotency_key.is_none());
        assert!(requests[0].body.is_empty());
        for request in &requests[1..] {
            assert_eq!(request.method, "POST");
            assert_eq!(request.content_type.as_deref(), Some(MEDIA_TYPE));
            assert!(request.idempotency_key.is_some());
        }
        assert_ne!(requests[1].idempotency_key, requests[2].idempotency_key);
    }

    #[test]
    fn reports_authorization_as_accept_then_one_value_free_terminal() {
        let (fixture, requests) = run_success(fixture(DependencyEvidenceV1::Authorization {
            observed_at: OBSERVED_AT.to_string(),
        }));
        assert_transport_contract(&requests);
        let accept: Value = serde_json::from_slice(&requests[1].body).expect("accept JSON");
        assert_eq!(accept, json!({"sequence": 1, "observed_at": OBSERVED_AT}));
        let report: Value = serde_json::from_slice(&requests[2].body).expect("report JSON");
        assert_eq!(
            report,
            json!({
                "sequence": 2,
                "state": "succeeded",
                "observed_at": OBSERVED_AT,
                "heartbeat": false,
                "janus_evidence": {
                    "kind": "authorization",
                    "result": "satisfied",
                    "authorized": true,
                    "observed_at": OBSERVED_AT,
                }
            })
        );
        let body = std::str::from_utf8(&requests[2].body).expect("report UTF-8");
        for forbidden in [
            "pharos_evidence",
            "blocker_codes",
            "callback",
            "command",
            "ciphertext",
            "secret",
            "runtime_path",
            "url",
        ] {
            assert!(!body.contains(forbidden), "report gained a forbidden field");
        }
        let journal_path = Path::new(&fixture.config.journal_directory)
            .join(format!("{}.json", fixture.config.handoff_id));
        let metadata = fs::metadata(&journal_path).expect("journal metadata");
        assert_eq!(metadata.mode() & 0o777, 0o600);
        let journal: ReporterJournalV1 = decode_strict(
            &fs::read(journal_path).expect("read journal"),
            "test_journal_invalid",
        )
        .expect("decode journal");
        assert_eq!(journal.completed.expect("completed receipt").sequence, 2);
    }

    #[test]
    fn reports_credential_handoff_with_no_authorization_or_owner_fields() {
        let (_, requests) = run_success(fixture(DependencyEvidenceV1::CredentialHandoff {
            observed_at: OBSERVED_AT.to_string(),
        }));
        assert_transport_contract(&requests);
        let report: Value = serde_json::from_slice(&requests[2].body).expect("report JSON");
        assert_eq!(report["janus_evidence"]["kind"], "credential_handoff");
        assert_eq!(report["janus_evidence"]["credential_ready"], true);
        assert!(report["janus_evidence"].get("authorized").is_none());
        assert!(report.get("pharos_evidence").is_none());
        assert_eq!(report["sequence"], 2);
        assert_eq!(report["heartbeat"], false);
    }

    #[test]
    fn protected_binding_is_value_free_and_rejects_any_config_change_before_io() {
        let mut fixture = fixture(DependencyEvidenceV1::CredentialHandoff {
            observed_at: OBSERVED_AT.to_string(),
        });
        fixture.config.paimos_origin = "https://paimos.example".to_string();
        let binding = reporter_binding(&fixture.config, false).expect("derive protected binding");
        validate_reporter_binding(&fixture.config, &binding, false).expect("exact binding");
        let encoded = serde_json::to_string(&binding).unwrap();
        for forbidden in [
            "paimos_origin",
            "api_key_file",
            "handoff_secret_file",
            "journal_directory",
            "ciphertext",
        ] {
            assert!(!encoded.contains(forbidden));
        }
        let mut changed = fixture.config;
        changed.expected.authority_epoch += 1;
        assert_eq!(
            validate_reporter_binding(&changed, &binding, false)
                .expect_err("changed config must fail")
                .reason_code(),
            "paimos_reporter_binding_refused"
        );
    }

    #[test]
    fn protected_binding_runs_real_reporter_once_under_concurrent_dispatch() {
        let mut fixture = fixture(DependencyEvidenceV1::CredentialHandoff {
            observed_at: OBSERVED_AT.to_string(),
        });
        let fake = FakeServer::start(
            success_steps(&fixture.config),
            fixture.authorization.clone(),
            fixture.handoff_header.clone(),
        );
        fixture.config.paimos_origin = fake.origin.clone();
        let binding = reporter_binding(&fixture.config, true).expect("derive protected binding");
        let first_config = fixture.config.clone();
        let second_config = fixture.config.clone();
        let first_binding = binding.clone();
        let second_binding = binding.clone();
        let owner_uid = fixture.owner_uid;
        let first = std::thread::spawn(move || {
            run_bound_config(first_config, &first_binding, owner_uid, true)
        });
        let second = std::thread::spawn(move || {
            run_bound_config(second_config, &second_binding, owner_uid, true)
        });
        let results = [first.join().unwrap(), second.join().unwrap()];
        assert!(results.iter().any(Result::is_ok));
        assert!(results.iter().all(|result| {
            result.is_ok()
                || result
                    .as_ref()
                    .is_err_and(|error| error.reason_code() == "paimos_reporter_busy")
        }));
        run_bound_config(fixture.config.clone(), &binding, owner_uid, true)
            .expect("completed journal is a no-op");
        let requests = fake.finish();
        assert_transport_contract(&requests);
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.path.ends_with("/reports"))
                .count(),
            1,
            "concurrent dispatch emitted a duplicate terminal sequence"
        );

        let mut conflicting = binding;
        conflicting.config_digest = format!("sha256:{}", "f".repeat(64));
        let error = run_bound_config(fixture.config, &conflicting, owner_uid, true)
            .expect_err("changed reporter config must fail closed");
        assert_eq!(error.reason_code(), "paimos_reporter_binding_refused");
    }

    #[test]
    fn pull_fails_closed_on_media_binding_role_sequence_and_unknown_fields() {
        let cases = [
            "media", "lineage", "role", "rotation", "sequence", "unknown",
        ];
        for case in cases {
            let mut fixture = fixture(DependencyEvidenceV1::Authorization {
                observed_at: OBSERVED_AT.to_string(),
            });
            let mut body = pull_body(&fixture.config, "issued");
            let media = if case == "media" {
                "application/json"
            } else {
                MEDIA_TYPE
            };
            match case {
                "lineage" => {
                    body["predecessor_digest"] = json!(format!("sha256:{}", "9".repeat(64)))
                }
                "role" => body["reporter_role"] = json!("owner"),
                "rotation" => body["credential_epoch"] = json!(2),
                "sequence" => body["state"] = json!("accepted"),
                "unknown" => body["opaque_metadata"] = json!("forbidden"),
                _ => {}
            }
            let fake = FakeServer::start(
                vec![FakeStep {
                    method: "GET",
                    path: "/api/external-stage/handoffs/01ARZ3NDEKTSV4RRFFQ69G5FAV",
                    status: 200,
                    media_type: media,
                    body: body.to_string(),
                    disconnect: false,
                }],
                fixture.authorization.clone(),
                fixture.handoff_header.clone(),
            );
            fixture.config.paimos_origin = fake.origin.clone();
            let error = Reporter::new(fixture.config.clone(), fixture.owner_uid, true)
                .expect("construct reporter")
                .run()
                .expect_err("unsafe pull must fail");
            assert!(
                matches!(
                    error.reason_code(),
                    "paimos_reporter_media_refused"
                        | "paimos_reporter_binding_refused"
                        | "paimos_reporter_sequence_refused"
                        | "paimos_reporter_response_invalid"
                ),
                "unexpected value-free refusal"
            );
            assert_eq!(fake.finish().len(), 1);
            let journal = Path::new(&fixture.config.journal_directory)
                .join(format!("{}.json", fixture.config.handoff_id));
            assert!(!journal.exists(), "refused pull touched durable state");
        }
    }

    #[test]
    fn revoked_handoff_and_unsafe_credential_custody_fail_closed() {
        let mut revoked = fixture(DependencyEvidenceV1::Authorization {
            observed_at: OBSERVED_AT.to_string(),
        });
        let fake = FakeServer::start(
            vec![FakeStep {
                method: "GET",
                path: "/api/external-stage/handoffs/01ARZ3NDEKTSV4RRFFQ69G5FAV",
                status: 404,
                media_type: "application/problem+json",
                body: "{}".to_string(),
                disconnect: false,
            }],
            revoked.authorization.clone(),
            revoked.handoff_header.clone(),
        );
        revoked.config.paimos_origin = fake.origin.clone();
        let error = Reporter::new(revoked.config.clone(), revoked.owner_uid, true)
            .expect("construct reporter")
            .run()
            .expect_err("revoked handoff must fail");
        assert_eq!(error.reason_code(), "paimos_reporter_remote_refused");
        assert_eq!(fake.finish().len(), 1);

        let mut unsafe_mode = fixture(DependencyEvidenceV1::Authorization {
            observed_at: OBSERVED_AT.to_string(),
        });
        unsafe_mode.config.paimos_origin = "http://127.0.0.1:1".to_string();
        fs::set_permissions(
            &unsafe_mode.config.handoff_secret_file,
            fs::Permissions::from_mode(0o640),
        )
        .expect("weaken test secret mode");
        let error = Reporter::new(unsafe_mode.config.clone(), unsafe_mode.owner_uid, true)
            .err()
            .expect("unsafe mode must fail");
        assert_eq!(
            error.reason_code(),
            "paimos_reporter_handoff_secret_unavailable"
        );

        let mut same_inode = fixture(DependencyEvidenceV1::Authorization {
            observed_at: OBSERVED_AT.to_string(),
        });
        same_inode.config.paimos_origin = "http://127.0.0.1:1".to_string();
        fs::remove_file(&same_inode.config.handoff_secret_file).expect("replace test secret");
        fs::hard_link(
            &same_inode.config.api_key_file,
            &same_inode.config.handoff_secret_file,
        )
        .expect("link test credentials");
        let error = Reporter::new(same_inode.config.clone(), same_inode.owner_uid, true)
            .err()
            .expect("shared credential inode must fail");
        assert_eq!(
            error.reason_code(),
            "paimos_reporter_credential_custody_refused"
        );
    }

    #[test]
    fn accept_crash_replays_exact_pre_send_journal_then_reports_sequence_two() {
        let mut fixture = fixture(DependencyEvidenceV1::Authorization {
            observed_at: OBSERVED_AT.to_string(),
        });
        let steps = vec![
            FakeStep {
                method: "GET",
                path: "/api/external-stage/handoffs/01ARZ3NDEKTSV4RRFFQ69G5FAV",
                status: 200,
                media_type: MEDIA_TYPE,
                body: pull_body(&fixture.config, "issued").to_string(),
                disconnect: false,
            },
            FakeStep {
                method: "POST",
                path: "/api/external-stage/handoffs/01ARZ3NDEKTSV4RRFFQ69G5FAV/accept",
                status: 201,
                media_type: MEDIA_TYPE,
                body: String::new(),
                disconnect: true,
            },
            FakeStep {
                method: "POST",
                path: "/api/external-stage/handoffs/01ARZ3NDEKTSV4RRFFQ69G5FAV/accept",
                status: 200,
                media_type: MEDIA_TYPE,
                body: receipt_body(&fixture.config, 1, "accepted", true),
                disconnect: false,
            },
            FakeStep {
                method: "POST",
                path: "/api/external-stage/handoffs/01ARZ3NDEKTSV4RRFFQ69G5FAV/reports",
                status: 201,
                media_type: MEDIA_TYPE,
                body: receipt_body(&fixture.config, 2, "succeeded", false),
                disconnect: false,
            },
        ];
        let fake = FakeServer::start(
            steps,
            fixture.authorization.clone(),
            fixture.handoff_header.clone(),
        );
        fixture.config.paimos_origin = fake.origin.clone();
        let first = Reporter::new(fixture.config.clone(), fixture.owner_uid, true)
            .expect("first reporter")
            .run()
            .expect_err("lost accept response must remain pending");
        assert_eq!(first.reason_code(), "paimos_reporter_transport_unavailable");
        Reporter::new(fixture.config.clone(), fixture.owner_uid, true)
            .expect("restarted reporter")
            .run()
            .expect("replay accept and report");
        let requests = fake.finish();
        assert_eq!(requests.len(), 4);
        assert_eq!(requests[1].body, requests[2].body);
        assert_eq!(requests[1].idempotency_key, requests[2].idempotency_key);
        assert_eq!(requests[3].path.rsplit('/').next(), Some("reports"));
    }

    #[test]
    fn report_crash_replays_exact_sequence_two_without_a_new_pull_or_accept() {
        let mut fixture = fixture(DependencyEvidenceV1::Authorization {
            observed_at: OBSERVED_AT.to_string(),
        });
        let steps = vec![
            FakeStep {
                method: "GET",
                path: "/api/external-stage/handoffs/01ARZ3NDEKTSV4RRFFQ69G5FAV",
                status: 200,
                media_type: MEDIA_TYPE,
                body: pull_body(&fixture.config, "issued").to_string(),
                disconnect: false,
            },
            FakeStep {
                method: "POST",
                path: "/api/external-stage/handoffs/01ARZ3NDEKTSV4RRFFQ69G5FAV/accept",
                status: 201,
                media_type: MEDIA_TYPE,
                body: receipt_body(&fixture.config, 1, "accepted", false),
                disconnect: false,
            },
            FakeStep {
                method: "POST",
                path: "/api/external-stage/handoffs/01ARZ3NDEKTSV4RRFFQ69G5FAV/reports",
                status: 201,
                media_type: MEDIA_TYPE,
                body: String::new(),
                disconnect: true,
            },
            FakeStep {
                method: "POST",
                path: "/api/external-stage/handoffs/01ARZ3NDEKTSV4RRFFQ69G5FAV/reports",
                status: 200,
                media_type: MEDIA_TYPE,
                body: receipt_body(&fixture.config, 2, "succeeded", true),
                disconnect: false,
            },
        ];
        let fake = FakeServer::start(
            steps,
            fixture.authorization.clone(),
            fixture.handoff_header.clone(),
        );
        fixture.config.paimos_origin = fake.origin.clone();
        Reporter::new(fixture.config.clone(), fixture.owner_uid, true)
            .expect("first reporter")
            .run()
            .expect_err("lost report response must remain pending");
        Reporter::new(fixture.config.clone(), fixture.owner_uid, true)
            .expect("restarted reporter")
            .run()
            .expect("replay terminal report");
        let requests = fake.finish();
        assert_eq!(requests.len(), 4);
        assert_eq!(requests[2].path, requests[3].path);
        assert_eq!(requests[2].body, requests[3].body);
        assert_eq!(requests[2].idempotency_key, requests[3].idempotency_key);
    }

    #[test]
    fn idempotency_is_handoff_sequence_and_request_digest_not_credential_epoch() {
        let digest = Sha256::digest(b"exact request bytes");
        let first = derive_idempotency_key(HANDOFF_ID, 2, digest.as_slice());
        let same_after_credential_rotation =
            derive_idempotency_key(HANDOFF_ID, 2, digest.as_slice());
        assert_eq!(first, same_after_credential_rotation);
        assert_ne!(
            first,
            derive_idempotency_key(HANDOFF_ID, 1, digest.as_slice())
        );
        assert_ne!(
            first,
            derive_idempotency_key(HANDOFF_ID, 2, Sha256::digest(b"different").as_slice())
        );
        assert_eq!(first.len(), 36);
        assert_eq!(first.as_bytes()[14], b'4');
        assert!(matches!(first.as_bytes()[19], b'8' | b'9' | b'a' | b'b'));
    }

    #[test]
    fn strict_decoder_rejects_duplicate_names_and_trailing_json() {
        assert_eq!(
            decode_strict::<AcceptRequestV1>(
                br#"{"sequence":1,"sequence":1,"observed_at":"2026-08-20T09:56:00Z"}"#,
                "duplicate",
            )
            .expect_err("duplicate name")
            .reason_code(),
            "duplicate"
        );
        assert_eq!(
            decode_strict::<AcceptRequestV1>(
                br#"{"sequence":1,"observed_at":"2026-08-20T09:56:00Z"} {}"#,
                "trailing",
            )
            .expect_err("trailing value")
            .reason_code(),
            "trailing"
        );
    }

    #[test]
    fn optional_ca_is_certificate_only_bounded_and_privately_custodied() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().expect("temporary CA test root");
        let ca = generate_test_ca(temporary.path(), "trusted-ca");
        let owner_uid = fs::metadata(&ca.certificate)
            .expect("ephemeral CA metadata")
            .uid();
        assert_eq!(
            load_ca_certificates(&ca.certificate, owner_uid)
                .expect("valid protected CA certificate")
                .len(),
            1
        );

        let invalid = temporary.path().join("invalid.pem");
        for bytes in [
            b"not a PEM certificate".as_slice(),
            b"-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n".as_slice(),
            b"-----BEGIN PUBLIC KEY-----\nYWJj\n-----END PUBLIC KEY-----\n".as_slice(),
        ] {
            write_private(&invalid, bytes);
            assert_eq!(
                load_ca_certificates(&invalid, owner_uid)
                    .expect_err("non-certificate or malformed PEM must fail")
                    .reason_code(),
                "paimos_reporter_ca_invalid"
            );
        }

        let mut certificate_and_key = fs::read(&ca.certificate).expect("read ephemeral CA PEM");
        certificate_and_key
            .extend_from_slice(&fs::read(&ca.private_key).expect("read ephemeral CA key"));
        write_private(&invalid, &certificate_and_key);
        certificate_and_key.fill(0);
        assert_eq!(
            load_ca_certificates(&invalid, owner_uid)
                .expect_err("certificate plus private key must fail")
                .reason_code(),
            "paimos_reporter_ca_invalid"
        );

        let certificate = fs::read(&ca.certificate).expect("read ephemeral CA for count bound");
        write_private(&invalid, &certificate.repeat(MAX_CA_CERTIFICATES + 1));
        assert_eq!(
            load_ca_certificates(&invalid, owner_uid)
                .expect_err("excess certificate count must fail")
                .reason_code(),
            "paimos_reporter_ca_invalid"
        );
        write_private(&invalid, &vec![b'A'; MAX_CA_BUNDLE_BYTES + 1]);
        assert_eq!(
            load_ca_certificates(&invalid, owner_uid)
                .expect_err("oversized certificate file must fail")
                .reason_code(),
            "paimos_reporter_ca_file_refused"
        );

        let missing = temporary.path().join("missing.pem");
        assert_eq!(
            load_ca_certificates(&missing, owner_uid)
                .expect_err("missing certificate file must fail")
                .reason_code(),
            "paimos_reporter_ca_file_refused"
        );
        let wrong_owner_uid = if owner_uid == 0 { 1 } else { 0 };
        assert_eq!(
            load_ca_certificates(&ca.certificate, wrong_owner_uid)
                .expect_err("certificate file with the wrong owner must fail")
                .reason_code(),
            "paimos_reporter_ca_file_refused"
        );
        fs::set_permissions(&ca.certificate, fs::Permissions::from_mode(0o644))
            .expect("weaken ephemeral CA mode");
        assert_eq!(
            load_ca_certificates(&ca.certificate, owner_uid)
                .expect_err("public certificate file mode must fail")
                .reason_code(),
            "paimos_reporter_ca_file_refused"
        );
        fs::set_permissions(&ca.certificate, fs::Permissions::from_mode(0o600))
            .expect("restore ephemeral CA mode");

        let linked = temporary.path().join("linked.pem");
        fs::hard_link(&ca.certificate, &linked).expect("hard-link ephemeral CA");
        assert_eq!(
            load_ca_certificates(&ca.certificate, owner_uid)
                .expect_err("multiply linked certificate file must fail")
                .reason_code(),
            "paimos_reporter_ca_file_refused"
        );
        fs::remove_file(&linked).expect("remove ephemeral test hard link");
        let symlinked = temporary.path().join("symlinked.pem");
        symlink(&ca.certificate, &symlinked).expect("symlink ephemeral CA");
        assert_eq!(
            load_ca_certificates(&symlinked, owner_uid)
                .expect_err("symlinked certificate file must fail")
                .reason_code(),
            "paimos_reporter_ca_file_refused"
        );
        let directory = temporary.path().join("certificate-directory");
        fs::create_dir(&directory).expect("create non-regular CA path");
        assert_eq!(
            load_ca_certificates(&directory, owner_uid)
                .expect_err("non-regular certificate path must fail")
                .reason_code(),
            "paimos_reporter_ca_file_refused"
        );
    }

    #[test]
    fn custom_ca_https_preserves_chain_and_hostname_verification() {
        let temporary = tempfile::tempdir().expect("temporary HTTPS test root");
        let trusted_ca = generate_test_ca(temporary.path(), "trusted-ca");
        let wrong_ca = generate_test_ca(temporary.path(), "wrong-ca");
        let matching_server = generate_server_certificate(
            temporary.path(),
            &trusted_ca,
            "matching-server",
            "IP:127.0.0.1",
        );
        let wrong_hostname_server = generate_server_certificate(
            temporary.path(),
            &trusted_ca,
            "wrong-hostname-server",
            "DNS:not-localhost.invalid",
        );
        let owner_uid = fs::metadata(&trusted_ca.certificate)
            .expect("trusted CA metadata")
            .uid();
        let trusted_path = trusted_ca.certificate.to_str().expect("UTF-8 CA path");
        let wrong_path = wrong_ca.certificate.to_str().expect("UTF-8 wrong CA path");

        let (origin, server) = start_test_https_server(&matching_server);
        let response = build_http_agent(Some(trusted_path), owner_uid)
            .expect("build trusted reporter HTTPS client")
            .get(&origin)
            .call()
            .expect("matching CA and hostname must succeed");
        assert_eq!(response.status(), 200);
        server.join().expect("matching HTTPS server exits");

        let (origin, server) = start_test_https_server(&matching_server);
        assert!(matches!(
            build_http_agent(None, owner_uid)
                .expect("build bundled-root reporter HTTPS client")
                .get(&origin)
                .call(),
            Err(ureq::Error::Transport(_))
        ));
        server.join().expect("missing-CA HTTPS server exits");

        let (origin, server) = start_test_https_server(&matching_server);
        assert!(matches!(
            build_http_agent(Some(wrong_path), owner_uid)
                .expect("build wrong-root reporter HTTPS client")
                .get(&origin)
                .call(),
            Err(ureq::Error::Transport(_))
        ));
        server.join().expect("wrong-CA HTTPS server exits");

        let (origin, server) = start_test_https_server(&wrong_hostname_server);
        assert!(matches!(
            build_http_agent(Some(trusted_path), owner_uid)
                .expect("build trusted reporter HTTPS client")
                .get(&origin)
                .call(),
            Err(ureq::Error::Transport(_))
        ));
        server.join().expect("wrong-hostname HTTPS server exits");
    }

    #[test]
    fn omitted_ca_preserves_legacy_serialized_config_shape() {
        let mut fixture = fixture(DependencyEvidenceV1::Authorization {
            observed_at: OBSERVED_AT.to_string(),
        });
        fixture.config.paimos_origin = "https://paimos.example".to_string();
        let serialized = serde_json::to_value(&fixture.config).expect("serialize reporter config");
        assert!(serialized.get("paimos_ca_file").is_none());

        let without_ca = reporter_binding(&fixture.config, false).expect("legacy reporter binding");
        fixture.config.paimos_ca_file = Some("/run/credentials/paimos-ca.pem".to_string());
        let with_ca = reporter_binding(&fixture.config, false).expect("custom-CA reporter binding");
        assert_ne!(without_ca.config_digest, with_ca.config_digest);
    }

    #[test]
    fn managed_config_keeps_optional_ca_strict_and_digest_bound() {
        let fixture = fixture(DependencyEvidenceV1::Authorization {
            observed_at: OBSERVED_AT.to_string(),
        });
        let mut config = ManagedReporterConfigV1 {
            schema: MANAGED_CONFIG_SCHEMA.to_string(),
            schema_version: 1,
            paimos_origin: "https://paimos.example".to_string(),
            paimos_ca_file: None,
            handoff_id: fixture.config.handoff_id,
            api_key_file: fixture.config.api_key_file,
            handoff_secret_file: fixture.config.handoff_secret_file,
            journal_directory: fixture.config.journal_directory,
            expected: fixture.config.expected,
            evidence: ManagedEvidencePolicyV1 {
                kind: "credential_handoff".to_string(),
                source: "managed_completion_record".to_string(),
            },
        };
        let canonical_without_ca = canonical_json_bytes(&config).expect("canonical managed config");
        assert!(!canonical_without_ca
            .windows(b"paimos_ca_file".len())
            .any(|window| window == b"paimos_ca_file"));
        let binding_without_ca =
            managed_reporter_binding(&config, false).expect("managed binding without CA");

        config.paimos_ca_file = Some("/run/credentials/paimos-ca.pem".to_string());
        let binding_with_ca =
            managed_reporter_binding(&config, false).expect("managed binding with CA");
        assert_ne!(
            binding_without_ca.config_digest,
            binding_with_ca.config_digest
        );

        let mut document = serde_json::to_value(&config).expect("serialize managed config");
        document["opaque"] = json!("forbidden");
        assert_eq!(
            decode_strict::<ManagedReporterConfigV1>(
                &serde_json::to_vec(&document).expect("encode invalid managed config"),
                "managed_unknown_field",
            )
            .expect_err("managed config must retain unknown-field refusal")
            .reason_code(),
            "managed_unknown_field"
        );
    }

    type ConfigMutation = fn(ReporterConfigV1) -> ReporterConfigV1;

    const CHECKED_EXAMPLE_PATH: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/paimos-dependency-reporter/config.example.json"
    );
    const README_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../README.md");
    const README_PAIMOS_JSON_MARKER: &str =
        "The strict configuration shape is mirrored byte-for-byte from that example:\n\n```json\n";

    fn checked_example_bytes() -> Vec<u8> {
        fs::read(CHECKED_EXAMPLE_PATH).expect("read checked Paimos example")
    }

    fn readme_paimos_config_bytes() -> Vec<u8> {
        let readme = fs::read_to_string(README_PATH).expect("read README");
        let start = readme
            .find(README_PAIMOS_JSON_MARKER)
            .expect("README Paimos JSON marker")
            + README_PAIMOS_JSON_MARKER.len();
        let rest = readme[start..]
            .split_once("\n```")
            .expect("README Paimos JSON fence")
            .0;
        rest.to_string().into_bytes()
    }

    fn parse_checked_config(raw: &[u8]) -> ReporterConfigV1 {
        decode_strict(raw, "checked_example_invalid").expect("checked example JSON")
    }

    #[test]
    fn checked_example_parses_and_validates_before_transport() {
        let raw = checked_example_bytes();
        let config = parse_checked_config(&raw);
        validate_config(&config, false).expect("checked example shape");
        assert_eq!(config.schema, CONFIG_SCHEMA);
        assert_eq!(config.schema_version, 1);
        assert_eq!(config.handoff_id, HANDOFF_ID);
        assert_eq!(
            config.paimos_ca_file.as_deref(),
            Some("/example/inert/paimos-ca.pem")
        );
        assert_eq!(config.evidence.kind(), EvidenceKind::Authorization);

        let mut omitted = config;
        omitted.paimos_ca_file = None;
        let legacy_bytes = serde_json::to_vec(&omitted).expect("serialize omitted-CA config");
        assert_eq!(
            wire_digest(&legacy_bytes),
            "sha256:02d813feecbfcfb168bb63a9978a666abb68a89d54e322ee78c87525d9c4057c",
            "omitting paimos_ca_file must preserve the pre-JANUS-466 config digest"
        );
    }

    #[test]
    fn readme_paimos_json_matches_checked_example() {
        let example = checked_example_bytes();
        let readme = readme_paimos_config_bytes();
        let example_value: Value =
            serde_json::from_slice(&example).expect("parse checked example JSON");
        let readme_value: Value = serde_json::from_slice(&readme).expect("parse README JSON");
        assert_eq!(
            example_value, readme_value,
            "README Paimos JSON must match examples/paimos-dependency-reporter/config.example.json"
        );
    }

    #[test]
    fn checked_example_negative_shapes_fail_before_transport() {
        let valid = parse_checked_config(&checked_example_bytes());
        let cases: Vec<(&str, ConfigMutation, &'static str)> = vec![
            (
                "shared credential path",
                |mut config| {
                    config.handoff_secret_file = config.api_key_file.clone();
                    config
                },
                "paimos_reporter_config_invalid",
            ),
            (
                "non-https origin",
                |mut config| {
                    config.paimos_origin = "http://paimos.example".to_string();
                    config
                },
                "paimos_reporter_origin_refused",
            ),
            (
                "relative CA path",
                |mut config| {
                    config.paimos_ca_file = Some("relative/paimos-ca.pem".to_string());
                    config
                },
                "paimos_reporter_config_invalid",
            ),
            (
                "wrong schema",
                |mut config| {
                    config.schema = "inspr.janus.paimos-dependency-reporter-config.v0".to_string();
                    config
                },
                "paimos_reporter_config_invalid",
            ),
            (
                "invalid execution number",
                |mut config| {
                    config.expected.execution_number = 0;
                    config
                },
                "paimos_reporter_config_invalid",
            ),
            (
                "invalid digest",
                |mut config| {
                    config.expected.plan_digest = "sha256:not-a-valid-wire-digest".to_string();
                    config
                },
                "paimos_reporter_config_invalid",
            ),
            (
                "invalid timestamp",
                |mut config| {
                    config.evidence = DependencyEvidenceV1::Authorization {
                        observed_at: "not-a-timestamp".to_string(),
                    };
                    config
                },
                "paimos_reporter_config_invalid",
            ),
        ];
        for (label, mutate, expected_reason) in cases {
            let config = mutate(valid.clone());
            let error = validate_config(&config, false)
                .expect_err(&format!("{label} must fail validation"));
            assert_eq!(
                error.reason_code(),
                expected_reason,
                "{label}: unexpected refusal"
            );
        }

        let unknown_field = br#"{"schema":"inspr.janus.paimos-dependency-reporter-config.v1","schema_version":1,"opaque":"forbidden"}"#;
        assert_eq!(
            decode_strict::<ReporterConfigV1>(unknown_field, "unknown_field")
                .expect_err("unknown field")
                .reason_code(),
            "unknown_field"
        );
        let duplicate_name =
            br#"{"schema":"inspr.janus.paimos-dependency-reporter-config.v1","schema":"dup"}"#;
        assert_eq!(
            decode_strict::<ReporterConfigV1>(duplicate_name, "duplicate_field")
                .expect_err("duplicate field")
                .reason_code(),
            "duplicate_field"
        );
    }
}
