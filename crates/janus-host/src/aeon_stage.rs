//! One-shot Aeon stage-handoff reporting for the Janus Access plugin.
//!
//! This is the Aeon counterpart of the classic Paimos external-stage adapter in
//! [`crate::paimos`]. The classic adapter, its fixtures, and its journals stay
//! unchanged; a root-owned config selects this adapter by its schema.
//!
//! One run binds one Aeon Access handoff (`stage.prepare` or `stage.apply`,
//! routed to the `janus` agent principal) and records exactly two value-free
//! facts followed by one terminal result:
//!
//! 1. `authorization` with `authorized: true`, observed when this process has
//!    just re-read the bound project journey and the open, unexpired handoff;
//! 2. `credential_handoff` with `credential_ready: true`, observed at the
//!    configured (static) or durable managed-completion (managed) time;
//! 3. a `succeeded` result echoing the stored prerequisite seal.
//!
//! Aeon has no accept step, handoff secret, or fixture digest. Its live agent
//! grant, gate, authority epoch, and seal are checked server-side on every
//! write. Exact request bytes are journaled before the first mutation and
//! replayed unchanged after an ambiguous failure, in a journal file namespaced
//! apart from classic journals so a restart can never replay a classic report
//! into Aeon.

use std::fmt;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use fs2::FileExt;
use janus_core::MaterialTimestamp;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{atomic_write, read_private_regular};
use crate::paimos::{
    absolute_path, acquire_lock, build_http_agent, canonical_json_bytes, decode_strict,
    normalized_origin, valid_timestamp, validate_private_directory, wire_digest,
    PaimosReporterError,
};

/// Aeon stage-handoff wire contract Janus is pinned to.
pub const AEON_STAGE_CONTRACT: &str = "inspr.aeon.stage-handoff.v1";
/// Aeon release carrying the pinned stage-handoff and journey contract.
pub const AEON_STAGE_RELEASE: &str = "v260926071154.0.0";
/// Aeon commit of [`AEON_STAGE_RELEASE`].
pub const AEON_STAGE_COMMIT: &str = "482c563482c014c2097e65f7ef528444e12ec7af";
/// SHA-256 of `api/openapi.yaml` at [`AEON_STAGE_COMMIT`].
pub const AEON_OPENAPI_SHA256: &str =
    "4420f2d269af7477bcb41a7fa0d670f28376a151145c71ebb368c61ade370493";

pub(crate) const CONFIG_SCHEMA: &str = "inspr.janus.aeon-stage-reporter-config.v1";
pub(crate) const MANAGED_CONFIG_SCHEMA: &str =
    "inspr.janus.aeon-managed-completion-reporter-config.v1";
const MANAGED_BINDING_SCHEMA: &str = "inspr.janus.aeon-managed-completion-reporter-binding.v1";
const JOURNAL_SCHEMA: &str = "inspr.janus.aeon-stage-reporter-journal.v1";
const JOURNAL_PREFIX: &str = "aeon-";
const MAX_CONFIG_BYTES: usize = 32 * 1024;
const MAX_API_KEY_BYTES: usize = 512;
const MAX_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_JOURNAL_BYTES: usize = 64 * 1024;
const JANUS_PLUGIN_ID: &str = "janus";
const ACCESS_STAGE: &str = "access";
const MANAGED_EVIDENCE_SOURCE: &str = "managed_completion_record";
const REATTESTATION_EVIDENCE_SOURCE: &str = "managed_credential_reattestation_record";
/// Go serializes the zero `time.Time` even under `omitempty`; Aeon therefore
/// echoes this value for the launch-readiness-only field on Janus evidence.
const GO_ZERO_TIME: &str = "0001-01-01T00:00:00Z";

/// Stable value-free adapter failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AeonReporterError {
    reason_code: &'static str,
}

impl AeonReporterError {
    fn new(reason_code: &'static str) -> Self {
        Self { reason_code }
    }

    /// Stable reason code that never contains a path, credential, URL, or body.
    pub fn reason_code(self) -> &'static str {
        self.reason_code
    }

    /// Rename a failure from a helper shared with the classic adapter so an
    /// Aeon run never reports a classic reason code.
    fn from_shared(error: PaimosReporterError) -> Self {
        Self::new(match error.reason_code() {
            "paimos_reporter_origin_refused" => "aeon_reporter_origin_refused",
            "paimos_reporter_ca_invalid" => "aeon_reporter_ca_invalid",
            "paimos_reporter_ca_file_refused" => "aeon_reporter_ca_file_refused",
            "paimos_reporter_journal_directory_unavailable" => {
                "aeon_reporter_journal_directory_unavailable"
            }
            "paimos_reporter_journal_directory_refused" => {
                "aeon_reporter_journal_directory_refused"
            }
            "paimos_reporter_lock_refused" => "aeon_reporter_lock_refused",
            "paimos_reporter_lock_unavailable" => "aeon_reporter_lock_unavailable",
            "paimos_reporter_busy" => "aeon_reporter_busy",
            _ => "aeon_reporter_local_refused",
        })
    }
}

impl fmt::Display for AeonReporterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code)
    }
}

impl std::error::Error for AeonReporterError {}

pub(crate) type AeonResult<T> = Result<T, AeonReporterError>;

/// Reviewed Aeon project identity. Every journey read must match it exactly.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AeonProjectBindingV1 {
    project_node_id: String,
    project_key: String,
    node_key: String,
    tenant_slug: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum AeonOperation {
    Prepare,
    Apply,
}

impl AeonOperation {
    fn as_str(self) -> &'static str {
        match self {
            Self::Prepare => "prepare",
            Self::Apply => "apply",
        }
    }
}

/// Reviewed Aeon handoff tuple, copied from `GET /api/stage-handoffs/{id}`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AeonHandoffBindingV1 {
    handoff_id: String,
    release_node_id: String,
    operation: AeonOperation,
    authority_epoch: i64,
    plan_digest: String,
    predecessor_digest: String,
    context_digest: String,
    expires_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AeonStaticEvidenceV1 {
    credential_ready_observed_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AeonManagedEvidencePolicyV1 {
    source: String,
}

/// Root-owned static dependency-reporter config selecting the Aeon adapter.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AeonStageReporterConfigV1 {
    schema: String,
    schema_version: u8,
    aeon_origin: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    aeon_ca_file: Option<String>,
    api_key_file: String,
    journal_directory: String,
    project: AeonProjectBindingV1,
    handoff: AeonHandoffBindingV1,
    evidence: AeonStaticEvidenceV1,
}

/// Root-owned managed-completion reporter config. The credential-ready time
/// comes later from the separately validated durable completion record.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AeonManagedReporterConfigV1 {
    schema: String,
    schema_version: u8,
    aeon_origin: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    aeon_ca_file: Option<String>,
    api_key_file: String,
    journal_directory: String,
    project: AeonProjectBindingV1,
    handoff: AeonHandoffBindingV1,
    evidence: AeonManagedEvidencePolicyV1,
}

/// Value-free fingerprint and exact Aeon tuple for one immutable managed
/// completion config. It grants no Aeon authority: the protected config, the
/// scoped key, and Aeon's live grant and gate checks are all still required.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AeonManagedCompletionBindingV1 {
    pub(crate) schema: String,
    pub(crate) schema_version: u8,
    pub(crate) config_digest: String,
    pub(crate) project_node_id: String,
    pub(crate) handoff_id: String,
    pub(crate) release_node_id: String,
    pub(crate) operation: String,
    pub(crate) authority_epoch: i64,
    pub(crate) plan_digest: String,
    pub(crate) predecessor_digest: String,
    pub(crate) context_digest: String,
    pub(crate) expires_at: String,
    pub(crate) evidence_source: String,
}

/// The shared runtime shape both entry points reduce to.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RuntimeConfig {
    config_digest: String,
    aeon_origin: String,
    aeon_ca_file: Option<String>,
    api_key_file: String,
    journal_directory: String,
    project: AeonProjectBindingV1,
    handoff: AeonHandoffBindingV1,
    credential_ready_observed_at: String,
}

/// Only the journey fields Janus binds to; the projection itself is not read.
#[derive(Debug, Deserialize)]
struct JourneyIdentity {
    project_node_id: String,
    project_key: String,
    node_key: Option<String>,
    tenant_slug: String,
    current_release_id: Option<String>,
}

/// Safe handoff projection at [`AEON_STAGE_COMMIT`]. Unknown fields fail
/// closed: a drifted contract needs a reviewed pin update.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HandoffResponse {
    id: String,
    project_node_id: String,
    release_node_id: String,
    stage: String,
    operation: String,
    plugin_id: String,
    attempt: i64,
    authority_epoch: i64,
    journey_revision: i64,
    state: String,
    expires_at: String,
    evidence_ceiling: Vec<String>,
    plan_digest: String,
    predecessor_digest: String,
    context_digest: String,
    prerequisite_seal_sha256: String,
    #[serde(default)]
    result: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct EvidenceWrite {
    sequence: i64,
    kind: String,
    outcome: String,
    observed_at: String,
    authority_epoch: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authorized: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    credential_ready: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceEcho {
    sequence: i64,
    kind: String,
    outcome: String,
    observed_at: String,
    authority_epoch: i64,
    #[serde(default)]
    authorized: Option<bool>,
    #[serde(default)]
    credential_ready: Option<bool>,
    #[serde(default)]
    backup_observed_at: Option<String>,
    handoff_id: String,
    received_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ResultWrite {
    outcome: String,
    terminal_sequence: i64,
    authority_epoch: i64,
    prerequisite_seal_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResultEcho {
    outcome: String,
    terminal_sequence: i64,
    authority_epoch: i64,
    prerequisite_seal_sha256: String,
    #[serde(default)]
    blocker_code: Option<String>,
    handoff_id: String,
    completed_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RequestJournalV1 {
    request_digest: String,
    body: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReceiptV1 {
    sequence: i64,
    server_time: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AeonJournalV1 {
    schema: String,
    schema_version: u8,
    contract: String,
    aeon_commit: String,
    aeon_release: String,
    openapi_sha256: String,
    handoff_id: String,
    config_digest: String,
    prerequisite_seal_sha256: String,
    authorization: RequestJournalV1,
    authorization_receipt: Option<ReceiptV1>,
    credential_handoff: RequestJournalV1,
    credential_handoff_receipt: Option<ReceiptV1>,
    result: RequestJournalV1,
    result_receipt: Option<ReceiptV1>,
}

#[derive(Deserialize)]
struct SchemaProbe {
    schema: String,
}

/// True when a root-owned reporter config selects the Aeon adapter. Anything
/// else, including an unreadable document, stays on the classic path, which
/// then applies its own strict decoding.
pub(crate) fn selects_aeon(raw: &[u8], schema: &str) -> bool {
    decode_strict::<SchemaProbe>(raw, "aeon_reporter_config_invalid")
        .is_ok_and(|probe| probe.schema == schema)
}

/// Run the static dependency reporter from already-read root-owned config bytes.
pub(crate) fn run_static_config(
    raw: &[u8],
    owner_uid: u32,
    allow_loopback_http: bool,
) -> AeonResult<()> {
    let config: AeonStageReporterConfigV1 = decode(raw, "aeon_reporter_config_invalid")?;
    let runtime = static_runtime(config, allow_loopback_http)?;
    Reporter::new(runtime, owner_uid, allow_loopback_http, now_unix())?.run()
}

/// Run the managed-completion reporter for one validated completion record.
pub(crate) fn run_managed_completion_from_path(
    path: &Path,
    binding: &AeonManagedCompletionBindingV1,
    credential_ready_observed_at: String,
    owner_uid: u32,
    allow_loopback_http: bool,
) -> AeonResult<()> {
    let raw = read_private_regular(
        path,
        MAX_CONFIG_BYTES,
        Some(owner_uid),
        "aeon_reporter_config_unavailable",
    )
    .map_err(|_| AeonReporterError::new("aeon_reporter_config_unavailable"))?;
    let config: AeonManagedReporterConfigV1 = decode(&raw, "aeon_reporter_config_invalid")?;
    let runtime = managed_runtime(
        config,
        binding,
        credential_ready_observed_at,
        allow_loopback_http,
    )?;
    Reporter::new(runtime, owner_uid, allow_loopback_http, now_unix())?.run()
}

fn decode<T: for<'de> Deserialize<'de>>(raw: &[u8], reason: &'static str) -> AeonResult<T> {
    decode_strict(raw, reason).map_err(|_| AeonReporterError::new(reason))
}

fn now_unix() -> i64 {
    MaterialTimestamp::from_system_time(SystemTime::now()).unix_seconds()
}

fn static_runtime(
    config: AeonStageReporterConfigV1,
    allow_loopback_http: bool,
) -> AeonResult<RuntimeConfig> {
    if config.schema != CONFIG_SCHEMA
        || config.schema_version != 1
        || !valid_second_timestamp(&config.evidence.credential_ready_observed_at)
    {
        return Err(AeonReporterError::new("aeon_reporter_config_invalid"));
    }
    validate_common(
        &config.aeon_origin,
        config.aeon_ca_file.as_deref(),
        &config.api_key_file,
        &config.journal_directory,
        &config.project,
        &config.handoff,
        allow_loopback_http,
    )?;
    Ok(RuntimeConfig {
        config_digest: config_digest(&config)?,
        aeon_origin: config.aeon_origin,
        aeon_ca_file: config.aeon_ca_file,
        api_key_file: config.api_key_file,
        journal_directory: config.journal_directory,
        project: config.project,
        handoff: config.handoff,
        credential_ready_observed_at: config.evidence.credential_ready_observed_at,
    })
}

fn managed_runtime(
    config: AeonManagedReporterConfigV1,
    binding: &AeonManagedCompletionBindingV1,
    credential_ready_observed_at: String,
    allow_loopback_http: bool,
) -> AeonResult<RuntimeConfig> {
    if managed_reporter_binding(&config, allow_loopback_http)? != *binding {
        return Err(AeonReporterError::new("aeon_reporter_binding_refused"));
    }
    if !valid_second_timestamp(&credential_ready_observed_at) {
        return Err(AeonReporterError::new("aeon_reporter_evidence_invalid"));
    }
    Ok(RuntimeConfig {
        config_digest: binding.config_digest.clone(),
        aeon_origin: config.aeon_origin,
        aeon_ca_file: config.aeon_ca_file,
        api_key_file: config.api_key_file,
        journal_directory: config.journal_directory,
        project: config.project,
        handoff: config.handoff,
        credential_ready_observed_at,
    })
}

fn validate_managed_config(
    config: &AeonManagedReporterConfigV1,
    allow_loopback_http: bool,
) -> AeonResult<()> {
    if config.schema != MANAGED_CONFIG_SCHEMA
        || config.schema_version != 1
        || !valid_evidence_source(&config.evidence.source)
    {
        return Err(AeonReporterError::new("aeon_reporter_config_invalid"));
    }
    validate_common(
        &config.aeon_origin,
        config.aeon_ca_file.as_deref(),
        &config.api_key_file,
        &config.journal_directory,
        &config.project,
        &config.handoff,
        allow_loopback_http,
    )
}

/// Build the value-free binding the managed-completion binding must carry.
pub(crate) fn managed_reporter_binding(
    config: &AeonManagedReporterConfigV1,
    allow_loopback_http: bool,
) -> AeonResult<AeonManagedCompletionBindingV1> {
    validate_managed_config(config, allow_loopback_http)?;
    Ok(AeonManagedCompletionBindingV1 {
        schema: MANAGED_BINDING_SCHEMA.to_string(),
        schema_version: 1,
        config_digest: config_digest(config)?,
        project_node_id: config.project.project_node_id.clone(),
        handoff_id: config.handoff.handoff_id.clone(),
        release_node_id: config.handoff.release_node_id.clone(),
        operation: config.handoff.operation.as_str().to_string(),
        authority_epoch: config.handoff.authority_epoch,
        plan_digest: config.handoff.plan_digest.clone(),
        predecessor_digest: config.handoff.predecessor_digest.clone(),
        context_digest: config.handoff.context_digest.clone(),
        expires_at: config.handoff.expires_at.clone(),
        evidence_source: config.evidence.source.clone(),
    })
}

/// Shape check for a binding read before its config is opened.
pub(crate) fn validate_managed_reporter_binding_shape(
    binding: &AeonManagedCompletionBindingV1,
) -> AeonResult<()> {
    if binding.schema != MANAGED_BINDING_SCHEMA
        || binding.schema_version != 1
        || !valid_wire_digest(&binding.config_digest)
        || !valid_uuid(&binding.project_node_id)
        || !valid_uuid(&binding.handoff_id)
        || !valid_uuid(&binding.release_node_id)
        || !matches!(binding.operation.as_str(), "prepare" | "apply")
        || binding.authority_epoch <= 0
        || !valid_hex64(&binding.plan_digest)
        || !valid_hex64(&binding.predecessor_digest)
        || !valid_hex64(&binding.context_digest)
        || parse_instant(&binding.expires_at).is_none()
        || !valid_evidence_source(&binding.evidence_source)
    {
        return Err(AeonReporterError::new("aeon_reporter_binding_refused"));
    }
    Ok(())
}

fn config_digest<T: Serialize>(config: &T) -> AeonResult<String> {
    canonical_json_bytes(config)
        .map(|bytes| wire_digest(&bytes))
        .map_err(|_| AeonReporterError::new("aeon_reporter_config_invalid"))
}

#[allow(clippy::too_many_arguments)]
fn validate_common(
    origin: &str,
    ca_file: Option<&str>,
    api_key_file: &str,
    journal_directory: &str,
    project: &AeonProjectBindingV1,
    handoff: &AeonHandoffBindingV1,
    allow_loopback_http: bool,
) -> AeonResult<()> {
    normalized_origin(origin, allow_loopback_http).map_err(AeonReporterError::from_shared)?;
    if ca_file.is_some_and(|path| !absolute_path(path))
        || !absolute_path(api_key_file)
        || !absolute_path(journal_directory)
        || !valid_uuid(&project.project_node_id)
        || !valid_project_key(&project.project_key)
        || !valid_node_key(&project.node_key)
        || !valid_tenant_slug(&project.tenant_slug)
        || !valid_uuid(&handoff.handoff_id)
        || !valid_uuid(&handoff.release_node_id)
        || handoff.authority_epoch <= 0
        || !valid_hex64(&handoff.plan_digest)
        || !valid_hex64(&handoff.predecessor_digest)
        || !valid_hex64(&handoff.context_digest)
        || parse_instant(&handoff.expires_at).is_none()
    {
        return Err(AeonReporterError::new("aeon_reporter_config_invalid"));
    }
    Ok(())
}

struct Reporter {
    config: RuntimeConfig,
    authorization: Zeroizing<String>,
    http: ureq::Agent,
    origin: String,
    journal_path: PathBuf,
    owner_uid: u32,
    now: i64,
    lock: File,
}

impl Drop for Reporter {
    fn drop(&mut self) {
        // Release the flock on the shared open-file description even if a
        // forked child still holds an inherited duplicate descriptor.
        let _ = FileExt::unlock(&self.lock);
    }
}

impl Reporter {
    fn new(
        config: RuntimeConfig,
        owner_uid: u32,
        allow_loopback_http: bool,
        now: i64,
    ) -> AeonResult<Self> {
        let origin = normalized_origin(&config.aeon_origin, allow_loopback_http)
            .map_err(AeonReporterError::from_shared)?;
        let authorization = read_api_key(Path::new(&config.api_key_file), owner_uid)?;
        let journal_directory = Path::new(&config.journal_directory);
        validate_private_directory(journal_directory, owner_uid)
            .map_err(AeonReporterError::from_shared)?;
        let name = format!("{JOURNAL_PREFIX}{}", config.handoff.handoff_id);
        let journal_path = journal_directory.join(format!("{name}.json"));
        let lock = acquire_lock(journal_directory, &name, owner_uid)
            .map_err(AeonReporterError::from_shared)?;
        let http = build_http_agent(config.aeon_ca_file.as_deref(), owner_uid)
            .map_err(AeonReporterError::from_shared)?;
        Ok(Self {
            config,
            authorization,
            http,
            origin,
            journal_path,
            owner_uid,
            now,
            lock,
        })
    }

    fn run(&self) -> AeonResult<()> {
        let mut journal = match self.load_journal()? {
            Some(journal) => journal,
            None => {
                let seal = self.preflight()?;
                let journal = self.initial_journal(seal)?;
                self.persist_journal(&journal)?;
                journal
            }
        };
        self.validate_journal(&journal)?;
        if journal.result_receipt.is_some() {
            return Ok(());
        }
        self.require_unexpired()?;

        if journal.authorization_receipt.is_none() {
            let receipt = self.send_evidence(&journal.authorization)?;
            journal.authorization_receipt = Some(receipt);
            self.persist_journal(&journal)?;
        }
        if journal.credential_handoff_receipt.is_none() {
            let receipt = self.send_evidence(&journal.credential_handoff)?;
            journal.credential_handoff_receipt = Some(receipt);
            self.persist_journal(&journal)?;
        }
        let receipt = self.send_result(&journal.result)?;
        journal.result_receipt = Some(receipt);
        self.persist_journal(&journal)
    }

    /// Re-read the bound journey and handoff before any report is journaled.
    /// Returns the stored prerequisite seal the terminal result must echo.
    fn preflight(&self) -> AeonResult<String> {
        self.require_unexpired()?;
        let journey: JourneyIdentity = self.get(&format!(
            "/api/projects/{}/journey",
            self.config.project.project_node_id
        ))?;
        let project = &self.config.project;
        let handoff = &self.config.handoff;
        if journey.project_node_id != project.project_node_id
            || journey.project_key != project.project_key
            || journey.node_key.as_deref() != Some(project.node_key.as_str())
            || journey.tenant_slug != project.tenant_slug
        {
            return Err(AeonReporterError::new("aeon_reporter_project_refused"));
        }
        if journey.current_release_id.as_deref() != Some(handoff.release_node_id.as_str()) {
            return Err(AeonReporterError::new("aeon_reporter_release_stale"));
        }

        let pulled: HandoffResponse =
            self.get(&format!("/api/stage-handoffs/{}", handoff.handoff_id))?;
        if pulled.id != handoff.handoff_id
            || pulled.project_node_id != project.project_node_id
            || pulled.release_node_id != handoff.release_node_id
            || pulled.stage != ACCESS_STAGE
            || pulled.operation != handoff.operation.as_str()
            || pulled.plugin_id != JANUS_PLUGIN_ID
            || pulled.attempt < 1
            || pulled.journey_revision < 1
            || pulled.plan_digest != handoff.plan_digest
            || pulled.predecessor_digest != handoff.predecessor_digest
            || pulled.context_digest != handoff.context_digest
            || pulled.evidence_ceiling != ["authorization", "credential_handoff"]
            || parse_instant(&pulled.expires_at) != parse_instant(&handoff.expires_at)
            || !valid_hex64(&pulled.prerequisite_seal_sha256)
        {
            return Err(AeonReporterError::new("aeon_reporter_binding_refused"));
        }
        if pulled.authority_epoch != handoff.authority_epoch {
            return Err(AeonReporterError::new("aeon_reporter_authority_stale"));
        }
        if pulled.result.is_some() || !matches!(pulled.state.as_str(), "requested" | "active") {
            return Err(AeonReporterError::new("aeon_reporter_handoff_closed"));
        }
        Ok(pulled.prerequisite_seal_sha256)
    }

    fn require_unexpired(&self) -> AeonResult<()> {
        match parse_instant(&self.config.handoff.expires_at) {
            Some((seconds, _)) if self.now < seconds => Ok(()),
            _ => Err(AeonReporterError::new("aeon_reporter_handoff_expired")),
        }
    }

    fn get<T: for<'de> Deserialize<'de>>(&self, path: &str) -> AeonResult<T> {
        let response = self
            .http
            .get(&format!("{}{path}", self.origin))
            .set("Accept", "application/json")
            .set("Accept-Encoding", "identity")
            .set("Authorization", self.authorization.as_str())
            .call();
        decode_response(accept_status(response, 200)?)
    }

    fn post(&self, path: &str, body: &str, status: u16) -> AeonResult<ureq::Response> {
        let response = self
            .http
            .post(&format!("{}{path}", self.origin))
            .set("Accept", "application/json")
            .set("Accept-Encoding", "identity")
            .set("Content-Type", "application/json")
            .set("Authorization", self.authorization.as_str())
            .send_bytes(body.as_bytes());
        accept_status(response, status)
    }

    fn send_evidence(&self, request: &RequestJournalV1) -> AeonResult<ReceiptV1> {
        let sent: EvidenceWrite = decode(request.body.as_bytes(), "aeon_reporter_journal_invalid")?;
        let response = self.post(
            &format!(
                "/api/stage-handoffs/{}/evidence",
                self.config.handoff.handoff_id
            ),
            &request.body,
            201,
        )?;
        let echo: EvidenceEcho = decode_response(response)?;
        if echo.handoff_id != self.config.handoff.handoff_id
            || echo.sequence != sent.sequence
            || echo.kind != sent.kind
            || echo.outcome != sent.outcome
            || parse_instant(&echo.observed_at) != parse_instant(&sent.observed_at)
            || echo.authority_epoch != sent.authority_epoch
            || echo.authorized != sent.authorized
            || echo.credential_ready != sent.credential_ready
            || echo
                .backup_observed_at
                .as_deref()
                .is_some_and(|value| value != GO_ZERO_TIME)
            || parse_instant(&echo.received_at).is_none()
        {
            return Err(AeonReporterError::new("aeon_reporter_receipt_invalid"));
        }
        Ok(ReceiptV1 {
            sequence: echo.sequence,
            server_time: echo.received_at,
        })
    }

    fn send_result(&self, request: &RequestJournalV1) -> AeonResult<ReceiptV1> {
        let sent: ResultWrite = decode(request.body.as_bytes(), "aeon_reporter_journal_invalid")?;
        let response = self.post(
            &format!(
                "/api/stage-handoffs/{}/result",
                self.config.handoff.handoff_id
            ),
            &request.body,
            200,
        )?;
        let echo: ResultEcho = decode_response(response)?;
        if echo.handoff_id != self.config.handoff.handoff_id
            || echo.outcome != sent.outcome
            || echo.terminal_sequence != sent.terminal_sequence
            || echo.authority_epoch != sent.authority_epoch
            || echo.prerequisite_seal_sha256 != sent.prerequisite_seal_sha256
            || echo.blocker_code.is_some()
            || parse_instant(&echo.completed_at).is_none()
        {
            return Err(AeonReporterError::new("aeon_reporter_receipt_invalid"));
        }
        Ok(ReceiptV1 {
            sequence: echo.terminal_sequence,
            server_time: echo.completed_at,
        })
    }

    fn authorization_request(&self, observed_at: String) -> EvidenceWrite {
        EvidenceWrite {
            sequence: 1,
            kind: "authorization".to_string(),
            outcome: "satisfied".to_string(),
            observed_at,
            authority_epoch: self.config.handoff.authority_epoch,
            authorized: Some(true),
            credential_ready: None,
        }
    }

    fn credential_request(&self) -> EvidenceWrite {
        EvidenceWrite {
            sequence: 2,
            kind: "credential_handoff".to_string(),
            outcome: "satisfied".to_string(),
            observed_at: self.config.credential_ready_observed_at.clone(),
            authority_epoch: self.config.handoff.authority_epoch,
            authorized: None,
            credential_ready: Some(true),
        }
    }

    fn result_request(&self, seal: &str) -> ResultWrite {
        ResultWrite {
            outcome: "succeeded".to_string(),
            terminal_sequence: 2,
            authority_epoch: self.config.handoff.authority_epoch,
            prerequisite_seal_sha256: seal.to_string(),
        }
    }

    fn initial_journal(&self, seal: String) -> AeonResult<AeonJournalV1> {
        let observed_at = MaterialTimestamp::from_unix_seconds(self.now).to_utc_string();
        Ok(AeonJournalV1 {
            schema: JOURNAL_SCHEMA.to_string(),
            schema_version: 1,
            contract: AEON_STAGE_CONTRACT.to_string(),
            aeon_commit: AEON_STAGE_COMMIT.to_string(),
            aeon_release: AEON_STAGE_RELEASE.to_string(),
            openapi_sha256: AEON_OPENAPI_SHA256.to_string(),
            handoff_id: self.config.handoff.handoff_id.clone(),
            config_digest: self.config.config_digest.clone(),
            authorization: journal_request(&self.authorization_request(observed_at))?,
            authorization_receipt: None,
            credential_handoff: journal_request(&self.credential_request())?,
            credential_handoff_receipt: None,
            result: journal_request(&self.result_request(&seal))?,
            result_receipt: None,
            prerequisite_seal_sha256: seal,
        })
    }

    fn load_journal(&self) -> AeonResult<Option<AeonJournalV1>> {
        match fs::symlink_metadata(&self.journal_path) {
            Ok(_) => {
                let raw = read_private_regular(
                    &self.journal_path,
                    MAX_JOURNAL_BYTES,
                    Some(self.owner_uid),
                    "aeon_reporter_journal_invalid",
                )
                .map_err(|_| AeonReporterError::new("aeon_reporter_journal_invalid"))?;
                decode(&raw, "aeon_reporter_journal_invalid").map(Some)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(AeonReporterError::new("aeon_reporter_journal_invalid")),
        }
    }

    fn validate_journal(&self, journal: &AeonJournalV1) -> AeonResult<()> {
        let invalid = || AeonReporterError::new("aeon_reporter_journal_invalid");
        if journal.schema != JOURNAL_SCHEMA
            || journal.schema_version != 1
            || journal.contract != AEON_STAGE_CONTRACT
            || journal.aeon_commit != AEON_STAGE_COMMIT
            || journal.aeon_release != AEON_STAGE_RELEASE
            || journal.openapi_sha256 != AEON_OPENAPI_SHA256
            || journal.handoff_id != self.config.handoff.handoff_id
            || journal.config_digest != self.config.config_digest
            || !valid_hex64(&journal.prerequisite_seal_sha256)
        {
            return Err(invalid());
        }
        for request in [
            &journal.authorization,
            &journal.credential_handoff,
            &journal.result,
        ] {
            if request.request_digest != wire_digest(request.body.as_bytes()) {
                return Err(invalid());
            }
        }
        // The authorization time was this process's own observation when the
        // journal was written; everything else in it is fixed by the config.
        let authorization: EvidenceWrite = decode(
            journal.authorization.body.as_bytes(),
            "aeon_reporter_journal_invalid",
        )?;
        if !valid_second_timestamp(&authorization.observed_at)
            || journal.authorization
                != journal_request(&self.authorization_request(authorization.observed_at))?
            || journal.credential_handoff != journal_request(&self.credential_request())?
            || journal.result
                != journal_request(&self.result_request(&journal.prerequisite_seal_sha256))?
        {
            return Err(invalid());
        }
        let receipts = [
            (&journal.authorization_receipt, 1),
            (&journal.credential_handoff_receipt, 2),
            (&journal.result_receipt, 2),
        ];
        let mut previous_present = true;
        for (receipt, sequence) in receipts {
            if let Some(receipt) = receipt {
                if !previous_present
                    || receipt.sequence != sequence
                    || parse_instant(&receipt.server_time).is_none()
                {
                    return Err(invalid());
                }
            }
            previous_present = receipt.is_some();
        }
        Ok(())
    }

    fn persist_journal(&self, journal: &AeonJournalV1) -> AeonResult<()> {
        let mut raw = serde_json::to_vec(journal)
            .map_err(|_| AeonReporterError::new("aeon_reporter_journal_invalid"))?;
        raw.push(b'\n');
        atomic_write(
            &self.journal_path,
            &raw,
            0o600,
            self.owner_uid,
            "aeon_reporter_journal_unavailable",
        )
        .map_err(|_| AeonReporterError::new("aeon_reporter_journal_unavailable"))
    }
}

fn journal_request<T: Serialize>(request: &T) -> AeonResult<RequestJournalV1> {
    let body = serde_json::to_vec(request)
        .map_err(|_| AeonReporterError::new("aeon_reporter_request_invalid"))?;
    Ok(RequestJournalV1 {
        request_digest: wire_digest(&body),
        body: String::from_utf8(body)
            .map_err(|_| AeonReporterError::new("aeon_reporter_request_invalid"))?,
    })
}

fn read_api_key(path: &Path, owner_uid: u32) -> AeonResult<Zeroizing<String>> {
    let raw = Zeroizing::new(
        read_private_regular(
            path,
            MAX_API_KEY_BYTES,
            Some(owner_uid),
            "aeon_reporter_api_key_unavailable",
        )
        .map_err(|_| AeonReporterError::new("aeon_reporter_api_key_unavailable"))?,
    );
    let key = Zeroizing::new(
        String::from_utf8(raw.to_vec())
            .map_err(|_| AeonReporterError::new("aeon_reporter_api_key_invalid"))?,
    );
    if !valid_aeon_api_key(&key) {
        return Err(AeonReporterError::new("aeon_reporter_api_key_invalid"));
    }
    Ok(Zeroizing::new(format!("Bearer {}", key.as_str())))
}

/// `aeon_<prefix>_<secret>`: exactly two underscores, both parts non-empty,
/// no whitespace or line ending.
fn valid_aeon_api_key(key: &str) -> bool {
    let Some(rest) = key.strip_prefix("aeon_") else {
        return false;
    };
    let Some((prefix, secret)) = rest.split_once('_') else {
        return false;
    };
    let part = |value: &str| {
        !value.is_empty()
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    };
    key.len() >= 24 && part(prefix) && part(secret)
}

fn accept_status(
    response: Result<ureq::Response, ureq::Error>,
    expected: u16,
) -> AeonResult<ureq::Response> {
    match response {
        Ok(response) if response.status() == expected => Ok(response),
        Ok(_) => Err(AeonReporterError::new("aeon_reporter_remote_refused")),
        Err(ureq::Error::Status(403, _)) | Err(ureq::Error::Status(401, _)) => {
            Err(AeonReporterError::new("aeon_reporter_forbidden"))
        }
        Err(ureq::Error::Status(404, _)) => Err(AeonReporterError::new("aeon_reporter_not_found")),
        Err(ureq::Error::Status(409, _)) => Err(AeonReporterError::new("aeon_reporter_conflict")),
        Err(ureq::Error::Status(_, _)) => {
            Err(AeonReporterError::new("aeon_reporter_remote_refused"))
        }
        Err(ureq::Error::Transport(_)) => Err(AeonReporterError::new(
            "aeon_reporter_transport_unavailable",
        )),
    }
}

fn decode_response<T: for<'de> Deserialize<'de>>(response: ureq::Response) -> AeonResult<T> {
    let content_type = response.all("Content-Type");
    let json = content_type.len() == 1
        && matches!(
            content_type[0].to_ascii_lowercase().as_str(),
            "application/json" | "application/json; charset=utf-8"
        );
    if !json || !response.all("Content-Encoding").is_empty() {
        return Err(AeonReporterError::new("aeon_reporter_media_refused"));
    }
    let mut raw = Vec::new();
    response
        .into_reader()
        .take(MAX_RESPONSE_BYTES as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|_| AeonReporterError::new("aeon_reporter_response_invalid"))?;
    if raw.is_empty() || raw.len() > MAX_RESPONSE_BYTES {
        return Err(AeonReporterError::new("aeon_reporter_response_invalid"));
    }
    decode(&raw, "aeon_reporter_response_invalid")
}

/// Durable local records whose observation time a managed Aeon report uses.
/// Each consumer additionally pins the one source it accepts.
fn valid_evidence_source(value: &str) -> bool {
    matches!(
        value,
        MANAGED_EVIDENCE_SOURCE | REATTESTATION_EVIDENCE_SOURCE
    )
}

/// Canonical lowercase 8-4-4-4-12 UUID text.
pub(crate) fn valid_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'),
        })
}

fn valid_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_wire_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(valid_hex64)
}

fn valid_project_key(value: &str) -> bool {
    (2..=10).contains(&value.len())
        && value.as_bytes()[0].is_ascii_uppercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

fn valid_node_key(value: &str) -> bool {
    let Some((key, number)) = value.split_once('-') else {
        return false;
    };
    valid_project_key(key)
        && !number.is_empty()
        && number.len() <= 18
        && !number.starts_with('0')
        && number.bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_tenant_slug(value: &str) -> bool {
    (1..=63).contains(&value.len())
        && (value.as_bytes()[0].is_ascii_lowercase() || value.as_bytes()[0].is_ascii_digit())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// Second-precision UTC, the only form Janus writes as an observation.
fn valid_second_timestamp(value: &str) -> bool {
    value.len() == 20 && valid_timestamp(value)
}

/// Parse RFC 3339 text as Go's `time.Time` marshals it (`Z` or a numeric
/// offset, optional fraction up to nanoseconds) into Unix seconds and nanos.
pub(crate) fn parse_instant(value: &str) -> Option<(i64, u32)> {
    let bytes = value.as_bytes();
    if bytes.len() < 20 || !value.is_ascii() {
        return None;
    }
    let (body, offset_seconds) = if let Some(body) = value.strip_suffix('Z') {
        (body, 0_i64)
    } else {
        let split = value.len().checked_sub(6)?;
        let (body, offset) = value.split_at(split);
        let sign = match offset.as_bytes()[0] {
            b'+' => 1,
            b'-' => -1,
            _ => return None,
        };
        let digits = &offset.as_bytes()[1..];
        if digits.len() != 5 || digits[2] != b':' {
            return None;
        }
        let hours: i64 = offset[1..3].parse().ok()?;
        let minutes: i64 = offset[4..6].parse().ok()?;
        if hours > 23 || minutes > 59 {
            return None;
        }
        (body, sign * (hours * 3_600 + minutes * 60))
    };
    let (seconds_part, fraction) = match body.split_once('.') {
        Some((seconds, fraction)) => (seconds, Some(fraction)),
        None => (body, None),
    };
    let whole = MaterialTimestamp::parse_utc(&format!("{seconds_part}Z")).ok()?;
    let nanos = match fraction {
        None => 0,
        Some(digits)
            if !digits.is_empty()
                && digits.len() <= 9
                && digits.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            format!("{digits:0<9}").parse().ok()?
        }
        Some(_) => return None,
    };
    Some((whole.unix_seconds() - offset_seconds, nanos))
}

#[cfg(test)]
#[path = "aeon_stage_tests.rs"]
pub(crate) mod tests;
