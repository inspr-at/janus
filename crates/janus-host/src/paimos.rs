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
const JOURNAL_SCHEMA: &str = "inspr.janus.paimos-dependency-reporter-journal.v1";
const SYSTEM_CONFIG_PATH: &str = "/run/janus-paimos-dependency-reporter/config.json";
const MAX_CONFIG_BYTES: usize = 32 * 1024;
const MAX_API_KEY_BYTES: usize = 4 * 1024;
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
    handoff_id: String,
    api_key_file: String,
    handoff_secret_file: String,
    journal_directory: String,
    expected: ExpectedBindingV1,
    evidence: DependencyEvidenceV1,
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
    let raw = read_private_regular(
        Path::new(SYSTEM_CONFIG_PATH),
        MAX_CONFIG_BYTES,
        Some(0),
        "paimos_reporter_config_unavailable",
    )
    .map_err(|_| PaimosReporterError::new("paimos_reporter_config_unavailable"))?;
    let config = decode_strict::<ReporterConfigV1>(&raw, "paimos_reporter_config_invalid")?;
    Reporter::new(config, 0, false)?.run()
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
        let http = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(3))
            .timeout_read(Duration::from_secs(8))
            .timeout_write(Duration::from_secs(8))
            .redirects(0)
            .build();
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

fn decode_strict<T: for<'de> Deserialize<'de>>(
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
}
