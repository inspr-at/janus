//! One exact managed-create completion to one existing Paimos reporter.
//!
//! The optional root-owned binding is a closed capability: it names one
//! reviewed transaction/catalog tuple and one value-free reporter tuple. The
//! durable record is written before lifecycle completion and is the only
//! record considered on restart; historical lifecycle journals are never
//! scanned to manufacture evidence.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use fs2::FileExt;
use janus_host::paimos::PaimosReporterBindingV1;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{EntryCompletionReceipt, EntryPhase};

const BINDING_SCHEMA: &str = "inspr.janus.managed-completion-paimos-binding.v1";
const RECORD_SCHEMA: &str = "inspr.janus.managed-completion-dispatch-record.v1";
const MAX_BINDING_BYTES: usize = 64 * 1024;
const MAX_RECORD_BYTES: usize = 64 * 1024;
const MAX_DIRECTORY_ENTRIES: usize = 2;
const ACTIVATION_FRESHNESS_SECONDS: u64 = 120;
const ACTIVATION_CLOCK_SKEW_SECONDS: u64 = 30;
const RECORD_FILE: &str = "completion.json";
const LOCK_FILE: &str = ".completion.lock";
const SYSTEM_BINDING_PATH: &str = "/etc/janus/managed-completion-paimos-binding.json";
const SYSTEM_RECORD_DIRECTORY: &str = "/var/lib/janus/managed-completion-dispatch";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CompletionBindingV1 {
    schema: String,
    schema_version: u8,
    operation_ref: String,
    operation_kind: String,
    source: String,
    host_ref: String,
    service_ref: String,
    slot_ref: String,
    declaration_fingerprint: String,
    secret_ref: String,
    scope_ref: String,
    generation: u64,
    revocation_epoch: u64,
    plan_fingerprint: String,
    target_fingerprint: String,
    producer_key_id: String,
    reporter: PaimosReporterBindingV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CompletionCandidate {
    pub(super) operation_ref: String,
    pub(super) operation_id: String,
    pub(super) operation_kind: String,
    pub(super) source: String,
    pub(super) host_ref: String,
    pub(super) service_ref: String,
    pub(super) slot_ref: String,
    pub(super) declaration_fingerprint: String,
    pub(super) secret_ref: String,
    pub(super) scope_ref: String,
    pub(super) generation: u64,
    pub(super) revocation_epoch: u64,
    pub(super) plan_fingerprint: String,
    pub(super) target_fingerprint: String,
    pub(super) producer_key_id: String,
    pub(super) prepared_at_unix_secs: u64,
    pub(super) preflighted_at_unix_secs: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct AcceptedActivationEvidence {
    pub(super) generation: u64,
    pub(super) materialized: bool,
    pub(super) process_state: String,
    pub(super) probe_state: String,
    pub(super) heartbeat_observed_at_unix_secs: u64,
    pub(super) process_observed_at_unix_secs: u64,
    pub(super) probe_observed_at_unix_secs: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CompletionRecordV1 {
    schema: String,
    schema_version: u8,
    binding_digest: String,
    operation_ref: String,
    operation_id: String,
    generation: u64,
    prepared_at_unix_secs: u64,
    preflighted_at_unix_secs: u64,
    evidence_accepted_at_unix_secs: u64,
    activation_evidence: AcceptedActivationEvidence,
    value_returned: bool,
    integrity_hash: String,
}

pub(super) trait ReporterDispatch: Send + Sync {
    fn validate(&self, binding: &PaimosReporterBindingV1) -> Result<()>;
    fn run(&self, binding: &PaimosReporterBindingV1) -> Result<()>;
}

struct SystemReporterDispatch;

impl ReporterDispatch for SystemReporterDispatch {
    fn validate(&self, binding: &PaimosReporterBindingV1) -> Result<()> {
        janus_host::paimos::validate_system_binding(binding)
            .map_err(|error| anyhow::anyhow!(error.reason_code()))
    }

    fn run(&self, binding: &PaimosReporterBindingV1) -> Result<()> {
        janus_host::paimos::run_from_system_if_bound(binding)
            .map_err(|error| anyhow::anyhow!(error.reason_code()))
    }
}

pub(super) struct CompletionProducer {
    binding: CompletionBindingV1,
    binding_digest: String,
    record_path: PathBuf,
    owner_uid: u32,
    reporter: Arc<dyn ReporterDispatch>,
    record_lock: Mutex<()>,
    _process_lock: File,
}

impl CompletionProducer {
    pub(super) fn load_optional_system() -> Result<Option<Self>> {
        let path = Path::new(SYSTEM_BINDING_PATH);
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => anyhow::bail!("completion binding metadata unavailable"),
            Ok(_) => Self::load(
                path,
                Path::new(SYSTEM_RECORD_DIRECTORY),
                0,
                Arc::new(SystemReporterDispatch),
            )
            .map(Some),
        }
    }

    fn load(
        path: &Path,
        record_directory: &Path,
        owner_uid: u32,
        reporter: Arc<dyn ReporterDispatch>,
    ) -> Result<Self> {
        let raw = read_private_regular(path, MAX_BINDING_BYTES, owner_uid)
            .context("completion binding unavailable")?;
        let binding: CompletionBindingV1 =
            decode_strict(&raw).context("completion binding invalid")?;
        validate_binding(&binding)?;
        validate_private_directory(record_directory, owner_uid)?;
        enforce_directory_capacity(record_directory)?;
        let process_lock = acquire_process_lock(record_directory, owner_uid)?;
        reporter
            .validate(&binding.reporter)
            .context("completion reporter binding refused")?;
        let canonical = serde_json::to_vec(&binding).context("completion binding invalid")?;
        let binding_digest = format!("sha256:{:x}", Sha256::digest(canonical));
        let record_path = record_directory.join(RECORD_FILE);
        Ok(Self {
            binding,
            binding_digest,
            record_path,
            owner_uid,
            reporter,
            record_lock: Mutex::new(()),
            _process_lock: process_lock,
        })
    }

    pub(super) fn matches_candidate(&self, candidate: &CompletionCandidate) -> bool {
        self.binding.operation_ref == candidate.operation_ref
            && self.binding.operation_kind == candidate.operation_kind
            && self.binding.source == candidate.source
            && self.binding.host_ref == candidate.host_ref
            && self.binding.service_ref == candidate.service_ref
            && self.binding.slot_ref == candidate.slot_ref
            && self.binding.declaration_fingerprint == candidate.declaration_fingerprint
            && self.binding.secret_ref == candidate.secret_ref
            && self.binding.scope_ref == candidate.scope_ref
            && self.binding.generation == candidate.generation
            && self.binding.revocation_epoch == candidate.revocation_epoch
            && self.binding.plan_fingerprint == candidate.plan_fingerprint
            && self.binding.target_fingerprint == candidate.target_fingerprint
            && self.binding.producer_key_id == candidate.producer_key_id
    }

    pub(super) fn operation_ref(&self) -> &str {
        &self.binding.operation_ref
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn matches_catalog_key(
        &self,
        operation_kind: &str,
        source: &str,
        host_ref: &str,
        service_ref: &str,
        slot_ref: &str,
        declaration_fingerprint: &str,
        secret_ref: &str,
        scope_ref: &str,
        generation: u64,
        revocation_epoch: u64,
        producer_key_id: &str,
    ) -> bool {
        self.binding.operation_kind == operation_kind
            && self.binding.source == source
            && self.binding.host_ref == host_ref
            && self.binding.service_ref == service_ref
            && self.binding.slot_ref == slot_ref
            && self.binding.declaration_fingerprint == declaration_fingerprint
            && self.binding.secret_ref == secret_ref
            && self.binding.scope_ref == scope_ref
            && self.binding.generation == generation
            && self.binding.revocation_epoch == revocation_epoch
            && self.binding.producer_key_id == producer_key_id
    }

    pub(super) fn persist_accepted(
        &self,
        candidate: &CompletionCandidate,
        evidence: AcceptedActivationEvidence,
        accepted_at: SystemTime,
    ) -> Result<bool> {
        if self.binding.operation_ref != candidate.operation_ref {
            return Ok(false);
        }
        if !self.matches_candidate(candidate) {
            anyhow::bail!("completion transaction conflicts with protected binding");
        }
        self.reporter
            .validate(&self.binding.reporter)
            .context("completion reporter binding changed")?;
        let accepted_at = unix_seconds(accepted_at)?;
        if evidence.generation != candidate.generation
            || candidate.prepared_at_unix_secs == 0
            || candidate.preflighted_at_unix_secs == 0
        {
            anyhow::bail!("completion evidence binding invalid");
        }
        let mut record = CompletionRecordV1 {
            schema: RECORD_SCHEMA.to_string(),
            schema_version: 1,
            binding_digest: self.binding_digest.clone(),
            operation_ref: candidate.operation_ref.clone(),
            operation_id: candidate.operation_id.clone(),
            generation: candidate.generation,
            prepared_at_unix_secs: candidate.prepared_at_unix_secs,
            preflighted_at_unix_secs: candidate.preflighted_at_unix_secs,
            evidence_accepted_at_unix_secs: accepted_at,
            activation_evidence: evidence,
            value_returned: false,
            integrity_hash: String::new(),
        };
        if !record_evidence_is_valid(&record) {
            anyhow::bail!("completion evidence is not positive and fresh");
        }
        record.integrity_hash = record_hash(&record)?;
        let _guard = self
            .record_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("completion record lock poisoned"))?;
        match read_record_if_present(&self.record_path, self.owner_uid)? {
            Some(existing) if record_matches_candidate(&existing, candidate, &record) => Ok(true),
            Some(_) => anyhow::bail!("completion record conflicts with existing binding"),
            None => {
                write_private_atomic_new(
                    &self.record_path,
                    &serde_json::to_vec(&record)?,
                    self.owner_uid,
                )?;
                Ok(true)
            }
        }
    }

    pub(super) fn dispatch_if_eligible(&self, receipt: &EntryCompletionReceipt) -> Result<bool> {
        let _guard = self
            .record_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("completion record lock poisoned"))?;
        let Some(record) = read_record_if_present(&self.record_path, self.owner_uid)? else {
            return Ok(false);
        };
        if record.binding_digest != self.binding_digest
            || record.operation_ref != self.binding.operation_ref
            || record.operation_id != receipt.operation_id
            || record.generation != receipt.generation
            || record.preflighted_at_unix_secs != receipt.preflighted_at_unix_secs
            || record.activation_evidence.generation != receipt.generation
            || receipt.secret_ref != self.binding.secret_ref
            || receipt.mode != "generated"
            || receipt.operation_kind != "create"
            || receipt.plan_fingerprint != self.binding.plan_fingerprint
            || receipt.target_fingerprint != self.binding.target_fingerprint
        {
            anyhow::bail!("completion record no longer matches transaction");
        }
        if receipt.phase != EntryPhase::Completed
            || receipt.reason_code != "entry_external_activation_ok"
        {
            return Ok(false);
        }
        self.reporter
            .run(&self.binding.reporter)
            .context("completion reporter failed")?;
        Ok(true)
    }
}

fn record_matches_candidate(
    existing: &CompletionRecordV1,
    candidate: &CompletionCandidate,
    proposed: &CompletionRecordV1,
) -> bool {
    existing.schema == proposed.schema
        && existing.schema_version == proposed.schema_version
        && existing.binding_digest == proposed.binding_digest
        && existing.operation_ref == candidate.operation_ref
        && existing.operation_id == candidate.operation_id
        && existing.generation == candidate.generation
        && existing.prepared_at_unix_secs == candidate.prepared_at_unix_secs
        && existing.preflighted_at_unix_secs == candidate.preflighted_at_unix_secs
        && existing.activation_evidence == proposed.activation_evidence
        && !existing.value_returned
}

fn validate_binding(binding: &CompletionBindingV1) -> Result<()> {
    if binding.schema != BINDING_SCHEMA
        || binding.schema_version != 1
        || !valid_ref("op_", &binding.operation_ref)
        || binding.operation_kind != "create"
        || binding.source != "generated"
        || !valid_ref("host_", &binding.host_ref)
        || !valid_ref("svc_", &binding.service_ref)
        || !valid_ref("slot_", &binding.slot_ref)
        || !valid_ref("decl_", &binding.declaration_fingerprint)
        || !valid_ref("sec_", &binding.secret_ref)
        || !valid_ref("scp_", &binding.scope_ref)
        || !valid_ref("key_", &binding.producer_key_id)
        || binding.generation == 0
        || binding.revocation_epoch == 0
        || !valid_hex_digest(&binding.plan_fingerprint)
        || !valid_hex_digest(&binding.target_fingerprint)
    {
        anyhow::bail!("completion binding contract invalid");
    }
    Ok(())
}

fn valid_ref(prefix: &str, value: &str) -> bool {
    value.len() >= prefix.len() + 8
        && value.len() <= 96
        && value.starts_with(prefix)
        && value.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
        })
}

fn valid_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn record_hash(record: &CompletionRecordV1) -> Result<String> {
    let mut unsigned = record.clone();
    unsigned.integrity_hash.clear();
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&unsigned)?)))
}

fn read_record_if_present(path: &Path, owner_uid: u32) -> Result<Option<CompletionRecordV1>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => anyhow::bail!("completion record metadata unavailable"),
        Ok(_) => {
            let raw = read_private_regular(path, MAX_RECORD_BYTES, owner_uid)?;
            let record: CompletionRecordV1 = decode_strict(&raw)?;
            if record.schema != RECORD_SCHEMA
                || record.schema_version != 1
                || record.value_returned
                || record.integrity_hash != record_hash(&record)?
                || !record_evidence_is_valid(&record)
            {
                anyhow::bail!("completion record invalid");
            }
            Ok(Some(record))
        }
    }
}

fn record_evidence_is_valid(record: &CompletionRecordV1) -> bool {
    let evidence = &record.activation_evidence;
    let oldest = evidence
        .heartbeat_observed_at_unix_secs
        .min(evidence.process_observed_at_unix_secs)
        .min(evidence.probe_observed_at_unix_secs);
    let newest = evidence
        .heartbeat_observed_at_unix_secs
        .max(evidence.process_observed_at_unix_secs)
        .max(evidence.probe_observed_at_unix_secs);
    evidence.generation == record.generation
        && evidence.materialized
        && evidence.process_state == "running"
        && evidence.probe_state == "healthy"
        && oldest >= record.prepared_at_unix_secs
        && newest
            <= record
                .evidence_accepted_at_unix_secs
                .saturating_add(ACTIVATION_CLOCK_SKEW_SECONDS)
        && record.evidence_accepted_at_unix_secs.saturating_sub(oldest)
            <= ACTIVATION_FRESHNESS_SECONDS
}

fn read_private_regular(path: &Path, maximum: usize, owner_uid: u32) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).context("private file unavailable")?;
    if !metadata.file_type().is_file()
        || metadata.uid() != owner_uid
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() == 0
        || metadata.len() > maximum as u64
    {
        anyhow::bail!("private file custody refused");
    }
    let mut file = File::open(path).context("private file unavailable")?;
    let opened = file.metadata().context("private file unavailable")?;
    if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
        anyhow::bail!("private file changed while opening");
    }
    let mut raw = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut raw)
        .context("private file unavailable")?;
    if raw.is_empty() || raw.len() > maximum {
        anyhow::bail!("private file size refused");
    }
    Ok(raw)
}

fn validate_private_directory(path: &Path, owner_uid: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(path).context("completion record directory unavailable")?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o777 != 0o700
    {
        anyhow::bail!("completion record directory custody refused");
    }
    Ok(())
}

fn enforce_directory_capacity(path: &Path) -> Result<()> {
    let mut entries = 0usize;
    for entry in fs::read_dir(path).context("completion record directory unavailable")? {
        let entry = entry.context("completion record directory unavailable")?;
        entries = entries.saturating_add(1);
        if entries > MAX_DIRECTORY_ENTRIES
            || !matches!(entry.file_name().to_str(), Some(RECORD_FILE | LOCK_FILE))
        {
            anyhow::bail!("completion record directory capacity refused");
        }
    }
    Ok(())
}

fn acquire_process_lock(directory: &Path, owner_uid: u32) -> Result<File> {
    let path = directory.join(LOCK_FILE);
    if let Ok(metadata) = fs::symlink_metadata(&path) {
        if !metadata.file_type().is_file()
            || metadata.uid() != owner_uid
            || metadata.nlink() != 1
            || metadata.mode() & 0o777 != 0o600
        {
            anyhow::bail!("completion process lock custody refused");
        }
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)?;
    let metadata = file.metadata()?;
    if metadata.uid() != owner_uid || metadata.nlink() != 1 || metadata.mode() & 0o777 != 0o600 {
        anyhow::bail!("completion process lock custody refused");
    }
    file.try_lock_exclusive()
        .context("completion producer already active")?;
    Ok(file)
}

fn write_private_atomic_new(path: &Path, bytes: &[u8], owner_uid: u32) -> Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
        anyhow::bail!("completion record size refused");
    }
    let parent = path.parent().context("completion record path invalid")?;
    validate_private_directory(parent, owner_uid)?;
    if path.exists() {
        anyhow::bail!("completion record already exists");
    }
    let temp = parent.join(format!(
        ".completion-{}.{}.tmp",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
            .context("completion record temporary file unavailable")?;
        let metadata = file.metadata()?;
        if metadata.uid() != owner_uid || metadata.nlink() != 1 || metadata.mode() & 0o777 != 0o600
        {
            anyhow::bail!("completion record temporary custody refused");
        }
        file.write_all(bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn decode_strict<T: for<'de> Deserialize<'de>>(raw: &[u8]) -> Result<T> {
    let mut decoder = serde_json::Deserializer::from_slice(raw);
    let value = T::deserialize(&mut decoder).context("invalid JSON")?;
    decoder.end().context("trailing JSON")?;
    Ok(value)
}

fn unix_seconds(time: SystemTime) -> Result<u64> {
    Ok(time.duration_since(UNIX_EPOCH)?.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingReporter {
        validations: AtomicUsize,
        runs: AtomicUsize,
    }

    impl CountingReporter {
        fn new() -> Self {
            Self {
                validations: AtomicUsize::new(0),
                runs: AtomicUsize::new(0),
            }
        }
    }

    impl ReporterDispatch for CountingReporter {
        fn validate(&self, _: &PaimosReporterBindingV1) -> Result<()> {
            self.validations.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn run(&self, _: &PaimosReporterBindingV1) -> Result<()> {
            self.runs.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct Fixture {
        _temporary: tempfile::TempDir,
        producer: CompletionProducer,
        reporter: Arc<CountingReporter>,
        candidate: CompletionCandidate,
        evidence: AcceptedActivationEvidence,
        owner_uid: u32,
        binding_path: PathBuf,
    }

    fn reporter_binding() -> PaimosReporterBindingV1 {
        serde_json::from_value(serde_json::json!({
            "schema": "inspr.janus.paimos-dependency-reporter-binding.v1",
            "schema_version": 1,
            "config_digest": format!("sha256:{}", "a".repeat(64)),
            "handoff_id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "dependency_key": "privileged-handoff",
            "stage_key": "deployment",
            "execution_number": 1,
            "plan_digest": format!("sha256:{}", "1".repeat(64)),
            "predecessor_digest": format!("sha256:{}", "2".repeat(64)),
            "authority_epoch": 1,
            "context_digest": format!("sha256:{}", "3".repeat(64)),
            "credential_epoch": 1,
            "expires_at": "2026-09-09T09:00:00Z",
            "evidence_kind": "credential_handoff",
            "evidence_observed_at": "2026-09-09T08:00:00Z"
        }))
        .unwrap()
    }

    fn fixture() -> Fixture {
        let temporary = tempfile::Builder::new()
            .prefix("completion.")
            .tempdir_in("/tmp")
            .unwrap();
        let owner_uid = fs::metadata(temporary.path()).unwrap().uid();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let record_directory = temporary.path().join("records");
        fs::create_dir(&record_directory).unwrap();
        fs::set_permissions(&record_directory, fs::Permissions::from_mode(0o700)).unwrap();
        let binding_path = temporary.path().join("binding.json");
        let binding = CompletionBindingV1 {
            schema: BINDING_SCHEMA.to_string(),
            schema_version: 1,
            operation_ref: "op_0123456789abcdef".to_string(),
            operation_kind: "create".to_string(),
            source: "generated".to_string(),
            host_ref: "host_0123456789abcdef".to_string(),
            service_ref: "svc_0123456789abcdef".to_string(),
            slot_ref: "slot_0123456789abcdef".to_string(),
            declaration_fingerprint: "decl_0123456789abcdef".to_string(),
            secret_ref: "sec_0123456789abcdef".to_string(),
            scope_ref: "scp_0123456789abcdef0123456789abcdef01234567".to_string(),
            generation: 3,
            revocation_epoch: 7,
            plan_fingerprint: "4".repeat(64),
            target_fingerprint: "5".repeat(64),
            producer_key_id: "key_0123456789abcdef".to_string(),
            reporter: reporter_binding(),
        };
        fs::write(&binding_path, serde_json::to_vec(&binding).unwrap()).unwrap();
        fs::set_permissions(&binding_path, fs::Permissions::from_mode(0o600)).unwrap();
        let reporter = Arc::new(CountingReporter::new());
        let producer = CompletionProducer::load(
            &binding_path,
            &record_directory,
            owner_uid,
            reporter.clone(),
        )
        .unwrap();
        let candidate = CompletionCandidate {
            operation_ref: binding.operation_ref,
            operation_id: "webtx_0123456789abcdef".to_string(),
            operation_kind: binding.operation_kind,
            source: binding.source,
            host_ref: binding.host_ref,
            service_ref: binding.service_ref,
            slot_ref: binding.slot_ref,
            declaration_fingerprint: binding.declaration_fingerprint,
            secret_ref: binding.secret_ref,
            scope_ref: binding.scope_ref,
            generation: binding.generation,
            revocation_epoch: binding.revocation_epoch,
            plan_fingerprint: binding.plan_fingerprint,
            target_fingerprint: binding.target_fingerprint,
            producer_key_id: binding.producer_key_id,
            prepared_at_unix_secs: 1_800_000_000,
            preflighted_at_unix_secs: 1_799_999_990,
        };
        let evidence = AcceptedActivationEvidence {
            generation: 3,
            materialized: true,
            process_state: "running".to_string(),
            probe_state: "healthy".to_string(),
            heartbeat_observed_at_unix_secs: 1_800_000_001,
            process_observed_at_unix_secs: 1_800_000_002,
            probe_observed_at_unix_secs: 1_800_000_003,
        };
        Fixture {
            _temporary: temporary,
            producer,
            reporter,
            candidate,
            evidence,
            owner_uid,
            binding_path,
        }
    }

    fn receipt(fixture: &Fixture, phase: EntryPhase, reason: &str) -> EntryCompletionReceipt {
        EntryCompletionReceipt {
            operation_id: fixture.candidate.operation_id.clone(),
            secret_ref: fixture.candidate.secret_ref.clone(),
            mode: "generated".to_string(),
            operation_kind: "create".to_string(),
            generation: fixture.candidate.generation,
            phase,
            reason_code: reason.to_string(),
            plan_fingerprint: fixture.candidate.plan_fingerprint.clone(),
            target_fingerprint: fixture.candidate.target_fingerprint.clone(),
            preflighted_at_unix_secs: fixture.candidate.preflighted_at_unix_secs,
        }
    }

    #[test]
    fn only_exact_external_completion_can_dispatch_the_persisted_evidence() {
        let fixture = fixture();
        fixture
            .producer
            .persist_accepted(
                &fixture.candidate,
                fixture.evidence.clone(),
                UNIX_EPOCH + std::time::Duration::from_secs(1_800_000_010),
            )
            .unwrap();
        for (phase, reason) in [
            (EntryPhase::Validated, "entry_validation_ok"),
            (EntryPhase::Failed, "entry_activation_failed"),
            (EntryPhase::RolledBack, "entry_rolled_back"),
            (EntryPhase::Completed, "entry_activation_ok"),
        ] {
            assert!(!fixture
                .producer
                .dispatch_if_eligible(&receipt(&fixture, phase, reason))
                .unwrap());
        }
        assert_eq!(fixture.reporter.runs.load(Ordering::SeqCst), 0);
        let mut wrong_generation = receipt(
            &fixture,
            EntryPhase::Completed,
            "entry_external_activation_ok",
        );
        wrong_generation.generation += 1;
        assert!(fixture
            .producer
            .dispatch_if_eligible(&wrong_generation)
            .is_err());
        let mut wrong_target = receipt(
            &fixture,
            EntryPhase::Completed,
            "entry_external_activation_ok",
        );
        wrong_target.target_fingerprint = "6".repeat(64);
        assert!(fixture
            .producer
            .dispatch_if_eligible(&wrong_target)
            .is_err());
        assert_eq!(fixture.reporter.runs.load(Ordering::SeqCst), 0);
        assert!(fixture
            .producer
            .dispatch_if_eligible(&receipt(
                &fixture,
                EntryPhase::Completed,
                "entry_external_activation_ok",
            ))
            .unwrap());
        assert_eq!(fixture.reporter.runs.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn retry_preserves_original_observations_and_conflicting_evidence_fails_closed() {
        let fixture = fixture();
        let first_accept = UNIX_EPOCH + std::time::Duration::from_secs(1_800_000_010);
        assert!(fixture
            .producer
            .persist_accepted(&fixture.candidate, fixture.evidence.clone(), first_accept)
            .unwrap());
        assert!(fixture
            .producer
            .persist_accepted(
                &fixture.candidate,
                fixture.evidence.clone(),
                first_accept + std::time::Duration::from_secs(30),
            )
            .unwrap());
        let record = read_record_if_present(&fixture.producer.record_path, fixture.owner_uid)
            .unwrap()
            .unwrap();
        assert_eq!(record.evidence_accepted_at_unix_secs, 1_800_000_010);
        assert_eq!(record.activation_evidence, fixture.evidence);
        let mut conflicting = fixture.evidence.clone();
        conflicting.probe_observed_at_unix_secs += 1;
        assert!(fixture
            .producer
            .persist_accepted(&fixture.candidate, conflicting, first_accept)
            .is_err());
    }

    #[test]
    fn stale_durable_evidence_cannot_reach_the_reporter() {
        let fixture = fixture();
        let mut stale = fixture.evidence.clone();
        stale.heartbeat_observed_at_unix_secs =
            fixture.candidate.prepared_at_unix_secs.saturating_sub(1);
        assert!(fixture
            .producer
            .persist_accepted(
                &fixture.candidate,
                stale,
                UNIX_EPOCH + std::time::Duration::from_secs(1_800_000_010),
            )
            .is_err());
        assert!(
            read_record_if_present(&fixture.producer.record_path, fixture.owner_uid)
                .unwrap()
                .is_none()
        );
        assert_eq!(fixture.reporter.runs.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn binding_custody_rejects_symlinks_and_hardlinks() {
        let fixture = fixture();
        let hardlink = fixture.binding_path.with_extension("hardlink");
        fs::hard_link(&fixture.binding_path, &hardlink).unwrap();
        assert!(CompletionProducer::load(
            &fixture.binding_path,
            fixture.producer.record_path.parent().unwrap(),
            fixture.owner_uid,
            fixture.reporter.clone(),
        )
        .is_err());
        fs::remove_file(hardlink).unwrap();
        let symlink = fixture.binding_path.with_extension("symlink");
        std::os::unix::fs::symlink(&fixture.binding_path, &symlink).unwrap();
        assert!(CompletionProducer::load(
            &symlink,
            fixture.producer.record_path.parent().unwrap(),
            fixture.owner_uid,
            fixture.reporter.clone(),
        )
        .is_err());
    }

    #[test]
    fn durable_record_is_private_bounded_and_value_free() {
        let fixture = fixture();
        fixture
            .producer
            .persist_accepted(
                &fixture.candidate,
                fixture.evidence.clone(),
                UNIX_EPOCH + std::time::Duration::from_secs(1_800_000_010),
            )
            .unwrap();
        let metadata = fs::metadata(&fixture.producer.record_path).unwrap();
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        assert!(metadata.len() <= MAX_RECORD_BYTES as u64);
        let raw = fs::read(&fixture.producer.record_path).unwrap();
        let rendered = String::from_utf8(raw).unwrap();
        for forbidden in [
            "SENSITIVE_TRANSACTION_CANARY",
            "ciphertext",
            "packet_base64",
        ] {
            assert!(!rendered.contains(forbidden));
        }
    }
}
