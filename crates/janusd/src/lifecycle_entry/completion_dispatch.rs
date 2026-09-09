//! Networkless producer for one managed-create completion.
//!
//! This module never reads reporter configuration or credentials and never
//! performs network I/O. It persists one immutable accepted-evidence record
//! before lifecycle completion, then moves the same inode from `pending.json`
//! to `ready.json` only after the exact bound completion receipt exists.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{EntryCompletionReceipt, EntryPhase};
use anyhow::{Context, Result};
use fs2::FileExt;
use janus_host::paimos_completion::{
    decode_record, AcceptedActivationEvidenceV1, ManagedCompletionCapabilityV1,
    ManagedCompletionRecordV2, RECORD_SCHEMA,
};

const SYSTEM_RECORD_DIRECTORY: &str = "/var/lib/janus-managed-central/completion-dispatch";
const PENDING_FILE: &str = "pending.json";
const READY_FILE: &str = "ready.json";
const LOCK_FILE: &str = ".producer.lock";
const MAX_RECORD_BYTES: usize = 64 * 1024;
const MAX_DIRECTORY_ENTRIES: usize = 2;
const PRODUCER_UID: u32 = 100;
const PRODUCER_GID: u32 = 993;

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

pub(super) struct CompletionProducer {
    capability: ManagedCompletionCapabilityV1,
    directory: PathBuf,
    pending_path: PathBuf,
    ready_path: PathBuf,
    owner_uid: u32,
    owner_gid: u32,
    record_lock: Mutex<()>,
    _process_lock: File,
}

impl CompletionProducer {
    pub(super) fn load_system(capability: ManagedCompletionCapabilityV1) -> Result<Self> {
        Self::load(
            capability,
            Path::new(SYSTEM_RECORD_DIRECTORY),
            PRODUCER_UID,
            PRODUCER_GID,
        )
    }

    fn load(
        capability: ManagedCompletionCapabilityV1,
        directory: &Path,
        owner_uid: u32,
        owner_gid: u32,
    ) -> Result<Self> {
        capability
            .validate()
            .map_err(|error| anyhow::anyhow!(error.reason_code()))?;
        validate_private_directory(directory, owner_uid, owner_gid)?;
        enforce_directory_capacity(directory)?;
        let process_lock = acquire_process_lock(directory, owner_uid, owner_gid)?;
        Ok(Self {
            capability,
            directory: directory.to_path_buf(),
            pending_path: directory.join(PENDING_FILE),
            ready_path: directory.join(READY_FILE),
            owner_uid,
            owner_gid,
            record_lock: Mutex::new(()),
            _process_lock: process_lock,
        })
    }

    #[cfg(test)]
    pub(super) fn load_for_test(
        capability: ManagedCompletionCapabilityV1,
        directory: &Path,
        owner_uid: u32,
        owner_gid: u32,
    ) -> Result<Self> {
        Self::load(capability, directory, owner_uid, owner_gid)
    }

    pub(super) fn persist_accepted(
        &self,
        candidate: &CompletionCandidate,
        evidence: AcceptedActivationEvidenceV1,
        accepted_at: SystemTime,
    ) -> Result<bool> {
        if candidate.operation_ref != self.capability.operation_ref {
            anyhow::bail!("completion operation conflicts with reviewed capability");
        }

        let _guard = self
            .record_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("completion record lock poisoned"))?;
        enforce_directory_capacity(&self.directory)?;
        let pending = read_record_if_present(&self.pending_path, self.owner_uid, self.owner_gid)?;
        let ready = read_record_if_present(&self.ready_path, self.owner_uid, self.owner_gid)?;
        let accepted_at_unix_secs = match (&pending, &ready) {
            (Some(existing), None) | (None, Some(existing)) => {
                existing.evidence_accepted_at_unix_secs
            }
            (None, None) => unix_seconds(accepted_at)?,
            (Some(_), Some(_)) => {
                anyhow::bail!("completion record conflicts with existing evidence")
            }
        };
        let mut proposed = ManagedCompletionRecordV2 {
            schema: RECORD_SCHEMA.to_string(),
            schema_version: 1,
            binding_digest: self.capability.binding_digest.clone(),
            operation_ref: candidate.operation_ref.clone(),
            operation_id: candidate.operation_id.clone(),
            operation_kind: candidate.operation_kind.clone(),
            source: candidate.source.clone(),
            host_ref: candidate.host_ref.clone(),
            service_ref: candidate.service_ref.clone(),
            slot_ref: candidate.slot_ref.clone(),
            declaration_fingerprint: candidate.declaration_fingerprint.clone(),
            secret_ref: candidate.secret_ref.clone(),
            scope_ref: candidate.scope_ref.clone(),
            generation: candidate.generation,
            revocation_epoch: candidate.revocation_epoch,
            plan_fingerprint: candidate.plan_fingerprint.clone(),
            target_fingerprint: candidate.target_fingerprint.clone(),
            producer_key_id: candidate.producer_key_id.clone(),
            prepared_at_unix_secs: candidate.prepared_at_unix_secs,
            preflighted_at_unix_secs: candidate.preflighted_at_unix_secs,
            evidence_accepted_at_unix_secs: accepted_at_unix_secs,
            activation_evidence: evidence,
            integrity_hash: String::new(),
        };
        proposed
            .seal()
            .map_err(|error| anyhow::anyhow!(error.reason_code()))?;

        match (pending, ready) {
            (Some(existing), None) | (None, Some(existing))
                if record_matches_proposed(&existing, &proposed) =>
            {
                Ok(true)
            }
            (None, None) => {
                write_private_atomic_new(
                    &self.pending_path,
                    &serde_json::to_vec(&proposed)?,
                    self.owner_uid,
                    self.owner_gid,
                )?;
                Ok(true)
            }
            _ => anyhow::bail!("completion record conflicts with existing evidence"),
        }
    }

    pub(super) fn operation_ref(&self) -> &str {
        &self.capability.operation_ref
    }

    pub(super) fn needs_reconciliation(&self) -> Result<bool> {
        let _guard = self
            .record_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("completion record lock poisoned"))?;
        enforce_directory_capacity(&self.directory)?;
        Ok(read_record_if_present(&self.pending_path, self.owner_uid, self.owner_gid)?.is_some())
    }

    /// Publish eligibility by moving, never rewriting, the accepted record.
    pub(super) fn mark_ready(&self, receipt: &EntryCompletionReceipt) -> Result<bool> {
        let _guard = self
            .record_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("completion record lock poisoned"))?;
        enforce_directory_capacity(&self.directory)?;
        if receipt.phase != EntryPhase::Completed
            || receipt.reason_code != "entry_external_activation_ok"
        {
            return Ok(false);
        }
        if let Some(ready) =
            read_record_if_present(&self.ready_path, self.owner_uid, self.owner_gid)?
        {
            validate_completion_receipt(&ready, receipt)?;
            return Ok(true);
        }
        let Some(pending) =
            read_record_if_present(&self.pending_path, self.owner_uid, self.owner_gid)?
        else {
            return Ok(false);
        };
        validate_completion_receipt(&pending, receipt)?;
        let before = fs::symlink_metadata(&self.pending_path)?;
        if self.ready_path.exists() {
            anyhow::bail!("completion ready record conflicts with pending evidence");
        }
        fs::rename(&self.pending_path, &self.ready_path)
            .context("completion readiness persistence failed")?;
        let after = fs::symlink_metadata(&self.ready_path)?;
        if after.dev() != before.dev()
            || after.ino() != before.ino()
            || after.nlink() != 1
            || after.uid() != self.owner_uid
            || after.gid() != self.owner_gid
            || after.mode() & 0o777 != 0o600
        {
            anyhow::bail!("completion ready record custody refused");
        }
        File::open(&self.directory)?.sync_all()?;
        Ok(true)
    }

    #[cfg(test)]
    pub(super) fn pending_path(&self) -> &Path {
        &self.pending_path
    }

    #[cfg(test)]
    pub(super) fn ready_path(&self) -> &Path {
        &self.ready_path
    }
}

fn record_matches_proposed(
    existing: &ManagedCompletionRecordV2,
    proposed: &ManagedCompletionRecordV2,
) -> bool {
    existing.schema == proposed.schema
        && existing.schema_version == proposed.schema_version
        && existing.binding_digest == proposed.binding_digest
        && existing.operation_ref == proposed.operation_ref
        && existing.operation_id == proposed.operation_id
        && existing.operation_kind == proposed.operation_kind
        && existing.source == proposed.source
        && existing.host_ref == proposed.host_ref
        && existing.service_ref == proposed.service_ref
        && existing.slot_ref == proposed.slot_ref
        && existing.declaration_fingerprint == proposed.declaration_fingerprint
        && existing.secret_ref == proposed.secret_ref
        && existing.scope_ref == proposed.scope_ref
        && existing.generation == proposed.generation
        && existing.revocation_epoch == proposed.revocation_epoch
        && existing.plan_fingerprint == proposed.plan_fingerprint
        && existing.target_fingerprint == proposed.target_fingerprint
        && existing.producer_key_id == proposed.producer_key_id
        && existing.prepared_at_unix_secs == proposed.prepared_at_unix_secs
        && existing.preflighted_at_unix_secs == proposed.preflighted_at_unix_secs
        && existing.evidence_accepted_at_unix_secs == proposed.evidence_accepted_at_unix_secs
        && existing.activation_evidence == proposed.activation_evidence
        && existing.integrity_hash == proposed.integrity_hash
}

fn validate_completion_receipt(
    record: &ManagedCompletionRecordV2,
    receipt: &EntryCompletionReceipt,
) -> Result<()> {
    if record.operation_id != receipt.operation_id
        || record.secret_ref != receipt.secret_ref
        || receipt.mode != "generated"
        || receipt.operation_kind != "create"
        || record.generation != receipt.generation
        || record.plan_fingerprint != receipt.plan_fingerprint
        || record.target_fingerprint != receipt.target_fingerprint
        || record.preflighted_at_unix_secs != receipt.preflighted_at_unix_secs
    {
        anyhow::bail!("completion record no longer matches transaction");
    }
    Ok(())
}

fn read_record_if_present(
    path: &Path,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<Option<ManagedCompletionRecordV2>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => anyhow::bail!("completion record metadata unavailable"),
        Ok(_) => {
            let raw = read_private_regular(path, MAX_RECORD_BYTES, owner_uid, owner_gid)?;
            let record =
                decode_record(&raw).map_err(|error| anyhow::anyhow!(error.reason_code()))?;
            Ok(Some(record))
        }
    }
}

fn read_private_regular(
    path: &Path,
    maximum: usize,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).context("private file unavailable")?;
    if !metadata.file_type().is_file()
        || metadata.uid() != owner_uid
        || metadata.gid() != owner_gid
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

fn validate_private_directory(path: &Path, owner_uid: u32, owner_gid: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(path).context("completion record directory unavailable")?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != owner_uid
        || metadata.gid() != owner_gid
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
            || !matches!(
                entry.file_name().to_str(),
                Some(PENDING_FILE | READY_FILE | LOCK_FILE)
            )
        {
            anyhow::bail!("completion record directory capacity refused");
        }
    }
    if path.join(PENDING_FILE).exists() && path.join(READY_FILE).exists() {
        anyhow::bail!("completion record directory contains conflicting states");
    }
    Ok(())
}

fn acquire_process_lock(directory: &Path, owner_uid: u32, owner_gid: u32) -> Result<File> {
    let path = directory.join(LOCK_FILE);
    if let Ok(metadata) = fs::symlink_metadata(&path) {
        if !metadata.file_type().is_file()
            || metadata.uid() != owner_uid
            || metadata.gid() != owner_gid
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
    if metadata.uid() != owner_uid
        || metadata.gid() != owner_gid
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
    {
        anyhow::bail!("completion process lock custody refused");
    }
    file.try_lock_exclusive()
        .context("completion producer already active")?;
    Ok(file)
}

fn write_private_atomic_new(
    path: &Path,
    bytes: &[u8],
    owner_uid: u32,
    owner_gid: u32,
) -> Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
        anyhow::bail!("completion record size refused");
    }
    let parent = path.parent().context("completion record path invalid")?;
    validate_private_directory(parent, owner_uid, owner_gid)?;
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
        if metadata.uid() != owner_uid
            || metadata.gid() != owner_gid
            || metadata.nlink() != 1
            || metadata.mode() & 0o777 != 0o600
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

fn unix_seconds(time: SystemTime) -> Result<u64> {
    Ok(time.duration_since(UNIX_EPOCH)?.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    struct Fixture {
        _temporary: tempfile::TempDir,
        producer: CompletionProducer,
        candidate: CompletionCandidate,
        evidence: AcceptedActivationEvidenceV1,
        owner_uid: u32,
        owner_gid: u32,
    }

    fn fixture() -> Fixture {
        let temporary = tempfile::Builder::new()
            .prefix("completion.")
            .tempdir_in("/tmp")
            .unwrap();
        let owner_uid = fs::metadata(temporary.path()).unwrap().uid();
        let owner_gid = fs::metadata(temporary.path()).unwrap().gid();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let capability = ManagedCompletionCapabilityV1 {
            schema: janus_host::paimos_completion::CAPABILITY_SCHEMA.to_string(),
            schema_version: 1,
            operation_ref: "op_0123456789abcdef".to_string(),
            binding_digest: format!("sha256:{}", "a".repeat(64)),
        };
        let producer =
            CompletionProducer::load(capability, temporary.path(), owner_uid, owner_gid).unwrap();
        let candidate = CompletionCandidate {
            operation_ref: "op_0123456789abcdef".to_string(),
            operation_id: "webtx_0123456789abcdef".to_string(),
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
            preflighted_at_unix_secs: 1_800_000_000,
            prepared_at_unix_secs: 1_800_000_005,
        };
        let evidence = AcceptedActivationEvidenceV1 {
            generation: 3,
            materialized: true,
            process_state: "running".to_string(),
            probe_state: "healthy".to_string(),
            heartbeat_observed_at_unix_secs: 1_800_000_006,
            process_observed_at_unix_secs: 1_800_000_007,
            probe_observed_at_unix_secs: 1_800_000_008,
        };
        Fixture {
            _temporary: temporary,
            producer,
            candidate,
            evidence,
            owner_uid,
            owner_gid,
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
    fn pending_record_is_immutable_until_exact_completion_moves_same_inode() {
        let fixture = fixture();
        fixture
            .producer
            .persist_accepted(
                &fixture.candidate,
                fixture.evidence.clone(),
                UNIX_EPOCH + std::time::Duration::from_secs(1_800_000_010),
            )
            .unwrap();
        let pending = fs::symlink_metadata(fixture.producer.pending_path()).unwrap();
        let pending_bytes = fs::read(fixture.producer.pending_path()).unwrap();
        assert!(fixture
            .producer
            .persist_accepted(
                &fixture.candidate,
                fixture.evidence.clone(),
                UNIX_EPOCH + std::time::Duration::from_secs(1_800_001_010),
            )
            .unwrap());
        assert_eq!(
            pending_bytes,
            fs::read(fixture.producer.pending_path()).unwrap()
        );
        assert!(!fixture
            .producer
            .mark_ready(&receipt(
                &fixture,
                EntryPhase::Validated,
                "entry_validation_ok"
            ))
            .unwrap());
        assert!(!fixture
            .producer
            .mark_ready(&receipt(
                &fixture,
                EntryPhase::Failed,
                "entry_activation_failed"
            ))
            .unwrap());
        assert!(!fixture
            .producer
            .mark_ready(&receipt(
                &fixture,
                EntryPhase::RolledBack,
                "entry_rollback_ok"
            ))
            .unwrap());
        assert!(!fixture.producer.ready_path().exists());
        assert!(fixture
            .producer
            .mark_ready(&receipt(
                &fixture,
                EntryPhase::Completed,
                "entry_external_activation_ok"
            ))
            .unwrap());
        let ready = fs::symlink_metadata(fixture.producer.ready_path()).unwrap();
        assert_eq!((pending.dev(), pending.ino()), (ready.dev(), ready.ino()));
        assert_eq!(
            pending_bytes,
            fs::read(fixture.producer.ready_path()).unwrap()
        );
    }

    #[test]
    fn future_stale_and_conflicting_evidence_fail_closed() {
        let fixture = fixture();
        let accepted = UNIX_EPOCH + std::time::Duration::from_secs(1_800_000_010);
        let mut future = fixture.evidence.clone();
        future.probe_observed_at_unix_secs = 1_800_000_011;
        assert!(fixture
            .producer
            .persist_accepted(&fixture.candidate, future, accepted)
            .is_err());
        let mut stale = fixture.evidence.clone();
        stale.heartbeat_observed_at_unix_secs = 1_799_999_889;
        let mut stale_candidate = fixture.candidate.clone();
        stale_candidate.preflighted_at_unix_secs = 1_799_999_799;
        stale_candidate.prepared_at_unix_secs = 1_799_999_800;
        assert!(fixture
            .producer
            .persist_accepted(&stale_candidate, stale, accepted)
            .is_err());
        fixture
            .producer
            .persist_accepted(&fixture.candidate, fixture.evidence.clone(), accepted)
            .unwrap();
        let original = fs::read(fixture.producer.pending_path()).unwrap();
        let mut conflicting = fixture.evidence.clone();
        conflicting.process_observed_at_unix_secs += 1;
        assert!(fixture
            .producer
            .persist_accepted(&fixture.candidate, conflicting, accepted)
            .is_err());
        assert_eq!(original, fs::read(fixture.producer.pending_path()).unwrap());
    }

    #[test]
    fn producer_custody_is_private_bounded_and_value_free() {
        let fixture = fixture();
        fixture
            .producer
            .persist_accepted(
                &fixture.candidate,
                fixture.evidence.clone(),
                UNIX_EPOCH + std::time::Duration::from_secs(1_800_000_010),
            )
            .unwrap();
        let metadata = fs::metadata(fixture.producer.pending_path()).unwrap();
        assert_eq!(metadata.uid(), fixture.owner_uid);
        assert_eq!(metadata.gid(), fixture.owner_gid);
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        let rendered = fs::read_to_string(fixture.producer.pending_path()).unwrap();
        for forbidden in [
            "SENSITIVE_TRANSACTION_CANARY",
            "ciphertext",
            "packet_base64",
            "paimos_origin",
            "api_key_file",
            "handoff_secret_file",
        ] {
            assert!(!rendered.contains(forbidden));
        }
    }
}
