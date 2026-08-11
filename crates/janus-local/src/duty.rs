//! Private append-only duty journal and fail-closed recovery operations.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use ed25519_dalek::SigningKey;
use fs2::FileExt;
use janus_core::{
    AccountabilityPosture, DutyAdmissionV1, DutyEpochCertificateV1, DutyJournalVerifier,
    JanusError, JanusResult, PolicyDutyCandidate, SeparationPolicy, VerifiedAuthoritativeOperation,
    VerifiedDutyJournal, VerifiedOperationView, MAX_DUTIES_PER_OPERATION, MAX_DUTY_RECORDS,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

const INDEX_SCHEMA: u8 = 1;
const BACKUP_SCHEMA: u8 = 1;
const MAX_JOURNAL_BYTES: u64 = 128 * 1024 * 1024;
const MAX_EPOCH_BYTES: u64 = 1024 * 1024;
const MAX_INDEX_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RECORD_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DutyAuthorizationOutcome {
    Allowed,
    Denied,
    ObservedConflict,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DutyAuthorizationAuditV1 {
    pub schema_version: u8,
    pub outcome: DutyAuthorizationOutcome,
    pub reason_code: String,
    pub actor_subject_ref: String,
    pub scope_ref: String,
    pub conflict_domain: String,
    pub operation_ref: String,
    pub duty: String,
    pub admission_id: Option<String>,
    pub journal_head_hash: String,
    pub audit_ref: String,
    pub value_returned: bool,
}

pub trait DutyAuthorizationAuditSink {
    fn record_duty_authorization(&mut self, event: DutyAuthorizationAuditV1) -> JanusResult<()>;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DutyAuthorizationReceiptV1 {
    pub schema_version: u8,
    pub admission_id: String,
    pub sequence: u64,
    pub journal_head_hash: String,
    pub authority: String,
    pub conflict_observed: bool,
    pub value_returned: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DutyJournalHealthV1 {
    pub schema_version: u8,
    pub sequence: u64,
    pub journal_head_hash: String,
    pub value_returned: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DutyJournalIndexV1 {
    schema_version: u8,
    journal_sequence: u64,
    journal_head_hash: String,
    operations: BTreeMap<String, Vec<u64>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DutyBackupManifestV1 {
    schema_version: u8,
    release_digest: String,
    journal_sequence: u64,
    journal_head_hash: String,
    epoch_count: usize,
    value_returned: bool,
}

/// Private file journal. Admission is crate-private so only the local broker
/// integration can turn a verified actor/operation into authority.
#[derive(Clone)]
pub struct FileDutyJournal {
    root: PathBuf,
    release_digest: String,
    signing_key: SigningKey,
}

impl FileDutyJournal {
    pub fn open_or_create(
        root: impl Into<PathBuf>,
        release_digest: String,
        signing_key: SigningKey,
    ) -> JanusResult<Self> {
        validate_sha256(&release_digest)?;
        let root = root.into();
        ensure_private_directory(&root)?;
        let journal = Self {
            root,
            release_digest,
            signing_key,
        };
        journal.initialize_or_verify()?;
        Ok(journal)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn verify_operation_view(
        &self,
        candidate: &PolicyDutyCandidate,
    ) -> JanusResult<VerifiedOperationView> {
        let lock = self.lock()?;
        let (journal, _) = self.load_verified(true)?;
        drop(lock);
        if candidate.release_digest() != self.release_digest {
            return Err(unavailable("duty candidate release mismatch"));
        }
        Ok(journal.operation_view(candidate))
    }

    /// Explicit recovery: rebuild the non-authoritative index only after the
    /// complete signed journal verifies. No record is removed or rewritten.
    pub fn rebuild_index(&self) -> JanusResult<()> {
        let lock = self.lock()?;
        let (journal, records) = self.load_verified(false)?;
        let index = build_index(&journal, &records);
        write_atomic_json(&self.index_path(), &index, "duty index")?;
        sync_directory(&self.root)?;
        drop(lock);
        Ok(())
    }

    /// V1 deliberately has no authority-history import path. Legacy bindings
    /// may be reviewed separately, but reconstructed duty rows are rejected.
    pub fn reject_legacy_duty_import(&self, _legacy_bytes: &[u8]) -> JanusResult<()> {
        Err(JanusError::policy_denied(
            "legacy_duty_import_forbidden",
            "durable duty history can only originate in a live broker admission",
        ))
    }

    /// Cross-sign and persist a new epoch before using the new key.
    pub fn rotate_signing_key(&mut self, next_key: SigningKey) -> JanusResult<()> {
        let lock = self.lock()?;
        let (_journal, _records) = self.load_verified(true)?;
        let mut epochs = self.read_epochs()?;
        let current = epochs
            .last()
            .ok_or_else(|| unavailable("duty epoch chain is empty"))?;
        if !current.matches_signing_key(&self.signing_key) {
            return Err(unavailable("duty signing key is stale"));
        }
        let next = DutyEpochCertificateV1::rotate(current, &self.signing_key, &next_key)?;
        append_json_line(
            &self.epochs_path(),
            &next,
            MAX_RECORD_BYTES,
            MAX_EPOCH_BYTES,
        )?;
        epochs.push(next);
        DutyJournalVerifier::verify(&epochs, &self.read_records()?, &self.release_digest)?;
        self.signing_key = next_key;
        drop(lock);
        Ok(())
    }

    /// Produce a verified, immutable backup in a new private directory.
    pub fn backup_to(&self, destination: &Path) -> JanusResult<()> {
        if fs::symlink_metadata(destination).is_ok() {
            return Err(unavailable("duty backup destination already exists"));
        }
        let lock = self.lock()?;
        let (journal, records) = self.load_verified(true)?;
        let epochs = self.read_epochs()?;
        fs::create_dir(destination).map_err(|_| unavailable("duty backup create failed"))?;
        fs::set_permissions(destination, fs::Permissions::from_mode(0o700))
            .map_err(|_| unavailable("duty backup permissions failed"))?;
        copy_private_file(&self.epochs_path(), &destination.join("epochs.jsonl"))?;
        copy_private_file(&self.journal_path(), &destination.join("journal.jsonl"))?;
        copy_private_file(&self.index_path(), &destination.join("index.json"))?;
        let manifest = DutyBackupManifestV1 {
            schema_version: BACKUP_SCHEMA,
            release_digest: self.release_digest.clone(),
            journal_sequence: records.len() as u64,
            journal_head_hash: journal.head_hash().to_string(),
            epoch_count: epochs.len(),
            value_returned: false,
        };
        write_new_json(
            &destination.join("backup.json"),
            &manifest,
            "duty backup manifest",
        )?;
        sync_directory(destination)?;
        drop(lock);
        Ok(())
    }

    /// Restore only into an absent destination and verify every copied byte
    /// before returning a usable journal.
    pub fn restore_from_backup(
        backup: &Path,
        destination: &Path,
        signing_key: SigningKey,
    ) -> JanusResult<Self> {
        ensure_existing_private_directory(backup)?;
        let manifest: DutyBackupManifestV1 =
            read_private_json(&backup.join("backup.json"), MAX_RECORD_BYTES as u64, false)?;
        if manifest.schema_version != BACKUP_SCHEMA || manifest.value_returned {
            return Err(unavailable("duty backup manifest invalid"));
        }
        let epochs: Vec<DutyEpochCertificateV1> =
            read_json_lines(&backup.join("epochs.jsonl"), MAX_EPOCH_BYTES, false)?;
        let records: Vec<DutyAdmissionV1> =
            read_json_lines(&backup.join("journal.jsonl"), MAX_JOURNAL_BYTES, true)?;
        let journal = DutyJournalVerifier::verify(&epochs, &records, &manifest.release_digest)?;
        let index: DutyJournalIndexV1 =
            read_private_json(&backup.join("index.json"), MAX_INDEX_BYTES, false)?;
        if manifest.journal_sequence != journal.sequence()
            || manifest.journal_head_hash != journal.head_hash()
            || manifest.epoch_count != epochs.len()
            || index != build_index(&journal, &records)
            || !epochs
                .last()
                .is_some_and(|epoch| epoch.matches_signing_key(&signing_key))
        {
            return Err(unavailable("duty backup verification failed"));
        }
        if fs::symlink_metadata(destination).is_ok() {
            return Err(unavailable("duty restore destination already exists"));
        }
        fs::create_dir(destination).map_err(|_| unavailable("duty restore create failed"))?;
        fs::set_permissions(destination, fs::Permissions::from_mode(0o700))
            .map_err(|_| unavailable("duty restore permissions failed"))?;
        copy_private_file(
            &backup.join("epochs.jsonl"),
            &destination.join("epochs.jsonl"),
        )?;
        copy_private_file(
            &backup.join("journal.jsonl"),
            &destination.join("journal.jsonl"),
        )?;
        copy_private_file(&backup.join("index.json"), &destination.join("index.json"))?;
        create_private_file(&destination.join("journal.lock"), false)?;
        sync_directory(destination)?;
        Self::open_or_create(destination, manifest.release_digest, signing_key)
    }

    /// Broker-only admission boundary. The actor value cannot be constructed
    /// outside `janus-local` and the operation can only come from signature,
    /// context, freshness, and nonce verification.
    pub fn authorize_and_admit(
        &self,
        actor: &crate::BrokerAuthenticatedActorV1,
        operation: VerifiedAuthoritativeOperation,
        audit_ref: &str,
        admitted_at: SystemTime,
        audit: &mut (impl DutyAuthorizationAuditSink + ?Sized),
    ) -> JanusResult<DutyAuthorizationReceiptV1> {
        self.authorize_and_admit_in_posture(
            actor,
            operation,
            audit_ref,
            admitted_at,
            AccountabilityPosture::EnforcedRecorded,
            audit,
        )
    }

    /// Admit one broker-authenticated operation under an explicit posture.
    /// Observation mode retains the conflicting duty and emits observation
    /// evidence; enforced mode denies before append.
    pub fn authorize_and_admit_in_posture(
        &self,
        actor: &crate::BrokerAuthenticatedActorV1,
        operation: VerifiedAuthoritativeOperation,
        audit_ref: &str,
        admitted_at: SystemTime,
        posture: AccountabilityPosture,
        audit: &mut (impl DutyAuthorizationAuditSink + ?Sized),
    ) -> JanusResult<DutyAuthorizationReceiptV1> {
        if !posture.requires_verified_journal() {
            return Err(unavailable(
                "legacy posture cannot create a durable duty admission",
            ));
        }
        let candidate =
            PolicyDutyCandidate::from_verified_operation(actor.subject_ref().clone(), operation);
        if candidate.scope() != actor.scope()
            || candidate.release_digest() != actor.release_digest()
        {
            return Err(unavailable(
                "authenticated actor operation context mismatch",
            ));
        }
        self.authorize_candidate_in_posture(&candidate, audit_ref, admitted_at, posture, audit)
    }

    /// Verify the complete signed history and derived index without creating
    /// authority. Every no-conflict action uses this in recorded postures.
    pub fn verify_health(&self) -> JanusResult<DutyJournalHealthV1> {
        let _lock = self.lock()?;
        let (journal, _) = self.load_verified(true)?;
        Ok(DutyJournalHealthV1 {
            schema_version: 1,
            sequence: journal.sequence(),
            journal_head_hash: journal.head_hash().to_string(),
            value_returned: false,
        })
    }

    #[cfg(test)]
    fn authorize_candidate(
        &self,
        candidate: &PolicyDutyCandidate,
        audit_ref: &str,
        admitted_at: SystemTime,
        audit: &mut (impl DutyAuthorizationAuditSink + ?Sized),
    ) -> JanusResult<DutyAuthorizationReceiptV1> {
        self.authorize_candidate_in_posture(
            candidate,
            audit_ref,
            admitted_at,
            AccountabilityPosture::EnforcedRecorded,
            audit,
        )
    }

    fn authorize_candidate_in_posture(
        &self,
        candidate: &PolicyDutyCandidate,
        audit_ref: &str,
        admitted_at: SystemTime,
        posture: AccountabilityPosture,
        audit: &mut (impl DutyAuthorizationAuditSink + ?Sized),
    ) -> JanusResult<DutyAuthorizationReceiptV1> {
        validate_prefixed_hex(audit_ref, "aud_", 24)?;
        if candidate.release_digest() != self.release_digest {
            return Err(unavailable("duty candidate release mismatch"));
        }
        let lock = self.lock()?;
        let (journal, records) = self.load_verified(true)?;
        let view = journal.operation_view(candidate);
        let conflict =
            view.evaluate_candidate(candidate, SeparationPolicy::default().conflicts())?;
        if let Some(reason) = conflict.filter(|_| posture.denies_conflicts()) {
            let event = audit_event(
                candidate,
                DutyAuthorizationOutcome::Denied,
                reason,
                None,
                journal.head_hash(),
                audit_ref,
            );
            audit.record_duty_authorization(event)?;
            return Err(JanusError::policy_denied(
                reason,
                "durable duty conflict denied authorization",
            ));
        }
        if records.len() >= MAX_DUTY_RECORDS {
            return Err(unavailable("duty journal capacity exceeded"));
        }
        let index = build_index(&journal, &records);
        if index
            .operations
            .get(&candidate_identity(candidate))
            .is_some_and(|entries| entries.len() >= MAX_DUTIES_PER_OPERATION)
        {
            return Err(unavailable("duty operation capacity exceeded"));
        }
        let epochs = self.read_epochs()?;
        let epoch = epochs
            .last()
            .ok_or_else(|| unavailable("duty epoch chain is empty"))?;
        if !epoch.matches_signing_key(&self.signing_key) {
            return Err(unavailable("duty signing key is stale"));
        }
        let sequence = journal
            .sequence()
            .checked_add(1)
            .ok_or_else(|| unavailable("duty sequence exhausted"))?;
        let record = DutyAdmissionV1::issue(
            &self.signing_key,
            epoch,
            sequence,
            journal.head_hash(),
            candidate,
            audit_ref,
            admitted_at,
        )?;
        append_json_line(
            &self.journal_path(),
            &record,
            MAX_RECORD_BYTES,
            MAX_JOURNAL_BYTES,
        )?;
        let mut updated = records;
        updated.push(record.clone());
        let verified = DutyJournalVerifier::verify(&epochs, &updated, &self.release_digest)?;
        write_atomic_json(
            &self.index_path(),
            &build_index(&verified, &updated),
            "duty index",
        )?;
        sync_directory(&self.root)?;
        drop(lock);

        let conflict_observed = conflict.is_some();
        let event = audit_event(
            candidate,
            if conflict_observed {
                DutyAuthorizationOutcome::ObservedConflict
            } else {
                DutyAuthorizationOutcome::Allowed
            },
            conflict.unwrap_or("duty_admitted"),
            Some(record.admission_id.clone()),
            &record.record_hash,
            audit_ref,
        );
        // A failed audit intentionally leaves the conservative synced duty in
        // place and returns an error so the domain mutation cannot proceed.
        audit.record_duty_authorization(event)?;
        Ok(DutyAuthorizationReceiptV1 {
            schema_version: 1,
            admission_id: record.admission_id,
            sequence,
            journal_head_hash: record.record_hash,
            authority: if conflict_observed {
                "durable_duty_observation".to_string()
            } else {
                "durable_duty_admission".to_string()
            },
            conflict_observed,
            value_returned: false,
        })
    }

    fn initialize_or_verify(&self) -> JanusResult<()> {
        let lock_path = self.lock_path();
        if !lock_path.exists() {
            create_private_file(&lock_path, false)?;
        }
        ensure_private_file(&lock_path, MAX_RECORD_BYTES as u64, true)?;
        let lock = self.lock()?;
        let epoch_exists = self.epochs_path().exists();
        let journal_exists = self.journal_path().exists();
        let index_exists = self.index_path().exists();
        if !epoch_exists && !journal_exists && !index_exists {
            let genesis = DutyEpochCertificateV1::genesis(&self.signing_key)?;
            write_new_json_line(&self.epochs_path(), &genesis, "duty epochs")?;
            create_private_file(&self.journal_path(), false)?;
            let journal = DutyJournalVerifier::verify(&[genesis], &[], &self.release_digest)?;
            write_new_json(
                &self.index_path(),
                &build_index(&journal, &[]),
                "duty index",
            )?;
            sync_directory(&self.root)?;
        } else if !(epoch_exists && journal_exists && index_exists) {
            return Err(unavailable("duty journal component missing"));
        }
        let (journal, _records) = self.load_verified(true)?;
        let epochs = self.read_epochs()?;
        if !epochs
            .last()
            .is_some_and(|epoch| epoch.matches_signing_key(&self.signing_key))
        {
            return Err(unavailable("duty signing key is stale"));
        }
        if journal.sequence() > MAX_DUTY_RECORDS as u64 {
            return Err(unavailable("duty journal capacity exceeded"));
        }
        drop(lock);
        Ok(())
    }

    fn load_verified(
        &self,
        verify_index: bool,
    ) -> JanusResult<(VerifiedDutyJournal, Vec<DutyAdmissionV1>)> {
        let epochs = self.read_epochs()?;
        let records = self.read_records()?;
        let journal = DutyJournalVerifier::verify(&epochs, &records, &self.release_digest)?;
        if verify_index {
            let index: DutyJournalIndexV1 =
                read_private_json(&self.index_path(), MAX_INDEX_BYTES, false)?;
            if index != build_index(&journal, &records) {
                return Err(unavailable("duty journal index diverged"));
            }
        }
        Ok((journal, records))
    }

    fn read_epochs(&self) -> JanusResult<Vec<DutyEpochCertificateV1>> {
        read_json_lines(&self.epochs_path(), MAX_EPOCH_BYTES, false)
    }

    fn read_records(&self) -> JanusResult<Vec<DutyAdmissionV1>> {
        read_json_lines(&self.journal_path(), MAX_JOURNAL_BYTES, true)
    }

    fn lock(&self) -> JanusResult<File> {
        ensure_private_file(&self.lock_path(), MAX_RECORD_BYTES as u64, true)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.lock_path())
            .map_err(|_| unavailable("duty journal lock unavailable"))?;
        file.lock_exclusive()
            .map_err(|_| unavailable("duty journal lock unavailable"))?;
        Ok(file)
    }

    fn epochs_path(&self) -> PathBuf {
        self.root.join("epochs.jsonl")
    }
    fn journal_path(&self) -> PathBuf {
        self.root.join("journal.jsonl")
    }
    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }
    fn lock_path(&self) -> PathBuf {
        self.root.join("journal.lock")
    }
}

fn audit_event(
    candidate: &PolicyDutyCandidate,
    outcome: DutyAuthorizationOutcome,
    reason_code: &str,
    admission_id: Option<String>,
    journal_head_hash: &str,
    audit_ref: &str,
) -> DutyAuthorizationAuditV1 {
    DutyAuthorizationAuditV1 {
        schema_version: 1,
        outcome,
        reason_code: reason_code.to_string(),
        actor_subject_ref: candidate.actor().as_str().to_string(),
        scope_ref: candidate.scope().as_str().to_string(),
        conflict_domain: candidate.conflict_domain().as_str().to_string(),
        operation_ref: candidate.operation_ref().as_str().to_string(),
        duty: candidate.duty().as_str().to_string(),
        admission_id,
        journal_head_hash: journal_head_hash.to_string(),
        audit_ref: audit_ref.to_string(),
        value_returned: false,
    }
}

fn candidate_identity(candidate: &PolicyDutyCandidate) -> String {
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest;
    for field in [
        "janus-duty-operation-identity-v1",
        candidate.actor().as_str(),
        candidate.scope().as_str(),
        candidate.conflict_domain().as_str(),
        candidate.operation_ref().as_str(),
    ] {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field.as_bytes());
    }
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn build_index(journal: &VerifiedDutyJournal, records: &[DutyAdmissionV1]) -> DutyJournalIndexV1 {
    let mut operations = BTreeMap::<String, Vec<u64>>::new();
    for record in records {
        operations
            .entry(record.operation_identity_fingerprint())
            .or_default()
            .push(record.sequence);
    }
    DutyJournalIndexV1 {
        schema_version: INDEX_SCHEMA,
        journal_sequence: journal.sequence(),
        journal_head_hash: journal.head_hash().to_string(),
        operations,
    }
}

fn ensure_private_directory(path: &Path) -> JanusResult<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => ensure_existing_private_directory(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(path).map_err(|_| unavailable("duty directory create failed"))?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .map_err(|_| unavailable("duty directory permissions failed"))?;
            ensure_existing_private_directory(path)
        }
        Err(_) => Err(unavailable("duty directory unavailable")),
    }
}

fn ensure_existing_private_directory(path: &Path) -> JanusResult<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| unavailable("private duty directory unavailable"))?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(unavailable("private duty directory invalid"));
    }
    Ok(())
}

fn ensure_private_file(path: &Path, maximum: u64, allow_empty: bool) -> JanusResult<()> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| unavailable("private duty file unavailable"))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > maximum
        || (!allow_empty && metadata.len() == 0)
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(unavailable("private duty file invalid"));
    }
    Ok(())
}

fn create_private_file(path: &Path, nonempty: bool) -> JanusResult<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options
        .open(path)
        .map_err(|_| unavailable("private duty file create failed"))?;
    if nonempty {
        file.write_all(b"\n")
            .map_err(|_| unavailable("private duty file write failed"))?;
    }
    file.sync_all()
        .map_err(|_| unavailable("private duty file persistence failed"))
}

fn read_json_lines<T: DeserializeOwned>(
    path: &Path,
    maximum: u64,
    allow_empty: bool,
) -> JanusResult<Vec<T>> {
    ensure_private_file(path, maximum, allow_empty)?;
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|mut file| file.read_to_end(&mut bytes))
        .map_err(|_| unavailable("duty journal read failed"))?;
    if bytes.is_empty() {
        return if allow_empty {
            Ok(Vec::new())
        } else {
            Err(unavailable("duty journal empty"))
        };
    }
    if bytes.last() != Some(&b'\n') {
        return Err(unavailable("duty journal has incomplete tail"));
    }
    bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).map_err(|_| unavailable("duty journal malformed")))
        .collect()
}

fn read_private_json<T: DeserializeOwned>(
    path: &Path,
    maximum: u64,
    allow_empty: bool,
) -> JanusResult<T> {
    ensure_private_file(path, maximum, allow_empty)?;
    let bytes = fs::read(path).map_err(|_| unavailable("private duty file read failed"))?;
    serde_json::from_slice(&bytes).map_err(|_| unavailable("private duty file malformed"))
}

fn append_json_line<T: Serialize>(
    path: &Path,
    value: &T,
    maximum_record: usize,
    maximum_file: u64,
) -> JanusResult<()> {
    ensure_private_file(path, maximum_file, true)?;
    let mut encoded =
        serde_json::to_vec(value).map_err(|_| unavailable("duty record encoding failed"))?;
    let current_bytes = fs::metadata(path)
        .map_err(|_| unavailable("duty append unavailable"))?
        .len();
    if encoded.len() > maximum_record
        || current_bytes.saturating_add(encoded.len() as u64 + 1) > maximum_file
    {
        return Err(unavailable("duty record capacity exceeded"));
    }
    encoded.push(b'\n');
    let mut file = OpenOptions::new()
        .append(true)
        .open(path)
        .map_err(|_| unavailable("duty append unavailable"))?;
    file.write_all(&encoded)
        .and_then(|_| file.flush())
        .and_then(|_| file.sync_all())
        .map_err(|_| unavailable("duty append persistence failed"))
}

fn write_new_json_line<T: Serialize>(
    path: &Path,
    value: &T,
    kind: &'static str,
) -> JanusResult<()> {
    let mut encoded =
        serde_json::to_vec(value).map_err(|_| unavailable(format!("{kind} encoding failed")))?;
    encoded.push(b'\n');
    write_new_bytes(path, &encoded, kind)
}

fn write_new_json<T: Serialize>(path: &Path, value: &T, kind: &'static str) -> JanusResult<()> {
    let encoded =
        serde_json::to_vec(value).map_err(|_| unavailable(format!("{kind} encoding failed")))?;
    write_new_bytes(path, &encoded, kind)
}

fn write_new_bytes(path: &Path, bytes: &[u8], kind: &'static str) -> JanusResult<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options
        .open(path)
        .map_err(|_| unavailable(format!("{kind} create failed")))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| unavailable(format!("{kind} persistence failed")))
}

fn write_atomic_json<T: Serialize>(path: &Path, value: &T, kind: &'static str) -> JanusResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| unavailable(format!("{kind} path invalid")))?;
    let temporary = parent.join(".duty-index.next");
    let encoded =
        serde_json::to_vec(value).map_err(|_| unavailable(format!("{kind} encoding failed")))?;
    write_new_bytes(&temporary, &encoded, kind)?;
    fs::rename(&temporary, path).map_err(|_| unavailable(format!("{kind} replace failed")))?;
    sync_directory(parent)
}

fn copy_private_file(source: &Path, destination: &Path) -> JanusResult<()> {
    ensure_private_file(source, MAX_JOURNAL_BYTES, true)?;
    let bytes = fs::read(source).map_err(|_| unavailable("duty backup read failed"))?;
    write_new_bytes(destination, &bytes, "duty backup file")
}

fn sync_directory(path: &Path) -> JanusResult<()> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| unavailable("duty directory persistence failed"))
}

fn validate_sha256(value: &str) -> JanusResult<()> {
    validate_prefixed_hex(value, "sha256:", 64)
}

fn validate_prefixed_hex(value: &str, prefix: &str, length: usize) -> JanusResult<()> {
    if !value.strip_prefix(prefix).is_some_and(|suffix| {
        suffix.len() == length
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    }) {
        return Err(unavailable("duty opaque reference invalid"));
    }
    Ok(())
}

fn unavailable(detail: impl Into<String>) -> JanusError {
    JanusError::StoreUnavailable {
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use janus_core::{
        ActorSubjectRef, AuthoritativeOperationRefV1, ConflictDomain, Duty, OperationRef,
        OperationStateVerifier, SafeLabel, ScopePathV1, TrustAdapterKind,
        VerifiedAuthoritativeOperation,
    };
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tempfile::tempdir;

    const RELEASE: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn test_nonce() -> String {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let clock = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!(
            "nce_{:024x}",
            clock ^ u128::from(SEQUENCE.fetch_add(1, Ordering::Relaxed))
        )
    }

    #[derive(Default)]
    struct Audit {
        events: Vec<DutyAuthorizationAuditV1>,
        fail: bool,
    }

    impl DutyAuthorizationAuditSink for Audit {
        fn record_duty_authorization(
            &mut self,
            event: DutyAuthorizationAuditV1,
        ) -> JanusResult<()> {
            if self.fail {
                return Err(JanusError::AuditUnavailable {
                    detail: "fixture failure".to_string(),
                });
            }
            self.events.push(event);
            Ok(())
        }
    }

    fn scope() -> janus_core::ScopeRef {
        ScopePathV1::new(
            janus_core::OrganizationId::new("fixture-org").unwrap(),
            janus_core::ProjectId::new("janus").unwrap(),
            janus_core::RepositoryId::new("janus").unwrap(),
            janus_core::EnvironmentId::new("dev").unwrap(),
        )
        .scope_ref()
    }

    fn verified_operation(
        domain_key: &SigningKey,
        verifier: &mut OperationStateVerifier,
        domain: ConflictDomain,
        duty: Duty,
        operation_lineage: &str,
        policy_revision: u8,
    ) -> VerifiedAuthoritativeOperation {
        let now = UNIX_EPOCH + Duration::from_secs(100);
        let operation = OperationRef::derive(domain, operation_lineage).unwrap();
        let reference = AuthoritativeOperationRefV1::issue(
            domain_key,
            "domain-service",
            &operation,
            &scope(),
            domain,
            duty,
            1,
            &SafeLabel::new(format!("policy-v{policy_revision}")).unwrap(),
            now,
            now + Duration::from_secs(60),
            &test_nonce(),
            "janus-duty",
            RELEASE,
        )
        .unwrap();
        verifier.verify_once(&reference, now).unwrap()
    }

    fn candidate(
        domain_key: &SigningKey,
        verifier: &mut OperationStateVerifier,
        actor: &ActorSubjectRef,
        domain: ConflictDomain,
        duty: Duty,
        operation_lineage: &str,
        policy_revision: u8,
    ) -> PolicyDutyCandidate {
        PolicyDutyCandidate::from_verified_operation(
            actor.clone(),
            verified_operation(
                domain_key,
                verifier,
                domain,
                duty,
                operation_lineage,
                policy_revision,
            ),
        )
    }

    fn fixture() -> (
        tempfile::TempDir,
        FileDutyJournal,
        SigningKey,
        OperationStateVerifier,
        ActorSubjectRef,
    ) {
        let directory = tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let journal_key = SigningKey::from_bytes(&[21; 32]);
        let domain_key = SigningKey::from_bytes(&[22; 32]);
        let journal = FileDutyJournal::open_or_create(
            directory.path().join("duty"),
            RELEASE.to_string(),
            journal_key,
        )
        .unwrap();
        let verifier = OperationStateVerifier::new(
            domain_key.verifying_key(),
            "domain-service",
            "janus-duty",
            RELEASE,
        )
        .unwrap();
        let actor =
            ActorSubjectRef::derive(TrustAdapterKind::LocalPeer, "host", "raw-local-user-501")
                .unwrap();
        (directory, journal, domain_key, verifier, actor)
    }

    #[test]
    fn restart_policy_change_and_all_nine_conflicts_deny() {
        let (_directory, journal, domain_key, mut verifier, actor) = fixture();
        let pairs = [
            (
                ConflictDomain::UseRequest,
                Duty::RequestUse,
                Duty::ApproveUse,
            ),
            (
                ConflictDomain::UseRequest,
                Duty::ApproveUse,
                Duty::ExecuteUse,
            ),
            (
                ConflictDomain::DelegationGrant,
                Duty::GrantDelegation,
                Duty::ReceiveDelegation,
            ),
            (
                ConflictDomain::RoleBinding,
                Duty::GrantRole,
                Duty::ReceiveRole,
            ),
            (
                ConflictDomain::PolicyChange,
                Duty::ManageRolePolicy,
                Duty::ReceiveRole,
            ),
            (
                ConflictDomain::BreakGlass,
                Duty::ActivateBreakGlass,
                Duty::ApproveBreakGlass,
            ),
            (
                ConflictDomain::BreakGlass,
                Duty::ActivateBreakGlass,
                Duty::UseBreakGlass,
            ),
            (
                ConflictDomain::BreakGlass,
                Duty::UseBreakGlass,
                Duty::ReviewBreakGlass,
            ),
            (
                ConflictDomain::Recovery,
                Duty::OperateRecovery,
                Duty::ReviewRecovery,
            ),
        ];
        for (index, (domain, first, second)) in pairs.into_iter().enumerate() {
            let lineage = format!("lineage-{index}");
            let first = candidate(
                &domain_key,
                &mut verifier,
                &actor,
                domain,
                first,
                &lineage,
                (index * 2 + 1) as u8,
            );
            let second = candidate(
                &domain_key,
                &mut verifier,
                &actor,
                domain,
                second,
                &lineage,
                (index * 2 + 2) as u8,
            );
            let mut audit = Audit::default();
            journal
                .authorize_candidate(
                    &first,
                    &format!("aud_{:024x}", index * 2 + 1),
                    UNIX_EPOCH + Duration::from_secs(101),
                    &mut audit,
                )
                .unwrap();
            assert!(journal
                .authorize_candidate(
                    &second,
                    &format!("aud_{:024x}", index * 2 + 2),
                    UNIX_EPOCH + Duration::from_secs(102),
                    &mut audit,
                )
                .is_err());
            assert_eq!(
                audit.events.last().unwrap().outcome,
                DutyAuthorizationOutcome::Denied
            );
        }
    }

    #[test]
    fn broker_actor_boundary_binds_scope_and_release_before_append() {
        let (_directory, journal, domain_key, mut verifier, actor) = fixture();
        let authenticated =
            crate::BrokerAuthenticatedActorV1::fixture(actor.clone(), scope(), RELEASE);
        let operation = verified_operation(
            &domain_key,
            &mut verifier,
            ConflictDomain::UseRequest,
            Duty::RequestUse,
            "broker-boundary",
            1,
        );
        let receipt = journal
            .authorize_and_admit(
                &authenticated,
                operation,
                "aud_000000000000000000000001",
                UNIX_EPOCH + Duration::from_secs(101),
                &mut Audit::default(),
            )
            .unwrap();
        assert_eq!(receipt.sequence, 1);

        let wrong_scope = ScopePathV1::new(
            janus_core::OrganizationId::new("fixture-org").unwrap(),
            janus_core::ProjectId::new("janus").unwrap(),
            janus_core::RepositoryId::new("janus").unwrap(),
            janus_core::EnvironmentId::new("prod").unwrap(),
        )
        .scope_ref();
        let mismatched = crate::BrokerAuthenticatedActorV1::fixture(actor, wrong_scope, RELEASE);
        let operation = verified_operation(
            &domain_key,
            &mut verifier,
            ConflictDomain::Recovery,
            Duty::OperateRecovery,
            "wrong-scope",
            2,
        );
        assert!(journal
            .authorize_and_admit(
                &mismatched,
                operation,
                "aud_000000000000000000000002",
                UNIX_EPOCH + Duration::from_secs(102),
                &mut Audit::default(),
            )
            .is_err());
        assert_eq!(journal.read_records().unwrap().len(), 1);
    }

    #[test]
    fn concurrent_incompatible_phases_admit_at_most_one() {
        let (directory, _journal, domain_key, mut verifier, actor) = fixture();
        let root = directory.path().join("duty");
        let request = candidate(
            &domain_key,
            &mut verifier,
            &actor,
            ConflictDomain::UseRequest,
            Duty::RequestUse,
            "race",
            1,
        );
        let approve = candidate(
            &domain_key,
            &mut verifier,
            &actor,
            ConflictDomain::UseRequest,
            Duty::ApproveUse,
            "race",
            2,
        );
        let results = Arc::new(Mutex::new(Vec::new()));
        thread::scope(|scope_threads| {
            for (candidate, audit_number) in [(request, 1_u8), (approve, 2_u8)] {
                let root = root.clone();
                let results = Arc::clone(&results);
                scope_threads.spawn(move || {
                    let journal = FileDutyJournal::open_or_create(
                        root,
                        RELEASE.to_string(),
                        SigningKey::from_bytes(&[21; 32]),
                    )
                    .unwrap();
                    let outcome = journal.authorize_candidate(
                        &candidate,
                        &format!("aud_{audit_number:024x}"),
                        UNIX_EPOCH + Duration::from_secs(101),
                        &mut Audit::default(),
                    );
                    results.lock().unwrap().push(outcome.is_ok());
                });
            }
        });
        let results = results.lock().unwrap();
        assert_eq!(results.iter().filter(|result| **result).count(), 1);
    }

    #[test]
    fn incomplete_tail_tamper_index_divergence_and_stale_key_fail_closed() {
        let (_directory, mut journal, domain_key, mut verifier, actor) = fixture();
        let first = candidate(
            &domain_key,
            &mut verifier,
            &actor,
            ConflictDomain::Recovery,
            Duty::OperateRecovery,
            "recover",
            1,
        );
        journal
            .authorize_candidate(
                &first,
                "aud_000000000000000000000001",
                UNIX_EPOCH + Duration::from_secs(101),
                &mut Audit::default(),
            )
            .unwrap();

        fs::write(journal.index_path(), b"{}").unwrap();
        assert!(journal.verify_operation_view(&first).is_err());
        journal.rebuild_index().unwrap();
        assert!(journal.verify_operation_view(&first).is_ok());

        let next_key = SigningKey::from_bytes(&[23; 32]);
        journal.rotate_signing_key(next_key).unwrap();
        assert!(FileDutyJournal::open_or_create(
            journal.root(),
            RELEASE.to_string(),
            SigningKey::from_bytes(&[21; 32]),
        )
        .is_err());

        OpenOptions::new()
            .append(true)
            .open(journal.journal_path())
            .unwrap()
            .write_all(b"{")
            .unwrap();
        assert!(journal.verify_operation_view(&first).is_err());
    }

    #[test]
    fn failed_audit_retains_conservative_admission_and_blocks_mutation() {
        let (_directory, journal, domain_key, mut verifier, actor) = fixture();
        let first = candidate(
            &domain_key,
            &mut verifier,
            &actor,
            ConflictDomain::Recovery,
            Duty::OperateRecovery,
            "audit-failure",
            1,
        );
        let mut audit = Audit {
            fail: true,
            ..Audit::default()
        };
        assert!(matches!(
            journal.authorize_candidate(
                &first,
                "aud_000000000000000000000001",
                UNIX_EPOCH + Duration::from_secs(101),
                &mut audit,
            ),
            Err(JanusError::AuditUnavailable { .. })
        ));
        let view = journal.verify_operation_view(&first).unwrap();
        assert!(view
            .evaluate_candidate(&first, SeparationPolicy::default().conflicts())
            .unwrap()
            .is_none());
        let records = journal.read_records().unwrap();
        assert_eq!(records.len(), 1);
    }

    #[test]
    fn restart_lock_release_and_legacy_import_are_fail_closed() {
        let (directory, journal, domain_key, mut verifier, actor) = fixture();
        let first = candidate(
            &domain_key,
            &mut verifier,
            &actor,
            ConflictDomain::UseRequest,
            Duty::RequestUse,
            "restart",
            1,
        );
        journal
            .authorize_candidate(
                &first,
                "aud_000000000000000000000001",
                UNIX_EPOCH + Duration::from_secs(101),
                &mut Audit::default(),
            )
            .unwrap();

        // An OS advisory lock is released when its owning descriptor/process
        // disappears; the reopened broker must verify the complete history.
        let held_lock = journal.lock().unwrap();
        drop(held_lock);
        drop(journal);
        let reopened = FileDutyJournal::open_or_create(
            directory.path().join("duty"),
            RELEASE.to_string(),
            SigningKey::from_bytes(&[21; 32]),
        )
        .unwrap();
        assert!(reopened.verify_operation_view(&first).is_ok());
        assert!(matches!(
            reopened.reject_legacy_duty_import(br#"[{"duty":"request_use"}]"#),
            Err(JanusError::PolicyDenied {
                reason_code: "legacy_duty_import_forbidden",
                ..
            })
        ));
    }

    #[test]
    fn verified_backup_restore_preserves_history_and_rejects_tamper() {
        let (directory, journal, domain_key, mut verifier, actor) = fixture();
        let first = candidate(
            &domain_key,
            &mut verifier,
            &actor,
            ConflictDomain::Recovery,
            Duty::OperateRecovery,
            "backup",
            1,
        );
        journal
            .authorize_candidate(
                &first,
                "aud_000000000000000000000001",
                UNIX_EPOCH + Duration::from_secs(101),
                &mut Audit::default(),
            )
            .unwrap();
        let backup = directory.path().join("backup");
        journal.backup_to(&backup).unwrap();
        let restored = FileDutyJournal::restore_from_backup(
            &backup,
            &directory.path().join("restored"),
            SigningKey::from_bytes(&[21; 32]),
        )
        .unwrap();
        assert!(restored.verify_operation_view(&first).is_ok());

        fs::write(backup.join("index.json"), b"{}").unwrap();
        assert!(FileDutyJournal::restore_from_backup(
            &backup,
            &directory.path().join("tampered"),
            SigningKey::from_bytes(&[21; 32]),
        )
        .is_err());
    }

    #[test]
    fn value_free_debug_and_receipts_exclude_raw_identity_material() {
        let (_directory, journal, domain_key, mut verifier, actor) = fixture();
        let candidate = candidate(
            &domain_key,
            &mut verifier,
            &actor,
            ConflictDomain::UseRequest,
            Duty::RequestUse,
            "safe-output",
            1,
        );
        let mut audit = Audit::default();
        let receipt = journal
            .authorize_candidate(
                &candidate,
                "aud_000000000000000000000001",
                UNIX_EPOCH + Duration::from_secs(101),
                &mut audit,
            )
            .unwrap();
        let output = format!(
            "{candidate:?} {} {}",
            serde_json::to_string(&receipt).unwrap(),
            serde_json::to_string(&audit.events).unwrap()
        );
        assert!(!output.contains("raw-local-user-501"));
        assert!(!output.contains("domain-service"));
        assert!(!output.contains("stable-lineage"));
        assert!(output.contains("value_returned"));
    }
}
