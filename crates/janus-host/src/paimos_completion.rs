//! Privilege-separated managed-transaction completion reporting.
//!
//! The network-none transaction daemon writes one immutable value-free record
//! under its own uid. This module is consumed only by a separate privileged
//! no-argument process: it checks an operator-owned binding and the ready
//! record before invoking the existing Paimos reporter.

use std::fmt;
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use janus_core::MaterialTimestamp;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::aeon_stage::AeonManagedCompletionBindingV1;
use crate::paimos::PaimosManagedCompletionBindingV1;

pub const CAPABILITY_SCHEMA: &str = "inspr.janus.managed-completion-capability.v1";
pub const BINDING_SCHEMA: &str = "inspr.janus.managed-completion-paimos-binding.v2";
/// JANUS-480: the same transaction association bound to one Aeon Access
/// handoff instead of a classic Paimos external-stage handoff.
pub const AEON_BINDING_SCHEMA: &str = "inspr.janus.managed-completion-aeon-binding.v1";
pub const RECORD_SCHEMA: &str = "inspr.janus.managed-completion-record.v2";

const SYSTEM_BINDING_PATH: &str =
    "/run/janus-paimos-dependency-reporter/managed-completion-binding.json";
const SYSTEM_READY_PATH: &str = "/var/lib/janus-managed-central/completion-dispatch/ready.json";
const MAX_BINDING_BYTES: usize = 64 * 1024;
const MAX_RECORD_BYTES: usize = 64 * 1024;
const MAX_DIRECTORY_ENTRIES: usize = 2;
const PRODUCER_UID: u32 = 100;
const PRODUCER_GID: u32 = 993;
const ACTIVATION_FRESHNESS_SECONDS: u64 = 120;

/// Stable, value-free privileged-consumer failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManagedCompletionError {
    reason_code: &'static str,
}

impl ManagedCompletionError {
    fn new(reason_code: &'static str) -> Self {
        Self { reason_code }
    }

    pub fn reason_code(self) -> &'static str {
        self.reason_code
    }
}

impl fmt::Display for ManagedCompletionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code)
    }
}

impl std::error::Error for ManagedCompletionError {}

type CompletionResult<T> = Result<T, ManagedCompletionError>;

/// Catalog-carried, operator-reviewed opt-in. The digest names exactly one
/// root-owned binding but conveys no reporter path, credential, or authority.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedCompletionCapabilityV1 {
    pub schema: String,
    pub schema_version: u8,
    pub operation_ref: String,
    pub binding_digest: String,
}

/// Original host facts accepted by the existing lifecycle boundary.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AcceptedActivationEvidenceV1 {
    pub generation: u64,
    pub materialized: bool,
    pub process_state: String,
    pub probe_state: String,
    pub heartbeat_observed_at_unix_secs: u64,
    pub process_observed_at_unix_secs: u64,
    pub probe_observed_at_unix_secs: u64,
}

/// Immutable daemon-owned evidence. Lifecycle completion is represented only
/// by moving this exact inode from `pending.json` to `ready.json`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedCompletionRecordV2 {
    pub schema: String,
    pub schema_version: u8,
    pub binding_digest: String,
    pub operation_ref: String,
    pub operation_id: String,
    pub operation_kind: String,
    pub source: String,
    pub host_ref: String,
    pub service_ref: String,
    pub slot_ref: String,
    pub declaration_fingerprint: String,
    pub secret_ref: String,
    pub scope_ref: String,
    pub generation: u64,
    pub revocation_epoch: u64,
    pub plan_fingerprint: String,
    pub target_fingerprint: String,
    pub producer_key_id: String,
    pub prepared_at_unix_secs: u64,
    pub preflighted_at_unix_secs: u64,
    pub evidence_accepted_at_unix_secs: u64,
    pub activation_evidence: AcceptedActivationEvidenceV1,
    pub integrity_hash: String,
}

/// Root-owned association between one transaction and one existing Paimos
/// dependency authority. Human approval cannot mint the nested authority.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedCompletionBindingV2 {
    pub schema: String,
    pub schema_version: u8,
    pub operation_ref: String,
    pub operation_kind: String,
    pub source: String,
    pub host_ref: String,
    pub service_ref: String,
    pub slot_ref: String,
    pub declaration_fingerprint: String,
    pub secret_ref: String,
    pub scope_ref: String,
    pub generation: u64,
    pub revocation_epoch: u64,
    pub plan_fingerprint: String,
    pub target_fingerprint: String,
    pub producer_key_id: String,
    pub reporter: PaimosManagedCompletionBindingV1,
}

/// Root-owned association between one transaction and one existing Aeon
/// Access handoff. The record carries this binding's digest exactly as for the
/// classic binding; only the privileged consumer reads which one it is.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedCompletionAeonBindingV1 {
    pub schema: String,
    pub schema_version: u8,
    pub operation_ref: String,
    pub operation_kind: String,
    pub source: String,
    pub host_ref: String,
    pub service_ref: String,
    pub slot_ref: String,
    pub declaration_fingerprint: String,
    pub secret_ref: String,
    pub scope_ref: String,
    pub generation: u64,
    pub revocation_epoch: u64,
    pub plan_fingerprint: String,
    pub target_fingerprint: String,
    pub producer_key_id: String,
    pub reporter: AeonManagedCompletionBindingV1,
}

/// The transaction tuple both binding schemas share with the record.
struct TransactionFields<'a> {
    operation_ref: &'a str,
    operation_kind: &'a str,
    source: &'a str,
    host_ref: &'a str,
    service_ref: &'a str,
    slot_ref: &'a str,
    declaration_fingerprint: &'a str,
    secret_ref: &'a str,
    scope_ref: &'a str,
    generation: u64,
    revocation_epoch: u64,
    plan_fingerprint: &'a str,
    target_fingerprint: &'a str,
    producer_key_id: &'a str,
}

macro_rules! transaction_fields {
    ($binding:expr) => {
        TransactionFields {
            operation_ref: &$binding.operation_ref,
            operation_kind: &$binding.operation_kind,
            source: &$binding.source,
            host_ref: &$binding.host_ref,
            service_ref: &$binding.service_ref,
            slot_ref: &$binding.slot_ref,
            declaration_fingerprint: &$binding.declaration_fingerprint,
            secret_ref: &$binding.secret_ref,
            scope_ref: &$binding.scope_ref,
            generation: $binding.generation,
            revocation_epoch: $binding.revocation_epoch,
            plan_fingerprint: &$binding.plan_fingerprint,
            target_fingerprint: &$binding.target_fingerprint,
            producer_key_id: &$binding.producer_key_id,
        }
    };
}

impl TransactionFields<'_> {
    fn valid(&self) -> bool {
        valid_ref("op_", self.operation_ref)
            && self.operation_kind == "create"
            && self.source == "generated"
            && valid_ref("host_", self.host_ref)
            && valid_ref("svc_", self.service_ref)
            && valid_ref("slot_", self.slot_ref)
            && valid_ref("decl_", self.declaration_fingerprint)
            && valid_ref("sec_", self.secret_ref)
            && valid_ref("scp_", self.scope_ref)
            && self.generation != 0
            && self.revocation_epoch != 0
            && valid_hex_digest(self.plan_fingerprint)
            && valid_hex_digest(self.target_fingerprint)
            && valid_ref("key_", self.producer_key_id)
    }

    fn matches_record(&self, record: &ManagedCompletionRecordV2) -> bool {
        self.operation_ref == record.operation_ref
            && self.operation_kind == record.operation_kind
            && self.source == record.source
            && self.host_ref == record.host_ref
            && self.service_ref == record.service_ref
            && self.slot_ref == record.slot_ref
            && self.declaration_fingerprint == record.declaration_fingerprint
            && self.secret_ref == record.secret_ref
            && self.scope_ref == record.scope_ref
            && self.generation == record.generation
            && self.revocation_epoch == record.revocation_epoch
            && self.plan_fingerprint == record.plan_fingerprint
            && self.target_fingerprint == record.target_fingerprint
            && self.producer_key_id == record.producer_key_id
    }
}

impl ManagedCompletionCapabilityV1 {
    pub fn validate(&self) -> CompletionResult<()> {
        if self.schema != CAPABILITY_SCHEMA
            || self.schema_version != 1
            || !valid_ref("op_", &self.operation_ref)
            || !valid_wire_digest(&self.binding_digest)
        {
            return Err(ManagedCompletionError::new(
                "managed_completion_capability_invalid",
            ));
        }
        Ok(())
    }
}

impl ManagedCompletionRecordV2 {
    pub fn seal(&mut self) -> CompletionResult<()> {
        self.integrity_hash.clear();
        validate_record_shape(self)?;
        self.integrity_hash = record_hash(self)?;
        Ok(())
    }

    pub fn validate(&self) -> CompletionResult<()> {
        validate_record_shape(self)?;
        if self.integrity_hash != record_hash(self)? {
            return Err(ManagedCompletionError::new(
                "managed_completion_record_invalid",
            ));
        }
        Ok(())
    }

    pub fn observed_at(&self) -> CompletionResult<String> {
        self.validate()?;
        let observed = newest_observation(&self.activation_evidence);
        let observed = i64::try_from(observed)
            .map_err(|_| ManagedCompletionError::new("managed_completion_record_invalid"))?;
        Ok(MaterialTimestamp::from_unix_seconds(observed).to_utc_string())
    }
}

/// Decode and verify one daemon-produced record with duplicate-key rejection.
/// The producer's idempotent reload and privileged consumer share this exact
/// closed decoder.
pub fn decode_record(raw: &[u8]) -> CompletionResult<ManagedCompletionRecordV2> {
    let record: ManagedCompletionRecordV2 =
        crate::paimos::decode_strict(raw, "managed_completion_record_invalid")
            .map_err(|_| ManagedCompletionError::new("managed_completion_record_invalid"))?;
    record.validate()?;
    Ok(record)
}

impl ManagedCompletionBindingV2 {
    pub fn digest(&self) -> CompletionResult<String> {
        validate_binding_shape(self)?;
        let canonical = crate::paimos::canonical_json_bytes(self)
            .map_err(|_| ManagedCompletionError::new("managed_completion_binding_invalid"))?;
        Ok(format!("sha256:{:x}", Sha256::digest(canonical)))
    }

    pub(crate) fn matches_record(&self, record: &ManagedCompletionRecordV2) -> bool {
        transaction_fields!(self).matches_record(record)
    }
}

impl ManagedCompletionAeonBindingV1 {
    pub fn digest(&self) -> CompletionResult<String> {
        validate_aeon_binding_shape(self)?;
        let canonical = crate::paimos::canonical_json_bytes(self)
            .map_err(|_| ManagedCompletionError::new("managed_completion_binding_invalid"))?;
        Ok(format!("sha256:{:x}", Sha256::digest(canonical)))
    }

    pub(crate) fn matches_record(&self, record: &ManagedCompletionRecordV2) -> bool {
        transaction_fields!(self).matches_record(record)
    }
}

/// Consume the single fixed ready record through the fixed privileged reporter
/// boundary. Missing optional state is inert; malformed or conflicting state
/// is a fail-closed error before credentials or transport are touched.
pub fn run_from_system() -> CompletionResult<()> {
    run_optional_from_paths(
        Path::new(SYSTEM_BINDING_PATH),
        Path::new(SYSTEM_READY_PATH),
        Path::new(super::paimos::SYSTEM_CONFIG_PATH),
        0,
        0,
        PRODUCER_UID,
        PRODUCER_GID,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_optional_from_paths(
    binding_path: &Path,
    ready_path: &Path,
    reporter_config_path: &Path,
    binding_uid: u32,
    binding_gid: u32,
    producer_uid: u32,
    producer_gid: u32,
    allow_loopback_http: bool,
) -> CompletionResult<()> {
    if !path_is_present(binding_path)? || !path_is_present(ready_path)? {
        return Ok(());
    }
    run_from_paths(
        binding_path,
        ready_path,
        reporter_config_path,
        binding_uid,
        binding_gid,
        producer_uid,
        producer_gid,
        allow_loopback_http,
    )
}

fn path_is_present(path: &Path) -> CompletionResult<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(ManagedCompletionError::new(
            "managed_completion_state_unavailable",
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn run_from_paths(
    binding_path: &Path,
    ready_path: &Path,
    reporter_config_path: &Path,
    binding_uid: u32,
    binding_gid: u32,
    producer_uid: u32,
    producer_gid: u32,
    allow_loopback_http: bool,
) -> CompletionResult<()> {
    let binding_raw = read_exact_private(
        binding_path,
        MAX_BINDING_BYTES,
        binding_uid,
        binding_gid,
        "managed_completion_binding_unavailable",
    )?;
    if crate::aeon_stage::selects_aeon(&binding_raw, AEON_BINDING_SCHEMA) {
        return run_aeon_binding(
            &binding_raw,
            ready_path,
            reporter_config_path,
            binding_uid,
            producer_uid,
            producer_gid,
            allow_loopback_http,
        );
    }
    let binding: ManagedCompletionBindingV2 =
        crate::paimos::decode_strict(&binding_raw, "managed_completion_binding_invalid")
            .map_err(|_| ManagedCompletionError::new("managed_completion_binding_invalid"))?;
    let binding_digest = binding.digest()?;

    let directory = ready_path
        .parent()
        .ok_or_else(|| ManagedCompletionError::new("managed_completion_record_unavailable"))?;
    validate_record_directory(directory, producer_uid, producer_gid)?;
    let record_raw = read_exact_private(
        ready_path,
        MAX_RECORD_BYTES,
        producer_uid,
        producer_gid,
        "managed_completion_record_unavailable",
    )?;
    let record = decode_record(&record_raw)?;
    if record.binding_digest != binding_digest || !binding.matches_record(&record) {
        return Err(ManagedCompletionError::new(
            "managed_completion_binding_refused",
        ));
    }
    let observed_at = record.observed_at()?;
    crate::paimos::run_managed_completion_from_path(
        reporter_config_path,
        &binding.reporter,
        observed_at,
        binding_uid,
        allow_loopback_http,
    )
    .map_err(|_| ManagedCompletionError::new("managed_completion_report_pending"))
}

/// Consume the ready record for an Aeon binding. The record, directory and
/// custody checks are the classic ones; only the reporter differs.
#[allow(clippy::too_many_arguments)]
fn run_aeon_binding(
    binding_raw: &[u8],
    ready_path: &Path,
    reporter_config_path: &Path,
    binding_uid: u32,
    producer_uid: u32,
    producer_gid: u32,
    allow_loopback_http: bool,
) -> CompletionResult<()> {
    let binding: ManagedCompletionAeonBindingV1 =
        crate::paimos::decode_strict(binding_raw, "managed_completion_binding_invalid")
            .map_err(|_| ManagedCompletionError::new("managed_completion_binding_invalid"))?;
    let binding_digest = binding.digest()?;
    let directory = ready_path
        .parent()
        .ok_or_else(|| ManagedCompletionError::new("managed_completion_record_unavailable"))?;
    validate_record_directory(directory, producer_uid, producer_gid)?;
    let record_raw = read_exact_private(
        ready_path,
        MAX_RECORD_BYTES,
        producer_uid,
        producer_gid,
        "managed_completion_record_unavailable",
    )?;
    let record = decode_record(&record_raw)?;
    if record.binding_digest != binding_digest || !binding.matches_record(&record) {
        return Err(ManagedCompletionError::new(
            "managed_completion_binding_refused",
        ));
    }
    let observed_at = record.observed_at()?;
    crate::aeon_stage::run_managed_completion_from_path(
        reporter_config_path,
        &binding.reporter,
        observed_at,
        binding_uid,
        allow_loopback_http,
    )
    .map_err(|_| ManagedCompletionError::new("managed_completion_report_pending"))
}

fn validate_aeon_binding_shape(binding: &ManagedCompletionAeonBindingV1) -> CompletionResult<()> {
    if crate::aeon_stage::validate_managed_reporter_binding_shape(&binding.reporter).is_err()
        || binding.reporter.evidence_source != "managed_completion_record"
        || binding.schema != AEON_BINDING_SCHEMA
        || binding.schema_version != 1
        || !transaction_fields!(binding).valid()
    {
        return Err(ManagedCompletionError::new(
            "managed_completion_binding_invalid",
        ));
    }
    Ok(())
}

pub(crate) fn validate_binding_shape(binding: &ManagedCompletionBindingV2) -> CompletionResult<()> {
    if crate::paimos::validate_managed_reporter_binding_shape(&binding.reporter).is_err()
        || binding.reporter.evidence_source != "managed_completion_record"
        || binding.schema != BINDING_SCHEMA
        || binding.schema_version != 1
        || !transaction_fields!(binding).valid()
    {
        return Err(ManagedCompletionError::new(
            "managed_completion_binding_invalid",
        ));
    }
    Ok(())
}

fn validate_record_shape(record: &ManagedCompletionRecordV2) -> CompletionResult<()> {
    let evidence = &record.activation_evidence;
    let oldest = oldest_observation(evidence);
    let newest = newest_observation(evidence);
    if record.schema != RECORD_SCHEMA
        || record.schema_version != 1
        || !valid_wire_digest(&record.binding_digest)
        || !valid_ref("op_", &record.operation_ref)
        || !valid_ref("webtx_", &record.operation_id)
        || record.operation_kind != "create"
        || record.source != "generated"
        || !valid_ref("host_", &record.host_ref)
        || !valid_ref("svc_", &record.service_ref)
        || !valid_ref("slot_", &record.slot_ref)
        || !valid_ref("decl_", &record.declaration_fingerprint)
        || !valid_ref("sec_", &record.secret_ref)
        || !valid_ref("scp_", &record.scope_ref)
        || record.generation == 0
        || record.revocation_epoch == 0
        || !valid_hex_digest(&record.plan_fingerprint)
        || !valid_hex_digest(&record.target_fingerprint)
        || !valid_ref("key_", &record.producer_key_id)
        || record.preflighted_at_unix_secs == 0
        || record.prepared_at_unix_secs < record.preflighted_at_unix_secs
        || record.evidence_accepted_at_unix_secs < record.prepared_at_unix_secs
        || evidence.generation != record.generation
        || !evidence.materialized
        || evidence.process_state != "running"
        || evidence.probe_state != "healthy"
        || oldest < record.prepared_at_unix_secs
        || newest > record.evidence_accepted_at_unix_secs
        || record.evidence_accepted_at_unix_secs.saturating_sub(oldest)
            > ACTIVATION_FRESHNESS_SECONDS
    {
        return Err(ManagedCompletionError::new(
            "managed_completion_record_invalid",
        ));
    }
    Ok(())
}

fn oldest_observation(evidence: &AcceptedActivationEvidenceV1) -> u64 {
    evidence
        .heartbeat_observed_at_unix_secs
        .min(evidence.process_observed_at_unix_secs)
        .min(evidence.probe_observed_at_unix_secs)
}

fn newest_observation(evidence: &AcceptedActivationEvidenceV1) -> u64 {
    evidence
        .heartbeat_observed_at_unix_secs
        .max(evidence.process_observed_at_unix_secs)
        .max(evidence.probe_observed_at_unix_secs)
}

fn record_hash(record: &ManagedCompletionRecordV2) -> CompletionResult<String> {
    let mut unsigned = record.clone();
    unsigned.integrity_hash.clear();
    let canonical = serde_json::to_vec(&unsigned)
        .map_err(|_| ManagedCompletionError::new("managed_completion_record_invalid"))?;
    Ok(format!("sha256:{:x}", Sha256::digest(canonical)))
}

fn valid_ref(prefix: &str, value: &str) -> bool {
    value.len() >= prefix.len() + 8
        && value.len() <= 96
        && value.starts_with(prefix)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_wire_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(valid_hex_digest)
}

fn valid_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn read_exact_private(
    path: &Path,
    maximum: usize,
    owner_uid: u32,
    owner_gid: u32,
    reason: &'static str,
) -> CompletionResult<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ManagedCompletionError::new(reason))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != owner_uid
        || metadata.gid() != owner_gid
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() == 0
        || metadata.len() > maximum as u64
    {
        return Err(ManagedCompletionError::new(reason));
    }
    let mut file = File::open(path).map_err(|_| ManagedCompletionError::new(reason))?;
    let opened = file
        .metadata()
        .map_err(|_| ManagedCompletionError::new(reason))?;
    if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
        return Err(ManagedCompletionError::new(reason));
    }
    let mut raw = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|_| ManagedCompletionError::new(reason))?;
    if raw.is_empty() || raw.len() > maximum {
        return Err(ManagedCompletionError::new(reason));
    }
    Ok(raw)
}

fn validate_record_directory(path: &Path, owner_uid: u32, owner_gid: u32) -> CompletionResult<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| ManagedCompletionError::new("managed_completion_record_unavailable"))?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != owner_uid
        || metadata.gid() != owner_gid
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(ManagedCompletionError::new(
            "managed_completion_record_unavailable",
        ));
    }
    let mut entries = 0usize;
    for entry in fs::read_dir(path)
        .map_err(|_| ManagedCompletionError::new("managed_completion_record_unavailable"))?
    {
        let entry = entry
            .map_err(|_| ManagedCompletionError::new("managed_completion_record_unavailable"))?;
        entries = entries.saturating_add(1);
        if entries > MAX_DIRECTORY_ENTRIES
            || !matches!(
                entry.file_name().to_str(),
                Some(".producer.lock" | "pending.json" | "ready.json")
            )
        {
            return Err(ManagedCompletionError::new(
                "managed_completion_record_unavailable",
            ));
        }
    }
    Ok(())
}

#[cfg(feature = "test-support")]
pub mod test_support {
    use super::*;

    pub fn run_from_paths_for_test(
        binding_path: &Path,
        ready_path: &Path,
        reporter_config_path: &Path,
        owner_uid: u32,
        owner_gid: u32,
    ) -> CompletionResult<()> {
        run_from_paths(
            binding_path,
            ready_path,
            reporter_config_path,
            owner_uid,
            owner_gid,
            owner_uid,
            owner_gid,
            true,
        )
    }

    pub fn run_optional_from_paths_for_test(
        binding_path: &Path,
        ready_path: &Path,
        reporter_config_path: &Path,
        owner_uid: u32,
        owner_gid: u32,
    ) -> CompletionResult<()> {
        run_optional_from_paths(
            binding_path,
            ready_path,
            reporter_config_path,
            owner_uid,
            owner_gid,
            owner_uid,
            owner_gid,
            true,
        )
    }

    pub fn reporter_binding_from_config(
        raw: &[u8],
    ) -> CompletionResult<PaimosManagedCompletionBindingV1> {
        let config: crate::paimos::ManagedReporterConfigV1 =
            crate::paimos::decode_strict(raw, "managed_completion_config_invalid")
                .map_err(|_| ManagedCompletionError::new("managed_completion_config_invalid"))?;
        crate::paimos::managed_reporter_binding(&config, true)
            .map_err(|_| ManagedCompletionError::new("managed_completion_config_invalid"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

    const GOLDEN_BINDING: &[u8] = include_bytes!(
        "../../../examples/paimos-dependency-reporter/managed-completion-binding.golden.json"
    );
    const GOLDEN_BINDING_DIGEST: &str =
        "sha256:797bd2d85f95c3c5a09a87986526ca6695e5e1e34f2565293d6ae0bf314de757";

    #[test]
    fn managed_completion_binding_digest_matches_cross_language_golden() {
        let binding: ManagedCompletionBindingV2 =
            crate::paimos::decode_strict(GOLDEN_BINDING, "managed_completion_binding_invalid")
                .expect("decode golden binding");

        assert_eq!(
            binding.digest().expect("digest binding"),
            GOLDEN_BINDING_DIGEST
        );
    }

    const AEON_GOLDEN_BINDING: &[u8] = include_bytes!(
        "../../../examples/aeon-stage-reporter/managed-completion-binding.golden.json"
    );
    const AEON_GOLDEN_BINDING_DIGEST: &str =
        "sha256:6e159146a3bbbb8ab03916d8de191cc61a85845c00712b4e0f024f5a206ff1da";

    #[test]
    fn aeon_binding_digest_matches_cross_language_golden_and_selects_aeon() {
        let binding: ManagedCompletionAeonBindingV1 =
            crate::paimos::decode_strict(AEON_GOLDEN_BINDING, "managed_completion_binding_invalid")
                .expect("decode Aeon golden binding");
        assert_eq!(
            binding.digest().expect("digest Aeon binding"),
            AEON_GOLDEN_BINDING_DIGEST
        );
        let mut relabelled = binding.clone();
        relabelled.reporter.evidence_source = "managed_credential_reattestation_record".to_string();
        assert!(relabelled.digest().is_err());
        assert!(crate::aeon_stage::selects_aeon(
            AEON_GOLDEN_BINDING,
            AEON_BINDING_SCHEMA
        ));
        assert!(!crate::aeon_stage::selects_aeon(
            GOLDEN_BINDING,
            AEON_BINDING_SCHEMA
        ));
        // A classic decoder never accepts the Aeon binding, nor the reverse.
        assert!(crate::paimos::decode_strict::<ManagedCompletionBindingV2>(
            AEON_GOLDEN_BINDING,
            "managed_completion_binding_invalid"
        )
        .is_err());
        assert!(
            crate::paimos::decode_strict::<ManagedCompletionAeonBindingV1>(
                GOLDEN_BINDING,
                "managed_completion_binding_invalid"
            )
            .is_err()
        );
    }

    fn aeon_record(binding_digest: String) -> ManagedCompletionRecordV2 {
        let mut record = ManagedCompletionRecordV2 {
            schema: RECORD_SCHEMA.to_string(),
            schema_version: 1,
            binding_digest,
            operation_ref: "op_0123456789abcdef".to_string(),
            operation_id: "webtx_0123456789abcdef".to_string(),
            operation_kind: "create".to_string(),
            source: "generated".to_string(),
            host_ref: "host_0123456789abcdef".to_string(),
            service_ref: "svc_0123456789abcdef".to_string(),
            slot_ref: "slot_0123456789abcdef".to_string(),
            declaration_fingerprint: "decl_0123456789abcdef".to_string(),
            secret_ref: "sec_fixturefixture".to_string(),
            scope_ref: "scp_0123456789abcdef".to_string(),
            generation: 1,
            revocation_epoch: 1,
            plan_fingerprint: "a".repeat(64),
            target_fingerprint: "b".repeat(64),
            producer_key_id: "key_0123456789abcdef".to_string(),
            prepared_at_unix_secs: 1_790_409_400,
            preflighted_at_unix_secs: 1_790_409_390,
            evidence_accepted_at_unix_secs: 1_790_409_500,
            activation_evidence: AcceptedActivationEvidenceV1 {
                generation: 1,
                materialized: true,
                process_state: "running".to_string(),
                probe_state: "healthy".to_string(),
                heartbeat_observed_at_unix_secs: 1_790_409_470,
                process_observed_at_unix_secs: 1_790_409_480,
                probe_observed_at_unix_secs: 1_790_409_490,
            },
            integrity_hash: String::new(),
        };
        record.seal().expect("seal record");
        record
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).expect("write private fixture");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("protect fixture");
    }

    #[test]
    fn aeon_managed_completion_reports_record_time_only_after_live_checks() {
        use crate::aeon_stage::tests as aeon;

        let fixture = aeon::new_fixture();
        let server = aeon::FakeAeon::start();
        let root = fixture.temporary.path();
        let metadata = fs::metadata(root).expect("fixture metadata");
        let (uid, gid) = (metadata.uid(), metadata.gid());

        let config = aeon::managed_config(&fixture, &server.origin);
        let reporter =
            crate::aeon_stage::managed_reporter_binding(&config, true).expect("reporter binding");
        let binding: ManagedCompletionAeonBindingV1 = {
            let mut value: serde_json::Value =
                serde_json::from_slice(AEON_GOLDEN_BINDING).expect("golden JSON");
            value["reporter"] = serde_json::to_value(&reporter).expect("reporter JSON");
            serde_json::from_value(value).expect("Aeon binding")
        };
        let config_path = root.join("reporter-config.json");
        let binding_path = root.join("binding.json");
        let records = root.join("records");
        fs::create_dir(&records).expect("record directory");
        fs::set_permissions(&records, fs::Permissions::from_mode(0o700)).expect("protect records");
        let ready_path = records.join("ready.json");
        write_private(
            &config_path,
            &serde_json::to_vec(&config).expect("config JSON"),
        );
        write_private(
            &binding_path,
            &serde_json::to_vec(&binding).expect("binding JSON"),
        );

        // A record bound to another binding digest is refused before any I/O.
        let foreign = aeon_record(format!("sha256:{}", "f".repeat(64)));
        write_private(
            &ready_path,
            &serde_json::to_vec(&foreign).expect("record JSON"),
        );
        assert_eq!(
            run_from_paths(
                &binding_path,
                &ready_path,
                &config_path,
                uid,
                gid,
                uid,
                gid,
                true
            )
            .expect_err("foreign record")
            .reason_code(),
            "managed_completion_binding_refused"
        );
        assert!(server.requests().is_empty());

        // Aeon refusing the live grant leaves the report pending: a local
        // completion alone never becomes Access success.
        let record = aeon_record(binding.digest().expect("binding digest"));
        write_private(
            &ready_path,
            &serde_json::to_vec(&record).expect("record JSON"),
        );
        server.with(|state| state.grant_live = false);
        assert_eq!(
            run_from_paths(
                &binding_path,
                &ready_path,
                &config_path,
                uid,
                gid,
                uid,
                gid,
                true
            )
            .expect_err("no live grant")
            .reason_code(),
            "managed_completion_report_pending"
        );
        server.with(|state| {
            assert!(state.evidence.is_empty() && state.result.is_none());
            state.grant_live = true;
            state.requests.clear();
        });

        run_from_paths(
            &binding_path,
            &ready_path,
            &config_path,
            uid,
            gid,
            uid,
            gid,
            true,
        )
        .expect("managed completion reported");
        let requests = server.requests();
        // The journal replays the first run's authorization observation.
        let authorization: serde_json::Value = serde_json::from_slice(
            &requests
                .iter()
                .find(|request| request.method == "POST")
                .expect("first write")
                .body,
        )
        .expect("authorization JSON");
        assert!(authorization["observed_at"].as_str().is_some());
        let credential = requests
            .iter()
            .filter(|request| request.method == "POST")
            .nth(1)
            .expect("credential write");
        let credential: serde_json::Value =
            serde_json::from_slice(&credential.body).expect("credential JSON");
        assert_eq!(
            credential["observed_at"],
            record.observed_at().expect("record time")
        );
        assert_eq!(credential["credential_ready"], true);
        server.with(|state| assert_eq!(state.result.as_ref().unwrap()["outcome"], "succeeded"));
    }

    #[test]
    fn capability_rejects_dependency_wait_and_authority_selectors() {
        for field in ["dependency_key", "wait_for", "config_path", "executable"] {
            let mut capability = serde_json::json!({
                "schema": CAPABILITY_SCHEMA,
                "schema_version": 1,
                "operation_ref": "op_0123456789abcdef",
                "binding_digest": format!("sha256:{}", "a".repeat(64))
            });
            capability
                .as_object_mut()
                .expect("capability object")
                .insert(field.to_string(), serde_json::json!("forbidden"));
            assert!(serde_json::from_value::<ManagedCompletionCapabilityV1>(capability).is_err());
        }
    }

    #[test]
    fn optional_missing_state_is_inert_without_reporter_config() {
        let temporary = tempfile::tempdir().expect("temporary optional state");
        let missing = temporary.path().join("missing");
        assert!(run_optional_from_paths(
            &missing.join("binding.json"),
            &missing.join("ready.json"),
            &missing.join("config.json"),
            0,
            0,
            0,
            0,
            true,
        )
        .is_ok());
    }

    #[test]
    fn completion_custody_rejects_owner_mode_links_size_and_capacity() {
        let temporary = tempfile::tempdir().expect("temporary custody root");
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
            .expect("protect custody root");
        let metadata = fs::metadata(temporary.path()).expect("custody metadata");
        let owner_uid = metadata.uid();
        let owner_gid = metadata.gid();
        let binding = temporary.path().join("binding.json");
        fs::write(&binding, GOLDEN_BINDING).expect("write binding");
        fs::set_permissions(&binding, fs::Permissions::from_mode(0o600)).expect("protect binding");
        assert!(
            read_exact_private(&binding, MAX_BINDING_BYTES, owner_uid, owner_gid, "fixture")
                .is_ok()
        );
        assert!(read_exact_private(
            &binding,
            MAX_BINDING_BYTES,
            owner_uid.saturating_add(1),
            owner_gid,
            "fixture"
        )
        .is_err());
        fs::set_permissions(&binding, fs::Permissions::from_mode(0o640))
            .expect("broaden binding mode");
        assert!(
            read_exact_private(&binding, MAX_BINDING_BYTES, owner_uid, owner_gid, "fixture")
                .is_err()
        );
        fs::set_permissions(&binding, fs::Permissions::from_mode(0o600))
            .expect("restore binding mode");

        let hardlink = temporary.path().join("binding-hardlink.json");
        fs::hard_link(&binding, &hardlink).expect("create hardlink fixture");
        assert!(
            read_exact_private(&binding, MAX_BINDING_BYTES, owner_uid, owner_gid, "fixture")
                .is_err()
        );
        fs::remove_file(&hardlink).expect("remove hardlink fixture");
        let link = temporary.path().join("binding-symlink.json");
        symlink(&binding, &link).expect("create symlink fixture");
        assert!(
            read_exact_private(&link, MAX_BINDING_BYTES, owner_uid, owner_gid, "fixture").is_err()
        );

        let oversized = temporary.path().join("oversized.json");
        fs::write(&oversized, vec![b'x'; MAX_BINDING_BYTES + 1]).expect("write oversized input");
        fs::set_permissions(&oversized, fs::Permissions::from_mode(0o600))
            .expect("protect oversized input");
        assert!(read_exact_private(
            &oversized,
            MAX_BINDING_BYTES,
            owner_uid,
            owner_gid,
            "fixture"
        )
        .is_err());

        fs::write(temporary.path().join("unexpected"), b"x").expect("write excess entry");
        assert!(validate_record_directory(temporary.path(), owner_uid, owner_gid).is_err());
    }
}
