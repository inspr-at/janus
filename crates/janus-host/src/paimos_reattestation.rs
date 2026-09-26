//! Read-only re-attestation of one retained managed credential generation.
//!
//! A privileged no-argument process proves the immutable original completion,
//! the current protected host generation, and a fresh digest-pinned local
//! process/probe observation before writing new value-free evidence. It never
//! opens the materialized credential and never changes its lifecycle state.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use janus_core::MaterialTimestamp;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::aeon_stage::AeonManagedCompletionBindingV1;
use crate::paimos::PaimosManagedCompletionBindingV1;
use crate::paimos_completion::{
    decode_record, validate_binding_shape as validate_completion_binding,
    ManagedCompletionAeonBindingV1, ManagedCompletionBindingV2,
    AEON_BINDING_SCHEMA as AEON_COMPLETION_BINDING_SCHEMA,
};
use crate::{HostCredentialAttestationStatusV1, HostExecutor};

pub const CAPABILITY_SCHEMA: &str = "inspr.janus.managed-credential-reattestation-capability.v1";
pub const BINDING_SCHEMA: &str = "inspr.janus.managed-credential-reattestation-binding.v1";
pub const OBSERVATION_SCHEMA: &str = "inspr.janus.managed-credential-current-observation.v1";
pub const EVIDENCE_SCHEMA: &str = "inspr.janus.managed-credential-reattestation-record.v1";
/// JANUS-480: the same re-attestation reported to one Aeon Access handoff.
pub const AEON_BINDING_SCHEMA: &str =
    "inspr.janus.managed-credential-reattestation-aeon-binding.v1";
pub const AEON_EVIDENCE_SCHEMA: &str =
    "inspr.janus.managed-credential-reattestation-aeon-record.v1";

const SYSTEM_CAPABILITY_PATH: &str = "/run/janus-managed-credential-reattestation/capability.json";
const SYSTEM_BINDING_PATH: &str = "/run/janus-managed-credential-reattestation/binding.json";
const SYSTEM_REPORTER_CONFIG_PATH: &str =
    "/run/janus-managed-credential-reattestation/reporter-config.json";
const SYSTEM_SOURCE_BINDING_PATH: &str =
    "/run/janus-paimos-dependency-reporter/managed-completion-binding.json";
const SYSTEM_SOURCE_RECORD_PATH: &str =
    "/var/lib/janus-managed-central/completion-dispatch/ready.json";
const SYSTEM_EVIDENCE_DIRECTORY: &str = "/var/lib/janus-managed-central/credential-reattestation";
const MAX_INPUT_BYTES: usize = 64 * 1024;
const MAX_OBSERVER_BYTES: usize = 64 * 1024;
const MAX_DIRECTORY_ENTRIES: usize = 1025;
const MAX_OBSERVER_SECONDS: u64 = 15;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManagedCredentialReattestationError {
    reason_code: &'static str,
}

impl ManagedCredentialReattestationError {
    fn new(reason_code: &'static str) -> Self {
        Self { reason_code }
    }

    pub fn reason_code(self) -> &'static str {
        self.reason_code
    }
}

impl fmt::Display for ManagedCredentialReattestationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code)
    }
}

impl std::error::Error for ManagedCredentialReattestationError {}

type Result<T> = std::result::Result<T, ManagedCredentialReattestationError>;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedCredentialReattestationCapabilityV1 {
    pub schema: String,
    pub schema_version: u8,
    pub attestation_ref: String,
    pub operation_ref: String,
    pub binding_digest: String,
}

/// The reporter a re-attestation binding names: classic Paimos or Aeon.
pub trait ReattestationReporter:
    Clone + fmt::Debug + PartialEq + Serialize + for<'de> Deserialize<'de>
{
    /// Binding schema that carries this reporter.
    const BINDING_SCHEMA: &'static str;
    /// Local evidence-record schema written for this reporter.
    const RECORD_SCHEMA: &'static str;
    /// Reporter shape, including the re-attestation evidence source.
    fn reattestation_shape_valid(&self) -> bool;
    /// The handoff tuple the local record binds.
    fn record_tuple(&self) -> RecordTuple;
    /// True when this reporter names a different attempt than the source.
    fn distinct_from(&self, source: &SourceReporter<'_>) -> bool;
    /// Report the record's observation through the reporter's adapter.
    fn report(
        &self,
        config_path: &Path,
        observed_at: String,
        owner_uid: u32,
        allow_loopback_http: bool,
    ) -> bool;
}

/// Handoff tuple copied into the local record. The classic-only fields are
/// absent for Aeon, which has no execution number or credential epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordTuple {
    handoff_id: String,
    execution_number: Option<i64>,
    authority_epoch: i64,
    credential_epoch: Option<i64>,
}

/// The reporter of the original managed completion being re-attested.
pub enum SourceReporter<'a> {
    Classic(&'a PaimosManagedCompletionBindingV1),
    Aeon(&'a AeonManagedCompletionBindingV1),
}

impl ReattestationReporter for PaimosManagedCompletionBindingV1 {
    const BINDING_SCHEMA: &'static str = BINDING_SCHEMA;
    const RECORD_SCHEMA: &'static str = EVIDENCE_SCHEMA;

    fn reattestation_shape_valid(&self) -> bool {
        crate::paimos::validate_managed_reporter_binding_shape(self).is_ok()
            && self.evidence_source == "managed_credential_reattestation_record"
    }

    fn record_tuple(&self) -> RecordTuple {
        RecordTuple {
            handoff_id: self.handoff_id.clone(),
            execution_number: Some(self.execution_number),
            authority_epoch: self.authority_epoch,
            credential_epoch: Some(self.credential_epoch),
        }
    }

    fn distinct_from(&self, source: &SourceReporter<'_>) -> bool {
        // A classic retry of an Aeon completion is never a supported shape.
        match source {
            SourceReporter::Classic(source) => {
                source.handoff_id != self.handoff_id
                    && source.execution_number != self.execution_number
            }
            SourceReporter::Aeon(_) => false,
        }
    }

    fn report(
        &self,
        config_path: &Path,
        observed_at: String,
        owner_uid: u32,
        allow_loopback_http: bool,
    ) -> bool {
        crate::paimos::run_managed_completion_from_path(
            config_path,
            self,
            observed_at,
            owner_uid,
            allow_loopback_http,
        )
        .is_ok()
    }
}

impl ReattestationReporter for AeonManagedCompletionBindingV1 {
    const BINDING_SCHEMA: &'static str = AEON_BINDING_SCHEMA;
    const RECORD_SCHEMA: &'static str = AEON_EVIDENCE_SCHEMA;

    fn reattestation_shape_valid(&self) -> bool {
        crate::aeon_stage::validate_managed_reporter_binding_shape(self).is_ok()
            && self.evidence_source == "managed_credential_reattestation_record"
    }

    fn record_tuple(&self) -> RecordTuple {
        RecordTuple {
            handoff_id: self.handoff_id.clone(),
            execution_number: None,
            authority_epoch: self.authority_epoch,
            credential_epoch: None,
        }
    }

    fn distinct_from(&self, source: &SourceReporter<'_>) -> bool {
        // An Aeon retry is a new handoff with its own attempt and epoch; a
        // classic source handoff can never share its UUID.
        match source {
            SourceReporter::Classic(_) => true,
            SourceReporter::Aeon(source) => {
                source.handoff_id != self.handoff_id
                    && (source.release_node_id != self.release_node_id
                        || source.authority_epoch != self.authority_epoch)
            }
        }
    }

    fn report(
        &self,
        config_path: &Path,
        observed_at: String,
        owner_uid: u32,
        allow_loopback_http: bool,
    ) -> bool {
        crate::aeon_stage::run_managed_completion_from_path(
            config_path,
            self,
            observed_at,
            owner_uid,
            allow_loopback_http,
        )
        .is_ok()
    }
}

pub type ManagedCredentialReattestationBindingV1 =
    ManagedCredentialReattestationBinding<PaimosManagedCompletionBindingV1>;
pub type ManagedCredentialReattestationAeonBindingV1 =
    ManagedCredentialReattestationBinding<AeonManagedCompletionBindingV1>;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedCredentialReattestationBinding<R> {
    pub schema: String,
    pub schema_version: u8,
    pub attestation_ref: String,
    pub reattestation_operation_ref: String,
    pub reattestation_declaration_fingerprint: String,
    pub source_completion_binding_digest: String,
    pub source_completion_record_sha256: String,
    pub host_ref: String,
    pub service_ref: String,
    pub slot_ref: String,
    pub source_operation_ref: String,
    pub envelope_ref: String,
    pub secret_ref: String,
    pub declaration_fingerprint: String,
    pub generation: u64,
    pub revocation_epoch: u64,
    pub producer_key_id: String,
    pub expected_packet_sha256: String,
    pub expected_material_owner_uid: u32,
    pub expected_material_size: u64,
    pub observer_path: String,
    pub observer_sha256: String,
    pub observer_config_digest: String,
    pub expected_process_executable_sha256: String,
    pub expected_artifact_digest: String,
    pub expected_release_ref: String,
    pub freshness_seconds: u64,
    pub reporter: R,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CurrentProcessObservationV1 {
    pub state: String,
    pub pid: u32,
    pub executable_sha256: String,
    pub observed_at_unix_secs: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CurrentProbeObservationV1 {
    pub state: String,
    pub credential_ready: bool,
    pub pid: u32,
    pub artifact_digest: String,
    pub release_ref: String,
    pub runtime_id: String,
    pub runtime_generation: u64,
    pub runtime_history_sha256: String,
    pub observed_at_unix_secs: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedCredentialCurrentObservationV1 {
    pub schema: String,
    pub schema_version: u8,
    pub attestation_ref: String,
    pub observer_config_digest: String,
    pub host_ref: String,
    pub service_ref: String,
    pub slot_ref: String,
    pub operation_ref: String,
    pub generation: u64,
    pub revocation_epoch: u64,
    pub process: CurrentProcessObservationV1,
    pub probe: CurrentProbeObservationV1,
    pub heartbeat_observed_at_unix_secs: u64,
    pub value_returned: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedCredentialReattestationRecordV1 {
    pub schema: String,
    pub schema_version: u8,
    pub attestation_ref: String,
    pub binding_digest: String,
    pub source_completion_record_sha256: String,
    pub handoff_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_number: Option<i64>,
    pub authority_epoch: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_epoch: Option<i64>,
    pub host_status: HostCredentialAttestationStatusV1,
    pub observation: ManagedCredentialCurrentObservationV1,
    pub evidence_accepted_at_unix_secs: u64,
    pub integrity_hash: String,
}

impl ManagedCredentialReattestationCapabilityV1 {
    fn validate(&self) -> Result<()> {
        if self.schema != CAPABILITY_SCHEMA
            || self.schema_version != 1
            || !valid_ref("reattest_", &self.attestation_ref)
            || !valid_ref("op_", &self.operation_ref)
            || !valid_wire_digest(&self.binding_digest)
        {
            return Err(error("managed_credential_reattestation_capability_invalid"));
        }
        Ok(())
    }
}

impl<R: ReattestationReporter> ManagedCredentialReattestationBinding<R> {
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        let canonical = crate::paimos::canonical_json_bytes(self)
            .map_err(|_| error("managed_credential_reattestation_binding_invalid"))?;
        Ok(wire_sha256(&canonical))
    }

    fn validate(&self) -> Result<()> {
        if self.schema != R::BINDING_SCHEMA
            || self.schema_version != 1
            || !valid_ref("reattest_", &self.attestation_ref)
            || !valid_ref("op_", &self.reattestation_operation_ref)
            || !valid_ref("decl_", &self.reattestation_declaration_fingerprint)
            || !valid_wire_digest(&self.source_completion_binding_digest)
            || !valid_wire_digest(&self.source_completion_record_sha256)
            || !valid_ref("host_", &self.host_ref)
            || !valid_ref("svc_", &self.service_ref)
            || !valid_ref("slot_", &self.slot_ref)
            || !valid_ref("op_", &self.source_operation_ref)
            || self.reattestation_operation_ref == self.source_operation_ref
            || !valid_ref("env_", &self.envelope_ref)
            || !valid_ref("sec_", &self.secret_ref)
            || !valid_ref("decl_", &self.declaration_fingerprint)
            || self.reattestation_declaration_fingerprint == self.declaration_fingerprint
            || self.generation == 0
            || self.revocation_epoch == 0
            || !valid_ref("key_", &self.producer_key_id)
            || !valid_wire_digest(&self.expected_packet_sha256)
            || self.expected_material_owner_uid == u32::MAX
            || self.expected_material_size == 0
            || self.expected_material_size > 64 * 1024
            || !absolute_path(&self.observer_path)
            || !valid_wire_digest(&self.observer_sha256)
            || !valid_wire_digest(&self.observer_config_digest)
            || !valid_wire_digest(&self.expected_process_executable_sha256)
            || !valid_wire_digest(&self.expected_artifact_digest)
            || !valid_ref("release_", &self.expected_release_ref)
            || !(1..=120).contains(&self.freshness_seconds)
            || !self.reporter.reattestation_shape_valid()
        {
            return Err(error("managed_credential_reattestation_binding_invalid"));
        }
        Ok(())
    }
}

impl ManagedCredentialReattestationRecordV1 {
    fn seal(&mut self) -> Result<()> {
        self.integrity_hash.clear();
        self.validate_shape()?;
        self.integrity_hash = record_hash(self)?;
        Ok(())
    }

    fn validate(&self) -> Result<()> {
        self.validate_shape()?;
        if self.integrity_hash != record_hash(self)? {
            return Err(error("managed_credential_reattestation_record_invalid"));
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<()> {
        let handoff_shape = match self.schema.as_str() {
            EVIDENCE_SCHEMA => {
                valid_handoff_id(&self.handoff_id)
                    && self.execution_number.is_some_and(|value| value > 0)
                    && self.credential_epoch.is_some_and(|value| value > 0)
            }
            AEON_EVIDENCE_SCHEMA => {
                crate::aeon_stage::valid_uuid(&self.handoff_id)
                    && self.execution_number.is_none()
                    && self.credential_epoch.is_none()
            }
            _ => false,
        };
        if !handoff_shape
            || self.schema_version != 1
            || !valid_ref("reattest_", &self.attestation_ref)
            || !valid_wire_digest(&self.binding_digest)
            || !valid_wire_digest(&self.source_completion_record_sha256)
            || self.authority_epoch <= 0
            || self.evidence_accepted_at_unix_secs == 0
            || self.observation.value_returned
            || self.host_status.value_returned
        {
            return Err(error("managed_credential_reattestation_record_invalid"));
        }
        Ok(())
    }

    fn observed_at(&self) -> Result<String> {
        self.validate()?;
        let seconds = newest_observation(&self.observation);
        let seconds = i64::try_from(seconds)
            .map_err(|_| error("managed_credential_reattestation_record_invalid"))?;
        Ok(MaterialTimestamp::from_unix_seconds(seconds).to_utc_string())
    }
}

pub fn run_from_system() -> Result<()> {
    let capability_present = path_is_present(Path::new(SYSTEM_CAPABILITY_PATH))?;
    let binding_present = path_is_present(Path::new(SYSTEM_BINDING_PATH))?;
    if !configuration_is_enabled(capability_present, binding_present)? {
        return Ok(());
    }
    run_from_paths(
        Path::new(SYSTEM_CAPABILITY_PATH),
        Path::new(SYSTEM_BINDING_PATH),
        Path::new(SYSTEM_SOURCE_BINDING_PATH),
        Path::new(SYSTEM_SOURCE_RECORD_PATH),
        Path::new(SYSTEM_REPORTER_CONFIG_PATH),
        Path::new(SYSTEM_EVIDENCE_DIRECTORY),
        0,
        0,
        false,
        HostExecutor::from_system,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_from_paths<F>(
    capability_path: &Path,
    binding_path: &Path,
    source_binding_path: &Path,
    source_record_path: &Path,
    reporter_config_path: &Path,
    evidence_directory: &Path,
    owner_uid: u32,
    owner_gid: u32,
    allow_loopback_http: bool,
    host_executor: F,
) -> Result<()>
where
    F: Fn() -> std::result::Result<HostExecutor, crate::HostEnvelopeError>,
{
    let capability: ManagedCredentialReattestationCapabilityV1 = decode_private(
        capability_path,
        owner_uid,
        owner_gid,
        "managed_credential_reattestation_capability_unavailable",
    )?;
    capability.validate()?;
    let binding_raw = read_private(
        binding_path,
        owner_uid,
        owner_gid,
        "managed_credential_reattestation_binding_unavailable",
    )?;
    if crate::aeon_stage::selects_aeon(&binding_raw, AEON_BINDING_SCHEMA) {
        let binding: ManagedCredentialReattestationAeonBindingV1 = decode_binding(&binding_raw)?;
        return run_bound(
            capability,
            binding,
            source_binding_path,
            source_record_path,
            reporter_config_path,
            evidence_directory,
            owner_uid,
            owner_gid,
            allow_loopback_http,
            host_executor,
        );
    }
    let binding: ManagedCredentialReattestationBindingV1 = decode_binding(&binding_raw)?;
    run_bound(
        capability,
        binding,
        source_binding_path,
        source_record_path,
        reporter_config_path,
        evidence_directory,
        owner_uid,
        owner_gid,
        allow_loopback_http,
        host_executor,
    )
}

fn decode_binding<R: ReattestationReporter>(
    raw: &[u8],
) -> Result<ManagedCredentialReattestationBinding<R>> {
    crate::paimos::decode_strict(raw, "managed_credential_reattestation_binding_unavailable")
        .map_err(|_| error("managed_credential_reattestation_binding_unavailable"))
}

#[allow(clippy::too_many_arguments)]
fn run_bound<R, F>(
    capability: ManagedCredentialReattestationCapabilityV1,
    binding: ManagedCredentialReattestationBinding<R>,
    source_binding_path: &Path,
    source_record_path: &Path,
    reporter_config_path: &Path,
    evidence_directory: &Path,
    owner_uid: u32,
    owner_gid: u32,
    allow_loopback_http: bool,
    host_executor: F,
) -> Result<()>
where
    R: ReattestationReporter,
    F: Fn() -> std::result::Result<HostExecutor, crate::HostEnvelopeError>,
{
    let binding_digest = binding.digest()?;
    if capability.attestation_ref != binding.attestation_ref
        || capability.operation_ref != binding.reattestation_operation_ref
        || capability.binding_digest != binding_digest
    {
        return Err(error("managed_credential_reattestation_binding_refused"));
    }
    validate_source_completion(
        &binding,
        source_binding_path,
        source_record_path,
        owner_uid,
        owner_gid,
    )?;
    validate_evidence_directory(evidence_directory, owner_uid, owner_gid)?;
    let evidence_path = evidence_directory.join(format!("{}.json", binding.attestation_ref));
    let lock_path = evidence_directory.join(".lock");
    let lock = open_lock(&lock_path, owner_uid)?;
    lock.lock_exclusive()
        .map_err(|_| error("managed_credential_reattestation_record_unavailable"))?;
    let executor = host_executor()
        .map_err(|_| error("managed_credential_reattestation_host_state_refused"))?;
    let record = if let Some(record) = load_existing_record_for_retry(
        &evidence_path,
        &binding,
        &binding_digest,
        owner_uid,
        owner_gid,
        || validate_current_state(&binding, &executor, owner_uid),
    )? {
        record
    } else {
        let before = executor
            .credential_attestation_status(&binding.service_ref, &binding.slot_ref)
            .map_err(|_| error("managed_credential_reattestation_host_state_refused"))?;
        let observation = run_observer(&binding, owner_uid)?;
        let accepted_at = unix_seconds(SystemTime::now())?;
        let after = executor
            .credential_attestation_status(&binding.service_ref, &binding.slot_ref)
            .map_err(|_| error("managed_credential_reattestation_host_state_refused"))?;
        let record = build_record(
            &binding,
            &binding_digest,
            before,
            after,
            observation,
            accepted_at,
        )?;
        write_new_record(&evidence_path, &record, owner_uid)?;
        record
    };
    let observed_at = record.observed_at()?;
    if !binding.reporter.report(
        reporter_config_path,
        observed_at,
        owner_uid,
        allow_loopback_http,
    ) {
        return Err(error("managed_credential_reattestation_report_pending"));
    }
    Ok(())
}

fn configuration_is_enabled(capability_present: bool, binding_present: bool) -> Result<bool> {
    match (capability_present, binding_present) {
        (false, false) => Ok(false),
        (true, true) => Ok(true),
        _ => Err(error(
            "managed_credential_reattestation_configuration_incomplete",
        )),
    }
}

fn load_existing_record_for_retry<R: ReattestationReporter, F>(
    evidence_path: &Path,
    binding: &ManagedCredentialReattestationBinding<R>,
    binding_digest: &str,
    owner_uid: u32,
    owner_gid: u32,
    live_check: F,
) -> Result<Option<ManagedCredentialReattestationRecordV1>>
where
    F: FnOnce() -> Result<()>,
{
    if !path_is_present(evidence_path)? {
        return Ok(None);
    }
    let record: ManagedCredentialReattestationRecordV1 = decode_private(
        evidence_path,
        owner_uid,
        owner_gid,
        "managed_credential_reattestation_record_unavailable",
    )?;
    validate_existing_record(&record, binding, binding_digest)?;
    live_check()?;
    Ok(Some(record))
}

fn validate_current_state<R: ReattestationReporter>(
    binding: &ManagedCredentialReattestationBinding<R>,
    executor: &HostExecutor,
    owner_uid: u32,
) -> Result<()> {
    let before = executor
        .credential_attestation_status(&binding.service_ref, &binding.slot_ref)
        .map_err(|_| error("managed_credential_reattestation_host_state_refused"))?;
    let observation = run_observer(binding, owner_uid)?;
    let accepted_at = unix_seconds(SystemTime::now())?;
    let after = executor
        .credential_attestation_status(&binding.service_ref, &binding.slot_ref)
        .map_err(|_| error("managed_credential_reattestation_host_state_refused"))?;
    validate_host_status(&before, binding)?;
    validate_host_status(&after, binding)?;
    validate_observation(&observation, binding, accepted_at)?;
    if before != after {
        return Err(error("managed_credential_reattestation_host_state_changed"));
    }
    Ok(())
}

fn build_record<R: ReattestationReporter>(
    binding: &ManagedCredentialReattestationBinding<R>,
    binding_digest: &str,
    before: HostCredentialAttestationStatusV1,
    after: HostCredentialAttestationStatusV1,
    observation: ManagedCredentialCurrentObservationV1,
    accepted_at: u64,
) -> Result<ManagedCredentialReattestationRecordV1> {
    validate_host_status(&before, binding)?;
    validate_host_status(&after, binding)?;
    validate_observation(&observation, binding, accepted_at)?;
    if before != after {
        return Err(error("managed_credential_reattestation_host_state_changed"));
    }
    let tuple = binding.reporter.record_tuple();
    let mut record = ManagedCredentialReattestationRecordV1 {
        schema: R::RECORD_SCHEMA.to_string(),
        schema_version: 1,
        attestation_ref: binding.attestation_ref.clone(),
        binding_digest: binding_digest.to_string(),
        source_completion_record_sha256: binding.source_completion_record_sha256.clone(),
        handoff_id: tuple.handoff_id,
        execution_number: tuple.execution_number,
        authority_epoch: tuple.authority_epoch,
        credential_epoch: tuple.credential_epoch,
        host_status: before,
        observation,
        evidence_accepted_at_unix_secs: accepted_at,
        integrity_hash: String::new(),
    };
    record.seal()?;
    Ok(record)
}

fn validate_source_completion<R: ReattestationReporter>(
    binding: &ManagedCredentialReattestationBinding<R>,
    source_binding_path: &Path,
    source_record_path: &Path,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<()> {
    validate_source_record_directory(
        source_record_path
            .parent()
            .ok_or_else(|| error("managed_credential_reattestation_source_unavailable"))?,
    )?;
    let source_binding_raw = read_private(
        source_binding_path,
        owner_uid,
        owner_gid,
        "managed_credential_reattestation_source_unavailable",
    )?;
    let source_binding = SourceCompletion::decode(&source_binding_raw)?;
    let source_digest = source_binding.digest()?;
    let source_record_raw = read_private(
        source_record_path,
        100,
        993,
        "managed_credential_reattestation_source_unavailable",
    )?;
    let source_record = decode_record(&source_record_raw)
        .map_err(|_| error("managed_credential_reattestation_source_invalid"))?;
    if !source_completion_matches(
        binding,
        &source_binding,
        &source_digest,
        &source_record,
        &source_record_raw,
    ) {
        return Err(error("managed_credential_reattestation_source_refused"));
    }
    Ok(())
}

/// The original completion binding, classic or Aeon, whose record proves the
/// retained credential was materialized under a reviewed operation.
enum SourceCompletion {
    Classic(ManagedCompletionBindingV2),
    Aeon(ManagedCompletionAeonBindingV1),
}

impl SourceCompletion {
    fn decode(raw: &[u8]) -> Result<Self> {
        let invalid = || error("managed_credential_reattestation_source_invalid");
        if crate::aeon_stage::selects_aeon(raw, AEON_COMPLETION_BINDING_SCHEMA) {
            return crate::paimos::decode_strict(
                raw,
                "managed_credential_reattestation_source_invalid",
            )
            .map(Self::Aeon)
            .map_err(|_| invalid());
        }
        let binding: ManagedCompletionBindingV2 =
            crate::paimos::decode_strict(raw, "managed_credential_reattestation_source_invalid")
                .map_err(|_| invalid())?;
        validate_completion_binding(&binding).map_err(|_| invalid())?;
        Ok(Self::Classic(binding))
    }

    fn digest(&self) -> Result<String> {
        match self {
            Self::Classic(binding) => binding.digest(),
            Self::Aeon(binding) => binding.digest(),
        }
        .map_err(|_| error("managed_credential_reattestation_source_invalid"))
    }

    fn matches_record(&self, record: &crate::paimos_completion::ManagedCompletionRecordV2) -> bool {
        match self {
            Self::Classic(binding) => binding.matches_record(record),
            Self::Aeon(binding) => binding.matches_record(record),
        }
    }

    fn reporter(&self) -> SourceReporter<'_> {
        match self {
            Self::Classic(binding) => SourceReporter::Classic(&binding.reporter),
            Self::Aeon(binding) => SourceReporter::Aeon(&binding.reporter),
        }
    }
}

fn source_completion_matches<R: ReattestationReporter>(
    binding: &ManagedCredentialReattestationBinding<R>,
    source_binding: &SourceCompletion,
    source_digest: &str,
    source_record: &crate::paimos_completion::ManagedCompletionRecordV2,
    source_record_raw: &[u8],
) -> bool {
    source_digest == binding.source_completion_binding_digest
        && wire_sha256(source_record_raw) == binding.source_completion_record_sha256
        && source_binding.matches_record(source_record)
        && binding.reporter.distinct_from(&source_binding.reporter())
        && source_record.host_ref == binding.host_ref
        && source_record.service_ref == binding.service_ref
        && source_record.slot_ref == binding.slot_ref
        && source_record.operation_ref == binding.source_operation_ref
        && source_record.secret_ref == binding.secret_ref
        && source_record.declaration_fingerprint == binding.declaration_fingerprint
        && source_record.generation == binding.generation
        && source_record.revocation_epoch == binding.revocation_epoch
        && source_record.producer_key_id == binding.producer_key_id
}

fn validate_source_record_directory(path: &Path) -> Result<()> {
    validate_source_record_directory_for_owner(path, 100, 993)
}

fn validate_source_record_directory_for_owner(
    path: &Path,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| error("managed_credential_reattestation_source_unavailable"))?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != owner_uid
        || metadata.gid() != owner_gid
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(error("managed_credential_reattestation_source_unavailable"));
    }
    let mut names = Vec::new();
    for entry in fs::read_dir(path)
        .map_err(|_| error("managed_credential_reattestation_source_unavailable"))?
    {
        let entry =
            entry.map_err(|_| error("managed_credential_reattestation_source_unavailable"))?;
        names.push(
            entry
                .file_name()
                .into_string()
                .map_err(|_| error("managed_credential_reattestation_source_unavailable"))?,
        );
    }
    names.sort();
    if names != [".producer.lock", "ready.json"] {
        return Err(error("managed_credential_reattestation_source_unavailable"));
    }
    Ok(())
}

fn validate_host_status<R: ReattestationReporter>(
    status: &HostCredentialAttestationStatusV1,
    binding: &ManagedCredentialReattestationBinding<R>,
) -> Result<()> {
    if status.host_ref != binding.host_ref
        || status.service_ref != binding.service_ref
        || status.slot_ref != binding.slot_ref
        || status.operation_ref != binding.source_operation_ref
        || status.envelope_ref != binding.envelope_ref
        || status.secret_ref != binding.secret_ref
        || status.declaration_fingerprint != binding.declaration_fingerprint
        || status.generation != binding.generation
        || status.revocation_epoch != binding.revocation_epoch
        || status.producer_key_id != binding.producer_key_id
        || status.packet_sha256 != binding.expected_packet_sha256
        || status.material_owner_uid != binding.expected_material_owner_uid
        || status.material_size != binding.expected_material_size
        || status.phase != "active"
        || status.value_returned
    {
        return Err(error("managed_credential_reattestation_host_state_refused"));
    }
    Ok(())
}

fn validate_observation<R: ReattestationReporter>(
    observation: &ManagedCredentialCurrentObservationV1,
    binding: &ManagedCredentialReattestationBinding<R>,
    accepted_at: u64,
) -> Result<()> {
    let oldest = oldest_observation(observation);
    let newest = newest_observation(observation);
    if observation.schema != OBSERVATION_SCHEMA
        || observation.schema_version != 1
        || observation.attestation_ref != binding.attestation_ref
        || observation.observer_config_digest != binding.observer_config_digest
        || observation.host_ref != binding.host_ref
        || observation.service_ref != binding.service_ref
        || observation.slot_ref != binding.slot_ref
        || observation.operation_ref != binding.source_operation_ref
        || observation.generation != binding.generation
        || observation.revocation_epoch != binding.revocation_epoch
        || observation.process.state != "running"
        || observation.process.pid <= 1
        || observation.process.executable_sha256 != binding.expected_process_executable_sha256
        || observation.probe.state != "healthy"
        || !observation.probe.credential_ready
        || observation.probe.pid != observation.process.pid
        || observation.probe.artifact_digest != binding.expected_artifact_digest
        || observation.probe.release_ref != binding.expected_release_ref
        || !valid_runtime_id(&observation.probe.runtime_id)
        || observation.probe.runtime_generation == 0
        || !valid_wire_digest(&observation.probe.runtime_history_sha256)
        || observation.value_returned
        || oldest == 0
        || newest > accepted_at
        || accepted_at.saturating_sub(oldest) > binding.freshness_seconds
        || newest.saturating_sub(oldest) > binding.freshness_seconds
    {
        return Err(error(
            "managed_credential_reattestation_observation_refused",
        ));
    }
    Ok(())
}

fn run_observer<R: ReattestationReporter>(
    binding: &ManagedCredentialReattestationBinding<R>,
    owner_uid: u32,
) -> Result<ManagedCredentialCurrentObservationV1> {
    let path = Path::new(&binding.observer_path);
    let executable = read_executable(path, owner_uid)?;
    if wire_sha256(&executable.raw) != binding.observer_sha256 {
        return Err(error("managed_credential_reattestation_observer_refused"));
    }
    let mut child = Command::new(path)
        .env_clear()
        .env("LANG", "C")
        .env("PATH", "/run/current-system/sw/bin:/usr/bin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| error("managed_credential_reattestation_observer_unavailable"))?;
    let executed = fs::symlink_metadata(path)
        .map_err(|_| error("managed_credential_reattestation_observer_unavailable"))?;
    if executed.dev() != executable.device || executed.ino() != executable.inode {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error("managed_credential_reattestation_observer_refused"));
    }
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| error("managed_credential_reattestation_observer_unavailable"))?;
    let reader = thread::spawn(move || {
        let mut bounded = Vec::new();
        Read::by_ref(&mut stdout)
            .take(MAX_OBSERVER_BYTES as u64 + 1)
            .read_to_end(&mut bounded)?;
        std::io::copy(&mut stdout, &mut std::io::sink())?;
        std::io::Result::Ok(bounded)
    });
    let deadline = Instant::now() + Duration::from_secs(MAX_OBSERVER_SECONDS);
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|_| error("managed_credential_reattestation_observer_unavailable"))?
        {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = reader.join();
            return Err(error(
                "managed_credential_reattestation_observer_unavailable",
            ));
        }
        thread::sleep(Duration::from_millis(20));
    };
    let raw = reader
        .join()
        .map_err(|_| error("managed_credential_reattestation_observer_unavailable"))?
        .map_err(|_| error("managed_credential_reattestation_observer_unavailable"))?;
    if !status.success() || raw.is_empty() || raw.len() > MAX_OBSERVER_BYTES {
        return Err(error("managed_credential_reattestation_observer_refused"));
    }
    crate::paimos::decode_strict(&raw, "managed_credential_reattestation_observation_refused")
        .map_err(|_| error("managed_credential_reattestation_observation_refused"))
}

fn validate_existing_record<R: ReattestationReporter>(
    record: &ManagedCredentialReattestationRecordV1,
    binding: &ManagedCredentialReattestationBinding<R>,
    binding_digest: &str,
) -> Result<()> {
    record.validate()?;
    let tuple = binding.reporter.record_tuple();
    if record.schema != R::RECORD_SCHEMA
        || record.attestation_ref != binding.attestation_ref
        || record.binding_digest != binding_digest
        || record.source_completion_record_sha256 != binding.source_completion_record_sha256
        || record.handoff_id != tuple.handoff_id
        || record.execution_number != tuple.execution_number
        || record.authority_epoch != tuple.authority_epoch
        || record.credential_epoch != tuple.credential_epoch
    {
        return Err(error("managed_credential_reattestation_record_refused"));
    }
    validate_host_status(&record.host_status, binding)?;
    validate_observation(
        &record.observation,
        binding,
        record.evidence_accepted_at_unix_secs,
    )
}

fn oldest_observation(observation: &ManagedCredentialCurrentObservationV1) -> u64 {
    observation
        .heartbeat_observed_at_unix_secs
        .min(observation.process.observed_at_unix_secs)
        .min(observation.probe.observed_at_unix_secs)
}

fn newest_observation(observation: &ManagedCredentialCurrentObservationV1) -> u64 {
    observation
        .heartbeat_observed_at_unix_secs
        .max(observation.process.observed_at_unix_secs)
        .max(observation.probe.observed_at_unix_secs)
}

fn record_hash(record: &ManagedCredentialReattestationRecordV1) -> Result<String> {
    let mut unsigned = record.clone();
    unsigned.integrity_hash.clear();
    let raw = crate::paimos::canonical_json_bytes(&unsigned)
        .map_err(|_| error("managed_credential_reattestation_record_invalid"))?;
    Ok(wire_sha256(&raw))
}

fn decode_private<T: for<'de> Deserialize<'de>>(
    path: &Path,
    owner_uid: u32,
    owner_gid: u32,
    reason: &'static str,
) -> Result<T> {
    let raw = read_private(path, owner_uid, owner_gid, reason)?;
    crate::paimos::decode_strict(&raw, reason).map_err(|_| error(reason))
}

fn read_private(
    path: &Path,
    owner_uid: u32,
    owner_gid: u32,
    reason: &'static str,
) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).map_err(|_| error(reason))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != owner_uid
        || metadata.gid() != owner_gid
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() == 0
        || metadata.len() > MAX_INPUT_BYTES as u64
    {
        return Err(error(reason));
    }
    let mut file = File::open(path).map_err(|_| error(reason))?;
    let opened = file.metadata().map_err(|_| error(reason))?;
    if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
        return Err(error(reason));
    }
    let mut raw = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_INPUT_BYTES as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|_| error(reason))?;
    if raw.is_empty() || raw.len() > MAX_INPUT_BYTES {
        return Err(error(reason));
    }
    Ok(raw)
}

struct CheckedExecutable {
    raw: Vec<u8>,
    device: u64,
    inode: u64,
}

fn read_executable(path: &Path, owner_uid: u32) -> Result<CheckedExecutable> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| error("managed_credential_reattestation_observer_unavailable"))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != owner_uid
        || metadata.nlink() != 1
        || metadata.mode() & 0o222 != 0
        || metadata.mode() & 0o111 == 0
        || metadata.len() == 0
        || metadata.len() > 64 * 1024 * 1024
    {
        return Err(error(
            "managed_credential_reattestation_observer_unavailable",
        ));
    }
    let mut file = File::open(path)
        .map_err(|_| error("managed_credential_reattestation_observer_unavailable"))?;
    let opened = file
        .metadata()
        .map_err(|_| error("managed_credential_reattestation_observer_unavailable"))?;
    if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
        return Err(error(
            "managed_credential_reattestation_observer_unavailable",
        ));
    }
    let mut raw = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut raw)
        .map_err(|_| error("managed_credential_reattestation_observer_unavailable"))?;
    Ok(CheckedExecutable {
        raw,
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn open_lock(path: &Path, owner_uid: u32) -> Result<File> {
    let prior = match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file()
                || metadata.uid() != owner_uid
                || metadata.nlink() != 1
                || metadata.mode() & 0o777 != 0o600
            {
                return Err(error("managed_credential_reattestation_record_unavailable"));
            }
            Some(metadata)
        }
        Err(error_value) if error_value.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err(error("managed_credential_reattestation_record_unavailable")),
    };
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .map_err(|_| error("managed_credential_reattestation_record_unavailable"))?;
    let metadata = file
        .metadata()
        .map_err(|_| error("managed_credential_reattestation_record_unavailable"))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != owner_uid
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
        || prior
            .as_ref()
            .is_some_and(|prior| prior.dev() != metadata.dev() || prior.ino() != metadata.ino())
    {
        return Err(error("managed_credential_reattestation_record_unavailable"));
    }
    Ok(file)
}

fn validate_evidence_directory(path: &Path, owner_uid: u32, owner_gid: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| error("managed_credential_reattestation_record_unavailable"))?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != owner_uid
        || metadata.gid() != owner_gid
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(error("managed_credential_reattestation_record_unavailable"));
    }
    let mut entries = 0usize;
    for entry in fs::read_dir(path)
        .map_err(|_| error("managed_credential_reattestation_record_unavailable"))?
    {
        let entry =
            entry.map_err(|_| error("managed_credential_reattestation_record_unavailable"))?;
        entries += 1;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| error("managed_credential_reattestation_record_unavailable"))?;
        let record_name_valid = name
            .strip_suffix(".json")
            .is_some_and(|reference| valid_ref("reattest_", reference));
        if entries > MAX_DIRECTORY_ENTRIES || (name != ".lock" && !record_name_valid) {
            return Err(error("managed_credential_reattestation_record_unavailable"));
        }
    }
    Ok(())
}

fn write_new_record(
    path: &Path,
    record: &ManagedCredentialReattestationRecordV1,
    owner_uid: u32,
) -> Result<()> {
    let raw = crate::paimos::canonical_json_bytes(record)
        .map_err(|_| error("managed_credential_reattestation_record_invalid"))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| error("managed_credential_reattestation_record_unavailable"))?;
    let metadata = file
        .metadata()
        .map_err(|_| error("managed_credential_reattestation_record_unavailable"))?;
    if metadata.uid() != owner_uid || metadata.nlink() != 1 || metadata.mode() & 0o777 != 0o600 {
        return Err(error("managed_credential_reattestation_record_unavailable"));
    }
    file.write_all(&raw)
        .and_then(|_| file.sync_all())
        .map_err(|_| error("managed_credential_reattestation_record_unavailable"))?;
    let directory = File::open(
        path.parent()
            .ok_or_else(|| error("managed_credential_reattestation_record_unavailable"))?,
    )
    .map_err(|_| error("managed_credential_reattestation_record_unavailable"))?;
    directory
        .sync_all()
        .map_err(|_| error("managed_credential_reattestation_record_unavailable"))
}

fn path_is_present(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error_value) if error_value.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(error("managed_credential_reattestation_state_unavailable")),
    }
}

fn unix_seconds(now: SystemTime) -> Result<u64> {
    now.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| error("managed_credential_reattestation_clock_invalid"))
}

fn wire_sha256(raw: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(raw))
}

fn valid_ref(prefix: &str, value: &str) -> bool {
    value.len() >= prefix.len() + 8
        && value.len() <= 128
        && value.starts_with(prefix)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_runtime_id(value: &str) -> bool {
    if valid_ref("runtime_", value) {
        return true;
    }
    let Some(uuid) = value.strip_prefix("runtime_") else {
        return false;
    };
    uuid.len() == 36
        && uuid.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
            }
        })
}

fn valid_wire_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    })
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

fn absolute_path(value: &str) -> bool {
    let path = PathBuf::from(value);
    path.is_absolute()
        && !value.contains('\0')
        && path.components().all(|component| {
            matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
}

fn error(reason_code: &'static str) -> ManagedCredentialReattestationError {
    ManagedCredentialReattestationError::new(reason_code)
}

#[cfg(feature = "test-support")]
pub mod test_support {
    use super::*;

    pub fn validate_observation_for_test(
        observation: &ManagedCredentialCurrentObservationV1,
        binding: &ManagedCredentialReattestationBindingV1,
        accepted_at: u64,
    ) -> Result<()> {
        binding.validate()?;
        validate_observation(observation, binding, accepted_at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    const GOLDEN_OBSERVATION: &[u8] = include_bytes!(
        "../../../examples/paimos-dependency-reporter/managed-credential-current-observation.golden.json"
    );
    const GOLDEN_BINDING: &[u8] = include_bytes!(
        "../../../examples/paimos-dependency-reporter/managed-credential-reattestation-binding.golden.json"
    );
    const GOLDEN_BINDING_DIGEST: &str =
        "sha256:815aa85115450ac9ad61f914b387cd866c9f8f625177a564608c1f657244428b";

    #[test]
    fn reattestation_binding_digest_matches_cross_language_golden() {
        let binding: ManagedCredentialReattestationBindingV1 = crate::paimos::decode_strict(
            GOLDEN_BINDING,
            "managed_credential_reattestation_binding_invalid",
        )
        .expect("decode golden binding");
        assert_eq!(
            binding.digest().expect("binding digest"),
            GOLDEN_BINDING_DIGEST
        );
    }

    #[test]
    fn observer_golden_is_closed_and_value_free() {
        let observation: ManagedCredentialCurrentObservationV1 = crate::paimos::decode_strict(
            GOLDEN_OBSERVATION,
            "managed_credential_reattestation_observation_refused",
        )
        .expect("decode golden observation");
        assert_eq!(observation.schema, OBSERVATION_SCHEMA);
        assert!(!observation.value_returned);
        assert!(observation.probe.credential_ready);
    }

    fn reporter() -> PaimosManagedCompletionBindingV1 {
        PaimosManagedCompletionBindingV1 {
            schema: "inspr.janus.paimos-managed-completion-reporter-binding.v1".to_string(),
            schema_version: 1,
            config_digest: wire_sha256(b"reporter"),
            handoff_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string(),
            dependency_key: "privileged-handoff".to_string(),
            stage_key: "deployment".to_string(),
            execution_number: 2,
            plan_digest: wire_sha256(b"plan"),
            predecessor_digest: wire_sha256(b"predecessor"),
            authority_epoch: 2,
            context_digest: wire_sha256(b"context"),
            credential_epoch: 1,
            expires_at: "2099-01-01T00:00:00Z".to_string(),
            evidence_kind: "credential_handoff".to_string(),
            evidence_source: "managed_credential_reattestation_record".to_string(),
        }
    }

    fn binding() -> ManagedCredentialReattestationBindingV1 {
        ManagedCredentialReattestationBindingV1 {
            schema: BINDING_SCHEMA.to_string(),
            schema_version: 1,
            attestation_ref: "reattest_0123456789abcdef".to_string(),
            reattestation_operation_ref: "op_1111111111111111".to_string(),
            reattestation_declaration_fingerprint: "decl_1111111111111111".to_string(),
            source_completion_binding_digest: wire_sha256(b"source-binding"),
            source_completion_record_sha256: wire_sha256(b"source-record"),
            host_ref: "host_0123456789abcdef".to_string(),
            service_ref: "svc_0123456789abcdef".to_string(),
            slot_ref: "slot_0123456789abcdef".to_string(),
            source_operation_ref: "op_0123456789abcdef".to_string(),
            envelope_ref: "env_0123456789abcdef".to_string(),
            secret_ref: "sec_fixture0".to_string(),
            declaration_fingerprint: "decl_0123456789abcdef".to_string(),
            generation: 1,
            revocation_epoch: 2,
            producer_key_id: "key_0123456789abcdef".to_string(),
            expected_packet_sha256: wire_sha256(b"packet"),
            expected_material_owner_uid: 100,
            expected_material_size: 48,
            observer_path: "/run/janus-managed-credential-reattestation/observe-current"
                .to_string(),
            observer_sha256: wire_sha256(b"observer"),
            observer_config_digest: wire_sha256(b"observer-config"),
            expected_process_executable_sha256: wire_sha256(b"process"),
            expected_artifact_digest: wire_sha256(b"artifact"),
            expected_release_ref: "release_0123456789abcdef".to_string(),
            freshness_seconds: 120,
            reporter: reporter(),
        }
    }

    fn observation(now: u64) -> ManagedCredentialCurrentObservationV1 {
        let binding = binding();
        ManagedCredentialCurrentObservationV1 {
            schema: OBSERVATION_SCHEMA.to_string(),
            schema_version: 1,
            attestation_ref: binding.attestation_ref,
            observer_config_digest: binding.observer_config_digest,
            host_ref: binding.host_ref,
            service_ref: binding.service_ref,
            slot_ref: binding.slot_ref,
            operation_ref: binding.source_operation_ref,
            generation: binding.generation,
            revocation_epoch: binding.revocation_epoch,
            process: CurrentProcessObservationV1 {
                state: "running".to_string(),
                pid: 42,
                executable_sha256: binding.expected_process_executable_sha256,
                observed_at_unix_secs: now - 2,
            },
            probe: CurrentProbeObservationV1 {
                state: "healthy".to_string(),
                credential_ready: true,
                pid: 42,
                artifact_digest: binding.expected_artifact_digest,
                release_ref: binding.expected_release_ref,
                runtime_id: "runtime_0123456789abcdef".to_string(),
                runtime_generation: 4,
                runtime_history_sha256: wire_sha256(b"history"),
                observed_at_unix_secs: now,
            },
            heartbeat_observed_at_unix_secs: now - 1,
            value_returned: false,
        }
    }

    fn sealed_record(
        binding: &ManagedCredentialReattestationBindingV1,
        binding_digest: String,
        owner_uid: u32,
        now: u64,
    ) -> ManagedCredentialReattestationRecordV1 {
        let mut record = ManagedCredentialReattestationRecordV1 {
            schema: EVIDENCE_SCHEMA.to_string(),
            schema_version: 1,
            attestation_ref: binding.attestation_ref.clone(),
            binding_digest,
            source_completion_record_sha256: binding.source_completion_record_sha256.clone(),
            handoff_id: binding.reporter.handoff_id.clone(),
            execution_number: Some(binding.reporter.execution_number),
            authority_epoch: binding.reporter.authority_epoch,
            credential_epoch: Some(binding.reporter.credential_epoch),
            host_status: HostCredentialAttestationStatusV1 {
                host_ref: binding.host_ref.clone(),
                service_ref: binding.service_ref.clone(),
                slot_ref: binding.slot_ref.clone(),
                operation_ref: binding.source_operation_ref.clone(),
                envelope_ref: binding.envelope_ref.clone(),
                secret_ref: binding.secret_ref.clone(),
                declaration_fingerprint: binding.declaration_fingerprint.clone(),
                generation: binding.generation,
                revocation_epoch: binding.revocation_epoch,
                producer_key_id: binding.producer_key_id.clone(),
                packet_sha256: binding.expected_packet_sha256.clone(),
                material_device: 1,
                material_inode: 2,
                material_size: binding.expected_material_size,
                material_owner_uid: owner_uid,
                phase: "active".to_string(),
                value_returned: false,
            },
            observation: observation(now),
            evidence_accepted_at_unix_secs: now,
            integrity_hash: String::new(),
        };
        record.seal().expect("seal record");
        record
    }

    #[test]
    fn optional_configuration_is_inert_only_when_both_files_are_absent() {
        assert!(!configuration_is_enabled(false, false).expect("both absent"));
        assert!(configuration_is_enabled(true, true).expect("both present"));
        for state in [(true, false), (false, true)] {
            assert_eq!(
                configuration_is_enabled(state.0, state.1)
                    .expect_err("partial configuration refused")
                    .reason_code(),
                "managed_credential_reattestation_configuration_incomplete"
            );
        }
    }

    #[test]
    fn reattestation_binding_refuses_source_operation_identity_aliases() {
        let mut aliased_operation = binding();
        aliased_operation.reattestation_operation_ref =
            aliased_operation.source_operation_ref.clone();
        assert_eq!(
            aliased_operation
                .validate()
                .expect_err("source operation alias refused")
                .reason_code(),
            "managed_credential_reattestation_binding_invalid"
        );

        let mut aliased_declaration = binding();
        aliased_declaration.reattestation_declaration_fingerprint =
            aliased_declaration.declaration_fingerprint.clone();
        assert_eq!(
            aliased_declaration
                .validate()
                .expect_err("source declaration alias refused")
                .reason_code(),
            "managed_credential_reattestation_binding_invalid"
        );
    }

    #[test]
    fn reattestation_reporter_refuses_source_handoff_or_execution_aliases() {
        let reattestation = reporter();
        let mut source = reporter();
        source.handoff_id = "01ARZ3NDEKTSV4RRFFQ69G5FAW".to_string();
        source.execution_number = 1;
        source.evidence_source = "managed_completion_record".to_string();
        assert!(reattestation.distinct_from(&SourceReporter::Classic(&source)));

        source.handoff_id = reattestation.handoff_id.clone();
        assert!(!reattestation.distinct_from(&SourceReporter::Classic(&source)));
        source.handoff_id = "01ARZ3NDEKTSV4RRFFQ69G5FAW".to_string();
        source.execution_number = reattestation.execution_number;
        assert!(!reattestation.distinct_from(&SourceReporter::Classic(&source)));
    }

    #[test]
    fn source_completion_requires_digest_identity_and_closed_ready_directory() {
        use crate::paimos_completion::{AcceptedActivationEvidenceV1, ManagedCompletionRecordV2};

        let mut binding = binding();
        let mut source_reporter = reporter();
        source_reporter.handoff_id = "01ARZ3NDEKTSV4RRFFQ69G5FAW".to_string();
        source_reporter.execution_number = 1;
        source_reporter.evidence_source = "managed_completion_record".to_string();
        let source_binding = ManagedCompletionBindingV2 {
            schema: crate::paimos_completion::BINDING_SCHEMA.to_string(),
            schema_version: 1,
            operation_ref: binding.source_operation_ref.clone(),
            operation_kind: "create".to_string(),
            source: "generated".to_string(),
            host_ref: binding.host_ref.clone(),
            service_ref: binding.service_ref.clone(),
            slot_ref: binding.slot_ref.clone(),
            declaration_fingerprint: binding.declaration_fingerprint.clone(),
            secret_ref: binding.secret_ref.clone(),
            scope_ref: "scp_0123456789abcdef".to_string(),
            generation: binding.generation,
            revocation_epoch: binding.revocation_epoch,
            plan_fingerprint: "a".repeat(64),
            target_fingerprint: "b".repeat(64),
            producer_key_id: binding.producer_key_id.clone(),
            reporter: source_reporter,
        };
        let source_digest = source_binding.digest().expect("source binding digest");
        let mut source_record = ManagedCompletionRecordV2 {
            schema: crate::paimos_completion::RECORD_SCHEMA.to_string(),
            schema_version: 1,
            binding_digest: source_digest.clone(),
            operation_ref: source_binding.operation_ref.clone(),
            operation_id: "webtx_0123456789abcdef".to_string(),
            operation_kind: source_binding.operation_kind.clone(),
            source: source_binding.source.clone(),
            host_ref: source_binding.host_ref.clone(),
            service_ref: source_binding.service_ref.clone(),
            slot_ref: source_binding.slot_ref.clone(),
            declaration_fingerprint: source_binding.declaration_fingerprint.clone(),
            secret_ref: source_binding.secret_ref.clone(),
            scope_ref: source_binding.scope_ref.clone(),
            generation: source_binding.generation,
            revocation_epoch: source_binding.revocation_epoch,
            plan_fingerprint: source_binding.plan_fingerprint.clone(),
            target_fingerprint: source_binding.target_fingerprint.clone(),
            producer_key_id: source_binding.producer_key_id.clone(),
            prepared_at_unix_secs: 1_799_999_995,
            preflighted_at_unix_secs: 1_799_999_990,
            evidence_accepted_at_unix_secs: 1_800_000_000,
            activation_evidence: AcceptedActivationEvidenceV1 {
                generation: binding.generation,
                materialized: true,
                process_state: "running".to_string(),
                probe_state: "healthy".to_string(),
                heartbeat_observed_at_unix_secs: 1_800_000_000,
                process_observed_at_unix_secs: 1_800_000_000,
                probe_observed_at_unix_secs: 1_800_000_000,
            },
            integrity_hash: String::new(),
        };
        source_record.seal().expect("seal source record");
        let source_record_raw =
            crate::paimos::canonical_json_bytes(&source_record).expect("source record bytes");
        binding.source_completion_binding_digest = source_digest.clone();
        binding.source_completion_record_sha256 = wire_sha256(&source_record_raw);
        assert!(source_completion_matches(
            &binding,
            &SourceCompletion::Classic(source_binding.clone()),
            &source_digest,
            &source_record,
            &source_record_raw
        ));

        let mut wrong_digest = binding.clone();
        wrong_digest.source_completion_record_sha256 = wire_sha256(b"other");
        assert!(!source_completion_matches(
            &wrong_digest,
            &SourceCompletion::Classic(source_binding.clone()),
            &source_digest,
            &source_record,
            &source_record_raw
        ));
        let mut aliased_handoff = source_binding.clone();
        aliased_handoff.reporter.handoff_id = binding.reporter.handoff_id.clone();
        assert!(!source_completion_matches(
            &binding,
            &SourceCompletion::Classic(aliased_handoff),
            &source_digest,
            &source_record,
            &source_record_raw
        ));

        let temporary = tempfile::tempdir().expect("source completion directory");
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
            .expect("private source directory");
        File::create(temporary.path().join(".producer.lock")).expect("producer lock");
        File::create(temporary.path().join("ready.json")).expect("ready record");
        let metadata = fs::metadata(temporary.path()).expect("source directory metadata");
        validate_source_record_directory_for_owner(
            temporary.path(),
            metadata.uid(),
            metadata.gid(),
        )
        .expect("closed source directory");
        File::create(temporary.path().join("unexpected.json")).expect("unexpected entry");
        assert_eq!(
            validate_source_record_directory_for_owner(
                temporary.path(),
                metadata.uid(),
                metadata.gid(),
            )
            .expect_err("extra entry refused")
            .reason_code(),
            "managed_credential_reattestation_source_unavailable"
        );
    }

    #[test]
    fn report_retry_reuses_sealed_evidence_after_a_new_live_check() {
        let temporary = tempfile::tempdir().expect("evidence directory");
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
            .expect("private evidence directory");
        let metadata = fs::metadata(temporary.path()).expect("directory metadata");
        let mut binding = binding();
        binding.expected_material_owner_uid = metadata.uid();
        let digest = binding.digest().expect("binding digest");
        let record = sealed_record(&binding, digest.clone(), metadata.uid(), 1_800_000_000);
        let path = temporary.path().join("reattest_0123456789abcdef.json");
        write_new_record(&path, &record, metadata.uid()).expect("create evidence");
        let before = fs::read(&path).expect("read initial evidence");
        let live_checks = Cell::new(0);

        let retained = load_existing_record_for_retry(
            &path,
            &binding,
            &digest,
            metadata.uid(),
            metadata.gid(),
            || {
                live_checks.set(live_checks.get() + 1);
                Ok(())
            },
        )
        .expect("load retry evidence")
        .expect("existing evidence");

        assert_eq!(live_checks.get(), 1);
        assert_eq!(retained.evidence_accepted_at_unix_secs, 1_800_000_000);
        assert_eq!(retained.observation, record.observation);
        assert_eq!(
            retained.observed_at().expect("retained observation"),
            record.observed_at().expect("original observation")
        );
        assert_eq!(fs::read(path).expect("read retained evidence"), before);
    }

    #[test]
    fn current_observation_binds_identity_process_probe_and_freshness() {
        let binding = binding();
        let now = 1_800_000_000;
        validate_observation(&observation(now), &binding, now).expect("valid observation");

        let mut cases = Vec::new();
        let mut changed = observation(now);
        changed.generation += 1;
        cases.push(changed);
        let mut changed = observation(now);
        changed.revocation_epoch += 1;
        cases.push(changed);
        let mut changed = observation(now);
        changed.process.executable_sha256 = wire_sha256(b"other");
        cases.push(changed);
        let mut changed = observation(now);
        changed.probe.pid += 1;
        cases.push(changed);
        let mut changed = observation(now);
        changed.probe.credential_ready = false;
        cases.push(changed);
        let mut changed = observation(now);
        changed.heartbeat_observed_at_unix_secs = now - 121;
        cases.push(changed);
        let mut changed = observation(now);
        changed.probe.observed_at_unix_secs = now + 1;
        cases.push(changed);
        let mut changed = observation(now);
        changed.probe.runtime_history_sha256 = "not-a-digest".to_string();
        cases.push(changed);
        for changed in cases {
            assert_eq!(
                validate_observation(&changed, &binding, now)
                    .expect_err("changed observation refused")
                    .reason_code(),
                "managed_credential_reattestation_observation_refused"
            );
        }
    }

    #[test]
    fn current_observation_accepts_canonical_runtime_uuid_and_rejects_malformed_ids() {
        let binding = binding();
        let now = 1_800_000_000;
        let mut current = observation(now);
        current.probe.runtime_id = "runtime_b9909e64-6df3-4ae7-99b3-b69f3948b40e".to_string();
        validate_observation(&current, &binding, now).expect("canonical runtime UUID");

        for runtime_id in [
            "runtime_b9909e64_6df3-4ae7-99b3-b69f3948b40e",
            "runtime_b9909e64-6df3-4ae7-99b3-b69f3948b40",
            "runtime_b9909e64-6df3-4ae7-99b3-b69f3948b40g",
            "runtime_B9909e64-6df3-4ae7-99b3-b69f3948b40e",
            "runtime_b9909e64-6df3-4ae7-99b3-b69f3948b40e ",
        ] {
            let mut changed = observation(now);
            changed.probe.runtime_id = runtime_id.to_string();
            assert_eq!(
                validate_observation(&changed, &binding, now)
                    .expect_err("malformed runtime ID refused")
                    .reason_code(),
                "managed_credential_reattestation_observation_refused"
            );
        }
    }

    const AEON_COMPLETION_GOLDEN: &[u8] = include_bytes!(
        "../../../examples/aeon-stage-reporter/managed-completion-binding.golden.json"
    );

    fn aeon_completion() -> ManagedCompletionAeonBindingV1 {
        crate::paimos::decode_strict(AEON_COMPLETION_GOLDEN, "fixture").expect("Aeon completion")
    }

    fn aeon_binding() -> ManagedCredentialReattestationAeonBindingV1 {
        let classic = binding();
        let mut reporter = aeon_completion().reporter;
        reporter.handoff_id = "00000000-0000-4000-8000-00000000000a".to_string();
        reporter.authority_epoch = 2;
        reporter.evidence_source = "managed_credential_reattestation_record".to_string();
        ManagedCredentialReattestationBinding {
            schema: AEON_BINDING_SCHEMA.to_string(),
            schema_version: classic.schema_version,
            attestation_ref: classic.attestation_ref,
            reattestation_operation_ref: classic.reattestation_operation_ref,
            reattestation_declaration_fingerprint: classic.reattestation_declaration_fingerprint,
            source_completion_binding_digest: classic.source_completion_binding_digest,
            source_completion_record_sha256: classic.source_completion_record_sha256,
            host_ref: classic.host_ref,
            service_ref: classic.service_ref,
            slot_ref: classic.slot_ref,
            source_operation_ref: classic.source_operation_ref,
            envelope_ref: classic.envelope_ref,
            secret_ref: classic.secret_ref,
            declaration_fingerprint: classic.declaration_fingerprint,
            generation: classic.generation,
            revocation_epoch: classic.revocation_epoch,
            producer_key_id: classic.producer_key_id,
            expected_packet_sha256: classic.expected_packet_sha256,
            expected_material_owner_uid: classic.expected_material_owner_uid,
            expected_material_size: classic.expected_material_size,
            observer_path: classic.observer_path,
            observer_sha256: classic.observer_sha256,
            observer_config_digest: classic.observer_config_digest,
            expected_process_executable_sha256: classic.expected_process_executable_sha256,
            expected_artifact_digest: classic.expected_artifact_digest,
            expected_release_ref: classic.expected_release_ref,
            freshness_seconds: classic.freshness_seconds,
            reporter,
        }
    }

    #[test]
    fn aeon_binding_is_schema_selected_and_needs_the_reattestation_source() {
        let binding = aeon_binding();
        let digest = binding.digest().expect("Aeon binding digest");
        let raw = serde_json::to_vec(&binding).expect("Aeon binding JSON");
        assert!(crate::aeon_stage::selects_aeon(&raw, AEON_BINDING_SCHEMA));
        assert_eq!(
            decode_binding::<AeonManagedCompletionBindingV1>(&raw)
                .expect("Aeon decode")
                .digest()
                .expect("digest"),
            digest
        );
        // Neither schema decodes as the other kind.
        assert!(decode_binding::<PaimosManagedCompletionBindingV1>(&raw).is_err());
        let classic_raw = serde_json::to_vec(&self::binding()).expect("classic JSON");
        assert!(!crate::aeon_stage::selects_aeon(
            &classic_raw,
            AEON_BINDING_SCHEMA
        ));
        assert!(decode_binding::<AeonManagedCompletionBindingV1>(&classic_raw).is_err());

        let mut wrong_schema = binding.clone();
        wrong_schema.schema = BINDING_SCHEMA.to_string();
        assert!(wrong_schema.digest().is_err());
        let mut completion_source = binding.clone();
        completion_source.reporter.evidence_source = "managed_completion_record".to_string();
        assert!(completion_source.digest().is_err());
    }

    #[test]
    fn aeon_record_carries_no_classic_fields_and_binds_its_handoff() {
        let binding = aeon_binding();
        let digest = binding.digest().expect("Aeon binding digest");
        let classic = sealed_record(&self::binding(), digest.clone(), 100, 1_800_000_000);
        let record = build_record(
            &binding,
            &digest,
            classic.host_status.clone(),
            classic.host_status.clone(),
            classic.observation.clone(),
            classic.evidence_accepted_at_unix_secs,
        )
        .expect("Aeon record");
        assert_eq!(record.schema, AEON_EVIDENCE_SCHEMA);
        assert_eq!(record.handoff_id, binding.reporter.handoff_id);
        assert_eq!(record.execution_number, None);
        assert_eq!(record.credential_epoch, None);
        let rendered = serde_json::to_string(&record).expect("record JSON");
        assert!(!rendered.contains("execution_number") && !rendered.contains("credential_epoch"));
        validate_existing_record(&record, &binding, &digest).expect("Aeon record validates");

        // A classic record is never accepted for an Aeon binding, and the
        // Aeon record shape refuses classic fields.
        assert!(validate_existing_record(&classic, &binding, &digest).is_err());
        let mut mixed = record.clone();
        mixed.execution_number = Some(1);
        assert!(mixed.seal().is_err());
        let mut classic_handoff = record;
        classic_handoff.handoff_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string();
        assert!(classic_handoff.seal().is_err());
    }

    #[test]
    fn aeon_reattestation_must_name_a_new_attempt() {
        let aeon = aeon_binding().reporter;
        let classic = reporter();
        let mut source = aeon_completion().reporter;
        // Classic source to Aeon retry is a new handoff by construction.
        assert!(aeon.distinct_from(&SourceReporter::Classic(&classic)));
        // A classic retry of an Aeon completion is refused.
        assert!(!classic.distinct_from(&SourceReporter::Aeon(&source)));

        source.authority_epoch = 1;
        assert!(aeon.distinct_from(&SourceReporter::Aeon(&source)));
        let mut same_handoff = source.clone();
        same_handoff.handoff_id = aeon.handoff_id.clone();
        assert!(!aeon.distinct_from(&SourceReporter::Aeon(&same_handoff)));
        let mut same_attempt = source;
        same_attempt.authority_epoch = aeon.authority_epoch;
        assert!(!aeon.distinct_from(&SourceReporter::Aeon(&same_attempt)));
    }

    #[test]
    fn source_completion_accepts_an_aeon_original() {
        let source = SourceCompletion::decode(AEON_COMPLETION_GOLDEN).expect("Aeon source");
        assert!(matches!(source, SourceCompletion::Aeon(_)));
        assert_eq!(
            source.digest().expect("source digest"),
            aeon_completion().digest().expect("completion digest")
        );
    }

    #[test]
    fn record_is_append_only_bound_to_new_handoff_and_rejects_mutation() {
        let binding = binding();
        let digest = binding.digest().expect("binding digest");
        let mut record = ManagedCredentialReattestationRecordV1 {
            schema: EVIDENCE_SCHEMA.to_string(),
            schema_version: 1,
            attestation_ref: binding.attestation_ref.clone(),
            binding_digest: digest.clone(),
            source_completion_record_sha256: binding.source_completion_record_sha256.clone(),
            handoff_id: binding.reporter.handoff_id.clone(),
            execution_number: Some(binding.reporter.execution_number),
            authority_epoch: binding.reporter.authority_epoch,
            credential_epoch: Some(binding.reporter.credential_epoch),
            host_status: HostCredentialAttestationStatusV1 {
                host_ref: binding.host_ref.clone(),
                service_ref: binding.service_ref.clone(),
                slot_ref: binding.slot_ref.clone(),
                operation_ref: binding.source_operation_ref.clone(),
                envelope_ref: binding.envelope_ref.clone(),
                secret_ref: binding.secret_ref.clone(),
                declaration_fingerprint: binding.declaration_fingerprint.clone(),
                generation: binding.generation,
                revocation_epoch: binding.revocation_epoch,
                producer_key_id: binding.producer_key_id.clone(),
                packet_sha256: wire_sha256(b"packet"),
                material_device: 1,
                material_inode: 2,
                material_size: 48,
                material_owner_uid: 100,
                phase: "active".to_string(),
                value_returned: false,
            },
            observation: observation(1_800_000_000),
            evidence_accepted_at_unix_secs: 1_800_000_000,
            integrity_hash: String::new(),
        };
        record.seal().expect("seal record");
        validate_existing_record(&record, &binding, &digest).expect("validate record");
        let mut changed_host = record.host_status.clone();
        changed_host.material_inode += 1;
        assert_eq!(
            build_record(
                &binding,
                &digest,
                record.host_status.clone(),
                changed_host,
                record.observation.clone(),
                record.evidence_accepted_at_unix_secs,
            )
            .expect_err("host change refused")
            .reason_code(),
            "managed_credential_reattestation_host_state_changed"
        );
        record.observation.probe.runtime_generation += 1;
        assert_eq!(
            record
                .validate()
                .expect_err("mutation refused")
                .reason_code(),
            "managed_credential_reattestation_record_invalid"
        );
    }

    #[test]
    fn evidence_record_creation_is_exclusive_and_preserves_first_bytes() {
        let temporary = tempfile::tempdir().expect("evidence directory");
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))
            .expect("private evidence directory");
        let metadata = fs::metadata(temporary.path()).expect("directory metadata");
        let binding = binding();
        let digest = binding.digest().expect("binding digest");
        let mut record = ManagedCredentialReattestationRecordV1 {
            schema: EVIDENCE_SCHEMA.to_string(),
            schema_version: 1,
            attestation_ref: binding.attestation_ref.clone(),
            binding_digest: digest,
            source_completion_record_sha256: binding.source_completion_record_sha256.clone(),
            handoff_id: binding.reporter.handoff_id.clone(),
            execution_number: Some(binding.reporter.execution_number),
            authority_epoch: binding.reporter.authority_epoch,
            credential_epoch: Some(binding.reporter.credential_epoch),
            host_status: HostCredentialAttestationStatusV1 {
                host_ref: binding.host_ref.clone(),
                service_ref: binding.service_ref.clone(),
                slot_ref: binding.slot_ref.clone(),
                operation_ref: binding.source_operation_ref.clone(),
                envelope_ref: binding.envelope_ref.clone(),
                secret_ref: binding.secret_ref.clone(),
                declaration_fingerprint: binding.declaration_fingerprint.clone(),
                generation: binding.generation,
                revocation_epoch: binding.revocation_epoch,
                producer_key_id: binding.producer_key_id.clone(),
                packet_sha256: binding.expected_packet_sha256.clone(),
                material_device: 1,
                material_inode: 2,
                material_size: 48,
                material_owner_uid: metadata.uid(),
                phase: "active".to_string(),
                value_returned: false,
            },
            observation: observation(1_800_000_000),
            evidence_accepted_at_unix_secs: 1_800_000_000,
            integrity_hash: String::new(),
        };
        record.seal().expect("seal record");
        let path = temporary.path().join("reattest_0123456789abcdef.json");
        write_new_record(&path, &record, metadata.uid()).expect("create evidence");
        let first = fs::read(&path).expect("read first evidence");
        assert_eq!(
            write_new_record(&path, &record, metadata.uid())
                .expect_err("second create refused")
                .reason_code(),
            "managed_credential_reattestation_record_unavailable"
        );
        assert_eq!(fs::read(path).expect("read retained evidence"), first);
    }

    #[test]
    fn completion_reporter_cannot_relabel_rettestation_evidence() {
        let binding = binding();
        let mut old = serde_json::json!({
            "schema": crate::paimos_completion::BINDING_SCHEMA,
            "schema_version": 1,
            "operation_ref": binding.source_operation_ref,
            "operation_kind": "create",
            "source": "generated",
            "host_ref": binding.host_ref,
            "service_ref": binding.service_ref,
            "slot_ref": binding.slot_ref,
            "declaration_fingerprint": binding.declaration_fingerprint,
            "secret_ref": binding.secret_ref,
            "scope_ref": "scp_0123456789abcdef",
            "generation": binding.generation,
            "revocation_epoch": binding.revocation_epoch,
            "plan_fingerprint": "a".repeat(64),
            "target_fingerprint": "b".repeat(64),
            "producer_key_id": "key_0123456789abcdef",
            "reporter": binding.reporter,
        });
        let parsed: ManagedCompletionBindingV2 = serde_json::from_value(old.take()).expect("shape");
        assert!(validate_completion_binding(&parsed).is_err());
    }
}
