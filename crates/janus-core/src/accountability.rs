//! Runtime-wide authenticated accountability posture and surface coverage.
//!
//! This module is the closed contract between the registered runtime catalog,
//! the local kernel-peer broker, and policy. Callers can carry a signed domain
//! state reference, but they cannot choose an actor, duty, transport, or
//! authority posture.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    runtime_endpoint_catalog_fingerprint, runtime_endpoint_policy, ActorSubjectRef, ConflictDomain,
    Duty, JanusError, JanusResult, Permission, RuntimeAction, RuntimeTransport, ScopeRef,
    SeparationPolicy,
};

pub const DUTY_SURFACE_MANIFEST_SCHEMA: u8 = 1;
pub const RUNTIME_ADMISSION_SCHEMA: u8 = 1;
pub const ACCOUNTABILITY_CUTOVER_SCHEMA: u8 = 1;
pub const MAX_RUNTIME_ADMISSION_TTL_SECS: u64 = 300;

const MAX_MANIFEST_BYTES: usize = 128 * 1024;
const MAX_TEXT_BYTES: usize = 512;

/// Explicit deployment posture. Parsing never defaults or falls back.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AccountabilityPosture {
    AccountabilityLegacy,
    AuthenticatedObserve,
    EnforcedRecorded,
}

impl AccountabilityPosture {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccountabilityLegacy => "accountability_legacy",
            Self::AuthenticatedObserve => "authenticated_observe",
            Self::EnforcedRecorded => "enforced_recorded",
        }
    }

    pub fn parse(value: &str) -> JanusResult<Self> {
        match value {
            "accountability_legacy" => Ok(Self::AccountabilityLegacy),
            "authenticated_observe" => Ok(Self::AuthenticatedObserve),
            "enforced_recorded" => Ok(Self::EnforcedRecorded),
            _ => Err(accountability_error(
                "accountability_posture_invalid",
                "accountability posture is missing or unsupported",
            )),
        }
    }

    pub const fn requires_verified_journal(self) -> bool {
        !matches!(self, Self::AccountabilityLegacy)
    }

    pub const fn denies_conflicts(self) -> bool {
        matches!(self, Self::EnforcedRecorded)
    }
}

/// Closed classification for one registered runtime action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeDutyClassification {
    NoConflict,
    Recorded {
        allowed: BTreeSet<(ConflictDomain, Duty)>,
    },
}

impl RuntimeDutyClassification {
    pub fn permits(&self, domain: ConflictDomain, duty: Duty) -> bool {
        match self {
            Self::NoConflict => false,
            Self::Recorded { allowed } => allowed.contains(&(domain, duty)),
        }
    }

    pub const fn kind(&self) -> &'static str {
        match self {
            Self::NoConflict => "no_conflict",
            Self::Recorded { .. } => "recorded",
        }
    }

    pub fn allowed(&self) -> impl Iterator<Item = (ConflictDomain, Duty)> + '_ {
        match self {
            Self::NoConflict => EitherDutyIter::Empty(std::iter::empty()),
            Self::Recorded { allowed } => EitherDutyIter::Recorded(allowed.iter().copied()),
        }
    }
}

enum EitherDutyIter<'a> {
    Empty(std::iter::Empty<(ConflictDomain, Duty)>),
    Recorded(std::iter::Copied<std::collections::btree_set::Iter<'a, (ConflictDomain, Duty)>>),
}

impl Iterator for EitherDutyIter<'_> {
    type Item = (ConflictDomain, Duty);

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Empty(iter) => iter.next(),
            Self::Recorded(iter) => iter.next(),
        }
    }
}

/// Exact reviewed action/transport/trust-adapter/duty entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeDutyPolicy {
    action: RuntimeAction,
    surface: String,
    transport: RuntimeTransport,
    classification: RuntimeDutyClassification,
}

impl RuntimeDutyPolicy {
    pub const fn action(&self) -> RuntimeAction {
        self.action
    }

    pub fn surface(&self) -> &str {
        &self.surface
    }

    pub const fn transport(&self) -> RuntimeTransport {
        self.transport
    }

    pub fn classification(&self) -> &RuntimeDutyClassification {
        &self.classification
    }
}

/// Closed release-reviewed coverage of every registered runtime action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DutySurfaceManifestV1 {
    identity_manifest_fingerprint: String,
    authority_service: String,
    policies: Vec<RuntimeDutyPolicy>,
    fingerprint: String,
}

impl DutySurfaceManifestV1 {
    pub fn parse_json(text: &str) -> JanusResult<Self> {
        if text.is_empty() || text.len() > MAX_MANIFEST_BYTES {
            return Err(accountability_error(
                "duty_surface_manifest_invalid",
                "duty surface manifest size is invalid",
            ));
        }
        let wire: DutySurfaceManifestWire = serde_json::from_str(text).map_err(|_| {
            accountability_error(
                "duty_surface_manifest_invalid",
                "duty surface manifest is malformed",
            )
        })?;
        if wire.schema_version != DUTY_SURFACE_MANIFEST_SCHEMA
            || wire.runtime_endpoint_catalog_fingerprint != runtime_endpoint_catalog_fingerprint()
            || !valid_sha256(&wire.identity_transport_manifest_fingerprint)
            || wire.authority_service != "janusd-identityd"
            || !wire.remote_authorizing_transports.is_empty()
        {
            return Err(accountability_error(
                "duty_surface_manifest_mismatch",
                "duty surface manifest does not match the registered local runtime",
            ));
        }

        let mut seen = BTreeSet::new();
        let mut covered_conflict_duties = BTreeSet::new();
        let mut policies = Vec::with_capacity(wire.actions.len());
        for entry in wire.actions {
            let action = RuntimeAction::parse(&entry.action)?;
            if !seen.insert(action.as_str())
                || entry.surface != runtime_surface(action)
                || entry.transport != runtime_endpoint_policy(action).transport.as_str()
            {
                return Err(accountability_error(
                    "duty_surface_manifest_entry_mismatch",
                    "duty surface entry is duplicate or context mismatched",
                ));
            }
            let classification = match entry.classification.as_str() {
                "no_conflict" if entry.allowed_duties.is_empty() => {
                    RuntimeDutyClassification::NoConflict
                }
                "recorded" if !entry.allowed_duties.is_empty() => {
                    let mut allowed = BTreeSet::new();
                    for pair in entry.allowed_duties {
                        if !pair.conflict_domain.permits(pair.duty)
                            || !allowed.insert((pair.conflict_domain, pair.duty))
                        {
                            return Err(accountability_error(
                                "duty_surface_manifest_entry_invalid",
                                "recorded duty classification is invalid or duplicated",
                            ));
                        }
                        covered_conflict_duties.insert(pair.duty);
                    }
                    RuntimeDutyClassification::Recorded { allowed }
                }
                _ => {
                    return Err(accountability_error(
                        "duty_surface_manifest_entry_invalid",
                        "duty surface classification is not closed",
                    ))
                }
            };
            policies.push(RuntimeDutyPolicy {
                action,
                surface: entry.surface,
                transport: runtime_endpoint_policy(action).transport,
                classification,
            });
        }
        if seen.len() != RuntimeAction::ALL.len()
            || RuntimeAction::ALL
                .iter()
                .any(|action| !seen.contains(action.as_str()))
        {
            return Err(accountability_error(
                "duty_surface_manifest_incomplete",
                "every registered runtime action requires one exact duty classification",
            ));
        }
        for conflict in SeparationPolicy::default().conflicts() {
            if !covered_conflict_duties.contains(&conflict.left)
                || !covered_conflict_duties.contains(&conflict.right)
            {
                return Err(accountability_error(
                    "duty_surface_manifest_conflict_incomplete",
                    "surface coverage does not expose every compiled conflict duty",
                ));
            }
        }
        policies.sort_by_key(|policy| policy.action.as_str());
        Ok(Self {
            identity_manifest_fingerprint: wire.identity_transport_manifest_fingerprint,
            authority_service: wire.authority_service,
            policies,
            fingerprint: fingerprint("janus-duty-surface-manifest-v1", text.as_bytes()),
        })
    }

    pub fn policy(&self, action: RuntimeAction) -> JanusResult<&RuntimeDutyPolicy> {
        self.policies
            .iter()
            .find(|policy| policy.action == action)
            .ok_or_else(|| {
                accountability_error(
                    "duty_surface_unknown",
                    "runtime action has no reviewed duty classification",
                )
            })
    }

    pub fn policies(&self) -> &[RuntimeDutyPolicy] {
        &self.policies
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn identity_manifest_fingerprint(&self) -> &str {
        &self.identity_manifest_fingerprint
    }

    pub fn authority_service(&self) -> &str {
        &self.authority_service
    }
}

/// Reviewed cutover evidence. Legacy active authority is never imported.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountabilityCutoverV1 {
    release_digest: String,
    scope_ref: ScopeRef,
    surface_manifest_fingerprint: String,
    identity_migration_fingerprint: String,
    active_legacy_operations: u64,
    enrolled_subjects: u64,
    backup_fingerprint: String,
    restore_rehearsal_fingerprint: String,
    observation_window_fingerprint: String,
    open_trust_root_recovery: bool,
    rollback_actor_schema: u8,
    rollback_duty_schema: u8,
}

impl AccountabilityCutoverV1 {
    pub fn parse_json(text: &str) -> JanusResult<Self> {
        let wire: AccountabilityCutoverWire = serde_json::from_str(text).map_err(|_| {
            accountability_error(
                "accountability_cutover_invalid",
                "accountability cutover evidence is malformed",
            )
        })?;
        let scope_ref = ScopeRef::from_opaque(wire.scope_ref)?;
        if wire.schema_version != ACCOUNTABILITY_CUTOVER_SCHEMA
            || !valid_sha256(&wire.release_digest)
            || !valid_sha256(&wire.surface_manifest_fingerprint)
            || !valid_sha256(&wire.identity_migration_fingerprint)
            || !valid_sha256(&wire.backup_fingerprint)
            || !valid_sha256(&wire.restore_rehearsal_fingerprint)
            || !valid_sha256(&wire.observation_window_fingerprint)
            || wire.rollback_actor_schema == 0
            || wire.rollback_duty_schema == 0
        {
            return Err(accountability_error(
                "accountability_cutover_invalid",
                "accountability cutover evidence fields are invalid",
            ));
        }
        Ok(Self {
            release_digest: wire.release_digest,
            scope_ref,
            surface_manifest_fingerprint: wire.surface_manifest_fingerprint,
            identity_migration_fingerprint: wire.identity_migration_fingerprint,
            active_legacy_operations: wire.active_legacy_operations,
            enrolled_subjects: wire.enrolled_subjects,
            backup_fingerprint: wire.backup_fingerprint,
            restore_rehearsal_fingerprint: wire.restore_rehearsal_fingerprint,
            observation_window_fingerprint: wire.observation_window_fingerprint,
            open_trust_root_recovery: wire.open_trust_root_recovery,
            rollback_actor_schema: wire.rollback_actor_schema,
            rollback_duty_schema: wire.rollback_duty_schema,
        })
    }

    pub fn enforce_ready(
        &self,
        expected_release: &str,
        expected_scope: &ScopeRef,
        expected_surface_manifest: &str,
    ) -> JanusResult<()> {
        if self.release_digest != expected_release
            || &self.scope_ref != expected_scope
            || self.surface_manifest_fingerprint != expected_surface_manifest
            || self.active_legacy_operations != 0
            || self.enrolled_subjects < 2
            || self.open_trust_root_recovery
            || self.rollback_actor_schema < 1
            || self.rollback_duty_schema < 1
        {
            return Err(accountability_error(
                "enforced_recorded_not_ready",
                "enforced recorded cutover prerequisites are incomplete",
            ));
        }
        Ok(())
    }

    pub fn active_legacy_operations(&self) -> u64 {
        self.active_legacy_operations
    }

    pub fn enrolled_subjects(&self) -> u64 {
        self.enrolled_subjects
    }

    pub fn identity_migration_fingerprint(&self) -> &str {
        &self.identity_migration_fingerprint
    }

    pub fn recovery_fingerprints(&self) -> (&str, &str, &str) {
        (
            &self.backup_fingerprint,
            &self.restore_rehearsal_fingerprint,
            &self.observation_window_fingerprint,
        )
    }
}

/// Signed value-free broker admission returned to one runtime action.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAdmissionV1 {
    pub schema_version: u8,
    pub admission_id: String,
    pub actor_subject_ref: String,
    pub scope_ref: String,
    pub surface: String,
    pub transport: String,
    pub action: String,
    pub classification: String,
    pub conflict_domain: Option<ConflictDomain>,
    pub operation_ref: Option<String>,
    pub duty: Option<Duty>,
    pub posture: String,
    pub journal_sequence: u64,
    pub journal_head_hash: String,
    pub audit_ref: String,
    pub issued_at_unix_secs: u64,
    pub expires_at_unix_secs: u64,
    pub audience_fingerprint: String,
    pub release_digest: String,
    pub authority: String,
    pub value_returned: bool,
    pub signature: String,
}

impl RuntimeAdmissionV1 {
    pub fn signing_bytes(&self) -> JanusResult<Vec<u8>> {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        serde_json::to_vec(&unsigned).map_err(|_| unavailable("runtime admission encoding failed"))
    }

    pub fn validate_shape(&self) -> JanusResult<()> {
        let posture = AccountabilityPosture::parse(&self.posture)?;
        let action = RuntimeAction::parse(&self.action)?;
        let classification_valid = match self.classification.as_str() {
            "legacy" => {
                posture == AccountabilityPosture::AccountabilityLegacy
                    && self.conflict_domain.is_none()
                    && self.operation_ref.is_none()
                    && self.duty.is_none()
            }
            "no_conflict" => {
                self.conflict_domain.is_none()
                    && self.operation_ref.is_none()
                    && self.duty.is_none()
            }
            "recorded" => self
                .conflict_domain
                .zip(self.duty)
                .is_some_and(|(domain, duty)| {
                    domain.permits(duty)
                        && self
                            .operation_ref
                            .as_deref()
                            .is_some_and(valid_operation_ref)
                }),
            _ => false,
        };
        let authority_valid = match posture {
            AccountabilityPosture::AccountabilityLegacy => {
                self.authority == "accountability_legacy"
            }
            AccountabilityPosture::AuthenticatedObserve => {
                self.authority == "durable_duty_observation"
            }
            AccountabilityPosture::EnforcedRecorded => self.authority == "durable_duty_admission",
        };
        if self.schema_version != RUNTIME_ADMISSION_SCHEMA
            || !valid_prefixed_hex(&self.admission_id, "adm_", 24)
            || ActorSubjectRef::from_opaque(self.actor_subject_ref.clone()).is_err()
            || ScopeRef::from_opaque(self.scope_ref.clone()).is_err()
            || self.surface != runtime_surface(action)
            || self.transport != runtime_endpoint_policy(action).transport.as_str()
            || !classification_valid
            || !valid_sha256(&self.journal_head_hash)
            || !valid_prefixed_hex(&self.audit_ref, "aud_", 24)
            || self.expires_at_unix_secs <= self.issued_at_unix_secs
            || self.expires_at_unix_secs - self.issued_at_unix_secs > MAX_RUNTIME_ADMISSION_TTL_SECS
            || !valid_sha256(&self.audience_fingerprint)
            || !valid_sha256(&self.release_digest)
            || !authority_valid
            || self.value_returned
            || !valid_signature(&self.signature)
        {
            return Err(accountability_error(
                "runtime_admission_invalid",
                "runtime admission is malformed or authority mismatched",
            ));
        }
        Ok(())
    }
}

/// Opaque verified admission accepted by policy. Callers cannot construct it.
#[derive(Clone)]
pub struct VerifiedRuntimeAdmission {
    action: RuntimeAction,
    actor: ActorSubjectRef,
    scope: ScopeRef,
    posture: AccountabilityPosture,
    operation_ref: Option<String>,
    duty: Option<Duty>,
    expires_at_unix_secs: u64,
}

impl fmt::Debug for VerifiedRuntimeAdmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedRuntimeAdmission")
            .field("action", &self.action)
            .field("actor", &self.actor)
            .field("scope", &self.scope)
            .field("posture", &self.posture)
            .field("operation_ref", &self.operation_ref)
            .field("duty", &self.duty)
            .finish_non_exhaustive()
    }
}

impl VerifiedRuntimeAdmission {
    pub const fn action(&self) -> RuntimeAction {
        self.action
    }

    pub fn actor(&self) -> &ActorSubjectRef {
        &self.actor
    }

    pub fn scope(&self) -> &ScopeRef {
        &self.scope
    }

    pub const fn posture(&self) -> AccountabilityPosture {
        self.posture
    }

    pub fn authorizes(&self, permission: Permission, scope: &ScopeRef) -> bool {
        Permission::for_runtime_action(self.action) == permission && &self.scope == scope
    }

    pub fn is_fresh_at(&self, now: SystemTime) -> bool {
        unix_secs(now).is_ok_and(|seconds| seconds < self.expires_at_unix_secs)
    }

    #[cfg(test)]
    pub(crate) fn fixture(action: RuntimeAction, scope: ScopeRef) -> Self {
        Self {
            action,
            actor: ActorSubjectRef::derive(crate::TrustAdapterKind::LocalPeer, "test", "actor")
                .expect("fixture actor"),
            scope,
            posture: AccountabilityPosture::EnforcedRecorded,
            operation_ref: None,
            duty: None,
            expires_at_unix_secs: u64::MAX,
        }
    }
}

/// Signature/context/replay verifier for broker admissions.
pub struct RuntimeAdmissionVerifier {
    manifest: DutySurfaceManifestV1,
    verifying_key: VerifyingKey,
    audience_fingerprint: String,
    release_digest: String,
    consumed: BTreeMap<String, u64>,
}

impl RuntimeAdmissionVerifier {
    pub fn new(
        manifest: DutySurfaceManifestV1,
        verifying_key: VerifyingKey,
        audience: &str,
        release_digest: &str,
    ) -> JanusResult<Self> {
        validate_text("runtime_admission_audience", audience)?;
        if !valid_sha256(release_digest) {
            return Err(accountability_error(
                "runtime_admission_verifier_invalid",
                "runtime admission verifier release is invalid",
            ));
        }
        Ok(Self {
            manifest,
            verifying_key,
            audience_fingerprint: fingerprint(
                "janus-runtime-admission-audience-v1",
                audience.as_bytes(),
            ),
            release_digest: release_digest.to_string(),
            consumed: BTreeMap::new(),
        })
    }

    pub fn verify_once(
        &mut self,
        admission: &RuntimeAdmissionV1,
        expected_action: RuntimeAction,
        now: SystemTime,
    ) -> JanusResult<VerifiedRuntimeAdmission> {
        admission.validate_shape()?;
        let seconds = unix_secs(now)?;
        self.consumed.retain(|_, expiry| *expiry > seconds);
        let action = RuntimeAction::parse(&admission.action)?;
        let policy = self.manifest.policy(action)?;
        let posture = AccountabilityPosture::parse(&admission.posture)?;
        let classification_matches = if posture == AccountabilityPosture::AccountabilityLegacy {
            admission.classification == "legacy"
        } else {
            admission.classification == policy.classification.kind()
        };
        if action != expected_action
            || admission.surface != policy.surface
            || admission.transport != policy.transport.as_str()
            || !classification_matches
            || admission.audience_fingerprint != self.audience_fingerprint
            || admission.release_digest != self.release_digest
            || seconds < admission.issued_at_unix_secs
            || seconds >= admission.expires_at_unix_secs
            || self.consumed.contains_key(&admission.admission_id)
            || self.consumed.len() >= 65_536
        {
            return Err(accountability_error(
                "runtime_admission_context_mismatch",
                "runtime admission is stale, replayed, or context mismatched",
            ));
        }
        match (
            posture,
            &policy.classification,
            admission.conflict_domain,
            admission.duty,
        ) {
            (AccountabilityPosture::AccountabilityLegacy, _, None, None) => {}
            (_, RuntimeDutyClassification::NoConflict, None, None) => {}
            (_, classification, Some(domain), Some(duty))
                if classification.permits(domain, duty) => {}
            _ => {
                return Err(accountability_error(
                    "runtime_admission_duty_mismatch",
                    "runtime admission duty is not release-reviewed for the action",
                ))
            }
        }
        let signature_bytes = hex::decode(&admission.signature).map_err(|_| {
            accountability_error(
                "runtime_admission_signature_invalid",
                "runtime admission signature is invalid",
            )
        })?;
        let signature = Signature::from_slice(&signature_bytes).map_err(|_| {
            accountability_error(
                "runtime_admission_signature_invalid",
                "runtime admission signature is invalid",
            )
        })?;
        self.verifying_key
            .verify(&admission.signing_bytes()?, &signature)
            .map_err(|_| {
                accountability_error(
                    "runtime_admission_signature_invalid",
                    "runtime admission signature is invalid",
                )
            })?;
        self.consumed.insert(
            admission.admission_id.clone(),
            admission.expires_at_unix_secs,
        );
        Ok(VerifiedRuntimeAdmission {
            action,
            actor: ActorSubjectRef::from_opaque(admission.actor_subject_ref.clone())?,
            scope: ScopeRef::from_opaque(admission.scope_ref.clone())?,
            posture: AccountabilityPosture::parse(&admission.posture)?,
            operation_ref: admission.operation_ref.clone(),
            duty: admission.duty,
            expires_at_unix_secs: admission.expires_at_unix_secs,
        })
    }
}

pub const fn runtime_surface(action: RuntimeAction) -> &'static str {
    match action {
        RuntimeAction::WardenListSecrets
        | RuntimeAction::WardenDescribeSecret
        | RuntimeAction::WardenRequestUse
        | RuntimeAction::WardenHealth => "janus-warden",
        RuntimeAction::ManagedRunPreflight
        | RuntimeAction::ManagedRun
        | RuntimeAction::EnvFilePreflight
        | RuntimeAction::EnvFile => "janusd-use",
        RuntimeAction::WebTransaction => "janusd-web-transactiond",
        RuntimeAction::DynamicCustody => "janusd-dynamic-custodyd",
        RuntimeAction::DynamicDelivery => "janusd-dynamic-deliveryd",
        RuntimeAction::DynamicTransport => "janusd-dynamic-transportd",
        _ => "janusd-admin",
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DutySurfaceManifestWire {
    schema_version: u8,
    runtime_endpoint_catalog_fingerprint: String,
    identity_transport_manifest_fingerprint: String,
    authority_service: String,
    remote_authorizing_transports: Vec<String>,
    actions: Vec<DutySurfaceActionWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DutySurfaceActionWire {
    action: String,
    surface: String,
    transport: String,
    classification: String,
    allowed_duties: Vec<DutyPairWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DutyPairWire {
    conflict_domain: ConflictDomain,
    duty: Duty,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountabilityCutoverWire {
    schema_version: u8,
    release_digest: String,
    scope_ref: String,
    surface_manifest_fingerprint: String,
    identity_migration_fingerprint: String,
    active_legacy_operations: u64,
    enrolled_subjects: u64,
    backup_fingerprint: String,
    restore_rehearsal_fingerprint: String,
    observation_window_fingerprint: String,
    open_trust_root_recovery: bool,
    rollback_actor_schema: u8,
    rollback_duty_schema: u8,
}

fn validate_text(kind: &'static str, value: &str) -> JanusResult<()> {
    if value.is_empty()
        || value.trim().len() != value.len()
        || value.len() > MAX_TEXT_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(JanusError::InvalidIdentifier { kind });
    }
    Ok(())
}

fn valid_operation_ref(value: &str) -> bool {
    valid_prefixed_hex(value, "opr_", 32)
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

fn valid_signature(value: &str) -> bool {
    value.len() == 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn fingerprint(domain: &str, bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain.as_bytes());
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn unix_secs(time: SystemTime) -> JanusResult<u64> {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| unavailable("runtime admission time is invalid"))
}

fn accountability_error(reason_code: &'static str, detail: &'static str) -> JanusError {
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
    use crate::test_scope;
    use serde_json::json;

    const RELEASE: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn reviewed_manifest_covers_every_action_transport_and_conflict() {
        let manifest = DutySurfaceManifestV1::parse_json(include_str!(
            "../../../config/authorization/duty-surface-manifest-v1.json"
        ))
        .unwrap();
        assert_eq!(manifest.policies().len(), RuntimeAction::ALL.len());
        for action in RuntimeAction::ALL {
            let policy = manifest.policy(action).unwrap();
            assert_eq!(policy.surface(), runtime_surface(action));
            assert_eq!(
                policy.transport(),
                runtime_endpoint_policy(action).transport
            );
        }
        let admission =
            VerifiedRuntimeAdmission::fixture(RuntimeAction::WardenHealth, test_scope("dev"));
        assert!(admission.authorizes(Permission::HealthRead, &test_scope("dev")));
        assert!(!admission.authorizes(Permission::SecretUse, &test_scope("dev")));
    }

    #[test]
    fn cutover_rejects_legacy_work_solo_recovery_and_context_drift() {
        let manifest = DutySurfaceManifestV1::parse_json(include_str!(
            "../../../config/authorization/duty-surface-manifest-v1.json"
        ))
        .unwrap();
        let scope = test_scope("prod");
        let cutover = |legacy, subjects, recovery, release: &str| {
            AccountabilityCutoverV1::parse_json(
                &json!({
                    "schema_version": 1,
                    "release_digest": release,
                    "scope_ref": scope.as_str(),
                    "surface_manifest_fingerprint": manifest.fingerprint(),
                    "identity_migration_fingerprint": RELEASE,
                    "active_legacy_operations": legacy,
                    "enrolled_subjects": subjects,
                    "backup_fingerprint": RELEASE,
                    "restore_rehearsal_fingerprint": RELEASE,
                    "observation_window_fingerprint": RELEASE,
                    "open_trust_root_recovery": recovery,
                    "rollback_actor_schema": 1,
                    "rollback_duty_schema": 1
                })
                .to_string(),
            )
            .unwrap()
        };
        cutover(0, 2, false, RELEASE)
            .enforce_ready(RELEASE, &scope, manifest.fingerprint())
            .unwrap();
        for denied in [
            cutover(1, 2, false, RELEASE),
            cutover(0, 1, false, RELEASE),
            cutover(0, 2, true, RELEASE),
            cutover(
                0,
                2,
                false,
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ),
        ] {
            assert!(denied
                .enforce_ready(RELEASE, &scope, manifest.fingerprint())
                .is_err());
        }
    }

    #[test]
    fn posture_has_only_three_explicit_values() {
        for posture in [
            AccountabilityPosture::AccountabilityLegacy,
            AccountabilityPosture::AuthenticatedObserve,
            AccountabilityPosture::EnforcedRecorded,
        ] {
            assert_eq!(
                AccountabilityPosture::parse(posture.as_str()).unwrap(),
                posture
            );
        }
        assert!(AccountabilityPosture::parse("").is_err());
        assert!(AccountabilityPosture::parse("enforced").is_err());
        assert!(AccountabilityPosture::parse("legacy_fallback").is_err());
    }
}
