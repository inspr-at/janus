//! Signed authoritative operation lineage and durable duty-history contracts.
//!
//! The types here deliberately separate untrusted serialized records from the
//! opaque views accepted by policy. A `VerifiedOperationView` can only be
//! produced after a complete epoch and journal chain verifies.

use std::collections::BTreeMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{ActorSubjectRef, Duty, DutyConflict, JanusError, JanusResult, SafeLabel, ScopeRef};

pub const OPERATION_STATE_SCHEMA: u8 = 1;
pub const DUTY_EPOCH_SCHEMA: u8 = 1;
pub const DUTY_ADMISSION_SCHEMA: u8 = 1;
pub const DUTY_JOURNAL_GENESIS_HASH: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";
pub const MAX_DUTY_RECORDS: usize = 65_536;
pub const MAX_DUTIES_PER_OPERATION: usize = 256;
pub const MAX_OPERATION_REFERENCE_TTL_SECS: u64 = 300;

const MAX_TEXT_BYTES: usize = 512;
const SIGNATURE_HEX_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictDomain {
    UseRequest,
    DelegationGrant,
    RoleBinding,
    PolicyChange,
    BreakGlass,
    Recovery,
}

impl ConflictDomain {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UseRequest => "use_request",
            Self::DelegationGrant => "delegation_grant",
            Self::RoleBinding => "role_binding",
            Self::PolicyChange => "policy_change",
            Self::BreakGlass => "break_glass",
            Self::Recovery => "recovery",
        }
    }

    pub const fn permits(self, duty: Duty) -> bool {
        matches!(
            (self, duty),
            (
                Self::UseRequest,
                Duty::RequestUse | Duty::ApproveUse | Duty::ExecuteUse
            ) | (
                Self::DelegationGrant,
                Duty::GrantDelegation | Duty::ReceiveDelegation
            ) | (Self::RoleBinding, Duty::GrantRole | Duty::ReceiveRole)
                | (
                    Self::PolicyChange,
                    Duty::ManageRolePolicy | Duty::ReceiveRole
                )
                | (
                    Self::BreakGlass,
                    Duty::ActivateBreakGlass
                        | Duty::ApproveBreakGlass
                        | Duty::UseBreakGlass
                        | Duty::ReviewBreakGlass
                )
                | (Self::Recovery, Duty::OperateRecovery | Duty::ReviewRecovery)
        )
    }
}

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OperationRef(String);

impl OperationRef {
    pub fn derive(domain: ConflictDomain, authoritative_lineage: &str) -> JanusResult<Self> {
        validate_text("authoritative_lineage", authoritative_lineage)?;
        Ok(Self(format!(
            "opr_{}",
            &digest_fields(
                "janus-operation-ref-v1",
                &[domain.as_str(), authoritative_lineage]
            )[7..39]
        )))
    }

    pub fn from_opaque(value: impl Into<String>) -> JanusResult<Self> {
        let value = value.into();
        validate_prefixed_hex("operation_ref", &value, "opr_", 32)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for OperationRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("OperationRef")
            .field(&self.0)
            .finish()
    }
}

/// Domain-service-signed state. Its action and duty are closed fields and the
/// operation reference is derived by the authoritative service, never a client.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeOperationRefV1 {
    pub schema_version: u8,
    pub domain_service: String,
    pub operation_ref: String,
    pub scope_ref: String,
    pub conflict_domain: ConflictDomain,
    pub duty: Duty,
    pub state_revision: u64,
    pub policy_revision: String,
    pub issued_at_unix_secs: u64,
    pub expires_at_unix_secs: u64,
    pub nonce_ref: String,
    pub audience_fingerprint: String,
    pub release_digest: String,
    pub signature: String,
}

impl AuthoritativeOperationRefV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        signing_key: &SigningKey,
        domain_service: &str,
        operation_ref: &OperationRef,
        scope: &ScopeRef,
        conflict_domain: ConflictDomain,
        duty: Duty,
        state_revision: u64,
        policy_revision: &SafeLabel,
        issued_at: SystemTime,
        expires_at: SystemTime,
        nonce_ref: &str,
        audience: &str,
        release_digest: &str,
    ) -> JanusResult<Self> {
        validate_text("domain_service", domain_service)?;
        validate_prefixed_hex("operation_nonce", nonce_ref, "nce_", 24)?;
        validate_text("operation_audience", audience)?;
        validate_sha256("release_digest", release_digest)?;
        if !conflict_domain.permits(duty) {
            return Err(duty_error(
                "operation_duty_domain_mismatch",
                "operation duty is not valid for its conflict domain",
            ));
        }
        let issued_at_unix_secs = unix_secs(issued_at)?;
        let expires_at_unix_secs = unix_secs(expires_at)?;
        if state_revision == 0
            || expires_at_unix_secs <= issued_at_unix_secs
            || expires_at_unix_secs - issued_at_unix_secs > MAX_OPERATION_REFERENCE_TTL_SECS
        {
            return Err(duty_error(
                "operation_time_invalid",
                "operation reference lifetime is invalid",
            ));
        }
        let mut reference = Self {
            schema_version: OPERATION_STATE_SCHEMA,
            domain_service: domain_service.to_string(),
            operation_ref: operation_ref.as_str().to_string(),
            scope_ref: scope.as_str().to_string(),
            conflict_domain,
            duty,
            state_revision,
            policy_revision: policy_revision.as_str().to_string(),
            issued_at_unix_secs,
            expires_at_unix_secs,
            nonce_ref: nonce_ref.to_string(),
            audience_fingerprint: fingerprint("janus-operation-audience-v1", audience.as_bytes()),
            release_digest: release_digest.to_string(),
            signature: String::new(),
        };
        reference.signature = hex::encode(signing_key.sign(&reference.signing_bytes()?).to_bytes());
        Ok(reference)
    }

    fn signing_bytes(&self) -> JanusResult<Vec<u8>> {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        serde_json::to_vec(&unsigned)
            .map_err(|_| unavailable("operation reference encoding failed"))
    }

    fn verify_shape(&self) -> JanusResult<()> {
        if self.schema_version != OPERATION_STATE_SCHEMA
            || OperationRef::from_opaque(self.operation_ref.clone()).is_err()
            || ScopeRef::from_opaque(self.scope_ref.clone()).is_err()
            || !self.conflict_domain.permits(self.duty)
            || SafeLabel::new(self.policy_revision.clone()).is_err()
            || validate_text("domain_service", &self.domain_service).is_err()
            || validate_prefixed_hex("operation_nonce", &self.nonce_ref, "nce_", 24).is_err()
            || validate_sha256("operation_audience", &self.audience_fingerprint).is_err()
            || validate_sha256("release_digest", &self.release_digest).is_err()
            || !valid_signature(&self.signature)
            || self.state_revision == 0
            || self.expires_at_unix_secs <= self.issued_at_unix_secs
            || self.expires_at_unix_secs - self.issued_at_unix_secs
                > MAX_OPERATION_REFERENCE_TTL_SECS
        {
            return Err(duty_error(
                "operation_reference_malformed",
                "operation reference is malformed",
            ));
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct VerifiedAuthoritativeOperation {
    operation_ref: OperationRef,
    scope: ScopeRef,
    conflict_domain: ConflictDomain,
    duty: Duty,
    policy_revision: SafeLabel,
    release_digest: String,
}

impl fmt::Debug for VerifiedAuthoritativeOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedAuthoritativeOperation")
            .field("operation_ref", &self.operation_ref)
            .field("scope", &self.scope)
            .field("conflict_domain", &self.conflict_domain)
            .field("duty", &self.duty)
            .field("release_digest", &self.release_digest)
            .finish_non_exhaustive()
    }
}

/// Stateful verifier consumes each signed state nonce exactly once.
pub struct OperationStateVerifier {
    verifying_key: VerifyingKey,
    expected_service: String,
    expected_audience_fingerprint: String,
    expected_release_digest: String,
    consumed_nonces: BTreeMap<String, u64>,
}

impl OperationStateVerifier {
    pub fn new(
        verifying_key: VerifyingKey,
        expected_service: &str,
        expected_audience: &str,
        expected_release_digest: &str,
    ) -> JanusResult<Self> {
        validate_text("domain_service", expected_service)?;
        validate_text("operation_audience", expected_audience)?;
        validate_sha256("release_digest", expected_release_digest)?;
        Ok(Self {
            verifying_key,
            expected_service: expected_service.to_string(),
            expected_audience_fingerprint: fingerprint(
                "janus-operation-audience-v1",
                expected_audience.as_bytes(),
            ),
            expected_release_digest: expected_release_digest.to_string(),
            consumed_nonces: BTreeMap::new(),
        })
    }

    pub fn verify_once(
        &mut self,
        reference: &AuthoritativeOperationRefV1,
        now: SystemTime,
    ) -> JanusResult<VerifiedAuthoritativeOperation> {
        reference.verify_shape()?;
        let now = unix_secs(now)?;
        self.consumed_nonces
            .retain(|_, expires_at| *expires_at > now);
        if reference.domain_service != self.expected_service
            || reference.audience_fingerprint != self.expected_audience_fingerprint
            || reference.release_digest != self.expected_release_digest
            || now < reference.issued_at_unix_secs
            || now >= reference.expires_at_unix_secs
            || self.consumed_nonces.contains_key(&reference.nonce_ref)
            || self.consumed_nonces.len() >= 4_096
        {
            return Err(duty_error(
                "operation_reference_context_mismatch",
                "operation reference is stale, replayed, or context mismatched",
            ));
        }
        verify_signature(
            &self.verifying_key,
            &reference.signing_bytes()?,
            &reference.signature,
            "operation_reference_signature_invalid",
        )?;
        self.consumed_nonces
            .insert(reference.nonce_ref.clone(), reference.expires_at_unix_secs);
        Ok(VerifiedAuthoritativeOperation {
            operation_ref: OperationRef::from_opaque(reference.operation_ref.clone())?,
            scope: ScopeRef::from_opaque(reference.scope_ref.clone())?,
            conflict_domain: reference.conflict_domain,
            duty: reference.duty,
            policy_revision: SafeLabel::new(reference.policy_revision.clone())?,
            release_digest: reference.release_digest.clone(),
        })
    }
}

/// Candidate derived exclusively from a verified authoritative operation.
#[derive(Clone)]
pub struct PolicyDutyCandidate {
    actor: ActorSubjectRef,
    operation_ref: OperationRef,
    scope: ScopeRef,
    conflict_domain: ConflictDomain,
    duty: Duty,
    policy_revision: SafeLabel,
    release_digest: String,
}

impl PolicyDutyCandidate {
    pub fn from_verified_operation(
        actor: ActorSubjectRef,
        operation: VerifiedAuthoritativeOperation,
    ) -> Self {
        Self {
            actor,
            operation_ref: operation.operation_ref,
            scope: operation.scope,
            conflict_domain: operation.conflict_domain,
            duty: operation.duty,
            policy_revision: operation.policy_revision,
            release_digest: operation.release_digest,
        }
    }

    pub fn actor(&self) -> &ActorSubjectRef {
        &self.actor
    }
    pub fn operation_ref(&self) -> &OperationRef {
        &self.operation_ref
    }
    pub fn scope(&self) -> &ScopeRef {
        &self.scope
    }
    pub fn conflict_domain(&self) -> ConflictDomain {
        self.conflict_domain
    }
    pub fn duty(&self) -> Duty {
        self.duty
    }
    pub fn policy_revision(&self) -> &SafeLabel {
        &self.policy_revision
    }
    pub fn release_digest(&self) -> &str {
        &self.release_digest
    }

    fn identity(&self) -> String {
        digest_fields(
            "janus-duty-operation-identity-v1",
            &[
                self.actor.as_str(),
                self.scope.as_str(),
                self.conflict_domain.as_str(),
                self.operation_ref.as_str(),
            ],
        )
    }

    #[cfg(test)]
    pub(crate) fn fixture(
        actor: ActorSubjectRef,
        operation_ref: OperationRef,
        scope: ScopeRef,
        conflict_domain: ConflictDomain,
        duty: Duty,
    ) -> Self {
        assert!(conflict_domain.permits(duty));
        Self {
            actor,
            operation_ref,
            scope,
            conflict_domain,
            duty,
            policy_revision: SafeLabel::new("fixture-policy").expect("valid fixture policy"),
            release_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
        }
    }
}

impl fmt::Debug for PolicyDutyCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PolicyDutyCandidate")
            .field("actor", &self.actor)
            .field("operation_ref", &self.operation_ref)
            .field("scope", &self.scope)
            .field("conflict_domain", &self.conflict_domain)
            .field("duty", &self.duty)
            .field("release_digest", &self.release_digest)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DutyEpochCertificateV1 {
    pub schema_version: u8,
    pub epoch: u64,
    pub key_id: String,
    pub verifying_key: String,
    pub previous_epoch: Option<u64>,
    pub previous_key_id: Option<String>,
    pub previous_signature: Option<String>,
    pub self_signature: String,
}

impl DutyEpochCertificateV1 {
    pub fn genesis(signing_key: &SigningKey) -> JanusResult<Self> {
        Self::issue(1, signing_key, None)
    }

    pub fn rotate(
        previous_epoch: &Self,
        previous_key: &SigningKey,
        next_key: &SigningKey,
    ) -> JanusResult<Self> {
        if previous_epoch.key_id != key_id(&previous_key.verifying_key()) {
            return Err(duty_error(
                "duty_epoch_previous_key_mismatch",
                "previous signing key does not match the epoch",
            ));
        }
        Self::issue(
            previous_epoch
                .epoch
                .checked_add(1)
                .ok_or_else(|| unavailable("duty epoch exhausted"))?,
            next_key,
            Some((previous_epoch, previous_key)),
        )
    }

    fn issue(
        epoch: u64,
        signing_key: &SigningKey,
        previous: Option<(&Self, &SigningKey)>,
    ) -> JanusResult<Self> {
        let verifying_key = signing_key.verifying_key();
        let mut certificate = Self {
            schema_version: DUTY_EPOCH_SCHEMA,
            epoch,
            key_id: key_id(&verifying_key),
            verifying_key: hex::encode(verifying_key.to_bytes()),
            previous_epoch: previous.map(|(certificate, _)| certificate.epoch),
            previous_key_id: previous.map(|(certificate, _)| certificate.key_id.clone()),
            previous_signature: None,
            self_signature: String::new(),
        };
        let bytes = certificate.signing_bytes()?;
        if let Some((_, previous_key)) = previous {
            certificate.previous_signature =
                Some(hex::encode(previous_key.sign(&bytes).to_bytes()));
        }
        certificate.self_signature = hex::encode(signing_key.sign(&bytes).to_bytes());
        Ok(certificate)
    }

    fn signing_bytes(&self) -> JanusResult<Vec<u8>> {
        let mut unsigned = self.clone();
        unsigned.previous_signature = None;
        unsigned.self_signature.clear();
        serde_json::to_vec(&unsigned).map_err(|_| unavailable("duty epoch encoding failed"))
    }

    fn verifying_key_value(&self) -> JanusResult<VerifyingKey> {
        let bytes = hex::decode(&self.verifying_key)
            .map_err(|_| unavailable("duty epoch key malformed"))?;
        let raw: [u8; 32] = bytes
            .try_into()
            .map_err(|_| unavailable("duty epoch key malformed"))?;
        VerifyingKey::from_bytes(&raw).map_err(|_| unavailable("duty epoch key malformed"))
    }

    pub fn matches_signing_key(&self, signing_key: &SigningKey) -> bool {
        self.key_id == key_id(&signing_key.verifying_key())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DutyAdmissionV1 {
    pub schema_version: u8,
    pub admission_id: String,
    pub sequence: u64,
    pub epoch: u64,
    pub key_id: String,
    pub previous_hash: String,
    pub actor_subject_ref: String,
    pub scope_ref: String,
    pub conflict_domain: ConflictDomain,
    pub operation_ref: String,
    pub duty: Duty,
    pub policy_revision: String,
    pub admitted_at_unix_secs: u64,
    pub audit_ref: String,
    pub release_digest: String,
    pub record_hash: String,
    pub signature: String,
}

impl DutyAdmissionV1 {
    pub fn issue(
        signing_key: &SigningKey,
        epoch: &DutyEpochCertificateV1,
        sequence: u64,
        previous_hash: &str,
        candidate: &PolicyDutyCandidate,
        audit_ref: &str,
        admitted_at: SystemTime,
    ) -> JanusResult<Self> {
        if sequence == 0
            || epoch.key_id != key_id(&signing_key.verifying_key())
            || validate_sha256("previous_hash", previous_hash).is_err()
        {
            return Err(unavailable("duty admission chain context invalid"));
        }
        validate_prefixed_hex("duty_audit_ref", audit_ref, "aud_", 24)?;
        let mut record = Self {
            schema_version: DUTY_ADMISSION_SCHEMA,
            admission_id: String::new(),
            sequence,
            epoch: epoch.epoch,
            key_id: epoch.key_id.clone(),
            previous_hash: previous_hash.to_string(),
            actor_subject_ref: candidate.actor.as_str().to_string(),
            scope_ref: candidate.scope.as_str().to_string(),
            conflict_domain: candidate.conflict_domain,
            operation_ref: candidate.operation_ref.as_str().to_string(),
            duty: candidate.duty,
            policy_revision: candidate.policy_revision.as_str().to_string(),
            admitted_at_unix_secs: unix_secs(admitted_at)?,
            audit_ref: audit_ref.to_string(),
            release_digest: candidate.release_digest.clone(),
            record_hash: String::new(),
            signature: String::new(),
        };
        record.record_hash = record.calculate_hash()?;
        record.admission_id = format!("dad_{}", &record.record_hash[7..31]);
        record.signature = hex::encode(signing_key.sign(record.record_hash.as_bytes()).to_bytes());
        Ok(record)
    }

    fn calculate_hash(&self) -> JanusResult<String> {
        let mut unsigned = self.clone();
        unsigned.admission_id.clear();
        unsigned.record_hash.clear();
        unsigned.signature.clear();
        let bytes = serde_json::to_vec(&unsigned)
            .map_err(|_| unavailable("duty admission encoding failed"))?;
        Ok(fingerprint("janus-duty-admission-v1", &bytes))
    }

    fn operation_identity(&self) -> String {
        digest_fields(
            "janus-duty-operation-identity-v1",
            &[
                &self.actor_subject_ref,
                &self.scope_ref,
                self.conflict_domain.as_str(),
                &self.operation_ref,
            ],
        )
    }

    pub fn operation_identity_fingerprint(&self) -> String {
        self.operation_identity()
    }
}

/// Complete verified journal. Construction validates every epoch, record,
/// signature, predecessor, bound, and release before exposing any view.
pub struct VerifiedDutyJournal {
    records: Vec<DutyAdmissionV1>,
    head_hash: String,
}

pub struct DutyJournalVerifier;

impl DutyJournalVerifier {
    pub fn verify(
        epochs: &[DutyEpochCertificateV1],
        records: &[DutyAdmissionV1],
        expected_release_digest: &str,
    ) -> JanusResult<VerifiedDutyJournal> {
        validate_sha256("release_digest", expected_release_digest)?;
        let keys = verify_epochs(epochs)?;
        if records.len() > MAX_DUTY_RECORDS {
            return Err(unavailable("duty journal capacity exceeded"));
        }
        let mut previous_hash = DUTY_JOURNAL_GENESIS_HASH.to_string();
        let mut per_operation = BTreeMap::<String, usize>::new();
        for (index, record) in records.iter().enumerate() {
            let expected_sequence = (index as u64) + 1;
            verify_record(
                record,
                expected_sequence,
                &previous_hash,
                expected_release_digest,
                &keys,
            )?;
            let count = per_operation
                .entry(record.operation_identity())
                .or_default();
            *count += 1;
            if *count > MAX_DUTIES_PER_OPERATION {
                return Err(unavailable("duty operation capacity exceeded"));
            }
            previous_hash = record.record_hash.clone();
        }
        Ok(VerifiedDutyJournal {
            records: records.to_vec(),
            head_hash: previous_hash,
        })
    }
}

impl VerifiedDutyJournal {
    pub fn head_hash(&self) -> &str {
        &self.head_hash
    }
    pub fn sequence(&self) -> u64 {
        self.records.len() as u64
    }

    pub fn operation_view(&self, candidate: &PolicyDutyCandidate) -> VerifiedOperationView {
        let identity = candidate.identity();
        let duties = self
            .records
            .iter()
            .filter(|record| record.operation_identity() == identity)
            .map(|record| record.duty)
            .collect();
        VerifiedOperationView {
            operation_identity: identity,
            duties,
            journal_head_hash: self.head_hash.clone(),
        }
    }
}

/// Opaque policy input; fields and production constructors are private.
pub struct VerifiedOperationView {
    operation_identity: String,
    duties: Vec<Duty>,
    journal_head_hash: String,
}

impl fmt::Debug for VerifiedOperationView {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedOperationView")
            .field("operation_identity", &self.operation_identity)
            .field("duty_count", &self.duties.len())
            .field("journal_head_hash", &self.journal_head_hash)
            .finish()
    }
}

impl VerifiedOperationView {
    pub(crate) fn conflict_reason(
        &self,
        candidate: &PolicyDutyCandidate,
        conflicts: &[DutyConflict],
    ) -> Result<Option<&'static str>, &'static str> {
        if self.operation_identity != candidate.identity() {
            return Err("duty_operation_view_mismatch");
        }
        for prior in &self.duties {
            for conflict in conflicts {
                if (conflict.left == *prior && conflict.right == candidate.duty)
                    || (conflict.right == *prior && conflict.left == candidate.duty)
                {
                    return Ok(Some(conflict.reason_code));
                }
            }
        }
        Ok(None)
    }

    pub fn evaluate_candidate(
        &self,
        candidate: &PolicyDutyCandidate,
        conflicts: &[DutyConflict],
    ) -> JanusResult<Option<&'static str>> {
        self.conflict_reason(candidate, conflicts)
            .map_err(|reason| {
                duty_error(reason, "verified operation view does not match candidate")
            })
    }

    #[cfg(test)]
    pub(crate) fn fixture(candidate: &PolicyDutyCandidate, duties: Vec<Duty>) -> Self {
        Self {
            operation_identity: candidate.identity(),
            duties,
            journal_head_hash: DUTY_JOURNAL_GENESIS_HASH.to_string(),
        }
    }
}

fn verify_epochs(
    epochs: &[DutyEpochCertificateV1],
) -> JanusResult<BTreeMap<u64, (String, VerifyingKey)>> {
    if epochs.is_empty() {
        return Err(unavailable("duty epoch chain is empty"));
    }
    let mut keys = BTreeMap::new();
    let mut previous: Option<&DutyEpochCertificateV1> = None;
    for certificate in epochs {
        let key = certificate.verifying_key_value()?;
        if certificate.schema_version != DUTY_EPOCH_SCHEMA
            || certificate.epoch == 0
            || certificate.key_id != key_id(&key)
            || !valid_signature(&certificate.self_signature)
            || certificate.epoch != previous.map_or(1, |entry| entry.epoch + 1)
            || certificate.previous_epoch != previous.map(|entry| entry.epoch)
            || certificate.previous_key_id.as_deref() != previous.map(|entry| entry.key_id.as_str())
        {
            return Err(unavailable("duty epoch chain invalid"));
        }
        let bytes = certificate.signing_bytes()?;
        verify_signature(
            &key,
            &bytes,
            &certificate.self_signature,
            "duty_epoch_self_signature_invalid",
        )?;
        match (previous, certificate.previous_signature.as_deref()) {
            (None, None) => {}
            (Some(previous), Some(signature)) => {
                let previous_key = keys
                    .get(&previous.epoch)
                    .map(|(_, key)| key)
                    .ok_or_else(|| unavailable("duty previous epoch key missing"))?;
                verify_signature(
                    previous_key,
                    &bytes,
                    signature,
                    "duty_epoch_cross_signature_invalid",
                )?;
            }
            _ => return Err(unavailable("duty epoch cross-signature missing")),
        }
        keys.insert(certificate.epoch, (certificate.key_id.clone(), key));
        previous = Some(certificate);
    }
    Ok(keys)
}

fn verify_record(
    record: &DutyAdmissionV1,
    expected_sequence: u64,
    expected_previous_hash: &str,
    expected_release_digest: &str,
    keys: &BTreeMap<u64, (String, VerifyingKey)>,
) -> JanusResult<()> {
    let Some((key_id_value, key)) = keys.get(&record.epoch) else {
        return Err(unavailable("duty admission epoch unknown"));
    };
    if record.schema_version != DUTY_ADMISSION_SCHEMA
        || record.sequence != expected_sequence
        || record.previous_hash != expected_previous_hash
        || &record.key_id != key_id_value
        || record.release_digest != expected_release_digest
        || ActorSubjectRef::from_opaque(record.actor_subject_ref.clone()).is_err()
        || ScopeRef::from_opaque(record.scope_ref.clone()).is_err()
        || OperationRef::from_opaque(record.operation_ref.clone()).is_err()
        || !record.conflict_domain.permits(record.duty)
        || SafeLabel::new(record.policy_revision.clone()).is_err()
        || validate_prefixed_hex("duty_audit_ref", &record.audit_ref, "aud_", 24).is_err()
        || validate_prefixed_hex("duty_admission_id", &record.admission_id, "dad_", 24).is_err()
        || validate_sha256("duty_record_hash", &record.record_hash).is_err()
        || !valid_signature(&record.signature)
        || record.calculate_hash()? != record.record_hash
        || record.admission_id != format!("dad_{}", &record.record_hash[7..31])
    {
        return Err(unavailable("duty admission chain invalid"));
    }
    verify_signature(
        key,
        record.record_hash.as_bytes(),
        &record.signature,
        "duty_admission_signature_invalid",
    )
}

fn key_id(key: &VerifyingKey) -> String {
    let fingerprint = fingerprint("janus-duty-epoch-key-v1", &key.to_bytes());
    format!("key_{}", &fingerprint[7..31])
}

fn verify_signature(
    key: &VerifyingKey,
    message: &[u8],
    encoded: &str,
    reason_code: &'static str,
) -> JanusResult<()> {
    let bytes = hex::decode(encoded).map_err(|_| unavailable("duty signature malformed"))?;
    let signature =
        Signature::from_slice(&bytes).map_err(|_| unavailable("duty signature malformed"))?;
    key.verify(message, &signature)
        .map_err(|_| duty_error(reason_code, "duty signature verification failed"))
}

fn valid_signature(value: &str) -> bool {
    value.len() == SIGNATURE_HEX_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn validate_text(kind: &'static str, value: &str) -> JanusResult<()> {
    if value.is_empty()
        || value.len() > MAX_TEXT_BYTES
        || value.trim().len() != value.len()
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(JanusError::InvalidIdentifier { kind });
    }
    Ok(())
}

fn validate_prefixed_hex(
    kind: &'static str,
    value: &str,
    prefix: &str,
    hex_len: usize,
) -> JanusResult<()> {
    let Some(suffix) = value.strip_prefix(prefix) else {
        return Err(JanusError::InvalidIdentifier { kind });
    };
    if suffix.len() != hex_len
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(JanusError::InvalidIdentifier { kind });
    }
    Ok(())
}

fn validate_sha256(kind: &'static str, value: &str) -> JanusResult<()> {
    validate_prefixed_hex(kind, value, "sha256:", 64)
}

fn unix_secs(time: SystemTime) -> JanusResult<u64> {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| unavailable("duty time predates Unix epoch"))
}

fn digest_fields(domain: &str, fields: &[&str]) -> String {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, domain);
    for field in fields {
        hash_field(&mut hasher, field);
    }
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn hash_field(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn fingerprint(domain: &str, bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain.as_bytes());
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn duty_error(reason_code: &'static str, detail: &'static str) -> JanusError {
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
    use crate::{test_scope, TrustAdapterKind};
    use std::time::Duration;

    const RELEASE: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn candidate(
        key: &SigningKey,
        verifier: &mut OperationStateVerifier,
        actor: &ActorSubjectRef,
        domain: ConflictDomain,
        duty: Duty,
        nonce: u8,
    ) -> PolicyDutyCandidate {
        let now = UNIX_EPOCH + Duration::from_secs(100);
        let operation = OperationRef::derive(domain, "stable-lineage").unwrap();
        let reference = AuthoritativeOperationRefV1::issue(
            key,
            "domain-service",
            &operation,
            &test_scope("dev"),
            domain,
            duty,
            1,
            &SafeLabel::new("policy-v1").unwrap(),
            now,
            now + Duration::from_secs(60),
            &format!("nce_{nonce:024x}"),
            "janus-duty",
            RELEASE,
        )
        .unwrap();
        PolicyDutyCandidate::from_verified_operation(
            actor.clone(),
            verifier.verify_once(&reference, now).unwrap(),
        )
    }

    #[test]
    fn authoritative_reference_rejects_replay_and_wrong_release() {
        let key = SigningKey::from_bytes(&[3; 32]);
        let actor = ActorSubjectRef::derive(TrustAdapterKind::LocalPeer, "host", "one").unwrap();
        let mut verifier = OperationStateVerifier::new(
            key.verifying_key(),
            "domain-service",
            "janus-duty",
            RELEASE,
        )
        .unwrap();
        let first = candidate(
            &key,
            &mut verifier,
            &actor,
            ConflictDomain::UseRequest,
            Duty::RequestUse,
            1,
        );
        assert_eq!(first.duty(), Duty::RequestUse);
        let operation = OperationRef::derive(ConflictDomain::UseRequest, "other").unwrap();
        let now = UNIX_EPOCH + Duration::from_secs(100);
        let reference = AuthoritativeOperationRefV1::issue(
            &key,
            "domain-service",
            &operation,
            &test_scope("dev"),
            ConflictDomain::UseRequest,
            Duty::ApproveUse,
            2,
            &SafeLabel::new("policy-v1").unwrap(),
            now,
            now + Duration::from_secs(60),
            "nce_000000000000000000000001",
            "janus-duty",
            RELEASE,
        )
        .unwrap();
        assert!(verifier.verify_once(&reference, now).is_err());
        let mut wrong_release = OperationStateVerifier::new(
            key.verifying_key(),
            "domain-service",
            "janus-duty",
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap();
        assert!(wrong_release.verify_once(&reference, now).is_err());
    }

    #[test]
    fn journal_verifies_rotation_and_keeps_policy_revisions_in_one_operation() {
        let domain_key = SigningKey::from_bytes(&[4; 32]);
        let first_key = SigningKey::from_bytes(&[5; 32]);
        let second_key = SigningKey::from_bytes(&[6; 32]);
        let actor = ActorSubjectRef::derive(TrustAdapterKind::LocalPeer, "host", "one").unwrap();
        let mut verifier = OperationStateVerifier::new(
            domain_key.verifying_key(),
            "domain-service",
            "janus-duty",
            RELEASE,
        )
        .unwrap();
        let request = candidate(
            &domain_key,
            &mut verifier,
            &actor,
            ConflictDomain::UseRequest,
            Duty::RequestUse,
            1,
        );
        let approve = candidate(
            &domain_key,
            &mut verifier,
            &actor,
            ConflictDomain::UseRequest,
            Duty::ApproveUse,
            2,
        );
        let epoch1 = DutyEpochCertificateV1::genesis(&first_key).unwrap();
        let epoch2 = DutyEpochCertificateV1::rotate(&epoch1, &first_key, &second_key).unwrap();
        let record1 = DutyAdmissionV1::issue(
            &first_key,
            &epoch1,
            1,
            DUTY_JOURNAL_GENESIS_HASH,
            &request,
            "aud_000000000000000000000001",
            UNIX_EPOCH + Duration::from_secs(101),
        )
        .unwrap();
        let record2 = DutyAdmissionV1::issue(
            &second_key,
            &epoch2,
            2,
            &record1.record_hash,
            &approve,
            "aud_000000000000000000000002",
            UNIX_EPOCH + Duration::from_secs(102),
        )
        .unwrap();
        let journal =
            DutyJournalVerifier::verify(&[epoch1, epoch2], &[record1, record2], RELEASE).unwrap();
        assert_eq!(journal.sequence(), 2);
        let view = journal.operation_view(&approve);
        assert_eq!(view.duties.len(), 2);
    }

    #[test]
    fn tamper_gap_unknown_epoch_and_missing_archival_history_fail_closed() {
        let domain_key = SigningKey::from_bytes(&[7; 32]);
        let journal_key = SigningKey::from_bytes(&[8; 32]);
        let actor = ActorSubjectRef::derive(TrustAdapterKind::LocalPeer, "host", "one").unwrap();
        let mut verifier = OperationStateVerifier::new(
            domain_key.verifying_key(),
            "domain-service",
            "janus-duty",
            RELEASE,
        )
        .unwrap();
        let candidate = candidate(
            &domain_key,
            &mut verifier,
            &actor,
            ConflictDomain::Recovery,
            Duty::OperateRecovery,
            1,
        );
        let epoch = DutyEpochCertificateV1::genesis(&journal_key).unwrap();
        let record = DutyAdmissionV1::issue(
            &journal_key,
            &epoch,
            1,
            DUTY_JOURNAL_GENESIS_HASH,
            &candidate,
            "aud_000000000000000000000001",
            UNIX_EPOCH + Duration::from_secs(101),
        )
        .unwrap();
        let mut tampered = record.clone();
        tampered.policy_revision = "policy-v2".to_string();
        assert!(
            DutyJournalVerifier::verify(std::slice::from_ref(&epoch), &[tampered], RELEASE)
                .is_err()
        );
        let mut unknown_schema = record.clone();
        unknown_schema.schema_version = 2;
        assert!(DutyJournalVerifier::verify(
            std::slice::from_ref(&epoch),
            &[unknown_schema],
            RELEASE
        )
        .is_err());
        let mut bad_signature = record.clone();
        bad_signature.signature = "00".repeat(64);
        assert!(DutyJournalVerifier::verify(
            std::slice::from_ref(&epoch),
            &[bad_signature],
            RELEASE
        )
        .is_err());
        let mut gap = record.clone();
        gap.sequence = 2;
        assert!(
            DutyJournalVerifier::verify(std::slice::from_ref(&epoch), &[gap], RELEASE).is_err()
        );
        let mut unknown = record;
        unknown.epoch = 2;
        assert!(DutyJournalVerifier::verify(&[epoch], &[unknown], RELEASE).is_err());
    }
}
