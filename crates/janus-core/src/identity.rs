//! Authenticated accountable-subject and identity-shadow contracts.
//!
//! This module deliberately does not grant authority. It defines opaque actor
//! references, the closed local transport manifest, signed value-free shadow
//! observations, and reviewed legacy-binding migration inputs. Durable duty
//! history and enforced separation remain separate delivery slices.

use std::collections::BTreeSet;
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{runtime_endpoint_matrix, JanusError, JanusResult, RoleBindingId, ScopeRef};

/// Accepted schema for the identity transport manifest.
pub const IDENTITY_TRANSPORT_MANIFEST_SCHEMA: u8 = 1;
/// Accepted schema for signed identity-shadow observations.
pub const ACTOR_OBSERVATION_SCHEMA: u8 = 1;
/// Accepted schema for reviewed legacy-binding mappings.
pub const IDENTITY_BINDING_MIGRATION_SCHEMA: u8 = 1;
/// Maximum lifetime of one broker-internal actor assertion and its observation.
pub const MAX_ACTOR_ASSERTION_TTL: Duration = Duration::from_secs(300);

const MAX_IDENTITY_TEXT_BYTES: usize = 512;
const MAX_MIGRATION_MAPPINGS: usize = 4_096;

/// Opaque, stable reference to one accountable subject.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ActorSubjectRef(String);

impl ActorSubjectRef {
    /// Derive a privacy-safe reference from a trust adapter, trust domain, and
    /// stable subject id. Raw subject material is not retained in the result.
    pub fn derive(
        adapter: TrustAdapterKind,
        trust_domain: &str,
        stable_subject_id: &str,
    ) -> JanusResult<Self> {
        validate_bounded("trust_domain", trust_domain)?;
        validate_bounded("stable_subject_id", stable_subject_id)?;
        let mut hasher = Sha256::new();
        hash_field(&mut hasher, "janus-actor-subject-v1");
        hash_field(&mut hasher, adapter.as_str());
        hash_field(&mut hasher, trust_domain);
        hash_field(&mut hasher, stable_subject_id);
        Ok(Self(format!(
            "act_{}",
            hex::encode(&hasher.finalize()[..16])
        )))
    }

    /// Rehydrate a strict opaque actor reference.
    pub fn from_opaque(value: impl Into<String>) -> JanusResult<Self> {
        let value = value.into();
        validate_prefixed_hex("actor_subject_ref", &value, "act_", 32)?;
        Ok(Self(value))
    }

    /// Safe opaque text for comparisons and value-free evidence.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ActorSubjectRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ActorSubjectRef")
            .field(&self.0)
            .finish()
    }
}

/// Accountable-subject class selected by a configured trust adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ActorSubjectClass {
    /// Enrolled human operator.
    Human,
    /// Attested service or automation workload.
    Workload,
    /// Dedicated operating-system service identity.
    System,
}

impl ActorSubjectClass {
    /// Stable schema text.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Workload => "workload",
            Self::System => "system",
        }
    }

    /// Parse closed schema text.
    pub fn parse(value: &str) -> JanusResult<Self> {
        match value {
            "human" => Ok(Self::Human),
            "workload" => Ok(Self::Workload),
            "system" => Ok(Self::System),
            _ => Err(identity_error(
                "actor_subject_class_invalid",
                "actor subject class is unsupported",
            )),
        }
    }
}

/// Configured source of authenticated subject evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TrustAdapterKind {
    /// Kernel-observed credentials on a connected local Unix socket.
    LocalPeer,
    /// Verified OIDC issuer and exact `(iss, sub)` pair.
    Oidc,
    /// Verified workload credential in one trust domain.
    WorkloadAttestation,
}

impl TrustAdapterKind {
    /// Stable schema text.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalPeer => "local_peer",
            Self::Oidc => "oidc",
            Self::WorkloadAttestation => "workload_attestation",
        }
    }

    /// Parse closed schema text.
    pub fn parse(value: &str) -> JanusResult<Self> {
        match value {
            "local_peer" => Ok(Self::LocalPeer),
            "oidc" => Ok(Self::Oidc),
            "workload_attestation" => Ok(Self::WorkloadAttestation),
            _ => Err(identity_error(
                "trust_adapter_invalid",
                "identity trust adapter is unsupported",
            )),
        }
    }
}

/// Local transport on which one registered Janus surface is exposed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IdentitySurfaceTransport {
    /// One local process invocation using argv.
    ProcessArgv,
    /// Local MCP over process stdio.
    McpStdio,
    /// Filesystem Unix-domain socket.
    UnixSocket,
}

impl IdentitySurfaceTransport {
    /// Stable manifest text.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProcessArgv => "process_argv",
            Self::McpStdio => "mcp_stdio",
            Self::UnixSocket => "unix_socket",
        }
    }

    fn parse(value: &str) -> JanusResult<Self> {
        match value {
            "process_argv" => Ok(Self::ProcessArgv),
            "mcp_stdio" => Ok(Self::McpStdio),
            "unix_socket" => Ok(Self::UnixSocket),
            _ => Err(identity_error(
                "identity_transport_invalid",
                "identity transport is unsupported or remote",
            )),
        }
    }
}

/// One entry in the release-reviewed identity surface manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentitySurfacePolicy {
    surface: String,
    transport: IdentitySurfaceTransport,
    adapter: TrustAdapterKind,
}

impl IdentitySurfacePolicy {
    /// Registered surface name.
    pub fn surface(&self) -> &str {
        &self.surface
    }

    /// Required local transport.
    pub fn transport(&self) -> IdentitySurfaceTransport {
        self.transport
    }

    /// Required trust adapter.
    pub fn adapter(&self) -> TrustAdapterKind {
        self.adapter
    }
}

/// Closed release-reviewed manifest of every current local identity surface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityTransportManifestV1 {
    runtime_catalog_fingerprint: String,
    surfaces: Vec<IdentitySurfacePolicy>,
    fingerprint: String,
}

impl IdentityTransportManifestV1 {
    /// Parse and validate an exact version-one manifest.
    pub fn parse_json(text: &str) -> JanusResult<Self> {
        if text.is_empty() || text.len() > 64 * 1024 {
            return Err(identity_error(
                "identity_manifest_invalid",
                "identity manifest size is invalid",
            ));
        }
        let wire: IdentityTransportManifestWire = serde_json::from_str(text).map_err(|_| {
            identity_error(
                "identity_manifest_invalid",
                "identity manifest is malformed",
            )
        })?;
        if wire.schema_version != IDENTITY_TRANSPORT_MANIFEST_SCHEMA
            || wire.posture != "identity_shadow_only"
            || !wire.remote_authorizing_transports.is_empty()
            || wire.runtime_endpoint_catalog_fingerprint != runtime_endpoint_catalog_fingerprint()
        {
            return Err(identity_error(
                "identity_manifest_mismatch",
                "identity manifest does not match the current local runtime catalog",
            ));
        }

        let mut names = BTreeSet::new();
        let mut surfaces = Vec::with_capacity(wire.surfaces.len());
        for entry in wire.surfaces {
            validate_surface_name(&entry.surface)?;
            if !names.insert(entry.surface.clone()) {
                return Err(identity_error(
                    "identity_manifest_duplicate",
                    "identity manifest contains a duplicate surface",
                ));
            }
            surfaces.push(IdentitySurfacePolicy {
                surface: entry.surface,
                transport: IdentitySurfaceTransport::parse(&entry.transport)?,
                adapter: TrustAdapterKind::parse(&entry.trust_adapter)?,
            });
        }
        surfaces.sort_by(|left, right| left.surface.cmp(&right.surface));
        if surfaces != expected_identity_surfaces() {
            return Err(identity_error(
                "identity_manifest_incomplete",
                "identity manifest is missing or broadening a registered local surface",
            ));
        }
        Ok(Self {
            runtime_catalog_fingerprint: wire.runtime_endpoint_catalog_fingerprint,
            surfaces,
            fingerprint: fingerprint("janus-identity-transport-manifest-v1", text.as_bytes()),
        })
    }

    /// Exact registered surface or a fail-closed error.
    pub fn surface(&self, name: &str) -> JanusResult<&IdentitySurfacePolicy> {
        self.surfaces
            .iter()
            .find(|entry| entry.surface == name)
            .ok_or_else(|| {
                identity_error(
                    "identity_surface_unknown",
                    "identity surface is not release-reviewed",
                )
            })
    }

    /// Stable runtime endpoint catalog fingerprint bound by this manifest.
    pub fn runtime_catalog_fingerprint(&self) -> &str {
        &self.runtime_catalog_fingerprint
    }

    /// Every registered surface in stable order.
    pub fn surfaces(&self) -> &[IdentitySurfacePolicy] {
        &self.surfaces
    }

    /// Value-free fingerprint of the exact reviewed manifest.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

/// Fingerprint of the complete registered runtime action/transport matrix.
pub fn runtime_endpoint_catalog_fingerprint() -> String {
    let encoded = serde_json::to_vec(&runtime_endpoint_matrix())
        .expect("runtime endpoint matrix contains only serializable values");
    fingerprint("janus-runtime-endpoint-catalog-v1", &encoded)
}

/// Signed, value-free, explicitly non-authorizing identity-shadow evidence.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActorObservationV1 {
    /// Exact schema version.
    pub schema_version: u8,
    /// Opaque observation id.
    pub observation_id: String,
    /// Opaque accountable-subject reference.
    pub subject_ref: String,
    /// Closed subject class.
    pub subject_class: String,
    /// Closed trust adapter.
    pub trust_adapter: String,
    /// Opaque exact scope.
    pub scope_ref: String,
    /// Release-reviewed surface name.
    pub surface: String,
    /// Manifest-derived local transport.
    pub transport: String,
    /// Opaque fingerprint of kernel peer evidence.
    pub peer_binding_ref: String,
    /// Opaque per-connection binding.
    pub channel_binding_ref: String,
    /// Issue time.
    pub issued_at_unix_secs: u64,
    /// Expiry time, capped at five minutes.
    pub expires_at_unix_secs: u64,
    /// Opaque single-use request nonce.
    pub nonce_ref: String,
    /// Exact audience fingerprint.
    pub audience_fingerprint: String,
    /// Exact admitted release digest.
    pub release_digest: String,
    /// Honest slice-one posture.
    pub posture: String,
    /// Always `none`; this record cannot authorize a domain mutation.
    pub authority: String,
    /// Always false.
    pub value_returned: bool,
    /// Ed25519 signature over every preceding field.
    pub signature: String,
}

impl ActorObservationV1 {
    /// Validate the strict value-free wire shape before signature verification.
    pub fn validate_shape(&self) -> JanusResult<()> {
        if self.schema_version != ACTOR_OBSERVATION_SCHEMA
            || ActorSubjectRef::from_opaque(self.subject_ref.clone()).is_err()
            || ActorSubjectClass::parse(&self.subject_class).is_err()
            || TrustAdapterKind::parse(&self.trust_adapter).is_err()
            || ScopeRef::from_opaque(self.scope_ref.clone()).is_err()
            || validate_surface_name(&self.surface).is_err()
            || IdentitySurfaceTransport::parse(&self.transport).is_err()
            || validate_prefixed_hex("observation_id", &self.observation_id, "obs_", 24).is_err()
            || validate_prefixed_hex("peer_binding_ref", &self.peer_binding_ref, "pbr_", 24)
                .is_err()
            || validate_prefixed_hex("channel_binding_ref", &self.channel_binding_ref, "cbr_", 24)
                .is_err()
            || validate_prefixed_hex("nonce_ref", &self.nonce_ref, "nce_", 24).is_err()
            || !valid_sha256(&self.audience_fingerprint)
            || !valid_sha256(&self.release_digest)
            || self.posture != "identity_shadow_only"
            || self.authority != "none"
            || self.value_returned
            || self.expires_at_unix_secs <= self.issued_at_unix_secs
            || self.expires_at_unix_secs - self.issued_at_unix_secs
                > MAX_ACTOR_ASSERTION_TTL.as_secs()
            || self.signature.len() != 128
            || !lower_hex(&self.signature)
        {
            return Err(identity_error(
                "actor_observation_invalid",
                "actor observation is malformed or authority-bearing",
            ));
        }
        Ok(())
    }

    /// Canonical bytes covered by the broker signature.
    pub fn signing_bytes(&self) -> JanusResult<Vec<u8>> {
        self.validate_shape()?;
        let unsigned = UnsignedActorObservationV1::from(self);
        serde_json::to_vec(&unsigned).map_err(|_| {
            identity_error(
                "actor_observation_invalid",
                "actor observation cannot be canonicalized",
            )
        })
    }

    /// Rehydrate the opaque subject ref.
    pub fn actor_subject_ref(&self) -> JanusResult<ActorSubjectRef> {
        ActorSubjectRef::from_opaque(self.subject_ref.clone())
    }

    /// Rehydrate the opaque scope ref.
    pub fn scope(&self) -> JanusResult<ScopeRef> {
        ScopeRef::from_opaque(self.scope_ref.clone())
    }

    /// Whether the observation is fresh at one instant.
    pub fn is_fresh_at(&self, now: SystemTime) -> bool {
        unix_secs(now)
            .is_ok_and(|now| now >= self.issued_at_unix_secs && now < self.expires_at_unix_secs)
    }
}

#[derive(Serialize)]
struct UnsignedActorObservationV1<'a> {
    schema_version: u8,
    observation_id: &'a str,
    subject_ref: &'a str,
    subject_class: &'a str,
    trust_adapter: &'a str,
    scope_ref: &'a str,
    surface: &'a str,
    transport: &'a str,
    peer_binding_ref: &'a str,
    channel_binding_ref: &'a str,
    issued_at_unix_secs: u64,
    expires_at_unix_secs: u64,
    nonce_ref: &'a str,
    audience_fingerprint: &'a str,
    release_digest: &'a str,
    posture: &'a str,
    authority: &'a str,
    value_returned: bool,
}

impl<'a> From<&'a ActorObservationV1> for UnsignedActorObservationV1<'a> {
    fn from(value: &'a ActorObservationV1) -> Self {
        Self {
            schema_version: value.schema_version,
            observation_id: &value.observation_id,
            subject_ref: &value.subject_ref,
            subject_class: &value.subject_class,
            trust_adapter: &value.trust_adapter,
            scope_ref: &value.scope_ref,
            surface: &value.surface,
            transport: &value.transport,
            peer_binding_ref: &value.peer_binding_ref,
            channel_binding_ref: &value.channel_binding_ref,
            issued_at_unix_secs: value.issued_at_unix_secs,
            expires_at_unix_secs: value.expires_at_unix_secs,
            nonce_ref: &value.nonce_ref,
            audience_fingerprint: &value.audience_fingerprint,
            release_digest: &value.release_digest,
            posture: &value.posture,
            authority: &value.authority,
            value_returned: value.value_returned,
        }
    }
}

/// Strict reviewed mapping from one legacy role binding to one enrolled actor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityBindingMigrationMapping {
    /// Existing opaque binding id.
    pub binding_id: RoleBindingId,
    /// Reviewed enrolled subject.
    pub subject_ref: ActorSubjectRef,
    /// Fingerprint of the preserved technical principal binding.
    pub technical_binding_fingerprint: String,
}

/// Strict value-free input for legacy binding migration preflight.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityBindingMigrationManifestV1 {
    migration_id: String,
    trust_domain_fingerprint: String,
    mappings: Vec<IdentityBindingMigrationMapping>,
    fingerprint: String,
}

impl IdentityBindingMigrationManifestV1 {
    /// Parse and validate a reviewed manifest without importing authority.
    pub fn parse_json(text: &str) -> JanusResult<Self> {
        if text.is_empty() || text.len() > 512 * 1024 {
            return Err(identity_error(
                "identity_migration_manifest_invalid",
                "identity migration manifest size is invalid",
            ));
        }
        let wire: IdentityBindingMigrationWire = serde_json::from_str(text).map_err(|_| {
            identity_error(
                "identity_migration_manifest_invalid",
                "identity migration manifest is malformed",
            )
        })?;
        validate_prefixed_hex("identity_migration_id", &wire.migration_id, "idm_", 24)?;
        if wire.schema_version != IDENTITY_BINDING_MIGRATION_SCHEMA
            || !valid_sha256(&wire.trust_domain_fingerprint)
            || wire.mappings.is_empty()
            || wire.mappings.len() > MAX_MIGRATION_MAPPINGS
        {
            return Err(identity_error(
                "identity_migration_manifest_invalid",
                "identity migration manifest fields are invalid",
            ));
        }
        let mut binding_ids = BTreeSet::new();
        let mut mappings = Vec::with_capacity(wire.mappings.len());
        for mapping in wire.mappings {
            let binding_id = RoleBindingId::from_opaque(mapping.binding_id)?;
            let subject_ref = ActorSubjectRef::from_opaque(mapping.subject_ref)?;
            if !valid_sha256(&mapping.technical_binding_fingerprint)
                || !binding_ids.insert(binding_id.as_str().to_string())
            {
                return Err(identity_error(
                    "identity_migration_mapping_invalid",
                    "identity migration contains an invalid or duplicate mapping",
                ));
            }
            mappings.push(IdentityBindingMigrationMapping {
                binding_id,
                subject_ref,
                technical_binding_fingerprint: mapping.technical_binding_fingerprint,
            });
        }
        mappings.sort_by(|left, right| left.binding_id.cmp(&right.binding_id));
        let fingerprint = fingerprint("janus-identity-migration-v1", text.as_bytes());
        Ok(Self {
            migration_id: wire.migration_id,
            trust_domain_fingerprint: wire.trust_domain_fingerprint,
            mappings,
            fingerprint,
        })
    }

    /// Opaque migration id.
    pub fn migration_id(&self) -> &str {
        &self.migration_id
    }

    /// Opaque trust-domain fingerprint.
    pub fn trust_domain_fingerprint(&self) -> &str {
        &self.trust_domain_fingerprint
    }

    /// Reviewed mappings in stable binding-id order.
    pub fn mappings(&self) -> &[IdentityBindingMigrationMapping] {
        &self.mappings
    }

    /// Value-free fingerprint of the exact manifest.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityTransportManifestWire {
    schema_version: u8,
    posture: String,
    runtime_endpoint_catalog_fingerprint: String,
    remote_authorizing_transports: Vec<String>,
    surfaces: Vec<IdentitySurfaceWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentitySurfaceWire {
    surface: String,
    transport: String,
    trust_adapter: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityBindingMigrationWire {
    schema_version: u8,
    migration_id: String,
    trust_domain_fingerprint: String,
    mappings: Vec<IdentityBindingMigrationMappingWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityBindingMigrationMappingWire {
    binding_id: String,
    subject_ref: String,
    technical_binding_fingerprint: String,
}

fn expected_identity_surfaces() -> Vec<IdentitySurfacePolicy> {
    let mut surfaces = vec![
        ("janus-claude-hook", IdentitySurfaceTransport::ProcessArgv),
        ("janus-warden", IdentitySurfaceTransport::McpStdio),
        ("janusd-admin", IdentitySurfaceTransport::ProcessArgv),
        (
            "janusd-dynamic-custodyd",
            IdentitySurfaceTransport::UnixSocket,
        ),
        (
            "janusd-dynamic-deliveryd",
            IdentitySurfaceTransport::UnixSocket,
        ),
        (
            "janusd-dynamic-transportd",
            IdentitySurfaceTransport::UnixSocket,
        ),
        ("janusd-identityd", IdentitySurfaceTransport::UnixSocket),
        ("janusd-use", IdentitySurfaceTransport::ProcessArgv),
        (
            "janusd-web-transactiond",
            IdentitySurfaceTransport::UnixSocket,
        ),
    ]
    .into_iter()
    .map(|(surface, transport)| IdentitySurfacePolicy {
        surface: surface.to_string(),
        transport,
        adapter: TrustAdapterKind::LocalPeer,
    })
    .collect::<Vec<_>>();
    surfaces.sort_by(|left, right| left.surface.cmp(&right.surface));
    surfaces
}

fn validate_surface_name(value: &str) -> JanusResult<()> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(identity_error(
            "identity_surface_invalid",
            "identity surface name is malformed",
        ));
    }
    Ok(())
}

fn validate_bounded(kind: &'static str, value: &str) -> JanusResult<()> {
    if value.is_empty()
        || value.trim().len() != value.len()
        || value.len() > MAX_IDENTITY_TEXT_BYTES
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
    suffix_len: usize,
) -> JanusResult<()> {
    let Some(suffix) = value.strip_prefix(prefix) else {
        return Err(JanusError::InvalidIdentifier { kind });
    };
    if suffix.len() != suffix_len || !lower_hex(suffix) {
        return Err(JanusError::InvalidIdentifier { kind });
    }
    Ok(())
}

fn lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_sha256(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|suffix| suffix.len() == 64 && lower_hex(suffix))
}

fn fingerprint(domain: &str, bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, domain);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn hash_field(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn unix_secs(time: SystemTime) -> JanusResult<u64> {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| identity_error("identity_time_invalid", "identity time is invalid"))
}

fn identity_error(reason_code: &'static str, detail: impl Into<String>) -> JanusError {
    JanusError::policy_denied(reason_code, detail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EnvironmentId, OrganizationId, ProjectId, RepositoryId, ScopePathV1};

    fn scope() -> ScopeRef {
        ScopePathV1::new(
            OrganizationId::new("fixture-org").unwrap(),
            ProjectId::new("janus").unwrap(),
            RepositoryId::new("janus").unwrap(),
            EnvironmentId::new("test").unwrap(),
        )
        .scope_ref()
    }

    #[test]
    fn actor_refs_are_stable_opaque_and_adapter_bound() {
        let first =
            ActorSubjectRef::derive(TrustAdapterKind::LocalPeer, "host-a", "uid:501").unwrap();
        let second =
            ActorSubjectRef::derive(TrustAdapterKind::LocalPeer, "host-a", "uid:501").unwrap();
        assert_eq!(first, second);
        assert_ne!(
            first,
            ActorSubjectRef::derive(TrustAdapterKind::Oidc, "host-a", "uid:501").unwrap()
        );
        assert!(first.as_str().starts_with("act_"));
        assert!(!first.as_str().contains("501"));
        assert!(!format!("{first:?}").contains("uid"));
    }

    #[test]
    fn observation_shape_is_non_authorizing_and_bounded() {
        let actor =
            ActorSubjectRef::derive(TrustAdapterKind::LocalPeer, "host-a", "seed-a").unwrap();
        let observation = ActorObservationV1 {
            schema_version: ACTOR_OBSERVATION_SCHEMA,
            observation_id: "obs_111111111111111111111111".to_string(),
            subject_ref: actor.as_str().to_string(),
            subject_class: "human".to_string(),
            trust_adapter: "local_peer".to_string(),
            scope_ref: scope().as_str().to_string(),
            surface: "janusd-use".to_string(),
            transport: "process_argv".to_string(),
            peer_binding_ref: "pbr_222222222222222222222222".to_string(),
            channel_binding_ref: "cbr_333333333333333333333333".to_string(),
            issued_at_unix_secs: 10,
            expires_at_unix_secs: 310,
            nonce_ref: "nce_444444444444444444444444".to_string(),
            audience_fingerprint: format!("sha256:{}", "5".repeat(64)),
            release_digest: format!("sha256:{}", "6".repeat(64)),
            posture: "identity_shadow_only".to_string(),
            authority: "none".to_string(),
            value_returned: false,
            signature: "7".repeat(128),
        };
        observation.validate_shape().unwrap();
        let mut bad = observation.clone();
        bad.authority = "enforced".to_string();
        assert!(bad.validate_shape().is_err());
        let mut expired = observation;
        expired.expires_at_unix_secs += 1;
        assert!(expired.validate_shape().is_err());
    }

    #[test]
    fn shipped_transport_manifest_is_exact_and_closed() {
        let manifest = IdentityTransportManifestV1::parse_json(include_str!(
            "../../../config/identity/transport-manifest-v1.json"
        ))
        .unwrap();
        assert_eq!(manifest.surfaces(), expected_identity_surfaces());
        assert!(manifest.surface("remote-api").is_err());
        assert_eq!(
            manifest.runtime_catalog_fingerprint(),
            runtime_endpoint_catalog_fingerprint()
        );
    }
}
