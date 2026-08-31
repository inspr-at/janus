//! Capability-named host projections.
//!
//! A caller names a reviewed capability and a host. Janus resolves the exact
//! reviewed env-file profile that projects that capability for that host,
//! issues the permit-bound handoff through the existing env-file executor, and
//! returns only value-free evidence: identifiers, reviewed paths, the published
//! immutable generation, and an opaque projection handle. Callers never supply
//! or receive the credential, and there is deliberately no reveal path.
//!
//! The catalog is closed. `pharos-beacon-token` publishes its reviewed verifier
//! generation; `managed-service-environment` publishes a value-independent
//! generation that cannot become a credential oracle.

use std::path::{Path, PathBuf};

use janus_core::{
    ConsumerRef, Destination, ExecutorRef, JanusError, JanusResult, ProfileId, SafeLabel, SecretRef,
};
use sha2::{Digest, Sha256};

use crate::{
    pharos_generation, EnvFileHashSidecarFormat, EnvFileOutcome, EnvFilePlan, EnvFileProfile,
};

const PROJECTION_REF_DOMAIN: &[u8] = b"janus-host-projection-ref-v1\0";

/// Closed catalog of capability names a caller may project onto a host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HostProjectionCapability {
    /// Pharos beacon bearer token. The host consumes the private env file;
    /// Pharos consumes only the value-free
    /// `pharos-beacon-token-generation-v2` verifier generation.
    PharosBeaconToken,
    /// A reviewed managed-service env file. Its generation contains only an
    /// opaque per-host revision and never a credential digest.
    ManagedServiceEnvironment,
}

impl HostProjectionCapability {
    /// Every issuable capability, used by closed-catalog tests.
    pub const ALL: [Self; 2] = [Self::PharosBeaconToken, Self::ManagedServiceEnvironment];

    /// Stable caller-facing name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PharosBeaconToken => "pharos-beacon-token",
            Self::ManagedServiceEnvironment => "managed-service-environment",
        }
    }

    /// Parse one exact catalog name. Unknown names fail closed without echoing
    /// the caller input.
    pub fn parse(value: &str) -> JanusResult<Self> {
        if let Some(capability) = Self::ALL
            .into_iter()
            .find(|capability| capability.as_str() == value)
        {
            return Ok(capability);
        }
        Err(JanusError::policy_denied(
            "projection_capability_unknown",
            "projection capability is not release-reviewed",
        ))
    }

    /// The reviewed hash-sidecar format whose profiles project this capability.
    pub const fn hash_sidecar_format(self) -> EnvFileHashSidecarFormat {
        match self {
            Self::PharosBeaconToken => EnvFileHashSidecarFormat::PharosBeaconTokenGenerationV2,
            Self::ManagedServiceEnvironment => {
                EnvFileHashSidecarFormat::ManagedServiceEnvironmentGenerationV1
            }
        }
    }

    /// Validate the host syntax this capability accepts.
    pub fn validate_host(self, host: &str) -> JanusResult<()> {
        match self {
            Self::PharosBeaconToken if pharos_generation::valid_token_subject(host) => Ok(()),
            Self::PharosBeaconToken => Err(JanusError::policy_denied(
                "projection_host_invalid",
                "projection host must be a canonical host name or host reference",
            )),
            Self::ManagedServiceEnvironment if pharos_generation::valid_token_subject(host) => {
                Ok(())
            }
            Self::ManagedServiceEnvironment => Err(JanusError::policy_denied(
                "projection_host_invalid",
                "projection host must be a canonical host name or host reference",
            )),
        }
    }
}

/// Value-free selector: which capability, for which host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostProjectionSelector {
    capability: HostProjectionCapability,
    host: SafeLabel,
}

impl HostProjectionSelector {
    /// Construct a selector, failing closed on host syntax the capability
    /// does not accept.
    pub fn new(capability: HostProjectionCapability, host: impl Into<String>) -> JanusResult<Self> {
        let host = host.into();
        capability.validate_host(&host)?;
        Ok(Self {
            capability,
            host: SafeLabel::new(host)?,
        })
    }

    /// Requested capability.
    pub fn capability(&self) -> HostProjectionCapability {
        self.capability
    }

    /// Requested host.
    pub fn host(&self) -> &SafeLabel {
        &self.host
    }

    fn matches(&self, profile: &EnvFileProfile) -> bool {
        profile.hash_sidecar().is_some_and(|sidecar| {
            sidecar.format() == self.capability.hash_sidecar_format()
                && sidecar.subject().as_str() == self.host.as_str()
        })
    }
}

/// Resolve exactly one reviewed env-file profile that projects the selected
/// capability for the selected host.
///
/// Zero matches and more than one match both fail closed. Profiles without a
/// hash sidecar, or with another reviewed format, never match.
pub fn resolve_host_projection_profile<'a>(
    profiles: impl IntoIterator<Item = &'a EnvFileProfile>,
    selector: &HostProjectionSelector,
) -> JanusResult<&'a EnvFileProfile> {
    let mut matches = profiles
        .into_iter()
        .filter(|profile| selector.matches(profile));
    let Some(profile) = matches.next() else {
        return Err(JanusError::policy_denied(
            "projection_profile_missing",
            "no reviewed env-file profile projects this capability for the requested host",
        ));
    };
    if matches.next().is_some() {
        return Err(JanusError::policy_denied(
            "projection_profile_ambiguous",
            "more than one reviewed env-file profile projects this capability for the requested host",
        ));
    }
    Ok(profile)
}

/// Opaque, value-free handle for one issued host projection.
///
/// It is derived from the capability, the host, and the published immutable
/// generation. It grants nothing and exposes no credential material.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HostProjectionRef(String);

impl HostProjectionRef {
    /// Derive the handle for one issued projection.
    pub fn derive(
        capability: HostProjectionCapability,
        host: &SafeLabel,
        generation: &str,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(PROJECTION_REF_DOMAIN);
        hasher.update(capability.as_str().as_bytes());
        hasher.update(b"\0");
        hasher.update(host.as_str().as_bytes());
        hasher.update(b"\0");
        hasher.update(generation.as_bytes());
        let digest = hasher.finalize();
        Self(format!("prj_{}", hex(&digest[..10])))
    }

    /// Safe string form for evidence and machine-readable output.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for HostProjectionRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("HostProjectionRef").field(&self.0).finish()
    }
}

/// Value-free reviewed plan for one host projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostProjectionPlan {
    /// Requested capability.
    pub capability: HostProjectionCapability,
    /// Requested host.
    pub host: SafeLabel,
    /// Reviewed profile that projects the capability.
    pub profile_id: ProfileId,
    /// Opaque reference to the projected secret.
    pub secret_ref: SecretRef,
    /// Reviewed executor bound by the permit.
    pub executor: ExecutorRef,
    /// Reviewed destination bound by the permit.
    pub destination: Destination,
    /// Reviewed private env-file target consumed by the host.
    pub output_path: PathBuf,
    /// Reviewed value-free hash-sidecar target.
    pub hash_output_path: PathBuf,
    /// Reviewed hash-sidecar format.
    pub hash_format: EnvFileHashSidecarFormat,
    /// Directory holding the immutable generations and the `current` pointer.
    pub projection_root: PathBuf,
    /// Reviewed consumer reference.
    pub consumer_ref: ConsumerRef,
    /// Invariant marker.
    pub value_returned: bool,
}

impl HostProjectionPlan {
    /// Build the value-free plan from a reviewed env-file plan, re-checking
    /// that the plan projects exactly the selected capability and host.
    pub fn from_env_file_plan(
        selector: &HostProjectionSelector,
        plan: EnvFilePlan,
    ) -> JanusResult<Self> {
        let sidecar = plan
            .hash_sidecar
            .filter(|sidecar| {
                sidecar.format == selector.capability.hash_sidecar_format()
                    && sidecar.subject.as_str() == selector.host.as_str()
            })
            .ok_or_else(|| {
                JanusError::policy_denied(
                    "projection_profile_mismatch",
                    "env-file profile does not project the selected capability for the selected host",
                )
            })?;
        let projection_root = sidecar
            .output_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .ok_or_else(|| JanusError::InvalidManifest {
                detail: "env-file hash sidecar output path must have a parent directory"
                    .to_string(),
            })?;
        Ok(Self {
            capability: selector.capability,
            host: selector.host.clone(),
            profile_id: plan.profile_id,
            secret_ref: plan.secret_ref,
            executor: plan.executor,
            destination: plan.destination,
            output_path: plan.output_path,
            hash_output_path: sidecar.output_path,
            hash_format: sidecar.format,
            projection_root,
            consumer_ref: plan.consumer_ref,
            value_returned: plan.value_returned || sidecar.value_returned,
        })
    }
}

/// Value-free outcome of one issued host projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostProjectionOutcome {
    /// Value-free reviewed plan.
    pub plan: HostProjectionPlan,
    /// Immutable generation now pointed to by `current` in the projection root.
    pub generation: String,
    /// Opaque handle bound to capability, host, and generation.
    pub projection_ref: HostProjectionRef,
    /// Stable value-free outcome reason.
    pub reason_code: &'static str,
    /// Invariant marker.
    pub value_returned: bool,
}

impl HostProjectionOutcome {
    /// Build the projection outcome from a completed env-file handoff.
    pub fn from_env_file_outcome(
        selector: &HostProjectionSelector,
        outcome: EnvFileOutcome,
    ) -> JanusResult<Self> {
        let EnvFileOutcome {
            plan,
            hash_generation,
            reason_code,
            value_returned,
        } = outcome;
        let plan = HostProjectionPlan::from_env_file_plan(selector, plan)?;
        let generation = hash_generation.ok_or_else(|| JanusError::StoreUnavailable {
            detail: "host projection generation was not published".to_string(),
        })?;
        let projection_ref =
            HostProjectionRef::derive(selector.capability, &selector.host, &generation);
        Ok(Self {
            value_returned: value_returned || plan.value_returned,
            plan,
            generation,
            projection_ref,
            reason_code,
        })
    }
}

fn hex(bytes: &[u8]) -> String {
    const CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(CHARS[(byte >> 4) as usize] as char);
        output.push(CHARS[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EnvFileHashSidecarSpec, EnvFileProfileSpec};
    use janus_core::{
        BlastRadius, ConsumerDescriptor, ConsumerKind, Environment, OwnerRef, ReloadMethod,
        ScopePathV1,
    };

    fn profile(profile_id: &str, subject: Option<&str>) -> EnvFileProfile {
        profile_with_format(
            profile_id,
            subject,
            EnvFileHashSidecarFormat::PharosBeaconTokenGenerationV2,
        )
    }

    fn profile_with_format(
        profile_id: &str,
        subject: Option<&str>,
        format: EnvFileHashSidecarFormat,
    ) -> EnvFileProfile {
        let secret_ref = SecretRef::new(format!("sec_{profile_id}")).unwrap();
        let scope = ScopePathV1::for_repository("fixture-org", "janus", "janus", "dev")
            .unwrap()
            .scope_ref();
        EnvFileProfile::new(EnvFileProfileSpec {
            profile_id: ProfileId::new(format!("profile.{profile_id}")).unwrap(),
            secret_ref: secret_ref.clone(),
            executor: ExecutorRef::new("janus-run@fixture").unwrap(),
            destination: Destination::new(format!("pharos-beacon-{profile_id}")).unwrap(),
            env_name: SafeLabel::new("PHAROS_TOKEN").unwrap(),
            output_path: PathBuf::from(format!("/run/janus/env/pharos/beacons/{profile_id}.env")),
            hash_sidecar: subject.map(|subject| EnvFileHashSidecarSpec {
                format,
                subject: SafeLabel::new(subject).unwrap(),
                output_path: PathBuf::from(format!(
                    "/run/janus/env/pharos/beacon-token-hashes/{profile_id}.json"
                )),
            }),
            consumer: ConsumerDescriptor {
                scope,
                consumer_ref: ConsumerRef::new(format!("consumer.{profile_id}")).unwrap(),
                secret_ref,
                kind: ConsumerKind::Service,
                owner: OwnerRef::new("pharos").unwrap(),
                environment: Environment::new("test").unwrap(),
                reload: ReloadMethod::None,
                validation: Vec::new(),
                supports_dual_value: false,
                blast_radius: BlastRadius::new("fixture").unwrap(),
                declared: true,
            },
        })
        .unwrap()
    }

    #[test]
    fn capability_catalog_is_closed_and_fails_closed_without_echo() {
        assert_eq!(HostProjectionCapability::ALL.len(), 2);
        assert_eq!(
            HostProjectionCapability::parse("pharos-beacon-token").unwrap(),
            HostProjectionCapability::PharosBeaconToken
        );
        assert_eq!(
            HostProjectionCapability::PharosBeaconToken.hash_sidecar_format(),
            EnvFileHashSidecarFormat::PharosBeaconTokenGenerationV2
        );
        assert_eq!(
            HostProjectionCapability::parse("managed-service-environment").unwrap(),
            HostProjectionCapability::ManagedServiceEnvironment
        );
        assert_eq!(
            HostProjectionCapability::ManagedServiceEnvironment.hash_sidecar_format(),
            EnvFileHashSidecarFormat::ManagedServiceEnvironmentGenerationV1
        );

        let unknown = HostProjectionCapability::parse("SENSITIVE_CAPABILITY_CANARY").unwrap_err();
        assert!(matches!(
            unknown,
            JanusError::PolicyDenied {
                reason_code: "projection_capability_unknown",
                ..
            }
        ));
        assert!(!unknown.to_string().contains("SENSITIVE_CAPABILITY_CANARY"));

        assert!(HostProjectionCapability::parse("").is_err());
        assert!(HostProjectionCapability::parse("Pharos-Beacon-Token").is_err());
    }

    #[test]
    fn selector_accepts_canonical_hosts_and_host_references_only() {
        let capability = HostProjectionCapability::PharosBeaconToken;
        assert!(HostProjectionSelector::new(capability, "ares").is_ok());
        assert!(HostProjectionSelector::new(capability, "host_58f36c72a91e").is_ok());
        for invalid in ["", "ARES", "ares env", "../ares", "host_", "a b"] {
            let error = HostProjectionSelector::new(capability, invalid).unwrap_err();
            assert!(matches!(
                error,
                JanusError::PolicyDenied {
                    reason_code: "projection_host_invalid",
                    ..
                }
            ));
            assert!(!error.to_string().contains("ARES"));
        }
    }

    #[test]
    fn resolution_requires_exactly_one_projecting_profile() {
        let capability = HostProjectionCapability::PharosBeaconToken;
        let ares = profile("ares", Some("ares"));
        let hera = profile("hera", Some("hera"));
        let plain = profile("plain", None);
        let selector = HostProjectionSelector::new(capability, "ares").unwrap();

        let resolved = resolve_host_projection_profile([&ares, &hera, &plain], &selector).unwrap();
        assert_eq!(resolved.profile_id().as_str(), "profile.ares");

        let missing = resolve_host_projection_profile([&hera, &plain], &selector).unwrap_err();
        assert!(matches!(
            missing,
            JanusError::PolicyDenied {
                reason_code: "projection_profile_missing",
                ..
            }
        ));

        let duplicate = profile("ares-duplicate", Some("ares"));
        let ambiguous =
            resolve_host_projection_profile([&ares, &duplicate], &selector).unwrap_err();
        assert!(matches!(
            ambiguous,
            JanusError::PolicyDenied {
                reason_code: "projection_profile_ambiguous",
                ..
            }
        ));

        let unknown_host = HostProjectionSelector::new(capability, "zeus").unwrap();
        assert!(resolve_host_projection_profile([&ares, &hera], &unknown_host).is_err());
    }

    #[test]
    fn managed_service_resolution_requires_its_dedicated_format_and_exact_host() {
        let managed = profile_with_format(
            "managed-ares",
            Some("ares"),
            EnvFileHashSidecarFormat::ManagedServiceEnvironmentGenerationV1,
        );
        let pharos = profile("pharos-ares", Some("ares"));
        let selector = HostProjectionSelector::new(
            HostProjectionCapability::ManagedServiceEnvironment,
            "ares",
        )
        .unwrap();
        let resolved = resolve_host_projection_profile([&managed, &pharos], &selector).unwrap();
        assert_eq!(resolved.profile_id().as_str(), "profile.managed-ares");
        assert!(resolve_host_projection_profile([&pharos], &selector).is_err());

        let other = HostProjectionSelector::new(
            HostProjectionCapability::ManagedServiceEnvironment,
            "hera",
        )
        .unwrap();
        assert!(resolve_host_projection_profile([&managed], &other).is_err());
    }

    #[test]
    fn projection_refs_are_opaque_stable_and_generation_bound() {
        let capability = HostProjectionCapability::PharosBeaconToken;
        let host = SafeLabel::new("ares").unwrap();
        let generation = "1".repeat(64);
        let first = HostProjectionRef::derive(capability, &host, &generation);
        let again = HostProjectionRef::derive(capability, &host, &generation);
        assert_eq!(first, again);
        assert!(first.as_str().starts_with("prj_"));
        assert_eq!(first.as_str().len(), "prj_".len() + 20);
        assert!(!first.as_str().contains("ares"));
        assert_ne!(
            first,
            HostProjectionRef::derive(capability, &host, &"2".repeat(64))
        );
        assert_ne!(
            first,
            HostProjectionRef::derive(capability, &SafeLabel::new("hera").unwrap(), &generation)
        );
    }

    #[test]
    fn plan_rejects_profiles_that_do_not_project_the_selection() {
        let capability = HostProjectionCapability::PharosBeaconToken;
        let ares = profile("ares", Some("ares"));
        let plain = profile("plain", None);
        let selector = HostProjectionSelector::new(capability, "ares").unwrap();

        let plan = HostProjectionPlan::from_env_file_plan(&selector, ares.plan()).unwrap();
        assert_eq!(plan.capability, capability);
        assert_eq!(plan.host.as_str(), "ares");
        assert_eq!(plan.profile_id.as_str(), "profile.ares");
        assert_eq!(
            plan.projection_root,
            PathBuf::from("/run/janus/env/pharos/beacon-token-hashes")
        );
        assert_eq!(
            plan.hash_format,
            EnvFileHashSidecarFormat::PharosBeaconTokenGenerationV2
        );
        assert!(!plan.value_returned);

        let wrong_host = HostProjectionSelector::new(capability, "hera").unwrap();
        assert!(matches!(
            HostProjectionPlan::from_env_file_plan(&wrong_host, ares.plan()).unwrap_err(),
            JanusError::PolicyDenied {
                reason_code: "projection_profile_mismatch",
                ..
            }
        ));
        assert!(HostProjectionPlan::from_env_file_plan(&selector, plain.plan()).is_err());

        let without_generation = EnvFileOutcome {
            plan: ares.plan(),
            hash_generation: None,
            reason_code: "ok",
            value_returned: false,
        };
        assert!(
            HostProjectionOutcome::from_env_file_outcome(&selector, without_generation).is_err()
        );
        let outcome = HostProjectionOutcome::from_env_file_outcome(
            &selector,
            EnvFileOutcome {
                plan: ares.plan(),
                hash_generation: Some("3".repeat(64)),
                reason_code: "ok",
                value_returned: false,
            },
        )
        .unwrap();
        assert_eq!(outcome.generation, "3".repeat(64));
        assert_eq!(
            outcome.projection_ref,
            HostProjectionRef::derive(
                capability,
                &SafeLabel::new("ares").unwrap(),
                &"3".repeat(64)
            )
        );
        assert!(!outcome.value_returned);
    }
}
