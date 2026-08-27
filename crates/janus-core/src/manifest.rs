//! Manifest-derived allowlist catalog.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::path::Path;

use serde::Deserialize;

use crate::{
    JanusError, JanusResult, ProfileId, ProjectId, SafeLabel, ScopeRef, SecretDescriptor,
    SecretLifecycle, SecretMeta, SecretMetadataOverlay, SecretName, SecretRef, TrustLevel,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretspecManifestToml {
    project: SecretspecProjectToml,
    profiles: BTreeMap<String, SecretspecProfileToml>,
    #[serde(default)]
    scopes: BTreeMap<String, SecretspecScopeToml>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretspecProjectToml {
    name: String,
    revision: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct SecretspecProfileToml {
    #[serde(default)]
    defaults: SecretspecDefaultsToml,
    #[serde(flatten)]
    secrets: BTreeMap<String, SecretspecSecretToml>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretspecDefaultsToml {
    inherit: Option<bool>,
    required: Option<bool>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretspecSecretToml {
    description: Option<String>,
    required: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretspecScopeToml {
    secrets: Vec<String>,
}

/// Load the strict Secretspec manifest subset that Janus uses as its allowlist.
///
/// Janus intentionally parses only project identity, profile and scope membership,
/// descriptions, and required flags. Provider construction and secret generation
/// stay outside this parser, so an unused RSA generator cannot enter the production
/// graph.
pub fn load_secretspec_manifest_catalog(
    path: impl AsRef<Path>,
    profile: &str,
    scope: &ScopeRef,
    metadata: Option<&SecretMetadataOverlay>,
) -> JanusResult<(ProjectId, ManifestCatalog)> {
    load_secretspec_manifest_catalog_with_membership_scope(path, profile, None, scope, metadata)
}

/// Load the strict Secretspec manifest subset with an optional membership scope.
pub fn load_secretspec_manifest_catalog_with_membership_scope(
    path: impl AsRef<Path>,
    profile: &str,
    membership_scope: Option<&str>,
    scope: &ScopeRef,
    metadata: Option<&SecretMetadataOverlay>,
) -> JanusResult<(ProjectId, ManifestCatalog)> {
    let content = fs::read_to_string(path).map_err(|err| JanusError::StoreUnavailable {
        detail: format!("secretspec manifest could not be read: {}", err.kind()),
    })?;
    parse_secretspec_manifest_catalog(&content, profile, membership_scope, scope, metadata)
}

/// Load every valid secret name declared by any reviewed Secretspec profile.
pub fn load_secretspec_manifest_secret_names(
    path: impl AsRef<Path>,
) -> JanusResult<BTreeSet<SecretName>> {
    let content = fs::read_to_string(path).map_err(|err| JanusError::StoreUnavailable {
        detail: format!("secretspec manifest could not be read: {}", err.kind()),
    })?;
    let parsed = parse_secretspec_manifest(&content)?;
    secretspec_manifest_secret_names(&parsed)
}

fn parse_secretspec_manifest_catalog(
    content: &str,
    profile: &str,
    membership_scope: Option<&str>,
    scope: &ScopeRef,
    metadata: Option<&SecretMetadataOverlay>,
) -> JanusResult<(ProjectId, ManifestCatalog)> {
    if profile.is_empty() || profile.trim() != profile {
        return Err(JanusError::InvalidManifest {
            detail: "secretspec profile is invalid".to_string(),
        });
    }
    let parsed = parse_secretspec_manifest(content)?;
    let manifest_names = secretspec_manifest_secret_names(&parsed)?;
    let selected_profile =
        parsed
            .profiles
            .get(profile)
            .ok_or_else(|| JanusError::InvalidManifest {
                detail: "selected secretspec profile is not declared".to_string(),
            })?;
    let mut secrets = resolve_secretspec_profile(&parsed, profile, selected_profile);
    if secrets.is_empty() {
        return Err(JanusError::InvalidManifest {
            detail: "secretspec profile has no declared secrets".to_string(),
        });
    }
    if let Some(membership_scope) = membership_scope {
        if membership_scope.is_empty() || membership_scope.trim() != membership_scope {
            return Err(JanusError::InvalidManifest {
                detail: "selected secretspec scope is invalid".to_string(),
            });
        }
        let selected_scope =
            parsed
                .scopes
                .get(membership_scope)
                .ok_or_else(|| JanusError::InvalidManifest {
                    detail: "selected secretspec scope is not declared".to_string(),
                })?;
        if selected_scope.secrets.is_empty() {
            return Err(JanusError::InvalidManifest {
                detail: "selected secretspec scope has no secrets".to_string(),
            });
        }
        let mut selected_names = BTreeSet::new();
        for name in &selected_scope.secrets {
            if SecretName::new(name.clone()).is_err()
                || !selected_names.insert(name.clone())
                || !secrets.contains_key(name)
            {
                return Err(JanusError::InvalidManifest {
                    detail: "selected secretspec scope contains invalid membership".to_string(),
                });
            }
        }
        secrets.retain(|name, _| selected_names.contains(name));
    }

    let project = ProjectId::new(parsed.project.name)?;
    let mut entries = Vec::with_capacity(secrets.len());
    for (name, secret) in &secrets {
        let name = SecretName::new(name.clone())?;
        entries.push(SecretMeta {
            secret_ref: SecretRef::for_manifest_entry(scope, &name),
            name: name.clone(),
            label: SafeLabel::new(
                secret
                    .description
                    .clone()
                    .unwrap_or_else(|| "Manifest-declared secret".to_string()),
            )?,
            scope: scope.clone(),
            owner: None,
            classification: None,
            lifecycle: SecretLifecycle::Active,
            required: secret
                .required
                .or(selected_profile.defaults.required)
                .unwrap_or(true),
            trust_level: TrustLevel::L1,
            allowed_uses: vec![ProfileId::new(format!("profile.{}", name.as_str()))?],
        });
    }
    if let Some(metadata) = metadata {
        metadata.apply_to_entries_with_manifest_names(&mut entries, &manifest_names)?;
    }
    Ok((project, ManifestCatalog::new(entries)?))
}

fn resolve_secretspec_profile(
    manifest: &SecretspecManifestToml,
    profile_name: &str,
    selected: &SecretspecProfileToml,
) -> BTreeMap<String, SecretspecSecretToml> {
    let inherit_default = profile_name != "default" && selected.defaults.inherit.unwrap_or(true);
    let mut resolved = if inherit_default {
        manifest
            .profiles
            .get("default")
            .map(|profile| profile.secrets.clone())
            .unwrap_or_default()
    } else {
        BTreeMap::new()
    };
    for (name, current) in &selected.secrets {
        let inherited = resolved.get(name);
        resolved.insert(
            name.clone(),
            SecretspecSecretToml {
                description: current
                    .description
                    .clone()
                    .or_else(|| inherited.and_then(|secret| secret.description.clone())),
                required: current
                    .required
                    .or_else(|| inherited.and_then(|secret| secret.required)),
            },
        );
    }
    resolved
}

fn parse_secretspec_manifest(content: &str) -> JanusResult<SecretspecManifestToml> {
    let parsed: SecretspecManifestToml =
        toml::from_str(content).map_err(|_| JanusError::InvalidManifest {
            detail: "secretspec manifest schema is invalid".to_string(),
        })?;
    if parsed.project.name.is_empty()
        || parsed.project.name.trim() != parsed.project.name
        || parsed.project.revision.is_empty()
        || parsed.project.revision.trim() != parsed.project.revision
    {
        return Err(JanusError::InvalidManifest {
            detail: "secretspec project identity is invalid".to_string(),
        });
    }
    validate_secretspec_scopes(&parsed)?;
    Ok(parsed)
}

fn validate_secretspec_scopes(manifest: &SecretspecManifestToml) -> JanusResult<()> {
    let manifest_names = secretspec_manifest_secret_names(manifest)?;
    for (name, scope) in &manifest.scopes {
        if name.is_empty() || name.trim() != name {
            return Err(JanusError::InvalidManifest {
                detail: "secretspec scope name is invalid".to_string(),
            });
        }
        if scope.secrets.is_empty() {
            return Err(JanusError::InvalidManifest {
                detail: "selected secretspec scope has no secrets".to_string(),
            });
        }
        let mut members = BTreeSet::new();
        for name in &scope.secrets {
            let Ok(name) = SecretName::new(name.clone()) else {
                return Err(JanusError::InvalidManifest {
                    detail: "selected secretspec scope contains invalid membership".to_string(),
                });
            };
            if !members.insert(name.clone()) || !manifest_names.contains(&name) {
                return Err(JanusError::InvalidManifest {
                    detail: "selected secretspec scope contains invalid membership".to_string(),
                });
            }
        }
    }
    Ok(())
}

fn secretspec_manifest_secret_names(
    manifest: &SecretspecManifestToml,
) -> JanusResult<BTreeSet<SecretName>> {
    manifest
        .profiles
        .values()
        .flat_map(|profile| profile.secrets.keys())
        .map(|name| SecretName::new(name.clone()))
        .collect()
}

/// Manifest allowlist with stable name-to-ref mapping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestCatalog {
    entries: Vec<SecretMeta>,
}

impl ManifestCatalog {
    /// Construct a catalog from manifest metadata.
    pub fn new(entries: Vec<SecretMeta>) -> JanusResult<Self> {
        let mut names = HashSet::new();
        let mut refs = HashSet::new();
        for entry in &entries {
            if !names.insert(entry.name.clone()) {
                return Err(JanusError::InvalidManifest {
                    detail: format!("duplicate secret name {}", entry.name.as_str()),
                });
            }
            if !refs.insert(entry.secret_ref.clone()) {
                return Err(JanusError::InvalidManifest {
                    detail: format!("duplicate secret ref {}", entry.secret_ref.as_str()),
                });
            }
        }
        Ok(Self { entries })
    }

    /// Borrow the catalog entries.
    pub fn entries(&self) -> &[SecretMeta] {
        &self.entries
    }

    /// Find manifest metadata by name.
    pub fn meta_by_name(&self, name: &SecretName) -> JanusResult<&SecretMeta> {
        self.entries
            .iter()
            .find(|entry| &entry.name == name)
            .ok_or_else(|| JanusError::NotInManifest {
                name: name.as_str().to_string(),
            })
    }

    /// Find manifest metadata by opaque ref.
    pub fn meta_by_ref(&self, secret_ref: &SecretRef) -> JanusResult<&SecretMeta> {
        self.entries
            .iter()
            .find(|entry| &entry.secret_ref == secret_ref)
            .ok_or_else(|| JanusError::NotInManifest {
                name: secret_ref.as_str().to_string(),
            })
    }

    /// Build a descriptor with caller-supplied presence.
    pub fn descriptor_by_name(
        &self,
        name: &SecretName,
        present: bool,
    ) -> JanusResult<SecretDescriptor> {
        Ok(self.meta_by_name(name)?.descriptor(present))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OwnerRef, ProfileId, SafeLabel, SecretClass, SecretLifecycle, TrustLevel};

    fn meta(name: &str) -> SecretMeta {
        let scope = crate::test_scope("dev");
        let name = SecretName::new(name).unwrap();
        SecretMeta {
            secret_ref: SecretRef::for_manifest_entry(&scope, &name),
            name,
            label: SafeLabel::new("Canary").unwrap(),
            scope,
            owner: Some(OwnerRef::new("infra").unwrap()),
            classification: Some(SecretClass::Normal),
            lifecycle: SecretLifecycle::Active,
            required: true,
            trust_level: TrustLevel::L1,
            allowed_uses: vec![ProfileId::new("profile.canary").unwrap()],
        }
    }

    #[test]
    fn catalog_denies_non_manifest_names() {
        let catalog = ManifestCatalog::new(vec![meta("CANARY")]).unwrap();
        let err = catalog
            .meta_by_name(&SecretName::new("OTHER").unwrap())
            .unwrap_err();
        assert!(matches!(err, JanusError::NotInManifest { .. }));
    }

    #[test]
    fn catalog_rejects_duplicate_names() {
        let err = ManifestCatalog::new(vec![meta("CANARY"), meta("CANARY")]).unwrap_err();
        assert!(matches!(err, JanusError::InvalidManifest { .. }));
    }

    #[test]
    fn strict_secretspec_subset_builds_a_deterministic_catalog() {
        let scope = crate::test_scope("dev");
        let (project, catalog) = parse_secretspec_manifest_catalog(
            r#"
            [project]
            name = "janus"
            revision = "1.0"

            [profiles.default]
            defaults = { required = false }
            OPTIONAL = { description = "Optional fixture" }
            REQUIRED = { description = "Required fixture", required = true }
            "#,
            "default",
            None,
            &scope,
            None,
        )
        .unwrap();

        assert_eq!(project.as_str(), "janus");
        assert_eq!(catalog.entries().len(), 2);
        assert_eq!(catalog.entries()[0].name.as_str(), "OPTIONAL");
        assert!(!catalog.entries()[0].required);
        assert_eq!(catalog.entries()[1].name.as_str(), "REQUIRED");
        assert!(catalog.entries()[1].required);
    }

    #[test]
    fn non_default_profile_inherits_default_and_overrides_fields() {
        let scope = crate::test_scope("dev");
        let (_, catalog) = parse_secretspec_manifest_catalog(
            r#"
            [project]
            name = "janus"
            revision = "1.0"

            [profiles.default]
            SHARED = { description = "Shared fixture", required = false }
            DEFAULT_ONLY = { description = "Default fixture", required = true }

            [profiles.production.defaults]
            required = false

            [profiles.production]
            SHARED = { description = "Production fixture", required = true }
            PRODUCTION_ONLY = { description = "Production-only fixture" }
            "#,
            "production",
            None,
            &scope,
            None,
        )
        .unwrap();

        assert_eq!(catalog.entries().len(), 3);
        assert_eq!(catalog.entries()[0].name.as_str(), "DEFAULT_ONLY");
        assert!(catalog.entries()[0].required);
        assert_eq!(catalog.entries()[1].name.as_str(), "PRODUCTION_ONLY");
        assert!(!catalog.entries()[1].required);
        assert_eq!(catalog.entries()[2].name.as_str(), "SHARED");
        assert_eq!(catalog.entries()[2].label.as_str(), "Production fixture");
        assert!(catalog.entries()[2].required);
    }

    #[test]
    fn non_default_profile_can_disable_default_inheritance() {
        let scope = crate::test_scope("dev");
        let (_, catalog) = parse_secretspec_manifest_catalog(
            r#"
            [project]
            name = "janus"
            revision = "1.0"

            [profiles.default]
            DEFAULT_ONLY = { description = "Default fixture" }

            [profiles.production.defaults]
            inherit = false

            [profiles.production]
            PRODUCTION_ONLY = { description = "Production fixture" }
            "#,
            "production",
            None,
            &scope,
            None,
        )
        .unwrap();

        assert_eq!(catalog.entries().len(), 1);
        assert_eq!(catalog.entries()[0].name.as_str(), "PRODUCTION_ONLY");
    }

    #[test]
    fn missing_named_profile_fails_closed() {
        let scope = crate::test_scope("dev");
        let error = parse_secretspec_manifest_catalog(
            r#"
            [project]
            name = "janus"
            revision = "1.0"

            [profiles.default]
            CANARY = { description = "Canary" }
            "#,
            "production",
            None,
            &scope,
            None,
        )
        .unwrap_err();

        assert!(matches!(error, JanusError::InvalidManifest { .. }));
    }

    #[test]
    fn membership_scope_filters_the_resolved_profile() {
        let scope = crate::test_scope("dev");
        let manifest = r#"
            [project]
            name = "janus"
            revision = "1.0"

            [profiles.default]
            SHARED = { description = "Shared fixture" }

            [profiles.production]
            PRODUCTION_ONLY = { description = "Production fixture" }

            [scopes.worker]
            secrets = ["SHARED"]
        "#;
        let (_, filtered) =
            parse_secretspec_manifest_catalog(manifest, "production", Some("worker"), &scope, None)
                .unwrap();
        assert_eq!(filtered.entries().len(), 1);
        assert_eq!(filtered.entries()[0].name.as_str(), "SHARED");

        let (_, unfiltered) =
            parse_secretspec_manifest_catalog(manifest, "production", None, &scope, None).unwrap();
        assert_eq!(unfiltered.entries().len(), 2);
    }

    #[test]
    fn invalid_membership_scope_selections_fail_closed_with_value_free_reasons() {
        let scope = crate::test_scope("dev");
        for (case, manifest, profile, selected_scope, expected_detail) in [
            (
                "unknown scope",
                r#"
                [project]
                name = "janus"
                revision = "1.0"
                [profiles.default]
                CANARY = { description = "Canary" }
                "#,
                "default",
                "missing",
                "selected secretspec scope is not declared",
            ),
            (
                "empty scope",
                r#"
                [project]
                name = "janus"
                revision = "1.0"
                [profiles.default]
                CANARY = { description = "Canary" }
                [scopes.worker]
                secrets = []
                "#,
                "default",
                "worker",
                "selected secretspec scope has no secrets",
            ),
            (
                "scope member outside selected profile",
                r#"
                [project]
                name = "janus"
                revision = "1.0"
                [profiles.default]
                DEFAULT_ONLY = { description = "Default fixture" }
                [profiles.production.defaults]
                inherit = false
                [profiles.production]
                PRODUCTION_ONLY = { description = "Production fixture" }
                [scopes.worker]
                secrets = ["DEFAULT_ONLY"]
                "#,
                "production",
                "worker",
                "selected secretspec scope contains invalid membership",
            ),
        ] {
            let error = parse_secretspec_manifest_catalog(
                manifest,
                profile,
                Some(selected_scope),
                &scope,
                None,
            )
            .unwrap_err();
            match error {
                JanusError::InvalidManifest { detail } => {
                    assert_eq!(detail, expected_detail, "{case}")
                }
                other => panic!("{case} returned unexpected error: {other:?}"),
            }
        }
    }

    #[test]
    fn invalid_scope_declarations_are_not_ignored_when_scope_is_unset() {
        let scope = crate::test_scope("dev");
        let error = parse_secretspec_manifest_catalog(
            r#"
            [project]
            name = "janus"
            revision = "1.0"
            [profiles.default]
            CANARY = { description = "Canary" }
            [scopes.worker]
            secrets = []
            "#,
            "default",
            None,
            &scope,
            None,
        )
        .unwrap_err();

        assert!(matches!(error, JanusError::InvalidManifest { .. }));
    }

    #[test]
    fn strict_secretspec_subset_rejects_every_authority_and_value_field() {
        let scope = crate::test_scope("dev");
        for (field, unsupported) in [
            (
                "project.provider",
                r#"
            [project]
            name = "janus"
            revision = "1.0"
            provider = "dotenv:.env"
            [profiles.default]
            CANARY = { description = "Canary" }
            "#,
            ),
            (
                "project.extends",
                r#"
            [project]
            name = "janus"
            revision = "1.0"
            extends = ["fixture"]
            [profiles.default]
            CANARY = { description = "Canary" }
            "#,
            ),
            (
                "project.require_reason",
                r#"
            [project]
            name = "janus"
            revision = "1.0"
            require_reason = true
            [profiles.default]
            CANARY = { description = "Canary" }
            "#,
            ),
            (
                "providers",
                r#"
            [project]
            name = "janus"
            revision = "1.0"
            [profiles.default]
            CANARY = { description = "Canary", providers = [] }
            "#,
            ),
            (
                "ref",
                r#"
            [project]
            name = "janus"
            revision = "1.0"
            [profiles.default]
            CANARY = { description = "Canary", ref = {} }
            "#,
            ),
            (
                "refs",
                r#"
            [project]
            name = "janus"
            revision = "1.0"
            [profiles.default]
            CANARY = { description = "Canary", refs = {} }
            "#,
            ),
            (
                "generate",
                r#"
            [project]
            name = "janus"
            revision = "1.0"
            [profiles.default]
            CANARY = { description = "Canary", generate = true }
            "#,
            ),
            (
                "type",
                r#"
            [project]
            name = "janus"
            revision = "1.0"
            [profiles.default]
            CANARY = { description = "Canary", type = "password" }
            "#,
            ),
            (
                "default",
                r#"
            [project]
            name = "janus"
            revision = "1.0"
            [profiles.default]
            CANARY = { description = "Canary", default = "" }
            "#,
            ),
            (
                "composed",
                r#"
            [project]
            name = "janus"
            revision = "1.0"
            [profiles.default]
            CANARY = { description = "Canary", composed = "${CANARY}" }
            "#,
            ),
            (
                "extract",
                r#"
            [project]
            name = "janus"
            revision = "1.0"
            [profiles.default]
            CANARY = { description = "Canary", extract = {} }
            "#,
            ),
            (
                "encoding",
                r#"
            [project]
            name = "janus"
            revision = "1.0"
            [profiles.default]
            CANARY = { description = "Canary", encoding = "base64" }
            "#,
            ),
            (
                "prompt",
                r#"
            [project]
            name = "janus"
            revision = "1.0"
            [profiles.default]
            CANARY = { description = "Canary", prompt = true }
            "#,
            ),
            (
                "as_path",
                r#"
            [project]
            name = "janus"
            revision = "1.0"
            [profiles.default]
            CANARY = { description = "Canary", as_path = true }
            "#,
            ),
            (
                "top-level providers table",
                r#"
            [project]
            name = "janus"
            revision = "1.0"
            [profiles.default]
            CANARY = { description = "Canary" }
            [providers]
            fixture = "dotenv:fixture.env"
            "#,
            ),
            (
                "defaults.default",
                r#"
            [project]
            name = "janus"
            revision = "1.0"
            [profiles.default]
            defaults = { default = "" }
            CANARY = { description = "Canary" }
            "#,
            ),
            (
                "defaults.providers",
                r#"
            [project]
            name = "janus"
            revision = "1.0"
            [profiles.default]
            defaults = { providers = [] }
            CANARY = { description = "Canary" }
            "#,
            ),
        ] {
            let err = parse_secretspec_manifest_catalog(unsupported, "default", None, &scope, None)
                .unwrap_err();
            assert!(
                matches!(err, JanusError::InvalidManifest { .. }),
                "unsupported field {field} did not fail closed"
            );
        }
    }

    #[test]
    fn overlay_is_validated_globally_but_applied_only_to_selected_profile() {
        let scope = crate::test_scope("dev");
        let overlay = SecretMetadataOverlay::parse_toml(
            r#"
            [[secrets]]
            name = "PRODUCTION_ONLY"
            lifecycle = "disabled"
            "#,
        )
        .unwrap();
        let (_, catalog) = parse_secretspec_manifest_catalog(
            r#"
            [project]
            name = "janus"
            revision = "1.0"

            [profiles.default]
            DEFAULT_ONLY = { description = "Default fixture" }

            [profiles.production]
            PRODUCTION_ONLY = { description = "Production fixture" }
            "#,
            "default",
            None,
            &scope,
            Some(&overlay),
        )
        .unwrap();

        assert_eq!(catalog.entries().len(), 1);
        assert_eq!(catalog.entries()[0].name.as_str(), "DEFAULT_ONLY");
        assert_eq!(catalog.entries()[0].lifecycle, SecretLifecycle::Active);
    }

    #[test]
    fn overlay_name_absent_from_every_profile_is_rejected() {
        let scope = crate::test_scope("dev");
        let overlay = SecretMetadataOverlay::parse_toml(
            r#"
            [[secrets]]
            name = "REMOVED"
            lifecycle = "destroyed"
            "#,
        )
        .unwrap();
        let error = parse_secretspec_manifest_catalog(
            r#"
            [project]
            name = "janus"
            revision = "1.0"

            [profiles.default]
            CANARY = { description = "Canary" }
            "#,
            "default",
            None,
            &scope,
            Some(&overlay),
        )
        .unwrap_err();

        assert!(matches!(error, JanusError::InvalidManifest { .. }));
    }
}
