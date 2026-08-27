//! Owner/classification metadata overlay for manifest-declared secrets.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{
    JanusError, JanusResult, MaterialLifetime, MaterialLifetimeProvenance, MaterialTimestamp,
    OwnerRef, SafeLabel, SecretClass, SecretLifecycle, SecretMeta, SecretName,
};

const MAX_METADATA_OVERLAY_BYTES: usize = 8 * 1024;

/// Optional owner/class metadata patch.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SecretMetadataPatch {
    /// Owning team/service.
    pub owner: Option<OwnerRef>,
    /// Risk classification.
    pub classification: Option<SecretClass>,
    /// Lifecycle state.
    pub lifecycle: Option<SecretLifecycle>,
    /// Reviewed value-free issuer material lifetime.
    pub material_lifetime: Option<MaterialLifetime>,
}

impl SecretMetadataPatch {
    fn apply_to(&self, meta: &mut SecretMeta) {
        if let Some(owner) = &self.owner {
            meta.owner = Some(owner.clone());
        }
        if let Some(classification) = self.classification {
            meta.classification = Some(classification);
        }
        if let Some(lifecycle) = self.lifecycle {
            meta.lifecycle = lifecycle;
        }
        if let Some(material_lifetime) = &self.material_lifetime {
            meta.material_lifetime = Some(material_lifetime.clone());
        }
    }

    fn to_toml(&self) -> SecretMetadataPatchTomlOut {
        SecretMetadataPatchTomlOut {
            owner: self.owner.as_ref().map(|owner| owner.as_str().to_string()),
            classification: self
                .classification
                .map(|classification| classification.as_str().to_string()),
            lifecycle: self
                .lifecycle
                .map(|lifecycle| lifecycle.as_str().to_string()),
            issued_at: self
                .material_lifetime
                .as_ref()
                .and_then(|lifetime| lifetime.issued_at)
                .map(MaterialTimestamp::to_utc_string),
            not_after: self
                .material_lifetime
                .as_ref()
                .map(|lifetime| lifetime.not_after.to_utc_string()),
            issuer: self
                .material_lifetime
                .as_ref()
                .and_then(|lifetime| lifetime.issuer.as_ref())
                .map(|issuer| issuer.as_str().to_string()),
            lifetime_provenance: self
                .material_lifetime
                .as_ref()
                .and_then(|lifetime| lifetime.provenance)
                .map(|provenance| provenance.as_str().to_string()),
        }
    }
}

/// Value-free metadata overlay matched against manifest secret names.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SecretMetadataOverlay {
    defaults: SecretMetadataPatch,
    secrets: BTreeMap<SecretName, SecretMetadataPatch>,
}

impl SecretMetadataOverlay {
    /// Empty overlay.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Parse a TOML metadata overlay.
    pub fn parse_toml(contents: &str) -> JanusResult<Self> {
        if contents.len() > MAX_METADATA_OVERLAY_BYTES {
            return Err(JanusError::InvalidManifest {
                detail: "metadata overlay exceeds the reviewed size limit".to_string(),
            });
        }
        let parsed: SecretMetadataOverlayToml =
            toml::from_str(contents).map_err(|err| JanusError::InvalidManifest {
                detail: format!("metadata overlay parse failed: {err}"),
            })?;

        let defaults = SecretMetadataPatch::try_from(parsed.defaults)?;
        let mut secrets = BTreeMap::new();
        for entry in parsed.secrets {
            let name = SecretName::new(entry.name)?;
            let patch = SecretMetadataPatch::try_from(SecretMetadataPatchToml {
                owner: entry.owner,
                classification: entry.classification,
                lifecycle: entry.lifecycle,
                issued_at: entry.issued_at,
                not_after: entry.not_after,
                issuer: entry.issuer,
                lifetime_provenance: entry.lifetime_provenance,
            })?;
            if secrets.insert(name.clone(), patch).is_some() {
                return Err(JanusError::InvalidManifest {
                    detail: format!("duplicate metadata entry for {}", name.as_str()),
                });
            }
        }

        Ok(Self { defaults, secrets })
    }

    /// Load a TOML metadata overlay from disk.
    pub fn load_toml_file(path: impl AsRef<Path>) -> JanusResult<Self> {
        let contents =
            fs::read_to_string(path.as_ref()).map_err(|err| JanusError::StoreUnavailable {
                detail: format!("metadata overlay read failed: {err}"),
            })?;
        Self::parse_toml(&contents)
    }

    /// Set or replace the per-secret lifecycle patch while preserving other metadata.
    pub fn set_secret_lifecycle(&mut self, name: SecretName, lifecycle: SecretLifecycle) {
        self.secrets.entry(name).or_default().lifecycle = Some(lifecycle);
    }

    /// Remove one explicit destroyed lifecycle patch after durable retirement evidence exists.
    ///
    /// Callers must separately prove that the secret is no longer declared and that the
    /// corresponding destroy tombstone is durable. A non-destroyed entry is never detached.
    pub fn detach_destroyed_secret(&mut self, name: &SecretName) -> JanusResult<bool> {
        let Some(patch) = self.secrets.get(name) else {
            return Ok(false);
        };
        if patch.lifecycle != Some(SecretLifecycle::Destroyed) {
            return Err(JanusError::InvalidManifest {
                detail: format!(
                    "metadata entry is not explicitly destroyed {}",
                    name.as_str()
                ),
            });
        }
        self.secrets.remove(name);
        Ok(true)
    }

    /// Serialize this overlay to canonical TOML.
    pub fn to_toml_string(&self) -> JanusResult<String> {
        let output = SecretMetadataOverlayTomlOut {
            defaults: self.defaults.to_toml(),
            secrets: self
                .secrets
                .iter()
                .map(|(name, patch)| SecretMetadataEntryTomlOut {
                    name: name.as_str().to_string(),
                    owner: patch.owner.as_ref().map(|owner| owner.as_str().to_string()),
                    classification: patch
                        .classification
                        .map(|classification| classification.as_str().to_string()),
                    lifecycle: patch
                        .lifecycle
                        .map(|lifecycle| lifecycle.as_str().to_string()),
                    issued_at: patch
                        .material_lifetime
                        .as_ref()
                        .and_then(|lifetime| lifetime.issued_at)
                        .map(MaterialTimestamp::to_utc_string),
                    not_after: patch
                        .material_lifetime
                        .as_ref()
                        .map(|lifetime| lifetime.not_after.to_utc_string()),
                    issuer: patch
                        .material_lifetime
                        .as_ref()
                        .and_then(|lifetime| lifetime.issuer.as_ref())
                        .map(|issuer| issuer.as_str().to_string()),
                    lifetime_provenance: patch
                        .material_lifetime
                        .as_ref()
                        .and_then(|lifetime| lifetime.provenance)
                        .map(|provenance| provenance.as_str().to_string()),
                })
                .collect(),
        };
        toml::to_string_pretty(&output).map_err(|err| JanusError::InvalidManifest {
            detail: format!("metadata overlay serialize failed: {err}"),
        })
    }

    /// Apply this overlay to manifest entries, rejecting stale overlay names.
    pub fn apply_to_entries(&self, entries: &mut [SecretMeta]) -> JanusResult<()> {
        let names = entries
            .iter()
            .map(|entry| entry.name.clone())
            .collect::<BTreeSet<_>>();
        self.apply_to_entries_with_manifest_names(entries, &names)
    }

    /// Apply this overlay to selected-profile entries after validating it against every
    /// reviewed manifest profile.
    pub fn apply_to_entries_with_manifest_names(
        &self,
        entries: &mut [SecretMeta],
        manifest_names: &BTreeSet<SecretName>,
    ) -> JanusResult<()> {
        self.validate_manifest_names(manifest_names)?;

        for entry in entries {
            self.defaults.apply_to(entry);
            if let Some(patch) = self.secrets.get(&entry.name) {
                patch.apply_to(entry);
            }
        }
        Ok(())
    }

    /// Reject overlay entries that are absent from every reviewed manifest profile.
    pub fn validate_manifest_names(
        &self,
        manifest_names: &BTreeSet<SecretName>,
    ) -> JanusResult<()> {
        for name in self.secrets.keys() {
            if !manifest_names.contains(name) {
                return Err(JanusError::InvalidManifest {
                    detail: format!("metadata entry has no manifest secret {}", name.as_str()),
                });
            }
        }
        Ok(())
    }
}

impl TryFrom<SecretMetadataPatchToml> for SecretMetadataPatch {
    type Error = JanusError;

    fn try_from(value: SecretMetadataPatchToml) -> Result<Self, Self::Error> {
        Ok(Self {
            owner: value.owner.map(OwnerRef::new).transpose()?,
            classification: value
                .classification
                .as_deref()
                .map(SecretClass::parse)
                .transpose()?,
            lifecycle: value
                .lifecycle
                .as_deref()
                .map(SecretLifecycle::parse)
                .transpose()?,
            material_lifetime: parse_reviewed_lifetime(
                value.issued_at,
                value.not_after,
                value.issuer,
                value.lifetime_provenance,
            )?,
        })
    }
}

fn parse_reviewed_lifetime(
    issued_at: Option<String>,
    not_after: Option<String>,
    issuer: Option<String>,
    provenance: Option<String>,
) -> JanusResult<Option<MaterialLifetime>> {
    let any_lifetime_field =
        issued_at.is_some() || not_after.is_some() || issuer.is_some() || provenance.is_some();
    if !any_lifetime_field {
        return Ok(None);
    }
    let not_after = not_after.ok_or_else(|| JanusError::InvalidManifest {
        detail: "material lifetime metadata requires not_after".to_string(),
    })?;
    let issued_at = issued_at
        .as_deref()
        .map(MaterialTimestamp::parse_utc)
        .transpose()
        .map_err(lifetime_manifest_error)?;
    let not_after = MaterialTimestamp::parse_utc(&not_after).map_err(lifetime_manifest_error)?;
    let issuer = issuer.map(SafeLabel::new).transpose()?;
    let provenance = provenance
        .as_deref()
        .map(MaterialLifetimeProvenance::parse)
        .transpose()
        .map_err(lifetime_manifest_error)?
        .unwrap_or(MaterialLifetimeProvenance::ReviewedManual);
    if provenance != MaterialLifetimeProvenance::ReviewedManual {
        return Err(JanusError::InvalidManifest {
            detail: "manual metadata overlay requires reviewed_manual provenance".to_string(),
        });
    }
    MaterialLifetime::new(issued_at, not_after, issuer, Some(provenance))
        .map(Some)
        .map_err(lifetime_manifest_error)
}

fn lifetime_manifest_error(error: crate::MaterialLifetimeError) -> JanusError {
    JanusError::InvalidManifest {
        detail: format!(
            "material lifetime metadata invalid: {}",
            error.reason_code()
        ),
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretMetadataOverlayToml {
    #[serde(default)]
    defaults: SecretMetadataPatchToml,
    #[serde(default)]
    secrets: Vec<SecretMetadataEntryToml>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretMetadataPatchToml {
    owner: Option<String>,
    classification: Option<String>,
    lifecycle: Option<String>,
    issued_at: Option<String>,
    not_after: Option<String>,
    issuer: Option<String>,
    lifetime_provenance: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretMetadataEntryToml {
    name: String,
    owner: Option<String>,
    classification: Option<String>,
    lifecycle: Option<String>,
    issued_at: Option<String>,
    not_after: Option<String>,
    issuer: Option<String>,
    lifetime_provenance: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct SecretMetadataOverlayTomlOut {
    #[serde(skip_serializing_if = "SecretMetadataPatchTomlOut::is_empty")]
    defaults: SecretMetadataPatchTomlOut,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    secrets: Vec<SecretMetadataEntryTomlOut>,
}

#[derive(Clone, Debug, Default, Serialize)]
struct SecretMetadataPatchTomlOut {
    #[serde(skip_serializing_if = "Option::is_none")]
    owner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    classification: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lifecycle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    issued_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    not_after: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lifetime_provenance: Option<String>,
}

impl SecretMetadataPatchTomlOut {
    fn is_empty(&self) -> bool {
        self.owner.is_none()
            && self.classification.is_none()
            && self.lifecycle.is_none()
            && self.issued_at.is_none()
            && self.not_after.is_none()
            && self.issuer.is_none()
            && self.lifetime_provenance.is_none()
    }
}

#[derive(Clone, Debug, Serialize)]
struct SecretMetadataEntryTomlOut {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    classification: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lifecycle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    issued_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    not_after: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lifetime_provenance: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProfileId, SafeLabel, SecretRef, TrustLevel};

    fn meta(name: &str) -> SecretMeta {
        let scope = crate::test_scope("dev");
        let name = SecretName::new(name).unwrap();
        SecretMeta {
            secret_ref: SecretRef::for_manifest_entry(&scope, &name),
            name,
            label: SafeLabel::new("Canary").unwrap(),
            scope,
            owner: None,
            classification: None,
            lifecycle: SecretLifecycle::Active,
            required: true,
            trust_level: TrustLevel::L1,
            allowed_uses: vec![ProfileId::new("profile.canary").unwrap()],
            material_lifetime: None,
        }
    }

    #[test]
    fn overlay_applies_defaults_and_per_secret_overrides() {
        let overlay = SecretMetadataOverlay::parse_toml(
            r#"
            [defaults]
            owner = "infra"
            classification = "normal"
            lifecycle = "active"

            [[secrets]]
            name = "CANARY"
            owner = "security"
            classification = "high_value"
            lifecycle = "disabled"
            "#,
        )
        .unwrap();
        let mut entries = vec![meta("CANARY"), meta("OTHER")];

        overlay.apply_to_entries(&mut entries).unwrap();

        assert_eq!(entries[0].owner.as_ref().unwrap().as_str(), "security");
        assert_eq!(entries[0].classification, Some(SecretClass::HighValue));
        assert_eq!(entries[0].lifecycle, SecretLifecycle::Disabled);
        assert_eq!(entries[1].owner.as_ref().unwrap().as_str(), "infra");
        assert_eq!(entries[1].classification, Some(SecretClass::Normal));
        assert_eq!(entries[1].lifecycle, SecretLifecycle::Active);
    }

    #[test]
    fn overlay_rejects_duplicate_unknown_and_invalid_class_entries() {
        let duplicate = SecretMetadataOverlay::parse_toml(
            r#"
            [[secrets]]
            name = "CANARY"
            owner = "infra"

            [[secrets]]
            name = "CANARY"
            classification = "normal"
            "#,
        )
        .unwrap_err();
        assert!(matches!(duplicate, JanusError::InvalidManifest { .. }));

        let mut entries = vec![meta("CANARY")];
        let stale = SecretMetadataOverlay::parse_toml(
            r#"
            [[secrets]]
            name = "STALE"
            owner = "infra"
            classification = "normal"
            "#,
        )
        .unwrap();
        let err = stale.apply_to_entries(&mut entries).unwrap_err();
        assert!(matches!(err, JanusError::InvalidManifest { .. }));

        let invalid = SecretMetadataOverlay::parse_toml(
            r#"
            [defaults]
            classification = "critical"
            "#,
        )
        .unwrap_err();
        assert!(matches!(invalid, JanusError::InvalidIdentifier { .. }));

        let invalid_lifecycle = SecretMetadataOverlay::parse_toml(
            r#"
            [defaults]
            lifecycle = "deleted"
            "#,
        )
        .unwrap_err();
        assert!(matches!(
            invalid_lifecycle,
            JanusError::InvalidIdentifier { .. }
        ));
    }

    #[test]
    fn overlay_updates_lifecycle_and_serializes_without_losing_metadata() {
        let mut overlay = SecretMetadataOverlay::parse_toml(
            r#"
            [defaults]
            owner = "infra"
            classification = "normal"
            lifecycle = "active"

            [[secrets]]
            name = "CANARY"
            owner = "security"
            classification = "high_value"
            lifecycle = "active"
            "#,
        )
        .unwrap();

        overlay.set_secret_lifecycle(
            SecretName::new("CANARY").unwrap(),
            SecretLifecycle::Disabled,
        );
        overlay.set_secret_lifecycle(
            SecretName::new("OTHER").unwrap(),
            SecretLifecycle::PendingDelete,
        );
        let encoded = overlay.to_toml_string().unwrap();
        let round_tripped = SecretMetadataOverlay::parse_toml(&encoded).unwrap();
        let mut entries = vec![meta("CANARY"), meta("OTHER")];

        round_tripped.apply_to_entries(&mut entries).unwrap();

        assert_eq!(entries[0].owner.as_ref().unwrap().as_str(), "security");
        assert_eq!(entries[0].classification, Some(SecretClass::HighValue));
        assert_eq!(entries[0].lifecycle, SecretLifecycle::Disabled);
        assert_eq!(entries[1].owner.as_ref().unwrap().as_str(), "infra");
        assert_eq!(entries[1].classification, Some(SecretClass::Normal));
        assert_eq!(entries[1].lifecycle, SecretLifecycle::PendingDelete);
    }

    #[test]
    fn scoped_application_accepts_other_profile_entries_without_applying_them() {
        let overlay = SecretMetadataOverlay::parse_toml(
            r#"
            [defaults]
            owner = "infra"

            [[secrets]]
            name = "OTHER_PROFILE"
            lifecycle = "disabled"
            "#,
        )
        .unwrap();
        let mut entries = vec![meta("SELECTED")];
        let manifest_names = [
            SecretName::new("SELECTED").unwrap(),
            SecretName::new("OTHER_PROFILE").unwrap(),
        ]
        .into_iter()
        .collect();

        overlay
            .apply_to_entries_with_manifest_names(&mut entries, &manifest_names)
            .unwrap();

        assert_eq!(entries[0].name.as_str(), "SELECTED");
        assert_eq!(entries[0].lifecycle, SecretLifecycle::Active);
        assert_eq!(entries[0].owner.as_ref().unwrap().as_str(), "infra");
    }

    #[test]
    fn destroyed_entry_detach_is_exact_and_idempotent() {
        let name = SecretName::new("CANARY").unwrap();
        let mut overlay = SecretMetadataOverlay::parse_toml(
            r#"
            [[secrets]]
            name = "CANARY"
            owner = "security"
            lifecycle = "destroyed"
            "#,
        )
        .unwrap();

        assert!(overlay.detach_destroyed_secret(&name).unwrap());
        assert!(!overlay.detach_destroyed_secret(&name).unwrap());
        assert!(!overlay.to_toml_string().unwrap().contains("CANARY"));

        let mut active = SecretMetadataOverlay::parse_toml(
            r#"
            [[secrets]]
            name = "CANARY"
            lifecycle = "active"
            "#,
        )
        .unwrap();
        assert!(matches!(
            active.detach_destroyed_secret(&name),
            Err(JanusError::InvalidManifest { .. })
        ));
    }

    #[test]
    fn reviewed_overlay_applies_and_round_trips_material_lifetime() {
        let overlay = SecretMetadataOverlay::parse_toml(
            r#"
            [[secrets]]
            name = "CANARY"
            issued_at = "2026-01-01T00:00:00Z"
            not_after = "2027-01-01T00:00:00Z"
            issuer = "issuer_fixture"
            lifetime_provenance = "reviewed_manual"
            "#,
        )
        .unwrap();
        let encoded = overlay.to_toml_string().unwrap();
        let round_tripped = SecretMetadataOverlay::parse_toml(&encoded).unwrap();
        let mut entries = vec![meta("CANARY")];

        round_tripped.apply_to_entries(&mut entries).unwrap();

        let lifetime = entries[0].material_lifetime.as_ref().unwrap();
        assert_eq!(lifetime.not_after.to_utc_string(), "2027-01-01T00:00:00Z");
        assert_eq!(
            lifetime.provenance,
            Some(MaterialLifetimeProvenance::ReviewedManual)
        );
    }

    #[test]
    fn reviewed_overlay_rejects_missing_and_malformed_dates_value_free() {
        let missing = SecretMetadataOverlay::parse_toml(
            r#"
            [[secrets]]
            name = "CANARY"
            issuer = "issuer_fixture"
            "#,
        )
        .unwrap_err();
        assert!(matches!(missing, JanusError::InvalidManifest { .. }));

        let marker = "malformed_fixture_marker";
        let malformed = SecretMetadataOverlay::parse_toml(&format!(
            "[[secrets]]\nname = \"CANARY\"\nnot_after = \"{marker}\"\n"
        ))
        .unwrap_err();
        let rendered = malformed.to_string();
        assert!(rendered.contains("material_lifetime_date_malformed"));
        assert!(!rendered.contains(marker));
    }
}
