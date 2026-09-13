//! Closed issuer aliases and the value-free resolver boundary.
//!
//! Forge owns this contract; concrete connector implementations live in the
//! issuer module and never expose a resolved value to a caller-facing API.

#![forbid(unsafe_code)]

use async_trait::async_trait;
use janus_core::{JanusError, JanusResult, SecretValue};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub mod invalidation;
pub mod tofu;
pub mod zitadel;

pub use invalidation::{
    invalidate_issuer_credential, IssuerInvalidationEvidence, IssuerInvalidationOutcome,
    IssuerInvalidator,
};

pub use tofu::{TofuOutputConfig, TofuOutputConnector};
pub use zitadel::{
    SystemIssuerClock, UreqZitadelTransport, ZitadelIssuerClock, ZitadelOidcClientConfig,
    ZitadelOidcClientConnector, ZitadelTransport,
};

/// Maximum bytes accepted from one issuer resolution.
pub const MAX_ISSUER_VALUE_BYTES: usize = 4096;
const MAX_ISSUER_CATALOG_BYTES: usize = 64 * 1024;
const MAX_ISSUER_CONNECTORS: usize = 32;
/// Schema identifier for the closed issuer connector catalog.
pub const ISSUER_CONNECTOR_SCHEMA: &str = "janus.issuer-connectors.v1";

/// The only issuer kinds supported by the generated-create contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum IssuerKind {
    /// Regenerate an OIDC client secret through a configured Zitadel client.
    ZitadelOidcClient,
    /// Read an existing sensitive output from a configured local state source.
    TofuOutput,
}

impl IssuerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ZitadelOidcClient => "zitadel-oidc-client",
            Self::TofuOutput => "tofu-output",
        }
    }

    fn parse(value: &str) -> JanusResult<Self> {
        match value {
            "zitadel-oidc-client" => Ok(Self::ZitadelOidcClient),
            "tofu-output" => Ok(Self::TofuOutput),
            _ => Err(JanusError::Unsupported {
                capability: "issuer_kind",
            }),
        }
    }
}

/// A strict, canonical issuer alias. The reference is an opaque configured
/// selector; it is never interpreted as a path, URL, or command argument.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct IssuerAlias {
    canonical: String,
    kind: IssuerKind,
    reference: String,
}

impl IssuerAlias {
    /// Parse `issuer:<kind>:<configured-reference>`.
    pub fn parse(value: &str) -> JanusResult<Self> {
        let Some(body) = value.strip_prefix("issuer:") else {
            return Err(JanusError::InvalidIdentifier {
                kind: "issuer_alias",
            });
        };
        let Some((kind_text, reference)) = body.split_once(':') else {
            return Err(JanusError::InvalidIdentifier {
                kind: "issuer_alias",
            });
        };
        let kind = IssuerKind::parse(kind_text)?;
        validate_reference(kind, reference)?;
        let canonical = format!("issuer:{}:{}", kind.as_str(), reference);
        if canonical != value || value.len() > 512 {
            return Err(JanusError::InvalidIdentifier {
                kind: "issuer_alias",
            });
        }
        Ok(Self {
            canonical,
            kind,
            reference: reference.to_string(),
        })
    }

    pub fn as_str(&self) -> &str {
        &self.canonical
    }

    pub fn kind(&self) -> IssuerKind {
        self.kind
    }

    pub fn reference(&self) -> &str {
        &self.reference
    }

    /// Stable value-free digest used in reservations and audit evidence.
    pub fn digest(&self) -> String {
        let mut hash = Sha256::new();
        hash.update(self.canonical.as_bytes());
        hex::encode(hash.finalize())
    }
}

fn validate_reference(kind: IssuerKind, reference: &str) -> JanusResult<()> {
    let parts = reference.split('/').collect::<Vec<_>>();
    let expected_parts = match kind {
        IssuerKind::ZitadelOidcClient | IssuerKind::TofuOutput => 2,
    };
    if parts.len() != expected_parts || parts.iter().any(|part| part.is_empty()) {
        return Err(JanusError::InvalidIdentifier {
            kind: "issuer_alias_reference",
        });
    }
    if parts.iter().any(|part| {
        *part == "."
            || *part == ".."
            || part.bytes().any(|byte| {
                !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b' '))
            })
            || part.starts_with(' ')
            || part.ends_with(' ')
            || part.contains("  ")
    }) {
        return Err(JanusError::InvalidIdentifier {
            kind: "issuer_alias_reference",
        });
    }
    Ok(())
}

/// A configured connector entry. `credential_ref` is a logical key selected
/// by the reviewed catalog; it is never a filesystem path or URL.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IssuerConnectorEntry {
    pub kind: String,
    pub alias: String,
    pub credential_ref: Option<String>,
    pub origin: Option<String>,
    pub project_id: Option<String>,
    pub application_id: Option<String>,
    pub timeout_seconds: Option<u64>,
    pub executable: Option<String>,
    pub executable_sha256: Option<String>,
    pub workdir: Option<String>,
    pub state_file: Option<String>,
    pub output: Option<String>,
    pub executable_owner_uid: Option<u32>,
    pub state_owner_uid: Option<u32>,
}

/// Strict closed connector catalog loaded by the admin boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuerConnectorCatalog {
    entries: Vec<(IssuerAlias, IssuerConnectorEntry)>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IssuerConnectorDocument {
    schema: String,
    connectors: Vec<IssuerConnectorEntry>,
}

impl IssuerConnectorCatalog {
    pub fn parse_json(bytes: &[u8]) -> JanusResult<Self> {
        if bytes.is_empty() || bytes.len() > MAX_ISSUER_CATALOG_BYTES {
            return Err(JanusError::InvalidManifest {
                detail: "issuer connector catalog exceeds its size bound".to_string(),
            });
        }
        let document: IssuerConnectorDocument =
            serde_json::from_slice(bytes).map_err(|_| JanusError::InvalidManifest {
                detail: "issuer connector catalog is not valid JSON".to_string(),
            })?;
        if document.schema != ISSUER_CONNECTOR_SCHEMA
            || document.connectors.is_empty()
            || document.connectors.len() > MAX_ISSUER_CONNECTORS
        {
            return Err(JanusError::InvalidManifest {
                detail: "issuer connector catalog schema or entries are invalid".to_string(),
            });
        }
        let mut aliases = BTreeSet::new();
        let mut entries = Vec::with_capacity(document.connectors.len());
        for entry in document.connectors {
            let alias = IssuerAlias::parse(&entry.alias)?;
            let kind = IssuerKind::parse(&entry.kind)?;
            let zitadel_fields_present = entry.origin.is_some()
                || entry.project_id.is_some()
                || entry.application_id.is_some();
            let tofu_fields_present = entry.executable.is_some()
                || entry.executable_sha256.is_some()
                || entry.workdir.is_some()
                || entry.state_file.is_some()
                || entry.output.is_some()
                || entry.executable_owner_uid.is_some()
                || entry.state_owner_uid.is_some();
            let shape_valid = match kind {
                IssuerKind::ZitadelOidcClient => {
                    entry
                        .credential_ref
                        .as_ref()
                        .is_some_and(|value| !value.is_empty() && value.len() <= 256)
                        && entry.origin.is_some()
                        && entry.project_id.is_some()
                        && entry.application_id.is_some()
                        && entry.timeout_seconds.is_some()
                        && !tofu_fields_present
                }
                IssuerKind::TofuOutput => {
                    entry.credential_ref.is_none()
                        && entry.executable.is_some()
                        && entry.executable_sha256.is_some()
                        && entry.workdir.is_some()
                        && entry.state_file.is_some()
                        && entry.output.is_some()
                        && entry.executable_owner_uid.is_some()
                        && entry.state_owner_uid.is_some()
                        && entry.timeout_seconds.is_some()
                        && !zitadel_fields_present
                }
            };
            if alias.kind() != kind || !shape_valid || !aliases.insert(alias.clone()) {
                return Err(JanusError::InvalidManifest {
                    detail: "issuer connector aliases or kinds are inconsistent".to_string(),
                });
            }
            match kind {
                IssuerKind::ZitadelOidcClient => {
                    ZitadelOidcClientConfig::new(
                        entry.origin.as_deref().expect("validated origin"),
                        entry.project_id.as_deref().expect("validated project id"),
                        entry
                            .application_id
                            .as_deref()
                            .expect("validated application id"),
                        entry.timeout_seconds.expect("validated timeout"),
                    )?;
                }
                IssuerKind::TofuOutput => {
                    TofuOutputConfig::new(
                        PathBuf::from(entry.executable.as_deref().expect("validated executable")),
                        entry
                            .executable_sha256
                            .as_deref()
                            .expect("validated executable digest"),
                        PathBuf::from(entry.workdir.as_deref().expect("validated workdir")),
                        PathBuf::from(entry.state_file.as_deref().expect("validated state file")),
                        entry.output.as_deref().expect("validated output"),
                        entry
                            .executable_owner_uid
                            .expect("validated executable owner"),
                        entry.state_owner_uid.expect("validated state owner"),
                        entry.timeout_seconds.expect("validated timeout"),
                    )?;
                }
            }
            entries.push((alias, entry));
        }
        Ok(Self { entries })
    }

    pub fn load(path: &Path) -> JanusResult<Self> {
        if !path.is_absolute() {
            return Err(JanusError::InvalidIdentifier {
                kind: "issuer_connector_config_path",
            });
        }
        let metadata =
            std::fs::symlink_metadata(path).map_err(|_| JanusError::StoreUnavailable {
                detail: "issuer connector catalog unavailable".to_string(),
            })?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() as usize > MAX_ISSUER_CATALOG_BYTES
        {
            return Err(JanusError::StoreUnavailable {
                detail: "issuer connector catalog custody is invalid".to_string(),
            });
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            if metadata.nlink() != 1 || metadata.permissions().mode() & 0o022 != 0 {
                return Err(JanusError::StoreUnavailable {
                    detail: "issuer connector catalog custody is invalid".to_string(),
                });
            }
        }
        let bytes = std::fs::read(path).map_err(|_| JanusError::StoreUnavailable {
            detail: "issuer connector catalog unavailable".to_string(),
        })?;
        Self::parse_json(&bytes)
    }

    pub fn entry(&self, alias: &IssuerAlias) -> Option<&IssuerConnectorEntry> {
        self.entries
            .iter()
            .find(|(candidate, _)| candidate == alias)
            .map(|(_, entry)| entry)
    }

    /// Digest the complete reviewed connector entry selected by an alias.
    pub fn entry_digest(&self, alias: &IssuerAlias) -> JanusResult<String> {
        let entry = self.entry(alias).ok_or_else(|| JanusError::NotFound {
            name: alias.as_str().to_string(),
        })?;
        let canonical = serde_json::to_vec(entry).map_err(|_| JanusError::InvalidManifest {
            detail: "issuer connector entry cannot be canonicalized".to_string(),
        })?;
        let mut hash = Sha256::new();
        hash.update(canonical);
        Ok(hex::encode(hash.finalize()))
    }

    pub fn aliases_digest(&self) -> String {
        let canonical = self
            .entries
            .iter()
            .map(|(alias, _)| alias.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let mut hash = Sha256::new();
        hash.update(canonical.as_bytes());
        hex::encode(hash.finalize())
    }
}

/// Restricted logical credential lookup supplied by the admin custody layer.
#[async_trait]
pub trait IssuerCredentialStore: Send + Sync {
    async fn load(&self, credential_ref: &str) -> JanusResult<SecretValue>;
}

/// Value-free evidence returned alongside an internal resolved value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuerResolutionEvidence {
    pub kind: IssuerKind,
    pub alias_digest: String,
}

/// A resolved value that remains inside the write-side broker boundary.
pub struct IssuerResolution {
    pub value: SecretValue,
    pub evidence: IssuerResolutionEvidence,
}

#[async_trait]
pub trait IssuerResolver: Send + Sync {
    async fn resolve(
        &self,
        alias: &IssuerAlias,
        credential_store: &dyn IssuerCredentialStore,
    ) -> JanusResult<IssuerResolution>;
}

/// Dispatcher binding the closed catalog to the two supported connectors.
/// Connector work runs in a blocking task; the async credential lookup stays
/// inside the Janus custody boundary and no resolved value is returned here.
pub struct ConfiguredIssuerResolver {
    catalog: IssuerConnectorCatalog,
}

impl ConfiguredIssuerResolver {
    pub fn new(catalog: IssuerConnectorCatalog) -> Self {
        Self { catalog }
    }
}

#[async_trait]
impl IssuerResolver for ConfiguredIssuerResolver {
    async fn resolve(
        &self,
        alias: &IssuerAlias,
        credential_store: &dyn IssuerCredentialStore,
    ) -> JanusResult<IssuerResolution> {
        let entry = self
            .catalog
            .entry(alias)
            .ok_or_else(|| JanusError::NotFound {
                name: alias.as_str().to_string(),
            })?;
        let value = match alias.kind() {
            IssuerKind::ZitadelOidcClient => {
                let config = ZitadelOidcClientConfig::new(
                    entry.origin.as_deref().expect("validated origin"),
                    entry.project_id.as_deref().expect("validated project id"),
                    entry
                        .application_id
                        .as_deref()
                        .expect("validated application id"),
                    entry.timeout_seconds.expect("validated timeout"),
                )?;
                let credential_ref = entry
                    .credential_ref
                    .as_deref()
                    .expect("validated credential reference")
                    .to_string();
                let profile = credential_store.load(&credential_ref).await?;
                let connector = ZitadelOidcClientConnector::default();
                tokio::task::spawn_blocking(move || connector.resolve(&config, profile))
                    .await
                    .map_err(|_| JanusError::StoreUnavailable {
                        detail: "Zitadel issuer task failed".to_string(),
                    })??
            }
            IssuerKind::TofuOutput => {
                let config = TofuOutputConfig::new(
                    PathBuf::from(entry.executable.as_deref().expect("validated executable")),
                    entry
                        .executable_sha256
                        .as_deref()
                        .expect("validated executable digest"),
                    PathBuf::from(entry.workdir.as_deref().expect("validated workdir")),
                    PathBuf::from(entry.state_file.as_deref().expect("validated state file")),
                    entry.output.as_deref().expect("validated output"),
                    entry
                        .executable_owner_uid
                        .expect("validated executable owner"),
                    entry.state_owner_uid.expect("validated state owner"),
                    entry.timeout_seconds.expect("validated timeout"),
                )?;
                let connector = TofuOutputConnector;
                tokio::task::spawn_blocking(move || connector.resolve(&config))
                    .await
                    .map_err(|_| JanusError::StoreUnavailable {
                        detail: "OpenTofu issuer task failed".to_string(),
                    })??
            }
        };
        Ok(IssuerResolution {
            value,
            evidence: IssuerResolutionEvidence {
                kind: alias.kind(),
                alias_digest: alias.digest(),
            },
        })
    }
}

#[async_trait]
impl IssuerInvalidator for ConfiguredIssuerResolver {
    async fn invalidate(
        &self,
        alias: &IssuerAlias,
        credential_store: &dyn IssuerCredentialStore,
    ) -> JanusResult<IssuerInvalidationEvidence> {
        if alias.kind() != IssuerKind::ZitadelOidcClient {
            return Err(JanusError::Unsupported {
                capability: "issuer_invalidation_kind",
            });
        }
        let entry = self
            .catalog
            .entry(alias)
            .ok_or_else(|| JanusError::NotFound {
                name: alias.as_str().to_string(),
            })?;
        let connector_config_digest = self.catalog.entry_digest(alias)?;
        let config = ZitadelOidcClientConfig::new(
            entry.origin.as_deref().expect("validated origin"),
            entry.project_id.as_deref().expect("validated project id"),
            entry
                .application_id
                .as_deref()
                .expect("validated application id"),
            entry.timeout_seconds.expect("validated timeout"),
        )?;
        let credential_ref = entry
            .credential_ref
            .as_deref()
            .expect("validated credential reference")
            .to_string();
        let profile = credential_store.load(&credential_ref).await?;
        let connector = ZitadelOidcClientConnector::default();
        tokio::task::spawn_blocking(move || connector.invalidate(&config, profile))
            .await
            .map_err(|_| JanusError::StoreUnavailable {
                detail: "Zitadel issuer invalidation task failed".to_string(),
            })??;
        Ok(IssuerInvalidationEvidence {
            kind: alias.kind(),
            alias_digest: alias.digest(),
            connector_config_digest,
            method: "regenerate-and-discard",
            value_returned: false,
        })
    }
}
