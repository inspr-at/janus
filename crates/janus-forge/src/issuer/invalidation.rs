//! Durable, value-free provider credential invalidation.

use super::{IssuerAlias, IssuerCredentialStore, IssuerKind};
use async_trait::async_trait;
use janus_core::{
    AuditAction, AuditEvent, AuditOutcome, AuditSink, JanusError, JanusResult, PrincipalChain,
    SafeLabel, SecretRef, Severity,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

const SCHEMA: &str = "janus.issuer-invalidation.v1";
const METHOD: &str = "regenerate-and-discard";
const MAX_RECORD_BYTES: usize = 16 * 1024;

/// Value-free proof returned by a connector after provider invalidation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuerInvalidationEvidence {
    pub kind: IssuerKind,
    pub alias_digest: String,
    pub connector_config_digest: String,
    pub method: &'static str,
    pub value_returned: bool,
}

/// Closed provider invalidation boundary.
#[async_trait]
pub trait IssuerInvalidator: Send + Sync {
    async fn invalidate(
        &self,
        alias: &IssuerAlias,
        credential_store: &dyn IssuerCredentialStore,
    ) -> JanusResult<IssuerInvalidationEvidence>;
}

/// Value-free outcome for an invalidation transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuerInvalidationOutcome {
    pub action: &'static str,
    pub changed: bool,
    pub state: &'static str,
    pub method: &'static str,
    pub operation_ref_digest: String,
    pub issuer_alias_digest: String,
    pub connector_config_digest: String,
    pub reason: SafeLabel,
    pub value_returned: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct InvalidationRecord {
    schema: String,
    version: u8,
    state: String,
    method: String,
    operation_ref_sha256: String,
    issuer_alias_sha256: String,
    connector_config_sha256: String,
    principal_binding_sha256: String,
    reason_sha256: String,
    value_returned: bool,
}

/// Regenerate a configured ZITADEL client secret, discard the replacement,
/// and durably record the completed provider operation without secret bytes.
#[allow(clippy::too_many_arguments)]
pub async fn invalidate_issuer_credential<I, C, A>(
    state_dir: &Path,
    operation_ref: &str,
    alias: &IssuerAlias,
    connector_config_digest: &str,
    reason: SafeLabel,
    principal: &PrincipalChain,
    invalidator: &I,
    credential_store: &C,
    audit: &mut A,
) -> JanusResult<IssuerInvalidationOutcome>
where
    I: IssuerInvalidator,
    C: IssuerCredentialStore,
    A: AuditSink,
{
    if alias.kind() != IssuerKind::ZitadelOidcClient {
        return Err(JanusError::Unsupported {
            capability: "issuer_invalidation_kind",
        });
    }
    validate_operation_ref(operation_ref)?;
    validate_digest(connector_config_digest, "issuer_connector_config_digest")?;
    validate_state_dir(state_dir)?;

    let mut expected = InvalidationRecord {
        schema: SCHEMA.to_string(),
        version: 1,
        state: "reserved".to_string(),
        method: METHOD.to_string(),
        operation_ref_sha256: digest_text(operation_ref),
        issuer_alias_sha256: alias.digest(),
        connector_config_sha256: connector_config_digest.to_string(),
        principal_binding_sha256: digest_text(&principal.binding_key()),
        reason_sha256: digest_text(reason.as_str()),
        value_returned: false,
    };
    let record_path = state_dir.join(format!("invalidate_{}.json", expected.operation_ref_sha256));
    match read_record(&record_path)? {
        Some(existing) if record_matches(&existing, &expected) && existing.state == "committed" => {
            return Ok(outcome(false, expected, reason));
        }
        Some(existing) if record_matches(&existing, &expected) && existing.state == "reserved" => {
            return Err(JanusError::policy_denied(
                "issuer_invalidation_interrupted",
                "a provider invalidation reservation is pending and cannot be replayed",
            ));
        }
        Some(_) => {
            return Err(JanusError::policy_denied(
                "issuer_invalidation_conflict",
                "the operation reference is bound to different invalidation inputs",
            ));
        }
        None => {}
    }

    let secret_ref = SecretRef::new(format!("issuer:invalidated:{}", alias.digest()))?;
    audit.record(
        AuditEvent::new(
            AuditAction::RotationApprove,
            AuditOutcome::Allowed,
            "issuer_invalidation_approved",
            Severity::High,
            Some(secret_ref.clone()),
            principal,
        )
        .with_evidence(SafeLabel::new(format!(
            "operation_sha256={} alias_sha256={} connector_sha256={} reason={}",
            expected.operation_ref_sha256,
            expected.issuer_alias_sha256,
            expected.connector_config_sha256,
            reason.as_str()
        ))?),
    )?;
    write_create_new(&record_path, &expected)?;

    let evidence = invalidator.invalidate(alias, credential_store).await?;
    if evidence.kind != IssuerKind::ZitadelOidcClient
        || evidence.alias_digest != expected.issuer_alias_sha256
        || evidence.connector_config_digest != expected.connector_config_sha256
        || evidence.method != METHOD
        || evidence.value_returned
    {
        return Err(JanusError::policy_denied(
            "issuer_invalidation_evidence_mismatch",
            "provider invalidation evidence does not match the reservation",
        ));
    }
    audit.record(
        AuditEvent::new(
            AuditAction::RotationLifecycle,
            AuditOutcome::Allowed,
            "issuer_credential_invalidated",
            Severity::High,
            Some(secret_ref),
            principal,
        )
        .with_evidence(SafeLabel::new(format!(
            "operation_sha256={} alias_sha256={} connector_sha256={} method={METHOD}",
            expected.operation_ref_sha256,
            expected.issuer_alias_sha256,
            expected.connector_config_sha256
        ))?),
    )?;
    expected.state = "committed".to_string();
    replace_record(&record_path, &expected)?;
    Ok(outcome(true, expected, reason))
}

fn outcome(
    changed: bool,
    record: InvalidationRecord,
    reason: SafeLabel,
) -> IssuerInvalidationOutcome {
    IssuerInvalidationOutcome {
        action: "issuer.credential.invalidate",
        changed,
        state: "committed",
        method: METHOD,
        operation_ref_digest: record.operation_ref_sha256,
        issuer_alias_digest: record.issuer_alias_sha256,
        connector_config_digest: record.connector_config_sha256,
        reason,
        value_returned: false,
    }
}

fn validate_operation_ref(value: &str) -> JanusResult<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || value.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
        })
    {
        return Err(JanusError::InvalidIdentifier {
            kind: "issuer_invalidation_operation_ref",
        });
    }
    Ok(())
}

fn validate_digest(value: &str, kind: &'static str) -> JanusResult<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(JanusError::InvalidIdentifier { kind });
    }
    Ok(())
}

fn validate_state_dir(path: &Path) -> JanusResult<()> {
    if !path.is_absolute() {
        return Err(JanusError::InvalidIdentifier {
            kind: "issuer_invalidation_state_dir",
        });
    }
    let metadata = fs::symlink_metadata(path).map_err(store_unavailable)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(store_unavailable(
            "issuer invalidation state custody is invalid",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(store_unavailable(
                "issuer invalidation state custody is invalid",
            ));
        }
    }
    Ok(())
}

fn read_record(path: &Path) -> JanusResult<Option<InvalidationRecord>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(store_unavailable(error)),
    };
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() as usize > MAX_RECORD_BYTES
    {
        return Err(store_unavailable(
            "issuer invalidation record custody is invalid",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.nlink() != 1 || metadata.permissions().mode() & 0o077 != 0 {
            return Err(store_unavailable(
                "issuer invalidation record custody is invalid",
            ));
        }
    }
    let bytes = fs::read(path).map_err(store_unavailable)?;
    if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
        return Err(store_unavailable("issuer invalidation record is invalid"));
    }
    let record: InvalidationRecord = serde_json::from_slice(&bytes)
        .map_err(|_| store_unavailable("issuer invalidation record is invalid"))?;
    if record.schema != SCHEMA
        || record.version != 1
        || !matches!(record.state.as_str(), "reserved" | "committed")
        || record.method != METHOD
        || record.value_returned
    {
        return Err(store_unavailable("issuer invalidation record is invalid"));
    }
    for digest in [
        &record.operation_ref_sha256,
        &record.issuer_alias_sha256,
        &record.connector_config_sha256,
        &record.principal_binding_sha256,
        &record.reason_sha256,
    ] {
        validate_digest(digest, "issuer_invalidation_record_digest")?;
    }
    Ok(Some(record))
}

fn record_matches(left: &InvalidationRecord, right: &InvalidationRecord) -> bool {
    left.schema == right.schema
        && left.version == right.version
        && left.method == right.method
        && left.operation_ref_sha256 == right.operation_ref_sha256
        && left.issuer_alias_sha256 == right.issuer_alias_sha256
        && left.connector_config_sha256 == right.connector_config_sha256
        && left.principal_binding_sha256 == right.principal_binding_sha256
        && left.reason_sha256 == right.reason_sha256
        && !left.value_returned
}

fn write_create_new(path: &Path, record: &InvalidationRecord) -> JanusResult<()> {
    let bytes = serde_json::to_vec(record)
        .map_err(|_| store_unavailable("issuer invalidation record serialization failed"))?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(store_unavailable)?;
    file.write_all(&bytes).map_err(store_unavailable)?;
    file.write_all(b"\n").map_err(store_unavailable)?;
    file.sync_all().map_err(store_unavailable)?;
    sync_parent(path)
}

fn replace_record(path: &Path, record: &InvalidationRecord) -> JanusResult<()> {
    let parent = path.parent().ok_or(JanusError::InvalidIdentifier {
        kind: "issuer_invalidation_state_dir",
    })?;
    let file_name =
        path.file_name()
            .and_then(|name| name.to_str())
            .ok_or(JanusError::InvalidIdentifier {
                kind: "issuer_invalidation_record_path",
            })?;
    let temporary = parent.join(format!(".{file_name}.{}.tmp", std::process::id()));
    let result = (|| {
        let bytes = serde_json::to_vec(record)
            .map_err(|_| store_unavailable("issuer invalidation record serialization failed"))?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary).map_err(store_unavailable)?;
        file.write_all(&bytes).map_err(store_unavailable)?;
        file.write_all(b"\n").map_err(store_unavailable)?;
        file.sync_all().map_err(store_unavailable)?;
        fs::rename(&temporary, path).map_err(store_unavailable)?;
        sync_parent(path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn sync_parent(path: &Path) -> JanusResult<()> {
    let parent = path.parent().ok_or(JanusError::InvalidIdentifier {
        kind: "issuer_invalidation_state_dir",
    })?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(store_unavailable)
}

fn digest_text(value: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(value.as_bytes());
    hex::encode(hash.finalize())
}

fn store_unavailable(error: impl std::fmt::Display) -> JanusError {
    JanusError::StoreUnavailable {
        detail: format!("issuer invalidation state unavailable: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use janus_core::{
        AuditWrite, EnvironmentId, OrganizationId, Principal, PrincipalId, PrincipalKind,
        ProjectId, RepositoryId, ScopePathV1, SecretValue,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::TempDir;

    struct EmptyStore;
    #[async_trait]
    impl IssuerCredentialStore for EmptyStore {
        async fn load(&self, _credential_ref: &str) -> JanusResult<SecretValue> {
            Ok(SecretValue::new(b"unused".to_vec()))
        }
    }

    struct FakeInvalidator {
        calls: AtomicUsize,
        evidence: IssuerInvalidationEvidence,
    }
    #[async_trait]
    impl IssuerInvalidator for FakeInvalidator {
        async fn invalidate(
            &self,
            _alias: &IssuerAlias,
            _store: &dyn IssuerCredentialStore,
        ) -> JanusResult<IssuerInvalidationEvidence> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.evidence.clone())
        }
    }

    fn fixture() -> (TempDir, IssuerAlias, PrincipalChain, FakeInvalidator) {
        let root = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let alias = IssuerAlias::parse("issuer:zitadel-oidc-client:Fixture/App").unwrap();
        let principal = PrincipalChain::new(
            Principal::new(
                PrincipalKind::Executor,
                PrincipalId::new("fixture").unwrap(),
            ),
            ScopePathV1::new(
                OrganizationId::new("org").unwrap(),
                ProjectId::new("project").unwrap(),
                RepositoryId::new("repo").unwrap(),
                EnvironmentId::new("test").unwrap(),
            )
            .scope_ref(),
        );
        let invalidator = FakeInvalidator {
            calls: AtomicUsize::new(0),
            evidence: IssuerInvalidationEvidence {
                kind: IssuerKind::ZitadelOidcClient,
                alias_digest: alias.digest(),
                connector_config_digest: "a".repeat(64),
                method: METHOD,
                value_returned: false,
            },
        };
        (root, alias, principal, invalidator)
    }

    #[tokio::test]
    async fn commits_once_and_replay_is_value_free_without_provider_call() {
        let (root, alias, principal, invalidator) = fixture();
        let mut audit = AuditWrite::accepting();
        let first = invalidate_issuer_credential(
            root.path(),
            "op_fixture_1",
            &alias,
            &"a".repeat(64),
            SafeLabel::new("fixture reason").unwrap(),
            &principal,
            &invalidator,
            &EmptyStore,
            &mut audit,
        )
        .await
        .unwrap();
        let second = invalidate_issuer_credential(
            root.path(),
            "op_fixture_1",
            &alias,
            &"a".repeat(64),
            SafeLabel::new("fixture reason").unwrap(),
            &principal,
            &invalidator,
            &EmptyStore,
            &mut audit,
        )
        .await
        .unwrap();
        assert!(first.changed);
        assert!(!second.changed);
        assert_eq!(invalidator.calls.load(Ordering::SeqCst), 1);
        assert!(!format!("{first:?}").contains("unused"));
        let record = fs::read_to_string(
            fs::read_dir(root.path())
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .path(),
        )
        .unwrap();
        assert!(!record.contains("op_fixture_1"));
        assert!(!record.contains(alias.as_str()));
        assert!(!record.contains(&principal.binding_key()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let record = fs::read_dir(root.path())
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .path();
            assert_eq!(
                fs::metadata(record).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[tokio::test]
    async fn interrupted_and_conflicting_operations_fail_closed() {
        let (root, alias, principal, invalidator) = fixture();
        let mut audit = AuditWrite::accepting();
        let bad = FakeInvalidator {
            calls: AtomicUsize::new(0),
            evidence: IssuerInvalidationEvidence {
                connector_config_digest: "b".repeat(64),
                ..invalidator.evidence.clone()
            },
        };
        let error = invalidate_issuer_credential(
            root.path(),
            "op_fixture_2",
            &alias,
            &"a".repeat(64),
            SafeLabel::new("fixture reason").unwrap(),
            &principal,
            &bad,
            &EmptyStore,
            &mut audit,
        )
        .await
        .unwrap_err();
        assert!(matches!(
            error,
            JanusError::PolicyDenied {
                reason_code: "issuer_invalidation_evidence_mismatch",
                ..
            }
        ));
        let error = invalidate_issuer_credential(
            root.path(),
            "op_fixture_2",
            &alias,
            &"a".repeat(64),
            SafeLabel::new("fixture reason").unwrap(),
            &principal,
            &invalidator,
            &EmptyStore,
            &mut audit,
        )
        .await
        .unwrap_err();
        assert!(matches!(
            error,
            JanusError::PolicyDenied {
                reason_code: "issuer_invalidation_interrupted",
                ..
            }
        ));
        let error = invalidate_issuer_credential(
            root.path(),
            "op_fixture_2",
            &alias,
            &"c".repeat(64),
            SafeLabel::new("fixture reason").unwrap(),
            &principal,
            &invalidator,
            &EmptyStore,
            &mut audit,
        )
        .await
        .unwrap_err();
        assert!(matches!(
            error,
            JanusError::PolicyDenied {
                reason_code: "issuer_invalidation_conflict",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn unsupported_kind_never_reserves_or_calls_provider() {
        let (root, _, principal, invalidator) = fixture();
        let alias = IssuerAlias::parse("issuer:tofu-output:Fixture/value").unwrap();
        let mut audit = AuditWrite::accepting();
        let error = invalidate_issuer_credential(
            root.path(),
            "op_fixture_3",
            &alias,
            &"a".repeat(64),
            SafeLabel::new("fixture reason").unwrap(),
            &principal,
            &invalidator,
            &EmptyStore,
            &mut audit,
        )
        .await
        .unwrap_err();
        assert!(matches!(
            error,
            JanusError::Unsupported {
                capability: "issuer_invalidation_kind"
            }
        ));
        assert_eq!(invalidator.calls.load(Ordering::SeqCst), 0);
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn audit_refusal_happens_before_reservation_or_provider_call() {
        let (root, alias, principal, invalidator) = fixture();
        let mut audit = AuditWrite::failing();
        let error = invalidate_issuer_credential(
            root.path(),
            "op_fixture_4",
            &alias,
            &"a".repeat(64),
            SafeLabel::new("fixture reason").unwrap(),
            &principal,
            &invalidator,
            &EmptyStore,
            &mut audit,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, JanusError::AuditUnavailable { .. }));
        assert_eq!(invalidator.calls.load(Ordering::SeqCst), 0);
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    }
}
