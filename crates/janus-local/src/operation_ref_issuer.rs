//! Offline controller-side issuance of short-lived operation references.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::{Duration, SystemTime};

use ed25519_dalek::SigningKey;
use janus_core::{
    AuthoritativeOperationRefV1, ConflictDomain, Duty, JanusError, JanusResult, OperationRef,
    SafeLabel, ScopeRef, MAX_OPERATION_REFERENCE_TTL_SECS,
};
use serde::{Deserialize, Serialize};

use crate::identity::{random_bytes, read_private_bytes};
use crate::identity_admin::{current_euid, private_open_flags};

pub const OPERATION_REF_ISSUE_REQUEST_SCHEMA: &str =
    "inspr.janus.authoritative-operation-ref-issue-request.v1";
const OPERATION_REF_ISSUE_REQUEST_VERSION: u8 = 1;
const MAX_REQUEST_BYTES: u64 = 16 * 1024;
const MAX_REQUEST_TEXT_BYTES: usize = 512;

/// Closed, value-free controller request for one fresh signed reference.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRefIssueRequestV1 {
    pub schema: String,
    pub schema_version: u8,
    pub domain_service: String,
    pub authoritative_lineage: String,
    pub scope_ref: String,
    pub conflict_domain: ConflictDomain,
    pub duty: Duty,
    pub state_revision: u64,
    pub policy_revision: String,
    pub ttl_seconds: u64,
    pub audience: String,
    pub release_digest: String,
}

/// Value-free stdout receipt. The signed reference exists only in the output file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OperationRefIssueOutcomeV1 {
    pub schema_version: u8,
    pub ok: bool,
    pub value_returned: bool,
}

/// Issue one short-lived reference with an existing controller key.
///
/// The request and key are opened without following symlinks. The output parent
/// must already be a caller-owned mode-0700 directory; the output is created
/// exclusively as mode 0600 and is never replaced.
pub fn issue_authoritative_operation_ref(
    request_file: &Path,
    signing_key_file: &Path,
    out_file: &Path,
    now: SystemTime,
) -> JanusResult<OperationRefIssueOutcomeV1> {
    if rustix::process::getuid() != rustix::process::geteuid() {
        return Err(invalid(
            "operation reference issuer must not run with elevated effective credentials",
        ));
    }
    let request = read_request(request_file)?;
    validate_request(&request)?;
    let signing_key = load_existing_signing_key(signing_key_file)?;
    validate_output_parent(out_file)?;

    let scope = ScopeRef::from_opaque(request.scope_ref.clone())
        .map_err(|_| invalid("scope_ref is malformed"))?;
    let policy_revision = SafeLabel::new(request.policy_revision.clone())
        .map_err(|_| invalid("policy_revision is malformed"))?;
    let operation_ref = OperationRef::derive(
        request.conflict_domain,
        request.authoritative_lineage.as_str(),
    )
    .map_err(|_| invalid("authoritative_lineage is malformed"))?;
    let expires_at = now
        .checked_add(Duration::from_secs(request.ttl_seconds))
        .ok_or_else(|| invalid("operation reference lifetime is invalid"))?;
    let nonce_ref = format!("nce_{}", hex::encode(random_bytes::<12>()?));
    let reference = AuthoritativeOperationRefV1::issue(
        &signing_key,
        request.domain_service.as_str(),
        &operation_ref,
        &scope,
        request.conflict_domain,
        request.duty,
        request.state_revision,
        &policy_revision,
        now,
        expires_at,
        nonce_ref.as_str(),
        request.audience.as_str(),
        request.release_digest.as_str(),
    )
    .map_err(|_| invalid("operation reference request fields are invalid"))?;
    let encoded = serde_json::to_vec(&reference)
        .map_err(|_| unavailable("operation reference encoding failed"))?;
    write_new_private(out_file, &encoded)?;
    Ok(OperationRefIssueOutcomeV1 {
        schema_version: OPERATION_REF_ISSUE_REQUEST_VERSION,
        ok: true,
        value_returned: false,
    })
}

fn read_request(path: &Path) -> JanusResult<OperationRefIssueRequestV1> {
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(private_open_flags());
    let mut file = options
        .open(path)
        .map_err(|_| invalid("operation reference request unavailable"))?;
    let metadata = file
        .metadata()
        .map_err(|_| invalid("operation reference request unavailable"))?;
    if !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_REQUEST_BYTES
        || metadata.uid() != current_euid()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(invalid(
            "operation reference request is not a bounded caller-owned regular file",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|_| invalid("operation reference request unavailable"))?;
    serde_json::from_slice(&bytes).map_err(|_| invalid("operation reference request is malformed"))
}

fn validate_request(request: &OperationRefIssueRequestV1) -> JanusResult<()> {
    if request.schema != OPERATION_REF_ISSUE_REQUEST_SCHEMA
        || request.schema_version != OPERATION_REF_ISSUE_REQUEST_VERSION
        || request.state_revision == 0
        || request.ttl_seconds == 0
        || request.ttl_seconds > MAX_OPERATION_REFERENCE_TTL_SECS
        || !bounded_text(&request.domain_service)
        || !bounded_text(&request.authoritative_lineage)
        || !bounded_text(&request.policy_revision)
        || !bounded_text(&request.audience)
        || !request.conflict_domain.permits(request.duty)
    {
        return Err(invalid("operation reference request fields are invalid"));
    }
    Ok(())
}

fn bounded_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_REQUEST_TEXT_BYTES
        && value.trim().len() == value.len()
        && !value.chars().any(char::is_control)
}

fn load_existing_signing_key(path: &Path) -> JanusResult<SigningKey> {
    let bytes = read_private_bytes(path, "operation authority signing key", 32)?;
    let raw: [u8; 32] = bytes
        .try_into()
        .map_err(|_| unavailable("operation authority signing key malformed"))?;
    Ok(SigningKey::from_bytes(&raw))
}

fn validate_output_parent(path: &Path) -> JanusResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("operation reference output path is invalid"))?;
    let metadata = fs::symlink_metadata(parent)
        .map_err(|_| invalid("operation reference output parent unavailable"))?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != current_euid()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(invalid(
            "operation reference output parent must be caller-owned and private",
        ));
    }
    Ok(())
}

fn write_new_private(path: &Path, bytes: &[u8]) -> JanusResult<()> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(private_open_flags());
    let mut file = options
        .open(path)
        .map_err(|_| invalid("operation reference output already exists or is unavailable"))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| unavailable("operation reference output persistence failed"))?;
    let parent = path
        .parent()
        .ok_or_else(|| invalid("operation reference output path is invalid"))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| unavailable("operation reference output directory persistence failed"))
}

fn invalid(detail: impl Into<String>) -> JanusError {
    JanusError::policy_denied("operation_ref_issue_request_invalid", detail)
}

fn unavailable(detail: impl Into<String>) -> JanusError {
    JanusError::StoreUnavailable {
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use janus_core::{OperationStateVerifier, OPERATION_STATE_SCHEMA};
    use std::os::unix::fs::{symlink, PermissionsExt};
    use tempfile::TempDir;

    const RELEASE: &str = "sha256:0c4fe7bd5c025fd5c78e11052b4202f9c9fbcd9f263332436868c4780d3af560";

    fn fixture_request() -> OperationRefIssueRequestV1 {
        OperationRefIssueRequestV1 {
            schema: OPERATION_REF_ISSUE_REQUEST_SCHEMA.to_string(),
            schema_version: 1,
            domain_service: "inspr397-guarded-deployment".to_string(),
            authoritative_lineage:
                "inspr397-guarded-action-v1|id=lease_fixture|host=hsb1|ticket=INSPR-397|phase=apply|action=update"
                    .to_string(),
            scope_ref: "scp_595bd0a954b7cd1564068bceae2d3be518d5a5b0".to_string(),
            conflict_domain: ConflictDomain::UseRequest,
            duty: Duty::ApproveUse,
            state_revision: 7,
            policy_revision: "inspr397-guarded-policy-v1".to_string(),
            ttl_seconds: 240,
            audience: "inspr397-guarded-operation".to_string(),
            release_digest: RELEASE.to_string(),
        }
    }

    fn fixture() -> (TempDir, std::path::PathBuf, std::path::PathBuf) {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let key = root.path().join("authority.key");
        fs::write(&key, [7u8; 32]).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        let request = root.path().join("request.json");
        fs::write(&request, serde_json::to_vec(&fixture_request()).unwrap()).unwrap();
        fs::set_permissions(&request, fs::Permissions::from_mode(0o600)).unwrap();
        (root, key, request)
    }

    fn reason(error: JanusError) -> String {
        match error {
            JanusError::PolicyDenied { reason_code, .. } => reason_code.to_string(),
            JanusError::StoreUnavailable { .. } => "store_unavailable".to_string(),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn issues_exact_runtime_reference_and_fresh_nonces() {
        let (root, key, request) = fixture();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_789_300_000);
        let first_path = root.path().join("first.json");
        let second_path = root.path().join("second.json");
        let outcome = issue_authoritative_operation_ref(&request, &key, &first_path, now).unwrap();
        issue_authoritative_operation_ref(&request, &key, &second_path, now).unwrap();
        assert_eq!(
            outcome,
            OperationRefIssueOutcomeV1 {
                schema_version: 1,
                ok: true,
                value_returned: false,
            }
        );
        let first: AuthoritativeOperationRefV1 =
            serde_json::from_slice(&fs::read(&first_path).unwrap()).unwrap();
        let second: AuthoritativeOperationRefV1 =
            serde_json::from_slice(&fs::read(&second_path).unwrap()).unwrap();
        assert_eq!(first.schema_version, OPERATION_STATE_SCHEMA);
        assert_eq!(first.operation_ref, second.operation_ref);
        assert_ne!(first.nonce_ref, second.nonce_ref);
        assert_eq!(first.expires_at_unix_secs - first.issued_at_unix_secs, 240);
        assert_eq!(
            fs::metadata(&first_path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let mut verifier = OperationStateVerifier::new(
            signing.verifying_key(),
            "inspr397-guarded-deployment",
            "inspr397-guarded-operation",
            RELEASE,
        )
        .unwrap();
        let verified = verifier
            .verify_once(&first, now + Duration::from_secs(1))
            .unwrap();
        assert_eq!(verified.scope().as_str(), fixture_request().scope_ref);
        assert_eq!(verified.conflict_domain(), ConflictDomain::UseRequest);
        assert_eq!(verified.duty(), Duty::ApproveUse);
    }

    #[test]
    fn refuses_overwrite_and_unsafe_key_custody() {
        let (root, key, request) = fixture();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_789_300_000);
        let out = root.path().join("reference.json");
        issue_authoritative_operation_ref(&request, &key, &out, now).unwrap();
        let before = fs::read(&out).unwrap();
        assert_eq!(
            reason(issue_authoritative_operation_ref(&request, &key, &out, now).unwrap_err()),
            "operation_ref_issue_request_invalid"
        );
        assert_eq!(fs::read(&out).unwrap(), before);

        let linked = root.path().join("linked.key");
        fs::hard_link(&key, &linked).unwrap();
        let linked_out = root.path().join("linked-reference.json");
        assert!(issue_authoritative_operation_ref(&request, &key, &linked_out, now).is_err());
        fs::remove_file(linked).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(issue_authoritative_operation_ref(&request, &key, &linked_out, now).is_err());
        assert!(!linked_out.exists());

        let missing = root.path().join("missing.key");
        assert!(issue_authoritative_operation_ref(&request, &missing, &linked_out, now).is_err());
        assert!(!missing.exists());
        assert!(!linked_out.exists());
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        let symlinked = root.path().join("symlinked.key");
        symlink(&key, &symlinked).unwrap();
        assert!(issue_authoritative_operation_ref(&request, &symlinked, &linked_out, now).is_err());
        assert!(!linked_out.exists());
    }

    #[test]
    fn refuses_invalid_closed_fields_and_unsafe_output_parent() {
        let (root, key, request) = fixture();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_789_300_000);
        let cases = [
            serde_json::json!({"ttl_seconds": 0}),
            serde_json::json!({"ttl_seconds": 301}),
            serde_json::json!({"state_revision": 0}),
            serde_json::json!({"scope_ref": "scope-not-opaque"}),
            serde_json::json!({"release_digest": "sha256:nope"}),
            serde_json::json!({"conflict_domain": "role_binding", "duty": "execute_use"}),
        ];
        for (index, change) in cases.into_iter().enumerate() {
            let mut value = serde_json::to_value(fixture_request()).unwrap();
            for (key, value_change) in change.as_object().unwrap() {
                value[key] = value_change.clone();
            }
            fs::write(&request, serde_json::to_vec(&value).unwrap()).unwrap();
            let out = root.path().join(format!("invalid-{index}.json"));
            assert_eq!(
                reason(issue_authoritative_operation_ref(&request, &key, &out, now).unwrap_err()),
                "operation_ref_issue_request_invalid"
            );
            assert!(!out.exists());
        }

        fs::write(&request, serde_json::to_vec(&fixture_request()).unwrap()).unwrap();
        let public = root.path().join("public");
        fs::create_dir(&public).unwrap();
        fs::set_permissions(&public, fs::Permissions::from_mode(0o755)).unwrap();
        let out = public.join("reference.json");
        assert_eq!(
            reason(issue_authoritative_operation_ref(&request, &key, &out, now).unwrap_err()),
            "operation_ref_issue_request_invalid"
        );
        assert!(!out.exists());
    }

    #[test]
    fn supports_exact_role_and_guarded_action_duties() {
        let (root, key, request) = fixture();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_789_300_000);
        let cases = [
            (
                ConflictDomain::RoleBinding,
                Duty::GrantRole,
                "inspr397-guarded-role-bootstrap-v1|source=INSPR-397|step=reviewed-operator",
            ),
            (
                ConflictDomain::UseRequest,
                Duty::ApproveUse,
                "inspr397-guarded-action-v1|id=lease_fixture|host=hsb1|ticket=INSPR-397|phase=apply|action=update",
            ),
            (
                ConflictDomain::UseRequest,
                Duty::ExecuteUse,
                "inspr397-guarded-action-v1|id=lease_fixture|host=hsb1|ticket=INSPR-397|phase=apply|action=update",
            ),
        ];
        let mut refs = Vec::new();
        for (index, (domain, duty, lineage)) in cases.into_iter().enumerate() {
            let mut value = fixture_request();
            value.conflict_domain = domain;
            value.duty = duty;
            value.authoritative_lineage = lineage.to_string();
            fs::write(&request, serde_json::to_vec(&value).unwrap()).unwrap();
            let out = root.path().join(format!("contract-{index}.json"));
            issue_authoritative_operation_ref(&request, &key, &out, now).unwrap();
            refs.push(
                serde_json::from_slice::<AuthoritativeOperationRefV1>(&fs::read(out).unwrap())
                    .unwrap(),
            );
        }
        assert_eq!(refs[0].conflict_domain, ConflictDomain::RoleBinding);
        assert_eq!(refs[0].duty, Duty::GrantRole);
        assert_ne!(refs[0].operation_ref, refs[1].operation_ref);
        assert_eq!(refs[1].operation_ref, refs[2].operation_ref);
        assert_ne!(refs[1].nonce_ref, refs[2].nonce_ref);
        assert_eq!(refs[1].duty, Duty::ApproveUse);
        assert_eq!(refs[2].duty, Duty::ExecuteUse);
    }
}
