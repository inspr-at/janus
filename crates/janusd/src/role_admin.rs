//! Closed local administration surface for durable role bindings.

use std::env;
use std::fs;
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use janus_core::{
    AuditAction, AuditEvent, AuditOutcome, AuditSink, PrincipalChain, Role, RoleBinding,
    RoleBindingId, RoleBindingSource, RoleBindingSourceKind, SafeLabel, Severity,
    MAX_ROLE_BINDING_TTL,
};
use janus_local::{
    FileRoleBindingRegistry, JsonlAuditSink, LoadedRoleAuthorization, RoleBindingRegistry,
};
use serde_json::json;

/// Exact out-of-band acknowledgement required to mint the first binding.
const BOOTSTRAP_ACK_ENV: &str = "JANUS_ROLE_BOOTSTRAP_ACK";
const BOOTSTRAP_ACK_VALUE: &str = "bootstrap-role-authorization";
/// A bootstrap binding exists only long enough to issue reviewed bindings.
/// Capping it here is what stops it becoming a durable hidden backdoor.
const MAX_BOOTSTRAP_TTL: Duration = Duration::from_secs(3600);

pub fn is_role_admin_command(args: &[String]) -> bool {
    matches!(
        args.first().map(String::as_str),
        Some("role-binding" | "authorization-policy")
    )
}

/// `role-binding issue --bootstrap` — the one administration command that must
/// work before any binding exists, because enforced authorization is otherwise
/// gated on the registry it exists to populate (JANUS-416).
pub fn is_role_bootstrap_request(args: &[String]) -> bool {
    matches!(args.first().map(String::as_str), Some("role-binding"))
        && matches!(args.get(1).map(String::as_str), Some("issue"))
        && args
            .iter()
            .take_while(|arg| arg.as_str() != "--")
            .any(|arg| arg == "--bootstrap")
}

pub fn run(
    args: &[String],
    principal: &PrincipalChain,
    authorization: Option<&LoadedRoleAuthorization>,
) -> Result<()> {
    // Checked before the authorization unwrap on purpose: bootstrap is the
    // only path that runs with no loaded authorization, and it fails closed
    // on an acknowledgement, an empty registry, one role and a short TTL.
    if is_role_bootstrap_request(args) {
        return bootstrap_binding(&args[2..], principal);
    }
    let authorization = authorization.context(
        "role administration is unavailable while role authorization is explicitly disabled",
    )?;
    match args {
        [role_binding, issue, rest @ ..]
            if role_binding == "role-binding" && issue == "issue" =>
        {
            issue_binding(rest, principal)
        }
        [role_binding, list] if role_binding == "role-binding" && list == "list" => {
            list_bindings()
        }
        [role_binding, status, rest @ ..]
            if role_binding == "role-binding" && status == "status" =>
        {
            binding_status(rest)
        }
        [role_binding, revoke, rest @ ..]
            if role_binding == "role-binding" && revoke == "revoke" =>
        {
            revoke_binding(rest, principal)
        }
        [policy, status] if policy == "authorization-policy" && status == "status" => {
            let snapshot = authorization.policy.snapshot();
            println!(
                "{}",
                json!({
                    "schema_version": snapshot.schema_version,
                    "policy_id": snapshot.policy_id,
                    "role_count": snapshot.roles.len(),
                    "status": "checked",
                    "value_returned": false
                })
            );
            Ok(())
        }
        _ => anyhow::bail!(
            "unsupported role administration command reason_code=role_admin_args_invalid value_returned=false"
        ),
    }
}

struct IssueConfig {
    principal_binding: Option<String>,
    role: Role,
    target_binding: Option<String>,
    ttl: Duration,
    source_reference: String,
    reason: SafeLabel,
    bootstrap: bool,
}

/// Exclusive one-shot guard so two concurrent bootstraps cannot both observe
/// an empty registry and both mint authority.
struct BootstrapLock {
    path: PathBuf,
}

impl BootstrapLock {
    fn acquire(dir: &Path) -> Result<Self> {
        // Deliberately a sibling of the registry, never inside it: the registry
        // is strict about its contents and rejects any entry that is not a
        // binding record.
        let parent = dir
            .parent()
            .context("role binding registry directory has no parent for the bootstrap lock")?;
        let path = parent.join(".janus-role-bootstrap.lock");
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(_) => Ok(Self { path }),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => anyhow::bail!(
                "role binding bootstrap denied reason_code=bootstrap_lock_held value_returned=false"
            ),
            Err(error) => Err(error).context("role binding bootstrap lock unavailable"),
        }
    }
}

impl Drop for BootstrapLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Mint the first `security_admin` binding so enforced authorization becomes
/// reachable from a clean install. Every guard here is deliberate: the
/// acknowledgement stops accidental invocation, the empty-registry check stops
/// it being a standing backdoor, the role restriction keeps the minted
/// authority to exactly what can issue reviewed bindings, and the TTL cap
/// makes the result expire rather than persist.
///
/// The self-grant separation check that `issue_binding` applies is
/// deliberately NOT applied: bootstrap binds the operator running it, which is
/// the entire point, and there is by definition no other principal to ask.
fn bootstrap_binding(args: &[String], actor: &PrincipalChain) -> Result<()> {
    let config = parse_issue(args)?;
    if env::var(BOOTSTRAP_ACK_ENV).unwrap_or_default() != BOOTSTRAP_ACK_VALUE {
        anyhow::bail!(
            "role binding bootstrap denied reason_code=bootstrap_acknowledgement_missing value_returned=false"
        );
    }
    // Bootstrap binds the operator running it and nobody else. Naming another
    // principal would be a footgun with no recovery: the binding key contains
    // an opaque scope reference the operator cannot compute by hand, so a
    // wrong value would consume the one-shot empty-registry window and lock
    // the deployment out permanently.
    if config.principal_binding.is_some() {
        anyhow::bail!(
            "role binding bootstrap denied reason_code=bootstrap_principal_not_selectable value_returned=false"
        );
    }
    if config.role != Role::SecurityAdmin {
        anyhow::bail!(
            "role binding bootstrap denied reason_code=bootstrap_role_forbidden value_returned=false"
        );
    }
    if config.ttl > MAX_BOOTSTRAP_TTL {
        anyhow::bail!(
            "role binding bootstrap denied reason_code=bootstrap_validity_invalid value_returned=false"
        );
    }
    let registry = registry()?;
    let _lock = BootstrapLock::acquire(registry.dir())?;
    if !registry.bindings()?.is_empty() {
        anyhow::bail!(
            "role binding bootstrap denied reason_code=bootstrap_registry_not_empty value_returned=false"
        );
    }
    let now = SystemTime::now();
    let binding = RoleBinding::issue(
        actor.binding_key(),
        actor.scope.clone(),
        config.role,
        config.target_binding,
        now,
        now.checked_add(config.ttl)
            .context("role binding expiry overflow")?,
        RoleBindingSource::new(
            RoleBindingSourceKind::UnsafeBootstrap,
            &config.source_reference,
        )?,
    )?;
    let mut audit = role_audit()?;
    audit.record(
        AuditEvent::new(
            AuditAction::RoleAssign,
            AuditOutcome::Allowed,
            "role_binding_bootstrapped",
            Severity::High,
            None,
            actor,
        )
        .with_evidence(SafeLabel::new(format!(
            "{} {} unsafe_bootstrap {}",
            binding.id().as_str(),
            binding.role().as_str(),
            config.reason.as_str()
        ))?),
    )?;
    registry.store(&binding)?;
    // A bootstrap that raced another writer must be loud, not silent.
    if registry.bindings()?.len() != 1 {
        anyhow::bail!(
            "role binding bootstrap denied reason_code=bootstrap_registry_raced value_returned=false"
        );
    }
    println!(
        "{}",
        json!({
            "binding_id": binding.id().as_str(),
            "role": binding.role().as_str(),
            "scope_ref": binding.scope().as_str(),
            "source_kind": RoleBindingSourceKind::UnsafeBootstrap.as_str(),
            "expires_at_unix_secs": unix_secs(binding.expires_at()),
            "status": "active",
            "value_returned": false
        })
    );
    Ok(())
}

fn issue_binding(args: &[String], actor: &PrincipalChain) -> Result<()> {
    let config = parse_issue(args)?;
    // Defence in depth: a bootstrap must never reach the reviewed issue path,
    // which would skip every bootstrap guard while claiming LocalReviewed.
    if config.bootstrap {
        anyhow::bail!(
            "role binding issue denied reason_code=bootstrap_route_invalid value_returned=false"
        );
    }
    let principal_binding = config
        .principal_binding
        .context("--principal-binding is required")?;
    if principal_binding == actor.binding_key() {
        anyhow::bail!(
            "role binding denied reason_code=separation_self_role_grant value_returned=false"
        );
    }
    let now = SystemTime::now();
    let binding = RoleBinding::issue(
        principal_binding,
        actor.scope.clone(),
        config.role,
        config.target_binding,
        now,
        now.checked_add(config.ttl)
            .context("role binding expiry overflow")?,
        RoleBindingSource::new(
            RoleBindingSourceKind::LocalReviewed,
            &config.source_reference,
        )?,
    )?;
    let mut audit = role_audit()?;
    audit.record(
        AuditEvent::new(
            AuditAction::RoleAssign,
            AuditOutcome::Allowed,
            "role_assignment_authorized",
            Severity::High,
            None,
            actor,
        )
        .with_evidence(SafeLabel::new(format!(
            "{} {} {}",
            binding.id().as_str(),
            binding.role().as_str(),
            config.reason.as_str()
        ))?),
    )?;
    registry()?.store(&binding)?;
    println!(
        "{}",
        json!({
            "binding_id": binding.id().as_str(),
            "role": binding.role().as_str(),
            "scope_ref": binding.scope().as_str(),
            "targeted": binding.target_binding().is_some(),
            "expires_at_unix_secs": unix_secs(binding.expires_at()),
            "status": "active",
            "value_returned": false
        })
    );
    Ok(())
}

fn list_bindings() -> Result<()> {
    let rows = registry()?
        .list(SystemTime::now())?
        .into_iter()
        .map(|row| {
            json!({
                "binding_id": row.binding_id.as_str(),
                "role": row.role.as_str(),
                "scope_ref": row.scope.as_str(),
                "targeted": row.targeted,
                "valid_from_unix_secs": unix_secs(row.valid_from),
                "expires_at_unix_secs": unix_secs(row.expires_at),
                "source_kind": row.source_kind.as_str(),
                "status": row.status.as_str(),
                "value_returned": false
            })
        })
        .collect::<Vec<_>>();
    println!("{}", json!({"bindings": rows, "value_returned": false}));
    Ok(())
}

fn binding_status(args: &[String]) -> Result<()> {
    let binding_id = parse_binding_only(args)?;
    let record = registry()?.get(binding_id.as_str())?;
    println!(
        "{}",
        json!({
            "binding_id": record.binding.id().as_str(),
            "role": record.binding.role().as_str(),
            "scope_ref": record.binding.scope().as_str(),
            "targeted": record.binding.target_binding().is_some(),
            "status": record.status_at(SystemTime::now()).as_str(),
            "value_returned": false
        })
    );
    Ok(())
}

fn revoke_binding(args: &[String], actor: &PrincipalChain) -> Result<()> {
    let (binding_id, reason) = parse_revoke(args)?;
    let registry = registry()?;
    let record = registry.get(binding_id.as_str())?;
    role_audit()?.record(
        AuditEvent::new(
            AuditAction::RoleRevoke,
            AuditOutcome::Allowed,
            "role_revocation_authorized",
            Severity::High,
            None,
            actor,
        )
        .with_evidence(SafeLabel::new(format!(
            "{} {} {}",
            record.binding.id().as_str(),
            record.binding.role().as_str(),
            reason.as_str()
        ))?),
    )?;
    registry.revoke(
        binding_id.as_str(),
        &actor.binding_key(),
        &reason,
        SystemTime::now(),
    )?;
    println!(
        "{}",
        json!({
            "binding_id": binding_id.as_str(),
            "status": "revoked",
            "value_returned": false
        })
    );
    Ok(())
}

fn parse_issue(args: &[String]) -> Result<IssueConfig> {
    let mut principal_binding = None;
    let mut role = None;
    let mut target_binding = None;
    let mut expires_in_seconds = None;
    let mut source_reference = None;
    let mut reason = None;
    let mut bootstrap = false;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--principal-binding" => replace_once(
                &mut principal_binding,
                required(arg, args.next())?.to_string(),
                arg,
            )?,
            "--target-binding" => replace_once(
                &mut target_binding,
                required(arg, args.next())?.to_string(),
                arg,
            )?,
            "--source-reference" => replace_once(
                &mut source_reference,
                required(arg, args.next())?.to_string(),
                arg,
            )?,
            "--role" => replace_once(
                &mut role,
                Role::parse(required(arg, args.next())?)?,
                arg,
            )?,
            "--expires-in-seconds" => replace_once(
                &mut expires_in_seconds,
                required(arg, args.next())?
                    .parse::<u64>()
                    .context("invalid --expires-in-seconds")?,
                arg,
            )?,
            "--reason" => replace_once(
                &mut reason,
                SafeLabel::new(required(arg, args.next())?)?,
                arg,
            )?,
            "--bootstrap" => {
                if bootstrap {
                    anyhow::bail!("--bootstrap may only be provided once");
                }
                bootstrap = true;
            }
            _ => anyhow::bail!(
                "role binding issue arguments invalid reason_code=role_admin_args_invalid value_returned=false"
            ),
        }
    }
    let ttl = Duration::from_secs(expires_in_seconds.context("--expires-in-seconds is required")?);
    if ttl.is_zero() || ttl > MAX_ROLE_BINDING_TTL {
        anyhow::bail!(
            "role binding validity denied reason_code=role_binding_validity_invalid value_returned=false"
        );
    }
    Ok(IssueConfig {
        principal_binding,
        role: role.context("--role is required")?,
        target_binding,
        ttl,
        source_reference: source_reference.context("--source-reference is required")?,
        reason: reason.context("--reason is required")?,
        bootstrap,
    })
}

fn parse_binding_only(args: &[String]) -> Result<RoleBindingId> {
    match args {
        [flag, binding_id] if flag == "--binding" => {
            Ok(RoleBindingId::from_opaque(binding_id.clone())?)
        }
        _ => anyhow::bail!(
            "role binding status arguments invalid reason_code=role_admin_args_invalid value_returned=false"
        ),
    }
}

fn parse_revoke(args: &[String]) -> Result<(RoleBindingId, SafeLabel)> {
    let mut binding = None;
    let mut reason = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--binding" => replace_once(
                &mut binding,
                RoleBindingId::from_opaque(required(arg, args.next())?.to_string())?,
                arg,
            )?,
            "--reason" => replace_once(
                &mut reason,
                SafeLabel::new(required(arg, args.next())?)?,
                arg,
            )?,
            _ => anyhow::bail!(
                "role binding revoke arguments invalid reason_code=role_admin_args_invalid value_returned=false"
            ),
        }
    }
    Ok((
        binding.context("--binding is required")?,
        reason.context("--reason is required")?,
    ))
}

fn required<'a>(flag: &str, value: Option<&'a String>) -> Result<&'a str> {
    value
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .with_context(|| format!("{flag} requires a value"))
}

fn replace_once<T>(slot: &mut Option<T>, value: T, flag: &str) -> Result<()> {
    if slot.replace(value).is_some() {
        anyhow::bail!("{flag} may only be provided once");
    }
    Ok(())
}

fn registry() -> Result<FileRoleBindingRegistry> {
    Ok(FileRoleBindingRegistry::new(required_env_path(
        "JANUS_ROLE_BINDINGS_ROOT",
    )?))
}

fn role_audit() -> Result<JsonlAuditSink> {
    Ok(JsonlAuditSink::open(required_env_path(
        "JANUS_ROLE_AUDIT_FILE",
    )?)?)
}

fn required_env_path(key: &'static str) -> Result<PathBuf> {
    env::var_os(key)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .with_context(|| format!("{key} is required"))
}

fn unix_secs(value: SystemTime) -> u64 {
    value
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_parser_is_closed_and_bounded() {
        let args = vec![
            "--principal-binding".to_string(),
            "executor:other|scope:scp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            "--role".to_string(),
            "viewer".to_string(),
            "--expires-in-seconds".to_string(),
            "60".to_string(),
            "--source-reference".to_string(),
            "review-1".to_string(),
            "--reason".to_string(),
            "on call".to_string(),
        ];
        assert_eq!(parse_issue(&args).unwrap().role, Role::Viewer);
        assert!(!parse_issue(&args).unwrap().bootstrap);
        let mut attacked = args;
        attacked.extend(["--claim-role".to_string(), "owner".to_string()]);
        assert!(parse_issue(&attacked).is_err());
    }

    fn bootstrap_args() -> Vec<String> {
        [
            "role-binding",
            "issue",
            "--bootstrap",
            "--role",
            "security_admin",
        ]
        .into_iter()
        .map(str::to_string)
        .collect()
    }

    #[test]
    fn bootstrap_is_detected_only_on_role_binding_issue() {
        assert!(is_role_bootstrap_request(&bootstrap_args()));
        for denied in [
            vec!["role-binding", "list"],
            vec!["role-binding", "revoke", "--bootstrap"],
            vec!["authorization-policy", "status", "--bootstrap"],
            vec!["role-binding", "issue"],
        ] {
            let args = denied.into_iter().map(str::to_string).collect::<Vec<_>>();
            assert!(!is_role_bootstrap_request(&args), "{args:?}");
        }
    }

    #[test]
    fn bootstrap_flag_after_terminator_is_not_a_bootstrap_request() {
        let args = ["role-binding", "issue", "--", "--bootstrap"]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        assert!(!is_role_bootstrap_request(&args));
    }

    #[test]
    fn bootstrap_flag_parses_once_and_is_not_repeatable() {
        let args = [
            "--bootstrap",
            "--role",
            "security_admin",
            "--expires-in-seconds",
            "60",
            "--source-reference",
            "review-1",
            "--reason",
            "bootstrap",
        ]
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
        let config = parse_issue(&args).unwrap();
        assert!(config.bootstrap);
        // Bootstrap binds the invoking principal, so none may be named.
        assert!(config.principal_binding.is_none());

        let mut repeated = args;
        repeated.push("--bootstrap".to_string());
        assert!(parse_issue(&repeated).is_err());
    }
}
