//! Host-local, one-name agenix-to-Janus import command.

#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use janus_core::{NamespaceId, ScopePathV1, ScopeRef, SecretName, WorkloadId};
use janus_provider_age::{import_agenix_material_if_absent, AgeAdminOutcome, AgeSecretStore};

fn main() {
    match run() {
        Ok(outcome) => emit_outcome(&outcome),
        Err(reason_code) => {
            eprintln!("janus-agenix-import failed reason_code={reason_code} value_returned=false");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<AgeAdminOutcome, &'static str> {
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    if args.len() != 1 {
        return Err("agenix_import_arguments_denied");
    }
    let raw_name = args[0]
        .clone()
        .into_string()
        .map_err(|_| "agenix_import_name_invalid")?;
    let name = SecretName::new(raw_name).map_err(|_| "agenix_import_name_invalid")?;
    let material_root = env::var_os("JANUS_AGENIX_MATERIAL_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/run/agenix"));
    let mut store = load_store_from_env()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .map_err(|_| "agenix_import_runtime_unavailable")?;
    runtime
        .block_on(import_agenix_material_if_absent(
            material_root,
            &name,
            &mut store,
        ))
        .map_err(|error| match error {
            janus_core::JanusError::InvalidIdentifier { .. } => "agenix_import_name_invalid",
            janus_core::JanusError::NotInManifest { .. } => "agenix_import_not_in_catalog",
            janus_core::JanusError::PolicyDenied { reason_code, .. } => reason_code,
            _ => "agenix_import_store_unavailable",
        })
}

fn load_store_from_env() -> Result<AgeSecretStore, &'static str> {
    let manifest = env_first(&[
        "JANUS_AGE_MANIFEST_FILE",
        "JANUS_WARDEN_AGE_MANIFEST_FILE",
        "JANUS_WARDEN_SECRETSPEC_FILE",
    ])
    .map(PathBuf::from)
    .ok_or("agenix_import_configuration_invalid")?;
    let profile = env_first(&["JANUS_AGE_PROFILE", "JANUS_WARDEN_AGE_PROFILE"])
        .unwrap_or_else(|| "default".to_string());
    let store_dir = env_first(&["JANUS_AGE_STORE_DIR", "JANUS_WARDEN_AGE_STORE_DIR"])
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/janus/secrets"));
    let identity_files = identity_files_from_env()?;
    let recipients = recipients_from_env()?;
    AgeSecretStore::load_from_secretspec_manifest(
        manifest,
        profile,
        store_dir,
        identity_files,
        recipients,
        scope_from_env()?,
    )
    .map_err(|_| "agenix_import_configuration_invalid")
}

fn identity_files_from_env() -> Result<Vec<PathBuf>, &'static str> {
    let mut files = Vec::new();
    for key in ["JANUS_AGE_IDENTITY_FILE", "JANUS_WARDEN_AGE_IDENTITY_FILE"] {
        if let Ok(value) = env::var(key) {
            files.push(PathBuf::from(value));
        }
    }
    for key in [
        "JANUS_AGE_IDENTITY_FILES",
        "JANUS_WARDEN_AGE_IDENTITY_FILES",
    ] {
        if let Ok(value) = env::var(key) {
            files.extend(
                value
                    .split(':')
                    .filter(|part| !part.trim().is_empty())
                    .map(PathBuf::from),
            );
        }
    }
    if files.is_empty() {
        return Err("agenix_import_configuration_invalid");
    }
    Ok(files)
}

fn recipients_from_env() -> Result<Vec<String>, &'static str> {
    let mut recipients = Vec::new();
    for key in ["JANUS_AGE_RECIPIENT", "JANUS_WARDEN_AGE_RECIPIENT"] {
        if let Ok(value) = env::var(key) {
            recipients.push(value);
        }
    }
    for key in [
        "JANUS_AGE_RECIPIENTS_FILE",
        "JANUS_WARDEN_AGE_RECIPIENTS_FILE",
    ] {
        if let Ok(path) = env::var(key) {
            recipients.extend(read_recipient_file(Path::new(&path))?);
        }
    }
    if recipients.is_empty() {
        return Err("agenix_import_configuration_invalid");
    }
    Ok(recipients)
}

fn read_recipient_file(path: &Path) -> Result<Vec<String>, &'static str> {
    let contents = fs::read_to_string(path).map_err(|_| "agenix_import_configuration_invalid")?;
    Ok(contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect())
}

fn scope_from_env() -> Result<ScopeRef, &'static str> {
    let mut scope = ScopePathV1::for_repository(
        required_env("JANUS_SCOPE_ORGANIZATION")?,
        required_env("JANUS_SCOPE_PROJECT")?,
        required_env("JANUS_SCOPE_REPOSITORY")?,
        required_env("JANUS_SCOPE_ENVIRONMENT")?,
    )
    .map_err(|_| "agenix_import_configuration_invalid")?;
    if let Some(namespace) = optional_env("JANUS_SCOPE_NAMESPACE")? {
        scope = scope.with_namespace(
            NamespaceId::new(namespace).map_err(|_| "agenix_import_configuration_invalid")?,
        );
    }
    if let Some(workload) = optional_env("JANUS_SCOPE_WORKLOAD")? {
        scope = scope
            .with_workload(
                WorkloadId::new(workload).map_err(|_| "agenix_import_configuration_invalid")?,
            )
            .map_err(|_| "agenix_import_configuration_invalid")?;
    }
    Ok(scope.scope_ref())
}

fn required_env(key: &'static str) -> Result<String, &'static str> {
    optional_env(key)?.ok_or("agenix_import_configuration_invalid")
}

fn optional_env(key: &'static str) -> Result<Option<String>, &'static str> {
    match env::var(key) {
        Ok(value) if !value.is_empty() && value.trim().len() == value.len() => Ok(Some(value)),
        Ok(_) | Err(env::VarError::NotUnicode(_)) => Err("agenix_import_configuration_invalid"),
        Err(env::VarError::NotPresent) => Ok(None),
    }
}

fn env_first(keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| env::var(key).ok())
}

fn emit_outcome(outcome: &AgeAdminOutcome) {
    println!(
        "{{\"action\":\"{}\",\"changed\":{},\"present_secrets\":{},\"recipient_count\":{},\"value_returned\":{}}}",
        outcome.action,
        outcome.changed,
        outcome.present_secrets,
        outcome.recipient_count,
        outcome.value_returned
    );
}
