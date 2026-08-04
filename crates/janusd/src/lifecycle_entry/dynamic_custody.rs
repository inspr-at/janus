//! Private, custody-only boundary for dynamic managed environment values.
//!
//! The daemon re-resolves a root-owned v2 declaration before it reads one
//! bounded value frame. It creates one independently encrypted Age object and
//! a strict value-free receipt. There is intentionally no delivery, reload,
//! health, Pharos, or host-agent code in this module.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use janus_core::{
    ManagedEnvironmentName, ManagedSecretRef, ManagedSecretSource, ManagedServiceDeclarationV2,
    SecretValue, MAX_MANAGED_SERVICE_CONTRACT_BYTES,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::time::{timeout, Duration};
use zeroize::Zeroize;

const REQUEST_SCHEMA: &str = "inspr.janus.managed-dynamic-custody-request.v1";
const RESPONSE_SCHEMA: &str = "inspr.janus.managed-dynamic-custody-response.v1";
const RECEIPT_SCHEMA: &str = "inspr.janus.managed-dynamic-custody-receipt.v1";
const SCHEMA_VERSION: u8 = 1;
const SOCKET_ENV: &str = "JANUS_MANAGED_DYNAMIC_CUSTODY_SOCKET";
const PEER_UID_ENV: &str = "JANUS_MANAGED_DYNAMIC_CUSTODY_ALLOWED_UID";
const DECLARATIONS_ENV: &str = "JANUS_MANAGED_DYNAMIC_CUSTODY_DECLARATION_PATHS";
const STORE_ENV: &str = "JANUS_MANAGED_DYNAMIC_CUSTODY_STORE_DIR";
const RECEIPTS_ENV: &str = "JANUS_MANAGED_DYNAMIC_CUSTODY_RECEIPT_DIR";
const MAX_REQUEST_BYTES: usize = 16 * 1024;
const MAX_RESPONSE_BYTES: usize = 16 * 1024;
const MAX_VALUE_BYTES: usize = 1024;
const MAX_CUSTODY_RECEIPTS: usize = 4096;
const REQUEST_WAIT: Duration = Duration::from_secs(5);
const VALUE_WAIT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CustodyRequest {
    schema: String,
    schema_version: u8,
    operation_ref: String,
    operation_kind: String,
    source: String,
    host_ref: String,
    service_ref: String,
    environment_policy_ref: String,
    environment_policy_fingerprint: String,
    declaration_fingerprint: String,
    environment_name: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct CustodyResponse {
    schema: &'static str,
    schema_version: u8,
    operation_ref: Option<String>,
    binding_ref: Option<String>,
    secret_ref: Option<String>,
    generation_ref: Option<String>,
    phase: &'static str,
    reason_code: &'static str,
    expects_value: bool,
    value_returned: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CustodyReceipt {
    schema: String,
    schema_version: u8,
    operation_ref: String,
    operation_kind: String,
    source: String,
    host_ref: String,
    service_ref: String,
    environment_policy_ref: String,
    environment_policy_fingerprint: String,
    declaration_fingerprint: String,
    environment_name: String,
    binding_ref: String,
    secret_ref: String,
    generation_ref: String,
    phase: String,
    created_at_unix_secs: u64,
    updated_at_unix_secs: u64,
    value_returned: bool,
}

struct SecretBuffer(Vec<u8>);

impl SecretBuffer {
    fn into_secret_value(mut self) -> SecretValue {
        SecretValue::new(std::mem::take(&mut self.0))
    }
}

impl Drop for SecretBuffer {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub(crate) async fn run_from_env() -> Result<()> {
    let socket_path = required_absolute_path(SOCKET_ENV)?;
    let store_dir = required_absolute_path(STORE_ENV)?;
    let receipt_dir = required_absolute_path(RECEIPTS_ENV)?;
    if store_dir.starts_with(&receipt_dir) || receipt_dir.starts_with(&store_dir) {
        anyhow::bail!("dynamic custody store and receipt roots must differ");
    }
    let allowed_uid = required_uid()?;
    let declaration_paths = required_declaration_paths()?;
    let declarations = load_declarations(&declaration_paths)?;
    let recipients = super::super::age_recipients_from_env()?;

    let principal =
        super::super::release_principal_from_env().context("dynamic custody principal denied")?;
    let release = janus_local::enforce_release_admission_from_env(&principal)
        .context("dynamic custody release admission denied")?;
    if !release.allows_secret_use() {
        anyhow::bail!("dynamic custody release admission denied");
    }
    janus_local::enforce_migration_ready_from_env()
        .context("dynamic custody migration state denied")?;
    janus_local::enforce_scope_transfer_ready_from_env()
        .context("dynamic custody scope transfer state denied")?;

    ensure_private_dir(&store_dir)?;
    ensure_private_dir(&receipt_dir)?;
    validate_receipt_directory(&receipt_dir, &store_dir)
        .context("dynamic custody receipts invalid")?;
    let listener = bind_private_socket(&socket_path)?;
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .context("dynamic custody socket accept failed")?;
        let peer = stream
            .peer_cred()
            .context("dynamic custody peer credentials unavailable")?;
        if peer.uid() != allowed_uid {
            let mut denied = stream;
            let _ = write_response(
                &mut denied,
                denied_response(None, "dynamic_custody_peer_denied"),
            )
            .await;
            continue;
        }
        handle_connection(stream, &declarations, &store_dir, &receipt_dir, &recipients).await;
    }
}

async fn handle_connection(
    mut stream: UnixStream,
    declarations: &[ManagedServiceDeclarationV2],
    store_dir: &Path,
    receipt_dir: &Path,
    recipients: &[String],
) {
    let request = match timeout(
        REQUEST_WAIT,
        read_json_frame::<CustodyRequest>(&mut stream, MAX_REQUEST_BYTES),
    )
    .await
    {
        Ok(Ok(request)) => request,
        Ok(Err(_)) => {
            let _ = write_response(
                &mut stream,
                denied_response(None, "dynamic_custody_protocol_invalid"),
            )
            .await;
            return;
        }
        Err(_) => {
            let _ = write_response(
                &mut stream,
                denied_response(None, "dynamic_custody_request_timeout"),
            )
            .await;
            return;
        }
    };
    let operation_ref =
        valid_ref("op_", &request.operation_ref).then(|| request.operation_ref.clone());
    let declaration = match resolve_request(declarations, &request) {
        Ok(declaration) => declaration,
        Err(reason) => {
            let _ = write_response(&mut stream, denied_response(operation_ref, reason)).await;
            return;
        }
    };
    let refs = derived_refs(&request.operation_ref);
    let receipt_path = receipt_dir.join(format!("{}.json", request.operation_ref));
    let ciphertext_path = store_dir.join(format!("{}.age", refs.secret_ref));

    if receipt_path.exists() {
        match load_bound_receipt(
            &receipt_path,
            &request,
            &refs,
            declaration,
            &ciphertext_path,
        ) {
            Ok(receipt) => {
                let _ = write_response(&mut stream, response_from_receipt(&receipt)).await;
            }
            Err(reason) => {
                let _ = write_response(&mut stream, denied_response(operation_ref, reason)).await;
            }
        }
        return;
    }

    if ciphertext_path.exists() {
        let response = recover_receipt(
            &receipt_path,
            &ciphertext_path,
            &request,
            &refs,
            declaration,
            SystemTime::now(),
        )
        .map(|receipt| response_from_receipt(&receipt))
        .unwrap_or_else(|reason| denied_response(operation_ref, reason));
        let _ = write_response(&mut stream, response).await;
        return;
    }

    if !receipt_capacity_available(receipt_dir) {
        let _ = write_response(
            &mut stream,
            denied_response(operation_ref, "dynamic_custody_capacity_denied"),
        )
        .await;
        return;
    }

    if write_response(&mut stream, preflight_response(&request.operation_ref))
        .await
        .is_err()
    {
        return;
    }
    let value = match timeout(VALUE_WAIT, read_raw_frame(&mut stream, MAX_VALUE_BYTES)).await {
        Ok(Ok(value)) if validate_value(&value.0) => value,
        Ok(_) => {
            let _ = write_response(
                &mut stream,
                denied_response(operation_ref, "dynamic_custody_value_invalid"),
            )
            .await;
            return;
        }
        Err(_) => {
            let _ = write_response(
                &mut stream,
                denied_response(operation_ref, "dynamic_custody_value_timeout"),
            )
            .await;
            return;
        }
    };
    let secret_ref = match ManagedSecretRef::new(refs.secret_ref.clone()) {
        Ok(secret_ref) => secret_ref,
        Err(_) => {
            let _ = write_response(
                &mut stream,
                denied_response(operation_ref, "dynamic_custody_internal_invalid"),
            )
            .await;
            return;
        }
    };
    let secret_value = value.into_secret_value();
    let stored = janus_provider_age::create_dynamic_custody_if_absent(
        store_dir.to_path_buf(),
        secret_ref,
        recipients.to_vec(),
        secret_value,
    )
    .await;
    if stored.is_err() && !ciphertext_path.exists() {
        let _ = write_response(
            &mut stream,
            denied_response(operation_ref, "dynamic_custody_store_unavailable"),
        )
        .await;
        return;
    }
    let response = recover_receipt(
        &receipt_path,
        &ciphertext_path,
        &request,
        &refs,
        declaration,
        SystemTime::now(),
    )
    .map(|receipt| response_from_receipt(&receipt))
    .unwrap_or_else(|reason| denied_response(operation_ref, reason));
    let _ = write_response(&mut stream, response).await;
}

#[derive(Clone)]
struct CustodyRefs {
    binding_ref: String,
    secret_ref: String,
    generation_ref: String,
}

fn resolve_request<'a>(
    declarations: &'a [ManagedServiceDeclarationV2],
    request: &CustodyRequest,
) -> std::result::Result<&'a ManagedServiceDeclarationV2, &'static str> {
    if request.schema != REQUEST_SCHEMA
        || request.schema_version != SCHEMA_VERSION
        || !valid_ref("op_", &request.operation_ref)
        || !matches!(request.operation_kind.as_str(), "create" | "replace")
        || !matches!(request.source.as_str(), "generated" | "import")
        || !valid_ref("host_", &request.host_ref)
        || !valid_ref("svc_", &request.service_ref)
        || !valid_ref("envpol_", &request.environment_policy_ref)
        || !valid_ref("envpf_", &request.environment_policy_fingerprint)
        || !valid_ref("decl_", &request.declaration_fingerprint)
    {
        return Err("dynamic_custody_request_invalid");
    }
    let environment_name = ManagedEnvironmentName::new(request.environment_name.clone())
        .map_err(|_| "dynamic_custody_request_invalid")?;
    let source = match request.source.as_str() {
        "generated" => ManagedSecretSource::Generated,
        "import" => ManagedSecretSource::Import,
        _ => return Err("dynamic_custody_request_invalid"),
    };
    let mut found = None;
    for declaration in declarations {
        let Some(policy) = declaration.dynamic_environment_policy() else {
            continue;
        };
        if declaration.host_ref().as_str() == request.host_ref
            && declaration.service_ref().as_str() == request.service_ref
            && declaration.declaration_fingerprint().as_str() == request.declaration_fingerprint
            && policy.environment_policy_ref().as_str() == request.environment_policy_ref
            && policy.environment_policy_fingerprint().as_str()
                == request.environment_policy_fingerprint
            && policy.allowed_sources().contains(&source)
            && policy.admits_name(&environment_name)
        {
            if found.is_some() {
                return Err("dynamic_custody_declaration_denied");
            }
            found = Some(declaration);
        }
    }
    found.ok_or("dynamic_custody_declaration_denied")
}

fn recover_receipt(
    receipt_path: &Path,
    ciphertext_path: &Path,
    request: &CustodyRequest,
    refs: &CustodyRefs,
    declaration: &ManagedServiceDeclarationV2,
    now: SystemTime,
) -> std::result::Result<CustodyReceipt, &'static str> {
    validate_private_ciphertext(ciphertext_path)?;
    let timestamp = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "dynamic_custody_clock_invalid")?
        .as_secs();
    let receipt = CustodyReceipt {
        schema: RECEIPT_SCHEMA.to_string(),
        schema_version: SCHEMA_VERSION,
        operation_ref: request.operation_ref.clone(),
        operation_kind: request.operation_kind.clone(),
        source: request.source.clone(),
        host_ref: request.host_ref.clone(),
        service_ref: request.service_ref.clone(),
        environment_policy_ref: request.environment_policy_ref.clone(),
        environment_policy_fingerprint: request.environment_policy_fingerprint.clone(),
        declaration_fingerprint: request.declaration_fingerprint.clone(),
        environment_name: request.environment_name.clone(),
        binding_ref: refs.binding_ref.clone(),
        secret_ref: refs.secret_ref.clone(),
        generation_ref: refs.generation_ref.clone(),
        phase: "custodied".to_string(),
        created_at_unix_secs: timestamp,
        updated_at_unix_secs: timestamp,
        value_returned: false,
    };
    validate_receipt(&receipt, request, refs, declaration)?;
    write_json_create_new(receipt_path, &receipt)?;
    load_bound_receipt(receipt_path, request, refs, declaration, ciphertext_path)
}

fn load_bound_receipt(
    path: &Path,
    request: &CustodyRequest,
    refs: &CustodyRefs,
    declaration: &ManagedServiceDeclarationV2,
    ciphertext_path: &Path,
) -> std::result::Result<CustodyReceipt, &'static str> {
    let raw = read_regular_bounded(path, MAX_RESPONSE_BYTES)?;
    let receipt: CustodyReceipt =
        serde_json::from_slice(&raw).map_err(|_| "dynamic_custody_receipt_invalid")?;
    validate_receipt(&receipt, request, refs, declaration)?;
    validate_private_ciphertext(ciphertext_path)?;
    Ok(receipt)
}

fn validate_receipt(
    receipt: &CustodyReceipt,
    request: &CustodyRequest,
    refs: &CustodyRefs,
    declaration: &ManagedServiceDeclarationV2,
) -> std::result::Result<(), &'static str> {
    if receipt.schema != RECEIPT_SCHEMA
        || receipt.schema_version != SCHEMA_VERSION
        || receipt.operation_ref != request.operation_ref
        || receipt.operation_kind != request.operation_kind
        || receipt.source != request.source
        || receipt.host_ref != request.host_ref
        || receipt.service_ref != request.service_ref
        || receipt.environment_policy_ref != request.environment_policy_ref
        || receipt.environment_policy_fingerprint != request.environment_policy_fingerprint
        || receipt.declaration_fingerprint != request.declaration_fingerprint
        || receipt.environment_name != request.environment_name
        || receipt.binding_ref != refs.binding_ref
        || receipt.secret_ref != refs.secret_ref
        || receipt.generation_ref != refs.generation_ref
        || receipt.phase != "custodied"
        || receipt.created_at_unix_secs == 0
        || receipt.updated_at_unix_secs < receipt.created_at_unix_secs
        || receipt.value_returned
        || resolve_request(std::slice::from_ref(declaration), request).is_err()
    {
        return Err("dynamic_custody_receipt_invalid");
    }
    Ok(())
}

fn validate_receipt_directory(path: &Path, store_dir: &Path) -> Result<()> {
    let mut count = 0usize;
    for entry in fs::read_dir(path).context("dynamic custody receipt directory unavailable")? {
        let entry = entry.context("dynamic custody receipt entry unavailable")?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .context("dynamic custody receipt filename invalid")?;
        if !name.ends_with(".json") || !valid_ref("op_", name.trim_end_matches(".json")) {
            anyhow::bail!("dynamic custody receipt filename invalid");
        }
        let raw =
            read_regular_bounded(&entry.path(), MAX_RESPONSE_BYTES).map_err(anyhow::Error::msg)?;
        let receipt: CustodyReceipt =
            serde_json::from_slice(&raw).context("dynamic custody receipt document invalid")?;
        let expected_refs = derived_refs(&receipt.operation_ref);
        if receipt.schema != RECEIPT_SCHEMA
            || receipt.schema_version != SCHEMA_VERSION
            || receipt.operation_ref != name.trim_end_matches(".json")
            || !matches!(receipt.operation_kind.as_str(), "create" | "replace")
            || !matches!(receipt.source.as_str(), "generated" | "import")
            || !valid_ref("host_", &receipt.host_ref)
            || !valid_ref("svc_", &receipt.service_ref)
            || !valid_ref("envpol_", &receipt.environment_policy_ref)
            || !valid_ref("envpf_", &receipt.environment_policy_fingerprint)
            || !valid_ref("decl_", &receipt.declaration_fingerprint)
            || ManagedEnvironmentName::new(receipt.environment_name.clone()).is_err()
            || !valid_ref("bind_", &receipt.binding_ref)
            || !valid_ref("sec_", &receipt.secret_ref)
            || !valid_ref("gen_", &receipt.generation_ref)
            || receipt.binding_ref != expected_refs.binding_ref
            || receipt.secret_ref != expected_refs.secret_ref
            || receipt.generation_ref != expected_refs.generation_ref
            || receipt.phase != "custodied"
            || receipt.created_at_unix_secs == 0
            || receipt.updated_at_unix_secs < receipt.created_at_unix_secs
            || receipt.value_returned
        {
            anyhow::bail!("dynamic custody receipt document invalid");
        }
        validate_private_ciphertext(&store_dir.join(format!("{}.age", receipt.secret_ref)))
            .map_err(anyhow::Error::msg)?;
        count += 1;
        if count > MAX_CUSTODY_RECEIPTS {
            anyhow::bail!("dynamic custody receipt capacity exceeded");
        }
    }
    Ok(())
}

fn receipt_capacity_available(path: &Path) -> bool {
    fs::read_dir(path)
        .ok()
        .and_then(|entries| {
            entries
                .take(MAX_CUSTODY_RECEIPTS + 1)
                .try_fold(0usize, |count, entry| entry.ok().map(|_| count + 1))
        })
        .is_some_and(|count| count < MAX_CUSTODY_RECEIPTS)
}

fn derived_refs(operation_ref: &str) -> CustodyRefs {
    CustodyRefs {
        binding_ref: derived_ref("bind_", "binding", operation_ref),
        secret_ref: derived_ref("sec_", "secret", operation_ref),
        generation_ref: derived_ref("gen_", "generation", operation_ref),
    }
}

fn derived_ref(prefix: &str, domain: &str, operation_ref: &str) -> String {
    let digest = Sha256::digest(format!(
        "inspr.janus.dynamic-custody.v1\0{domain}\0{operation_ref}"
    ));
    format!("{prefix}{}", &hex::encode(digest)[..32])
}

fn validate_value(value: &[u8]) -> bool {
    !value.is_empty()
        && value.len() <= MAX_VALUE_BYTES
        && std::str::from_utf8(value).is_ok()
        && !value.iter().any(|byte| matches!(byte, 0 | b'\r' | b'\n'))
}

fn response_from_receipt(receipt: &CustodyReceipt) -> CustodyResponse {
    CustodyResponse {
        schema: RESPONSE_SCHEMA,
        schema_version: SCHEMA_VERSION,
        operation_ref: Some(receipt.operation_ref.clone()),
        binding_ref: Some(receipt.binding_ref.clone()),
        secret_ref: Some(receipt.secret_ref.clone()),
        generation_ref: Some(receipt.generation_ref.clone()),
        phase: "custodied",
        reason_code: "dynamic_custody_stored",
        expects_value: false,
        value_returned: false,
    }
}

fn preflight_response(operation_ref: &str) -> CustodyResponse {
    CustodyResponse {
        schema: RESPONSE_SCHEMA,
        schema_version: SCHEMA_VERSION,
        operation_ref: Some(operation_ref.to_string()),
        binding_ref: None,
        secret_ref: None,
        generation_ref: None,
        phase: "preflighted",
        reason_code: "dynamic_custody_preflighted",
        expects_value: true,
        value_returned: false,
    }
}

fn denied_response(operation_ref: Option<String>, reason_code: &'static str) -> CustodyResponse {
    CustodyResponse {
        schema: RESPONSE_SCHEMA,
        schema_version: SCHEMA_VERSION,
        operation_ref,
        binding_ref: None,
        secret_ref: None,
        generation_ref: None,
        phase: "denied",
        reason_code,
        expects_value: false,
        value_returned: false,
    }
}

fn load_declarations(paths: &[PathBuf]) -> Result<Vec<ManagedServiceDeclarationV2>> {
    let mut declarations = Vec::with_capacity(paths.len());
    let mut service_keys = std::collections::BTreeSet::new();
    let mut policy_refs = std::collections::BTreeSet::new();
    for path in paths {
        let raw = read_regular_bounded(path, MAX_MANAGED_SERVICE_CONTRACT_BYTES)
            .map_err(anyhow::Error::msg)?;
        let text = std::str::from_utf8(&raw).context("dynamic custody declaration is not UTF-8")?;
        let declaration = ManagedServiceDeclarationV2::parse_json(text)
            .context("dynamic custody declaration invalid")?;
        let service_key = format!(
            "{}\0{}",
            declaration.host_ref().as_str(),
            declaration.service_ref().as_str()
        );
        if !service_keys.insert(service_key) {
            anyhow::bail!("duplicate dynamic custody service declaration");
        }
        if let Some(policy) = declaration.dynamic_environment_policy() {
            if !policy_refs.insert(policy.environment_policy_ref().as_str().to_string()) {
                anyhow::bail!("duplicate dynamic custody policy declaration");
            }
        }
        declarations.push(declaration);
    }
    Ok(declarations)
}

fn required_declaration_paths() -> Result<Vec<PathBuf>> {
    let raw = std::env::var(DECLARATIONS_ENV).context("dynamic custody declarations required")?;
    let paths = raw
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    if paths.is_empty()
        || paths.len() > 64
        || paths.iter().any(|path| !path.is_absolute())
        || paths
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != paths.len()
    {
        anyhow::bail!("dynamic custody declaration paths invalid");
    }
    Ok(paths)
}

fn required_absolute_path(name: &str) -> Result<PathBuf> {
    let path = PathBuf::from(std::env::var(name).with_context(|| format!("{name} is required"))?);
    if !path.is_absolute()
        || path.components().any(|part| {
            matches!(
                part,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        anyhow::bail!("{name} must be an absolute normalized path");
    }
    Ok(path)
}

fn required_uid() -> Result<u32> {
    std::env::var(PEER_UID_ENV)
        .context("dynamic custody allowed UID required")?
        .parse::<u32>()
        .context("dynamic custody allowed UID invalid")
}

fn valid_ref(prefix: &str, value: &str) -> bool {
    value.len() >= prefix.len() + 8
        && value.len() <= 96
        && value.starts_with(prefix)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn ensure_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).context("dynamic custody directory unavailable")?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .context("dynamic custody directory permissions unavailable")
}

fn bind_private_socket(path: &Path) -> Result<UnixListener> {
    let parent = path
        .parent()
        .context("dynamic custody socket has no parent")?;
    ensure_private_dir(parent)?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.file_type().is_socket() {
            anyhow::bail!("dynamic custody socket path occupied");
        }
        fs::remove_file(path).context("stale dynamic custody socket unavailable")?;
    }
    let listener = UnixListener::bind(path).context("dynamic custody socket bind failed")?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .context("dynamic custody socket permissions failed")?;
    Ok(listener)
}

fn validate_private_ciphertext(path: &Path) -> std::result::Result<(), &'static str> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "dynamic_custody_store_unavailable")?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err("dynamic_custody_store_unavailable");
    }
    Ok(())
}

fn read_regular_bounded(path: &Path, maximum: usize) -> std::result::Result<Vec<u8>, &'static str> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "dynamic_custody_file_unavailable")?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > maximum as u64
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err("dynamic_custody_file_invalid");
    }
    fs::read(path).map_err(|_| "dynamic_custody_file_unavailable")
}

fn write_json_create_new(
    path: &Path,
    receipt: &CustodyReceipt,
) -> std::result::Result<(), &'static str> {
    let parent = path.parent().ok_or("dynamic_custody_receipt_unavailable")?;
    ensure_private_dir(parent).map_err(|_| "dynamic_custody_receipt_unavailable")?;
    let encoded = serde_json::to_vec(receipt).map_err(|_| "dynamic_custody_receipt_invalid")?;
    if encoded.len() > MAX_RESPONSE_BYTES {
        return Err("dynamic_custody_receipt_invalid");
    }
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .ok_or("dynamic_custody_receipt_unavailable")?,
        std::process::id()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|_| "dynamic_custody_receipt_unavailable")?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| "dynamic_custody_receipt_unavailable")?;
        file.write_all(&encoded)
            .map_err(|_| "dynamic_custody_receipt_unavailable")?;
        file.sync_all()
            .map_err(|_| "dynamic_custody_receipt_unavailable")?;
        fs::hard_link(&temporary, path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                "dynamic_custody_receipt_present"
            } else {
                "dynamic_custody_receipt_unavailable"
            }
        })?;
        fs::remove_file(&temporary).map_err(|_| "dynamic_custody_receipt_unavailable")?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| "dynamic_custody_receipt_unavailable")
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

async fn read_json_frame<T: for<'de> Deserialize<'de>>(
    stream: &mut UnixStream,
    maximum: usize,
) -> Result<T> {
    let bytes = read_frame(stream, maximum).await?;
    serde_json::from_slice(&bytes).context("dynamic custody JSON frame invalid")
}

async fn read_raw_frame(stream: &mut UnixStream, maximum: usize) -> Result<SecretBuffer> {
    read_frame(stream, maximum).await.map(SecretBuffer)
}

async fn read_frame(stream: &mut UnixStream, maximum: usize) -> Result<Vec<u8>> {
    let length = stream
        .read_u32()
        .await
        .context("frame header unavailable")? as usize;
    if length == 0 || length > maximum {
        anyhow::bail!("frame length invalid");
    }
    let mut bytes = vec![0; length];
    stream
        .read_exact(&mut bytes)
        .await
        .context("frame body unavailable")?;
    Ok(bytes)
}

async fn write_response(stream: &mut UnixStream, response: CustodyResponse) -> Result<()> {
    let bytes = serde_json::to_vec(&response).context("dynamic custody response invalid")?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        anyhow::bail!("dynamic custody response oversized");
    }
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct TestResponse {
        secret_ref: Option<String>,
        phase: String,
        expects_value: bool,
        value_returned: bool,
    }

    fn fixture_request() -> CustodyRequest {
        CustodyRequest {
            schema: REQUEST_SCHEMA.to_string(),
            schema_version: SCHEMA_VERSION,
            operation_ref: "op_0123456789abcdef".to_string(),
            operation_kind: "create".to_string(),
            source: "import".to_string(),
            host_ref: "host_0123456789abcdef".to_string(),
            service_ref: "svc_0123456789abcdef".to_string(),
            environment_policy_ref: "envpol_0123456789abcdef".to_string(),
            environment_policy_fingerprint: "envpf_0123456789abcdef".to_string(),
            declaration_fingerprint: "decl_0123456789abcdef".to_string(),
            environment_name: "SERVICE_TOKEN".to_string(),
        }
    }

    #[test]
    fn references_are_stable_opaque_and_separated() {
        let first = derived_refs(&fixture_request().operation_ref);
        let second = derived_refs(&fixture_request().operation_ref);
        assert_eq!(first.binding_ref, second.binding_ref);
        assert_eq!(first.secret_ref, second.secret_ref);
        assert_eq!(first.generation_ref, second.generation_ref);
        assert_ne!(
            first.binding_ref.trim_start_matches("bind_"),
            first.secret_ref.trim_start_matches("sec_")
        );
    }

    #[test]
    fn value_contract_is_single_line_utf8_and_bounded() {
        assert!(validate_value(b"one-secret"));
        for denied in [b"".as_slice(), b"line\n", b"line\r", b"nul\0byte", &[0xff]] {
            assert!(!validate_value(denied));
        }
        assert!(!validate_value(&vec![b'x'; MAX_VALUE_BYTES + 1]));
    }

    #[test]
    fn responses_never_contain_value_or_path_fields() {
        let response = serde_json::to_value(preflight_response("op_0123456789abcdef")).unwrap();
        assert_eq!(response["value_returned"], false);
        for denied in ["value", "ciphertext", "path", "filename", "digest"] {
            assert!(response.get(denied).is_none());
        }
    }

    #[tokio::test]
    async fn connection_encrypts_once_then_recovers_without_another_value_frame() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../contracts/managed-service-dynamic-env-contract-v2.json"
        ))
        .unwrap();
        let declaration = ManagedServiceDeclarationV2::parse_json(
            &serde_json::to_string(&fixture["declaration"]).unwrap(),
        )
        .unwrap();
        let temporary = tempfile::TempDir::new().unwrap();
        let store_dir = temporary.path().join("custody");
        let receipt_dir = temporary.path().join("receipts");
        ensure_private_dir(&store_dir).unwrap();
        ensure_private_dir(&receipt_dir).unwrap();
        let identity = age::x25519::Identity::generate();
        let recipients = vec![identity.to_public().to_string()];
        let request = CustodyRequest {
            schema: REQUEST_SCHEMA.to_string(),
            schema_version: SCHEMA_VERSION,
            operation_ref: "op_0123456789abcdef".to_string(),
            operation_kind: "create".to_string(),
            source: "import".to_string(),
            host_ref: "host_7f94a1c8e912".to_string(),
            service_ref: "svc_24b7c8f0aa19".to_string(),
            environment_policy_ref: "envpol_41e6720bc591".to_string(),
            environment_policy_fingerprint: "envpf_3f8d9a061c42".to_string(),
            declaration_fingerprint: "decl_51268e2b772a".to_string(),
            environment_name: "HOME_ASSISTANT_TOKEN".to_string(),
        };
        let canary = b"dynamic-custody-canary";

        let (mut client, server) = UnixStream::pair().unwrap();
        let task = tokio::spawn({
            let declaration = declaration.clone();
            let store_dir = store_dir.clone();
            let receipt_dir = receipt_dir.clone();
            let recipients = recipients.clone();
            async move {
                handle_connection(
                    server,
                    &[declaration],
                    &store_dir,
                    &receipt_dir,
                    &recipients,
                )
                .await
            }
        });
        let request_bytes = serde_json::to_vec(&request).unwrap();
        client.write_u32(request_bytes.len() as u32).await.unwrap();
        client.write_all(&request_bytes).await.unwrap();
        let preflight: TestResponse = read_json_frame(&mut client, MAX_RESPONSE_BYTES)
            .await
            .unwrap();
        assert_eq!(preflight.phase, "preflighted");
        assert!(preflight.expects_value);
        client.write_u32(canary.len() as u32).await.unwrap();
        client.write_all(canary).await.unwrap();
        let stored: TestResponse = read_json_frame(&mut client, MAX_RESPONSE_BYTES)
            .await
            .unwrap();
        assert_eq!(stored.phase, "custodied");
        assert!(!stored.value_returned);
        task.await.unwrap();

        let ciphertext =
            fs::read(store_dir.join(format!("{}.age", stored.secret_ref.as_ref().unwrap())))
                .unwrap();
        assert!(!ciphertext
            .windows(canary.len())
            .any(|window| window == canary));
        let receipt = fs::read(receipt_dir.join("op_0123456789abcdef.json")).unwrap();
        assert!(!receipt.windows(canary.len()).any(|window| window == canary));
        assert!(!String::from_utf8_lossy(&receipt).contains("ciphertext"));

        let (mut retry_client, retry_server) = UnixStream::pair().unwrap();
        let retry_task = tokio::spawn({
            let store_dir = store_dir.clone();
            let receipt_dir = receipt_dir.clone();
            async move {
                handle_connection(
                    retry_server,
                    &[declaration],
                    &store_dir,
                    &receipt_dir,
                    &recipients,
                )
                .await
            }
        });
        retry_client
            .write_u32(request_bytes.len() as u32)
            .await
            .unwrap();
        retry_client.write_all(&request_bytes).await.unwrap();
        let recovered: TestResponse = read_json_frame(&mut retry_client, MAX_RESPONSE_BYTES)
            .await
            .unwrap();
        assert_eq!(recovered.phase, "custodied");
        assert!(!recovered.expects_value);
        assert_eq!(recovered.secret_ref, stored.secret_ref);
        retry_task.await.unwrap();
    }
}
