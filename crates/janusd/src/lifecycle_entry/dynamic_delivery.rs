//! Private preparation boundary for dynamic managed-environment host packages.
//!
//! This daemon accepts only value-free custody references. It re-resolves the
//! current reviewed declaration and delivery profile, opens custody in bounded
//! memory, and persists one separately signed, host-encrypted packet. Nothing
//! in this module transports, installs, reloads, or probes a host.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use ed25519_dalek::SigningKey;
use janus_core::{ManagedSecretRef, ManagedServiceDeclarationV2};
use janus_host::{
    seal_dynamic_host_envelope, DynamicHostEnvelopeBindingV1, DynamicHostEnvelopeSealRequest,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::time::{timeout, Duration};

const CATALOG_SCHEMA: &str = "inspr.janus.managed-dynamic-delivery-catalog.v1";
const PROFILE_SCHEMA: &str = "inspr.janus.managed-dynamic-delivery-profile.v1";
const REQUEST_SCHEMA: &str = "inspr.janus.managed-dynamic-delivery-request.v1";
const RESPONSE_SCHEMA: &str = "inspr.janus.managed-dynamic-delivery-response.v1";
const OUTBOX_SCHEMA: &str = "inspr.janus.managed-dynamic-host-package-outbox.v1";
const HOST_PAYLOAD_SCHEMA: &str = "inspr.janus.dynamic-host-envelope-payload.v1";
const SCHEMA_VERSION: u8 = 1;
const SOCKET_ENV: &str = "JANUS_MANAGED_DYNAMIC_DELIVERY_SOCKET";
const PEER_UID_ENV: &str = "JANUS_MANAGED_DYNAMIC_DELIVERY_ALLOWED_UID";
const DECLARATIONS_ENV: &str = "JANUS_MANAGED_DYNAMIC_DELIVERY_DECLARATION_PATHS";
const PROFILE_ENV: &str = "JANUS_MANAGED_DYNAMIC_DELIVERY_PROFILE_FILE";
const STORE_ENV: &str = "JANUS_MANAGED_DYNAMIC_DELIVERY_CUSTODY_STORE_DIR";
const RECEIPTS_ENV: &str = "JANUS_MANAGED_DYNAMIC_DELIVERY_CUSTODY_RECEIPT_DIR";
const MAX_REQUEST_BYTES: usize = 16 * 1024;
const MAX_RESPONSE_BYTES: usize = 16 * 1024;
const MAX_CATALOG_BYTES: usize = 1024 * 1024;
const MAX_OUTBOX_BYTES: usize = 512 * 1024;
const MAX_PROFILES: usize = 256;
const MAX_DELIVERY_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
const MAX_CUSTODY_PLAINTEXT_BYTES: usize = 1024;
const REQUEST_WAIT: Duration = Duration::from_secs(5);

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveryCatalog {
    schema: String,
    schema_version: u8,
    profiles: Vec<DeliveryProfile>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveryProfile {
    schema: String,
    schema_version: u8,
    host_ref: String,
    service_ref: String,
    delivery_profile_ref: String,
    host_recipient: String,
    producer_key_id: String,
    producer_signing_key_file: PathBuf,
    revocation_epoch: u64,
    envelope_ttl_seconds: u64,
    outbox_dir: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DeliveryRequest {
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
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct DeliveryResponse {
    schema: &'static str,
    schema_version: u8,
    operation_ref: Option<String>,
    package_ref: Option<String>,
    envelope_ref: Option<String>,
    phase: &'static str,
    reason_code: &'static str,
    packet_returned: bool,
    value_returned: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OutboxRecord {
    schema: String,
    schema_version: u8,
    package_ref: String,
    envelope_ref: String,
    operation_ref: String,
    operation_kind: String,
    source: String,
    host_ref: String,
    service_ref: String,
    binding_ref: String,
    secret_ref: String,
    generation_ref: String,
    environment_policy_ref: String,
    environment_policy_fingerprint: String,
    declaration_fingerprint: String,
    environment_name: String,
    delivery_profile_ref: String,
    reload_profile_ref: String,
    health_profile_ref: String,
    revocation_epoch: u64,
    prepared_at_unix_secs: u64,
    expires_at_unix_secs: u64,
    packet_base64: String,
    packet_returned: bool,
    value_returned: bool,
    integrity_hash: String,
}

type ProfileKey = (String, String, String);

pub(crate) async fn run_from_env() -> Result<()> {
    let socket_path = required_absolute_path(SOCKET_ENV)?;
    let store_dir = required_absolute_path(STORE_ENV)?;
    let receipt_dir = required_absolute_path(RECEIPTS_ENV)?;
    if store_dir.starts_with(&receipt_dir) || receipt_dir.starts_with(&store_dir) {
        anyhow::bail!("dynamic delivery custody roots must differ");
    }
    let declarations =
        super::dynamic_custody::load_declarations(&required_paths(DECLARATIONS_ENV)?)?;
    let profiles = load_catalog(&required_absolute_path(PROFILE_ENV)?)?;
    validate_profile_bindings(&declarations, &profiles)?;
    validate_storage_separation(&store_dir, &receipt_dir, &profiles)?;
    let identities = super::super::age_identity_files_from_env()?;
    let allowed_uid = required_uid()?;
    super::ensure_private_dir(&store_dir).context("dynamic delivery custody store invalid")?;
    super::ensure_private_dir(&receipt_dir).context("dynamic delivery custody receipts invalid")?;

    let principal =
        super::super::release_principal_from_env().context("dynamic delivery principal denied")?;
    let release = janus_local::enforce_release_admission_from_env(&principal)
        .context("dynamic delivery release admission denied")?;
    if !release.allows_secret_use() {
        anyhow::bail!("dynamic delivery release admission denied");
    }
    janus_local::enforce_migration_ready_from_env()
        .context("dynamic delivery migration state denied")?;
    janus_local::enforce_scope_transfer_ready_from_env()
        .context("dynamic delivery scope transfer state denied")?;

    let listener = bind_private_socket(&socket_path)?;
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .context("dynamic delivery socket accept failed")?;
        let peer = stream
            .peer_cred()
            .context("dynamic delivery peer credentials unavailable")?;
        if peer.uid() != allowed_uid {
            let mut denied_stream = stream;
            let _ = write_response(
                &mut denied_stream,
                denied(None, "dynamic_delivery_peer_denied"),
            )
            .await;
            continue;
        }
        handle_connection(
            stream,
            &declarations,
            &profiles,
            &store_dir,
            &receipt_dir,
            &identities,
            SystemTime::now(),
        )
        .await;
    }
}

async fn handle_connection(
    mut stream: UnixStream,
    declarations: &[ManagedServiceDeclarationV2],
    profiles: &BTreeMap<ProfileKey, DeliveryProfile>,
    store_dir: &Path,
    receipt_dir: &Path,
    identity_files: &[PathBuf],
    now: SystemTime,
) {
    let request = match timeout(REQUEST_WAIT, read_request(&mut stream)).await {
        Ok(Ok(request)) => request,
        Ok(Err(_)) => {
            let _ = write_response(
                &mut stream,
                denied(None, "dynamic_delivery_protocol_invalid"),
            )
            .await;
            return;
        }
        Err(_) => {
            let _ = write_response(
                &mut stream,
                denied(None, "dynamic_delivery_request_timeout"),
            )
            .await;
            return;
        }
    };
    let operation_ref =
        valid_ref("op_", &request.operation_ref).then(|| request.operation_ref.clone());
    let response = prepare(
        declarations,
        profiles,
        store_dir,
        receipt_dir,
        identity_files,
        &request,
        now,
    )
    .await
    .unwrap_or_else(|reason| denied(operation_ref, reason));
    let _ = write_response(&mut stream, response).await;
}

async fn prepare(
    declarations: &[ManagedServiceDeclarationV2],
    profiles: &BTreeMap<ProfileKey, DeliveryProfile>,
    store_dir: &Path,
    receipt_dir: &Path,
    identity_files: &[PathBuf],
    request: &DeliveryRequest,
    now: SystemTime,
) -> std::result::Result<DeliveryResponse, &'static str> {
    validate_request(request)?;
    let handoff = super::dynamic_custody::validate_delivery_handoff(
        declarations,
        receipt_dir,
        store_dir,
        super::dynamic_custody::CustodyHandoffRequest {
            operation_ref: &request.operation_ref,
            operation_kind: &request.operation_kind,
            source: &request.source,
            host_ref: &request.host_ref,
            service_ref: &request.service_ref,
            environment_policy_ref: &request.environment_policy_ref,
            environment_policy_fingerprint: &request.environment_policy_fingerprint,
            declaration_fingerprint: &request.declaration_fingerprint,
            environment_name: &request.environment_name,
            binding_ref: &request.binding_ref,
            secret_ref: &request.secret_ref,
            generation_ref: &request.generation_ref,
        },
    )?;
    if handoff.binding_ref != request.binding_ref
        || handoff.secret_ref != request.secret_ref
        || handoff.generation_ref != request.generation_ref
    {
        return Err("dynamic_delivery_custody_invalid");
    }
    let policy = handoff
        .declaration
        .dynamic_environment_policy()
        .ok_or("dynamic_delivery_declaration_denied")?;
    let profile = profiles
        .get(&(
            request.host_ref.clone(),
            request.service_ref.clone(),
            policy.delivery_profile_ref().as_str().to_string(),
        ))
        .ok_or("dynamic_delivery_profile_denied")?;
    let package_ref = derived_ref("pkg_", "package", &request.operation_ref);
    let envelope_ref = derived_ref("env_", "envelope", &request.operation_ref);
    let path = profile.outbox_dir.join(format!("{package_ref}.json"));
    if path.exists() {
        let record = load_bound_outbox(&path, request, profile, policy, now)?;
        return Ok(response_from_record(&record));
    }

    let prepared_at = unix_seconds(now)?;
    let expires_at = prepared_at
        .checked_add(profile.envelope_ttl_seconds)
        .ok_or("dynamic_delivery_clock_invalid")?;
    let secret_ref = ManagedSecretRef::new(request.secret_ref.clone())
        .map_err(|_| "dynamic_delivery_request_invalid")?;
    let value = janus_provider_age::open_dynamic_custody(
        store_dir.to_path_buf(),
        secret_ref,
        identity_files.to_vec(),
        MAX_CUSTODY_PLAINTEXT_BYTES,
    )
    .await
    .map_err(|_| "dynamic_delivery_custody_unavailable")?;
    let signing_key = load_signing_key(profile)?;
    let packet = seal_dynamic_host_envelope(DynamicHostEnvelopeSealRequest {
        binding: DynamicHostEnvelopeBindingV1 {
            schema: HOST_PAYLOAD_SCHEMA.to_string(),
            schema_version: SCHEMA_VERSION,
            envelope_ref: envelope_ref.clone(),
            operation_ref: request.operation_ref.clone(),
            operation_kind: request.operation_kind.clone(),
            source: request.source.clone(),
            host_ref: request.host_ref.clone(),
            service_ref: request.service_ref.clone(),
            binding_ref: request.binding_ref.clone(),
            secret_ref: request.secret_ref.clone(),
            generation_ref: request.generation_ref.clone(),
            environment_policy_ref: request.environment_policy_ref.clone(),
            environment_policy_fingerprint: request.environment_policy_fingerprint.clone(),
            declaration_fingerprint: request.declaration_fingerprint.clone(),
            environment_name: request.environment_name.clone(),
            delivery_profile_ref: policy.delivery_profile_ref().as_str().to_string(),
            reload_profile_ref: policy.reload_profile_ref().as_str().to_string(),
            health_profile_ref: policy.health_profile_ref().as_str().to_string(),
            revocation_epoch: profile.revocation_epoch,
            issued_at_unix_secs: prepared_at,
            expires_at_unix_secs: expires_at,
        },
        host_recipient: &profile.host_recipient,
        signing_key_id: &profile.producer_key_id,
        signing_key: &signing_key,
        value,
    })
    .map_err(|_| "dynamic_delivery_seal_failed")?;
    let mut record = OutboxRecord {
        schema: OUTBOX_SCHEMA.to_string(),
        schema_version: SCHEMA_VERSION,
        package_ref,
        envelope_ref,
        operation_ref: request.operation_ref.clone(),
        operation_kind: request.operation_kind.clone(),
        source: request.source.clone(),
        host_ref: request.host_ref.clone(),
        service_ref: request.service_ref.clone(),
        binding_ref: request.binding_ref.clone(),
        secret_ref: request.secret_ref.clone(),
        generation_ref: request.generation_ref.clone(),
        environment_policy_ref: request.environment_policy_ref.clone(),
        environment_policy_fingerprint: request.environment_policy_fingerprint.clone(),
        declaration_fingerprint: request.declaration_fingerprint.clone(),
        environment_name: request.environment_name.clone(),
        delivery_profile_ref: policy.delivery_profile_ref().as_str().to_string(),
        reload_profile_ref: policy.reload_profile_ref().as_str().to_string(),
        health_profile_ref: policy.health_profile_ref().as_str().to_string(),
        revocation_epoch: profile.revocation_epoch,
        prepared_at_unix_secs: prepared_at,
        expires_at_unix_secs: expires_at,
        packet_base64: STANDARD_NO_PAD.encode(packet),
        packet_returned: false,
        value_returned: false,
        integrity_hash: String::new(),
    };
    record.integrity_hash = outbox_hash(&record)?;
    match write_create_new(&path, &record) {
        Ok(()) | Err("dynamic_delivery_outbox_present") => {}
        Err(reason) => return Err(reason),
    }
    let record = load_bound_outbox(&path, request, profile, policy, now)?;
    Ok(response_from_record(&record))
}

fn load_catalog(path: &Path) -> Result<BTreeMap<ProfileKey, DeliveryProfile>> {
    let raw = super::read_regular_bounded(path, MAX_CATALOG_BYTES, true)
        .context("dynamic delivery catalog unavailable")?;
    let catalog: DeliveryCatalog =
        serde_json::from_slice(&raw).context("dynamic delivery catalog invalid")?;
    if catalog.schema != CATALOG_SCHEMA
        || catalog.schema_version != SCHEMA_VERSION
        || catalog.profiles.is_empty()
        || catalog.profiles.len() > MAX_PROFILES
    {
        anyhow::bail!("dynamic delivery catalog invalid");
    }
    let mut profiles = BTreeMap::new();
    let mut outboxes: BTreeSet<PathBuf> = BTreeSet::new();
    for profile in catalog.profiles {
        validate_profile(&profile)?;
        let key = (
            profile.host_ref.clone(),
            profile.service_ref.clone(),
            profile.delivery_profile_ref.clone(),
        );
        if profiles.insert(key, profile.clone()).is_some()
            || outboxes.iter().any(|existing| {
                existing.starts_with(&profile.outbox_dir)
                    || profile.outbox_dir.starts_with(existing)
            })
        {
            anyhow::bail!("dynamic delivery catalog entries must be unique");
        }
        outboxes.insert(profile.outbox_dir.clone());
    }
    Ok(profiles)
}

fn validate_profile(profile: &DeliveryProfile) -> Result<()> {
    if profile.schema != PROFILE_SCHEMA
        || profile.schema_version != SCHEMA_VERSION
        || !valid_ref("host_", &profile.host_ref)
        || !valid_ref("svc_", &profile.service_ref)
        || !valid_ref("delivery_", &profile.delivery_profile_ref)
        || !(profile.host_recipient.starts_with("age1")
            || profile.host_recipient.starts_with("ssh-ed25519 "))
        || profile.host_recipient.len() > 1024
        || !valid_ref("key_", &profile.producer_key_id)
        || !normalized_absolute(&profile.producer_signing_key_file)
        || !normalized_absolute(&profile.outbox_dir)
        || profile.revocation_epoch == 0
        || !(60..=MAX_DELIVERY_TTL_SECONDS).contains(&profile.envelope_ttl_seconds)
    {
        anyhow::bail!("dynamic delivery profile invalid");
    }
    load_signing_key(profile).map_err(anyhow::Error::msg)?;
    janus_host::validate_host_recipient(&profile.host_recipient)
        .map_err(|_| anyhow::anyhow!("dynamic delivery host recipient invalid"))?;
    super::ensure_private_dir(&profile.outbox_dir).context("dynamic delivery outbox invalid")?;
    Ok(())
}

fn validate_profile_bindings(
    declarations: &[ManagedServiceDeclarationV2],
    profiles: &BTreeMap<ProfileKey, DeliveryProfile>,
) -> Result<()> {
    let mut expected = BTreeSet::new();
    for declaration in declarations {
        let policy = declaration
            .dynamic_environment_policy()
            .context("dynamic delivery declaration has no dynamic policy")?;
        expected.insert((
            declaration.host_ref().as_str().to_string(),
            declaration.service_ref().as_str().to_string(),
            policy.delivery_profile_ref().as_str().to_string(),
        ));
    }
    if expected.len() != declarations.len()
        || profiles.len() != expected.len()
        || profiles.keys().any(|key| !expected.contains(key))
    {
        anyhow::bail!("dynamic delivery profile bindings are incomplete");
    }
    Ok(())
}

fn validate_storage_separation(
    store_dir: &Path,
    receipt_dir: &Path,
    profiles: &BTreeMap<ProfileKey, DeliveryProfile>,
) -> Result<()> {
    if profiles.values().any(|profile| {
        profile.outbox_dir.starts_with(store_dir)
            || store_dir.starts_with(&profile.outbox_dir)
            || profile.outbox_dir.starts_with(receipt_dir)
            || receipt_dir.starts_with(&profile.outbox_dir)
            || profile
                .producer_signing_key_file
                .starts_with(&profile.outbox_dir)
    }) {
        anyhow::bail!("dynamic delivery storage roots must be separate");
    }
    Ok(())
}

fn load_signing_key(profile: &DeliveryProfile) -> std::result::Result<SigningKey, &'static str> {
    super::load_host_producer_signing_key(
        &profile.producer_signing_key_file,
        &profile.producer_key_id,
    )
    .map_err(|_| "dynamic_delivery_signing_key_invalid")
}

fn validate_request(request: &DeliveryRequest) -> std::result::Result<(), &'static str> {
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
        || !valid_ref("bind_", &request.binding_ref)
        || !valid_ref("sec_", &request.secret_ref)
        || !valid_ref("gen_", &request.generation_ref)
        || janus_core::ManagedEnvironmentName::new(request.environment_name.clone()).is_err()
    {
        return Err("dynamic_delivery_request_invalid");
    }
    Ok(())
}

fn load_bound_outbox(
    path: &Path,
    request: &DeliveryRequest,
    profile: &DeliveryProfile,
    policy: &janus_core::ManagedDynamicEnvironmentPolicyV2,
    now: SystemTime,
) -> std::result::Result<OutboxRecord, &'static str> {
    let raw = super::read_regular_bounded(path, MAX_OUTBOX_BYTES, true)
        .map_err(|_| "dynamic_delivery_outbox_unavailable")?;
    let record: OutboxRecord =
        serde_json::from_slice(&raw).map_err(|_| "dynamic_delivery_outbox_invalid")?;
    let now = unix_seconds(now)?;
    if record.schema != OUTBOX_SCHEMA
        || record.schema_version != SCHEMA_VERSION
        || record.package_ref != derived_ref("pkg_", "package", &request.operation_ref)
        || record.envelope_ref != derived_ref("env_", "envelope", &request.operation_ref)
        || record.operation_ref != request.operation_ref
        || record.operation_kind != request.operation_kind
        || record.source != request.source
        || record.host_ref != request.host_ref
        || record.service_ref != request.service_ref
        || record.binding_ref != request.binding_ref
        || record.secret_ref != request.secret_ref
        || record.generation_ref != request.generation_ref
        || record.environment_policy_ref != request.environment_policy_ref
        || record.environment_policy_fingerprint != request.environment_policy_fingerprint
        || record.declaration_fingerprint != request.declaration_fingerprint
        || record.environment_name != request.environment_name
        || record.delivery_profile_ref != policy.delivery_profile_ref().as_str()
        || record.reload_profile_ref != policy.reload_profile_ref().as_str()
        || record.health_profile_ref != policy.health_profile_ref().as_str()
        || record.revocation_epoch != profile.revocation_epoch
        || record.prepared_at_unix_secs == 0
        || record.expires_at_unix_secs <= record.prepared_at_unix_secs
        || now >= record.expires_at_unix_secs
        || record.packet_returned
        || record.value_returned
        || record.integrity_hash != outbox_hash(&record)?
    {
        return Err("dynamic_delivery_outbox_invalid");
    }
    let packet = STANDARD_NO_PAD
        .decode(record.packet_base64.as_bytes())
        .map_err(|_| "dynamic_delivery_outbox_invalid")?;
    if packet.is_empty() || packet.len() > janus_host::maximum_packet_bytes() {
        return Err("dynamic_delivery_outbox_invalid");
    }
    Ok(record)
}

fn write_create_new(path: &Path, record: &OutboxRecord) -> std::result::Result<(), &'static str> {
    let parent = path.parent().ok_or("dynamic_delivery_outbox_unavailable")?;
    super::ensure_private_dir(parent).map_err(|_| "dynamic_delivery_outbox_unavailable")?;
    let mut encoded =
        serde_json::to_vec_pretty(record).map_err(|_| "dynamic_delivery_outbox_invalid")?;
    encoded.push(b'\n');
    if encoded.len() > MAX_OUTBOX_BYTES {
        return Err("dynamic_delivery_outbox_invalid");
    }
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .ok_or("dynamic_delivery_outbox_unavailable")?,
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|_| "dynamic_delivery_outbox_unavailable")?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| "dynamic_delivery_outbox_unavailable")?;
        file.write_all(&encoded)
            .map_err(|_| "dynamic_delivery_outbox_unavailable")?;
        file.sync_all()
            .map_err(|_| "dynamic_delivery_outbox_unavailable")?;
        fs::hard_link(&temporary, path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                "dynamic_delivery_outbox_present"
            } else {
                "dynamic_delivery_outbox_unavailable"
            }
        })?;
        fs::remove_file(&temporary).map_err(|_| "dynamic_delivery_outbox_unavailable")?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| "dynamic_delivery_outbox_unavailable")
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn outbox_hash(record: &OutboxRecord) -> std::result::Result<String, &'static str> {
    let mut unsigned = record.clone();
    unsigned.integrity_hash.clear();
    let encoded = serde_json::to_vec(&unsigned).map_err(|_| "dynamic_delivery_outbox_invalid")?;
    Ok(hex::encode(Sha256::digest(encoded)))
}

fn response_from_record(record: &OutboxRecord) -> DeliveryResponse {
    DeliveryResponse {
        schema: RESPONSE_SCHEMA,
        schema_version: SCHEMA_VERSION,
        operation_ref: Some(record.operation_ref.clone()),
        package_ref: Some(record.package_ref.clone()),
        envelope_ref: Some(record.envelope_ref.clone()),
        phase: "prepared",
        reason_code: "dynamic_delivery_prepared",
        packet_returned: false,
        value_returned: false,
    }
}

fn denied(operation_ref: Option<String>, reason_code: &'static str) -> DeliveryResponse {
    DeliveryResponse {
        schema: RESPONSE_SCHEMA,
        schema_version: SCHEMA_VERSION,
        operation_ref,
        package_ref: None,
        envelope_ref: None,
        phase: "denied",
        reason_code,
        packet_returned: false,
        value_returned: false,
    }
}

fn derived_ref(prefix: &str, domain: &str, operation_ref: &str) -> String {
    let digest = Sha256::digest(format!(
        "inspr.janus.dynamic-delivery.v1\0{domain}\0{operation_ref}"
    ));
    format!("{prefix}{}", &hex::encode(digest)[..32])
}

fn valid_ref(prefix: &str, value: &str) -> bool {
    value.len() >= prefix.len() + 8
        && value.len() <= 96
        && value.starts_with(prefix)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn normalized_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path.file_name().is_some()
        && !path.components().any(|part| {
            matches!(
                part,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
}

fn required_absolute_path(name: &str) -> Result<PathBuf> {
    let path = PathBuf::from(std::env::var(name).with_context(|| format!("{name} is required"))?);
    if !normalized_absolute(&path) {
        anyhow::bail!("{name} must be an absolute normalized path");
    }
    Ok(path)
}

fn required_paths(name: &str) -> Result<Vec<PathBuf>> {
    let raw = std::env::var(name).with_context(|| format!("{name} is required"))?;
    let paths = raw
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    if paths.is_empty()
        || paths.len() > 64
        || paths.iter().any(|path| !normalized_absolute(path))
        || paths.iter().collect::<BTreeSet<_>>().len() != paths.len()
    {
        anyhow::bail!("{name} is invalid");
    }
    Ok(paths)
}

fn required_uid() -> Result<u32> {
    std::env::var(PEER_UID_ENV)
        .context("dynamic delivery allowed UID required")?
        .parse::<u32>()
        .context("dynamic delivery allowed UID invalid")
}

fn bind_private_socket(path: &Path) -> Result<UnixListener> {
    let parent = path
        .parent()
        .context("dynamic delivery socket has no parent")?;
    super::ensure_private_dir(parent)?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.file_type().is_socket() {
            anyhow::bail!("dynamic delivery socket path occupied");
        }
        fs::remove_file(path).context("stale dynamic delivery socket unavailable")?;
    }
    let listener = UnixListener::bind(path).context("dynamic delivery socket bind failed")?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .context("dynamic delivery socket permissions failed")?;
    Ok(listener)
}

fn unix_seconds(now: SystemTime) -> std::result::Result<u64, &'static str> {
    now.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "dynamic_delivery_clock_invalid")
}

async fn read_request(stream: &mut UnixStream) -> Result<DeliveryRequest> {
    let length = stream
        .read_u32()
        .await
        .context("request header unavailable")? as usize;
    if length == 0 || length > MAX_REQUEST_BYTES {
        anyhow::bail!("request length invalid");
    }
    let mut bytes = vec![0; length];
    stream
        .read_exact(&mut bytes)
        .await
        .context("request body unavailable")?;
    serde_json::from_slice(&bytes).context("request JSON invalid")
}

async fn write_response(stream: &mut UnixStream, response: DeliveryResponse) -> Result<()> {
    let bytes = serde_json::to_vec(&response).context("dynamic delivery response invalid")?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        anyhow::bail!("dynamic delivery response oversized");
    }
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::secrecy::ExposeSecret;

    fn private_dir(path: &Path) {
        fs::create_dir_all(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn custody_ref(prefix: &str, domain: &str, operation_ref: &str) -> String {
        let digest = Sha256::digest(format!(
            "inspr.janus.dynamic-custody.v1\0{domain}\0{operation_ref}"
        ));
        format!("{prefix}{}", &hex::encode(digest)[..32])
    }

    #[tokio::test]
    async fn prepares_one_value_free_retry_stable_host_package() {
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
        let outbox_dir = temporary.path().join("outbox");
        for path in [&store_dir, &receipt_dir, &outbox_dir] {
            private_dir(path);
        }
        let custody_identity = age::x25519::Identity::generate();
        let custody_identity_file = temporary.path().join("custody.identity");
        fs::write(
            &custody_identity_file,
            custody_identity.to_string().expose_secret(),
        )
        .unwrap();
        fs::set_permissions(&custody_identity_file, fs::Permissions::from_mode(0o600)).unwrap();
        let host_identity = age::x25519::Identity::generate();
        let signing_key = SigningKey::from_bytes(&[23; 32]);
        let signing_key_file = temporary.path().join("signing-key.json");
        fs::write(
            &signing_key_file,
            serde_json::to_vec(&serde_json::json!({
                "schema": super::super::HOST_SIGNING_KEY_SCHEMA,
                "schema_version": 1,
                "key_id": "key_dynamic0001",
                "private_key_base64": STANDARD_NO_PAD.encode(signing_key.to_bytes())
            }))
            .unwrap(),
        )
        .unwrap();
        fs::set_permissions(&signing_key_file, fs::Permissions::from_mode(0o600)).unwrap();

        let operation_ref = "op_dynamicfixture";
        let binding_ref = custody_ref("bind_", "binding", operation_ref);
        let secret_ref = custody_ref("sec_", "secret", operation_ref);
        let generation_ref = custody_ref("gen_", "generation", operation_ref);
        let canary = b"dynamic-delivery-canary";
        janus_provider_age::create_dynamic_custody_if_absent(
            store_dir.clone(),
            ManagedSecretRef::new(secret_ref.clone()).unwrap(),
            vec![custody_identity.to_public().to_string()],
            janus_core::SecretValue::new(canary.to_vec()),
        )
        .await
        .unwrap();
        let receipt = serde_json::json!({
            "schema": "inspr.janus.managed-dynamic-custody-receipt.v1",
            "schema_version": 1,
            "operation_ref": operation_ref,
            "operation_kind": "create",
            "source": "import",
            "host_ref": "host_7f94a1c8e912",
            "service_ref": "svc_24b7c8f0aa19",
            "environment_policy_ref": "envpol_41e6720bc591",
            "environment_policy_fingerprint": "envpf_3f8d9a061c42",
            "declaration_fingerprint": "decl_51268e2b772a",
            "environment_name": "HOME_ASSISTANT_TOKEN",
            "binding_ref": binding_ref,
            "secret_ref": secret_ref,
            "generation_ref": generation_ref,
            "phase": "custodied",
            "created_at_unix_secs": 1_800_000_000u64,
            "updated_at_unix_secs": 1_800_000_000u64,
            "value_returned": false
        });
        let receipt_path = receipt_dir.join(format!("{operation_ref}.json"));
        fs::write(&receipt_path, serde_json::to_vec(&receipt).unwrap()).unwrap();
        fs::set_permissions(&receipt_path, fs::Permissions::from_mode(0o600)).unwrap();

        let policy = declaration.dynamic_environment_policy().unwrap();
        let profile = DeliveryProfile {
            schema: PROFILE_SCHEMA.to_string(),
            schema_version: 1,
            host_ref: declaration.host_ref().as_str().to_string(),
            service_ref: declaration.service_ref().as_str().to_string(),
            delivery_profile_ref: policy.delivery_profile_ref().as_str().to_string(),
            host_recipient: host_identity.to_public().to_string(),
            producer_key_id: "key_dynamic0001".to_string(),
            producer_signing_key_file: signing_key_file,
            revocation_epoch: 7,
            envelope_ttl_seconds: 3600,
            outbox_dir: outbox_dir.clone(),
        };
        let profiles = BTreeMap::from([(
            (
                profile.host_ref.clone(),
                profile.service_ref.clone(),
                profile.delivery_profile_ref.clone(),
            ),
            profile,
        )]);
        let request = DeliveryRequest {
            schema: REQUEST_SCHEMA.to_string(),
            schema_version: 1,
            operation_ref: operation_ref.to_string(),
            operation_kind: "create".to_string(),
            source: "import".to_string(),
            host_ref: "host_7f94a1c8e912".to_string(),
            service_ref: "svc_24b7c8f0aa19".to_string(),
            environment_policy_ref: "envpol_41e6720bc591".to_string(),
            environment_policy_fingerprint: "envpf_3f8d9a061c42".to_string(),
            declaration_fingerprint: "decl_51268e2b772a".to_string(),
            environment_name: "HOME_ASSISTANT_TOKEN".to_string(),
            binding_ref,
            secret_ref,
            generation_ref,
        };
        let now = UNIX_EPOCH + Duration::from_secs(1_800_000_010);
        let declarations = vec![declaration];
        let identities = vec![custody_identity_file];
        let (first, second) = tokio::join!(
            prepare(
                &declarations,
                &profiles,
                &store_dir,
                &receipt_dir,
                &identities,
                &request,
                now,
            ),
            prepare(
                &declarations,
                &profiles,
                &store_dir,
                &receipt_dir,
                &identities,
                &request,
                now,
            )
        );
        let first = first.unwrap();
        let second = second.unwrap();
        assert_eq!(first.package_ref, second.package_ref);
        assert_eq!(first.envelope_ref, second.envelope_ref);
        assert!(!first.packet_returned && !first.value_returned);
        let outbox =
            fs::read(outbox_dir.join(format!("{}.json", first.package_ref.as_ref().unwrap())))
                .unwrap();
        assert!(!outbox.windows(canary.len()).any(|window| window == canary));
        assert!(!String::from_utf8_lossy(&outbox).contains("custody.identity"));
    }
}
