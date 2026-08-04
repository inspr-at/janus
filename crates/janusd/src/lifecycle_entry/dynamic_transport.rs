//! Private transport boundary for prepared dynamic host packages.
//!
//! This process never opens custody. It returns one already signed and
//! host-encrypted packet to the trusted Go edge and persists only an exact,
//! value-free materialization receipt. Reload, health, activation,
//! replacement, rollback, and removal remain outside this boundary.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::time::{timeout, Duration};

use super::dynamic_delivery::{
    load_catalog, normalized_absolute, outbox_hash, valid_ref, DeliveryProfile, OutboxRecord,
    ProfileKey, MAX_OUTBOX_BYTES, OUTBOX_SCHEMA, SCHEMA_VERSION,
};

const REQUEST_SCHEMA: &str = "inspr.janus.managed-dynamic-transport-request.v1";
const RESPONSE_SCHEMA: &str = "inspr.janus.managed-dynamic-transport-response.v1";
const RECEIPT_SCHEMA: &str = "inspr.janus.managed-dynamic-host-receipt.v1";
const SOCKET_ENV: &str = "JANUS_MANAGED_DYNAMIC_TRANSPORT_SOCKET";
const PEER_UID_ENV: &str = "JANUS_MANAGED_DYNAMIC_TRANSPORT_ALLOWED_UID";
const PROFILE_ENV: &str = "JANUS_MANAGED_DYNAMIC_TRANSPORT_PROFILE_FILE";
const RECEIPT_DIR_ENV: &str = "JANUS_MANAGED_DYNAMIC_TRANSPORT_RECEIPT_DIR";
const MAX_REQUEST_BYTES: usize = 32 * 1024;
const MAX_RESPONSE_BYTES: usize = 768 * 1024;
const MAX_RECEIPT_BYTES: usize = 32 * 1024;
const MAX_OUTBOX_RECORDS: usize = 4096;
const REQUEST_WAIT: Duration = Duration::from_secs(5);

#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum TransportRequest {
    Claim {
        schema: String,
        schema_version: u8,
        host_ref: String,
        packet_returned: bool,
        value_returned: bool,
    },
    Acknowledge {
        schema: String,
        schema_version: u8,
        receipt: Box<TransportAcknowledgementRequest>,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransportAcknowledgementRequest {
    host_ref: String,
    service_ref: String,
    environment_policy_ref: String,
    operation_ref: String,
    package_ref: String,
    envelope_ref: String,
    binding_ref: String,
    generation_ref: String,
    phase: String,
    reason_code: String,
    observed_at_unix_secs: u64,
    packet_returned: bool,
    value_returned: bool,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct TransportResponse {
    schema: &'static str,
    schema_version: u8,
    action: &'static str,
    host_ref: Option<String>,
    service_ref: Option<String>,
    environment_policy_ref: Option<String>,
    operation_ref: Option<String>,
    package_ref: Option<String>,
    envelope_ref: Option<String>,
    binding_ref: Option<String>,
    generation_ref: Option<String>,
    packet_base64: Option<String>,
    phase: &'static str,
    reason_code: &'static str,
    packet_returned: bool,
    value_returned: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct MaterializationReceipt {
    schema: String,
    schema_version: u8,
    host_ref: String,
    service_ref: String,
    environment_policy_ref: String,
    operation_ref: String,
    package_ref: String,
    envelope_ref: String,
    binding_ref: String,
    generation_ref: String,
    phase: String,
    reason_code: String,
    observed_at_unix_secs: u64,
    packet_returned: bool,
    value_returned: bool,
    integrity_hash: String,
}

#[derive(Clone)]
struct Acknowledgement {
    host_ref: String,
    service_ref: String,
    environment_policy_ref: String,
    operation_ref: String,
    package_ref: String,
    envelope_ref: String,
    binding_ref: String,
    generation_ref: String,
    phase: String,
    reason_code: String,
    observed_at_unix_secs: u64,
    packet_returned: bool,
    value_returned: bool,
}

pub(crate) async fn run_from_env() -> Result<()> {
    let socket_path = required_absolute_path(SOCKET_ENV)?;
    let profile_path = required_absolute_path(PROFILE_ENV)?;
    let receipt_dir = required_absolute_path(RECEIPT_DIR_ENV)?;
    let profiles = load_catalog(&profile_path)?;
    validate_receipt_separation(&receipt_dir, &profiles)?;
    super::ensure_private_dir(&receipt_dir).context("dynamic transport receipt root invalid")?;
    let allowed_uid = required_uid()?;

    let principal =
        super::super::release_principal_from_env().context("dynamic transport principal denied")?;
    let release = janus_local::enforce_release_admission_from_env(&principal)
        .context("dynamic transport release admission denied")?;
    if !release.allows_secret_use() {
        anyhow::bail!("dynamic transport release admission denied");
    }
    janus_local::enforce_migration_ready_from_env()
        .context("dynamic transport migration state denied")?;
    janus_local::enforce_scope_transfer_ready_from_env()
        .context("dynamic transport scope transfer state denied")?;

    let listener = bind_private_socket(&socket_path)?;
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .context("dynamic transport socket accept failed")?;
        let peer = stream
            .peer_cred()
            .context("dynamic transport peer credentials unavailable")?;
        if peer.uid() != allowed_uid {
            let mut denied_stream = stream;
            let _ = write_response(
                &mut denied_stream,
                denied("unknown", "dynamic_transport_peer_denied"),
            )
            .await;
            continue;
        }
        handle_connection(stream, &profiles, &receipt_dir, SystemTime::now()).await;
    }
}

async fn handle_connection(
    mut stream: UnixStream,
    profiles: &BTreeMap<ProfileKey, DeliveryProfile>,
    receipt_dir: &Path,
    now: SystemTime,
) {
    let request = match timeout(REQUEST_WAIT, read_request(&mut stream)).await {
        Ok(Ok(request)) => request,
        Ok(Err(_)) => {
            let _ = write_response(
                &mut stream,
                denied("unknown", "dynamic_transport_protocol_invalid"),
            )
            .await;
            return;
        }
        Err(_) => {
            let _ = write_response(
                &mut stream,
                denied("unknown", "dynamic_transport_request_timeout"),
            )
            .await;
            return;
        }
    };
    let response = match request {
        TransportRequest::Claim {
            schema,
            schema_version,
            host_ref,
            packet_returned,
            value_returned,
        } => {
            if schema != REQUEST_SCHEMA
                || schema_version != SCHEMA_VERSION
                || !valid_ref("host_", &host_ref)
                || packet_returned
                || value_returned
            {
                denied("claim", "dynamic_transport_request_invalid")
            } else {
                claim(profiles, receipt_dir, &host_ref, now)
                    .unwrap_or_else(|reason| denied("claim", reason))
            }
        }
        TransportRequest::Acknowledge {
            schema,
            schema_version,
            receipt,
        } => {
            let acknowledgement = Acknowledgement {
                host_ref: receipt.host_ref,
                service_ref: receipt.service_ref,
                environment_policy_ref: receipt.environment_policy_ref,
                operation_ref: receipt.operation_ref,
                package_ref: receipt.package_ref,
                envelope_ref: receipt.envelope_ref,
                binding_ref: receipt.binding_ref,
                generation_ref: receipt.generation_ref,
                phase: receipt.phase,
                reason_code: receipt.reason_code,
                observed_at_unix_secs: receipt.observed_at_unix_secs,
                packet_returned: receipt.packet_returned,
                value_returned: receipt.value_returned,
            };
            if schema != REQUEST_SCHEMA || schema_version != SCHEMA_VERSION {
                denied("acknowledge", "dynamic_transport_request_invalid")
            } else {
                acknowledge(profiles, receipt_dir, &acknowledgement, now)
                    .unwrap_or_else(|reason| denied("acknowledge", reason))
            }
        }
    };
    let _ = write_response(&mut stream, response).await;
}

fn claim(
    profiles: &BTreeMap<ProfileKey, DeliveryProfile>,
    receipt_dir: &Path,
    host_ref: &str,
    now: SystemTime,
) -> std::result::Result<TransportResponse, &'static str> {
    let now = unix_seconds(now)?;
    let matching = profiles
        .values()
        .filter(|profile| profile.host_ref == host_ref)
        .collect::<Vec<_>>();
    if matching.is_empty() {
        return Err("dynamic_transport_host_denied");
    }
    let mut candidates = Vec::new();
    let mut records = 0usize;
    for profile in matching {
        let entries = fs::read_dir(&profile.outbox_dir)
            .map_err(|_| "dynamic_transport_outbox_unavailable")?;
        for entry in entries {
            records = records
                .checked_add(1)
                .ok_or("dynamic_transport_outbox_invalid")?;
            if records > MAX_OUTBOX_RECORDS {
                return Err("dynamic_transport_outbox_invalid");
            }
            let entry = entry.map_err(|_| "dynamic_transport_outbox_unavailable")?;
            let path = entry.path();
            let filename = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or("dynamic_transport_outbox_invalid")?;
            let package_ref = filename
                .strip_suffix(".json")
                .filter(|value| valid_ref("pkg_", value))
                .ok_or("dynamic_transport_outbox_invalid")?;
            let record = load_outbox(&path, package_ref, profile)?;
            match load_receipt(receipt_dir, &record)? {
                Some(_) => continue,
                None if now >= record.expires_at_unix_secs => continue,
                None => candidates.push(record),
            }
        }
    }
    candidates.sort_by(|left, right| {
        (left.prepared_at_unix_secs, left.package_ref.as_str())
            .cmp(&(right.prepared_at_unix_secs, right.package_ref.as_str()))
    });
    let Some(record) = candidates.into_iter().next() else {
        return Ok(no_work(host_ref));
    };
    Ok(TransportResponse {
        schema: RESPONSE_SCHEMA,
        schema_version: SCHEMA_VERSION,
        action: "claim",
        host_ref: Some(record.host_ref),
        service_ref: Some(record.service_ref),
        environment_policy_ref: Some(record.environment_policy_ref),
        operation_ref: Some(record.operation_ref),
        package_ref: Some(record.package_ref),
        envelope_ref: Some(record.envelope_ref),
        binding_ref: Some(record.binding_ref),
        generation_ref: Some(record.generation_ref),
        packet_base64: Some(record.packet_base64),
        phase: "claimed",
        reason_code: "dynamic_transport_package_claimed",
        packet_returned: true,
        value_returned: false,
    })
}

fn acknowledge(
    profiles: &BTreeMap<ProfileKey, DeliveryProfile>,
    receipt_dir: &Path,
    acknowledgement: &Acknowledgement,
    now: SystemTime,
) -> std::result::Result<TransportResponse, &'static str> {
    validate_acknowledgement(acknowledgement)?;
    let now = unix_seconds(now)?;
    let profile_matches = profiles
        .values()
        .filter(|profile| {
            profile.host_ref == acknowledgement.host_ref
                && profile.service_ref == acknowledgement.service_ref
        })
        .collect::<Vec<_>>();
    if profile_matches.len() != 1 {
        return Err("dynamic_transport_receipt_denied");
    }
    let profile = profile_matches[0];
    let record = load_outbox(
        &profile
            .outbox_dir
            .join(format!("{}.json", acknowledgement.package_ref)),
        &acknowledgement.package_ref,
        profile,
    )?;
    if record.host_ref != acknowledgement.host_ref
        || record.service_ref != acknowledgement.service_ref
        || record.environment_policy_ref != acknowledgement.environment_policy_ref
        || record.operation_ref != acknowledgement.operation_ref
        || record.package_ref != acknowledgement.package_ref
        || record.envelope_ref != acknowledgement.envelope_ref
        || record.binding_ref != acknowledgement.binding_ref
        || record.generation_ref != acknowledgement.generation_ref
        || now >= record.expires_at_unix_secs
        || acknowledgement.observed_at_unix_secs < record.prepared_at_unix_secs
        || acknowledgement.observed_at_unix_secs > now.saturating_add(30)
    {
        return Err("dynamic_transport_receipt_denied");
    }
    let mut receipt = MaterializationReceipt {
        schema: RECEIPT_SCHEMA.to_string(),
        schema_version: SCHEMA_VERSION,
        host_ref: acknowledgement.host_ref.clone(),
        service_ref: acknowledgement.service_ref.clone(),
        environment_policy_ref: acknowledgement.environment_policy_ref.clone(),
        operation_ref: acknowledgement.operation_ref.clone(),
        package_ref: acknowledgement.package_ref.clone(),
        envelope_ref: acknowledgement.envelope_ref.clone(),
        binding_ref: acknowledgement.binding_ref.clone(),
        generation_ref: acknowledgement.generation_ref.clone(),
        phase: acknowledgement.phase.clone(),
        reason_code: acknowledgement.reason_code.clone(),
        observed_at_unix_secs: acknowledgement.observed_at_unix_secs,
        packet_returned: false,
        value_returned: false,
        integrity_hash: String::new(),
    };
    receipt.integrity_hash = receipt_hash(&receipt)?;
    let path = receipt_path(receipt_dir, &receipt.package_ref);
    if path.exists() {
        if load_receipt(receipt_dir, &record)?.as_ref() != Some(&receipt) {
            return Err("dynamic_transport_receipt_conflict");
        }
    } else {
        write_receipt_create_new(&path, &receipt)?;
    }
    Ok(TransportResponse {
        schema: RESPONSE_SCHEMA,
        schema_version: SCHEMA_VERSION,
        action: "acknowledge",
        host_ref: Some(receipt.host_ref),
        service_ref: Some(receipt.service_ref),
        environment_policy_ref: Some(receipt.environment_policy_ref),
        operation_ref: Some(receipt.operation_ref),
        package_ref: Some(receipt.package_ref),
        envelope_ref: Some(receipt.envelope_ref),
        binding_ref: Some(receipt.binding_ref),
        generation_ref: Some(receipt.generation_ref),
        packet_base64: None,
        phase: "materialized",
        reason_code: "dynamic_transport_receipt_recorded",
        packet_returned: false,
        value_returned: false,
    })
}

fn validate_acknowledgement(
    acknowledgement: &Acknowledgement,
) -> std::result::Result<(), &'static str> {
    if !valid_ref("host_", &acknowledgement.host_ref)
        || !valid_ref("svc_", &acknowledgement.service_ref)
        || !valid_ref("envpol_", &acknowledgement.environment_policy_ref)
        || !valid_ref("op_", &acknowledgement.operation_ref)
        || !valid_ref("pkg_", &acknowledgement.package_ref)
        || !valid_ref("env_", &acknowledgement.envelope_ref)
        || !valid_ref("bind_", &acknowledgement.binding_ref)
        || !valid_ref("gen_", &acknowledgement.generation_ref)
        || acknowledgement.phase != "materialized"
        || !matches!(
            acknowledgement.reason_code.as_str(),
            "dynamic_host_environment_materialized" | "dynamic_host_materialization_idempotent"
        )
        || acknowledgement.observed_at_unix_secs == 0
        || acknowledgement.packet_returned
        || acknowledgement.value_returned
    {
        return Err("dynamic_transport_receipt_invalid");
    }
    Ok(())
}

fn load_outbox(
    path: &Path,
    package_ref: &str,
    profile: &DeliveryProfile,
) -> std::result::Result<OutboxRecord, &'static str> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| "dynamic_transport_outbox_unavailable")?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_OUTBOX_BYTES as u64
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err("dynamic_transport_outbox_invalid");
    }
    let raw = fs::read(path).map_err(|_| "dynamic_transport_outbox_unavailable")?;
    let record: OutboxRecord =
        serde_json::from_slice(&raw).map_err(|_| "dynamic_transport_outbox_invalid")?;
    if record.schema != OUTBOX_SCHEMA
        || record.schema_version != SCHEMA_VERSION
        || record.package_ref != package_ref
        || !valid_ref("pkg_", &record.package_ref)
        || !valid_ref("env_", &record.envelope_ref)
        || !valid_ref("op_", &record.operation_ref)
        || record.operation_kind != "create"
        || !matches!(record.source.as_str(), "generated" | "import")
        || record.host_ref != profile.host_ref
        || record.service_ref != profile.service_ref
        || !valid_ref("bind_", &record.binding_ref)
        || !valid_ref("sec_", &record.secret_ref)
        || !valid_ref("gen_", &record.generation_ref)
        || !valid_ref("envpol_", &record.environment_policy_ref)
        || !valid_ref("envpf_", &record.environment_policy_fingerprint)
        || !valid_ref("decl_", &record.declaration_fingerprint)
        || janus_core::ManagedEnvironmentName::new(record.environment_name.clone()).is_err()
        || record.delivery_profile_ref != profile.delivery_profile_ref
        || !valid_ref("reload_", &record.reload_profile_ref)
        || !valid_ref("health_", &record.health_profile_ref)
        || record.revocation_epoch != profile.revocation_epoch
        || record.prepared_at_unix_secs == 0
        || record.expires_at_unix_secs <= record.prepared_at_unix_secs
        || record.packet_returned
        || record.value_returned
        || record.integrity_hash != outbox_hash(&record)?
    {
        return Err("dynamic_transport_outbox_invalid");
    }
    let packet = STANDARD_NO_PAD
        .decode(record.packet_base64.as_bytes())
        .map_err(|_| "dynamic_transport_outbox_invalid")?;
    if packet.is_empty() || packet.len() > janus_host::maximum_packet_bytes() {
        return Err("dynamic_transport_outbox_invalid");
    }
    Ok(record)
}

fn load_receipt(
    receipt_dir: &Path,
    record: &OutboxRecord,
) -> std::result::Result<Option<MaterializationReceipt>, &'static str> {
    let path = receipt_path(receipt_dir, &record.package_ref);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("dynamic_transport_receipt_unavailable"),
    };
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_RECEIPT_BYTES as u64
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err("dynamic_transport_receipt_invalid");
    }
    let raw = fs::read(path).map_err(|_| "dynamic_transport_receipt_unavailable")?;
    let receipt: MaterializationReceipt =
        serde_json::from_slice(&raw).map_err(|_| "dynamic_transport_receipt_invalid")?;
    if receipt.schema != RECEIPT_SCHEMA
        || receipt.schema_version != SCHEMA_VERSION
        || receipt.host_ref != record.host_ref
        || receipt.service_ref != record.service_ref
        || receipt.environment_policy_ref != record.environment_policy_ref
        || receipt.operation_ref != record.operation_ref
        || receipt.package_ref != record.package_ref
        || receipt.envelope_ref != record.envelope_ref
        || receipt.binding_ref != record.binding_ref
        || receipt.generation_ref != record.generation_ref
        || receipt.phase != "materialized"
        || !matches!(
            receipt.reason_code.as_str(),
            "dynamic_host_environment_materialized" | "dynamic_host_materialization_idempotent"
        )
        || receipt.observed_at_unix_secs < record.prepared_at_unix_secs
        || receipt.packet_returned
        || receipt.value_returned
        || receipt.integrity_hash != receipt_hash(&receipt)?
    {
        return Err("dynamic_transport_receipt_invalid");
    }
    Ok(Some(receipt))
}

fn receipt_hash(receipt: &MaterializationReceipt) -> std::result::Result<String, &'static str> {
    let mut unsigned = receipt.clone();
    unsigned.integrity_hash.clear();
    let encoded = serde_json::to_vec(&unsigned).map_err(|_| "dynamic_transport_receipt_invalid")?;
    Ok(hex::encode(Sha256::digest(encoded)))
}

fn write_receipt_create_new(
    path: &Path,
    receipt: &MaterializationReceipt,
) -> std::result::Result<(), &'static str> {
    let parent = path
        .parent()
        .ok_or("dynamic_transport_receipt_unavailable")?;
    super::ensure_private_dir(parent).map_err(|_| "dynamic_transport_receipt_unavailable")?;
    let mut encoded =
        serde_json::to_vec_pretty(receipt).map_err(|_| "dynamic_transport_receipt_invalid")?;
    encoded.push(b'\n');
    if encoded.len() > MAX_RECEIPT_BYTES {
        return Err("dynamic_transport_receipt_invalid");
    }
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .ok_or("dynamic_transport_receipt_unavailable")?,
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
            .map_err(|_| "dynamic_transport_receipt_unavailable")?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| "dynamic_transport_receipt_unavailable")?;
        file.write_all(&encoded)
            .map_err(|_| "dynamic_transport_receipt_unavailable")?;
        file.sync_all()
            .map_err(|_| "dynamic_transport_receipt_unavailable")?;
        fs::hard_link(&temporary, path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                "dynamic_transport_receipt_present"
            } else {
                "dynamic_transport_receipt_unavailable"
            }
        })?;
        fs::remove_file(&temporary).map_err(|_| "dynamic_transport_receipt_unavailable")?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| "dynamic_transport_receipt_unavailable")
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn validate_receipt_separation(
    receipt_dir: &Path,
    profiles: &BTreeMap<ProfileKey, DeliveryProfile>,
) -> Result<()> {
    let service_bindings = profiles
        .values()
        .map(|profile| (profile.host_ref.as_str(), profile.service_ref.as_str()))
        .collect::<BTreeSet<_>>();
    if service_bindings.len() != profiles.len() {
        anyhow::bail!("dynamic transport profile bindings must be unique");
    }
    if profiles.values().any(|profile| {
        receipt_dir.starts_with(&profile.outbox_dir)
            || profile.outbox_dir.starts_with(receipt_dir)
            || receipt_dir.starts_with(&profile.producer_signing_key_file)
            || profile.producer_signing_key_file.starts_with(receipt_dir)
    }) {
        anyhow::bail!("dynamic transport receipt root must be separate");
    }
    Ok(())
}

fn receipt_path(receipt_dir: &Path, package_ref: &str) -> PathBuf {
    receipt_dir.join(format!("{package_ref}.json"))
}

fn no_work(host_ref: &str) -> TransportResponse {
    TransportResponse {
        schema: RESPONSE_SCHEMA,
        schema_version: SCHEMA_VERSION,
        action: "claim",
        host_ref: Some(host_ref.to_string()),
        service_ref: None,
        environment_policy_ref: None,
        operation_ref: None,
        package_ref: None,
        envelope_ref: None,
        binding_ref: None,
        generation_ref: None,
        packet_base64: None,
        phase: "empty",
        reason_code: "dynamic_transport_no_package",
        packet_returned: false,
        value_returned: false,
    }
}

fn denied(action: &'static str, reason_code: &'static str) -> TransportResponse {
    TransportResponse {
        schema: RESPONSE_SCHEMA,
        schema_version: SCHEMA_VERSION,
        action,
        host_ref: None,
        service_ref: None,
        environment_policy_ref: None,
        operation_ref: None,
        package_ref: None,
        envelope_ref: None,
        binding_ref: None,
        generation_ref: None,
        packet_base64: None,
        phase: "denied",
        reason_code,
        packet_returned: false,
        value_returned: false,
    }
}

fn required_absolute_path(name: &str) -> Result<PathBuf> {
    let path = PathBuf::from(std::env::var(name).with_context(|| format!("{name} is required"))?);
    if !normalized_absolute(&path) {
        anyhow::bail!("{name} must be an absolute normalized path");
    }
    Ok(path)
}

fn required_uid() -> Result<u32> {
    std::env::var(PEER_UID_ENV)
        .context("dynamic transport allowed UID required")?
        .parse::<u32>()
        .context("dynamic transport allowed UID invalid")
}

fn bind_private_socket(path: &Path) -> Result<UnixListener> {
    let parent = path
        .parent()
        .context("dynamic transport socket has no parent")?;
    super::ensure_private_dir(parent)?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.file_type().is_socket() {
            anyhow::bail!("dynamic transport socket path occupied");
        }
        fs::remove_file(path).context("stale dynamic transport socket unavailable")?;
    }
    let listener = UnixListener::bind(path).context("dynamic transport socket bind failed")?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .context("dynamic transport socket permissions failed")?;
    Ok(listener)
}

fn unix_seconds(now: SystemTime) -> std::result::Result<u64, &'static str> {
    now.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "dynamic_transport_clock_invalid")
}

async fn read_request(stream: &mut UnixStream) -> Result<TransportRequest> {
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

async fn write_response(stream: &mut UnixStream, response: TransportResponse) -> Result<()> {
    let bytes = serde_json::to_vec(&response).context("dynamic transport response invalid")?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        anyhow::bail!("dynamic transport response oversized");
    }
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    struct Fixture {
        temporary: tempfile::TempDir,
        profiles: BTreeMap<ProfileKey, DeliveryProfile>,
        receipt_dir: PathBuf,
        record: OutboxRecord,
    }

    fn private_dir(path: &Path) {
        fs::create_dir_all(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn fixture() -> Fixture {
        let temporary = tempfile::TempDir::new().unwrap();
        let outbox_dir = temporary.path().join("outbox");
        let receipt_dir = temporary.path().join("receipts");
        private_dir(&outbox_dir);
        private_dir(&receipt_dir);
        let signing_key_file = temporary.path().join("signing-key.json");
        let signing_key = SigningKey::from_bytes(&[17; 32]);
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
        let identity = age::x25519::Identity::generate();
        let profile = DeliveryProfile {
            schema: "inspr.janus.managed-dynamic-delivery-profile.v1".to_string(),
            schema_version: 1,
            host_ref: "host_7f94a1c8e912".to_string(),
            service_ref: "svc_24b7c8f0aa19".to_string(),
            delivery_profile_ref: "delivery_63dc8874e181".to_string(),
            host_recipient: identity.to_public().to_string(),
            producer_key_id: "key_dynamic0001".to_string(),
            producer_signing_key_file: signing_key_file,
            revocation_epoch: 7,
            envelope_ttl_seconds: 3600,
            outbox_dir: outbox_dir.clone(),
        };
        let packet = b"signed-host-ciphertext";
        let mut record = OutboxRecord {
            schema: OUTBOX_SCHEMA.to_string(),
            schema_version: 1,
            package_ref: "pkg_12345678abcdef00".to_string(),
            envelope_ref: "env_12345678abcdef00".to_string(),
            operation_ref: "op_12345678abcdef00".to_string(),
            operation_kind: "create".to_string(),
            source: "import".to_string(),
            host_ref: profile.host_ref.clone(),
            service_ref: profile.service_ref.clone(),
            binding_ref: "bind_12345678abcdef00".to_string(),
            secret_ref: ["sec_", "12345678abcdef00"].concat(),
            generation_ref: "gen_12345678abcdef00".to_string(),
            environment_policy_ref: "envpol_12345678abcdef00".to_string(),
            environment_policy_fingerprint: "envpf_12345678abcdef00".to_string(),
            declaration_fingerprint: "decl_12345678abcdef00".to_string(),
            environment_name: "CANARY_TOKEN".to_string(),
            delivery_profile_ref: profile.delivery_profile_ref.clone(),
            reload_profile_ref: "reload_12345678abcdef00".to_string(),
            health_profile_ref: "health_12345678abcdef00".to_string(),
            revocation_epoch: profile.revocation_epoch,
            prepared_at_unix_secs: 1_800_000_000,
            expires_at_unix_secs: 1_800_003_600,
            packet_base64: STANDARD_NO_PAD.encode(packet),
            packet_returned: false,
            value_returned: false,
            integrity_hash: String::new(),
        };
        record.integrity_hash = outbox_hash(&record).unwrap();
        let path = outbox_dir.join(format!("{}.json", record.package_ref));
        fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let profiles = BTreeMap::from([(
            (
                profile.host_ref.clone(),
                profile.service_ref.clone(),
                profile.delivery_profile_ref.clone(),
            ),
            profile,
        )]);
        Fixture {
            temporary,
            profiles,
            receipt_dir,
            record,
        }
    }

    #[test]
    fn exact_host_claim_and_idempotent_receipt_are_value_free() {
        let fixture = fixture();
        let now = UNIX_EPOCH + Duration::from_secs(1_800_000_010);
        let claimed = claim(
            &fixture.profiles,
            &fixture.receipt_dir,
            &fixture.record.host_ref,
            now,
        )
        .unwrap();
        assert_eq!(claimed.phase, "claimed");
        assert!(claimed.packet_returned);
        assert!(!claimed.value_returned);
        assert_eq!(
            claimed.packet_base64.as_deref(),
            Some(fixture.record.packet_base64.as_str())
        );
        let acknowledgement = Acknowledgement {
            host_ref: fixture.record.host_ref.clone(),
            service_ref: fixture.record.service_ref.clone(),
            environment_policy_ref: fixture.record.environment_policy_ref.clone(),
            operation_ref: fixture.record.operation_ref.clone(),
            package_ref: fixture.record.package_ref.clone(),
            envelope_ref: fixture.record.envelope_ref.clone(),
            binding_ref: fixture.record.binding_ref.clone(),
            generation_ref: fixture.record.generation_ref.clone(),
            phase: "materialized".to_string(),
            reason_code: "dynamic_host_environment_materialized".to_string(),
            observed_at_unix_secs: 1_800_000_010,
            packet_returned: false,
            value_returned: false,
        };
        let first = acknowledge(
            &fixture.profiles,
            &fixture.receipt_dir,
            &acknowledgement,
            now,
        )
        .unwrap();
        let second = acknowledge(
            &fixture.profiles,
            &fixture.receipt_dir,
            &acknowledgement,
            now,
        )
        .unwrap();
        assert_eq!(first.phase, "materialized");
        assert_eq!(second.phase, "materialized");
        assert!(!first.packet_returned && !first.value_returned);
        let empty = claim(
            &fixture.profiles,
            &fixture.receipt_dir,
            &fixture.record.host_ref,
            now,
        )
        .unwrap();
        assert_eq!(empty.phase, "empty");
        let receipt = fs::read(receipt_path(
            &fixture.receipt_dir,
            &fixture.record.package_ref,
        ))
        .unwrap();
        assert!(!receipt
            .windows(b"signed-host-ciphertext".len())
            .any(|window| window == b"signed-host-ciphertext"));
        drop(fixture.temporary);
    }

    #[test]
    fn wire_protocol_requires_a_nested_value_free_receipt() {
        let raw = serde_json::json!({
            "schema": REQUEST_SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "action": "acknowledge",
            "receipt": {
                "host_ref": "host_7f94a1c8e912",
                "service_ref": "svc_24b7c8f0aa19",
                "environment_policy_ref": "envpol_12345678abcdef00",
                "operation_ref": "op_12345678abcdef00",
                "package_ref": "pkg_12345678abcdef00",
                "envelope_ref": "env_12345678abcdef00",
                "binding_ref": "bind_12345678abcdef00",
                "generation_ref": "gen_12345678abcdef00",
                "phase": "materialized",
                "reason_code": "dynamic_host_environment_materialized",
                "observed_at_unix_secs": 1_800_000_010_u64,
                "packet_returned": false,
                "value_returned": false
            }
        });
        assert!(matches!(
            serde_json::from_value::<TransportRequest>(raw.clone()).unwrap(),
            TransportRequest::Acknowledge { .. }
        ));
        let mut leaking = raw;
        leaking["receipt"]["secret_value"] = serde_json::json!("SENSITIVE_CANARY");
        assert!(serde_json::from_value::<TransportRequest>(leaking).is_err());
    }

    #[test]
    fn wrong_host_tamper_and_conflicting_receipt_fail_closed() {
        let fixture = fixture();
        let now = UNIX_EPOCH + Duration::from_secs(1_800_000_010);
        assert_eq!(
            claim(
                &fixture.profiles,
                &fixture.receipt_dir,
                "host_aaaaaaaaaaaaaaaa",
                now,
            )
            .unwrap_err(),
            "dynamic_transport_host_denied"
        );
        let acknowledgement = Acknowledgement {
            host_ref: fixture.record.host_ref.clone(),
            service_ref: fixture.record.service_ref.clone(),
            environment_policy_ref: fixture.record.environment_policy_ref.clone(),
            operation_ref: fixture.record.operation_ref.clone(),
            package_ref: fixture.record.package_ref.clone(),
            envelope_ref: fixture.record.envelope_ref.clone(),
            binding_ref: fixture.record.binding_ref.clone(),
            generation_ref: fixture.record.generation_ref.clone(),
            phase: "materialized".to_string(),
            reason_code: "dynamic_host_environment_materialized".to_string(),
            observed_at_unix_secs: 1_800_000_010,
            packet_returned: false,
            value_returned: false,
        };
        acknowledge(
            &fixture.profiles,
            &fixture.receipt_dir,
            &acknowledgement,
            now,
        )
        .unwrap();
        let mut conflicting = acknowledgement;
        conflicting.reason_code = "dynamic_host_materialization_idempotent".to_string();
        assert_eq!(
            acknowledge(&fixture.profiles, &fixture.receipt_dir, &conflicting, now,).unwrap_err(),
            "dynamic_transport_receipt_conflict"
        );
        let path = fixture
            .profiles
            .values()
            .next()
            .unwrap()
            .outbox_dir
            .join(format!("{}.json", fixture.record.package_ref));
        let mut tampered = fixture.record.clone();
        tampered.service_ref = "svc_aaaaaaaaaaaaaaaa".to_string();
        fs::write(&path, serde_json::to_vec(&tampered).unwrap()).unwrap();
        assert_eq!(
            claim(
                &fixture.profiles,
                &fixture.receipt_dir,
                &fixture.record.host_ref,
                now,
            )
            .unwrap_err(),
            "dynamic_transport_outbox_invalid"
        );
    }

    #[test]
    fn ambiguous_service_profiles_and_key_overlap_fail_startup() {
        let fixture = fixture();
        let mut profiles = fixture.profiles.clone();
        let mut duplicate = profiles.values().next().unwrap().clone();
        duplicate.delivery_profile_ref = "delivery_aaaaaaaaaaaaaaaa".to_string();
        duplicate.outbox_dir = fixture.temporary.path().join("second-outbox");
        private_dir(&duplicate.outbox_dir);
        profiles.insert(
            (
                duplicate.host_ref.clone(),
                duplicate.service_ref.clone(),
                duplicate.delivery_profile_ref.clone(),
            ),
            duplicate,
        );
        assert!(validate_receipt_separation(&fixture.receipt_dir, &profiles).is_err());

        let key_parent = fixture.temporary.path().join("key-root");
        private_dir(&key_parent);
        let mut key_profile = fixture.profiles.values().next().unwrap().clone();
        key_profile.producer_signing_key_file = key_parent.join("producer-key.json");
        let key_profiles = BTreeMap::from([(
            (
                key_profile.host_ref.clone(),
                key_profile.service_ref.clone(),
                key_profile.delivery_profile_ref.clone(),
            ),
            key_profile,
        )]);
        assert!(validate_receipt_separation(&key_parent, &key_profiles).is_err());
    }
}
