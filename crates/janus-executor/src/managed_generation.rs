use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use janus_core::{JanusError, JanusResult, SafeLabel};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(crate) const ENTRY_SCHEMA: &str = "inspr.janus.managed-service-environment-entry.v1";
pub(crate) const GENERATION_SCHEMA: &str = "inspr.janus.managed-service-environment-generation.v1";
const CURRENT_FILE: &str = "current";
const MAX_CURRENT_BYTES: u64 = 65;
const MAX_GENERATION_BYTES: u64 = 1024 * 1024;
const MAX_GENERATION_HOSTS: usize = 1024;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentEntryFile {
    schema: String,
    host: EnvironmentHost,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentHost {
    name: String,
    revision: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentGeneration {
    schema: String,
    generation: String,
    hosts: Vec<EnvironmentHost>,
}

/// Write one value-independent entry. This API deliberately receives no
/// credential bytes, so neither the entry revision nor the public generation
/// can become a reusable verifier or offline oracle for the projected value.
pub(crate) fn write_entry(mut writer: impl Write, subject: &SafeLabel) -> JanusResult<String> {
    if !valid_subject(subject.as_str()) {
        return Err(JanusError::InvalidManifest {
            detail: "managed-service generation subject must be a canonical host or host reference"
                .to_string(),
        });
    }
    let revision = opaque_revision()?;
    serde_json::to_writer(
        &mut writer,
        &EnvironmentEntryFile {
            schema: ENTRY_SCHEMA.to_string(),
            host: EnvironmentHost {
                name: subject.as_str().to_string(),
                revision: revision.clone(),
            },
        },
    )
    .and_then(|_| writer.write_all(b"\n").map_err(serde_json::Error::io))
    .map_err(|_| generation_unavailable("failed to write managed-service generation entry"))?;
    Ok(revision)
}

pub(crate) fn publish_entry(
    root: &Path,
    subject: &SafeLabel,
    revision: &str,
) -> JanusResult<String> {
    if !valid_subject(subject.as_str()) || !is_sha256_hex(revision) {
        return Err(JanusError::InvalidManifest {
            detail: "managed-service generation entry is invalid".to_string(),
        });
    }
    with_generation_lock(root, |mut hosts| {
        hosts.insert(subject.as_str().to_string(), revision.to_string());
        publish_generation(root, hosts)
    })
}

/// Validate the private generation root and its current immutable generation
/// without creating files. Projection preflight and issue call this before a
/// permit or credential is consumed, so corrupt public evidence cannot leave
/// a newly rendered credential without a matching generation.
pub(crate) fn preflight_root(root: &Path) -> JanusResult<()> {
    validate_private_root(root)?;
    load_current_generation(root).map(|_| ())
}

fn opaque_revision() -> JanusResult<String> {
    let mut random = [0_u8; 32];
    getrandom::getrandom(&mut random)
        .map_err(|_| generation_unavailable("managed-service revision entropy is unavailable"))?;
    Ok(hex(&random))
}

fn with_generation_lock<T>(
    root: &Path,
    operation: impl FnOnce(BTreeMap<String, String>) -> JanusResult<T>,
) -> JanusResult<T> {
    validate_private_root(root)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = options
        .open(root.join(".generation.lock"))
        .map_err(|_| generation_unavailable("failed to open generation lock"))?;
    lock.lock_exclusive()
        .map_err(|_| generation_unavailable("failed to acquire generation lock"))?;
    let hosts = load_current_generation(root)?;
    let outcome = operation(hosts);
    let _ = FileExt::unlock(&lock);
    outcome
}

fn load_current_generation(root: &Path) -> JanusResult<BTreeMap<String, String>> {
    let current = match read_bounded(&root.join(CURRENT_FILE), MAX_CURRENT_BYTES) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(_) => return Err(generation_unavailable("failed to read current generation")),
    };
    let current = std::str::from_utf8(&current)
        .map_err(|_| generation_unavailable("current generation is invalid"))?
        .trim_end_matches('\n');
    if !is_sha256_hex(current) {
        return Err(generation_unavailable("current generation is invalid"));
    }
    let payload = read_bounded(
        &root.join(format!("generation-{current}.json")),
        MAX_GENERATION_BYTES,
    )
    .map_err(|_| generation_unavailable("failed to read current generation payload"))?;
    parse_generation(&payload, current)
}

fn parse_generation(bytes: &[u8], expected: &str) -> JanusResult<BTreeMap<String, String>> {
    let payload: EnvironmentGeneration = serde_json::from_slice(bytes)
        .map_err(|_| generation_unavailable("current generation payload is invalid"))?;
    if payload.schema != GENERATION_SCHEMA || payload.generation != expected {
        return Err(generation_unavailable(
            "current generation contract is unsupported",
        ));
    }
    if payload.hosts.len() > MAX_GENERATION_HOSTS {
        return Err(generation_unavailable("current generation is too large"));
    }
    let mut hosts = BTreeMap::new();
    for host in payload.hosts {
        if !valid_subject(&host.name) || !is_sha256_hex(&host.revision) {
            return Err(generation_unavailable(
                "current generation entry is invalid",
            ));
        }
        if hosts.insert(host.name, host.revision).is_some() {
            return Err(generation_unavailable(
                "current generation contains duplicate hosts",
            ));
        }
    }
    if generation_id(&hosts) != expected {
        return Err(generation_unavailable(
            "current generation integrity check failed",
        ));
    }
    Ok(hosts)
}

fn publish_generation(root: &Path, hosts: BTreeMap<String, String>) -> JanusResult<String> {
    if hosts.len() > MAX_GENERATION_HOSTS {
        return Err(generation_unavailable("generation host bound exceeded"));
    }
    let generation = generation_id(&hosts);
    let payload = EnvironmentGeneration {
        schema: GENERATION_SCHEMA.to_string(),
        generation: generation.clone(),
        hosts: hosts
            .into_iter()
            .map(|(name, revision)| EnvironmentHost { name, revision })
            .collect(),
    };
    let bytes = serde_json::to_vec(&payload)
        .map_err(|_| generation_unavailable("failed to encode generation"))?;
    if bytes.len() as u64 > MAX_GENERATION_BYTES {
        return Err(generation_unavailable("generation size bound exceeded"));
    }
    let path = root.join(format!("generation-{generation}.json"));
    match OpenOptions::new().read(true).open(&path) {
        Ok(_) => {
            let existing = read_bounded(&path, MAX_GENERATION_BYTES)
                .map_err(|_| generation_unavailable("existing generation is unreadable"))?;
            if existing != bytes {
                return Err(generation_unavailable(
                    "immutable generation content mismatch",
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            write_immutable_synced(&path, &bytes)?;
        }
        Err(_) => return Err(generation_unavailable("generation path is unavailable")),
    }
    replace_synced(
        root.join(CURRENT_FILE),
        format!("{generation}\n").as_bytes(),
    )?;
    sync_directory(root)?;
    Ok(generation)
}

fn write_immutable_synced(path: &Path, bytes: &[u8]) -> JanusResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| generation_unavailable("generation parent is invalid"))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| generation_unavailable("generation name is invalid"))?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp = parent.join(format!(".{name}.{}.{}.tmp", std::process::id(), nonce));
    let result = (|| {
        write_new_synced(&temp, bytes)?;
        match fs::hard_link(&temp, path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = read_bounded(path, MAX_GENERATION_BYTES)
                    .map_err(|_| generation_unavailable("existing generation is unreadable"))?;
                if existing != bytes {
                    return Err(generation_unavailable(
                        "immutable generation content mismatch",
                    ));
                }
            }
            Err(_) => {
                return Err(generation_unavailable(
                    "failed to publish immutable generation",
                ));
            }
        }
        Ok(())
    })();
    let cleanup = fs::remove_file(temp);
    result?;
    cleanup.map_err(|_| generation_unavailable("failed to remove generation temporary file"))?;
    sync_directory(parent)
}

fn write_new_synced(path: &Path, bytes: &[u8]) -> JanusResult<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_| generation_unavailable("failed to create immutable generation"))?;
    file.write_all(bytes)
        .and_then(|_| file.flush())
        .and_then(|_| file.sync_all())
        .map_err(|_| generation_unavailable("failed to sync immutable generation"))
}

fn replace_synced(path: PathBuf, bytes: &[u8]) -> JanusResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| generation_unavailable("generation pointer parent is invalid"))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| generation_unavailable("generation pointer name is invalid"))?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp = parent.join(format!(".{name}.{}.{}.tmp", std::process::id(), nonce));
    let result = (|| {
        write_new_synced(&temp, bytes)?;
        fs::rename(&temp, &path)
            .map_err(|_| generation_unavailable("failed to publish generation pointer"))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

fn read_bounded(path: &Path, max_bytes: u64) -> std::io::Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unsafe or oversized generation file",
        ));
    }
    let mut file = OpenOptions::new().read(true).open(path)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::take(&mut file, max_bytes + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "oversized generation file",
        ));
    }
    Ok(bytes)
}

fn validate_private_root(root: &Path) -> JanusResult<()> {
    let metadata = fs::symlink_metadata(root)
        .map_err(|_| generation_unavailable("generation root is unavailable"))?;
    if !root.is_absolute() || metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(generation_unavailable("generation root is unsafe"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(generation_unavailable("generation root must be private"));
        }
    }
    Ok(())
}

fn sync_directory(path: &Path) -> JanusResult<()> {
    OpenOptions::new()
        .read(true)
        .open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| generation_unavailable("failed to sync generation directory"))
}

fn generation_id(hosts: &BTreeMap<String, String>) -> String {
    let mut digest = Sha256::new();
    digest.update(b"inspr.janus.managed-service-environment-generation.v1\0");
    for (host, revision) in hosts {
        digest.update((host.len() as u64).to_be_bytes());
        digest.update(host.as_bytes());
        digest.update(revision.as_bytes());
    }
    hex(&digest.finalize())
}

pub(crate) fn valid_subject(value: &str) -> bool {
    crate::pharos_generation::valid_token_subject(value)
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex(bytes: &[u8]) -> String {
    const CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(CHARS[(byte >> 4) as usize] as char);
        output.push(CHARS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn generation_unavailable(detail: &str) -> JanusError {
    JanusError::StoreUnavailable {
        detail: detail.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn private_root(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "janus-managed-generation-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        fs::create_dir(&path).expect("create generation root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure generation root");
        }
        path
    }

    #[test]
    fn entry_and_generation_are_value_independent_and_immutable() {
        let root = private_root("publish");
        let host = SafeLabel::new("host_58f36c72a91e").expect("host ref");
        let mut entry = Vec::new();
        let revision = write_entry(&mut entry, &host).expect("write value-free entry");
        let generation = publish_entry(&root, &host, &revision).expect("publish generation");
        let rendered = String::from_utf8(entry).expect("entry utf8");
        assert!(rendered.contains(ENTRY_SCHEMA));
        assert!(rendered.contains(host.as_str()));
        assert!(rendered.contains(&revision));
        assert!(!rendered.contains("fixture-secret"));
        let payload = fs::read_to_string(root.join(format!("generation-{generation}.json")))
            .expect("immutable generation");
        assert!(payload.contains(GENERATION_SCHEMA));
        assert!(payload.contains(&revision));
        assert!(!payload.contains("fixture-secret"));
        assert_eq!(
            fs::read_to_string(root.join(CURRENT_FILE))
                .expect("current pointer")
                .trim(),
            generation
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn revisions_are_opaque_unique_and_not_subject_digests() {
        let host = SafeLabel::new("ares").expect("host");
        let first = opaque_revision().expect("first revision");
        let second = opaque_revision().expect("second revision");
        assert_ne!(first, second);
        assert_ne!(first, hex(&Sha256::digest(host.as_str().as_bytes())));
        assert!(is_sha256_hex(&first));
    }

    #[test]
    fn current_generation_is_strict_and_preserves_multiple_hosts() {
        let root = private_root("strict");
        let ares = SafeLabel::new("ares").expect("host");
        let athena = SafeLabel::new("athena").expect("host");
        let ares_revision = opaque_revision().expect("ares revision");
        let athena_revision = opaque_revision().expect("athena revision");

        publish_entry(&root, &ares, &ares_revision).expect("publish first host");
        let generation =
            publish_entry(&root, &athena, &athena_revision).expect("publish second host");
        let hosts = load_current_generation(&root).expect("load complete generation");
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts.get("ares"), Some(&ares_revision));
        assert_eq!(hosts.get("athena"), Some(&athena_revision));

        let path = root.join(format!("generation-{generation}.json"));
        let mut payload: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("read generation"))
                .expect("parse generation");
        payload["hosts"][0]["revision"] = serde_json::Value::String("0".repeat(64));
        fs::write(&path, serde_json::to_vec(&payload).expect("encode tamper"))
            .expect("tamper generation");
        assert!(preflight_root(&root).is_err());
        assert!(publish_entry(
            &root,
            &ares,
            &opaque_revision().expect("replacement revision")
        )
        .is_err());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn concurrent_publishers_do_not_lose_hosts_or_leave_temporaries() {
        let root = private_root("concurrent");
        let mut threads = Vec::new();
        for index in 0..16 {
            let root = root.clone();
            threads.push(std::thread::spawn(move || {
                let host = SafeLabel::new(format!("host-{index}")).expect("host");
                let revision = opaque_revision().expect("revision");
                publish_entry(&root, &host, &revision).expect("publish concurrent host");
            }));
        }
        for thread in threads {
            thread.join().expect("publisher thread completes");
        }

        let hosts = load_current_generation(&root).expect("load concurrent generation");
        assert_eq!(hosts.len(), 16);
        assert!((0..16).all(|index| hosts.contains_key(&format!("host-{index}"))));
        assert_eq!(
            fs::read_dir(&root)
                .expect("read generation root")
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
                .count(),
            0
        );

        let _ = fs::remove_dir_all(root);
    }
}
