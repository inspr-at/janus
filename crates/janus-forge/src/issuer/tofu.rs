//! Read-only connector for one exact OpenTofu local-state output.

use janus_core::{JanusError, JanusResult, SecretValue};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use wait_timeout::ChildExt;
use zeroize::Zeroizing;

const MAX_TOFU_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_STATE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PATH_BYTES: usize = 4096;
const MIN_TIMEOUT_SECONDS: u64 = 1;
const MAX_TIMEOUT_SECONDS: u64 = 60;

/// Exact public configuration for one reviewed local-state output.
#[derive(Clone, PartialEq, Eq)]
pub struct TofuOutputConfig {
    executable: PathBuf,
    executable_sha256: String,
    workdir: PathBuf,
    state_file: PathBuf,
    output: String,
    executable_owner_uid: u32,
    state_owner_uid: u32,
    timeout: Duration,
}

impl TofuOutputConfig {
    /// Validate a catalog entry without opening state or running OpenTofu.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        executable: impl Into<PathBuf>,
        executable_sha256: &str,
        workdir: impl Into<PathBuf>,
        state_file: impl Into<PathBuf>,
        output: &str,
        executable_owner_uid: u32,
        state_owner_uid: u32,
        timeout_seconds: u64,
    ) -> JanusResult<Self> {
        let executable = executable.into();
        let workdir = workdir.into();
        let state_file = state_file.into();
        if !normalized_absolute(&executable)
            || !normalized_absolute(&workdir)
            || !normalized_absolute(&state_file)
            || path_bytes(&executable) > MAX_PATH_BYTES
            || path_bytes(&workdir) > MAX_PATH_BYTES
            || path_bytes(&state_file) > MAX_PATH_BYTES
            || state_file.parent() != Some(workdir.as_path())
            || !valid_digest(executable_sha256)
            || !valid_output_name(output)
            || !(MIN_TIMEOUT_SECONDS..=MAX_TIMEOUT_SECONDS).contains(&timeout_seconds)
        {
            return Err(invalid_config());
        }
        Ok(Self {
            executable,
            executable_sha256: executable_sha256.to_string(),
            workdir,
            state_file,
            output: output.to_string(),
            executable_owner_uid,
            state_owner_uid,
            timeout: Duration::from_secs(timeout_seconds),
        })
    }
}

fn path_bytes(path: &Path) -> usize {
    path.as_os_str().as_encoded_bytes().len()
}

fn normalized_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_output_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().enumerate().all(|(index, byte)| {
            if index == 0 {
                byte == b'_' || byte.is_ascii_alphabetic()
            } else {
                byte == b'_' || byte == b'-' || byte.is_ascii_alphanumeric()
            }
        })
}

fn invalid_config() -> JanusError {
    JanusError::InvalidManifest {
        detail: "OpenTofu issuer connector configuration is invalid".to_string(),
    }
}

fn unavailable() -> JanusError {
    JanusError::StoreUnavailable {
        detail: "OpenTofu issuer operation failed".to_string(),
    }
}

/// Direct, shell-free OpenTofu output resolver.
#[derive(Clone, Copy, Default)]
pub struct TofuOutputConnector;

impl TofuOutputConnector {
    /// Read only the configured output from the configured local state file.
    pub fn resolve(&self, config: &TofuOutputConfig) -> JanusResult<SecretValue> {
        let before = validate_material(config)?;
        let mut child = Command::new(&config.executable)
            .arg(format!("-chdir={}", config.workdir.display()))
            .arg("output")
            .arg(format!("-state={}", config.state_file.display()))
            .arg("-json")
            .arg(&config.output)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| unavailable())?;
        let stdout = child.stdout.take().ok_or_else(unavailable)?;
        let stderr = child.stderr.take().ok_or_else(unavailable)?;
        let stdout_reader = thread::spawn(move || read_bounded(stdout, MAX_TOFU_OUTPUT_BYTES));
        let stderr_reader = thread::spawn(move || drain(stderr));
        let wait_result = child.wait_timeout(config.timeout);
        let status = match wait_result {
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(unavailable());
            }
            Ok(Some(status)) => status,
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(unavailable());
            }
        };
        let (stdout, oversized) = stdout_reader.join().map_err(|_| unavailable())??;
        stderr_reader.join().map_err(|_| unavailable())??;
        if !status.success() || oversized || validate_material(config)? != before {
            return Err(unavailable());
        }
        let secret: String = serde_json::from_slice(&stdout).map_err(|_| unavailable())?;
        let secret = Zeroizing::new(secret);
        if secret.is_empty()
            || secret.len() > super::MAX_ISSUER_VALUE_BYTES
            || secret.bytes().any(|byte| matches!(byte, 0 | b'\n' | b'\r'))
        {
            return Err(unavailable());
        }
        Ok(SecretValue::new(secret.as_bytes().to_vec()))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MaterialStamp {
    executable_device: u64,
    executable_inode: u64,
    executable_size: u64,
    executable_modified_seconds: i64,
    executable_modified_nanoseconds: i64,
    workdir_device: u64,
    workdir_inode: u64,
    state_device: u64,
    state_inode: u64,
    state_size: u64,
    state_modified_seconds: i64,
    state_modified_nanoseconds: i64,
}

fn validate_material(config: &TofuOutputConfig) -> JanusResult<MaterialStamp> {
    let executable = std::fs::symlink_metadata(&config.executable).map_err(|_| unavailable())?;
    if !executable.file_type().is_file()
        || executable.uid() != config.executable_owner_uid
        || executable.size() == 0
        || executable.size() > MAX_EXECUTABLE_BYTES
        || executable.permissions().mode() & 0o022 != 0
        || executable.permissions().mode() & 0o111 == 0
        || digest_file(&config.executable)? != config.executable_sha256
    {
        return Err(unavailable());
    }
    let workdir = std::fs::symlink_metadata(&config.workdir).map_err(|_| unavailable())?;
    if !workdir.file_type().is_dir()
        || workdir.uid() != config.state_owner_uid
        || workdir.permissions().mode() & 0o022 != 0
    {
        return Err(unavailable());
    }
    let state = std::fs::symlink_metadata(&config.state_file).map_err(|_| unavailable())?;
    if !state.file_type().is_file()
        || state.uid() != config.state_owner_uid
        || state.size() == 0
        || state.size() > MAX_STATE_BYTES
        || state.nlink() != 1
        || state.permissions().mode() & 0o077 != 0
    {
        return Err(unavailable());
    }
    Ok(MaterialStamp {
        executable_device: executable.dev(),
        executable_inode: executable.ino(),
        executable_size: executable.size(),
        executable_modified_seconds: executable.mtime(),
        executable_modified_nanoseconds: executable.mtime_nsec(),
        workdir_device: workdir.dev(),
        workdir_inode: workdir.ino(),
        state_device: state.dev(),
        state_inode: state.ino(),
        state_size: state.size(),
        state_modified_seconds: state.mtime(),
        state_modified_nanoseconds: state.mtime_nsec(),
    })
}

fn digest_file(path: &Path) -> JanusResult<String> {
    let mut file = File::open(path).map_err(|_| unavailable())?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|_| unavailable())?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    Ok(format!("sha256:{}", hex::encode(hash.finalize())))
}

fn read_bounded(mut reader: impl Read, limit: usize) -> JanusResult<(Zeroizing<Vec<u8>>, bool)> {
    let mut stored = Zeroizing::new(Vec::new());
    let mut total = 0_usize;
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let read = reader.read(&mut buffer).map_err(|_| unavailable())?;
        if read == 0 {
            return Ok((stored, total > limit));
        }
        total = total.saturating_add(read);
        if stored.len() <= limit {
            let remaining = (limit + 1).saturating_sub(stored.len());
            stored.extend_from_slice(&buffer[..read.min(remaining)]);
        }
    }
}

fn drain(mut reader: impl Read) -> JanusResult<()> {
    let mut buffer = [0_u8; 8 * 1024];
    while reader.read(&mut buffer).map_err(|_| unavailable())? != 0 {}
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    struct Fixture {
        _temporary: TempDir,
        config: TofuOutputConfig,
        arguments: PathBuf,
    }

    fn fixture(script_body: &str) -> Fixture {
        let temporary = tempfile::tempdir().unwrap();
        let workdir = temporary.path().join("state");
        fs::create_dir(&workdir).unwrap();
        fs::set_permissions(&workdir, fs::Permissions::from_mode(0o700)).unwrap();
        let state_file = workdir.join("terraform.tfstate");
        fs::write(&state_file, b"synthetic-state-not-read-by-test-program").unwrap();
        fs::set_permissions(&state_file, fs::Permissions::from_mode(0o600)).unwrap();
        let arguments = temporary.path().join("arguments");
        let executable = temporary.path().join("tofu-fixture");
        let script = format!(
            "#!/bin/sh\nif [ -n \"${{HOME+x}}\" ]; then exit 23; fi\nprintf '%s\\n' \"$@\" > '{}'\n{}\n",
            arguments.display(),
            script_body
        );
        fs::write(&executable, script).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let executable_metadata = fs::metadata(&executable).unwrap();
        let state_metadata = fs::metadata(&state_file).unwrap();
        let config = TofuOutputConfig::new(
            &executable,
            &digest_file(&executable).unwrap(),
            &workdir,
            &state_file,
            "application_client_secret",
            executable_metadata.uid(),
            state_metadata.uid(),
            5,
        )
        .unwrap();
        Fixture {
            _temporary: temporary,
            config,
            arguments,
        }
    }

    #[test]
    fn reads_only_the_configured_local_state_output_with_an_empty_environment() {
        let fixture = fixture("printf '\"synthetic-tofu-value\"\\n'");
        let value = TofuOutputConnector.resolve(&fixture.config).unwrap();
        assert_eq!(value.expose_bytes(), b"synthetic-tofu-value");
        let arguments = fs::read_to_string(&fixture.arguments).unwrap();
        assert_eq!(
            arguments.lines().collect::<Vec<_>>(),
            vec![
                format!("-chdir={}", fixture.config.workdir.display()),
                "output".to_string(),
                format!("-state={}", fixture.config.state_file.display()),
                "-json".to_string(),
                "application_client_secret".to_string(),
            ]
        );
    }

    #[test]
    fn rejects_material_drift_and_never_replays_subprocess_stderr() {
        let fixture = fixture("printf 'synthetic-sensitive-stderr' >&2; exit 7");
        let error = match TofuOutputConnector.resolve(&fixture.config) {
            Ok(_) => panic!("nonzero OpenTofu exit must fail"),
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            "store unavailable: OpenTofu issuer operation failed"
        );
        assert!(!error.to_string().contains("synthetic-sensitive"));

        fs::write(&fixture.config.executable, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(
            &fixture.config.executable,
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        assert!(TofuOutputConnector.resolve(&fixture.config).is_err());
    }

    #[test]
    fn rejects_caller_paths_and_noncanonical_digests() {
        assert!(TofuOutputConfig::new(
            "/nix/store/example/bin/tofu",
            "sha256:NOT-CANONICAL",
            "/private/tofu",
            "/private/tofu/terraform.tfstate",
            "application_client_secret",
            0,
            1000,
            5,
        )
        .is_err());
        assert!(TofuOutputConfig::new(
            "/nix/store/example/bin/tofu",
            &format!("sha256:{}", "0".repeat(64)),
            "/private/tofu",
            "/private/other/terraform.tfstate",
            "application_client_secret",
            0,
            1000,
            5,
        )
        .is_err());
    }
}
