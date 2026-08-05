use std::fs;
use std::io::Cursor;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use age::secrecy::ExposeSecret;
use tempfile::TempDir;

use super::*;

const NOW: u64 = 1_800_000_000;
const SCOPE_REF: &str = "scp_0123456789abcdef0123456789abcdef01234567";
const HOST_REF: &str = "host_58f36c72a91e";
const SERVICE_REF: &str = "svc_0bca8d31f7e2";
const SLOT_REF: &str = "slot_49c0e8a17d63";
const SECRET_REF: &str = "sec_7a6fd9e3b521";
const DECLARATION_REF: &str = "decl_a84f209c4b32";
const KEY_REF: &str = "key_7f4a29c10e8d";
const ENVIRONMENT_POLICY_REF: &str = "envpol_41e6720bc591";
const ENVIRONMENT_POLICY_FINGERPRINT: &str = "envpf_3f8d9a061c42";
const DELIVERY_PROFILE_REF: &str = "delivery_2ed71ad75c98";
const RELOAD_PROFILE_REF: &str = "reload_5e776ec5d9a1";
const HEALTH_PROFILE_REF: &str = "health_84c12f390b2a";

struct Fixture {
    _temporary: TempDir,
    executor: HostExecutor,
    recipient: String,
    signing_key: SigningKey,
    cache_root: PathBuf,
    runtime_root: PathBuf,
    identity_path: PathBuf,
    owner_uid: u32,
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let cache_root = temporary.path().join("cache");
        let runtime_root = temporary.path().join("runtime");
        private_dir(&cache_root);
        private_dir(&runtime_root);
        let owner_uid = fs::metadata(&cache_root).expect("cache metadata").uid();
        let identity = age::x25519::Identity::generate();
        let recipient = identity.to_public().to_string();
        let identity_path = temporary.path().join("identity.txt");
        fs::write(
            &identity_path,
            identity.to_string().expose_secret().as_bytes(),
        )
        .expect("write identity");
        fs::set_permissions(&identity_path, fs::Permissions::from_mode(0o600))
            .expect("identity permissions");
        let signing_key = SigningKey::from_bytes(&[17; 32]);
        let config = config(&signing_key, owner_uid);
        let executor = HostExecutor::new(
            config,
            ExecutorPaths {
                identity: identity_path.clone(),
                cache_root: cache_root.clone(),
                runtime_root: runtime_root.clone(),
                executor_uid: owner_uid,
            },
        )
        .expect("executor");
        Self {
            _temporary: temporary,
            executor,
            recipient,
            signing_key,
            cache_root,
            runtime_root,
            identity_path,
            owner_uid,
        }
    }

    fn packet(&self, generation: u64, value: &[u8]) -> Vec<u8> {
        packet(
            generation,
            generation,
            value,
            &self.recipient,
            &self.signing_key,
            HOST_REF,
            format!("env_{generation:08x}"),
            format!("op_{generation:08x}"),
        )
    }

    fn runtime_target(&self) -> PathBuf {
        self.runtime_root
            .join(SERVICE_REF)
            .join(format!("{SLOT_REF}.env"))
    }

    fn slot_cache(&self) -> PathBuf {
        self.cache_root.join(SLOT_REF)
    }

    fn dynamic_executor(&self, maximum_bindings: u16) -> HostExecutor {
        HostExecutor::new_v2(
            dynamic_config(&self.signing_key, self.owner_uid, maximum_bindings),
            ExecutorPaths {
                identity: self.identity_path.clone(),
                cache_root: self.cache_root.clone(),
                runtime_root: self.runtime_root.clone(),
                executor_uid: self.owner_uid,
            },
        )
        .expect("dynamic executor")
    }

    #[allow(clippy::too_many_arguments)]
    fn dynamic_packet(
        &self,
        binding_suffix: &str,
        operation_suffix: &str,
        generation_suffix: &str,
        environment_name: &str,
        value: &[u8],
        operation_kind: &str,
        service_ref: &str,
    ) -> Vec<u8> {
        seal_dynamic_host_envelope(DynamicHostEnvelopeSealRequest {
            binding: DynamicHostEnvelopeBindingV1 {
                schema: DYNAMIC_PAYLOAD_SCHEMA.to_string(),
                schema_version: SCHEMA_VERSION,
                envelope_ref: format!("env_{binding_suffix}"),
                operation_ref: format!("op_{operation_suffix}"),
                operation_kind: operation_kind.to_string(),
                source: "import".to_string(),
                host_ref: HOST_REF.to_string(),
                service_ref: service_ref.to_string(),
                binding_ref: format!("bind_{binding_suffix}"),
                secret_ref: format!("sec_{binding_suffix}"),
                generation_ref: format!("gen_{generation_suffix}"),
                environment_policy_ref: ENVIRONMENT_POLICY_REF.to_string(),
                environment_policy_fingerprint: ENVIRONMENT_POLICY_FINGERPRINT.to_string(),
                declaration_fingerprint: DECLARATION_REF.to_string(),
                environment_name: environment_name.to_string(),
                delivery_profile_ref: DELIVERY_PROFILE_REF.to_string(),
                reload_profile_ref: RELOAD_PROFILE_REF.to_string(),
                health_profile_ref: HEALTH_PROFILE_REF.to_string(),
                revocation_epoch: 1,
                issued_at_unix_secs: NOW - 10,
                expires_at_unix_secs: NOW + 3600,
            },
            host_recipient: &self.recipient,
            signing_key_id: KEY_REF,
            signing_key: &self.signing_key,
            value: SecretValue::new(value.to_vec()),
        })
        .expect("seal dynamic packet")
    }

    fn dynamic_removal_packet(
        &self,
        target_suffix: &str,
        removal_suffix: &str,
        environment_name: &str,
    ) -> Vec<u8> {
        seal_dynamic_host_removal(DynamicHostRemovalSealRequest {
            binding: DynamicHostEnvelopeBindingV1 {
                schema: DYNAMIC_PAYLOAD_SCHEMA.to_string(),
                schema_version: SCHEMA_VERSION,
                envelope_ref: format!("env_{removal_suffix}"),
                operation_ref: format!("op_{removal_suffix}"),
                operation_kind: "remove".to_string(),
                source: "remove".to_string(),
                host_ref: HOST_REF.to_string(),
                service_ref: SERVICE_REF.to_string(),
                binding_ref: format!("bind_{target_suffix}"),
                secret_ref: format!("sec_{target_suffix}"),
                generation_ref: format!("gen_{target_suffix}"),
                environment_policy_ref: ENVIRONMENT_POLICY_REF.to_string(),
                environment_policy_fingerprint: ENVIRONMENT_POLICY_FINGERPRINT.to_string(),
                declaration_fingerprint: DECLARATION_REF.to_string(),
                environment_name: environment_name.to_string(),
                delivery_profile_ref: DELIVERY_PROFILE_REF.to_string(),
                reload_profile_ref: RELOAD_PROFILE_REF.to_string(),
                health_profile_ref: HEALTH_PROFILE_REF.to_string(),
                revocation_epoch: 1,
                issued_at_unix_secs: NOW - 10,
                expires_at_unix_secs: NOW + 3600,
            },
            host_recipient: &self.recipient,
            signing_key_id: KEY_REF,
            signing_key: &self.signing_key,
        })
        .expect("seal dynamic removal packet")
    }

    fn dynamic_runtime_target(&self) -> PathBuf {
        self.runtime_root.join(SERVICE_REF).join("dynamic.env")
    }

    fn dynamic_cache(&self) -> PathBuf {
        self.cache_root.join(".dynamic").join(SERVICE_REF)
    }
}

fn config(signing_key: &SigningKey, owner_uid: u32) -> HostExecutorConfigV1 {
    HostExecutorConfigV1 {
        schema: CONFIG_SCHEMA.to_string(),
        schema_version: SCHEMA_VERSION,
        host_ref: HOST_REF.to_string(),
        scope_ref: SCOPE_REF.to_string(),
        owner_uid,
        minimum_revocation_epoch: 1,
        retired: false,
        producer_keys: vec![HostProducerKeyV1 {
            key_id: KEY_REF.to_string(),
            public_key: STANDARD_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
        }],
        revoked_envelope_refs: Vec::new(),
        slots: vec![HostSecretSlotV1 {
            service_ref: SERVICE_REF.to_string(),
            slot_ref: SLOT_REF.to_string(),
            secret_ref: SECRET_REF.to_string(),
            declaration_fingerprint: DECLARATION_REF.to_string(),
            minimum_generation: 1,
            rollback_window_seconds: 300,
        }],
    }
}

fn dynamic_config(
    signing_key: &SigningKey,
    owner_uid: u32,
    maximum_bindings: u16,
) -> HostExecutorConfigV2 {
    let base = config(signing_key, owner_uid);
    HostExecutorConfigV2 {
        schema: CONFIG_V2_SCHEMA.to_string(),
        schema_version: 2,
        host_ref: base.host_ref,
        scope_ref: base.scope_ref,
        owner_uid: base.owner_uid,
        minimum_revocation_epoch: base.minimum_revocation_epoch,
        retired: base.retired,
        producer_keys: base.producer_keys,
        revoked_envelope_refs: base.revoked_envelope_refs,
        slots: base.slots,
        dynamic_environment_policies: vec![HostDynamicEnvironmentPolicyV1 {
            schema: "inspr.janus.host-dynamic-environment-policy.v1".to_string(),
            schema_version: 1,
            service_ref: SERVICE_REF.to_string(),
            environment_policy_ref: ENVIRONMENT_POLICY_REF.to_string(),
            environment_policy_fingerprint: ENVIRONMENT_POLICY_FINGERPRINT.to_string(),
            declaration_fingerprint: DECLARATION_REF.to_string(),
            delivery_profile_ref: DELIVERY_PROFILE_REF.to_string(),
            reload_profile_ref: RELOAD_PROFILE_REF.to_string(),
            health_profile_ref: HEALTH_PROFILE_REF.to_string(),
            allowed_sources: vec!["generated".to_string(), "import".to_string()],
            name_policy: "portable_secret_env_v1".to_string(),
            additional_reserved_names: vec!["DATABASE_URL".to_string()],
            max_active_bindings: maximum_bindings,
            runtime_owner_uid: owner_uid,
        }],
    }
}

#[allow(clippy::too_many_arguments)]
fn packet(
    generation: u64,
    revocation_epoch: u64,
    value: &[u8],
    recipient: &str,
    signing_key: &SigningKey,
    host_ref: &str,
    envelope_ref: String,
    operation_ref: String,
) -> Vec<u8> {
    seal_host_envelope(HostEnvelopeSealRequest {
        binding: HostEnvelopeBindingV1 {
            schema: PAYLOAD_SCHEMA.to_string(),
            schema_version: SCHEMA_VERSION,
            envelope_ref,
            operation_ref,
            host_ref: host_ref.to_string(),
            service_ref: SERVICE_REF.to_string(),
            slot_ref: SLOT_REF.to_string(),
            secret_ref: SECRET_REF.to_string(),
            scope_ref: SCOPE_REF.to_string(),
            declaration_fingerprint: DECLARATION_REF.to_string(),
            generation,
            revocation_epoch,
            issued_at_unix_secs: NOW - 10,
            expires_at_unix_secs: NOW + 3600,
        },
        host_recipient: recipient,
        signing_key_id: KEY_REF,
        signing_key,
        value: SecretValue::new(value.to_vec()),
    })
    .expect("seal packet")
}

fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(NOW)
}

fn private_dir(path: &Path) {
    fs::create_dir(path).expect("create private directory");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("private directory mode");
}

fn control(generation: u64) -> HostEnvelopeControlV1 {
    HostEnvelopeControlV1 {
        schema: CONTROL_SCHEMA.to_string(),
        schema_version: SCHEMA_VERSION,
        operation_ref: format!("op_{generation:08x}"),
        host_ref: HOST_REF.to_string(),
        service_ref: SERVICE_REF.to_string(),
        slot_ref: SLOT_REF.to_string(),
        generation,
    }
}

fn quarantine_control(generation: u64) -> HostEnvelopeQuarantineControlV1 {
    HostEnvelopeQuarantineControlV1 {
        schema: QUARANTINE_CONTROL_SCHEMA.to_string(),
        schema_version: SCHEMA_VERSION,
        operation_ref: "op_remove00000001".to_string(),
        host_ref: HOST_REF.to_string(),
        service_ref: SERVICE_REF.to_string(),
        slot_ref: SLOT_REF.to_string(),
        generation,
        purge_not_before_unix_secs: NOW + 300,
    }
}

#[test]
fn first_boot_restore_reports_a_declared_missing_slot_without_blocking_install() {
    let fixture = Fixture::new();
    let outcomes = fixture
        .executor
        .restore_all(now())
        .expect("missing restore");
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].phase, "missing");
    assert_eq!(outcomes[0].reason_code, "host_envelope_missing");
    assert!(!outcomes[0].value_returned);
    assert!(!fixture.runtime_target().exists());

    fixture
        .executor
        .install(&fixture.packet(1, b"first-boot-canary"), now())
        .expect("first install after missing restore");
    assert!(fixture.runtime_target().exists());
}

#[test]
fn install_caches_only_ciphertext_and_materializes_private_runtime_value() {
    let fixture = Fixture::new();
    let canary = b"host-envelope-canary-not-for-cache";
    let outcome = fixture
        .executor
        .install(&fixture.packet(1, canary), now())
        .expect("install");
    assert_eq!(outcome.phase, "materialized");
    assert!(!outcome.value_returned);
    assert_eq!(
        fs::read(fixture.runtime_target()).expect("runtime value"),
        canary
    );
    let runtime_metadata = fs::metadata(fixture.runtime_target()).expect("runtime metadata");
    assert_eq!(runtime_metadata.mode() & 0o777, 0o400);
    assert_eq!(runtime_metadata.uid(), fixture.owner_uid);
    let cache = fs::read(fixture.slot_cache().join("current.envelope")).expect("cached envelope");
    assert!(!cache.windows(canary.len()).any(|window| window == canary));
    let cache_metadata =
        fs::metadata(fixture.slot_cache().join("current.envelope")).expect("cache metadata");
    assert_eq!(cache_metadata.mode() & 0o777, 0o600);
    assert_eq!(cache_metadata.nlink(), 1);
    let status = fixture.executor.status().expect("status");
    assert_eq!(status[0].phase, "staged");
    fixture.executor.commit(&control(1)).expect("commit");
    let status = fixture.executor.status().expect("committed status");
    assert_eq!(status[0].phase, "active");
    assert_eq!(status[0].generation, Some(1));
}

#[test]
fn privileged_executor_separates_cache_and_runtime_ownership() {
    let fixture = Fixture::new();
    if fixture.owner_uid != 0 {
        return;
    }

    let runtime_owner_uid = 65_534;
    let executor = HostExecutor::new(
        config(&fixture.signing_key, runtime_owner_uid),
        ExecutorPaths {
            identity: fixture.identity_path.clone(),
            cache_root: fixture.cache_root.clone(),
            runtime_root: fixture.runtime_root.clone(),
            executor_uid: fixture.owner_uid,
        },
    )
    .expect("privileged executor");
    executor
        .install(&fixture.packet(1, b"split-owner-canary"), now())
        .expect("split-owner install");

    assert_eq!(
        fs::metadata(fixture.slot_cache().join("current.envelope"))
            .expect("cache metadata")
            .uid(),
        fixture.owner_uid
    );
    assert_eq!(
        fs::metadata(fixture.runtime_root.join(SERVICE_REF))
            .expect("runtime directory metadata")
            .uid(),
        fixture.owner_uid
    );
    assert_eq!(
        fs::metadata(fixture.runtime_target())
            .expect("runtime target metadata")
            .uid(),
        runtime_owner_uid
    );
}

#[test]
fn failed_first_install_rolls_back_runtime_and_ciphertext_before_activation() {
    let fixture = Fixture::new();
    fixture
        .executor
        .install(&fixture.packet(1, b"create-that-fails-health"), now())
        .expect("stage first generation");
    let rollback = fixture
        .executor
        .rollback(&control(1), now() + Duration::from_secs(30))
        .expect("rollback staged create");
    assert_eq!(rollback.phase, "rolled_back");
    assert!(!fixture.runtime_target().exists());
    assert!(!fixture.slot_cache().join("current.envelope").exists());
    assert!(!fixture.slot_cache().join("state.json").exists());
    let status = fixture.executor.status().expect("missing status");
    assert_eq!(status[0].phase, "missing");
}

#[test]
fn recipient_and_janus_signature_are_both_required() {
    let fixture = Fixture::new();
    let packet = fixture.packet(1, b"recipient-canary");

    let other_identity = age::x25519::Identity::generate();
    fs::write(
        &fixture.identity_path,
        other_identity.to_string().expose_secret().as_bytes(),
    )
    .expect("replace identity");
    fs::set_permissions(&fixture.identity_path, fs::Permissions::from_mode(0o600))
        .expect("identity mode");
    assert_eq!(
        fixture.executor.install(&packet, now()).unwrap_err(),
        HostEnvelopeError::new("host_envelope_decrypt_denied")
    );

    let fixture = Fixture::new();
    let mut signed: SignedHostEnvelopeV1 =
        serde_json::from_slice(&fixture.packet(1, b"signature-canary")).expect("packet");
    let mut ciphertext = STANDARD_NO_PAD
        .decode(signed.ciphertext.as_bytes())
        .expect("ciphertext");
    ciphertext[8] ^= 0x01;
    signed.ciphertext = STANDARD_NO_PAD.encode(ciphertext);
    let tampered = serde_json::to_vec(&signed).expect("tampered packet");
    assert_eq!(
        fixture.executor.install(&tampered, now()).unwrap_err(),
        HostEnvelopeError::new("host_envelope_signature_invalid")
    );
}

#[test]
fn exact_host_scope_slot_declaration_epoch_and_generation_are_enforced() {
    let fixture = Fixture::new();
    let wrong_host = packet(
        1,
        1,
        b"wrong-host",
        &fixture.recipient,
        &fixture.signing_key,
        "host_ffffffffffff",
        "env_ffffffff".to_string(),
        "op_ffffffff".to_string(),
    );
    assert_eq!(
        fixture.executor.install(&wrong_host, now()).unwrap_err(),
        HostEnvelopeError::new("host_envelope_binding_denied")
    );

    fixture
        .executor
        .install(&fixture.packet(2, b"generation-two"), now())
        .expect("new generation");
    assert_eq!(
        fixture
            .executor
            .install(&fixture.packet(1, b"downgrade"), now())
            .unwrap_err(),
        HostEnvelopeError::new("host_envelope_generation_downgrade")
    );

    let mut revoked_config = config(&fixture.signing_key, fixture.owner_uid);
    revoked_config.minimum_revocation_epoch = 5;
    let revoked = HostExecutor::new(
        revoked_config,
        ExecutorPaths {
            identity: fixture.identity_path.clone(),
            cache_root: fixture.cache_root.join("revoked-cache"),
            runtime_root: fixture.runtime_root.join("revoked-runtime"),
            executor_uid: fixture.owner_uid,
        },
    )
    .expect("revocation executor");
    private_dir(&fixture.cache_root.join("revoked-cache"));
    private_dir(&fixture.runtime_root.join("revoked-runtime"));
    assert_eq!(
        revoked
            .install(
                &packet(
                    6,
                    4,
                    b"revoked-epoch",
                    &fixture.recipient,
                    &fixture.signing_key,
                    HOST_REF,
                    "env_00000006".to_string(),
                    "op_00000006".to_string(),
                ),
                now(),
            )
            .unwrap_err(),
        HostEnvelopeError::new("host_envelope_binding_denied")
    );
}

#[test]
fn replacement_preserves_one_bounded_rollback_generation_then_commit_destroys_it() {
    let fixture = Fixture::new();
    fixture
        .executor
        .install(&fixture.packet(1, b"first-generation"), now())
        .expect("first");
    fixture.executor.commit(&control(1)).expect("commit first");
    fixture
        .executor
        .install(&fixture.packet(2, b"second-generation"), now())
        .expect("second");
    assert!(fixture.slot_cache().join("previous.envelope").is_file());
    assert_eq!(
        fs::read(fixture.runtime_target()).expect("second runtime"),
        b"second-generation"
    );
    assert_eq!(
        fixture.executor.status().expect("status")[0].phase,
        "staged"
    );
    fixture.executor.commit(&control(2)).expect("commit");
    assert!(!fixture.slot_cache().join("previous.envelope").exists());
    assert_eq!(
        fixture.executor.status().expect("status")[0].phase,
        "active"
    );
    assert_eq!(
        fixture.executor.rollback(&control(2), now()).unwrap_err(),
        HostEnvelopeError::new("host_envelope_rollback_not_available")
    );
}

#[test]
fn quarantine_recovers_interrupted_write_restores_and_purges_only_when_due() {
    let fixture = Fixture::new();
    let canary = b"host-quarantine-plaintext-canary";
    fixture
        .executor
        .install(&fixture.packet(1, canary), now())
        .expect("install");
    fixture.executor.commit(&control(1)).expect("commit");
    let request = quarantine_control(1);

    // Simulate a crash after the encrypted packet copy but before the
    // quarantine state and active-cache removal. The same bound request must
    // finish, without accepting different bytes.
    let quarantine_root = fixture.cache_root.join(".quarantine");
    private_dir(&quarantine_root);
    let quarantine_slot = quarantine_root.join(SLOT_REF);
    private_dir(&quarantine_slot);
    let quarantine_dir = quarantine_slot.join(&request.operation_ref);
    private_dir(&quarantine_dir);
    let quarantine_packet = quarantine_dir.join("current.envelope");
    fs::copy(
        fixture.slot_cache().join("current.envelope"),
        &quarantine_packet,
    )
    .expect("interrupted packet copy");
    fs::set_permissions(&quarantine_packet, fs::Permissions::from_mode(0o600))
        .expect("quarantine packet mode");

    let outcome = fixture
        .executor
        .quarantine(&request)
        .expect("resume quarantine");
    assert_eq!(outcome.phase, "quarantined");
    assert!(!outcome.value_returned);
    assert!(!fixture.runtime_target().exists());
    assert!(!fixture.slot_cache().join("current.envelope").exists());
    assert!(!fixture.slot_cache().join("state.json").exists());
    assert!(!fs::read(&quarantine_packet)
        .expect("quarantine ciphertext")
        .windows(canary.len())
        .any(|window| window == canary));
    let status = fixture.executor.status().expect("restart-safe status");
    assert_eq!(status[0].phase, "quarantined");
    assert_eq!(
        status[0].operation_ref.as_deref(),
        Some("op_remove00000001")
    );
    assert_eq!(
        fixture
            .executor
            .quarantine(&request)
            .expect("idempotent quarantine")
            .phase,
        "quarantined"
    );

    let mut wrong_deadline = request.clone();
    wrong_deadline.purge_not_before_unix_secs += 1;
    assert_eq!(
        fixture.executor.quarantine(&wrong_deadline).unwrap_err(),
        HostEnvelopeError::new("host_quarantine_state_mismatch")
    );
    assert_eq!(
        fixture
            .executor
            .purge_quarantine(&request, now() + Duration::from_secs(299))
            .unwrap_err(),
        HostEnvelopeError::new("host_quarantine_not_due")
    );

    let restored = fixture
        .executor
        .restore_quarantine(&request, now() + Duration::from_secs(10))
        .expect("restore inside recovery window");
    assert_eq!(restored.phase, "active");
    assert_eq!(
        fs::read(fixture.runtime_target()).expect("restored runtime"),
        canary
    );
    assert_eq!(
        fixture.executor.status().expect("active status")[0].phase,
        "active"
    );

    fixture
        .executor
        .quarantine(&request)
        .expect("quarantine again for purge");
    let purged = fixture
        .executor
        .purge_quarantine(&request, now() + Duration::from_secs(300))
        .expect("purge at boundary");
    assert_eq!(purged.phase, "destroyed");
    assert!(!purged.value_returned);
    assert_eq!(
        fixture.executor.status().expect("missing status")[0].phase,
        "missing"
    );
    assert_eq!(
        fixture
            .executor
            .purge_quarantine(&request, now() + Duration::from_secs(301))
            .expect("idempotent purge")
            .reason_code,
        "host_envelope_quarantine_purge_idempotent"
    );
}

#[test]
fn rollback_and_offline_reboot_restore_the_exact_previous_generation() {
    let fixture = Fixture::new();
    fixture
        .executor
        .install(&fixture.packet(1, b"stable-generation"), now())
        .expect("first");
    fixture.executor.commit(&control(1)).expect("commit first");
    fixture
        .executor
        .install(&fixture.packet(2, b"failed-generation"), now())
        .expect("second");
    let rollback = fixture
        .executor
        .rollback(&control(2), now() + Duration::from_secs(30))
        .expect("rollback");
    assert_eq!(rollback.phase, "rolled_back");
    assert_eq!(
        fs::read(fixture.runtime_target()).expect("rolled back runtime"),
        b"stable-generation"
    );
    fs::remove_file(fixture.runtime_target()).expect("simulate reboot tmpfs");
    let restored = fixture
        .executor
        .restore_all(now() + Duration::from_secs(60))
        .expect("offline restore");
    assert_eq!(restored[0].reason_code, "host_envelope_restored_offline");
    assert_eq!(
        fs::read(fixture.runtime_target()).expect("restored runtime"),
        b"stable-generation"
    );
}

#[test]
fn interrupted_atomic_replace_is_reconciled_without_accepting_partial_bytes() {
    let fixture = Fixture::new();
    fixture
        .executor
        .install(&fixture.packet(1, b"stable-before-crash"), now())
        .expect("first");
    fixture.executor.commit(&control(1)).expect("commit first");
    let current = fixture.slot_cache().join("current.envelope");
    let previous = fixture.slot_cache().join("previous.envelope");

    fs::hard_link(&current, &previous).expect("simulate crash before replace");
    assert_eq!(
        fixture
            .executor
            .restore_all(now() + Duration::from_secs(5))
            .unwrap_err(),
        HostEnvelopeError::new("host_cache_current_unavailable")
    );
    fs::remove_file(&previous).expect("remove rejected hardlink");
    assert_eq!(fs::metadata(&current).expect("current metadata").nlink(), 1);

    atomic_write(
        &previous,
        &fs::read(&current).expect("current packet"),
        0o600,
        fixture.owner_uid,
        "test_write_failed",
    )
    .expect("preserve old generation");
    atomic_write(
        &current,
        &fixture.packet(2, b"new-after-crash"),
        0o600,
        fixture.owner_uid,
        "test_write_failed",
    )
    .expect("simulate replace before state");
    fs::remove_file(fixture.runtime_target()).expect("simulate tmpfs reset");
    fixture
        .executor
        .restore_all(now() + Duration::from_secs(10))
        .expect("state recovery");
    assert_eq!(
        fs::read(fixture.runtime_target()).expect("recovered runtime"),
        b"new-after-crash"
    );
    assert_eq!(
        fixture.executor.status().expect("status")[0].phase,
        "staged"
    );
}

#[test]
fn expired_envelopes_and_expired_rollback_windows_fail_closed() {
    let fixture = Fixture::new();
    fixture
        .executor
        .install(&fixture.packet(1, b"stable"), now())
        .expect("first");
    fixture.executor.commit(&control(1)).expect("commit first");
    fixture
        .executor
        .install(&fixture.packet(2, b"staged"), now())
        .expect("second");
    assert_eq!(
        fixture
            .executor
            .rollback(&control(2), now() + Duration::from_secs(301))
            .unwrap_err(),
        HostEnvelopeError::new("host_envelope_rollback_expired")
    );
    assert_eq!(
        fixture
            .executor
            .restore_all(now() + Duration::from_secs(301))
            .unwrap_err(),
        HostEnvelopeError::new("host_envelope_rollback_expired")
    );

    let fixture = Fixture::new();
    assert_eq!(
        fixture
            .executor
            .install(
                &fixture.packet(1, b"expired"),
                now() + Duration::from_secs(3600),
            )
            .unwrap_err(),
        HostEnvelopeError::new("host_envelope_expired")
    );
}

#[test]
fn committed_cache_restores_after_delivery_expiry_but_staged_cache_still_expires() {
    let fixture = Fixture::new();
    fixture
        .executor
        .install(&fixture.packet(1, b"committed"), now())
        .expect("install committed generation");
    fixture
        .executor
        .commit(&control(1))
        .expect("commit generation");
    fs::remove_file(fixture.runtime_target()).expect("simulate runtime loss");

    let restored = fixture
        .executor
        .restore_all(now() + Duration::from_secs(3600))
        .expect("restore committed cache after delivery expiry");
    assert_eq!(restored[0].reason_code, "host_envelope_restored_offline");
    assert_eq!(
        fs::read(fixture.runtime_target()).expect("restored runtime"),
        b"committed"
    );
    fs::remove_file(fixture.runtime_target()).expect("simulate another runtime loss");
    let mut revoked_config = config(&fixture.signing_key, fixture.owner_uid);
    revoked_config.revoked_envelope_refs = vec!["env_00000001".to_string()];
    let revoked_executor = HostExecutor::new(
        revoked_config,
        ExecutorPaths {
            identity: fixture.identity_path.clone(),
            cache_root: fixture.cache_root.clone(),
            runtime_root: fixture.runtime_root.clone(),
            executor_uid: fixture.owner_uid,
        },
    )
    .expect("revoked executor");
    assert_eq!(
        revoked_executor
            .restore_all(now() + Duration::from_secs(3600))
            .unwrap_err(),
        HostEnvelopeError::new("host_envelope_binding_denied")
    );

    let fixture = Fixture::new();
    fixture
        .executor
        .install(&fixture.packet(1, b"staged"), now())
        .expect("install staged generation");
    assert_eq!(
        fixture
            .executor
            .restore_all(now() + Duration::from_secs(3600))
            .unwrap_err(),
        HostEnvelopeError::new("host_envelope_rollback_expired")
    );
}

#[test]
fn partial_symlink_hardlink_and_tampered_cache_objects_are_rejected() {
    let fixture = Fixture::new();
    fixture
        .executor
        .install(&fixture.packet(1, b"safe-cache"), now())
        .expect("install");
    let partial = fixture.slot_cache().join(".interrupted.tmp");
    fs::write(&partial, b"partial").expect("partial");
    fs::set_permissions(&partial, fs::Permissions::from_mode(0o600)).expect("partial mode");
    assert_eq!(
        fixture.executor.restore_all(now()).unwrap_err(),
        HostEnvelopeError::new("host_cache_partial_file")
    );
    fs::remove_file(&partial).expect("remove test partial");

    let current = fixture.slot_cache().join("current.envelope");
    let outside = fixture.cache_root.join("outside");
    fs::write(&outside, b"outside").expect("outside");
    fs::set_permissions(&outside, fs::Permissions::from_mode(0o600)).expect("outside mode");
    fs::remove_file(&current).expect("remove current");
    symlink(&outside, &current).expect("symlink current");
    assert_eq!(
        fixture.executor.restore_all(now()).unwrap_err(),
        HostEnvelopeError::new("host_cache_unsafe_entry")
    );

    let fixture = Fixture::new();
    fixture
        .executor
        .install(&fixture.packet(1, b"hardlink-cache"), now())
        .expect("install");
    fs::hard_link(
        fixture.slot_cache().join("current.envelope"),
        fixture.cache_root.join("linked-envelope"),
    )
    .expect("hard link");
    assert_eq!(
        fixture.executor.restore_all(now()).unwrap_err(),
        HostEnvelopeError::new("host_cache_unsafe_entry")
    );

    let fixture = Fixture::new();
    fixture
        .executor
        .install(&fixture.packet(1, b"state-cache"), now())
        .expect("install");
    let state = fixture.slot_cache().join("state.json");
    let mut raw = fs::read(&state).expect("state");
    let byte = raw
        .iter_mut()
        .find(|byte| **byte == b'1')
        .expect("state digit");
    *byte = b'2';
    fs::write(&state, raw).expect("tamper state");
    fs::set_permissions(&state, fs::Permissions::from_mode(0o600)).expect("state mode");
    assert_eq!(
        fixture.executor.restore_all(now()).unwrap_err(),
        HostEnvelopeError::new("host_cache_state_tampered")
    );
}

#[test]
fn retired_host_removes_runtime_and_bounded_input_rejects_oversize() {
    let fixture = Fixture::new();
    fixture
        .executor
        .install(&fixture.packet(1, b"retired-host"), now())
        .expect("install");
    let mut retired_config = config(&fixture.signing_key, fixture.owner_uid);
    retired_config.retired = true;
    let retired = HostExecutor::new(
        retired_config,
        ExecutorPaths {
            identity: fixture.identity_path.clone(),
            cache_root: fixture.cache_root.clone(),
            runtime_root: fixture.runtime_root.clone(),
            executor_uid: fixture.owner_uid,
        },
    )
    .expect("retired executor");
    assert_eq!(
        retired.restore_all(now()).unwrap_err(),
        HostEnvelopeError::new("host_executor_retired")
    );
    assert!(!fixture.runtime_target().exists());

    let mut oversized = Cursor::new(vec![b'x'; 17]);
    assert_eq!(
        read_bounded_input(&mut oversized, 16).unwrap_err(),
        HostEnvelopeError::new("host_executor_input_invalid")
    );
}

#[test]
fn errors_status_and_persisted_metadata_never_echo_the_canary() {
    let fixture = Fixture::new();
    let canary = b"literal-super-secret-canary";
    fixture
        .executor
        .install(&fixture.packet(1, canary), now())
        .expect("install");
    let status = serde_json::to_vec(&fixture.executor.status().expect("status")).expect("json");
    let state = fs::read(fixture.slot_cache().join("state.json")).expect("state");
    let packet = fs::read(fixture.slot_cache().join("current.envelope")).expect("packet");
    for surface in [&status[..], &state[..], &packet[..]] {
        assert!(!surface.windows(canary.len()).any(|window| window == canary));
    }
    let error = fixture
        .executor
        .install(&fixture.packet(1, canary), now())
        .unwrap_err()
        .to_string();
    assert!(!error.contains("canary"));
}

#[test]
fn dynamic_packet_is_separately_sealed_and_v1_executor_rejects_it() {
    let fixture = Fixture::new();
    let canary = b"dynamic-host-package-canary";
    let packet = seal_dynamic_host_envelope(DynamicHostEnvelopeSealRequest {
        binding: DynamicHostEnvelopeBindingV1 {
            schema: DYNAMIC_PAYLOAD_SCHEMA.to_string(),
            schema_version: SCHEMA_VERSION,
            envelope_ref: "env_dynamic0001".to_string(),
            operation_ref: "op_dynamic0001".to_string(),
            operation_kind: "create".to_string(),
            source: "import".to_string(),
            host_ref: HOST_REF.to_string(),
            service_ref: SERVICE_REF.to_string(),
            binding_ref: "bind_dynamic0001".to_string(),
            secret_ref: "sec_dynamic0001".to_string(),
            generation_ref: "gen_dynamic0001".to_string(),
            environment_policy_ref: "envpol_dynamic0001".to_string(),
            environment_policy_fingerprint: "envpf_dynamic0001".to_string(),
            declaration_fingerprint: DECLARATION_REF.to_string(),
            environment_name: "DATABASE_PASSWORD".to_string(),
            delivery_profile_ref: "delivery_dynamic0001".to_string(),
            reload_profile_ref: "reload_dynamic0001".to_string(),
            health_profile_ref: "health_dynamic0001".to_string(),
            revocation_epoch: 1,
            issued_at_unix_secs: NOW - 10,
            expires_at_unix_secs: NOW + 3600,
        },
        host_recipient: &fixture.recipient,
        signing_key_id: KEY_REF,
        signing_key: &fixture.signing_key,
        value: SecretValue::new(canary.to_vec()),
    })
    .expect("seal dynamic packet");
    assert!(!packet.windows(canary.len()).any(|window| window == canary));
    assert_eq!(
        fixture.executor.install(&packet, now()).unwrap_err(),
        HostEnvelopeError::new("host_envelope_packet_invalid")
    );
    assert!(!fixture.runtime_target().exists());
}

#[test]
fn dynamic_create_rebuilds_one_sorted_private_aggregate_without_caching_plaintext() {
    let fixture = Fixture::new();
    let executor = fixture.dynamic_executor(3);
    let beta = fixture.dynamic_packet(
        "dynamicbeta01",
        "dynamicbeta01",
        "dynamicbeta01",
        "SERVICE_TOKEN",
        b"beta-canary-value",
        "create",
        SERVICE_REF,
    );
    let alpha = fixture.dynamic_packet(
        "dynamicalpha1",
        "dynamicalpha1",
        "dynamicalpha1",
        "API_PASSWORD",
        b"alpha-canary-value",
        "create",
        SERVICE_REF,
    );

    let first = executor
        .install_dynamic(&beta, now())
        .expect("first create");
    assert_eq!(first.phase, "materialized");
    assert_eq!(first.binding_count, 1);
    assert!(!first.value_returned);
    let second = executor
        .install_dynamic(&alpha, now())
        .expect("second create");
    assert_eq!(second.binding_count, 2);
    assert_eq!(
        fs::read(fixture.dynamic_runtime_target()).expect("dynamic runtime"),
        b"API_PASSWORD=alpha-canary-value\nSERVICE_TOKEN=beta-canary-value\n"
    );
    let metadata = fs::metadata(fixture.dynamic_runtime_target()).expect("runtime metadata");
    assert_eq!(metadata.mode() & 0o777, 0o400);
    assert_eq!(metadata.uid(), fixture.owner_uid);

    for entry in fs::read_dir(fixture.dynamic_cache()).expect("dynamic cache") {
        let entry = entry.expect("cache entry");
        let bytes = fs::read(entry.path()).expect("cache bytes");
        for canary in [b"alpha-canary-value".as_slice(), b"beta-canary-value"] {
            assert!(!bytes.windows(canary.len()).any(|window| window == canary));
        }
    }

    let repeated = executor
        .install_dynamic(&alpha, now())
        .expect("exact retry");
    assert_eq!(
        repeated.reason_code,
        "dynamic_host_materialization_idempotent"
    );
    assert_eq!(repeated.binding_count, 2);
}

#[test]
fn dynamic_restore_reconstructs_the_complete_aggregate_after_delivery_expiry() {
    let fixture = Fixture::new();
    let executor = fixture.dynamic_executor(2);
    let packet = fixture.dynamic_packet(
        "restorevalue01",
        "restorevalue01",
        "restorevalue01",
        "SERVICE_TOKEN",
        b"offline-restore-canary",
        "create",
        SERVICE_REF,
    );
    executor
        .install_dynamic(&packet, now())
        .expect("dynamic create");
    fs::remove_file(fixture.dynamic_runtime_target()).expect("remove volatile runtime");

    let restored = executor
        .restore_dynamic_all(UNIX_EPOCH + Duration::from_secs(NOW + 7200))
        .expect("offline restore after delivery expiry");
    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].phase, "materialized");
    assert_eq!(restored[0].binding_count, 1);
    assert_eq!(
        fs::read(fixture.dynamic_runtime_target()).expect("restored runtime"),
        b"SERVICE_TOKEN=offline-restore-canary\n"
    );
}

#[test]
fn dynamic_restore_reconciles_both_interrupted_create_boundaries() {
    let fixture = Fixture::new();
    let executor = fixture.dynamic_executor(2);
    let packet = fixture.dynamic_packet(
        "pendingpacket1",
        "pendingpacket1",
        "pendingpacket1",
        "SERVICE_TOKEN",
        b"pending-recovery-canary",
        "create",
        SERVICE_REF,
    );
    executor
        .install_dynamic(&packet, now())
        .expect("initial dynamic create");
    executor
        .test_move_dynamic_binding_to_pending(SERVICE_REF)
        .expect("model post-cache crash");
    fs::remove_file(fixture.dynamic_runtime_target()).expect("remove volatile runtime");

    let restored = executor
        .restore_dynamic_all(now())
        .expect("complete pending create with packet");
    assert_eq!(restored[0].binding_count, 1);
    assert_eq!(
        fs::read(fixture.dynamic_runtime_target()).expect("recovered aggregate"),
        b"SERVICE_TOKEN=pending-recovery-canary\n"
    );

    let fixture = Fixture::new();
    let executor = fixture.dynamic_executor(2);
    let packet = fixture.dynamic_packet(
        "missingpacket1",
        "missingpacket1",
        "missingpacket1",
        "SERVICE_TOKEN",
        b"discarded-pending-canary",
        "create",
        SERVICE_REF,
    );
    executor
        .install_dynamic(&packet, now())
        .expect("initial create before interrupted cache write");
    let binding_ref = executor
        .test_move_dynamic_binding_to_pending(SERVICE_REF)
        .expect("model pre-cache crash");
    fs::remove_file(
        fixture
            .dynamic_cache()
            .join(format!("{binding_ref}.envelope")),
    )
    .expect("remove packet to model pre-create crash");
    fs::remove_file(fixture.dynamic_runtime_target()).expect("remove volatile runtime");

    let restored = executor
        .restore_dynamic_all(now())
        .expect("discard pending state without packet");
    assert_eq!(restored[0].phase, "missing");
    assert_eq!(restored[0].binding_count, 0);
    assert!(!fixture.dynamic_runtime_target().exists());
}

#[test]
fn dynamic_policy_collision_capacity_replace_and_invalid_values_fail_closed() {
    let fixture = Fixture::new();
    let executor = fixture.dynamic_executor(1);
    let accepted = fixture.dynamic_packet(
        "acceptedvalue1",
        "acceptedvalue1",
        "acceptedvalue1",
        "SERVICE_TOKEN",
        b"accepted-canary",
        "create",
        SERVICE_REF,
    );
    executor
        .install_dynamic(&accepted, now())
        .expect("accepted create");
    let expected = fs::read(fixture.dynamic_runtime_target()).expect("accepted runtime");

    let collision = fixture.dynamic_packet(
        "collisionval1",
        "collisionval1",
        "collisionval1",
        "SERVICE_TOKEN",
        b"collision-canary",
        "create",
        SERVICE_REF,
    );
    assert_eq!(
        executor.install_dynamic(&collision, now()).unwrap_err(),
        HostEnvelopeError::new("dynamic_host_binding_collision")
    );
    let capacity = fixture.dynamic_packet(
        "capacityvalue1",
        "capacityvalue1",
        "capacityvalue1",
        "ANOTHER_TOKEN",
        b"capacity-canary",
        "create",
        SERVICE_REF,
    );
    assert_eq!(
        executor.install_dynamic(&capacity, now()).unwrap_err(),
        HostEnvelopeError::new("dynamic_host_capacity_exhausted")
    );
    let replace = fixture.dynamic_packet(
        "replacevalue01",
        "replacevalue01",
        "replacevalue01",
        "SERVICE_TOKEN",
        b"replace-canary",
        "replace",
        SERVICE_REF,
    );
    let staged = executor
        .install_dynamic(&replace, now())
        .expect("exact existing name may be staged for replacement");
    assert_eq!(staged.reason_code, "dynamic_host_replacement_materialized");
    assert_eq!(
        fs::read(fixture.dynamic_runtime_target()).expect("replacement runtime"),
        b"SERVICE_TOKEN=replace-canary\n"
    );
    let rolled_back = executor
        .rollback_dynamic_replacement(
            &DynamicHostReplacementControlV1 {
                operation_ref: "op_replacevalue01".to_string(),
                binding_ref: "bind_replacevalue01".to_string(),
                generation_ref: "gen_replacevalue01".to_string(),
            },
            now(),
        )
        .expect("rollback replacement");
    assert_eq!(rolled_back.phase, "rolled_back");
    assert_eq!(
        rolled_back.previous_generation_ref.as_deref(),
        Some("gen_acceptedvalue1")
    );
    let reserved = fixture.dynamic_packet(
        "reservedvalue1",
        "reservedvalue1",
        "reservedvalue1",
        "DATABASE_URL",
        b"reserved-canary",
        "create",
        SERVICE_REF,
    );
    assert_eq!(
        executor.install_dynamic(&reserved, now()).unwrap_err(),
        HostEnvelopeError::new("dynamic_host_policy_drift")
    );
    let multiline = fixture.dynamic_packet(
        "multilineval1",
        "multilineval1",
        "multilineval1",
        "ANOTHER_TOKEN",
        b"not\nportable",
        "create",
        SERVICE_REF,
    );
    assert_eq!(
        executor.install_dynamic(&multiline, now()).unwrap_err(),
        HostEnvelopeError::new("dynamic_host_value_invalid")
    );
    assert_eq!(
        fs::read(fixture.dynamic_runtime_target()).expect("unchanged runtime"),
        expected
    );
}

#[test]
fn dynamic_replacement_commit_is_idempotent_and_restores_only_the_new_generation() {
    let fixture = Fixture::new();
    let executor = fixture.dynamic_executor(2);
    let original = fixture.dynamic_packet(
        "originalvalue1",
        "originalvalue1",
        "originalvalue1",
        "SERVICE_TOKEN",
        b"original-canary",
        "create",
        SERVICE_REF,
    );
    let replacement = fixture.dynamic_packet(
        "replacement01",
        "replacement01",
        "replacement01",
        "SERVICE_TOKEN",
        b"replacement-canary",
        "replace",
        SERVICE_REF,
    );
    executor
        .install_dynamic(&original, now())
        .expect("original create");
    executor
        .install_dynamic(&replacement, now())
        .expect("replacement stage");
    let control = DynamicHostReplacementControlV1 {
        operation_ref: "op_replacement01".to_string(),
        binding_ref: "bind_replacement01".to_string(),
        generation_ref: "gen_replacement01".to_string(),
    };
    let committed = executor
        .commit_dynamic_replacement(&control, now())
        .expect("commit after healthy reload");
    assert_eq!(committed.phase, "committed");
    assert_eq!(
        executor
            .commit_dynamic_replacement(&control, now())
            .expect("lost commit response is idempotent")
            .reason_code,
        "dynamic_host_replacement_commit_idempotent"
    );
    fs::remove_file(fixture.dynamic_runtime_target()).expect("remove volatile runtime");
    executor
        .restore_dynamic_all(UNIX_EPOCH + Duration::from_secs(NOW + 7200))
        .expect("restore committed replacement after packet expiry");
    assert_eq!(
        fs::read(fixture.dynamic_runtime_target()).expect("committed runtime"),
        b"SERVICE_TOKEN=replacement-canary\n"
    );
    assert!(!fixture
        .dynamic_cache()
        .join("bind_originalvalue1.envelope")
        .exists());
}

#[test]
fn dynamic_restore_rolls_back_an_unconfirmed_replacement() {
    let fixture = Fixture::new();
    let executor = fixture.dynamic_executor(2);
    let original = fixture.dynamic_packet(
        "crashoriginal1",
        "crashoriginal1",
        "crashoriginal1",
        "SERVICE_TOKEN",
        b"crash-original-canary",
        "create",
        SERVICE_REF,
    );
    let replacement = fixture.dynamic_packet(
        "crashreplace01",
        "crashreplace01",
        "crashreplace01",
        "SERVICE_TOKEN",
        b"crash-replacement-canary",
        "replace",
        SERVICE_REF,
    );
    executor
        .install_dynamic(&original, now())
        .expect("original create");
    executor
        .install_dynamic(&replacement, now())
        .expect("replacement stage");
    fs::remove_file(fixture.dynamic_runtime_target()).expect("simulate reboot");
    executor
        .restore_dynamic_all(now())
        .expect("unconfirmed replacement safely rolls back on reboot");
    assert_eq!(
        fs::read(fixture.dynamic_runtime_target()).expect("recovered runtime"),
        b"SERVICE_TOKEN=crash-original-canary\n"
    );
    assert!(!fixture
        .dynamic_cache()
        .join("bind_crashreplace01.envelope")
        .exists());
}

#[test]
fn dynamic_restore_finishes_interrupted_replacement_commit_and_rollback() {
    for (phase, remove_packet, expected) in [
        (
            "commit_pending",
            true,
            b"SERVICE_TOKEN=new-canary\n".as_slice(),
        ),
        (
            "rollback_pending",
            true,
            b"SERVICE_TOKEN=old-canary\n".as_slice(),
        ),
    ] {
        let fixture = Fixture::new();
        let executor = fixture.dynamic_executor(2);
        executor
            .install_dynamic(
                &fixture.dynamic_packet(
                    "interruptold1",
                    "interruptold1",
                    "interruptold1",
                    "SERVICE_TOKEN",
                    b"old-canary",
                    "create",
                    SERVICE_REF,
                ),
                now(),
            )
            .expect("old create");
        executor
            .install_dynamic(
                &fixture.dynamic_packet(
                    "interruptnew1",
                    "interruptnew1",
                    "interruptnew1",
                    "SERVICE_TOKEN",
                    b"new-canary",
                    "replace",
                    SERVICE_REF,
                ),
                now(),
            )
            .expect("new stage");
        executor
            .test_interrupt_dynamic_replacement(SERVICE_REF, phase, remove_packet)
            .expect("model interrupted terminalization");
        fs::remove_file(fixture.dynamic_runtime_target()).expect("simulate reboot");
        executor
            .restore_dynamic_all(now())
            .expect("deterministic replacement recovery");
        assert_eq!(
            fs::read(fixture.dynamic_runtime_target()).expect("recovered runtime"),
            expected,
            "phase={phase}"
        );
    }
}

#[test]
fn dynamic_removal_stages_exact_binding_and_rolls_back_idempotently() {
    let fixture = Fixture::new();
    let executor = fixture.dynamic_executor(2);
    executor
        .install_dynamic(
            &fixture.dynamic_packet(
                "removevalue001",
                "removevalue001",
                "removevalue001",
                "SERVICE_TOKEN",
                b"keep-until-healthy",
                "create",
                SERVICE_REF,
            ),
            now(),
        )
        .expect("create removal target");
    let staged = executor
        .install_dynamic(
            &fixture.dynamic_removal_packet("removevalue001", "removecontrol01", "SERVICE_TOKEN"),
            now(),
        )
        .expect("stage removal");
    assert_eq!(staged.reason_code, "dynamic_host_removal_materialized");
    assert_eq!(staged.binding_count, 0);
    assert!(!fixture.dynamic_runtime_target().exists());
    assert!(fixture
        .dynamic_cache()
        .join("bind_removevalue001.envelope")
        .exists());
    let control = DynamicHostRemovalControlV1 {
        operation_ref: "op_removecontrol01".to_string(),
        binding_ref: "bind_removevalue001".to_string(),
        generation_ref: "gen_removevalue001".to_string(),
    };
    let restored = executor
        .rollback_dynamic_removal(&control, now())
        .expect("rollback removal");
    assert_eq!(restored.phase, "rolled_back");
    assert_eq!(
        fs::read(fixture.dynamic_runtime_target()).expect("restored aggregate"),
        b"SERVICE_TOKEN=keep-until-healthy\n"
    );
    assert_eq!(
        executor
            .rollback_dynamic_removal(&control, now())
            .expect("lost rollback response is idempotent")
            .reason_code,
        "dynamic_host_removal_rollback_idempotent"
    );
}

#[test]
fn dynamic_removal_commit_destroys_only_target_packet_and_is_idempotent() {
    let fixture = Fixture::new();
    let executor = fixture.dynamic_executor(2);
    for (suffix, name, value) in [
        ("removecommit01", "SERVICE_TOKEN", b"retire".as_slice()),
        ("remaincommit01", "ANOTHER_TOKEN", b"remain".as_slice()),
    ] {
        executor
            .install_dynamic(
                &fixture.dynamic_packet(suffix, suffix, suffix, name, value, "create", SERVICE_REF),
                now(),
            )
            .expect("create binding");
    }
    executor
        .install_dynamic(
            &fixture.dynamic_removal_packet("removecommit01", "removecommitop", "SERVICE_TOKEN"),
            now(),
        )
        .expect("stage removal");
    let control = DynamicHostRemovalControlV1 {
        operation_ref: "op_removecommitop".to_string(),
        binding_ref: "bind_removecommit01".to_string(),
        generation_ref: "gen_removecommit01".to_string(),
    };
    assert_eq!(
        executor
            .commit_dynamic_removal(&control, now())
            .expect("commit healthy removal")
            .phase,
        "removed"
    );
    assert_eq!(
        fs::read(fixture.dynamic_runtime_target()).expect("reduced aggregate"),
        b"ANOTHER_TOKEN=remain\n"
    );
    assert!(!fixture
        .dynamic_cache()
        .join("bind_removecommit01.envelope")
        .exists());
    assert!(fixture
        .dynamic_cache()
        .join("bind_remaincommit01.envelope")
        .exists());
    assert_eq!(
        executor
            .commit_dynamic_removal(&control, now())
            .expect("lost commit response is idempotent")
            .reason_code,
        "dynamic_host_removal_commit_idempotent"
    );
}

#[test]
fn dynamic_restore_rolls_back_unconfirmed_removal() {
    let fixture = Fixture::new();
    let executor = fixture.dynamic_executor(2);
    executor
        .install_dynamic(
            &fixture.dynamic_packet(
                "rebootremove01",
                "rebootremove01",
                "rebootremove01",
                "SERVICE_TOKEN",
                b"reboot-safe",
                "create",
                SERVICE_REF,
            ),
            now(),
        )
        .expect("create target");
    executor
        .install_dynamic(
            &fixture.dynamic_removal_packet("rebootremove01", "rebootremoveop", "SERVICE_TOKEN"),
            now(),
        )
        .expect("stage removal");
    executor
        .restore_dynamic_all(now())
        .expect("restore rolls back unconfirmed removal");
    assert_eq!(
        fs::read(fixture.dynamic_runtime_target()).expect("recovered aggregate"),
        b"SERVICE_TOKEN=reboot-safe\n"
    );
}

#[test]
fn dynamic_cross_service_and_unsafe_cache_objects_fail_without_runtime_changes() {
    let fixture = Fixture::new();
    let executor = fixture.dynamic_executor(2);
    let cross_service = fixture.dynamic_packet(
        "crossservice01",
        "crossservice01",
        "crossservice01",
        "SERVICE_TOKEN",
        b"cross-service-canary",
        "create",
        "svc_other000001",
    );
    assert_eq!(
        executor.install_dynamic(&cross_service, now()).unwrap_err(),
        HostEnvelopeError::new("dynamic_host_policy_denied")
    );
    assert!(!fixture.dynamic_runtime_target().exists());

    let accepted = fixture.dynamic_packet(
        "safecachevalue",
        "safecachevalue",
        "safecachevalue",
        "SERVICE_TOKEN",
        b"safe-cache-canary",
        "create",
        SERVICE_REF,
    );
    executor
        .install_dynamic(&accepted, now())
        .expect("accepted create");
    fs::remove_file(fixture.dynamic_runtime_target()).expect("remove runtime");
    fs::write(fixture.dynamic_cache().join("orphan.tmp"), b"partial")
        .expect("partial cache object");
    fs::set_permissions(
        fixture.dynamic_cache().join("orphan.tmp"),
        fs::Permissions::from_mode(0o600),
    )
    .expect("partial permissions");
    assert_eq!(
        executor.restore_dynamic_all(now()).unwrap_err(),
        HostEnvelopeError::new("dynamic_host_cache_partial_file")
    );
    assert!(!fixture.dynamic_runtime_target().exists());
}

#[test]
fn dynamic_v2_configuration_is_strict_canonical_and_policy_bound() {
    let fixture = Fixture::new();
    let config = dynamic_config(&fixture.signing_key, fixture.owner_uid, 2);
    let mut value = serde_json::to_value(&config).expect("config value");
    value["unexpected"] = serde_json::json!(true);
    assert!(serde_json::from_value::<HostExecutorConfigV2>(value).is_err());

    let mut duplicate_source = config.clone();
    duplicate_source.dynamic_environment_policies[0].allowed_sources =
        vec!["import".to_string(), "import".to_string()];
    let error = HostExecutor::new_v2(
        duplicate_source,
        ExecutorPaths {
            identity: fixture.identity_path.clone(),
            cache_root: fixture.cache_root.clone(),
            runtime_root: fixture.runtime_root.clone(),
            executor_uid: fixture.owner_uid,
        },
    )
    .err()
    .expect("duplicate source must be denied");
    assert_eq!(
        error,
        HostEnvelopeError::new("host_executor_config_invalid")
    );
}
