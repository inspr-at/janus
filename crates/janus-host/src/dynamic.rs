//! Dynamic service-environment acceptance and aggregate materialization.
//!
//! This module is deliberately create-only. It accepts no transport, reload,
//! health, activation, replacement, rollback, or removal authority.

use super::*;

const DYNAMIC_POLICY_SCHEMA: &str = "inspr.janus.host-dynamic-environment-policy.v1";
const DYNAMIC_STATE_SCHEMA: &str = "inspr.janus.host-dynamic-environment-state.v1";
const DYNAMIC_CONFIG_VERSION: u8 = 2;
const DYNAMIC_SCHEMA_VERSION: u8 = 1;
const DYNAMIC_CACHE_DIR: &str = ".dynamic";
const DYNAMIC_RUNTIME_FILE: &str = "dynamic.env";
const MAX_DYNAMIC_VALUE_BYTES: usize = 1024;
const MAX_DYNAMIC_AGGREGATE_BYTES: usize = 128 * 1024;

/// One root-owned deployed service policy that may accept dynamic creates.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostDynamicEnvironmentPolicyV1 {
    pub schema: String,
    pub schema_version: u8,
    pub service_ref: String,
    pub environment_policy_ref: String,
    pub environment_policy_fingerprint: String,
    pub declaration_fingerprint: String,
    pub delivery_profile_ref: String,
    pub reload_profile_ref: String,
    pub health_profile_ref: String,
    pub allowed_sources: Vec<String>,
    pub name_policy: String,
    pub additional_reserved_names: Vec<String>,
    pub max_active_bindings: u16,
    pub runtime_owner_uid: u32,
}

/// Additive executor configuration. Version 1 remains decoded independently.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostExecutorConfigV2 {
    pub schema: String,
    pub schema_version: u8,
    pub host_ref: String,
    pub scope_ref: String,
    pub owner_uid: u32,
    pub minimum_revocation_epoch: u64,
    pub retired: bool,
    pub producer_keys: Vec<HostProducerKeyV1>,
    pub revoked_envelope_refs: Vec<String>,
    pub slots: Vec<HostSecretSlotV1>,
    pub dynamic_environment_policies: Vec<HostDynamicEnvironmentPolicyV1>,
}

/// Value-free dynamic materialization result.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DynamicHostExecutorOutcome {
    pub action: String,
    pub host_ref: String,
    pub service_ref: String,
    pub environment_policy_ref: String,
    pub binding_ref: Option<String>,
    pub operation_ref: Option<String>,
    pub generation_ref: Option<String>,
    pub binding_count: u16,
    pub phase: String,
    pub reason_code: String,
    pub value_returned: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CachedDynamicBindingV1 {
    envelope_ref: String,
    operation_ref: String,
    source: String,
    binding_ref: String,
    secret_ref: String,
    generation_ref: String,
    environment_name: String,
    revocation_epoch: u64,
    expires_at_unix_secs: u64,
    packet_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct HostDynamicServiceStateV1 {
    schema: String,
    schema_version: u8,
    host_ref: String,
    service_ref: String,
    environment_policy_ref: String,
    environment_policy_fingerprint: String,
    declaration_fingerprint: String,
    bindings: Vec<CachedDynamicBindingV1>,
    pending: Option<CachedDynamicBindingV1>,
    integrity_hash: String,
}

struct DecryptedDynamicHostEnvelope {
    binding: DynamicHostEnvelopeBindingV1,
    value: SecretValue,
    packet_sha256: String,
}

pub(super) fn validate_config_v2(
    config: HostExecutorConfigV2,
) -> HostResult<(HostExecutorConfigV1, Vec<HostDynamicEnvironmentPolicyV1>)> {
    if config.schema != CONFIG_V2_SCHEMA
        || config.schema_version != DYNAMIC_CONFIG_VERSION
        || config.slots.is_empty() && config.dynamic_environment_policies.is_empty()
        || config.dynamic_environment_policies.len()
            > janus_core::MAX_MANAGED_DYNAMIC_BINDINGS as usize
    {
        return Err(HostEnvelopeError::new("host_executor_config_invalid"));
    }
    validate_dynamic_policies(&config.dynamic_environment_policies)?;
    let base = HostExecutorConfigV1 {
        schema: CONFIG_SCHEMA.to_string(),
        schema_version: SCHEMA_VERSION,
        host_ref: config.host_ref,
        scope_ref: config.scope_ref,
        owner_uid: config.owner_uid,
        minimum_revocation_epoch: config.minimum_revocation_epoch,
        retired: config.retired,
        producer_keys: config.producer_keys,
        revoked_envelope_refs: config.revoked_envelope_refs,
        slots: config.slots,
    };
    Ok((base, config.dynamic_environment_policies))
}

fn validate_dynamic_policies(policies: &[HostDynamicEnvironmentPolicyV1]) -> HostResult<()> {
    let mut services = BTreeSet::new();
    let mut policy_refs = BTreeSet::new();
    for policy in policies {
        if policy.schema != DYNAMIC_POLICY_SCHEMA
            || policy.schema_version != DYNAMIC_SCHEMA_VERSION
            || !valid_ref("svc_", &policy.service_ref)
            || !valid_ref("envpol_", &policy.environment_policy_ref)
            || !valid_ref("envpf_", &policy.environment_policy_fingerprint)
            || !valid_ref("decl_", &policy.declaration_fingerprint)
            || !valid_ref("delivery_", &policy.delivery_profile_ref)
            || !valid_ref("reload_", &policy.reload_profile_ref)
            || !valid_ref("health_", &policy.health_profile_ref)
            || policy.name_policy != "portable_secret_env_v1"
            || policy.allowed_sources.is_empty()
            || policy.allowed_sources.len() > 2
            || policy.max_active_bindings == 0
            || policy.max_active_bindings > janus_core::MAX_MANAGED_DYNAMIC_BINDINGS
            || policy.runtime_owner_uid == u32::MAX
            || !services.insert(policy.service_ref.clone())
            || !policy_refs.insert(policy.environment_policy_ref.clone())
        {
            return Err(HostEnvelopeError::new("host_executor_config_invalid"));
        }
        let mut sources = BTreeSet::new();
        for source in &policy.allowed_sources {
            if !matches!(source.as_str(), "generated" | "import") || !sources.insert(source.clone())
            {
                return Err(HostEnvelopeError::new("host_executor_config_invalid"));
            }
        }
        if policy
            .allowed_sources
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(HostEnvelopeError::new("host_executor_config_invalid"));
        }
        let mut reserved = BTreeSet::new();
        for name in &policy.additional_reserved_names {
            if ManagedEnvironmentName::new(name.clone()).is_err() || !reserved.insert(name.clone())
            {
                return Err(HostEnvelopeError::new("host_executor_config_invalid"));
            }
        }
        if policy
            .additional_reserved_names
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(HostEnvelopeError::new("host_executor_config_invalid"));
        }
    }
    Ok(())
}

impl HostExecutor {
    /// Accept one exact dynamic create and atomically rebuild its service file.
    pub fn install_dynamic(
        &self,
        packet: &[u8],
        now: SystemTime,
    ) -> HostResult<DynamicHostExecutorOutcome> {
        if self.config.retired {
            return Err(HostEnvelopeError::new("host_executor_retired"));
        }
        if packet.is_empty() || packet.len() > MAX_PACKET_BYTES {
            return Err(HostEnvelopeError::new(
                "dynamic_host_envelope_packet_oversized",
            ));
        }
        let opened = self.open_dynamic_packet_with_expiry(packet, now, false)?;
        let policy = self.resolve_dynamic_policy(&opened.binding)?;
        validate_dynamic_value(opened.value.expose_bytes())?;

        self.ensure_dynamic_service_dirs(policy)?;
        let service_dir = self.dynamic_service_cache_dir(policy);
        let _lock = lock_slot(&service_dir, self.paths.executor_uid)?;
        let mut state = load_dynamic_state(
            &service_dir.join("state.json"),
            &self.config.host_ref,
            policy,
            self.paths.executor_uid,
        )?;
        validate_dynamic_inventory(&service_dir, &state, self.paths.executor_uid)?;
        state = self.reconcile_dynamic_pending(policy, state, now)?;
        validate_dynamic_inventory(&service_dir, &state, self.paths.executor_uid)?;

        let cached = cached_dynamic_binding(&opened.binding, &opened.packet_sha256);
        if let Some(existing) = state
            .bindings
            .iter()
            .find(|entry| entry.binding_ref == cached.binding_ref)
        {
            if existing != &cached {
                return Err(HostEnvelopeError::new("dynamic_host_binding_exists"));
            }
            drop(opened);
            self.materialize_dynamic_state(policy, &state.bindings, now)?;
            return Ok(dynamic_outcome(
                "install-dynamic",
                &self.config.host_ref,
                policy,
                Some(existing),
                state.bindings.len(),
                "materialized",
                "dynamic_host_materialization_idempotent",
            ));
        }
        if state.bindings.iter().any(|entry| {
            entry.environment_name == cached.environment_name
                || entry.operation_ref == cached.operation_ref
                || entry.envelope_ref == cached.envelope_ref
                || entry.secret_ref == cached.secret_ref
                || entry.generation_ref == cached.generation_ref
        }) {
            return Err(HostEnvelopeError::new("dynamic_host_binding_collision"));
        }
        if state.bindings.len() >= usize::from(policy.max_active_bindings) {
            return Err(HostEnvelopeError::new("dynamic_host_capacity_exhausted"));
        }

        // Prove the complete previous aggregate before recording a pending
        // mutation. Plaintext is immediately zeroized without touching /run.
        let mut previous_aggregate = self.build_dynamic_aggregate(policy, &state.bindings, now)?;
        previous_aggregate.zeroize();
        drop(opened);

        let previous_state = state.clone();
        state.pending = Some(cached.clone());
        write_dynamic_state(
            &service_dir.join("state.json"),
            state.clone(),
            self.paths.executor_uid,
        )?;
        let packet_path = dynamic_packet_path(&service_dir, &cached.binding_ref);
        if let Err(error) = atomic_create_private(
            &packet_path,
            packet,
            self.paths.executor_uid,
            "dynamic_host_cache_write_failed",
        ) {
            return self.fail_dynamic_create(policy, previous_state, &packet_path, now, error);
        }

        let mut completed = state.clone();
        completed.bindings.push(cached.clone());
        completed
            .bindings
            .sort_by(|left, right| left.environment_name.cmp(&right.environment_name));
        completed.pending = None;
        if let Err(error) = self
            .materialize_dynamic_state(policy, &completed.bindings, now)
            .and_then(|()| {
                write_dynamic_state(
                    &service_dir.join("state.json"),
                    completed.clone(),
                    self.paths.executor_uid,
                )
            })
        {
            return self.fail_dynamic_create(policy, previous_state, &packet_path, now, error);
        }
        sync_dir(&service_dir, "dynamic_host_cache_sync_failed")?;
        Ok(dynamic_outcome(
            "install-dynamic",
            &self.config.host_ref,
            policy,
            Some(&cached),
            completed.bindings.len(),
            "materialized",
            "dynamic_host_environment_materialized",
        ))
    }

    /// Rebuild every configured dynamic service aggregate from signed cache.
    pub fn restore_dynamic_all(
        &self,
        now: SystemTime,
    ) -> HostResult<Vec<DynamicHostExecutorOutcome>> {
        if self.config.retired {
            self.remove_dynamic_runtime_files()?;
            return Err(HostEnvelopeError::new("host_executor_retired"));
        }
        let mut outcomes = Vec::with_capacity(self.dynamic_policies.len());
        for policy in &self.dynamic_policies {
            self.ensure_dynamic_service_dirs(policy)?;
            let service_dir = self.dynamic_service_cache_dir(policy);
            let _lock = lock_slot(&service_dir, self.paths.executor_uid)?;
            let mut state = load_dynamic_state(
                &service_dir.join("state.json"),
                &self.config.host_ref,
                policy,
                self.paths.executor_uid,
            )?;
            validate_dynamic_inventory(&service_dir, &state, self.paths.executor_uid)?;
            state = self.reconcile_dynamic_pending(policy, state, now)?;
            validate_dynamic_inventory(&service_dir, &state, self.paths.executor_uid)?;
            self.materialize_dynamic_state(policy, &state.bindings, now)?;
            outcomes.push(dynamic_outcome(
                "restore-dynamic",
                &self.config.host_ref,
                policy,
                None,
                state.bindings.len(),
                if state.bindings.is_empty() {
                    "missing"
                } else {
                    "materialized"
                },
                if state.bindings.is_empty() {
                    "dynamic_host_environment_missing"
                } else {
                    "dynamic_host_environment_restored"
                },
            ));
        }
        Ok(outcomes)
    }

    pub(super) fn remove_dynamic_runtime_files(&self) -> HostResult<()> {
        for policy in &self.dynamic_policies {
            remove_private_file_if_present(
                &self.dynamic_runtime_path(policy),
                policy.runtime_owner_uid,
                "dynamic_host_runtime_target_unsafe",
            )?;
        }
        Ok(())
    }

    fn fail_dynamic_create(
        &self,
        policy: &HostDynamicEnvironmentPolicyV1,
        previous_state: HostDynamicServiceStateV1,
        packet_path: &Path,
        now: SystemTime,
        original: HostEnvelopeError,
    ) -> HostResult<DynamicHostExecutorOutcome> {
        let service_dir = self.dynamic_service_cache_dir(policy);
        let recovered = remove_private_file_if_present(
            packet_path,
            self.paths.executor_uid,
            "dynamic_host_cache_rollback_failed",
        )
        .and_then(|()| {
            write_dynamic_state(
                &service_dir.join("state.json"),
                previous_state.clone(),
                self.paths.executor_uid,
            )
        })
        .and_then(|()| self.materialize_dynamic_state(policy, &previous_state.bindings, now));
        match recovered {
            Ok(()) => Err(original),
            Err(_) => Err(HostEnvelopeError::new("dynamic_host_recovery_failed")),
        }
    }

    fn reconcile_dynamic_pending(
        &self,
        policy: &HostDynamicEnvironmentPolicyV1,
        mut state: HostDynamicServiceStateV1,
        now: SystemTime,
    ) -> HostResult<HostDynamicServiceStateV1> {
        let Some(pending) = state.pending.clone() else {
            return Ok(state);
        };
        let service_dir = self.dynamic_service_cache_dir(policy);
        let packet_path = dynamic_packet_path(&service_dir, &pending.binding_ref);
        if !entry_exists(&packet_path, "dynamic_host_cache_unavailable")? {
            state.pending = None;
            write_dynamic_state(
                &service_dir.join("state.json"),
                state.clone(),
                self.paths.executor_uid,
            )?;
            return Ok(state);
        }
        let packet = read_private_regular(
            &packet_path,
            MAX_PACKET_BYTES,
            Some(self.paths.executor_uid),
            "dynamic_host_cache_unavailable",
        )?;
        if sha256_hex(&packet) != pending.packet_sha256 {
            return Err(HostEnvelopeError::new("dynamic_host_cache_tampered"));
        }
        let opened = self.open_dynamic_packet_with_expiry(&packet, now, true)?;
        self.resolve_dynamic_policy(&opened.binding)?;
        validate_dynamic_value(opened.value.expose_bytes())?;
        if cached_dynamic_binding(&opened.binding, &opened.packet_sha256) != pending {
            return Err(HostEnvelopeError::new("dynamic_host_cache_mismatch"));
        }
        drop(opened);
        let mut completed = state.bindings.clone();
        completed.push(pending);
        completed.sort_by(|left, right| left.environment_name.cmp(&right.environment_name));
        validate_cached_dynamic_set(&completed, policy.max_active_bindings)?;
        self.materialize_dynamic_state(policy, &completed, now)?;
        state.bindings = completed;
        state.pending = None;
        write_dynamic_state(
            &service_dir.join("state.json"),
            state.clone(),
            self.paths.executor_uid,
        )?;
        Ok(state)
    }

    fn materialize_dynamic_state(
        &self,
        policy: &HostDynamicEnvironmentPolicyV1,
        bindings: &[CachedDynamicBindingV1],
        now: SystemTime,
    ) -> HostResult<()> {
        let target = self.dynamic_runtime_path(policy);
        if bindings.is_empty() {
            return remove_private_file_if_present(
                &target,
                policy.runtime_owner_uid,
                "dynamic_host_runtime_target_unsafe",
            );
        }
        let mut aggregate = self.build_dynamic_aggregate(policy, bindings, now)?;
        let result = (|| {
            ensure_private_dir(&self.paths.runtime_root, self.paths.executor_uid)?;
            let service_dir = self.paths.runtime_root.join(&policy.service_ref);
            ensure_private_dir(&service_dir, self.paths.executor_uid)?;
            atomic_write_owned(
                &target,
                &aggregate,
                0o400,
                self.paths.executor_uid,
                policy.runtime_owner_uid,
                "dynamic_host_runtime_write_failed",
            )?;
            sync_dir(&service_dir, "dynamic_host_runtime_sync_failed")
        })();
        aggregate.zeroize();
        result
    }

    fn build_dynamic_aggregate(
        &self,
        policy: &HostDynamicEnvironmentPolicyV1,
        bindings: &[CachedDynamicBindingV1],
        now: SystemTime,
    ) -> HostResult<Vec<u8>> {
        validate_cached_dynamic_set(bindings, policy.max_active_bindings)?;
        let service_dir = self.dynamic_service_cache_dir(policy);
        let mut aggregate = Vec::new();
        for cached in bindings {
            let packet = read_private_regular(
                &dynamic_packet_path(&service_dir, &cached.binding_ref),
                MAX_PACKET_BYTES,
                Some(self.paths.executor_uid),
                "dynamic_host_cache_unavailable",
            )?;
            if sha256_hex(&packet) != cached.packet_sha256 {
                aggregate.zeroize();
                return Err(HostEnvelopeError::new("dynamic_host_cache_tampered"));
            }
            let opened = self.open_dynamic_packet_with_expiry(&packet, now, true)?;
            self.resolve_dynamic_policy(&opened.binding)?;
            validate_dynamic_value(opened.value.expose_bytes())?;
            if cached_dynamic_binding(&opened.binding, &opened.packet_sha256) != *cached {
                aggregate.zeroize();
                return Err(HostEnvelopeError::new("dynamic_host_cache_mismatch"));
            }
            aggregate.extend_from_slice(cached.environment_name.as_bytes());
            aggregate.push(b'=');
            aggregate.extend_from_slice(opened.value.expose_bytes());
            aggregate.push(b'\n');
            if aggregate.len() > MAX_DYNAMIC_AGGREGATE_BYTES {
                aggregate.zeroize();
                return Err(HostEnvelopeError::new("dynamic_host_environment_oversized"));
            }
        }
        Ok(aggregate)
    }

    fn open_dynamic_packet_with_expiry(
        &self,
        raw_packet: &[u8],
        now: SystemTime,
        allow_expired: bool,
    ) -> HostResult<DecryptedDynamicHostEnvelope> {
        let packet: SignedDynamicHostEnvelopeV1 =
            decode_strict_json(raw_packet, "dynamic_host_envelope_packet_invalid")?;
        if packet.schema != DYNAMIC_ENVELOPE_SCHEMA
            || packet.schema_version != SCHEMA_VERSION
            || !valid_ref("key_", &packet.key_id)
        {
            return Err(HostEnvelopeError::new(
                "dynamic_host_envelope_packet_invalid",
            ));
        }
        let ciphertext = STANDARD_NO_PAD
            .decode(packet.ciphertext.as_bytes())
            .map_err(|_| HostEnvelopeError::new("dynamic_host_envelope_ciphertext_invalid"))?;
        if ciphertext.is_empty() || ciphertext.len() > MAX_CIPHERTEXT_BYTES {
            return Err(HostEnvelopeError::new(
                "dynamic_host_envelope_ciphertext_oversized",
            ));
        }
        let signature_bytes = STANDARD_NO_PAD
            .decode(packet.signature.as_bytes())
            .map_err(|_| HostEnvelopeError::new("dynamic_host_envelope_signature_invalid"))?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|_| HostEnvelopeError::new("dynamic_host_envelope_signature_invalid"))?;
        let key = self
            .keys
            .get(&packet.key_id)
            .ok_or_else(|| HostEnvelopeError::new("dynamic_host_envelope_signing_key_unknown"))?;
        key.verify(
            &dynamic_signature_message(&packet.key_id, &ciphertext),
            &signature,
        )
        .map_err(|_| HostEnvelopeError::new("dynamic_host_envelope_signature_invalid"))?;
        let mut plaintext =
            decrypt_with_identity(&ciphertext, &self.paths.identity, self.paths.executor_uid)?;
        let parsed = parse_dynamic_plaintext(&plaintext);
        plaintext.zeroize();
        let (binding, value) = parsed?;
        self.validate_dynamic_host_binding(&binding, now, allow_expired)?;
        Ok(DecryptedDynamicHostEnvelope {
            binding,
            value,
            packet_sha256: sha256_hex(raw_packet),
        })
    }

    fn validate_dynamic_host_binding(
        &self,
        binding: &DynamicHostEnvelopeBindingV1,
        now: SystemTime,
        allow_expired: bool,
    ) -> HostResult<()> {
        validate_dynamic_binding(binding)?;
        if binding.host_ref != self.config.host_ref
            || binding.revocation_epoch < self.config.minimum_revocation_epoch
            || self
                .config
                .revoked_envelope_refs
                .iter()
                .any(|reference| reference == &binding.envelope_ref)
        {
            return Err(HostEnvelopeError::new(
                "dynamic_host_envelope_binding_denied",
            ));
        }
        let now = unix_seconds(now)?;
        if binding.issued_at_unix_secs > now.saturating_add(CLOCK_SKEW.as_secs())
            || (!allow_expired && now >= binding.expires_at_unix_secs)
        {
            return Err(HostEnvelopeError::new("dynamic_host_envelope_expired"));
        }
        Ok(())
    }

    fn resolve_dynamic_policy(
        &self,
        binding: &DynamicHostEnvelopeBindingV1,
    ) -> HostResult<&HostDynamicEnvironmentPolicyV1> {
        if binding.operation_kind != "create" {
            return Err(HostEnvelopeError::new("dynamic_host_operation_denied"));
        }
        let policy = self
            .dynamic_policies
            .iter()
            .find(|policy| policy.service_ref == binding.service_ref)
            .ok_or_else(|| HostEnvelopeError::new("dynamic_host_policy_denied"))?;
        if policy.environment_policy_ref != binding.environment_policy_ref
            || policy.environment_policy_fingerprint != binding.environment_policy_fingerprint
            || policy.declaration_fingerprint != binding.declaration_fingerprint
            || policy.delivery_profile_ref != binding.delivery_profile_ref
            || policy.reload_profile_ref != binding.reload_profile_ref
            || policy.health_profile_ref != binding.health_profile_ref
            || !policy.allowed_sources.contains(&binding.source)
            || policy
                .additional_reserved_names
                .binary_search(&binding.environment_name)
                .is_ok()
        {
            return Err(HostEnvelopeError::new("dynamic_host_policy_drift"));
        }
        Ok(policy)
    }

    fn ensure_dynamic_service_dirs(
        &self,
        policy: &HostDynamicEnvironmentPolicyV1,
    ) -> HostResult<()> {
        ensure_private_dir(&self.paths.cache_root, self.paths.executor_uid)?;
        let dynamic_root = self.paths.cache_root.join(DYNAMIC_CACHE_DIR);
        ensure_private_dir(&dynamic_root, self.paths.executor_uid)?;
        ensure_private_dir(
            &dynamic_root.join(&policy.service_ref),
            self.paths.executor_uid,
        )
    }

    fn dynamic_service_cache_dir(&self, policy: &HostDynamicEnvironmentPolicyV1) -> PathBuf {
        self.paths
            .cache_root
            .join(DYNAMIC_CACHE_DIR)
            .join(&policy.service_ref)
    }

    fn dynamic_runtime_path(&self, policy: &HostDynamicEnvironmentPolicyV1) -> PathBuf {
        self.paths
            .runtime_root
            .join(&policy.service_ref)
            .join(DYNAMIC_RUNTIME_FILE)
    }

    #[cfg(test)]
    pub(super) fn test_move_dynamic_binding_to_pending(
        &self,
        service_ref: &str,
    ) -> HostResult<String> {
        let policy = self
            .dynamic_policies
            .iter()
            .find(|policy| policy.service_ref == service_ref)
            .ok_or_else(|| HostEnvelopeError::new("dynamic_host_policy_denied"))?;
        let service_dir = self.dynamic_service_cache_dir(policy);
        let mut state = load_dynamic_state(
            &service_dir.join("state.json"),
            &self.config.host_ref,
            policy,
            self.paths.executor_uid,
        )?;
        let binding = state
            .bindings
            .pop()
            .ok_or_else(|| HostEnvelopeError::new("dynamic_host_cache_state_invalid"))?;
        let binding_ref = binding.binding_ref.clone();
        state.pending = Some(binding);
        write_dynamic_state(
            &service_dir.join("state.json"),
            state,
            self.paths.executor_uid,
        )?;
        Ok(binding_ref)
    }
}

fn parse_dynamic_plaintext(raw: &[u8]) -> HostResult<(DynamicHostEnvelopeBindingV1, SecretValue)> {
    if raw.len() < 5 {
        return Err(HostEnvelopeError::new(
            "dynamic_host_envelope_plaintext_invalid",
        ));
    }
    let metadata_len = u32::from_be_bytes(
        raw[..4]
            .try_into()
            .map_err(|_| HostEnvelopeError::new("dynamic_host_envelope_plaintext_invalid"))?,
    ) as usize;
    if metadata_len == 0
        || metadata_len > MAX_PAYLOAD_METADATA_BYTES
        || 4 + metadata_len >= raw.len()
    {
        return Err(HostEnvelopeError::new(
            "dynamic_host_envelope_plaintext_invalid",
        ));
    }
    let binding = decode_strict_json(
        &raw[4..4 + metadata_len],
        "dynamic_host_envelope_metadata_invalid",
    )?;
    let value = &raw[4 + metadata_len..];
    validate_dynamic_value(value)?;
    Ok((binding, SecretValue::new(value.to_vec())))
}

fn validate_dynamic_value(value: &[u8]) -> HostResult<()> {
    if value.is_empty()
        || value.len() > MAX_DYNAMIC_VALUE_BYTES
        || std::str::from_utf8(value).is_err()
        || value
            .iter()
            .any(|byte| matches!(*byte, b'\0' | b'\r' | b'\n'))
    {
        return Err(HostEnvelopeError::new("dynamic_host_value_invalid"));
    }
    Ok(())
}

fn cached_dynamic_binding(
    binding: &DynamicHostEnvelopeBindingV1,
    packet_sha256: &str,
) -> CachedDynamicBindingV1 {
    CachedDynamicBindingV1 {
        envelope_ref: binding.envelope_ref.clone(),
        operation_ref: binding.operation_ref.clone(),
        source: binding.source.clone(),
        binding_ref: binding.binding_ref.clone(),
        secret_ref: binding.secret_ref.clone(),
        generation_ref: binding.generation_ref.clone(),
        environment_name: binding.environment_name.clone(),
        revocation_epoch: binding.revocation_epoch,
        expires_at_unix_secs: binding.expires_at_unix_secs,
        packet_sha256: packet_sha256.to_string(),
    }
}

fn validate_cached_dynamic_set(
    bindings: &[CachedDynamicBindingV1],
    maximum: u16,
) -> HostResult<()> {
    if bindings.len() > usize::from(maximum) {
        return Err(HostEnvelopeError::new("dynamic_host_cache_state_invalid"));
    }
    let mut names = BTreeSet::new();
    let mut binding_refs = BTreeSet::new();
    let mut secret_refs = BTreeSet::new();
    let mut generation_refs = BTreeSet::new();
    let mut operation_refs = BTreeSet::new();
    let mut envelope_refs = BTreeSet::new();
    let mut previous_name: Option<&str> = None;
    for binding in bindings {
        if !valid_cached_dynamic_binding(binding)
            || previous_name.is_some_and(|name| name >= binding.environment_name.as_str())
            || !names.insert(binding.environment_name.as_str())
            || !binding_refs.insert(binding.binding_ref.as_str())
            || !secret_refs.insert(binding.secret_ref.as_str())
            || !generation_refs.insert(binding.generation_ref.as_str())
            || !operation_refs.insert(binding.operation_ref.as_str())
            || !envelope_refs.insert(binding.envelope_ref.as_str())
        {
            return Err(HostEnvelopeError::new("dynamic_host_cache_state_invalid"));
        }
        previous_name = Some(binding.environment_name.as_str());
    }
    Ok(())
}

fn valid_cached_dynamic_binding(binding: &CachedDynamicBindingV1) -> bool {
    valid_ref("env_", &binding.envelope_ref)
        && valid_ref("op_", &binding.operation_ref)
        && matches!(binding.source.as_str(), "generated" | "import")
        && valid_ref("bind_", &binding.binding_ref)
        && valid_ref("sec_", &binding.secret_ref)
        && valid_ref("gen_", &binding.generation_ref)
        && ManagedEnvironmentName::new(binding.environment_name.clone()).is_ok()
        && binding.revocation_epoch > 0
        && binding.expires_at_unix_secs > 0
        && validate_state_hash(&binding.packet_sha256)
}

fn load_dynamic_state(
    path: &Path,
    host_ref: &str,
    policy: &HostDynamicEnvironmentPolicyV1,
    owner_uid: u32,
) -> HostResult<HostDynamicServiceStateV1> {
    let state = if entry_exists(path, "dynamic_host_cache_state_invalid")? {
        let raw = read_private_regular(
            path,
            MAX_CONFIG_BYTES,
            Some(owner_uid),
            "dynamic_host_cache_state_invalid",
        )?;
        let state: HostDynamicServiceStateV1 =
            decode_strict_json(&raw, "dynamic_host_cache_state_invalid")?;
        if state.integrity_hash != dynamic_state_integrity(&state)? {
            return Err(HostEnvelopeError::new("dynamic_host_cache_state_tampered"));
        }
        state
    } else {
        HostDynamicServiceStateV1 {
            schema: DYNAMIC_STATE_SCHEMA.to_string(),
            schema_version: DYNAMIC_SCHEMA_VERSION,
            host_ref: host_ref.to_string(),
            service_ref: policy.service_ref.clone(),
            environment_policy_ref: policy.environment_policy_ref.clone(),
            environment_policy_fingerprint: policy.environment_policy_fingerprint.clone(),
            declaration_fingerprint: policy.declaration_fingerprint.clone(),
            bindings: Vec::new(),
            pending: None,
            integrity_hash: String::new(),
        }
    };
    validate_dynamic_state(&state, host_ref, policy)?;
    Ok(state)
}

fn validate_dynamic_state(
    state: &HostDynamicServiceStateV1,
    host_ref: &str,
    policy: &HostDynamicEnvironmentPolicyV1,
) -> HostResult<()> {
    if state.schema != DYNAMIC_STATE_SCHEMA
        || state.schema_version != DYNAMIC_SCHEMA_VERSION
        || state.host_ref != host_ref
        || state.service_ref != policy.service_ref
        || state.environment_policy_ref != policy.environment_policy_ref
        || state.environment_policy_fingerprint != policy.environment_policy_fingerprint
        || state.declaration_fingerprint != policy.declaration_fingerprint
        || state.bindings.len() > usize::from(policy.max_active_bindings)
    {
        return Err(HostEnvelopeError::new("dynamic_host_cache_state_invalid"));
    }
    validate_cached_dynamic_set(&state.bindings, policy.max_active_bindings)?;
    if let Some(pending) = &state.pending {
        if !valid_cached_dynamic_binding(pending)
            || state.bindings.len() >= usize::from(policy.max_active_bindings)
            || state.bindings.iter().any(|current| {
                current.environment_name == pending.environment_name
                    || current.binding_ref == pending.binding_ref
                    || current.secret_ref == pending.secret_ref
                    || current.generation_ref == pending.generation_ref
                    || current.operation_ref == pending.operation_ref
                    || current.envelope_ref == pending.envelope_ref
            })
        {
            return Err(HostEnvelopeError::new("dynamic_host_cache_state_invalid"));
        }
    }
    Ok(())
}

fn write_dynamic_state(
    path: &Path,
    mut state: HostDynamicServiceStateV1,
    owner_uid: u32,
) -> HostResult<()> {
    state.integrity_hash.clear();
    state.integrity_hash = dynamic_state_integrity(&state)?;
    let raw = serde_json::to_vec(&state)
        .map_err(|_| HostEnvelopeError::new("dynamic_host_cache_state_invalid"))?;
    atomic_write(
        path,
        &raw,
        0o600,
        owner_uid,
        "dynamic_host_cache_state_write_failed",
    )
}

fn dynamic_state_integrity(state: &HostDynamicServiceStateV1) -> HostResult<String> {
    let mut unsigned = state.clone();
    unsigned.integrity_hash.clear();
    let raw = serde_json::to_vec(&unsigned)
        .map_err(|_| HostEnvelopeError::new("dynamic_host_cache_state_invalid"))?;
    Ok(sha256_hex(&raw))
}

fn validate_dynamic_inventory(
    service_dir: &Path,
    state: &HostDynamicServiceStateV1,
    owner_uid: u32,
) -> HostResult<()> {
    let mut expected = state
        .bindings
        .iter()
        .map(|binding| format!("{}.envelope", binding.binding_ref))
        .collect::<BTreeSet<_>>();
    if let Some(pending) = &state.pending {
        let name = format!("{}.envelope", pending.binding_ref);
        if entry_exists(&service_dir.join(&name), "dynamic_host_cache_unavailable")? {
            expected.insert(name);
        }
    }
    let mut found = BTreeSet::new();
    for entry in fs::read_dir(service_dir)
        .map_err(|_| HostEnvelopeError::new("dynamic_host_cache_unavailable"))?
    {
        let entry = entry.map_err(|_| HostEnvelopeError::new("dynamic_host_cache_unavailable"))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| HostEnvelopeError::new("dynamic_host_cache_unsafe_entry"))?;
        if name.ends_with(".tmp") {
            return Err(HostEnvelopeError::new("dynamic_host_cache_partial_file"));
        }
        if matches!(name.as_str(), ".lock" | "state.json") {
            validate_private_regular_metadata(
                &entry.path(),
                owner_uid,
                "dynamic_host_cache_unsafe_entry",
            )?;
            continue;
        }
        let Some(binding_ref) = name.strip_suffix(".envelope") else {
            return Err(HostEnvelopeError::new("dynamic_host_cache_unsafe_entry"));
        };
        if !valid_ref("bind_", binding_ref) || !expected.contains(&name) || !found.insert(name) {
            return Err(HostEnvelopeError::new("dynamic_host_cache_unsafe_entry"));
        }
        validate_private_regular_metadata(
            &entry.path(),
            owner_uid,
            "dynamic_host_cache_unsafe_entry",
        )?;
    }
    if found != expected {
        return Err(HostEnvelopeError::new(
            "dynamic_host_cache_inventory_mismatch",
        ));
    }
    Ok(())
}

fn dynamic_packet_path(service_dir: &Path, binding_ref: &str) -> PathBuf {
    service_dir.join(format!("{binding_ref}.envelope"))
}

fn atomic_create_private(
    path: &Path,
    bytes: &[u8],
    owner_uid: u32,
    reason: &'static str,
) -> HostResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| HostEnvelopeError::new(reason))?;
    ensure_private_dir(parent, owner_uid)?;
    if entry_exists(path, reason)? {
        return Err(HostEnvelopeError::new(reason));
    }
    let temporary = parent.join(format!(
        ".janus-host-create-{}.{}.tmp",
        std::process::id(),
        monotonic_nonce()?
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|_| HostEnvelopeError::new(reason))?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| HostEnvelopeError::new(reason))?;
        if file
            .metadata()
            .map_err(|_| HostEnvelopeError::new(reason))?
            .uid()
            != owner_uid
        {
            fchown(&file, Some(Uid::from_raw(owner_uid)), None)
                .map_err(|_| HostEnvelopeError::new(reason))?;
        }
        file.write_all(bytes)
            .map_err(|_| HostEnvelopeError::new(reason))?;
        file.sync_all()
            .map_err(|_| HostEnvelopeError::new(reason))?;
        drop(file);
        fs::hard_link(&temporary, path).map_err(|_| HostEnvelopeError::new(reason))?;
        fs::remove_file(&temporary).map_err(|_| HostEnvelopeError::new(reason))?;
        let metadata = validate_private_regular_metadata(path, owner_uid, reason)?;
        if metadata.mode() & 0o777 != 0o600 {
            return Err(HostEnvelopeError::new(reason));
        }
        sync_dir(parent, reason)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn dynamic_outcome(
    action: &str,
    host_ref: &str,
    policy: &HostDynamicEnvironmentPolicyV1,
    binding: Option<&CachedDynamicBindingV1>,
    binding_count: usize,
    phase: &str,
    reason_code: &str,
) -> DynamicHostExecutorOutcome {
    DynamicHostExecutorOutcome {
        action: action.to_string(),
        host_ref: host_ref.to_string(),
        service_ref: policy.service_ref.clone(),
        environment_policy_ref: policy.environment_policy_ref.clone(),
        binding_ref: binding.map(|value| value.binding_ref.clone()),
        operation_ref: binding.map(|value| value.operation_ref.clone()),
        generation_ref: binding.map(|value| value.generation_ref.clone()),
        binding_count: u16::try_from(binding_count).unwrap_or(u16::MAX),
        phase: phase.to_string(),
        reason_code: reason_code.to_string(),
        value_returned: false,
    }
}
