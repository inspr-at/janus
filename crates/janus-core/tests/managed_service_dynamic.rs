use janus_core::{
    parse_managed_dynamic_environment_contract_fixture, parse_managed_service_contract_fixture,
    ManagedEnvironmentBindingState, ManagedEnvironmentBindingV2, ManagedEnvironmentName,
    ManagedEnvironmentNamePolicy, ManagedSecretSource, ManagedServiceDeclarationV2,
    MAX_MANAGED_DYNAMIC_BINDINGS, MAX_MANAGED_RESERVED_ENV_NAMES,
    MAX_MANAGED_SERVICE_CONTRACT_BYTES,
};

const FIXTURE: &str =
    include_str!("../../../contracts/managed-service-dynamic-env-contract-v2.json");
const V1_FIXTURE: &str = include_str!("../../../contracts/managed-service-secret-contract-v1.json");

fn fixture_value() -> serde_json::Value {
    serde_json::from_str(FIXTURE).expect("checked fixture")
}

#[test]
fn canonical_fixture_parses_cross_checks_and_round_trips() {
    let (declaration, binding) =
        parse_managed_dynamic_environment_contract_fixture(FIXTURE).unwrap();
    let policy = declaration.dynamic_environment_policy().unwrap();

    assert_eq!(declaration.slots().len(), 1);
    assert_eq!(policy.max_active_bindings(), 32);
    assert_eq!(
        policy.name_policy(),
        ManagedEnvironmentNamePolicy::PortableSecretEnvV1
    );
    assert_eq!(
        policy.allowed_sources(),
        &[ManagedSecretSource::Generated, ManagedSecretSource::Import]
    );
    assert_eq!(binding.environment_name().as_str(), "HOME_ASSISTANT_TOKEN");
    assert_eq!(binding.state(), ManagedEnvironmentBindingState::Active);
    binding.validate_against(&declaration).unwrap();

    assert_eq!(
        ManagedServiceDeclarationV2::parse_json(&declaration.to_json().unwrap()).unwrap(),
        declaration
    );
    assert_eq!(
        ManagedEnvironmentBindingV2::parse_json(&binding.to_json().unwrap()).unwrap(),
        binding
    );
    parse_managed_service_contract_fixture(V1_FIXTURE).unwrap();
}

#[test]
fn documents_are_strict_bounded_and_versioned() {
    let mut fixture = fixture_value();
    fixture["extra"] = serde_json::json!(true);
    assert!(parse_managed_dynamic_environment_contract_fixture(&fixture.to_string()).is_err());

    for version in [0, 1, 3] {
        let mut fixture = fixture_value();
        fixture["schema_version"] = serde_json::json!(version);
        assert!(parse_managed_dynamic_environment_contract_fixture(&fixture.to_string()).is_err());
    }

    let mut declaration = fixture_value()["declaration"].clone();
    declaration["extra"] = serde_json::json!(true);
    assert!(ManagedServiceDeclarationV2::parse_json(&declaration.to_string()).is_err());

    let mut binding = fixture_value()["binding"].clone();
    binding["ciphertext"] = serde_json::json!("not-even-ciphertext");
    assert!(ManagedEnvironmentBindingV2::parse_json(&binding.to_string()).is_err());

    assert!(ManagedServiceDeclarationV2::parse_json("").is_err());
    assert!(ManagedEnvironmentBindingV2::parse_json("").is_err());
    assert!(parse_managed_dynamic_environment_contract_fixture("").is_err());
    let oversized = " ".repeat(MAX_MANAGED_SERVICE_CONTRACT_BYTES + 1);
    assert!(ManagedServiceDeclarationV2::parse_json(&oversized).is_err());
    assert!(ManagedEnvironmentBindingV2::parse_json(&oversized).is_err());
    assert!(parse_managed_dynamic_environment_contract_fixture(&oversized).is_err());
}

#[test]
fn declaration_requires_a_capability_and_policy_is_optional() {
    let mut declaration = fixture_value()["declaration"].clone();
    declaration["dynamic_environment_policy"] = serde_json::Value::Null;
    assert!(
        ManagedServiceDeclarationV2::parse_json(&declaration.to_string())
            .unwrap()
            .dynamic_environment_policy()
            .is_none()
    );

    declaration["slots"] = serde_json::json!([]);
    assert!(ManagedServiceDeclarationV2::parse_json(&declaration.to_string()).is_err());

    let mut declaration = fixture_value()["declaration"].clone();
    declaration["slots"] = serde_json::json!([]);
    assert!(
        ManagedServiceDeclarationV2::parse_json(&declaration.to_string())
            .unwrap()
            .dynamic_environment_policy()
            .is_some()
    );
}

#[test]
fn policy_rejects_invalid_capacity_duplicates_and_reserved_names() {
    for capacity in [0, MAX_MANAGED_DYNAMIC_BINDINGS + 1] {
        let mut declaration = fixture_value()["declaration"].clone();
        declaration["dynamic_environment_policy"]["max_active_bindings"] =
            serde_json::json!(capacity);
        assert!(ManagedServiceDeclarationV2::parse_json(&declaration.to_string()).is_err());
    }

    let mut declaration = fixture_value()["declaration"].clone();
    declaration["dynamic_environment_policy"]["allowed_sources"] =
        serde_json::json!(["import", "import"]);
    assert!(ManagedServiceDeclarationV2::parse_json(&declaration.to_string()).is_err());

    let mut declaration = fixture_value()["declaration"].clone();
    declaration["dynamic_environment_policy"]["additional_reserved_names"] =
        serde_json::json!(["DATABASE_URL", "DATABASE_URL"]);
    assert!(ManagedServiceDeclarationV2::parse_json(&declaration.to_string()).is_err());

    let mut declaration = fixture_value()["declaration"].clone();
    declaration["dynamic_environment_policy"]["additional_reserved_names"] =
        serde_json::Value::Array(
            (0..=MAX_MANAGED_RESERVED_ENV_NAMES)
                .map(|index| serde_json::json!(format!("SERVICE_SECRET_{index}")))
                .collect(),
        );
    assert!(ManagedServiceDeclarationV2::parse_json(&declaration.to_string()).is_err());
}

#[test]
fn environment_names_are_exact_portable_and_fail_closed() {
    for valid in [
        "A",
        "A_",
        "SERVICE_TOKEN_2",
        &format!("A{}", "B".repeat(127)),
    ] {
        assert_eq!(ManagedEnvironmentName::new(valid).unwrap().as_str(), valid);
    }

    for invalid in [
        "",
        "2TOKEN",
        "lowercase",
        "Mixed_CASE",
        "HAS-DASH",
        "HAS SPACE",
        "PATH",
        "HOME",
        "NODE_OPTIONS",
        "PYTHONPATH",
        "GIT_CONFIG_COUNT",
        "JANUS_TOKEN",
        "LD_PRELOAD",
        "DYLD_INSERT_LIBRARIES",
        "NIX_PATH",
        &format!("A{}", "B".repeat(128)),
    ] {
        assert!(ManagedEnvironmentName::new(invalid).is_err(), "{invalid}");
    }
}

#[test]
fn policy_serialization_is_canonical_without_renaming_environment_names() {
    let mut declaration = fixture_value()["declaration"].clone();
    declaration["dynamic_environment_policy"]["allowed_sources"] =
        serde_json::json!(["import", "generated"]);
    declaration["dynamic_environment_policy"]["additional_reserved_names"] =
        serde_json::json!(["TRUSTED_PROXIES", "DATABASE_URL"]);
    let declaration = ManagedServiceDeclarationV2::parse_json(&declaration.to_string()).unwrap();
    let serialized: serde_json::Value =
        serde_json::from_str(&declaration.to_json().unwrap()).unwrap();

    assert_eq!(
        serialized["dynamic_environment_policy"]["allowed_sources"],
        serde_json::json!(["generated", "import"])
    );
    assert_eq!(
        serialized["dynamic_environment_policy"]["additional_reserved_names"],
        serde_json::json!(["DATABASE_URL", "TRUSTED_PROXIES"])
    );
    assert!(ManagedEnvironmentName::new("service_token").is_err());
}

#[test]
fn binding_must_match_policy_source_name_and_fingerprints() {
    for (field, value) in [
        ("host_ref", "host_aaaaaaaaaaaa"),
        ("service_ref", "svc_aaaaaaaaaaaa"),
        ("environment_policy_ref", "envpol_aaaaaaaaaaaa"),
        ("environment_policy_fingerprint", "envpf_aaaaaaaaaaaa"),
        ("declaration_fingerprint", "decl_aaaaaaaaaaaa"),
    ] {
        let mut fixture = fixture_value();
        fixture["binding"][field] = serde_json::json!(value);
        assert!(parse_managed_dynamic_environment_contract_fixture(&fixture.to_string()).is_err());
    }

    let mut fixture = fixture_value();
    fixture["declaration"]["dynamic_environment_policy"]["allowed_sources"] =
        serde_json::json!(["generated"]);
    assert!(parse_managed_dynamic_environment_contract_fixture(&fixture.to_string()).is_err());

    let mut fixture = fixture_value();
    fixture["binding"]["environment_name"] = serde_json::json!("DATABASE_URL");
    assert!(parse_managed_dynamic_environment_contract_fixture(&fixture.to_string()).is_err());

    let mut fixture = fixture_value();
    fixture["declaration"]["dynamic_environment_policy"] = serde_json::Value::Null;
    assert!(parse_managed_dynamic_environment_contract_fixture(&fixture.to_string()).is_err());
}

#[test]
fn binding_lifecycle_timestamps_and_value_flag_are_strict() {
    let mut binding = fixture_value()["binding"].clone();
    binding["value_returned"] = serde_json::json!(true);
    assert!(ManagedEnvironmentBindingV2::parse_json(&binding.to_string()).is_err());

    let mut binding = fixture_value()["binding"].clone();
    binding["created_at_unix_secs"] = serde_json::json!(0);
    assert!(ManagedEnvironmentBindingV2::parse_json(&binding.to_string()).is_err());

    let mut binding = fixture_value()["binding"].clone();
    binding["updated_at_unix_secs"] = serde_json::json!(1);
    assert!(ManagedEnvironmentBindingV2::parse_json(&binding.to_string()).is_err());

    let mut binding = fixture_value()["binding"].clone();
    binding["retired_at_unix_secs"] = serde_json::json!(1785916801_u64);
    assert!(ManagedEnvironmentBindingV2::parse_json(&binding.to_string()).is_err());

    let mut binding = fixture_value()["binding"].clone();
    binding["state"] = serde_json::json!("detached");
    assert!(ManagedEnvironmentBindingV2::parse_json(&binding.to_string()).is_err());

    binding["retired_at_unix_secs"] = serde_json::json!(1785916801_u64);
    assert!(ManagedEnvironmentBindingV2::parse_json(&binding.to_string()).is_ok());
}

#[test]
fn canonical_contract_contains_no_secret_or_execution_fields() {
    fn inspect(value: &serde_json::Value) {
        match value {
            serde_json::Value::Object(object) => {
                for (key, value) in object {
                    assert!(!matches!(
                        key.as_str(),
                        "value"
                            | "secret_value"
                            | "ciphertext"
                            | "path"
                            | "command"
                            | "callback_url"
                            | "permit"
                            | "request_body"
                    ));
                    inspect(value);
                }
            }
            serde_json::Value::Array(values) => values.iter().for_each(inspect),
            _ => {}
        }
    }
    inspect(&fixture_value());
}
