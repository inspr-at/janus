package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const managedDynamicTestNow = int64(1_785_916_800)

func managedDynamicTestIntent() managedDynamicSetupIntent {
	return managedDynamicSetupIntent{
		Schema:                       managedDynamicSetupIntentSchema,
		SchemaVersion:                managedDynamicContractVersion,
		IntentRef:                    "intent_0f92b78c3d16",
		OperationKind:                "create",
		Source:                       "import",
		HostRef:                      "host_7f94a1c8e912",
		ServiceRef:                   "svc_24b7c8f0aa19",
		EnvironmentPolicyRef:         "envpol_41e6720bc591",
		EnvironmentPolicyFingerprint: "envpf_3f8d9a061c42",
		DeclarationFingerprint:       "decl_51268e2b772a",
		EnvironmentName:              "HOME_ASSISTANT_TOKEN",
		HumanSessionRef:              "hsn_489e126a70bf",
		IssuerRef:                    managedSetupExpectedIssuerRef,
		AudienceRef:                  managedSetupExpectedAudienceRef,
		NonceRef:                     "nonce_a280fd61b9ce",
		IssuedAtUnixSeconds:          managedDynamicTestNow,
		ExpiresAtUnixSeconds:         managedDynamicTestNow + 300,
		ReturnTarget:                 "pharos_service",
	}
}

func signManagedDynamicTestIntent(t *testing.T, intent managedDynamicSetupIntent) (managedSignedIntent, ed25519.PublicKey) {
	t.Helper()
	payload, err := encodeManagedCanonicalJSON(intent)
	if err != nil {
		t.Fatal(err)
	}
	return signManagedDynamicRaw(t, payload)
}

func signManagedDynamicRaw(t *testing.T, payload []byte) (managedSignedIntent, ed25519.PublicKey) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index + 17)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	keyID := "key_dynamic0001"
	signature := ed25519.Sign(privateKey, managedIntentSignatureMessageForDomain(
		managedDynamicIntentSignatureDomain,
		keyID,
		payload,
	))
	return managedSignedIntent{
		Schema:             managedDynamicSignedIntentSchema,
		SchemaVersion:      managedDynamicContractVersion,
		KeyID:              keyID,
		PayloadBase64URL:   base64.RawURLEncoding.EncodeToString(payload),
		SignatureBase64URL: base64.RawURLEncoding.EncodeToString(signature),
	}, publicKey
}

func managedDynamicFixtureDeclaration(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "contracts", "managed-service-dynamic-env-contract-v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Schema        string          `json:"schema"`
		SchemaVersion int             `json:"schema_version"`
		Declaration   json.RawMessage `json:"declaration"`
		Binding       json.RawMessage `json:"binding"`
	}
	if err := decodeStrictJSON(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Schema != "inspr.janus.managed-dynamic-env-contract-fixture.v2" ||
		fixture.SchemaVersion != managedDynamicContractVersion {
		t.Fatalf("unexpected fixture contract: %#v", fixture)
	}
	return fixture.Declaration
}

func managedDynamicFixtureIntent(t *testing.T) managedDynamicSetupIntent {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "contracts", "managed-dynamic-env-setup-intent-v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Schema        string                    `json:"schema"`
		SchemaVersion int                       `json:"schema_version"`
		Intent        managedDynamicSetupIntent `json:"intent"`
	}
	if err := decodeStrictJSON(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Schema != "inspr.janus.managed-environment-setup-intent-fixture.v2" ||
		fixture.SchemaVersion != managedDynamicContractVersion ||
		validateManagedDynamicSetupIntent(fixture.Intent) != nil {
		t.Fatalf("unexpected dynamic setup fixture: %#v", fixture)
	}
	return fixture.Intent
}

func managedDynamicTestResolver(t *testing.T, declaration []byte) managedDynamicDeclarationResolver {
	t.Helper()
	path := filepath.Join(t.TempDir(), "declaration.json")
	if err := os.WriteFile(path, declaration, 0600); err != nil {
		t.Fatal(err)
	}
	return managedDynamicDeclarationResolver{paths: []string{path}}
}

func TestManagedDynamicIntentAcceptsCanonicalV2FixturePolicy(t *testing.T) {
	intent := managedDynamicFixtureIntent(t)
	envelope, publicKey := signManagedDynamicTestIntent(t, intent)
	consumer := managedDynamicSetupIntentConsumer{
		keyring:     managedIntentKeyring{"key_dynamic0001": publicKey},
		declaration: managedDynamicTestResolver(t, managedDynamicFixtureDeclaration(t)),
		issuerRef:   managedSetupExpectedIssuerRef,
		audienceRef: managedSetupExpectedAudienceRef,
		now:         func() time.Time { return time.Unix(managedDynamicTestNow+1, 0) },
	}

	inspection, err := consumer.Inspect(envelope, intent.IntentRef, intent.HumanSessionRef)
	if err != nil {
		t.Fatal(err)
	}
	if inspection.Intent.EnvironmentName != "HOME_ASSISTANT_TOKEN" ||
		inspection.Context.EnvironmentPolicyRef != "envpol_41e6720bc591" ||
		inspection.Context.DeliveryProfileRef != "delivery_2ed71ad75c98" ||
		inspection.Context.ReloadProfileRef != "reload_5e776ec5d9a1" ||
		inspection.Context.HealthProfileRef != "health_84c12f390b2a" ||
		inspection.Context.MaxActiveBindings != 32 {
		t.Fatalf("fixture policy was not preserved: %#v", inspection)
	}
}

func TestManagedDynamicIntentFixtureIsValueFree(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "contracts", "managed-dynamic-env-setup-intent-v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"secret_value", "ciphertext", "private_path", "command", "callback_url", "permit",
	} {
		if strings.Contains(string(raw), `"`+forbidden+`"`) {
			t.Fatalf("canonical signed-handoff payload contains forbidden field %q", forbidden)
		}
	}
}

func TestManagedDynamicIntentRejectsSecretAndCallerShapedAuthorityFields(t *testing.T) {
	base, err := json.Marshal(managedDynamicTestIntent())
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(base, &document); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		"secret_value", "ciphertext", "path", "command", "callback_url",
		"delivery_profile_ref", "reload_profile_ref", "health_profile_ref", "slot_ref",
	} {
		t.Run(field, func(t *testing.T) {
			candidate := make(map[string]any, len(document)+1)
			for key, value := range document {
				candidate[key] = value
			}
			candidate[field] = "caller-controlled"
			payload, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			envelope, publicKey := signManagedDynamicRaw(t, payload)
			if _, err := verifyManagedDynamicSetupIntent(
				envelope,
				managedIntentKeyring{"key_dynamic0001": publicKey},
			); err == nil || err.Error() != "managed_intent_payload_invalid" {
				t.Fatalf("field %q crossed the value-free boundary: %v", field, err)
			}
		})
	}
}

func TestManagedDynamicSignedEnvelopeIsStrictAndBounded(t *testing.T) {
	envelope, _ := signManagedDynamicTestIntent(t, managedDynamicTestIntent())
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeManagedDynamicSignedIntent(raw); err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	document["callback_url"] = "https://caller.example.test"
	unknownField, _ := json.Marshal(document)
	if _, err := decodeManagedDynamicSignedIntent(unknownField); err == nil ||
		err.Error() != "managed_intent_envelope_invalid" {
		t.Fatalf("unknown outer field was admitted: %v", err)
	}
	if _, err := decodeManagedDynamicSignedIntent(make([]byte, managedIntentMaxEnvelopeBytes+1)); err == nil ||
		err.Error() != "managed_intent_envelope_invalid" {
		t.Fatalf("oversized envelope was admitted: %v", err)
	}
}

func TestManagedDynamicIntentRejectsPolicyDriftBeforeValueAdmission(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(*managedDynamicSetupIntent)
	}{
		{"host", func(intent *managedDynamicSetupIntent) { intent.HostRef = "host_aaaaaaaaaaaa" }},
		{"service", func(intent *managedDynamicSetupIntent) { intent.ServiceRef = "svc_aaaaaaaaaaaa" }},
		{"declaration fingerprint", func(intent *managedDynamicSetupIntent) { intent.DeclarationFingerprint = "decl_aaaaaaaaaaaa" }},
		{"policy ref", func(intent *managedDynamicSetupIntent) { intent.EnvironmentPolicyRef = "envpol_aaaaaaaaaaaa" }},
		{"policy fingerprint", func(intent *managedDynamicSetupIntent) { intent.EnvironmentPolicyFingerprint = "envpf_aaaaaaaaaaaa" }},
		{"source", func(intent *managedDynamicSetupIntent) { intent.Source = "generated" }},
		{"service reserved name", func(intent *managedDynamicSetupIntent) { intent.EnvironmentName = "DATABASE_URL" }},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			intent := managedDynamicTestIntent()
			test.mutate(&intent)
			declaration := managedDynamicFixtureDeclaration(t)
			if test.name == "source" {
				var declarationDocument map[string]any
				if err := json.Unmarshal(declaration, &declarationDocument); err != nil {
					t.Fatal(err)
				}
				policy := declarationDocument["dynamic_environment_policy"].(map[string]any)
				policy["allowed_sources"] = []any{"import"}
				declaration, _ = json.Marshal(declarationDocument)
			}
			envelope, publicKey := signManagedDynamicTestIntent(t, intent)
			consumer := managedDynamicSetupIntentConsumer{
				keyring:     managedIntentKeyring{"key_dynamic0001": publicKey},
				declaration: managedDynamicTestResolver(t, declaration),
				issuerRef:   managedSetupExpectedIssuerRef,
				audienceRef: managedSetupExpectedAudienceRef,
				now:         func() time.Time { return time.Unix(managedDynamicTestNow+1, 0) },
			}
			if _, err := consumer.Inspect(envelope, intent.IntentRef, intent.HumanSessionRef); err == nil ||
				err.Error() != "managed_intent_declaration_drift" {
				t.Fatalf("%s drift was admitted: %v", test.name, err)
			}
		})
	}
}

func TestManagedDynamicIntentPayloadPolicyIsClosed(t *testing.T) {
	validReplace := managedDynamicTestIntent()
	validReplace.OperationKind = "replace"
	if err := validateManagedDynamicSetupIntent(validReplace); err != nil {
		t.Fatalf("reviewed replace action was rejected: %v", err)
	}
	validRemove := managedDynamicTestIntent()
	validRemove.OperationKind = "remove"
	validRemove.Source = "remove"
	validRemove.BindingRef = "bind_fixture0001"
	validRemove.SecretRef = "sec_fixture0001"
	validRemove.GenerationRef = "gen_fixture0001"
	if err := validateManagedDynamicSetupIntent(validRemove); err != nil {
		t.Fatalf("exact value-free removal was rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*managedDynamicSetupIntent)
	}{
		{"remove action", func(intent *managedDynamicSetupIntent) { intent.OperationKind = "remove" }},
		{"remove source", func(intent *managedDynamicSetupIntent) { intent.Source = "remove" }},
		{"caller return", func(intent *managedDynamicSetupIntent) { intent.ReturnTarget = "https://caller.example.test" }},
		{"overlong lifetime", func(intent *managedDynamicSetupIntent) {
			intent.ExpiresAtUnixSeconds = intent.IssuedAtUnixSeconds + managedIntentMaxTTLSeconds + 1
		}},
		{"zero lifetime", func(intent *managedDynamicSetupIntent) { intent.ExpiresAtUnixSeconds = intent.IssuedAtUnixSeconds }},
		{"reserved name", func(intent *managedDynamicSetupIntent) { intent.EnvironmentName = "PATH" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			intent := managedDynamicTestIntent()
			test.mutate(&intent)
			if err := validateManagedDynamicSetupIntent(intent); err == nil {
				t.Fatal("invalid dynamic intent payload was admitted")
			}
		})
	}
}

func TestManagedDynamicIntentRejectsUnsafeNamesWithoutNormalization(t *testing.T) {
	for _, name := range []string{
		"", "home_assistant_token", "Home_ASSISTANT_TOKEN", " HOME_ASSISTANT_TOKEN",
		"HOME-ASSISTANT-TOKEN", "HÖME_ASSISTANT_TOKEN", "PATH", "LD_PRELOAD",
		"GIT_CONFIG_COUNT", "JANUS_TOKEN", strings.Repeat("A", 129),
	} {
		if validManagedEnvironmentName(name) {
			t.Errorf("unsafe or normalized name %q was admitted", name)
		}
	}
	for _, name := range []string{"A", "HOME_ASSISTANT_TOKEN", "TOKEN_2"} {
		if !validManagedEnvironmentName(name) {
			t.Errorf("portable name %q was rejected", name)
		}
	}
}

func TestManagedDynamicIntentFailsClosedOnIdentityTimeSignatureAndVersion(t *testing.T) {
	base := managedDynamicTestIntent()
	tests := []struct {
		name       string
		mutate     func(*managedDynamicSetupIntent)
		requestRef string
		humanRef   string
		now        int64
		want       string
	}{
		{"wrong user", nil, "", "hsn_someone_else0", managedDynamicTestNow + 1, "managed_intent_wrong_user"},
		{"wrong issuer", func(intent *managedDynamicSetupIntent) { intent.IssuerRef = "sys_another_issuer000" }, "", "", managedDynamicTestNow + 1, "managed_intent_wrong_issuer"},
		{"wrong audience", func(intent *managedDynamicSetupIntent) { intent.AudienceRef = "sys_another_audience0" }, "", "", managedDynamicTestNow + 1, "managed_intent_wrong_audience"},
		{"reference mismatch", nil, "intent_different0001", "", managedDynamicTestNow + 1, "managed_intent_reference_mismatch"},
		{"expired", nil, "", "", managedDynamicTestNow + 300, "managed_intent_expired"},
		{"future", func(intent *managedDynamicSetupIntent) {
			intent.IssuedAtUnixSeconds += 60
			intent.ExpiresAtUnixSeconds += 60
		}, "", "", managedDynamicTestNow, "managed_intent_not_yet_valid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			intent := base
			if test.mutate != nil {
				test.mutate(&intent)
			}
			envelope, publicKey := signManagedDynamicTestIntent(t, intent)
			consumer := managedDynamicSetupIntentConsumer{
				keyring:     managedIntentKeyring{"key_dynamic0001": publicKey},
				declaration: managedDynamicTestResolver(t, managedDynamicFixtureDeclaration(t)),
				issuerRef:   managedSetupExpectedIssuerRef,
				audienceRef: managedSetupExpectedAudienceRef,
				now:         func() time.Time { return time.Unix(test.now, 0) },
			}
			requestRef := test.requestRef
			if requestRef == "" {
				requestRef = intent.IntentRef
			}
			humanRef := test.humanRef
			if humanRef == "" {
				humanRef = intent.HumanSessionRef
			}
			if _, err := consumer.Inspect(envelope, requestRef, humanRef); err == nil || err.Error() != test.want {
				t.Fatalf("got %v, want %s", err, test.want)
			}
		})
	}

	envelope, publicKey := signManagedDynamicTestIntent(t, base)
	tampered := envelope
	payload, _ := base64.RawURLEncoding.DecodeString(tampered.PayloadBase64URL)
	payload[len(payload)/2] ^= 1
	tampered.PayloadBase64URL = base64.RawURLEncoding.EncodeToString(payload)
	if _, err := verifyManagedDynamicSetupIntent(tampered, managedIntentKeyring{"key_dynamic0001": publicKey}); err == nil || err.Error() != "managed_intent_signature_invalid" {
		t.Fatalf("tampered signature was admitted: %v", err)
	}
	wrongVersion := envelope
	wrongVersion.SchemaVersion = 1
	if _, err := verifyManagedDynamicSetupIntent(wrongVersion, managedIntentKeyring{"key_dynamic0001": publicKey}); err == nil || err.Error() != "managed_intent_version_unsupported" {
		t.Fatalf("wrong version was admitted: %v", err)
	}
}

func TestManagedDynamicResolverRejectsMissingPolicyAndInvalidDeclarations(t *testing.T) {
	fixture := managedDynamicFixtureDeclaration(t)
	var declaration map[string]any
	if err := json.Unmarshal(fixture, &declaration); err != nil {
		t.Fatal(err)
	}

	withoutPolicy := make(map[string]any, len(declaration))
	for key, value := range declaration {
		withoutPolicy[key] = value
	}
	withoutPolicy["dynamic_environment_policy"] = nil
	rawWithoutPolicy, _ := json.Marshal(withoutPolicy)
	if _, err := managedDynamicTestResolver(t, rawWithoutPolicy).Resolve(managedDynamicTestIntent()); err == nil || err.Error() != "managed_intent_declaration_drift" {
		t.Fatalf("missing policy should disable dynamic ingress: %v", err)
	}

	for _, mutate := range []func(map[string]any){
		func(candidate map[string]any) { candidate["command"] = "restart everything" },
		func(candidate map[string]any) { candidate["schema_version"] = float64(3) },
		func(candidate map[string]any) {
			candidate["dynamic_environment_policy"].(map[string]any)["max_active_bindings"] = float64(65)
		},
		func(candidate map[string]any) {
			candidate["dynamic_environment_policy"].(map[string]any)["additional_reserved_names"] = []any{"DATABASE_URL", "DATABASE_URL"}
		},
		func(candidate map[string]any) { candidate["slots"] = nil },
		func(candidate map[string]any) {
			candidate["dynamic_environment_policy"].(map[string]any)["additional_reserved_names"] = nil
		},
	} {
		candidate := map[string]any{}
		if err := json.Unmarshal(fixture, &candidate); err != nil {
			t.Fatal(err)
		}
		mutate(candidate)
		raw, _ := json.Marshal(candidate)
		if _, err := managedDynamicTestResolver(t, raw).Resolve(managedDynamicTestIntent()); err == nil || err.Error() != "managed_intent_declaration_unavailable" {
			t.Fatalf("invalid root-owned declaration was admitted: %v", err)
		}
	}
}
