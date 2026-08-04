package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func clearManagedDynamicSetupEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		managedDynamicSetupEnabledEnv,
		managedDynamicSetupOriginEnv,
		managedDynamicSetupTokenFileEnv,
		managedDynamicSetupKeyFileEnv,
		managedDynamicSetupPathsEnv,
	} {
		t.Setenv(name, "")
	}
}

func writeManagedDynamicSetupConfigFiles(t *testing.T) (string, string, string, managedIntentKeyring) {
	t.Helper()
	directory := t.TempDir()
	tokenPath := filepath.Join(directory, "token")
	if err := os.WriteFile(tokenPath, []byte(strings.Repeat("t", 32)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, publicKey := signManagedDynamicTestIntent(t, managedDynamicTestIntent())
	keyPath := filepath.Join(directory, "keys.json")
	keyDocument := managedVerificationKeyDocument{
		Schema:        managedVerificationKeysSchema,
		SchemaVersion: managedIntentContractVersion,
		Keys: []managedVerificationKey{{
			KeyID:              "key_dynamic0001",
			PublicKeyBase64URL: base64.RawURLEncoding.EncodeToString(publicKey),
		}},
	}
	rawKeys, err := json.Marshal(keyDocument)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, rawKeys, 0600); err != nil {
		t.Fatal(err)
	}
	declarationPath := filepath.Join(directory, "declaration.json")
	if err := os.WriteFile(declarationPath, managedDynamicFixtureDeclaration(t), 0444); err != nil {
		t.Fatal(err)
	}
	return tokenPath, keyPath, declarationPath, managedIntentKeyring{"key_dynamic0001": publicKey}
}

func TestManagedDynamicSetupRuntimeConfigRequiresExplicitCompleteGate(t *testing.T) {
	clearManagedDynamicSetupEnvironment(t)
	if config, err := loadManagedDynamicSetupRuntimeConfigFromEnv(); err != nil || config != nil {
		t.Fatalf("unset dynamic setup must stay disabled: config=%#v err=%v", config, err)
	}
	t.Setenv(managedDynamicSetupEnabledEnv, "false")
	if config, err := loadManagedDynamicSetupRuntimeConfigFromEnv(); err != nil || config != nil {
		t.Fatalf("explicit false must stay disabled: config=%#v err=%v", config, err)
	}
	t.Setenv(managedDynamicSetupEnabledEnv, "yes")
	if _, err := loadManagedDynamicSetupRuntimeConfigFromEnv(); err == nil {
		t.Fatal("non-boolean enable flag was accepted")
	}

	clearManagedDynamicSetupEnvironment(t)
	t.Setenv(managedDynamicSetupOriginEnv, "https://control.example.test")
	if _, err := loadManagedDynamicSetupRuntimeConfigFromEnv(); err == nil {
		t.Fatal("configuration without the explicit enable flag was accepted")
	}

	clearManagedDynamicSetupEnvironment(t)
	t.Setenv(managedDynamicSetupEnabledEnv, "true")
	if _, err := loadManagedDynamicSetupRuntimeConfigFromEnv(); err == nil {
		t.Fatal("partial enabled configuration was accepted")
	}

	tokenPath, keyPath, declarationPath, _ := writeManagedDynamicSetupConfigFiles(t)
	t.Setenv(managedDynamicSetupOriginEnv, "http://control.example.test")
	t.Setenv(managedDynamicSetupTokenFileEnv, tokenPath)
	t.Setenv(managedDynamicSetupKeyFileEnv, keyPath)
	t.Setenv(managedDynamicSetupPathsEnv, declarationPath)
	if _, err := loadManagedDynamicSetupRuntimeConfigFromEnv(); err == nil {
		t.Fatal("non-HTTPS control-plane origin was accepted")
	}

	t.Setenv(managedDynamicSetupOriginEnv, "https://control.example.test")
	config, err := loadManagedDynamicSetupRuntimeConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if config == nil ||
		config.ControlPlaneOrigin != "https://control.example.test" ||
		config.InternalToken != strings.Repeat("t", 32) ||
		len(config.Keyring) != 1 ||
		len(config.DeclarationPaths) != 1 ||
		config.DeclarationPaths[0] != declarationPath {
		t.Fatalf("complete explicit configuration was not preserved: %#v", config)
	}

	t.Setenv(managedDynamicSetupTokenFileEnv, "relative-token")
	if _, err := loadManagedDynamicSetupRuntimeConfigFromEnv(); err == nil {
		t.Fatal("relative token path was accepted")
	}
	t.Setenv(managedDynamicSetupTokenFileEnv, tokenPath)
	t.Setenv(managedDynamicSetupPathsEnv, declarationPath+","+declarationPath)
	if _, err := loadManagedDynamicSetupRuntimeConfigFromEnv(); err == nil {
		t.Fatal("duplicate declaration path was accepted")
	}
	t.Setenv(managedDynamicSetupPathsEnv, "relative.json")
	if _, err := loadManagedDynamicSetupRuntimeConfigFromEnv(); err == nil {
		t.Fatal("relative declaration path was accepted")
	}
	if err := os.Chmod(tokenPath, 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(managedDynamicSetupPathsEnv, declarationPath)
	if _, err := loadManagedDynamicSetupRuntimeConfigFromEnv(); err == nil {
		t.Fatal("group/world-readable dynamic setup token was accepted")
	}
}

func newManagedDynamicHTTPAuthorityForTest(
	t *testing.T,
	handler http.Handler,
) (*managedDynamicHTTPAuthority, *httptest.Server, managedDynamicSetupIntent) {
	t.Helper()
	intent := managedDynamicTestIntent()
	_, _, declarationPath, keyring := writeManagedDynamicSetupConfigFiles(t)
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	authority, err := newManagedDynamicSetupAuthority(managedDynamicSetupRuntimeConfig{
		ControlPlaneOrigin: server.URL,
		InternalToken:      strings.Repeat("a", 32),
		Keyring:            keyring,
		DeclarationPaths:   []string{declarationPath},
	}, t.TempDir(), server.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	authority.consumer.now = func() time.Time { return time.Unix(managedDynamicTestNow+1, 0) }
	return authority, server, intent
}

func TestManagedDynamicHTTPAuthorityFetchesAndRevalidatesExactIntent(t *testing.T) {
	intent := managedDynamicTestIntent()
	envelope, _ := signManagedDynamicTestIntent(t, intent)
	rawEnvelope, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	authority, _, _ := newManagedDynamicHTTPAuthorityForTest(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.Method != http.MethodGet ||
			request.URL.RequestURI() != managedDynamicSetupEndpoint+intent.IntentRef ||
			request.Header.Get("Authorization") != "Bearer "+strings.Repeat("a", 32) ||
			request.Header.Get("Accept") != "application/json" ||
			request.Header.Get("Accept-Encoding") != "identity" ||
			request.Header.Get("Cache-Control") != "no-store" {
			t.Error("authority request did not match the fixed method, path, and safe header contract")
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write(rawEnvelope)
	}))
	inspection, err := authority.Inspect(t.Context(), intent.IntentRef, intent.HumanSessionRef)
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 ||
		inspection.Intent.IntentRef != intent.IntentRef ||
		inspection.Context.EnvironmentPolicyRef != intent.EnvironmentPolicyRef {
		t.Fatalf("exact signed intent was not revalidated: requests=%d inspection=%#v", requests.Load(), inspection)
	}

	if _, err := authority.Inspect(t.Context(), "intent_../../escape", intent.HumanSessionRef); err == nil ||
		err.Error() != "managed_intent_unknown" ||
		requests.Load() != 1 {
		t.Fatalf("unsafe reference reached the authority: requests=%d err=%v", requests.Load(), err)
	}
	if _, err := authority.Inspect(t.Context(), intent.IntentRef, "hsn_someone_else0"); err == nil ||
		err.Error() != "managed_intent_wrong_user" {
		t.Fatalf("human-session mismatch was accepted: %v", err)
	}
}

func TestManagedDynamicHTTPAuthorityRejectsRedirectOversizeAndUntrustedDenial(t *testing.T) {
	tests := []struct {
		name    string
		handler http.Handler
		want    string
	}{
		{
			name: "redirect",
			handler: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				http.Redirect(response, request, "https://other.example.test", http.StatusFound)
			}),
			want: "managed_intent_pharos_unavailable",
		},
		{
			name: "oversized",
			handler: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				_, _ = response.Write(make([]byte, managedIntentMaxEnvelopeBytes+1))
			}),
			want: "managed_intent_pharos_unavailable",
		},
		{
			name: "untrusted denial schema",
			handler: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				response.WriteHeader(http.StatusGone)
				_, _ = response.Write([]byte(`{"schema":"evil","schema_version":2,"outcome":"denied","reason_code":"managed_intent_expired","value_returned":false}`))
			}),
			want: "managed_intent_pharos_unavailable",
		},
		{
			name: "denial unknown field",
			handler: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				response.WriteHeader(http.StatusGone)
				_, _ = response.Write([]byte(`{"schema":"inspr.pharos.managed-environment-setup-intent-delivery.v2","schema_version":2,"outcome":"denied","reason_code":"managed_intent_expired","value_returned":false,"detail":"secret"}`))
			}),
			want: "managed_intent_pharos_unavailable",
		},
		{
			name: "denial claims a value",
			handler: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				response.WriteHeader(http.StatusGone)
				_, _ = response.Write([]byte(`{"schema":"inspr.pharos.managed-environment-setup-intent-delivery.v2","schema_version":2,"outcome":"denied","reason_code":"managed_intent_expired","value_returned":true}`))
			}),
			want: "managed_intent_pharos_unavailable",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authority, _, intent := newManagedDynamicHTTPAuthorityForTest(t, test.handler)
			if _, err := authority.Inspect(t.Context(), intent.IntentRef, intent.HumanSessionRef); err == nil ||
				err.Error() != test.want {
				t.Fatalf("got %v, want %s", err, test.want)
			}
		})
	}
}

func TestManagedDynamicHTTPAuthorityAcceptsOnlyReviewedValueFreeDenial(t *testing.T) {
	authority, _, intent := newManagedDynamicHTTPAuthorityForTest(t, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusGone)
		_, _ = response.Write([]byte(`{"schema":"inspr.pharos.managed-environment-setup-intent-delivery.v2","schema_version":2,"outcome":"denied","reason_code":"managed_intent_expired","value_returned":false}`))
	}))
	if _, err := authority.Inspect(t.Context(), intent.IntentRef, intent.HumanSessionRef); err == nil ||
		err.Error() != "managed_intent_expired" {
		t.Fatalf("reviewed denial was not preserved: %v", err)
	}
}

func TestManagedDynamicHTTPAuthorityReservesAndRecoversAcrossRestart(t *testing.T) {
	intent := managedDynamicTestIntent()
	envelope, publicKey := signManagedDynamicTestIntent(t, intent)
	rawEnvelope, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write(rawEnvelope)
	}))
	t.Cleanup(server.Close)
	_, _, declarationPath, _ := writeManagedDynamicSetupConfigFiles(t)
	config := managedDynamicSetupRuntimeConfig{
		ControlPlaneOrigin: server.URL,
		InternalToken:      strings.Repeat("a", 32),
		Keyring:            managedIntentKeyring{"key_dynamic0001": publicKey},
		DeclarationPaths:   []string{declarationPath},
	}
	dataDir := t.TempDir()
	authority, err := newManagedDynamicSetupAuthority(config, dataDir, server.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	authority.consumer.now = func() time.Time { return time.Unix(managedDynamicTestNow+1, 0) }
	reservation, err := authority.Reserve(t.Context(), intent.IntentRef, intent.HumanSessionRef)
	if err != nil || !validManagedRef("op_", reservation.OperationRef) {
		t.Fatalf("authority did not reserve exact signed intent: %#v %v", reservation, err)
	}
	if _, err := authority.Reserve(t.Context(), intent.IntentRef, intent.HumanSessionRef); err == nil || err.Error() != "managed_intent_replayed" {
		t.Fatalf("authority accepted a duplicate reservation: %v", err)
	}
	if recovered, err := authority.RecoverReservation(t.Context(), intent.IntentRef, intent.HumanSessionRef, reservation.OperationRef); err != nil || recovered.OperationRef != reservation.OperationRef {
		t.Fatalf("authority did not recover exact reservation: %#v %v", recovered, err)
	}

	restarted, err := newManagedDynamicSetupAuthority(config, dataDir, server.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	restarted.consumer.now = func() time.Time { return time.Unix(managedDynamicTestNow+1, 0) }
	if recovered, err := restarted.RecoverReservation(t.Context(), intent.IntentRef, intent.HumanSessionRef, reservation.OperationRef); err != nil || recovered.Inspection.Intent != intent {
		t.Fatalf("authority restart lost exact reservation: %#v %v", recovered, err)
	}
	target := managedDynamicTargetFromInspection(reservation.Inspection)
	started, err := restarted.BeginValueAdmission(t.Context(), target, reservation.OperationRef)
	if err != nil || !started.ValueAdmissionStarted || started.ValueAdmissionComplete {
		t.Fatalf("authority did not begin exact value admission: %#v %v", started, err)
	}
	if _, err := restarted.BeginValueAdmission(t.Context(), target, reservation.OperationRef); err == nil || err.Error() != "managed_intent_value_replayed" {
		t.Fatalf("authority admitted a duplicate value: %v", err)
	}
	completed, err := restarted.CompleteValueAdmission(t.Context(), target, reservation.OperationRef)
	if err != nil || !completed.ValueAdmissionStarted || !completed.ValueAdmissionComplete {
		t.Fatalf("authority did not complete the value-free admission receipt: %#v %v", completed, err)
	}

	again, err := newManagedDynamicSetupAuthority(config, dataDir, server.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	again.consumer.now = func() time.Time { return time.Unix(managedDynamicTestNow+1, 0) }
	recovered, err := again.RecoverReservation(t.Context(), intent.IntentRef, intent.HumanSessionRef, reservation.OperationRef)
	if err != nil || !recovered.ValueAdmissionComplete {
		t.Fatalf("authority restart lost the value-free admission receipt: %#v %v", recovered, err)
	}
}

func TestNewAppWiresDynamicAuthorityOnlyFromDedicatedConfig(t *testing.T) {
	_, _, declarationPath, keyring := writeManagedDynamicSetupConfigFiles(t)
	config := testConfig()
	config.DataDir = t.TempDir()
	config.RequireAuth = false
	config.OIDCIssuer = ""
	config.OIDCClientID = ""
	config.OIDCSecret = ""
	store, err := NewStore(config.DataDir, "")
	if err != nil {
		t.Fatal(err)
	}
	app, err := NewApp(t.Context(), config, store)
	if err != nil {
		t.Fatal(err)
	}
	if app.managedDynamicSetup != nil {
		t.Fatal("v2 authority was enabled without its dedicated configuration")
	}

	config.DynamicSetup = &managedDynamicSetupRuntimeConfig{
		ControlPlaneOrigin: "https://control.example.test",
		InternalToken:      strings.Repeat("a", 32),
		Keyring:            keyring,
		DeclarationPaths:   []string{declarationPath},
	}
	app, err = NewApp(t.Context(), config, store)
	if err != nil {
		t.Fatal(err)
	}
	if app.managedDynamicSetup == nil {
		t.Fatal("complete dedicated v2 configuration was not wired")
	}
	if err := os.Chmod(declarationPath, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(declarationPath, []byte(`{"schema":"invalid"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewApp(t.Context(), config, store); err == nil {
		t.Fatal("malformed configured v2 declaration did not fail startup")
	}
}
