package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	managedBrowserAssuranceEnv  = "JANUS_MANAGED_BROWSER_ASSURANCE_SERVER"
	managedBrowserAssuranceAddr = "127.0.0.1:18082"
	managedBrowserAuthAddr      = "127.0.0.1:18083"
	managedBrowserRemoveIntent  = "intent_abcdef0123456789"
	managedBrowserRemoveOp      = "op_abcdef0123456789"
	managedBrowserDynamicIntent = "intent_13579bdf2468ace0"
)

type managedBrowserDynamicAuthority struct {
	mu         sync.Mutex
	inspection managedDynamicSetupInspection
	reserved   *managedDynamicSetupReservation
}

func newManagedBrowserDynamicAuthority(issuer string) *managedBrowserDynamicAuthority {
	now := time.Now().UTC()
	intent := managedDynamicSetupIntent{
		Schema: managedDynamicSetupIntentSchema, SchemaVersion: managedDynamicContractVersion,
		IntentRef: managedBrowserDynamicIntent, OperationKind: "create", Source: "import",
		HostRef: "host_0123456789abcdef", ServiceRef: "svc_0123456789abcdef",
		EnvironmentPolicyRef: "envpol_0123456789abcdef", EnvironmentPolicyFingerprint: "envpf_0123456789abcdef",
		DeclarationFingerprint: "decl_0123456789abcdef", EnvironmentName: "DATABASE_PASSWORD",
		HumanSessionRef: managedHumanSessionRef(issuer, managedTestSubject),
		IssuerRef:       managedSetupExpectedIssuerRef, AudienceRef: managedSetupExpectedAudienceRef,
		NonceRef: "nonce_13579bdf2468ace0", IssuedAtUnixSeconds: now.Add(-time.Minute).Unix(),
		ExpiresAtUnixSeconds: now.Add(10 * time.Minute).Unix(), ReturnTarget: "pharos_service",
	}
	return &managedBrowserDynamicAuthority{inspection: managedDynamicSetupInspection{
		Intent: intent,
		Context: managedDynamicDeclarationContext{
			ConsumerKind: "managed_service", DeliveryKind: "private_env_file",
			DeliveryProfileRef: "delivery_0123456789abcdef", ReloadProfileRef: "reload_0123456789abcdef",
			HealthProfileRef: "health_0123456789abcdef", AllowedSources: []string{"generated", "import"},
			NamePolicy: "portable_secret_env_v1", MaxActiveBindings: 16, AdditionalReservedNames: []string{},
			EnvironmentPolicyRef: intent.EnvironmentPolicyRef, EnvironmentPolicyFingerprint: intent.EnvironmentPolicyFingerprint,
		},
	}}
}

func (authority *managedBrowserDynamicAuthority) Inspect(_ context.Context, intentRef, humanSessionRef string) (managedDynamicSetupInspection, error) {
	if authority.inspection.Intent.IntentRef != intentRef || authority.inspection.Intent.HumanSessionRef != humanSessionRef {
		return managedDynamicSetupInspection{}, managedIntentError("managed_intent_wrong_user")
	}
	return authority.inspection, nil
}

func (authority *managedBrowserDynamicAuthority) reset(source string) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	authority.inspection.Intent.Source = source
	authority.reserved = nil
}

func (authority *managedBrowserDynamicAuthority) Reserve(ctx context.Context, intentRef, humanSessionRef string) (managedDynamicSetupReservation, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	inspection, err := authority.Inspect(ctx, intentRef, humanSessionRef)
	if err != nil {
		return managedDynamicSetupReservation{}, err
	}
	if authority.reserved != nil {
		return managedDynamicSetupReservation{}, managedIntentError("managed_intent_replayed")
	}
	reservation := managedDynamicSetupReservation{Inspection: inspection, OperationRef: "op_13579bdf2468ace0"}
	authority.reserved = &reservation
	return reservation, nil
}

func (authority *managedBrowserDynamicAuthority) RecoverReservation(ctx context.Context, intentRef, humanSessionRef, operationRef string) (managedDynamicSetupReservation, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	inspection, err := authority.Inspect(ctx, intentRef, humanSessionRef)
	if err != nil || authority.reserved == nil || authority.reserved.OperationRef != operationRef || authority.reserved.Inspection.Intent != inspection.Intent {
		return managedDynamicSetupReservation{}, managedIntentError("managed_intent_recovery_unavailable")
	}
	return *authority.reserved, nil
}

func (authority *managedBrowserDynamicAuthority) BeginValueAdmission(ctx context.Context, expected managedDynamicStepUpTarget, operationRef string) (managedDynamicSetupReservation, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	inspection, err := authority.Inspect(ctx, expected.IntentRef, expected.HumanSessionRef)
	if err != nil || managedDynamicTargetFromInspection(inspection) != expected || authority.reserved == nil || authority.reserved.OperationRef != operationRef {
		return managedDynamicSetupReservation{}, managedIntentError("managed_intent_value_admission_unavailable")
	}
	if authority.reserved.ValueAdmissionStarted {
		return *authority.reserved, managedIntentError("managed_intent_value_replayed")
	}
	authority.reserved.ValueAdmissionStarted = true
	return *authority.reserved, nil
}

func (authority *managedBrowserDynamicAuthority) CompleteValueAdmission(ctx context.Context, expected managedDynamicStepUpTarget, operationRef string, custody managedDynamicCustodyResult, delivery managedDynamicDeliveryResult) (managedDynamicSetupReservation, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	inspection, err := authority.Inspect(ctx, expected.IntentRef, expected.HumanSessionRef)
	if err != nil || managedDynamicTargetFromInspection(inspection) != expected || authority.reserved == nil || authority.reserved.OperationRef != operationRef || !authority.reserved.ValueAdmissionStarted || authority.reserved.ValueAdmissionComplete {
		return managedDynamicSetupReservation{}, managedIntentError("managed_intent_value_admission_unavailable")
	}
	authority.reserved.ValueAdmissionComplete = true
	authority.reserved.BindingRef = custody.BindingRef
	authority.reserved.SecretRef = custody.SecretRef
	authority.reserved.GenerationRef = custody.GenerationRef
	authority.reserved.PackageRef = delivery.PackageRef
	authority.reserved.EnvelopeRef = delivery.EnvelopeRef
	return *authority.reserved, nil
}

type managedBrowserAuthority struct {
	mu       sync.Mutex
	intents  map[string]managedSetupIntent
	consumed map[string]bool
}

func newManagedBrowserAuthority(issuer string) *managedBrowserAuthority {
	now := time.Now().UTC()
	create := managedSetupIntent{
		Schema:                 managedSetupIntentSchema,
		SchemaVersion:          managedIntentContractVersion,
		IntentRef:              managedTestIntentRef,
		OperationKind:          "create",
		AllowedSources:         []string{"generated", "import"},
		HostRef:                "host_0123456789abcdef",
		ServiceRef:             "svc_0123456789abcdef",
		SlotRef:                "slot_0123456789abcdef",
		HumanSessionRef:        managedHumanSessionRef(issuer, managedTestSubject),
		IssuerRef:              managedSetupExpectedIssuerRef,
		AudienceRef:            managedSetupExpectedAudienceRef,
		NonceRef:               "nonce_0123456789abcdef",
		DeclarationFingerprint: "decl_0123456789abcdef",
		IssuedAtUnixSeconds:    now.Add(-time.Minute).Unix(),
		ExpiresAtUnixSeconds:   now.Add(time.Hour).Unix(),
		ReturnTarget:           "pharos_service",
	}
	remove := create
	remove.IntentRef = managedBrowserRemoveIntent
	remove.OperationKind = "remove"
	remove.AllowedSources = nil
	remove.NonceRef = "nonce_abcdef0123456789"
	return &managedBrowserAuthority{
		intents: map[string]managedSetupIntent{
			create.IntentRef: create,
			remove.IntentRef: remove,
		},
		consumed: make(map[string]bool),
	}
}

func (authority *managedBrowserAuthority) reset(intentRef string) bool {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if _, ok := authority.intents[intentRef]; !ok {
		return false
	}
	delete(authority.consumed, intentRef)
	return true
}

func (authority *managedBrowserAuthority) Inspect(
	_ context.Context,
	intentRef string,
	humanSessionRef string,
) (managedSetupInspection, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	intent, ok := authority.intents[intentRef]
	if !ok {
		return managedSetupInspection{}, managedIntentError("managed_intent_unknown")
	}
	if intent.HumanSessionRef != humanSessionRef {
		return managedSetupInspection{}, managedIntentError("managed_intent_wrong_user")
	}
	return managedSetupInspection{
		Intent:  intent,
		Context: managedBrowserContext(intent),
	}, nil
}

func (authority *managedBrowserAuthority) Consume(
	_ context.Context,
	intentRef string,
	humanSessionRef string,
	source string,
) (managedAcceptedIntent, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	intent, ok := authority.intents[intentRef]
	if !ok {
		return managedAcceptedIntent{}, managedIntentError("managed_intent_unknown")
	}
	if intent.HumanSessionRef != humanSessionRef {
		return managedAcceptedIntent{}, managedIntentError("managed_intent_wrong_user")
	}
	if authority.consumed[intentRef] {
		return managedAcceptedIntent{}, managedIntentError("managed_intent_replayed")
	}
	if intent.OperationKind == "remove" && source != "remove" ||
		intent.OperationKind != "remove" && !containsManagedSource(intent.AllowedSources, source) {
		return managedAcceptedIntent{}, managedIntentError("managed_intent_source_denied")
	}
	authority.consumed[intentRef] = true
	operationRef := managedTestOpRef
	if intent.OperationKind == "remove" {
		operationRef = managedBrowserRemoveOp
	}
	return managedAcceptedIntent{
		Intent:       intent,
		Context:      managedBrowserContext(intent),
		Source:       source,
		OperationRef: operationRef,
	}, nil
}

func (authority *managedBrowserAuthority) Recover(
	_ context.Context,
	intentRef string,
	humanSessionRef string,
	source string,
) (managedAcceptedIntent, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	intent, ok := authority.intents[intentRef]
	if !ok || !authority.consumed[intentRef] {
		return managedAcceptedIntent{}, managedIntentError("managed_intent_recovery_unavailable")
	}
	if intent.HumanSessionRef != humanSessionRef {
		return managedAcceptedIntent{}, managedIntentError("managed_intent_wrong_user")
	}
	if intent.OperationKind == "remove" && source != "remove" ||
		intent.OperationKind != "remove" && !containsManagedSource(intent.AllowedSources, source) {
		return managedAcceptedIntent{}, managedIntentError("managed_intent_source_denied")
	}
	operationRef := managedTestOpRef
	if intent.OperationKind == "remove" {
		operationRef = managedBrowserRemoveOp
	}
	return managedAcceptedIntent{
		Intent:       intent,
		Context:      managedBrowserContext(intent),
		Source:       source,
		OperationRef: operationRef,
	}, nil
}

func managedBrowserContext(intent managedSetupIntent) managedDeclarationContext {
	context := managedDeclarationContext{
		ServiceLabel:       "Managed browser canary",
		SlotLabel:          "Service credential",
		ConsumerKind:       "managed_service",
		DeliveryKind:       "private_env_file",
		DeliveryProfileRef: "delivery_2d7a0f63c951",
		ReloadProfileRef:   "reload_65bc19f3a087",
		HealthProfileRef:   "health_918d0ce7b4a2",
		BindingState:       "required",
		AllowedSources:     append([]string(nil), intent.AllowedSources...),
	}
	if intent.OperationKind == "remove" {
		context.BindingState = "detached"
		context.DetachProfileRef = "detach_8a0f4e271c93"
	}
	return context
}

type managedBrowserExecutor struct {
	mu                 sync.Mutex
	executions         int
	lastValueByteCount int
	lastOperationRef   string
	lastSource         string
}

func (executor *managedBrowserExecutor) Execute(
	_ context.Context,
	accepted managedAcceptedIntent,
	importedValue []byte,
) (managedTransactionResult, error) {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if accepted.Source == "import" && len(importedValue) == 0 ||
		accepted.Source != "import" && len(importedValue) != 0 {
		return managedTransactionResult{}, errors.New("managed browser value shape invalid")
	}
	executor.executions++
	executor.lastValueByteCount = len(importedValue)
	executor.lastOperationRef = accepted.OperationRef
	executor.lastSource = accepted.Source
	return managedTransactionResult{
		OperationRef:  accepted.OperationRef,
		SecretRef:     managedTestSecretRef,
		Mode:          accepted.Source,
		Generation:    1,
		Phase:         "registered",
		ReasonCode:    "managed_operation_registered",
		ValueReturned: false,
	}, nil
}

func (executor *managedBrowserExecutor) Recover(
	_ context.Context,
	accepted managedAcceptedIntent,
) error {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if executor.executions == 0 ||
		executor.lastOperationRef != accepted.OperationRef ||
		executor.lastSource != accepted.Source {
		return managedTransactionError("managed_operation_recovery_unavailable")
	}
	return nil
}

func (executor *managedBrowserExecutor) evidence() (int, int) {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	return executor.executions, executor.lastValueByteCount
}

func (executor *managedBrowserExecutor) reset() {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	executor.executions = 0
	executor.lastValueByteCount = 0
	executor.lastOperationRef = ""
	executor.lastSource = ""
}

type managedBrowserAuthorization struct {
	nonce string
}

type managedBrowserHarness struct {
	app              *App
	routes           http.Handler
	authority        *managedBrowserAuthority
	dynamicAuthority *managedBrowserDynamicAuthority
	executor         *managedBrowserExecutor
	privateKey       *rsa.PrivateKey
	baseURL          string
	authorizations   map[string]managedBrowserAuthorization
	mu               sync.Mutex
}

func newManagedBrowserHarness(t *testing.T, baseURL, authBaseURL string) *managedBrowserHarness {
	t.Helper()
	app := newTestApp(t)
	issuer := baseURL + "/__managed-browser/issuer"
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	authority := newManagedBrowserAuthority(issuer)
	dynamicAuthority := newManagedBrowserDynamicAuthority(issuer)
	executor := &managedBrowserExecutor{}
	authOrigin, err := url.Parse(authBaseURL)
	if err != nil || authOrigin.Port() == "" {
		t.Fatal("managed browser auth origin is invalid")
	}
	app.cfg.PublicURL = baseURL
	app.cfg.OIDCIssuer = issuer
	app.cfg.OIDCClientID = "managed-browser-client"
	app.cfg.OIDCSecret = "managed-browser-secret"
	app.cfg.RolePolicy = RolePolicy{
		OwnerSubjects: map[string]bool{managedTestSubject: true},
	}
	app.cfg.ManagedSetup = &managedSetupRuntimeConfig{
		// Use the same host on a different port so browser assurance proves the
		// Janus completion page can cross origins without broadening form-action.
		PharosReturnOrigin: "http://127.0.0.1:" + authOrigin.Port(),
	}
	app.oauth = &oauth2.Config{
		ClientID:     app.cfg.OIDCClientID,
		ClientSecret: app.cfg.OIDCSecret,
		RedirectURL:  baseURL + "/oidc/callback",
		Scopes:       []string{"openid", "email", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  authBaseURL + "/__managed-browser/authorize",
			TokenURL: authBaseURL + "/__managed-browser/token",
		},
	}
	app.verifier = oidc.NewVerifier(
		issuer,
		&oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&privateKey.PublicKey}},
		&oidc.Config{ClientID: app.cfg.OIDCClientID},
	)
	app.managedSetup = authority
	app.managedTxn = executor
	app.managedDynamicSetup = dynamicAuthority
	app.managedDynamicCustody = &fakeManagedDynamicCustodyExecutor{}
	app.managedDynamicDelivery = &fakeManagedDynamicDeliveryExecutor{}
	return &managedBrowserHarness{
		app:              app,
		routes:           app.routes(),
		authority:        authority,
		dynamicAuthority: dynamicAuthority,
		executor:         executor,
		privateKey:       privateKey,
		baseURL:          baseURL,
		authorizations:   make(map[string]managedBrowserAuthorization),
	}
}

func (harness *managedBrowserHarness) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case "/__managed-browser/session":
		harness.session(response, request)
	case "/__managed-browser/expired":
		harness.expired(response, request)
	case "/__managed-browser/expired-oidc":
		harness.expiredOIDC(response, request)
	case "/__managed-browser/authorize":
		harness.authorize(response, request)
	case "/__managed-browser/token":
		harness.token(response, request)
	case "/__managed-browser/evidence":
		harness.evidence(response)
	default:
		if strings.HasPrefix(request.URL.Path, "/managed-service/operations/") {
			harness.operation(response, request)
			return
		}
		harness.routes.ServeHTTP(response, request)
	}
}

func (harness *managedBrowserHarness) session(response http.ResponseWriter, request *http.Request) {
	kind := request.URL.Query().Get("kind")
	if kind == "dynamic" || kind == "dynamic-generated" {
		source := "import"
		if kind == "dynamic-generated" {
			source = "generated"
		}
		harness.dynamicAuthority.reset(source)
		harness.executor.reset()
		harness.writeSession(response)
		response.Header().Set("Cache-Control", "no-store")
		http.Redirect(response, request, "/managed-environment/setup?intent="+url.QueryEscape(managedBrowserDynamicIntent), http.StatusFound)
		return
	}
	intentRef := managedTestIntentRef
	if request.URL.Query().Get("kind") == "remove" {
		intentRef = managedBrowserRemoveIntent
	}
	if !harness.authority.reset(intentRef) {
		http.Error(response, "fixture unavailable", http.StatusBadRequest)
		return
	}
	harness.executor.reset()
	harness.writeSession(response)
	response.Header().Set("Cache-Control", "no-store")
	http.Redirect(
		response,
		request,
		"/managed-service/setup?intent="+url.QueryEscape(intentRef),
		http.StatusFound,
	)
}

func (harness *managedBrowserHarness) expired(response http.ResponseWriter, request *http.Request) {
	harness.executor.reset()
	harness.writeSession(response)
	now := time.Now().UTC()
	harness.app.writeManagedStepUpProof(response, managedStepUpProof{
		Schema:          managedStepUpProofDomain,
		IntentRef:       managedTestIntentRef,
		Source:          "import",
		HumanSessionRef: managedHumanSessionRef(harness.app.cfg.OIDCIssuer, managedTestSubject),
		AuthenticatedAt: now.Add(-10 * time.Minute).Unix(),
		ExpiresAt:       now.Add(-5 * time.Minute).Unix(),
	})
	response.Header().Set("Cache-Control", "no-store")
	http.Redirect(
		response,
		request,
		"/managed-service/setup?intent="+url.QueryEscape(managedTestIntentRef),
		http.StatusFound,
	)
}

func (harness *managedBrowserHarness) expiredOIDC(response http.ResponseWriter, request *http.Request) {
	if !harness.authority.reset(managedTestIntentRef) {
		http.Error(response, "fixture unavailable", http.StatusBadRequest)
		return
	}
	harness.executor.reset()
	harness.writeSession(response)
	now := time.Now().UTC()
	harness.app.writeManagedStepUpRetry(response, managedStepUpRetry{
		Schema:    managedStepUpRetryDomain,
		IntentRef: managedTestIntentRef,
		StateHash: managedStateHash("expired"),
		IssuedAt:  now.Add(-7 * time.Minute).Unix(),
		ExpiresAt: now.Add(8 * time.Minute).Unix(),
	})
	response.Header().Set("Cache-Control", "no-store")
	http.Redirect(
		response,
		request,
		"/oidc/callback?state=expired&code=unused",
		http.StatusFound,
	)
}

func (harness *managedBrowserHarness) writeSession(response http.ResponseWriter) {
	harness.app.writeSession(response, Session{
		Subject: managedTestSubject,
		Name:    "Managed browser reviewer",
		Roles:   []string{RoleViewer, RoleOwner},
		Expiry:  time.Now().UTC().Add(time.Hour),
	})
}

func (harness *managedBrowserHarness) authorize(response http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	if request.Method != http.MethodGet ||
		query.Get("redirect_uri") != harness.baseURL+"/oidc/callback" ||
		query.Get("state") == "" ||
		query.Get("nonce") == "" ||
		query.Get("code_challenge") == "" ||
		query.Get("code_challenge_method") != "S256" ||
		query.Get("prompt") != "login" ||
		query.Get("max_age") != "0" {
		http.Error(response, "authorization denied", http.StatusBadRequest)
		return
	}
	code := randomToken(24)
	harness.mu.Lock()
	harness.authorizations[code] = managedBrowserAuthorization{nonce: query.Get("nonce")}
	harness.mu.Unlock()
	callback, _ := url.Parse(query.Get("redirect_uri"))
	callbackQuery := callback.Query()
	callbackQuery.Set("state", query.Get("state"))
	callbackQuery.Set("code", code)
	callback.RawQuery = callbackQuery.Encode()
	response.Header().Set("Cache-Control", "no-store")
	http.Redirect(response, request, callback.String(), http.StatusFound)
}

func (harness *managedBrowserHarness) token(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || request.ParseForm() != nil ||
		request.Form.Get("grant_type") != "authorization_code" ||
		request.Form.Get("redirect_uri") != harness.baseURL+"/oidc/callback" ||
		request.Form.Get("code_verifier") == "" {
		http.Error(response, "token denied", http.StatusBadRequest)
		return
	}
	code := request.Form.Get("code")
	harness.mu.Lock()
	authorization, ok := harness.authorizations[code]
	delete(harness.authorizations, code)
	harness.mu.Unlock()
	if !ok {
		http.Error(response, "token denied", http.StatusBadRequest)
		return
	}
	now := time.Now().UTC()
	rawIDToken, err := signManagedBrowserIDToken(harness.privateKey, map[string]any{
		"iss":       harness.app.cfg.OIDCIssuer,
		"sub":       managedTestSubject,
		"aud":       harness.app.cfg.OIDCClientID,
		"exp":       now.Add(5 * time.Minute).Unix(),
		"iat":       now.Unix(),
		"auth_time": now.Unix(),
		"nonce":     authorization.nonce,
		"amr":       []string{"user", "mfa"},
	})
	if err != nil {
		http.Error(response, "token unavailable", http.StatusInternalServerError)
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(response).Encode(map[string]any{
		"access_token": "managed-browser-access",
		"token_type":   "Bearer",
		"expires_in":   300,
		"id_token":     rawIDToken,
	})
}

func (harness *managedBrowserHarness) operation(response http.ResponseWriter, request *http.Request) {
	session, ok := harness.app.readSession(request)
	if !ok {
		http.Redirect(response, request, "/", http.StatusFound)
		return
	}
	response.Header().Set("Cache-Control", "no-store, no-transform")
	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(response, `<!doctype html><html lang="en"><head><title>Operation registered</title></head><body><main><h1>Operation registered</h1><p>Pharos will show value-free progress.</p><form method="post" action="/logout"><input type="hidden" name="csrf_token" value="`)
	_, _ = io.WriteString(response, harness.app.csrfToken(session))
	_, _ = io.WriteString(response, `"><button type="submit">Sign out</button></form></main></body></html>`)
}

func (harness *managedBrowserHarness) evidence(response http.ResponseWriter) {
	executions, lastValueByteCount := harness.executor.evidence()
	audit, err := json.Marshal(harness.app.store.RecentAudit(128))
	if err != nil {
		http.Error(response, "evidence unavailable", http.StatusInternalServerError)
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(response).Encode(map[string]any{
		"schema":                "janus.managed-browser-assurance.v1",
		"executions":            executions,
		"last_value_byte_count": lastValueByteCount,
		"authority_kind":        "test_fixture",
		"audit":                 json.RawMessage(audit),
	})
}

func signManagedBrowserIDToken(privateKey *rsa.PrivateKey, claims map[string]any) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func TestManagedBrowserAssuranceServer(t *testing.T) {
	if os.Getenv(managedBrowserAssuranceEnv) != "1" {
		t.Skip("managed browser assurance server is started only by Playwright")
	}
	listener, err := net.Listen("tcp", managedBrowserAssuranceAddr)
	if err != nil {
		t.Fatal(err)
	}
	authListener, err := net.Listen("tcp", managedBrowserAuthAddr)
	if err != nil {
		t.Fatal(err)
	}
	baseURL := "http://" + managedBrowserAssuranceAddr
	_, authPort, err := net.SplitHostPort(managedBrowserAuthAddr)
	if err != nil {
		t.Fatal(err)
	}
	authBaseURL := "http://localhost:" + authPort
	harness := newManagedBrowserHarness(t, baseURL, authBaseURL)
	authServer := &http.Server{
		Handler:           harness,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := authServer.Serve(authListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Printf("managed_browser_auth_server_error=%v\n", err)
		}
	}()
	server := &http.Server{
		Handler:           harness,
		ReadHeaderTimeout: 5 * time.Second,
	}
	fmt.Println("managed_browser_assurance_server=ready")
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		t.Fatal(err)
	}
}
