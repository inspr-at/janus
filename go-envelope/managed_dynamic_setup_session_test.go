package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

type fakeManagedDynamicIntentAuthority struct {
	inspection    managedDynamicSetupInspection
	inspectErr    error
	inspectCount  int
	reservation   *managedDynamicSetupReservation
	reserveErr    error
	recoverErr    error
	reserveCount  int
	recoverCount  int
	beginCount    int
	completeCount int
}

func (fake *fakeManagedDynamicIntentAuthority) Inspect(_ context.Context, intentRef, humanSessionRef string) (managedDynamicSetupInspection, error) {
	fake.inspectCount++
	if fake.inspectErr != nil {
		return managedDynamicSetupInspection{}, fake.inspectErr
	}
	if intentRef != fake.inspection.Intent.IntentRef || humanSessionRef != fake.inspection.Intent.HumanSessionRef {
		return managedDynamicSetupInspection{}, managedIntentError("managed_intent_wrong_user")
	}
	return fake.inspection, nil
}

func (fake *fakeManagedDynamicIntentAuthority) Reserve(ctx context.Context, intentRef, humanSessionRef string) (managedDynamicSetupReservation, error) {
	fake.reserveCount++
	if fake.reserveErr != nil {
		return managedDynamicSetupReservation{}, fake.reserveErr
	}
	inspection, err := fake.Inspect(ctx, intentRef, humanSessionRef)
	if err != nil {
		return managedDynamicSetupReservation{}, err
	}
	if fake.reservation != nil {
		return managedDynamicSetupReservation{}, managedIntentError("managed_intent_replayed")
	}
	reservation := managedDynamicSetupReservation{
		Inspection:   inspection,
		OperationRef: "op_0123456789abcdef",
	}
	fake.reservation = &reservation
	return reservation, nil
}

func (fake *fakeManagedDynamicIntentAuthority) RecoverReservation(ctx context.Context, intentRef, humanSessionRef, operationRef string) (managedDynamicSetupReservation, error) {
	fake.recoverCount++
	if fake.recoverErr != nil {
		return managedDynamicSetupReservation{}, fake.recoverErr
	}
	inspection, err := fake.Inspect(ctx, intentRef, humanSessionRef)
	if err != nil || fake.reservation == nil || fake.reservation.OperationRef != operationRef || fake.reservation.Inspection.Intent != inspection.Intent {
		return managedDynamicSetupReservation{}, managedIntentError("managed_intent_recovery_unavailable")
	}
	return *fake.reservation, nil
}

func (fake *fakeManagedDynamicIntentAuthority) BeginValueAdmission(ctx context.Context, expected managedDynamicStepUpTarget, operationRef string) (managedDynamicSetupReservation, error) {
	fake.beginCount++
	inspection, err := fake.Inspect(ctx, expected.IntentRef, expected.HumanSessionRef)
	if err != nil || managedDynamicTargetFromInspection(inspection) != expected || fake.reservation == nil || fake.reservation.OperationRef != operationRef {
		return managedDynamicSetupReservation{}, managedIntentError("managed_intent_value_admission_unavailable")
	}
	if fake.reservation.ValueAdmissionStarted {
		return *fake.reservation, managedIntentError("managed_intent_value_replayed")
	}
	fake.reservation.ValueAdmissionStarted = true
	return *fake.reservation, nil
}

func (fake *fakeManagedDynamicIntentAuthority) CompleteValueAdmission(ctx context.Context, expected managedDynamicStepUpTarget, operationRef string) (managedDynamicSetupReservation, error) {
	fake.completeCount++
	inspection, err := fake.Inspect(ctx, expected.IntentRef, expected.HumanSessionRef)
	if err != nil || managedDynamicTargetFromInspection(inspection) != expected || fake.reservation == nil || fake.reservation.OperationRef != operationRef || !fake.reservation.ValueAdmissionStarted || fake.reservation.ValueAdmissionComplete {
		return managedDynamicSetupReservation{}, managedIntentError("managed_intent_value_admission_unavailable")
	}
	fake.reservation.ValueAdmissionComplete = true
	return *fake.reservation, nil
}

func managedDynamicSessionFixture(t *testing.T) (*App, *fakeManagedDynamicIntentAuthority, Session, *http.Cookie, managedDynamicStepUpTarget) {
	t.Helper()
	app := newTestApp(t)
	app.oauth = testOAuthConfig()
	session := Session{
		Subject: managedTestSubject,
		Roles:   []string{RoleViewer, RoleOwner},
		Expiry:  time.Now().UTC().Add(time.Hour),
	}
	intent := managedDynamicSetupIntent{
		Schema:                       managedDynamicSetupIntentSchema,
		SchemaVersion:                managedDynamicContractVersion,
		IntentRef:                    managedTestIntentRef,
		OperationKind:                "create",
		Source:                       "import",
		HostRef:                      "host_0123456789abcdef",
		ServiceRef:                   "svc_0123456789abcdef",
		EnvironmentPolicyRef:         "envpol_0123456789abcdef",
		EnvironmentPolicyFingerprint: "envpf_0123456789abcdef",
		DeclarationFingerprint:       "decl_0123456789abcdef",
		EnvironmentName:              "DATABASE_PASSWORD",
		HumanSessionRef:              managedHumanSessionRef(app.cfg.OIDCIssuer, session.Subject),
		IssuerRef:                    managedSetupExpectedIssuerRef,
		AudienceRef:                  managedSetupExpectedAudienceRef,
		NonceRef:                     "nonce_0123456789abcdef",
		IssuedAtUnixSeconds:          time.Now().UTC().Add(-time.Minute).Unix(),
		ExpiresAtUnixSeconds:         time.Now().UTC().Add(time.Minute).Unix(),
		ReturnTarget:                 "pharos_service",
	}
	inspection := managedDynamicSetupInspection{
		Intent: intent,
		Context: managedDynamicDeclarationContext{
			ConsumerKind:                 "managed_service",
			DeliveryKind:                 "private_env_file",
			DeliveryProfileRef:           "delivery_0123456789abcdef",
			ReloadProfileRef:             "reload_0123456789abcdef",
			HealthProfileRef:             "health_0123456789abcdef",
			AllowedSources:               []string{"generated", "import"},
			NamePolicy:                   "portable_secret_env_v1",
			MaxActiveBindings:            16,
			AdditionalReservedNames:      []string{},
			EnvironmentPolicyRef:         intent.EnvironmentPolicyRef,
			EnvironmentPolicyFingerprint: intent.EnvironmentPolicyFingerprint,
		},
	}
	authority := &fakeManagedDynamicIntentAuthority{inspection: inspection}
	app.managedDynamicSetup = authority
	sessionWriter := httptest.NewRecorder()
	app.writeSession(sessionWriter, session)
	sessionCookie := cookieByName(t, sessionWriter.Result().Cookies(), hostSessionCookie)
	return app, authority, session, sessionCookie, managedDynamicTargetFromInspection(inspection)
}

func TestManagedDynamicSetupPageBindsTargetBeforeAnyValueAdmission(t *testing.T) {
	app, authority, _, sessionCookie, target := managedDynamicSessionFixture(t)

	request := httptest.NewRequest(http.MethodGet, "/managed-environment/setup?intent="+managedTestIntentRef, nil)
	request.AddCookie(sessionCookie)
	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("expected dynamic setup page, got %d body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, expected := range []string{
		"Confirm with passkey", target.HostRef, target.ServiceRef, target.EnvironmentName,
		"Import once", target.EnvironmentPolicyRef, "No secret value is requested here",
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("dynamic setup should show %q: %s", expected, body)
		}
	}
	for _, forbidden := range []string{`name="secret_value"`, `type="password"`, "/managed-service/setup/execute", "/managed-environment/setup/admit"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("dynamic setup must remain value-free and non-executable; found %q", forbidden)
		}
	}
	if authority.inspectCount != 1 {
		t.Fatalf("expected one signed-target inspection, got %d", authority.inspectCount)
	}
	if got := response.Header().Get("Content-Security-Policy"); !strings.Contains(got, "form-action 'self' https://auth.example.test;") {
		t.Fatalf("dynamic setup should scope OIDC form destination: %s", got)
	}
}

func TestManagedDynamicSetupCarriesOnlyIntentAcrossOrdinaryLogin(t *testing.T) {
	app, _, _, _, _ := managedDynamicSessionFixture(t)
	request := httptest.NewRequest(http.MethodGet, "/managed-environment/setup?intent="+managedTestIntentRef, nil)
	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `href="/login?dynamic=1"`) {
		t.Fatalf("unauthenticated dynamic setup should render its exact login start: status=%d body=%s", response.Code, response.Body.String())
	}
	loginCookie := cookieByName(t, response.Result().Cookies(), hostDynamicLoginCookie)
	loginRequest := httptest.NewRequest(http.MethodGet, "/login?dynamic=1", nil)
	loginRequest.AddCookie(loginCookie)
	if intentRef, ok := app.readManagedDynamicLoginIntent(loginRequest); !ok || intentRef != managedTestIntentRef {
		t.Fatalf("login continuation should carry only the bounded intent reference: ref=%q ok=%v", intentRef, ok)
	}
}

func TestManagedDynamicSetupAcceptsOnlyProofForCurrentExactTarget(t *testing.T) {
	app, authority, _, sessionCookie, target := managedDynamicSessionFixture(t)
	reservation, err := authority.Reserve(t.Context(), target.IntentRef, target.HumanSessionRef)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	proofWriter := httptest.NewRecorder()
	app.writeManagedDynamicStepUpProof(proofWriter, managedDynamicStepUpProof{
		Schema: managedDynamicStepUpProofDomain, Target: target,
		OperationRef:    reservation.OperationRef,
		AuthenticatedAt: now.Unix(), ExpiresAt: now.Add(managedStepUpProofTTL).Unix(),
	})
	proofCookie := cookieByName(t, proofWriter.Result().Cookies(), hostDynamicProofCookie)

	request := httptest.NewRequest(http.MethodGet, "/managed-environment/setup?intent="+managedTestIntentRef, nil)
	request.AddCookie(sessionCookie)
	request.AddCookie(proofCookie)
	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)
	body := response.Body.String()
	if response.Code != http.StatusOK || !strings.Contains(body, "Add one value") || !strings.Contains(body, "Validation only") || !strings.Contains(body, `name="secret_value"`) || !strings.Contains(body, reservation.OperationRef) || strings.Contains(body, "Confirm with passkey") {
		t.Fatalf("exact proof should unlock only the bounded admission form: status=%d body=%s", response.Code, body)
	}
	if authority.recoverCount != 1 {
		t.Fatalf("refresh did not recover the durable reservation exactly once: %d", authority.recoverCount)
	}

	authority.inspection.Intent.EnvironmentName = "ROTATED_DATABASE_PASSWORD"
	request = httptest.NewRequest(http.MethodGet, "/managed-environment/setup?intent="+managedTestIntentRef, nil)
	request.AddCookie(sessionCookie)
	request.AddCookie(proofCookie)
	response = httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)
	if !strings.Contains(response.Body.String(), "Confirm with passkey") || !managedDynamicCookieCleared(response.Result().Cookies(), hostDynamicProofCookie) {
		t.Fatalf("target drift must invalidate proof and return to confirmation: %s", response.Body.String())
	}
}

func managedDynamicCookieCleared(cookies []*http.Cookie, name string) bool {
	for _, cookie := range cookies {
		if cookie.Name == name && cookie.MaxAge < 0 {
			return true
		}
	}
	return false
}

func TestManagedDynamicStepUpFlowLocksEveryTargetField(t *testing.T) {
	app, authority, session, sessionCookie, target := managedDynamicSessionFixture(t)
	form := url.Values{
		"csrf_token": {app.csrfToken(session)},
		"intent_ref": {managedTestIntentRef},
	}.Encode()
	request := httptest.NewRequest(http.MethodPost, "/managed-environment/setup/step-up", strings.NewReader(form))
	request.Header.Set("Content-Type", managedSecretFormMediaType)
	request.Header.Set("Origin", app.cfg.PublicURL)
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.AddCookie(sessionCookie)
	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)
	if response.Code != http.StatusFound {
		t.Fatalf("expected OIDC redirect, got %d body=%s", response.Code, response.Body.String())
	}
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil || location.Query().Get("prompt") != "login" || location.Query().Get("max_age") != "0" || location.Query().Get("code_challenge") == "" {
		t.Fatalf("step-up must require fresh OIDC plus PKCE: %s", response.Header().Get("Location"))
	}
	callback := httptest.NewRequest(http.MethodGet, "/oidc/callback", nil)
	for _, cookie := range response.Result().Cookies() {
		if cookie.MaxAge > 0 {
			callback.AddCookie(cookie)
		}
	}
	flow, present, err := app.readManagedDynamicStepUpFlow(callback)
	if err != nil || !present || flow.Target != target {
		t.Fatalf("flow should bind every exact target field: present=%v err=%v flow=%#v target=%#v", present, err, flow, target)
	}
	retry, ok := app.readManagedDynamicStepUpRetry(callback)
	if !ok || retry.Target != target || retry.StateHash != flow.StateHash {
		t.Fatalf("retry breadcrumb should bind the same target: %#v", retry)
	}
	if authority.inspectCount != 1 {
		t.Fatalf("step-up start must freshly inspect once, got %d", authority.inspectCount)
	}
}

func TestManagedDynamicStepUpCompletionReinspectsBeforeProof(t *testing.T) {
	app, authority, session, _, target := managedDynamicSessionFixture(t)
	state := "fresh-dynamic-state"
	now := time.Now().UTC()
	flow := managedDynamicStepUpFlow{
		Schema: managedDynamicStepUpFlowDomain, Target: target, StateHash: managedStateHash(state),
		IssuedAt: now.Unix(), ExpiresAt: now.Add(managedStepUpFlowTTL).Unix(),
	}
	request := httptest.NewRequest(http.MethodGet, "/oidc/callback", nil)
	response := httptest.NewRecorder()
	if !app.completeManagedDynamicStepUpCallback(response, request, session, flow, state, now.Unix(), []string{"user", "mfa"}) {
		t.Fatalf("fresh exact assertion should complete: status=%d body=%s", response.Code, response.Body.String())
	}
	proofRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == hostDynamicProofCookie && cookie.MaxAge > 0 {
			proofRequest.AddCookie(cookie)
		}
	}
	proof, ok := app.readManagedDynamicStepUpProof(proofRequest)
	if !ok || proof.Target != target || !validManagedRef("op_", proof.OperationRef) {
		t.Fatalf("completion should mint an exact-target proof: %#v", proof)
	}

	authority.inspection.Intent.EnvironmentPolicyFingerprint = "envpf_fedcba9876543210"
	response = httptest.NewRecorder()
	if app.completeManagedDynamicStepUpCallback(response, request, session, flow, state, now.Unix(), []string{"user", "mfa"}) || response.Code != http.StatusForbidden {
		t.Fatalf("policy drift during passkey round-trip must fail closed: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestManagedDynamicStepUpCompletionReservesOnceBeforeIssuingProof(t *testing.T) {
	app, authority, session, _, target := managedDynamicSessionFixture(t)
	state := "single-use-dynamic-state"
	now := time.Now().UTC()
	flow := managedDynamicStepUpFlow{
		Schema: managedDynamicStepUpFlowDomain, Target: target, StateHash: managedStateHash(state),
		IssuedAt: now.Unix(), ExpiresAt: now.Add(managedStepUpFlowTTL).Unix(),
	}
	request := httptest.NewRequest(http.MethodGet, "/oidc/callback", nil)
	first := httptest.NewRecorder()
	if !app.completeManagedDynamicStepUpCallback(first, request, session, flow, state, now.Unix(), []string{"user", "mfa"}) {
		t.Fatalf("first exact passkey callback did not reserve: status=%d body=%s", first.Code, first.Body.String())
	}
	if authority.reserveCount != 1 || authority.reservation == nil {
		t.Fatalf("proof was issued without one durable reservation: reserve=%d reservation=%#v", authority.reserveCount, authority.reservation)
	}

	duplicate := httptest.NewRecorder()
	if app.completeManagedDynamicStepUpCallback(duplicate, request, session, flow, state, now.Unix(), []string{"user", "mfa"}) || duplicate.Code != http.StatusConflict {
		t.Fatalf("duplicate passkey callback was accepted: status=%d body=%s", duplicate.Code, duplicate.Body.String())
	}
	if authority.reserveCount != 2 || !strings.Contains(duplicate.Body.String(), "already used") {
		t.Fatalf("duplicate did not fail at single-use reservation: reserve=%d body=%s", authority.reserveCount, duplicate.Body.String())
	}
}

func TestManagedDynamicStepUpDenialNeverReservesIntent(t *testing.T) {
	app, authority, session, _, target := managedDynamicSessionFixture(t)
	state := "denied-dynamic-state"
	now := time.Now().UTC()
	flow := managedDynamicStepUpFlow{
		Schema: managedDynamicStepUpFlowDomain, Target: target, StateHash: managedStateHash(state),
		IssuedAt: now.Unix(), ExpiresAt: now.Add(managedStepUpFlowTTL).Unix(),
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/oidc/callback", nil)
	if app.completeManagedDynamicStepUpCallback(response, request, session, flow, state, now.Unix(), []string{"pwd"}) || response.Code != http.StatusForbidden {
		t.Fatalf("non-passkey assertion was accepted: status=%d body=%s", response.Code, response.Body.String())
	}
	if authority.reserveCount != 0 || authority.reservation != nil {
		t.Fatalf("denied assertion consumed replay budget: reserve=%d reservation=%#v", authority.reserveCount, authority.reservation)
	}
}

func TestManagedDynamicStepUpCompletionRejectsEveryTargetSubstitution(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(*managedDynamicStepUpTarget)
	}{
		{name: "intent", mutate: func(target *managedDynamicStepUpTarget) { target.IntentRef = "intent_fedcba9876543210" }},
		{name: "operation", mutate: func(target *managedDynamicStepUpTarget) { target.OperationKind = "replace" }},
		{name: "source", mutate: func(target *managedDynamicStepUpTarget) { target.Source = "generated" }},
		{name: "host", mutate: func(target *managedDynamicStepUpTarget) { target.HostRef = "host_fedcba9876543210" }},
		{name: "service", mutate: func(target *managedDynamicStepUpTarget) { target.ServiceRef = "svc_fedcba9876543210" }},
		{name: "policy", mutate: func(target *managedDynamicStepUpTarget) { target.EnvironmentPolicyRef = "envpol_fedcba9876543210" }},
		{name: "policy fingerprint", mutate: func(target *managedDynamicStepUpTarget) {
			target.EnvironmentPolicyFingerprint = "envpf_fedcba9876543210"
		}},
		{name: "declaration", mutate: func(target *managedDynamicStepUpTarget) { target.DeclarationFingerprint = "decl_fedcba9876543210" }},
		{name: "environment name", mutate: func(target *managedDynamicStepUpTarget) { target.EnvironmentName = "ROTATED_DATABASE_PASSWORD" }},
		{name: "human session", mutate: func(target *managedDynamicStepUpTarget) { target.HumanSessionRef = "hsn_fedcba9876543210" }},
		{name: "issuer", mutate: func(target *managedDynamicStepUpTarget) { target.IssuerRef = "sys_other_control_plane" }},
		{name: "audience", mutate: func(target *managedDynamicStepUpTarget) { target.AudienceRef = "sys_other_custody" }},
		{name: "nonce", mutate: func(target *managedDynamicStepUpTarget) { target.NonceRef = "nonce_fedcba9876543210" }},
		{name: "issued time", mutate: func(target *managedDynamicStepUpTarget) { target.IntentIssuedAt-- }},
		{name: "expiry", mutate: func(target *managedDynamicStepUpTarget) { target.IntentExpiresAt-- }},
		{name: "return target", mutate: func(target *managedDynamicStepUpTarget) { target.ReturnTarget = "other" }},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			app, authority, session, _, target := managedDynamicSessionFixture(t)
			test.mutate(&target)
			now := time.Now().UTC()
			state := "substitution-state"
			flow := managedDynamicStepUpFlow{
				Schema: managedDynamicStepUpFlowDomain, Target: target, StateHash: managedStateHash(state),
				IssuedAt: now.Unix(), ExpiresAt: now.Add(managedStepUpFlowTTL).Unix(),
			}
			request := httptest.NewRequest(http.MethodGet, "/oidc/callback", nil)
			response := httptest.NewRecorder()
			if app.completeManagedDynamicStepUpCallback(response, request, session, flow, state, now.Unix(), []string{"user", "mfa"}) || response.Code != http.StatusForbidden {
				t.Fatalf("%s substitution must fail closed: status=%d body=%s", test.name, response.Code, response.Body.String())
			}
			if authority.reserveCount != 0 {
				t.Fatalf("%s substitution consumed replay budget", test.name)
			}
		})
	}
}

func TestManagedDynamicInspectionRejectsAuthorityContextDrift(t *testing.T) {
	mutations := []struct {
		name   string
		mutate func(*managedDynamicSetupInspection)
	}{
		{name: "policy reference", mutate: func(inspection *managedDynamicSetupInspection) {
			inspection.Context.EnvironmentPolicyRef = "envpol_fedcba9876543210"
		}},
		{name: "policy fingerprint", mutate: func(inspection *managedDynamicSetupInspection) {
			inspection.Context.EnvironmentPolicyFingerprint = "envpf_fedcba9876543210"
		}},
		{name: "source", mutate: func(inspection *managedDynamicSetupInspection) {
			inspection.Context.AllowedSources = []string{"generated"}
		}},
		{name: "consumer", mutate: func(inspection *managedDynamicSetupInspection) { inspection.Context.ConsumerKind = "other" }},
		{name: "delivery", mutate: func(inspection *managedDynamicSetupInspection) { inspection.Context.DeliveryKind = "other" }},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			app, authority, session, _, _ := managedDynamicSessionFixture(t)
			test.mutate(&authority.inspection)
			if _, err := app.inspectManagedDynamicSetupIntent(context.Background(), session, managedTestIntentRef); err == nil {
				t.Fatalf("%s drift should fail at the authority adapter", test.name)
			}
		})
	}
}

func TestManagedDynamicAndDeclaredSlotFlowsCannotMix(t *testing.T) {
	app, _, _, _, target := managedDynamicSessionFixture(t)
	app.verifier = &oidc.IDTokenVerifier{}
	now := time.Now().UTC()
	writer := httptest.NewRecorder()
	app.writeManagedStepUpFlow(writer, managedStepUpFlow{
		Schema: managedStepUpFlowDomain, IntentRef: target.IntentRef, Source: target.Source,
		HumanSessionRef: target.HumanSessionRef, StateHash: managedStateHash("mixed"),
		IssuedAt: now.Unix(), ExpiresAt: now.Add(managedStepUpFlowTTL).Unix(),
	})
	app.writeManagedDynamicStepUpFlow(writer, managedDynamicStepUpFlow{
		Schema: managedDynamicStepUpFlowDomain, Target: target, StateHash: managedStateHash("mixed"),
		IssuedAt: now.Unix(), ExpiresAt: now.Add(managedStepUpFlowTTL).Unix(),
	})
	request := httptest.NewRequest(http.MethodGet, "/oidc/callback?state=mixed&code=unused", nil)
	for _, cookie := range writer.Result().Cookies() {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	app.handleCallback(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "passwordless_step_up_failed") {
		t.Fatalf("mixed v1/v2 flows must fail before identity exchange: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestManagedDynamicSetupRemainsDisabledWithoutExplicitAuthority(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false
	request := httptest.NewRequest(http.MethodGet, "/managed-environment/setup?intent="+managedTestIntentRef, nil)
	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || strings.Contains(response.Body.String(), "DATABASE_PASSWORD") {
		t.Fatalf("unwired production path must fail closed and value-free: status=%d body=%s", response.Code, response.Body.String())
	}
}
