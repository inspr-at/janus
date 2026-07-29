package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

const (
	managedTestSubject   = "managed-user-357"
	managedTestIntentRef = "intent_0123456789abcdef"
	managedTestOpRef     = "op_0123456789abcdef"
	managedTestSecretRef = "sec_0000000000000000"
)

type fakeManagedIntentAuthority struct {
	intent         managedSetupIntent
	inspectCount   int
	consumeCount   int
	recoverCount   int
	inspectErr     error
	consumeErr     error
	replayAfterOne bool
}

func (fake *fakeManagedIntentAuthority) Inspect(_ context.Context, intentRef, humanSessionRef string) (managedSetupInspection, error) {
	fake.inspectCount++
	if fake.inspectErr != nil {
		return managedSetupInspection{}, fake.inspectErr
	}
	if intentRef != fake.intent.IntentRef || humanSessionRef != fake.intent.HumanSessionRef {
		return managedSetupInspection{}, managedIntentError("managed_intent_wrong_user")
	}
	bindingState := "required"
	detachProfileRef := ""
	if fake.intent.OperationKind == "remove" {
		bindingState = "detached"
		detachProfileRef = "detach_0123456789abcdef"
	}
	return managedSetupInspection{
		Intent: fake.intent,
		Context: managedDeclarationContext{
			ServiceLabel:       "Canary service",
			SlotLabel:          "Admin password",
			ConsumerKind:       "managed_service",
			DeliveryKind:       "private_env_file",
			DeliveryProfileRef: "delivery_2d7a0f63c951",
			ReloadProfileRef:   "reload_65bc19f3a087",
			HealthProfileRef:   "health_918d0ce7b4a2",
			BindingState:       bindingState,
			DetachProfileRef:   detachProfileRef,
			AllowedSources:     append([]string(nil), fake.intent.AllowedSources...),
		},
	}, nil
}

func (fake *fakeManagedIntentAuthority) Consume(_ context.Context, intentRef, humanSessionRef, source string) (managedAcceptedIntent, error) {
	fake.consumeCount++
	if fake.consumeErr != nil {
		return managedAcceptedIntent{}, fake.consumeErr
	}
	if fake.replayAfterOne && fake.consumeCount > 1 {
		return managedAcceptedIntent{}, managedIntentError("managed_intent_replayed")
	}
	if intentRef != fake.intent.IntentRef || humanSessionRef != fake.intent.HumanSessionRef {
		return managedAcceptedIntent{}, managedIntentError("managed_intent_wrong_user")
	}
	if fake.intent.OperationKind == "remove" && source != "remove" ||
		fake.intent.OperationKind != "remove" && !containsManagedSource(fake.intent.AllowedSources, source) {
		return managedAcceptedIntent{}, managedIntentError("managed_intent_source_denied")
	}
	bindingState := "required"
	detachProfileRef := ""
	if fake.intent.OperationKind == "remove" {
		bindingState = "detached"
		detachProfileRef = "detach_0123456789abcdef"
	}
	return managedAcceptedIntent{
		Intent:       fake.intent,
		Source:       source,
		OperationRef: managedTestOpRef,
		Context: managedDeclarationContext{
			ServiceLabel:       "Canary service",
			SlotLabel:          "Admin password",
			ConsumerKind:       "managed_service",
			DeliveryKind:       "private_env_file",
			DeliveryProfileRef: "delivery_2d7a0f63c951",
			ReloadProfileRef:   "reload_65bc19f3a087",
			HealthProfileRef:   "health_918d0ce7b4a2",
			BindingState:       bindingState,
			DetachProfileRef:   detachProfileRef,
			AllowedSources:     append([]string(nil), fake.intent.AllowedSources...),
		},
	}, nil
}

func (fake *fakeManagedIntentAuthority) Recover(_ context.Context, intentRef, humanSessionRef, source string) (managedAcceptedIntent, error) {
	if fake.consumeCount == 0 {
		return managedAcceptedIntent{}, managedIntentError("managed_intent_recovery_unavailable")
	}
	fake.recoverCount++
	if intentRef != fake.intent.IntentRef || humanSessionRef != fake.intent.HumanSessionRef {
		return managedAcceptedIntent{}, managedIntentError("managed_intent_wrong_user")
	}
	if fake.intent.OperationKind == "remove" && source != "remove" ||
		fake.intent.OperationKind != "remove" && !containsManagedSource(fake.intent.AllowedSources, source) {
		return managedAcceptedIntent{}, managedIntentError("managed_intent_source_denied")
	}
	bindingState := "required"
	detachProfileRef := ""
	if fake.intent.OperationKind == "remove" {
		bindingState = "detached"
		detachProfileRef = "detach_0123456789abcdef"
	}
	return managedAcceptedIntent{
		Intent:       fake.intent,
		Source:       source,
		OperationRef: managedTestOpRef,
		Context: managedDeclarationContext{
			ServiceLabel:       "Canary service",
			SlotLabel:          "Admin password",
			ConsumerKind:       "managed_service",
			DeliveryKind:       "private_env_file",
			DeliveryProfileRef: "delivery_2d7a0f63c951",
			ReloadProfileRef:   "reload_65bc19f3a087",
			HealthProfileRef:   "health_918d0ce7b4a2",
			BindingState:       bindingState,
			DetachProfileRef:   detachProfileRef,
			AllowedSources:     append([]string(nil), fake.intent.AllowedSources...),
		},
	}, nil
}

type fakeManagedTransactionExecutor struct {
	count          int
	recoverCount   int
	expectedValue  []byte
	valueObserved  bool
	retainedBuffer []byte
	err            error
	result         managedTransactionResult
}

func (fake *fakeManagedTransactionExecutor) Execute(_ context.Context, accepted managedAcceptedIntent, importedValue []byte) (managedTransactionResult, error) {
	fake.count++
	fake.valueObserved = bytes.Equal(importedValue, fake.expectedValue)
	fake.retainedBuffer = importedValue
	if accepted.OperationRef != managedTestOpRef {
		return managedTransactionResult{}, errors.New("unexpected operation")
	}
	if fake.err != nil {
		return managedTransactionResult{}, fake.err
	}
	return fake.result, nil
}

func (fake *fakeManagedTransactionExecutor) Recover(_ context.Context, accepted managedAcceptedIntent) error {
	if fake.count == 0 ||
		accepted.OperationRef != fake.result.OperationRef ||
		accepted.Source != fake.result.Mode {
		return managedTransactionError("managed_operation_recovery_unavailable")
	}
	fake.recoverCount++
	return nil
}

type managedReadOrderSpy struct {
	body           []byte
	offset         int
	secretOffset   int
	intentConsumed *bool
	earlyRead      bool
}

func (spy *managedReadOrderSpy) Read(target []byte) (int, error) {
	if spy.offset >= len(spy.body) {
		return 0, io.EOF
	}
	if spy.offset >= spy.secretOffset && !*spy.intentConsumed {
		spy.earlyRead = true
	}
	count := copy(target, spy.body[spy.offset:])
	spy.offset += count
	return count, nil
}

func managedIngressFixture(t *testing.T, source string) (*App, *fakeManagedIntentAuthority, *fakeManagedTransactionExecutor, Session, *http.Cookie, *http.Cookie) {
	t.Helper()
	app := newTestApp(t)
	app.oauth = testOAuthConfig()
	app.cfg.ManagedSetup = &managedSetupRuntimeConfig{
		PharosReturnOrigin: "https://pharos.barta.cm",
	}
	session := Session{
		Subject: managedTestSubject,
		Roles:   []string{RoleViewer, RoleOwner},
		Expiry:  time.Now().UTC().Add(time.Hour),
	}
	intent := managedSetupIntent{
		Schema:                 managedSetupIntentSchema,
		SchemaVersion:          managedIntentContractVersion,
		IntentRef:              managedTestIntentRef,
		OperationKind:          "create",
		AllowedSources:         []string{"generated", "import"},
		HostRef:                "host_0123456789abcdef",
		ServiceRef:             "svc_0123456789abcdef",
		SlotRef:                "slot_0123456789abcdef",
		HumanSessionRef:        managedHumanSessionRef(app.cfg.OIDCIssuer, session.Subject),
		IssuerRef:              managedSetupExpectedIssuerRef,
		AudienceRef:            managedSetupExpectedAudienceRef,
		NonceRef:               "nonce_0123456789abcdef",
		DeclarationFingerprint: "decl_0123456789abcdef",
		IssuedAtUnixSeconds:    time.Now().UTC().Add(-time.Minute).Unix(),
		ExpiresAtUnixSeconds:   time.Now().UTC().Add(time.Minute).Unix(),
		ReturnTarget:           "pharos_service",
	}
	if source == "remove" {
		intent.OperationKind = "remove"
		intent.AllowedSources = nil
	}
	authority := &fakeManagedIntentAuthority{intent: intent}
	executor := &fakeManagedTransactionExecutor{result: managedTransactionResult{
		OperationRef:  managedTestOpRef,
		SecretRef:     managedTestSecretRef,
		Mode:          source,
		Generation:    1,
		Phase:         "registered",
		ReasonCode:    "managed_operation_registered",
		ValueReturned: false,
	}}
	app.managedSetup = authority
	app.managedTxn = executor

	sessionWriter := httptest.NewRecorder()
	app.writeSession(sessionWriter, session)
	sessionCookie := cookieByName(t, sessionWriter.Result().Cookies(), hostSessionCookie)
	now := time.Now().UTC()
	proofWriter := httptest.NewRecorder()
	app.writeManagedStepUpProof(proofWriter, managedStepUpProof{
		Schema:          managedStepUpProofDomain,
		IntentRef:       managedTestIntentRef,
		Source:          source,
		HumanSessionRef: intent.HumanSessionRef,
		AuthenticatedAt: now.Unix(),
		ExpiresAt:       now.Add(managedStepUpProofTTL).Unix(),
	})
	proofCookie := cookieByName(t, proofWriter.Result().Cookies(), hostStepUpProofCookie)
	return app, authority, executor, session, sessionCookie, proofCookie
}

func managedRequest(t *testing.T, app *App, session Session, sessionCookie, proofCookie *http.Cookie, body io.Reader, bodyLength int64) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/managed-service/setup/execute", body)
	request.ContentLength = bodyLength
	request.Header.Set("Content-Type", managedSecretFormMediaType)
	request.Header.Set("Origin", app.cfg.PublicURL)
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.AddCookie(sessionCookie)
	if proofCookie != nil {
		request.AddCookie(proofCookie)
	}
	if app.csrfToken(session) == "" {
		t.Fatal("test session should have a CSRF token")
	}
	return request
}

func TestManagedSetupPageRequiresPasskeyBeforeRenderingValueInput(t *testing.T) {
	app, authority, _, _, sessionCookie, proofCookie := managedIngressFixture(t, "import")

	request := httptest.NewRequest(http.MethodGet, "/managed-service/setup?intent="+managedTestIntentRef, nil)
	request.AddCookie(sessionCookie)
	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("expected setup page, got %d body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, "Confirm with passkey") ||
		!strings.Contains(body, `name="source"`) ||
		!strings.Contains(body, "Generate securely") ||
		!strings.Contains(body, "Use my own value") ||
		!strings.Contains(body, "Canary service") ||
		!strings.Contains(body, "Admin password") ||
		strings.Contains(body, `name="secret_value"`) ||
		strings.Contains(body, `type="password"`) {
		t.Fatalf("value input must remain absent before step-up: %s", body)
	}

	request = httptest.NewRequest(http.MethodGet, "/managed-service/setup?intent="+managedTestIntentRef, nil)
	request.AddCookie(sessionCookie)
	request.AddCookie(proofCookie)
	response = httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)
	body = response.Body.String()
	for _, expected := range []string{
		`type="password"`,
		`name="secret_value"`,
		`autocomplete="off"`,
		`data-1p-ignore`,
		`data-bwignore`,
		"will not display it again",
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("stepped-up page should contain %q: %s", expected, body)
		}
	}
	if authority.inspectCount != 2 || strings.Contains(body, "JANUS_IMPORT_CANARY_357") {
		t.Fatalf("setup page should inspect twice and remain value-free: count=%d body=%s", authority.inspectCount, body)
	}
	if got := response.Header().Get("Cache-Control"); got != "no-store, no-transform" {
		t.Fatalf("managed setup must not be cached or transformed, got %q", got)
	}
	if got := response.Header().Get("Content-Encoding"); got != "identity" {
		t.Fatalf("managed setup must not be compressed, got %q", got)
	}
	for header, expected := range map[string]string{
		"Content-Security-Policy":      "script-src 'none'",
		"Referrer-Policy":              "origin",
		"Cross-Origin-Resource-Policy": "same-origin",
	} {
		if got := response.Header().Get(header); !strings.Contains(got, expected) {
			t.Fatalf("managed setup %s should contain %q, got %q", header, expected, got)
		}
	}
	csp := response.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "form-action 'self' https://auth.example.test;") ||
		strings.Contains(csp, "/oauth/v2/authorize") {
		t.Fatalf("managed setup CSP must allow only the configured OIDC authorization origin: %s", csp)
	}

	healthRequest := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	healthResponse := httptest.NewRecorder()
	app.routes().ServeHTTP(healthResponse, healthRequest)
	healthCSP := healthResponse.Header().Get("Content-Security-Policy")
	if !strings.Contains(healthCSP, "form-action 'self';") ||
		strings.Contains(healthCSP, "auth.example.test") {
		t.Fatalf("OIDC form destination must stay scoped to the managed setup page: %s", healthCSP)
	}
}

func TestManagedSetupFailureStatesStayPlainValueFreeAndRetryable(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
	}{
		{name: "expired intent", err: managedIntentError("managed_intent_expired"), status: http.StatusConflict},
		{name: "stale declaration", err: managedIntentError("managed_intent_declaration_drift"), status: http.StatusConflict},
		{name: "Pharos offline", err: managedIntentError("managed_intent_pharos_unavailable"), status: http.StatusServiceUnavailable},
		{name: "declaration unavailable", err: managedIntentError("managed_intent_declaration_unavailable"), status: http.StatusServiceUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			app, authority, _, _, sessionCookie, _ := managedIngressFixture(t, "generated")
			authority.inspectErr = test.err
			request := httptest.NewRequest(http.MethodGet, "/managed-service/setup?intent="+managedTestIntentRef, nil)
			request.AddCookie(sessionCookie)
			response := httptest.NewRecorder()
			app.routes().ServeHTTP(response, request)
			if response.Code != test.status ||
				!strings.Contains(response.Body.String(), "Start again from Pharos") ||
				strings.Contains(response.Body.String(), managedTestIntentRef) {
				t.Fatalf("unsafe failure state: status=%d body=%s", response.Code, response.Body.String())
			}
			if got := response.Header().Get("Cache-Control"); got != "no-store, no-transform" {
				t.Fatalf("failure response crossed managed cache boundary: %q", got)
			}
		})
	}
}

func TestUnauthenticatedManagedSetupPreservesOnlySignedIntentAcrossLogin(t *testing.T) {
	app, _, _, _, _, _ := managedIngressFixture(t, "generated")
	request := httptest.NewRequest(http.MethodGet, "/managed-service/setup?intent="+managedTestIntentRef, nil)
	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)
	if response.Code != http.StatusOK ||
		!strings.Contains(response.Body.String(), `href="/login?managed=1"`) {
		t.Fatalf("managed setup should render a login choice without losing the intent: status=%d body=%s", response.Code, response.Body.String())
	}
	loginIntentCookie := cookieByName(t, response.Result().Cookies(), hostManagedLoginCookie)
	if !loginIntentCookie.HttpOnly ||
		!loginIntentCookie.Secure ||
		loginIntentCookie.SameSite != http.SameSiteLaxMode ||
		strings.Contains(loginIntentCookie.Value, managedTestIntentRef) {
		t.Fatalf("managed login intent cookie must be opaque, signed, secure, and lax: %#v", loginIntentCookie)
	}
	cookieRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	cookieRequest.AddCookie(loginIntentCookie)
	if intentRef, ok := app.readManagedLoginIntent(cookieRequest); !ok || intentRef != managedTestIntentRef {
		t.Fatalf("managed login cookie did not recover the exact intent: ref=%q ok=%v", intentRef, ok)
	}

	login := httptest.NewRequest(http.MethodGet, "/login?managed=1", nil)
	login.AddCookie(loginIntentCookie)
	loginResponse := httptest.NewRecorder()
	app.handleLogin(loginResponse, login)
	if loginResponse.Code != http.StatusFound {
		t.Fatalf("managed login should start OIDC, got %d body=%s", loginResponse.Code, loginResponse.Body.String())
	}
	for _, cookie := range loginResponse.Result().Cookies() {
		if cookie.Name == hostManagedLoginCookie && cookie.MaxAge < 0 {
			t.Fatalf("managed login start unexpectedly cleared its signed intent: %#v", cookie)
		}
	}

	ordinaryLogin := httptest.NewRequest(http.MethodGet, "/login", nil)
	ordinaryLogin.AddCookie(loginIntentCookie)
	ordinaryResponse := httptest.NewRecorder()
	app.handleLogin(ordinaryResponse, ordinaryLogin)
	cleared := false
	for _, cookie := range ordinaryResponse.Result().Cookies() {
		if cookie.Name == hostManagedLoginCookie && cookie.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("ordinary login should clear a stale managed setup intent")
	}
}

func TestManagedStepUpStartsFreshPasswordlessOIDCFlow(t *testing.T) {
	app, authority, _, session, sessionCookie, _ := managedIngressFixture(t, "generated")
	form := url.Values{
		"csrf_token": {app.csrfToken(session)},
		"intent_ref": {managedTestIntentRef},
		"source":     {"generated"},
	}.Encode()
	request := httptest.NewRequest(http.MethodPost, "/managed-service/setup/step-up", strings.NewReader(form))
	request.Header.Set("Content-Type", managedSecretFormMediaType)
	request.Header.Set("Origin", app.cfg.PublicURL)
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.AddCookie(sessionCookie)
	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)
	if response.Code != http.StatusFound {
		t.Fatalf("expected OIDC redirect, got %d body=%s", response.Code, response.Body.String())
	}
	target, err := url.Parse(response.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if target.Query().Get("prompt") != "login" ||
		target.Query().Get("max_age") != "0" ||
		target.Query().Get("nonce") == "" ||
		target.Query().Get("code_challenge") == "" ||
		target.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("step-up redirect is not fresh passwordless PKCE: %s", target.String())
	}
	cookies := response.Result().Cookies()
	flowCookie := cookieByName(t, cookies, hostStepUpFlowCookie)
	retryCookie := cookieByName(t, cookies, hostStepUpRetryCookie)
	stateCookie := cookieByName(t, cookies, hostStateCookie)
	if !flowCookie.HttpOnly || !flowCookie.Secure || flowCookie.SameSite != http.SameSiteLaxMode ||
		!retryCookie.HttpOnly || !retryCookie.Secure || retryCookie.SameSite != http.SameSiteLaxMode ||
		retryCookie.MaxAge != int(managedStepUpRetryTTL/time.Second) ||
		stateCookie.Value == "" || authority.inspectCount != 1 {
		t.Fatalf("step-up cookies or intent inspection are invalid: cookies=%#v inspect=%d", cookies, authority.inspectCount)
	}
	callback := httptest.NewRequest(http.MethodGet, "/oidc/callback", nil)
	callback.AddCookie(flowCookie)
	flow, present, err := app.readManagedStepUpFlow(callback)
	if err != nil || !present ||
		flow.IntentRef != managedTestIntentRef ||
		flow.Source != "generated" ||
		flow.StateHash != managedStateHash(stateCookie.Value) ||
		flow.HumanSessionRef != authority.intent.HumanSessionRef {
		t.Fatalf("signed step-up flow is not bound: flow=%#v present=%v err=%v", flow, present, err)
	}
	callback.AddCookie(retryCookie)
	retry, ok := app.readManagedStepUpRetry(callback)
	if !ok ||
		retry.IntentRef != managedTestIntentRef ||
		retry.StateHash != managedStateHash(stateCookie.Value) {
		t.Fatalf("step-up retry breadcrumb is not exactly bound: retry=%#v ok=%v", retry, ok)
	}
}

func TestManagedStepUpExpiredOIDCStateReturnsToExactConfirm(t *testing.T) {
	cases := []struct {
		name    string
		target  string
		cookies []*http.Cookie
	}{
		{
			name:   "provider cancellation",
			target: "/oidc/callback?error=access_denied&state=expired",
		},
		{
			name:   "state cookie expired",
			target: "/oidc/callback?state=expired&code=unused",
		},
		{
			name:   "nonce cookie expired",
			target: "/oidc/callback?state=expired&code=unused",
			cookies: []*http.Cookie{
				{Name: hostStateCookie, Value: "expired"},
			},
		},
		{
			name:   "pkce cookie expired",
			target: "/oidc/callback?state=expired&code=unused",
			cookies: []*http.Cookie{
				{Name: hostStateCookie, Value: "expired"},
				{Name: hostNonceCookie, Value: "nonce"},
			},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			app, _, executor, _, _, _ := managedIngressFixture(t, "generated")
			app.verifier = &oidc.IDTokenVerifier{}
			now := time.Now().UTC()
			writer := httptest.NewRecorder()
			app.writeManagedStepUpRetry(writer, managedStepUpRetry{
				Schema:    managedStepUpRetryDomain,
				IntentRef: managedTestIntentRef,
				StateHash: managedStateHash("expired"),
				IssuedAt:  now.Add(-7 * time.Minute).Unix(),
				ExpiresAt: now.Add(8 * time.Minute).Unix(),
			})
			retryCookie := cookieByName(t, writer.Result().Cookies(), hostStepUpRetryCookie)
			request := httptest.NewRequest(http.MethodGet, test.target, nil)
			request.Header.Set("X-Request-Id", "managed-step-up-expired-state")
			request.AddCookie(retryCookie)
			for _, cookie := range test.cookies {
				request.AddCookie(cookie)
			}
			response := httptest.NewRecorder()
			app.routes().ServeHTTP(response, request)

			wantTarget := "/managed-service/setup?intent=" + managedTestIntentRef
			if response.Code != http.StatusOK ||
				response.Header().Get("Refresh") != "0; url="+wantTarget ||
				!strings.Contains(response.Body.String(), `href="`+wantTarget+`"`) ||
				!strings.Contains(response.Body.String(), "Passkey check expired") ||
				!strings.Contains(response.Body.String(), "Nothing changed.") ||
				!strings.Contains(response.Body.String(), "value_returned=false") {
				t.Fatalf(
					"expired OIDC state did not recover to exact Confirm: status=%d refresh=%q body=%s",
					response.Code,
					response.Header().Get("Refresh"),
					response.Body.String(),
				)
			}
			if executor.count != 0 {
				t.Fatalf("OIDC recovery must not execute a transaction: count=%d", executor.count)
			}
			retryCleared := false
			for _, cookie := range response.Result().Cookies() {
				if cookie.Name == hostSessionCookie && cookie.Value != "" ||
					cookie.Name == hostStepUpProofCookie ||
					cookie.Name == hostAttemptCookie {
					t.Fatalf("OIDC recovery must not mint or revoke unrelated authority: %#v", cookie)
				}
				if cookie.Name == hostStepUpRetryCookie && cookie.MaxAge < 0 && cookie.Value == "" {
					retryCleared = true
				}
			}
			if !retryCleared {
				t.Fatalf("OIDC recovery should consume its retry breadcrumb: %#v", response.Result().Cookies())
			}
			audit := app.store.RecentAudit(1)
			if len(audit) != 1 ||
				audit[0].Action != "managed_secret.step_up.recover" ||
				audit[0].Outcome != "denied" {
				t.Fatalf("expired recovery should remain a denied auth outcome: %#v", audit)
			}
		})
	}
}

func TestManagedStepUpInvalidRetryCannotRecoverCallback(t *testing.T) {
	app, _, executor, _, _, _ := managedIngressFixture(t, "generated")
	app.verifier = &oidc.IDTokenVerifier{}
	request := httptest.NewRequest(http.MethodGet, "/oidc/callback?state=expired&code=unused", nil)
	request.AddCookie(&http.Cookie{Name: hostStepUpRetryCookie, Value: "tampered"})
	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest ||
		!strings.Contains(response.Body.String(), "login_restart_required") ||
		strings.Contains(response.Body.String(), "Return to Confirm") ||
		executor.count != 0 {
		t.Fatalf("invalid retry breadcrumb must fail closed: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestManagedStepUpRetryCannotCaptureUnrelatedLoginFailure(t *testing.T) {
	app, _, executor, _, _, _ := managedIngressFixture(t, "generated")
	app.verifier = &oidc.IDTokenVerifier{}
	now := time.Now().UTC()
	writer := httptest.NewRecorder()
	app.writeManagedStepUpRetry(writer, managedStepUpRetry{
		Schema:    managedStepUpRetryDomain,
		IntentRef: managedTestIntentRef,
		StateHash: managedStateHash("managed-state"),
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(managedStepUpRetryTTL).Unix(),
	})
	request := httptest.NewRequest(http.MethodGet, "/oidc/callback?state=ordinary-login-state&code=unused", nil)
	request.AddCookie(cookieByName(t, writer.Result().Cookies(), hostStepUpRetryCookie))
	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest ||
		!strings.Contains(response.Body.String(), "login_restart_required") ||
		strings.Contains(response.Body.String(), "Return to Confirm") ||
		executor.count != 0 {
		t.Fatalf("unrelated callback must remain an ordinary denied login: status=%d body=%s", response.Code, response.Body.String())
	}
	audit := app.store.RecentAudit(1)
	if len(audit) != 1 ||
		audit[0].Action != "auth.login.callback" ||
		audit[0].Outcome != "denied" ||
		audit[0].Reason != "bad state" {
		t.Fatalf("unrelated callback audit was misclassified: %#v", audit)
	}
}

func TestManagedStepUpRetryRejectsInvalidPayloads(t *testing.T) {
	app, _, _, _, _, _ := managedIngressFixture(t, "generated")
	now := time.Now().UTC()
	valid := managedStepUpRetry{
		Schema:    managedStepUpRetryDomain,
		IntentRef: managedTestIntentRef,
		StateHash: managedStateHash("managed-state"),
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(managedStepUpRetryTTL).Unix(),
	}
	cases := []struct {
		name   string
		mutate func(*managedStepUpRetry)
	}{
		{name: "wrong schema", mutate: func(retry *managedStepUpRetry) {
			retry.Schema = "other"
		}},
		{name: "malformed intent", mutate: func(retry *managedStepUpRetry) {
			retry.IntentRef = "intent_../other"
		}},
		{name: "malformed state hash", mutate: func(retry *managedStepUpRetry) {
			retry.StateHash = "not-a-hash"
		}},
		{name: "issued in future", mutate: func(retry *managedStepUpRetry) {
			retry.IssuedAt = now.Add(managedStepUpClockSkew + time.Second).Unix()
		}},
		{name: "expired", mutate: func(retry *managedStepUpRetry) {
			retry.IssuedAt = now.Add(-managedStepUpRetryTTL - time.Minute).Unix()
			retry.ExpiresAt = now.Add(-time.Minute).Unix()
		}},
		{name: "ttl over ceiling", mutate: func(retry *managedStepUpRetry) {
			retry.ExpiresAt = now.Add(managedStepUpRetryTTL + time.Second).Unix()
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			retry := valid
			test.mutate(&retry)
			writer := httptest.NewRecorder()
			app.writeManagedStepUpRetry(writer, retry)
			request := httptest.NewRequest(http.MethodGet, "/oidc/callback", nil)
			request.AddCookie(cookieByName(t, writer.Result().Cookies(), hostStepUpRetryCookie))
			if got, ok := app.readManagedStepUpRetry(request); ok {
				t.Fatalf("invalid retry payload was accepted: %#v", got)
			}
		})
	}
}

func TestManagedStepUpRejectsSourceOutsideDeclaration(t *testing.T) {
	app, authority, _, session, sessionCookie, _ := managedIngressFixture(t, "generated")
	authority.intent.AllowedSources = []string{"generated"}
	form := url.Values{
		"csrf_token": {app.csrfToken(session)},
		"intent_ref": {managedTestIntentRef},
		"source":     {"import"},
	}.Encode()
	request := httptest.NewRequest(http.MethodPost, "/managed-service/setup/step-up", strings.NewReader(form))
	request.Header.Set("Content-Type", managedSecretFormMediaType)
	request.Header.Set("Origin", app.cfg.PublicURL)
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.AddCookie(sessionCookie)
	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || response.Header().Get("Location") != "" {
		t.Fatalf("unreviewed source must not reach OIDC: status=%d location=%q body=%s", response.Code, response.Header().Get("Location"), response.Body.String())
	}
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == hostStepUpFlowCookie && cookie.Value != "" {
			t.Fatalf("unreviewed source minted a step-up flow: %#v", cookie)
		}
	}
}

func TestPasswordlessAssertionRequiresExactZitadelPasskeyAMR(t *testing.T) {
	now := time.Now().UTC()
	cases := []struct {
		name     string
		authTime int64
		amr      []string
		want     bool
	}{
		{name: "passwordless", authTime: now.Unix(), amr: []string{"user", "mfa"}, want: true},
		{name: "order independent", authTime: now.Unix(), amr: []string{"mfa", "user"}, want: true},
		{name: "attended delay", authTime: now.Add(-managedStepUpProofTTL + time.Second).Unix(), amr: []string{"user", "mfa"}, want: true},
		{name: "password plus u2f", authTime: now.Unix(), amr: []string{"pwd", "user", "mfa"}},
		{name: "password", authTime: now.Unix(), amr: []string{"pwd"}},
		{name: "otp", authTime: now.Unix(), amr: []string{"otp", "mfa"}},
		{name: "duplicate", authTime: now.Unix(), amr: []string{"user", "user"}},
		{name: "missing mfa", authTime: now.Unix(), amr: []string{"user"}},
		{name: "stale", authTime: now.Add(-managedStepUpProofTTL - time.Second).Unix(), amr: []string{"user", "mfa"}},
		{name: "future", authTime: now.Add(managedStepUpClockSkew + time.Second).Unix(), amr: []string{"user", "mfa"}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := validManagedPasswordlessAssertion(test.authTime, test.amr, now); got != test.want {
				t.Fatalf("got %v, want %v", got, test.want)
			}
		})
	}
}

func TestManagedStepUpCompletionBindsSubjectStateRoleAndFreshAssertion(t *testing.T) {
	app, _, _, session, _, _ := managedIngressFixture(t, "generated")
	state := "state-0123456789abcdef"
	now := time.Now().UTC()
	flow := managedStepUpFlow{
		Schema:          managedStepUpFlowDomain,
		IntentRef:       managedTestIntentRef,
		Source:          "generated",
		HumanSessionRef: managedHumanSessionRef(app.cfg.OIDCIssuer, session.Subject),
		StateHash:       managedStateHash(state),
		IssuedAt:        now.Unix(),
		ExpiresAt:       now.Add(managedStepUpFlowTTL).Unix(),
	}
	request := httptest.NewRequest(http.MethodGet, "/oidc/callback", nil)
	response := httptest.NewRecorder()
	if !app.completeManagedStepUpCallback(response, request, session, flow, state, now.Unix(), []string{"user", "mfa"}) {
		t.Fatalf("expected step-up completion, got %d body=%s", response.Code, response.Body.String())
	}
	if response.Code != http.StatusOK ||
		response.Header().Get("Refresh") != "0; url=/managed-service/setup?intent="+managedTestIntentRef ||
		!strings.Contains(response.Body.String(), `href="/managed-service/setup?intent=`+managedTestIntentRef+`"`) ||
		!strings.Contains(response.Body.String(), "Passkey confirmed") {
		t.Fatalf(
			"unexpected completion handoff: status=%d refresh=%q body=%s",
			response.Code,
			response.Header().Get("Refresh"),
			response.Body.String(),
		)
	}
	proofCookie := cookieByName(t, response.Result().Cookies(), hostStepUpProofCookie)
	if !proofCookie.HttpOnly || !proofCookie.Secure || proofCookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("step-up proof cookie must be host-prefixed, secure, httponly, strict: %#v", proofCookie)
	}
	retryCleared := false
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == hostStepUpRetryCookie && cookie.MaxAge < 0 && cookie.Value == "" {
			retryCleared = true
		}
	}
	if !retryCleared {
		t.Fatalf("successful step-up should clear the retry breadcrumb: %#v", response.Result().Cookies())
	}

	response = httptest.NewRecorder()
	if app.completeManagedStepUpCallback(response, request, session, flow, state, now.Unix(), []string{"pwd", "user", "mfa"}) {
		t.Fatal("password plus U2F must not satisfy passwordless step-up")
	}
	if response.Code != http.StatusForbidden {
		t.Fatalf("invalid assertion should fail closed, got %d", response.Code)
	}
	retryCleared = false
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == hostStepUpProofCookie && cookie.Value != "" {
			t.Fatalf("denied step-up must not mint proof: %#v", cookie)
		}
		if cookie.Name == hostStepUpRetryCookie && cookie.MaxAge < 0 && cookie.Value == "" {
			retryCleared = true
		}
	}
	if !retryCleared {
		t.Fatalf("denied step-up should clear the retry breadcrumb: %#v", response.Result().Cookies())
	}

	deniedSession := session
	deniedSession.Roles = []string{RoleViewer}
	response = httptest.NewRecorder()
	if app.completeManagedStepUpCallback(response, request, deniedSession, flow, state, now.Unix(), []string{"user", "mfa"}) {
		t.Fatal("fresh passkey must not bypass lifecycle.entry authorization")
	}
	if response.Code != http.StatusForbidden {
		t.Fatalf("unauthorized step-up should fail closed, got %d", response.Code)
	}
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == hostStepUpProofCookie && cookie.Value != "" {
			t.Fatalf("unauthorized step-up must not mint proof: %#v", cookie)
		}
	}
}

func TestOIDCCallbackCompletesOnlyBoundPasswordlessStepUp(t *testing.T) {
	app, _, _, _, _, _ := managedIngressFixture(t, "generated")
	app.cfg.RolePolicy = RolePolicy{
		OwnerSubjects: map[string]bool{managedTestSubject: true},
	}
	state := "state-0123456789abcdef"
	nonce := "nonce-0123456789abcdef"
	pkce := "pkce-0123456789abcdef0123456789abcdef"
	now := time.Now().UTC()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rawIDToken := signedManagedTestIDToken(t, privateKey, map[string]any{
		"iss":       app.cfg.OIDCIssuer,
		"sub":       managedTestSubject,
		"aud":       app.cfg.OIDCClientID,
		"exp":       now.Add(5 * time.Minute).Unix(),
		"iat":       now.Unix(),
		"auth_time": now.Unix(),
		"nonce":     nonce,
		"amr":       []string{"user", "mfa"},
	})
	tokenServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.ParseForm() != nil ||
			request.Form.Get("code") != "step-up-code" ||
			request.Form.Get("code_verifier") != pkce {
			t.Errorf("unexpected token exchange: method=%s form=%#v", request.Method, request.Form)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{
			"access_token": "synthetic-access-token",
			"token_type":   "Bearer",
			"expires_in":   300,
			"id_token":     rawIDToken,
		})
	}))
	defer tokenServer.Close()
	app.oauth = testOAuthConfig()
	app.oauth.Endpoint.TokenURL = tokenServer.URL
	app.verifier = oidc.NewVerifier(
		app.cfg.OIDCIssuer,
		&oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&privateKey.PublicKey}},
		&oidc.Config{ClientID: app.cfg.OIDCClientID},
	)

	flowWriter := httptest.NewRecorder()
	app.writeManagedStepUpFlow(flowWriter, managedStepUpFlow{
		Schema:          managedStepUpFlowDomain,
		IntentRef:       managedTestIntentRef,
		Source:          "generated",
		HumanSessionRef: managedHumanSessionRef(app.cfg.OIDCIssuer, managedTestSubject),
		StateHash:       managedStateHash(state),
		IssuedAt:        now.Unix(),
		ExpiresAt:       now.Add(managedStepUpFlowTTL).Unix(),
	})
	request := httptest.NewRequest(http.MethodGet, "/oidc/callback?state="+state+"&code=step-up-code", nil)
	request.AddCookie(cookieByName(t, flowWriter.Result().Cookies(), hostStepUpFlowCookie))
	request.AddCookie(&http.Cookie{Name: hostStateCookie, Value: state})
	request.AddCookie(&http.Cookie{Name: hostNonceCookie, Value: nonce})
	request.AddCookie(&http.Cookie{Name: hostPKCECookie, Value: pkce})
	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)
	if response.Code != http.StatusOK ||
		response.Header().Get("Refresh") != "0; url=/managed-service/setup?intent="+managedTestIntentRef ||
		!strings.Contains(response.Body.String(), "Passkey confirmed") {
		t.Fatalf("bound passwordless callback did not complete: status=%d refresh=%q body=%s", response.Code, response.Header().Get("Refresh"), response.Body.String())
	}
	proofCookie := cookieByName(t, response.Result().Cookies(), hostStepUpProofCookie)
	proofRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	proofRequest.AddCookie(proofCookie)
	proof, ok := app.readManagedStepUpProof(proofRequest)
	if !ok ||
		proof.IntentRef != managedTestIntentRef ||
		proof.Source != "generated" ||
		proof.HumanSessionRef != managedHumanSessionRef(app.cfg.OIDCIssuer, managedTestSubject) ||
		proof.AuthenticatedAt != now.Unix() {
		t.Fatalf("callback proof is not bound to the assertion: proof=%#v ok=%v", proof, ok)
	}
	sessionCookie := cookieByName(t, response.Result().Cookies(), hostSessionCookie)
	sessionRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	sessionRequest.AddCookie(sessionCookie)
	if session, ok := app.readSession(sessionRequest); !ok ||
		session.Subject != managedTestSubject ||
		!SessionHasPermission(session, PermissionLifecycleEntry) {
		t.Fatalf("callback did not refresh an authorized same-subject session: session=%#v ok=%v", session, ok)
	}
}

func signedManagedTestIDToken(t *testing.T, privateKey *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestManagedImportConsumesIntentBeforeReadingAndZeroizesValue(t *testing.T) {
	app, authority, executor, session, sessionCookie, proofCookie := managedIngressFixture(t, "import")
	canary := []byte("JANUS_IMPORT_CANARY_357+value")
	executor.expectedValue = canary
	formPrefix := "csrf_token=" + app.csrfToken(session) + "&intent_ref=" + managedTestIntentRef + "&source=import&secret_value="
	body := []byte(formPrefix + "JANUS_IMPORT_CANARY_357%2Bvalue")
	consumed := false
	spy := &managedReadOrderSpy{
		body:           body,
		secretOffset:   len(formPrefix),
		intentConsumed: &consumed,
	}
	request := managedRequest(t, app, session, sessionCookie, proofCookie, spy, int64(len(body)))
	response := httptest.NewRecorder()

	// Flip the read-order witness from the authority call itself.
	wrapped := &consumeWitnessAuthority{delegate: authority, consumed: &consumed}
	app.managedSetup = wrapped
	app.routes().ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther ||
		response.Header().Get("Location") != managedCompletionPrefix+managedTestOpRef {
		t.Fatalf("expected safe same-origin completion redirect, got %d location=%q body=%s", response.Code, response.Header().Get("Location"), response.Body.String())
	}
	if spy.earlyRead || authority.consumeCount != 1 || executor.count != 1 || !executor.valueObserved {
		t.Fatalf("value boundary order failed: early=%v consume=%d execute=%d observed=%v", spy.earlyRead, authority.consumeCount, executor.count, executor.valueObserved)
	}
	if !allZero(executor.retainedBuffer) {
		t.Fatalf("handler-owned imported buffer was not zeroized after transaction: %q", executor.retainedBuffer)
	}
	if got := response.Header().Get("Clear-Site-Data"); got != `"cache", "storage"` {
		t.Fatalf("completion should clear browser cache/storage, got %q", got)
	}
	completionCookie := cookieByName(t, response.Result().Cookies(), hostManagedDoneCookie)
	completionRequest := httptest.NewRequest(http.MethodGet, managedCompletionPrefix+managedTestOpRef, nil)
	completionRequest.AddCookie(sessionCookie)
	completionRequest.AddCookie(completionCookie)
	completionResponse := httptest.NewRecorder()
	app.routes().ServeHTTP(completionResponse, completionRequest)
	if completionResponse.Code != http.StatusOK ||
		completionResponse.Header().Get("Refresh") != "1; url=https://pharos.barta.cm/managed-service/operations/"+managedTestOpRef ||
		!strings.Contains(completionResponse.Body.String(), "Secret accepted") ||
		!strings.Contains(completionResponse.Body.String(), "Opening service status") ||
		!strings.Contains(completionResponse.Body.String(), "No reveal and no copy-back") ||
		strings.Contains(completionResponse.Body.String(), `action="/managed-service/setup/execute"`) {
		t.Fatalf(
			"same-origin completion handoff is not safe and actionable: status=%d refresh=%q body=%s",
			completionResponse.Code,
			completionResponse.Header().Get("Refresh"),
			completionResponse.Body.String(),
		)
	}
	if csp := completionResponse.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'none'") ||
		!strings.Contains(csp, "form-action 'self';") ||
		strings.Contains(csp, "pharos.barta.cm") {
		t.Fatalf("completion handoff weakened CSP: %s", csp)
	}
	assertManagedCanaryAbsent(t, app, response, string(canary))
	assertManagedCanaryAbsent(t, app, completionResponse, string(canary))
}

type consumeWitnessAuthority struct {
	delegate *fakeManagedIntentAuthority
	consumed *bool
}

func (witness *consumeWitnessAuthority) Inspect(ctx context.Context, intentRef, humanSessionRef string) (managedSetupInspection, error) {
	return witness.delegate.Inspect(ctx, intentRef, humanSessionRef)
}

func (witness *consumeWitnessAuthority) Consume(ctx context.Context, intentRef, humanSessionRef, source string) (managedAcceptedIntent, error) {
	accepted, err := witness.delegate.Consume(ctx, intentRef, humanSessionRef, source)
	if err == nil {
		*witness.consumed = true
	}
	return accepted, err
}

func TestManagedGeneratedModeSendsNoValue(t *testing.T) {
	app, authority, executor, session, sessionCookie, proofCookie := managedIngressFixture(t, "generated")
	form := "csrf_token=" + app.csrfToken(session) + "&intent_ref=" + managedTestIntentRef + "&source=generated&secret_value="
	request := managedRequest(t, app, session, sessionCookie, proofCookie, strings.NewReader(form), int64(len(form)))
	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther ||
		authority.consumeCount != 1 ||
		executor.count != 1 ||
		!executor.valueObserved ||
		len(executor.retainedBuffer) != 0 {
		t.Fatalf("generated execution should contain no value: status=%d consume=%d execute=%d observed=%v len=%d body=%s", response.Code, authority.consumeCount, executor.count, executor.valueObserved, len(executor.retainedBuffer), response.Body.String())
	}
}

func TestManagedOfflineTransactionStopsWithPlainRecoveryAndNoValueReturn(t *testing.T) {
	app, authority, executor, session, sessionCookie, proofCookie := managedIngressFixture(t, "generated")
	executor.err = managedTransactionError("web_transaction_unavailable")
	form := "csrf_token=" + app.csrfToken(session) + "&intent_ref=" + managedTestIntentRef + "&source=generated&secret_value="
	request := managedRequest(t, app, session, sessionCookie, proofCookie, strings.NewReader(form), int64(len(form)))
	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable ||
		authority.consumeCount != 1 ||
		executor.count != 1 ||
		!strings.Contains(response.Body.String(), "operation status in Pharos") {
		t.Fatalf("offline transaction recovery is unsafe: status=%d consume=%d execute=%d body=%s", response.Code, authority.consumeCount, executor.count, response.Body.String())
	}
	assertManagedCanaryAbsent(t, app, response, managedTestIntentRef)
}

func TestManagedIngressRejectsIntegrityFailuresBeforeValueReadOrConsume(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: "missing origin", mutate: func(request *http.Request) { request.Header.Del("Origin") }},
		{name: "referer is not origin", mutate: func(request *http.Request) {
			request.Header.Del("Origin")
			request.Header.Set("Referer", "https://vault.barta.cm/managed-service/setup")
		}},
		{name: "cross origin", mutate: func(request *http.Request) { request.Header.Set("Origin", "https://evil.example") }},
		{name: "cross site fetch", mutate: func(request *http.Request) { request.Header.Set("Sec-Fetch-Site", "cross-site") }},
		{name: "content type parameters", mutate: func(request *http.Request) {
			request.Header.Set("Content-Type", managedSecretFormMediaType+"; charset=utf-8")
		}},
		{name: "compressed", mutate: func(request *http.Request) { request.Header.Set("Content-Encoding", "gzip") }},
		{name: "chunked", mutate: func(request *http.Request) {
			request.ContentLength = -1
			request.TransferEncoding = []string{"chunked"}
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			app, authority, executor, session, sessionCookie, proofCookie := managedIngressFixture(t, "import")
			prefix := "csrf_token=" + app.csrfToken(session) + "&intent_ref=" + managedTestIntentRef + "&source=import&secret_value="
			body := []byte(prefix + "JANUS_EARLY_READ_CANARY_357")
			consumed := false
			spy := &managedReadOrderSpy{body: body, secretOffset: len(prefix), intentConsumed: &consumed}
			request := managedRequest(t, app, session, sessionCookie, proofCookie, spy, int64(len(body)))
			test.mutate(request)
			response := httptest.NewRecorder()
			app.routes().ServeHTTP(response, request)
			if response.Code == http.StatusSeeOther ||
				authority.consumeCount != 0 ||
				executor.count != 0 ||
				spy.offset != 0 ||
				spy.earlyRead {
				t.Fatalf("integrity failure crossed value boundary: status=%d consume=%d execute=%d read=%d early=%v", response.Code, authority.consumeCount, executor.count, spy.offset, spy.earlyRead)
			}
			assertManagedCanaryAbsent(t, app, response, "JANUS_EARLY_READ_CANARY_357")
		})
	}
}

func TestManagedIngressRejectsBadCSRFBeforeReadingValue(t *testing.T) {
	app, authority, executor, session, sessionCookie, proofCookie := managedIngressFixture(t, "import")
	prefix := "csrf_token=wrong-token&intent_ref=" + managedTestIntentRef + "&source=import&secret_value="
	body := []byte(prefix + "JANUS_CSRF_CANARY_357")
	consumed := false
	spy := &managedReadOrderSpy{body: body, secretOffset: len(prefix), intentConsumed: &consumed}
	request := managedRequest(t, app, session, sessionCookie, proofCookie, spy, int64(len(body)))
	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden ||
		authority.consumeCount != 0 ||
		executor.count != 0 ||
		spy.earlyRead ||
		spy.offset != len(prefix) {
		t.Fatalf("bad CSRF should stop at value-free prefix: status=%d consume=%d execute=%d offset=%d early=%v", response.Code, authority.consumeCount, executor.count, spy.offset, spy.earlyRead)
	}
	assertManagedCanaryAbsent(t, app, response, "JANUS_CSRF_CANARY_357")
}

func TestManagedIngressRejectsSourceChangedAfterPasskeyBeforeReadingValue(t *testing.T) {
	app, authority, executor, session, sessionCookie, proofCookie := managedIngressFixture(t, "generated")
	prefix := "csrf_token=" + app.csrfToken(session) + "&intent_ref=" + managedTestIntentRef + "&source=import&secret_value="
	body := []byte(prefix + "JANUS_SOURCE_SWAP_CANARY_358")
	consumed := false
	spy := &managedReadOrderSpy{body: body, secretOffset: len(prefix), intentConsumed: &consumed}
	request := managedRequest(t, app, session, sessionCookie, proofCookie, spy, int64(len(body)))
	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden ||
		authority.consumeCount != 0 ||
		executor.count != 0 ||
		spy.earlyRead ||
		spy.offset != len(prefix) {
		t.Fatalf("source swap crossed value boundary: status=%d consume=%d execute=%d offset=%d early=%v", response.Code, authority.consumeCount, executor.count, spy.offset, spy.earlyRead)
	}
	assertManagedCanaryAbsent(t, app, response, "JANUS_SOURCE_SWAP_CANARY_358")
}

func TestManagedIngressRestartsConfirmationWhenProofIsUnavailableBeforeConsumption(t *testing.T) {
	cases := []struct {
		name        string
		proofCookie func(*testing.T, *App, *http.Cookie) *http.Cookie
	}{
		{name: "missing", proofCookie: func(_ *testing.T, _ *App, _ *http.Cookie) *http.Cookie {
			return nil
		}},
		{name: "tampered", proofCookie: func(_ *testing.T, _ *App, valid *http.Cookie) *http.Cookie {
			tampered := *valid
			tampered.Value += "x"
			return &tampered
		}},
		{name: "expired", proofCookie: func(t *testing.T, app *App, _ *http.Cookie) *http.Cookie {
			t.Helper()
			now := time.Now().UTC()
			writer := httptest.NewRecorder()
			app.writeManagedStepUpProof(writer, managedStepUpProof{
				Schema:          managedStepUpProofDomain,
				IntentRef:       managedTestIntentRef,
				Source:          "import",
				HumanSessionRef: managedHumanSessionRef(app.cfg.OIDCIssuer, managedTestSubject),
				AuthenticatedAt: now.Add(-managedStepUpProofTTL - time.Minute).Unix(),
				ExpiresAt:       now.Add(-time.Minute).Unix(),
			})
			return cookieByName(t, writer.Result().Cookies(), hostStepUpProofCookie)
		}},
		{name: "wrong human", proofCookie: func(t *testing.T, app *App, _ *http.Cookie) *http.Cookie {
			t.Helper()
			now := time.Now().UTC()
			writer := httptest.NewRecorder()
			app.writeManagedStepUpProof(writer, managedStepUpProof{
				Schema:          managedStepUpProofDomain,
				IntentRef:       managedTestIntentRef,
				Source:          "import",
				HumanSessionRef: managedHumanSessionRef(app.cfg.OIDCIssuer, "different-managed-user"),
				AuthenticatedAt: now.Unix(),
				ExpiresAt:       now.Add(managedStepUpProofTTL).Unix(),
			})
			return cookieByName(t, writer.Result().Cookies(), hostStepUpProofCookie)
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			app, authority, executor, session, sessionCookie, validProof := managedIngressFixture(t, "import")
			prefix := "csrf_token=" + app.csrfToken(session) + "&intent_ref=" + managedTestIntentRef + "&source=import&secret_value="
			body := []byte(prefix + "JANUS_EXPIRED_PROOF_CANARY_369")
			consumed := false
			spy := &managedReadOrderSpy{
				body:           body,
				secretOffset:   len(prefix),
				intentConsumed: &consumed,
			}
			request := managedRequest(
				t,
				app,
				session,
				sessionCookie,
				test.proofCookie(t, app, validProof),
				spy,
				int64(len(body)),
			)
			response := httptest.NewRecorder()
			app.routes().ServeHTTP(response, request)
			if response.Code != http.StatusSeeOther ||
				response.Header().Get("Location") != "/managed-service/setup?intent="+managedTestIntentRef ||
				response.Header().Get("Clear-Site-Data") != `"cache", "storage"` ||
				authority.consumeCount != 0 ||
				executor.count != 0 ||
				spy.earlyRead ||
				spy.offset != len(prefix) {
				t.Fatalf(
					"unavailable proof did not restart safely: status=%d location=%q clear=%q consume=%d execute=%d offset=%d early=%v",
					response.Code,
					response.Header().Get("Location"),
					response.Header().Get("Clear-Site-Data"),
					authority.consumeCount,
					executor.count,
					spy.offset,
					spy.earlyRead,
				)
			}
			cleared := false
			for _, cookie := range response.Result().Cookies() {
				if cookie.Name == hostStepUpProofCookie && cookie.MaxAge < 0 {
					cleared = true
				}
			}
			if !cleared {
				t.Fatal("unavailable proof was not cleared")
			}
			audit := app.store.RecentAudit(1)
			if len(audit) != 1 ||
				audit[0].Outcome != "denied" ||
				!strings.Contains(audit[0].Reason, "setup restarted") ||
				test.name == "wrong human" && !strings.Contains(audit[0].Reason, "different human session") {
				t.Fatalf("confirmation restart audit is not actionable: %#v", audit)
			}
			assertManagedCanaryAbsent(t, app, response, "JANUS_EXPIRED_PROOF_CANARY_369")
		})
	}
}

func TestManagedIncompleteBodyIntentionallyBurnsIntentBeforeValueAdmission(t *testing.T) {
	app, authority, executor, session, sessionCookie, proofCookie := managedIngressFixture(t, "import")
	form := "csrf_token=" + app.csrfToken(session) + "&intent_ref=" + managedTestIntentRef + "&source=import&secret_value=partial"
	request := managedRequest(
		t,
		app,
		session,
		sessionCookie,
		proofCookie,
		strings.NewReader(form),
		int64(len(form)+8),
	)
	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest ||
		authority.consumeCount != 1 ||
		executor.count != 0 {
		t.Fatalf(
			"incomplete upload must burn exactly one intent before value admission: status=%d consume=%d execute=%d",
			response.Code,
			authority.consumeCount,
			executor.count,
		)
	}
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == hostStepUpProofCookie && cookie.MaxAge >= 0 {
			t.Fatalf("incomplete upload must clear the step-up proof: %#v", cookie)
		}
	}
	assertManagedCanaryAbsent(t, app, response, "partial")
}

func TestManagedDuplicateSubmitResolvesToExistingOperationWithoutReplay(t *testing.T) {
	app, authority, executor, session, sessionCookie, proofCookie := managedIngressFixture(t, "import")
	authority.replayAfterOne = true
	executor.expectedValue = []byte("one-time-value")
	form := "csrf_token=" + app.csrfToken(session) + "&intent_ref=" + managedTestIntentRef + "&source=import&secret_value=one-time-value"

	var completionCookie *http.Cookie
	for attempt := 1; attempt <= 2; attempt++ {
		request := managedRequest(t, app, session, sessionCookie, proofCookie, strings.NewReader(form), int64(len(form)))
		if completionCookie != nil {
			request.AddCookie(completionCookie)
		}
		response := httptest.NewRecorder()
		app.routes().ServeHTTP(response, request)
		if response.Code != http.StatusSeeOther ||
			response.Header().Get("Location") != managedCompletionPrefix+managedTestOpRef {
			t.Fatalf("submit %d should resolve to the same completion, got %d location=%q body=%s", attempt, response.Code, response.Header().Get("Location"), response.Body.String())
		}
		if attempt == 1 {
			completionCookie = cookieByName(t, response.Result().Cookies(), hostManagedDoneCookie)
			if !completionCookie.HttpOnly ||
				!completionCookie.Secure ||
				completionCookie.SameSite != http.SameSiteStrictMode ||
				completionCookie.MaxAge != int(managedCompletionTTL.Seconds()) {
				t.Fatalf("completion receipt cookie is not strictly bounded: %#v", completionCookie)
			}
			receiptRequest := httptest.NewRequest(http.MethodGet, "/", nil)
			receiptRequest.AddCookie(completionCookie)
			receipt, ok := app.readManagedCompletionReceipt(receiptRequest)
			if !ok ||
				receipt.IntentRef != managedTestIntentRef ||
				receipt.OperationRef != managedTestOpRef ||
				receipt.Source != "import" ||
				receipt.OperationKind != "create" ||
				receipt.HumanSessionRef != managedHumanSessionRef(app.cfg.OIDCIssuer, session.Subject) {
				t.Fatalf("completion receipt is not exactly bound: receipt=%#v ok=%v", receipt, ok)
			}
		}
	}
	if authority.consumeCount != 1 || executor.count != 1 {
		t.Fatalf("duplicate crossed transaction boundary: consume=%d execute=%d", authority.consumeCount, executor.count)
	}
}

func TestManagedAcceptedOperationRecoversWithoutCompletionOrStepUpCookie(t *testing.T) {
	app, authority, executor, session, sessionCookie, proofCookie := managedIngressFixture(t, "import")
	executor.expectedValue = []byte("one-time-value")
	prefix := "csrf_token=" + app.csrfToken(session) + "&intent_ref=" + managedTestIntentRef + "&source=import&secret_value="
	form := prefix + "one-time-value"

	first := managedRequest(t, app, session, sessionCookie, proofCookie, strings.NewReader(form), int64(len(form)))
	firstResponse := httptest.NewRecorder()
	app.routes().ServeHTTP(firstResponse, first)
	if firstResponse.Code != http.StatusSeeOther {
		t.Fatalf("first submission was not accepted: status=%d body=%s", firstResponse.Code, firstResponse.Body.String())
	}

	consumed := true
	spy := &managedReadOrderSpy{
		body:           []byte(form),
		secretOffset:   len(prefix),
		intentConsumed: &consumed,
	}
	repeated := managedRequest(t, app, session, sessionCookie, nil, spy, int64(len(form)))
	repeatedResponse := httptest.NewRecorder()
	app.routes().ServeHTTP(repeatedResponse, repeated)
	if repeatedResponse.Code != http.StatusSeeOther ||
		repeatedResponse.Header().Get("Location") != managedCompletionPrefix+managedTestOpRef {
		t.Fatalf(
			"accepted operation was not recovered: status=%d location=%q body=%s",
			repeatedResponse.Code,
			repeatedResponse.Header().Get("Location"),
			repeatedResponse.Body.String(),
		)
	}
	if spy.offset != len(prefix) {
		t.Fatalf("recovery read value bytes: read=%d prefix=%d", spy.offset, len(prefix))
	}
	completionCookie := cookieByName(t, repeatedResponse.Result().Cookies(), hostManagedDoneCookie)
	if completionCookie.MaxAge != int(managedCompletionTTL.Seconds()) {
		t.Fatalf("recovery did not issue a bounded completion receipt: %#v", completionCookie)
	}
	if authority.consumeCount != 1 ||
		authority.recoverCount != 1 ||
		executor.count != 1 ||
		executor.recoverCount != 1 {
		t.Fatalf(
			"recovery crossed the transaction boundary: consume=%d recover=%d execute=%d transaction_recover=%d",
			authority.consumeCount,
			authority.recoverCount,
			executor.count,
			executor.recoverCount,
		)
	}
}

func TestManagedCompletionReceiptRecoversRefreshBackAndLostNavigation(t *testing.T) {
	app, authority, _, session, sessionCookie, _ := managedIngressFixture(t, "generated")
	writer := httptest.NewRecorder()
	app.writeManagedCompletionReceipt(writer, managedCompletionReceipt{
		IntentRef:       managedTestIntentRef,
		OperationRef:    managedTestOpRef,
		OperationKind:   "create",
		Source:          "generated",
		HumanSessionRef: managedHumanSessionRef(app.cfg.OIDCIssuer, session.Subject),
	})
	completionCookie := cookieByName(t, writer.Result().Cookies(), hostManagedDoneCookie)

	request := httptest.NewRequest(http.MethodGet, "/managed-service/setup?intent="+managedTestIntentRef, nil)
	request.AddCookie(sessionCookie)
	request.AddCookie(completionCookie)
	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther ||
		response.Header().Get("Location") != managedCompletionPrefix+managedTestOpRef ||
		authority.inspectCount != 0 {
		t.Fatalf(
			"completed setup did not recover without re-inspection: status=%d location=%q inspect=%d body=%s",
			response.Code,
			response.Header().Get("Location"),
			authority.inspectCount,
			response.Body.String(),
		)
	}

	for attempt := 1; attempt <= 2; attempt++ {
		request = httptest.NewRequest(http.MethodGet, managedCompletionPrefix+managedTestOpRef, nil)
		request.AddCookie(sessionCookie)
		request.AddCookie(completionCookie)
		response = httptest.NewRecorder()
		app.routes().ServeHTTP(response, request)
		if response.Code != http.StatusOK ||
			response.Header().Get("Refresh") != "1; url=https://pharos.barta.cm/managed-service/operations/"+managedTestOpRef {
			t.Fatalf("completion refresh %d did not stay idempotent: status=%d refresh=%q body=%s", attempt, response.Code, response.Header().Get("Refresh"), response.Body.String())
		}
	}
}

func TestManagedCompletionReceiptTamperExpiryWrongUserAndWrongOperationFailClosed(t *testing.T) {
	app, _, _, session, sessionCookie, _ := managedIngressFixture(t, "generated")
	now := time.Now().UTC()
	valid := managedCompletionReceipt{
		Schema:          managedCompletionDomain,
		IntentRef:       managedTestIntentRef,
		OperationRef:    managedTestOpRef,
		OperationKind:   "create",
		Source:          "generated",
		HumanSessionRef: managedHumanSessionRef(app.cfg.OIDCIssuer, session.Subject),
		CompletedAt:     now.Unix(),
		ExpiresAt:       now.Add(managedCompletionTTL).Unix(),
	}
	writer := httptest.NewRecorder()
	app.writeManagedSignedCookie(
		writer,
		app.cfg.ManagedCompletionCookieName(),
		managedCompletionDomain,
		valid,
		http.SameSiteStrictMode,
		managedCompletionTTL,
	)
	validCookie := cookieByName(t, writer.Result().Cookies(), hostManagedDoneCookie)

	wrongSession := session
	wrongSession.Subject = "different-managed-user"
	wrongSessionWriter := httptest.NewRecorder()
	app.writeSession(wrongSessionWriter, wrongSession)
	wrongSessionCookie := cookieByName(t, wrongSessionWriter.Result().Cookies(), hostSessionCookie)

	expired := valid
	expired.CompletedAt = now.Add(-2 * managedCompletionTTL).Unix()
	expired.ExpiresAt = now.Add(-managedCompletionTTL).Unix()
	expiredWriter := httptest.NewRecorder()
	app.writeManagedSignedCookie(
		expiredWriter,
		app.cfg.ManagedCompletionCookieName(),
		managedCompletionDomain,
		expired,
		http.SameSiteStrictMode,
		managedCompletionTTL,
	)

	tampered := *validCookie
	tampered.Value += "x"
	tests := []struct {
		name      string
		path      string
		session   *http.Cookie
		completed *http.Cookie
	}{
		{name: "tampered", path: managedCompletionPrefix + managedTestOpRef, session: sessionCookie, completed: &tampered},
		{name: "expired", path: managedCompletionPrefix + managedTestOpRef, session: sessionCookie, completed: cookieByName(t, expiredWriter.Result().Cookies(), hostManagedDoneCookie)},
		{name: "wrong user", path: managedCompletionPrefix + managedTestOpRef, session: wrongSessionCookie, completed: validCookie},
		{name: "wrong operation", path: managedCompletionPrefix + "op_abcdef0123456789", session: sessionCookie, completed: validCookie},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, test.path, nil)
			request.AddCookie(test.session)
			request.AddCookie(test.completed)
			response := httptest.NewRecorder()
			app.routes().ServeHTTP(response, request)
			if response.Code != http.StatusConflict ||
				!strings.Contains(response.Body.String(), "Open the operation from Pharos") ||
				response.Header().Get("Refresh") != "" {
				t.Fatalf("unsafe completion receipt was not denied: status=%d refresh=%q body=%s", response.Code, response.Header().Get("Refresh"), response.Body.String())
			}
		})
	}
}

func TestManagedFormDecoderIsStrictAndInPlace(t *testing.T) {
	raw := []byte("a%2Bb+c%20d")
	decoded, err := decodeManagedFormValueInPlace(raw)
	if err != nil || string(decoded) != "a+b c d" {
		t.Fatalf("unexpected decode: %q err=%v", decoded, err)
	}
	for _, invalid := range [][]byte{
		[]byte("value&extra=field"),
		[]byte("truncated%"),
		[]byte("bad%XZ"),
	} {
		if _, err := decodeManagedFormValueInPlace(invalid); err == nil {
			t.Fatalf("expected strict rejection for %q", invalid)
		}
	}
	zeroizeBytes(raw)
	if !allZero(raw) {
		t.Fatalf("decoder backing buffer did not zeroize: %q", raw)
	}
}

func TestManagedStepUpCookieTamperAndExpiryFailClosed(t *testing.T) {
	app, _, _, _, _, proofCookie := managedIngressFixture(t, "generated")
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	tampered := *proofCookie
	tampered.Value += "x"
	request.AddCookie(&tampered)
	if _, ok := app.readManagedStepUpProof(request); ok {
		t.Fatal("tampered proof cookie was accepted")
	}

	expiredWriter := httptest.NewRecorder()
	now := time.Now().UTC()
	app.writeManagedStepUpProof(expiredWriter, managedStepUpProof{
		Schema:          managedStepUpProofDomain,
		IntentRef:       managedTestIntentRef,
		Source:          "generated",
		HumanSessionRef: managedHumanSessionRef(app.cfg.OIDCIssuer, managedTestSubject),
		AuthenticatedAt: now.Add(-3 * time.Minute).Unix(),
		ExpiresAt:       now.Add(-time.Minute).Unix(),
	})
	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.AddCookie(cookieByName(t, expiredWriter.Result().Cookies(), hostStepUpProofCookie))
	if _, ok := app.readManagedStepUpProof(request); ok {
		t.Fatal("expired proof cookie was accepted")
	}
}

func TestManagedValueBoundaryIsNotAddedToOrdinaryAPI(t *testing.T) {
	app := newTestApp(t)
	for _, route := range app.routeSpecs() {
		lower := strings.ToLower(route.pattern)
		if strings.Contains(lower, "managed-service/setup") && strings.Contains(lower, "/api/") {
			t.Fatalf("managed value boundary leaked into ordinary API: %s", route.pattern)
		}
		if strings.Contains(lower, "secret_value") || strings.Contains(lower, "passwordless") {
			t.Fatalf("route vocabulary exposes a value or alternate auth method: %s", route.pattern)
		}
	}
}

func assertManagedCanaryAbsent(t *testing.T, app *App, response *httptest.ResponseRecorder, canary string) {
	t.Helper()
	if strings.Contains(response.Body.String(), canary) ||
		strings.Contains(response.Header().Get("Location"), canary) {
		t.Fatalf("response leaked managed canary %q: headers=%#v body=%s", canary, response.Header(), response.Body.String())
	}
	for _, cookie := range response.Result().Cookies() {
		if strings.Contains(cookie.Value, canary) {
			t.Fatalf("cookie leaked managed canary %q: %#v", canary, cookie)
		}
	}
	audit, err := json.Marshal(app.store.RecentAudit(32))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(audit, []byte(canary)) {
		t.Fatalf("audit leaked managed canary %q: %s", canary, audit)
	}
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
