package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/oauth2"
)

const (
	managedDynamicStepUpFlowDomain  = "inspr.janus.managed-dynamic-step-up-flow.v2"
	managedDynamicStepUpProofDomain = "inspr.janus.managed-dynamic-step-up-proof.v2"
	managedDynamicStepUpRetryDomain = "inspr.janus.managed-dynamic-step-up-retry.v2"
	managedDynamicLoginIntentDomain = "inspr.janus.managed-dynamic-login-intent.v2"
)

// managedDynamicSetupIntentAuthority is wired only by the dedicated, complete
// v2 runtime configuration. Existing v1 setup never enables this capability.
type managedDynamicSetupIntentAuthority interface {
	Inspect(context.Context, string, string) (managedDynamicSetupInspection, error)
	Reserve(context.Context, string, string) (managedDynamicSetupReservation, error)
	RecoverReservation(context.Context, string, string, string) (managedDynamicSetupReservation, error)
}

type managedDynamicSetupReservation struct {
	Inspection   managedDynamicSetupInspection
	OperationRef string
}

// managedDynamicStepUpTarget contains every authority-bearing choice that a
// fresh passkey assertion approves. It is value-free by construction.
type managedDynamicStepUpTarget struct {
	IntentRef                    string `json:"intent_ref"`
	OperationKind                string `json:"operation_kind"`
	Source                       string `json:"source"`
	HostRef                      string `json:"host_ref"`
	ServiceRef                   string `json:"service_ref"`
	EnvironmentPolicyRef         string `json:"environment_policy_ref"`
	EnvironmentPolicyFingerprint string `json:"environment_policy_fingerprint"`
	DeclarationFingerprint       string `json:"declaration_fingerprint"`
	EnvironmentName              string `json:"environment_name"`
	HumanSessionRef              string `json:"human_session_ref"`
	IssuerRef                    string `json:"issuer_ref"`
	AudienceRef                  string `json:"audience_ref"`
	NonceRef                     string `json:"nonce_ref"`
	IntentIssuedAt               int64  `json:"intent_issued_at"`
	IntentExpiresAt              int64  `json:"intent_expires_at"`
	ReturnTarget                 string `json:"return_target"`
}

type managedDynamicStepUpFlow struct {
	Schema    string                     `json:"schema"`
	Target    managedDynamicStepUpTarget `json:"target"`
	StateHash string                     `json:"state_hash"`
	IssuedAt  int64                      `json:"issued_at"`
	ExpiresAt int64                      `json:"expires_at"`
}

type managedDynamicStepUpProof struct {
	Schema          string                     `json:"schema"`
	Target          managedDynamicStepUpTarget `json:"target"`
	OperationRef    string                     `json:"operation_ref"`
	AuthenticatedAt int64                      `json:"authenticated_at"`
	ExpiresAt       int64                      `json:"expires_at"`
}

type managedDynamicStepUpRetry struct {
	Schema    string                     `json:"schema"`
	Target    managedDynamicStepUpTarget `json:"target"`
	StateHash string                     `json:"state_hash"`
	IssuedAt  int64                      `json:"issued_at"`
	ExpiresAt int64                      `json:"expires_at"`
}

type managedDynamicLoginIntent struct {
	Schema    string `json:"schema"`
	IntentRef string `json:"intent_ref"`
	IssuedAt  int64  `json:"issued_at"`
	ExpiresAt int64  `json:"expires_at"`
}

type managedDynamicSetupPageData struct {
	Title                        string
	ActivePage                   string
	CSPNonce                     string
	Mode                         string
	Session                      Session
	SessionRoleBadge             string
	CSRF                         string
	IntentRef                    string
	OperationKind                string
	Source                       string
	HostRef                      string
	ServiceRef                   string
	EnvironmentName              string
	EnvironmentPolicyRef         string
	EnvironmentPolicyFingerprint string
	DeclarationFingerprint       string
	ConsumerLabel                string
	DeliveryLabel                string
	StepUpReady                  bool
	OperationRef                 string
	RequestID                    string
}

func (app *App) handleManagedDynamicSetup(w http.ResponseWriter, r *http.Request) {
	managedSecretResponseBoundary(w)
	session := currentSession(r.Context())
	intentRef, ok := exactManagedIntentQuery(r.URL)
	if !ok {
		app.audit(r, "managed_environment.setup.view", "denied", session.Subject, "invalid intent reference")
		app.renderSafeFailure(w, r, http.StatusBadRequest, "setup_link_invalid", "This setup link is not valid. Start again from Pharos.", nil)
		return
	}
	inspection, err := app.inspectManagedDynamicSetupIntent(r.Context(), session, intentRef)
	if err != nil {
		app.audit(r, "managed_environment.setup.view", "denied", session.Subject, "intent unavailable")
		app.renderSafeFailure(w, r, managedIntentHTTPStatus(err), "setup_link_unavailable", "This setup request is unavailable or expired. Start again from Pharos.", nil)
		return
	}
	target := managedDynamicTargetFromInspection(inspection)
	proof, proofOK := app.readManagedDynamicStepUpProof(r)
	stepUpReady := false
	if proofOK && proof.Target == target {
		reservation, reservationErr := app.managedDynamicSetup.RecoverReservation(
			r.Context(),
			target.IntentRef,
			target.HumanSessionRef,
			proof.OperationRef,
		)
		stepUpReady = reservationErr == nil &&
			reservation.OperationRef == proof.OperationRef &&
			managedDynamicTargetFromInspection(reservation.Inspection) == target
	}
	if proofOK && !stepUpReady {
		app.clearManagedDynamicStepUpProofCookies(w)
		app.audit(r, "managed_environment.step_up.proof", "denied", session.Subject, "proof or reservation invalid")
	}
	app.audit(r, "managed_environment.setup.view", "allowed", session.Subject, "value-free dynamic setup context")
	renderTemplateStatus(w, app.templates, "managed_dynamic_setup", http.StatusOK, managedDynamicSetupPageData{
		Title:                        "Janus — Service environment",
		ActivePage:                   "vault",
		CSPNonce:                     cspNonceFromContext(r.Context()),
		Mode:                         app.cfg.ProductMode,
		Session:                      session,
		SessionRoleBadge:             SessionRoleBadge(session),
		CSRF:                         app.csrfToken(session),
		IntentRef:                    target.IntentRef,
		OperationKind:                target.OperationKind,
		Source:                       target.Source,
		HostRef:                      target.HostRef,
		ServiceRef:                   target.ServiceRef,
		EnvironmentName:              target.EnvironmentName,
		EnvironmentPolicyRef:         target.EnvironmentPolicyRef,
		EnvironmentPolicyFingerprint: target.EnvironmentPolicyFingerprint,
		DeclarationFingerprint:       target.DeclarationFingerprint,
		ConsumerLabel:                managedConsumerLabel(inspection.Context.ConsumerKind),
		DeliveryLabel:                managedDeliveryLabel(inspection.Context.DeliveryKind),
		StepUpReady:                  stepUpReady,
		OperationRef:                 proof.OperationRef,
		RequestID:                    requestID(r),
	})
}

func (app *App) handleManagedDynamicSetupStepUp(w http.ResponseWriter, r *http.Request) {
	managedSecretResponseBoundary(w)
	session := currentSession(r.Context())
	if !app.managedDynamicSetupEnabled() || !app.cfg.RequireAuth || !app.cfg.OIDCConfigured() || app.oauth == nil {
		app.audit(r, "managed_environment.step_up.start", "denied", session.Subject, "dynamic setup unavailable")
		app.renderSafeFailure(w, r, http.StatusServiceUnavailable, "managed_setup_unavailable", "Managed environment setup is not ready.", nil)
		return
	}
	if !app.exactSameOriginBrowserMutation(r) ||
		!strictFormRequest(r, false) ||
		r.URL.RawQuery != "" ||
		r.ParseForm() != nil ||
		!exactFormKeys(r.PostForm, "csrf_token", "intent_ref") ||
		!hmac.Equal([]byte(app.csrfToken(session)), []byte(r.PostForm.Get("csrf_token"))) {
		app.audit(r, "managed_environment.step_up.start", "denied", session.Subject, "request integrity failed")
		app.renderSafeFailure(w, r, http.StatusForbidden, "request_integrity_failed", "Reload the setup page and try again.", nil)
		return
	}
	inspection, err := app.inspectManagedDynamicSetupIntent(r.Context(), session, r.PostForm.Get("intent_ref"))
	if err != nil {
		app.audit(r, "managed_environment.step_up.start", "denied", session.Subject, "intent unavailable")
		app.renderSafeFailure(w, r, managedIntentHTTPStatus(err), "setup_link_unavailable", "This setup request is unavailable or expired. Start again from Pharos.", nil)
		return
	}

	state := randomToken(32)
	nonce := randomToken(32)
	verifier := oauth2.GenerateVerifier()
	now := time.Now().UTC()
	target := managedDynamicTargetFromInspection(inspection)
	flow := managedDynamicStepUpFlow{
		Schema:    managedDynamicStepUpFlowDomain,
		Target:    target,
		StateHash: managedStateHash(state),
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(managedStepUpFlowTTL).Unix(),
	}
	app.clearManagedStepUpCookies(w)
	app.clearManagedDynamicStepUpCookies(w)
	app.writeManagedDynamicStepUpFlow(w, flow)
	app.writeManagedDynamicStepUpRetry(w, managedDynamicStepUpRetry{
		Schema:    managedDynamicStepUpRetryDomain,
		Target:    target,
		StateHash: flow.StateHash,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(managedStepUpRetryTTL).Unix(),
	})
	app.writeOIDCEphemeralCookie(w, app.cfg.StateCookieName(), state)
	app.writeOIDCEphemeralCookie(w, app.cfg.NonceCookieName(), nonce)
	app.writeOIDCEphemeralCookie(w, app.cfg.PKCECookieName(), verifier)
	app.audit(r, "managed_environment.step_up.start", "allowed", session.Subject, "fresh passwordless assertion requested for exact dynamic target")
	http.Redirect(w, r, app.oauth.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("prompt", "login"),
		oauth2.SetAuthURLParam("max_age", "0"),
		oauth2.S256ChallengeOption(verifier),
	), http.StatusFound)
}

func (app *App) inspectManagedDynamicSetupIntent(ctx context.Context, session Session, intentRef string) (managedDynamicSetupInspection, error) {
	if !app.managedDynamicSetupEnabled() || !validManagedRef("intent_", intentRef) {
		return managedDynamicSetupInspection{}, managedIntentError("managed_intent_invalid_request")
	}
	humanSessionRef := managedHumanSessionRef(app.cfg.OIDCIssuer, session.Subject)
	inspection, err := app.managedDynamicSetup.Inspect(ctx, intentRef, humanSessionRef)
	if err != nil {
		return managedDynamicSetupInspection{}, err
	}
	intent := inspection.Intent
	declaration := inspection.Context
	now := time.Now().UTC().Unix()
	if validateManagedDynamicSetupIntent(intent) != nil ||
		intent.IntentRef != intentRef ||
		intent.HumanSessionRef != humanSessionRef ||
		intent.IssuerRef != managedSetupExpectedIssuerRef ||
		intent.AudienceRef != managedSetupExpectedAudienceRef ||
		intent.IssuedAtUnixSeconds > now+managedIntentClockSkewSeconds ||
		now >= intent.ExpiresAtUnixSeconds ||
		declaration.EnvironmentPolicyRef != intent.EnvironmentPolicyRef ||
		declaration.EnvironmentPolicyFingerprint != intent.EnvironmentPolicyFingerprint ||
		declaration.ConsumerKind != "managed_service" ||
		declaration.DeliveryKind != "private_env_file" ||
		declaration.NamePolicy != "portable_secret_env_v1" ||
		!containsManagedSource(declaration.AllowedSources, intent.Source) ||
		!validManagedRef("delivery_", declaration.DeliveryProfileRef) ||
		!validManagedRef("reload_", declaration.ReloadProfileRef) ||
		!validManagedRef("health_", declaration.HealthProfileRef) ||
		!validManagedDynamicStepUpTarget(managedDynamicTargetFromInspection(inspection)) {
		return managedDynamicSetupInspection{}, managedIntentError("managed_intent_payload_invalid")
	}
	return inspection, nil
}

func (app *App) managedDynamicSetupEnabled() bool {
	return app.managedDynamicSetup != nil
}

func managedDynamicTargetFromInspection(inspection managedDynamicSetupInspection) managedDynamicStepUpTarget {
	intent := inspection.Intent
	return managedDynamicStepUpTarget{
		IntentRef:                    intent.IntentRef,
		OperationKind:                intent.OperationKind,
		Source:                       intent.Source,
		HostRef:                      intent.HostRef,
		ServiceRef:                   intent.ServiceRef,
		EnvironmentPolicyRef:         intent.EnvironmentPolicyRef,
		EnvironmentPolicyFingerprint: intent.EnvironmentPolicyFingerprint,
		DeclarationFingerprint:       intent.DeclarationFingerprint,
		EnvironmentName:              intent.EnvironmentName,
		HumanSessionRef:              intent.HumanSessionRef,
		IssuerRef:                    intent.IssuerRef,
		AudienceRef:                  intent.AudienceRef,
		NonceRef:                     intent.NonceRef,
		IntentIssuedAt:               intent.IssuedAtUnixSeconds,
		IntentExpiresAt:              intent.ExpiresAtUnixSeconds,
		ReturnTarget:                 intent.ReturnTarget,
	}
}

func validManagedDynamicStepUpTarget(target managedDynamicStepUpTarget) bool {
	return validManagedRef("intent_", target.IntentRef) &&
		(target.OperationKind == "create" || target.OperationKind == "replace") &&
		validManagedSource(target.Source) && target.Source != "remove" &&
		validManagedRef("host_", target.HostRef) &&
		validManagedRef("svc_", target.ServiceRef) &&
		validManagedRef("envpol_", target.EnvironmentPolicyRef) &&
		validManagedRef("envpf_", target.EnvironmentPolicyFingerprint) &&
		validManagedRef("decl_", target.DeclarationFingerprint) &&
		validManagedEnvironmentName(target.EnvironmentName) &&
		validManagedRef("hsn_", target.HumanSessionRef) &&
		validManagedRef("sys_", target.IssuerRef) &&
		validManagedRef("sys_", target.AudienceRef) &&
		validManagedRef("nonce_", target.NonceRef) &&
		target.IntentIssuedAt > 0 &&
		target.IntentExpiresAt > target.IntentIssuedAt &&
		target.IntentExpiresAt-target.IntentIssuedAt <= managedIntentMaxTTLSeconds &&
		target.ReturnTarget == "pharos_service"
}

func (app *App) writeManagedDynamicStepUpFlow(w http.ResponseWriter, flow managedDynamicStepUpFlow) {
	app.writeManagedSignedCookie(w, app.cfg.DynamicStepUpFlowCookieName(), managedDynamicStepUpFlowDomain, flow, http.SameSiteLaxMode, managedStepUpFlowTTL)
}

func (app *App) writeManagedDynamicStepUpProof(w http.ResponseWriter, proof managedDynamicStepUpProof) {
	app.writeManagedSignedCookie(w, app.cfg.DynamicStepUpProofCookieName(), managedDynamicStepUpProofDomain, proof, http.SameSiteStrictMode, managedStepUpProofTTL)
}

func (app *App) writeManagedDynamicStepUpRetry(w http.ResponseWriter, retry managedDynamicStepUpRetry) {
	app.writeManagedSignedCookie(w, app.cfg.DynamicStepUpRetryCookieName(), managedDynamicStepUpRetryDomain, retry, http.SameSiteLaxMode, managedStepUpRetryTTL)
}

func (app *App) writeManagedDynamicLoginIntent(w http.ResponseWriter, intentRef string) {
	if !validManagedRef("intent_", intentRef) {
		return
	}
	now := time.Now().UTC()
	app.writeManagedSignedCookie(w, app.cfg.DynamicLoginCookieName(), managedDynamicLoginIntentDomain, managedDynamicLoginIntent{
		Schema: managedDynamicLoginIntentDomain, IntentRef: intentRef,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(managedStepUpFlowTTL).Unix(),
	}, http.SameSiteLaxMode, managedStepUpFlowTTL)
}

func (app *App) readManagedDynamicStepUpFlow(r *http.Request) (managedDynamicStepUpFlow, bool, error) {
	cookie, err := firstCookie(r, app.cfg.DynamicStepUpFlowCookieName(), dynamicFlowCookie)
	if err != nil {
		return managedDynamicStepUpFlow{}, false, nil
	}
	var flow managedDynamicStepUpFlow
	if !app.decodeManagedSignedCookie(cookie.Value, managedDynamicStepUpFlowDomain, &flow) ||
		flow.Schema != managedDynamicStepUpFlowDomain ||
		!validManagedDynamicStepUpTarget(flow.Target) ||
		!isLowerHexString(flow.StateHash, sha256.Size*2) ||
		!validManagedStepUpTimes(flow.IssuedAt, flow.ExpiresAt, managedStepUpFlowTTL, time.Now().UTC()) {
		return managedDynamicStepUpFlow{}, true, errors.New("managed dynamic step-up flow cookie invalid")
	}
	return flow, true, nil
}

func (app *App) readManagedDynamicStepUpProof(r *http.Request) (managedDynamicStepUpProof, bool) {
	cookie, err := firstCookie(r, app.cfg.DynamicStepUpProofCookieName(), dynamicProofCookie)
	if err != nil {
		return managedDynamicStepUpProof{}, false
	}
	var proof managedDynamicStepUpProof
	if !app.decodeManagedSignedCookie(cookie.Value, managedDynamicStepUpProofDomain, &proof) ||
		proof.Schema != managedDynamicStepUpProofDomain ||
		!validManagedDynamicStepUpTarget(proof.Target) ||
		!validManagedRef("op_", proof.OperationRef) ||
		!validManagedStepUpTimes(proof.AuthenticatedAt, proof.ExpiresAt, managedStepUpProofTTL, time.Now().UTC()) {
		return managedDynamicStepUpProof{}, false
	}
	return proof, true
}

func (app *App) readManagedDynamicStepUpRetry(r *http.Request) (managedDynamicStepUpRetry, bool) {
	cookie, err := firstCookie(r, app.cfg.DynamicStepUpRetryCookieName(), dynamicRetryCookie)
	if err != nil {
		return managedDynamicStepUpRetry{}, false
	}
	var retry managedDynamicStepUpRetry
	if !app.decodeManagedSignedCookie(cookie.Value, managedDynamicStepUpRetryDomain, &retry) ||
		retry.Schema != managedDynamicStepUpRetryDomain ||
		!validManagedDynamicStepUpTarget(retry.Target) ||
		!isLowerHexString(retry.StateHash, sha256.Size*2) ||
		!validManagedStepUpTimes(retry.IssuedAt, retry.ExpiresAt, managedStepUpRetryTTL, time.Now().UTC()) {
		return managedDynamicStepUpRetry{}, false
	}
	return retry, true
}

func (app *App) readManagedDynamicLoginIntent(r *http.Request) (string, bool) {
	cookie, err := firstCookie(r, app.cfg.DynamicLoginCookieName(), dynamicLoginCookie)
	if err != nil {
		return "", false
	}
	var intent managedDynamicLoginIntent
	if !app.decodeManagedSignedCookie(cookie.Value, managedDynamicLoginIntentDomain, &intent) ||
		intent.Schema != managedDynamicLoginIntentDomain ||
		!validManagedRef("intent_", intent.IntentRef) ||
		!validManagedStepUpTimes(intent.IssuedAt, intent.ExpiresAt, managedStepUpFlowTTL, time.Now().UTC()) {
		return "", false
	}
	return intent.IntentRef, true
}

func (app *App) recoverManagedDynamicStepUpCallback(w http.ResponseWriter, r *http.Request, retry managedDynamicStepUpRetry, ok bool, reason string) bool {
	callbackState := r.URL.Query().Get("state")
	if !ok || callbackState == "" || retry.StateHash != managedStateHash(callbackState) {
		return false
	}
	app.clearOIDCLoginCookies(w)
	app.clearManagedDynamicStepUpRetryCookies(w)
	app.clearManagedDynamicLoginIntentCookies(w)
	app.audit(r, "managed_environment.step_up.recover", "denied", "", reason)
	app.renderAuthContinuation(w, r, "/managed-environment/setup?intent="+url.QueryEscape(retry.Target.IntentRef), "dynamic_step_up_retry")
	return true
}

func (app *App) completeManagedDynamicStepUpCallback(w http.ResponseWriter, r *http.Request, session Session, flow managedDynamicStepUpFlow, state string, authTime int64, amr []string) bool {
	now := time.Now().UTC()
	humanSessionRef := managedHumanSessionRef(app.cfg.OIDCIssuer, session.Subject)
	inspection, err := app.inspectManagedDynamicSetupIntent(r.Context(), session, flow.Target.IntentRef)
	currentTarget := managedDynamicTargetFromInspection(inspection)
	if err != nil || flow.Target != currentTarget ||
		flow.Target.HumanSessionRef != humanSessionRef ||
		flow.StateHash != managedStateHash(state) ||
		!validManagedPasswordlessAssertion(authTime, amr, now) ||
		!SessionHasPermission(session, PermissionLifecycleEntry) {
		app.clearOIDCLoginCookies(w)
		app.clearManagedDynamicStepUpProofCookies(w)
		app.clearManagedDynamicStepUpRetryCookies(w)
		app.audit(r, "managed_environment.step_up.complete", "denied", session.Subject, "passwordless assertion or target denied")
		app.renderAuthError(w, r, http.StatusForbidden, "passwordless_step_up_failed", "A fresh passwordless passkey confirmation is required for this exact environment change.")
		return false
	}
	reservation, err := app.managedDynamicSetup.Reserve(r.Context(), currentTarget.IntentRef, humanSessionRef)
	if err != nil ||
		!validManagedRef("op_", reservation.OperationRef) ||
		managedDynamicTargetFromInspection(reservation.Inspection) != currentTarget {
		app.clearOIDCLoginCookies(w)
		app.clearManagedDynamicStepUpProofCookies(w)
		app.clearManagedDynamicStepUpRetryCookies(w)
		app.audit(r, "managed_environment.step_up.complete", "denied", session.Subject, "intent reservation denied")
		app.renderAuthError(w, r, http.StatusConflict, "setup_request_already_used", "This setup request was already used or could not be reserved. Start again from Pharos.")
		return false
	}
	app.writeSession(w, session)
	app.writeManagedDynamicStepUpProof(w, managedDynamicStepUpProof{
		Schema: managedDynamicStepUpProofDomain, Target: currentTarget,
		OperationRef:    reservation.OperationRef,
		AuthenticatedAt: authTime,
		ExpiresAt:       time.Unix(authTime, 0).UTC().Add(managedStepUpProofTTL).Unix(),
	})
	app.clearOIDCLoginCookies(w)
	app.clearManagedDynamicStepUpRetryCookies(w)
	app.clearOIDCLoginAttemptCookie(w)
	app.clearManagedDynamicLoginIntentCookies(w)
	app.audit(r, "managed_environment.step_up.complete", "allowed", session.Subject, "fresh passwordless assertion reserved exact dynamic target")
	app.renderAuthContinuation(w, r, "/managed-environment/setup?intent="+url.QueryEscape(flow.Target.IntentRef), "dynamic_step_up")
	return true
}

func (app *App) clearManagedDynamicStepUpFlowCookies(w http.ResponseWriter) {
	app.clearCookie(w, app.cfg.DynamicStepUpFlowCookieName())
	if app.cfg.DynamicStepUpFlowCookieName() != dynamicFlowCookie {
		app.clearCookie(w, dynamicFlowCookie)
	}
}

func (app *App) clearManagedDynamicStepUpProofCookies(w http.ResponseWriter) {
	app.clearCookie(w, app.cfg.DynamicStepUpProofCookieName())
	if app.cfg.DynamicStepUpProofCookieName() != dynamicProofCookie {
		app.clearCookie(w, dynamicProofCookie)
	}
}

func (app *App) clearManagedDynamicStepUpRetryCookies(w http.ResponseWriter) {
	app.clearCookie(w, app.cfg.DynamicStepUpRetryCookieName())
	if app.cfg.DynamicStepUpRetryCookieName() != dynamicRetryCookie {
		app.clearCookie(w, dynamicRetryCookie)
	}
}

func (app *App) clearManagedDynamicStepUpCookies(w http.ResponseWriter) {
	app.clearManagedDynamicStepUpFlowCookies(w)
	app.clearManagedDynamicStepUpProofCookies(w)
	app.clearManagedDynamicStepUpRetryCookies(w)
}

func (app *App) clearManagedDynamicLoginIntentCookies(w http.ResponseWriter) {
	app.clearCookie(w, app.cfg.DynamicLoginCookieName())
	if app.cfg.DynamicLoginCookieName() != dynamicLoginCookie {
		app.clearCookie(w, dynamicLoginCookie)
	}
}
