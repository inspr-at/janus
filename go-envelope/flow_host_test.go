package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	paimosProjectRef17 = "paimos:proj-9b2899fb59591130607952d66fcb5607"
	paimosProjectRef99 = "paimos:proj-492d86f8b3c9707ece3f9fb96f07682a"
)

func TestPaimosOpaqueRefMatchesLiteralFixture(t *testing.T) {
	if got := paimosOpaqueRef("proj", "17"); got != paimosProjectRef17 {
		t.Fatalf("proj 17 = %s", got)
	}
	if got := paimosOpaqueRef("proj", "99"); got != paimosProjectRef99 {
		t.Fatalf("proj 99 = %s", got)
	}
}

func TestFlowVendorManifestMatchesEmbeddedAssets(t *testing.T) {
	raw, err := flowAssetFS.ReadFile("ui/vendor/flow-shell/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Version          string `json:"version"`
		SourceCommit     string `json:"source_commit"`
		RuntimeTGZSHA256 string `json:"runtime_tgz_sha256"`
		Files            []struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"files"`
	}
	if json.Unmarshal(raw, &manifest) != nil {
		t.Fatal("manifest json")
	}
	if manifest.Version != "0.1.4" || manifest.SourceCommit != "efc5e63a6a37cc9d1fd9aa437f8808b3a6536acf" {
		t.Fatalf("unexpected pin version=%s commit=%s", manifest.Version, manifest.SourceCommit)
	}
	if manifest.RuntimeTGZSHA256 != "sha256:b5e773eeca6eff42432efe4c776e9079132ccaa58f65a48a64bbc5b6a18d55b0" {
		t.Fatalf("unexpected tgz pin %s", manifest.RuntimeTGZSHA256)
	}
	for _, entry := range manifest.Files {
		data, err := flowAssetFS.ReadFile("ui/vendor/flow-shell/" + entry.Path)
		if err != nil {
			t.Fatalf("missing %s: %v", entry.Path, err)
		}
		sum := sha256.Sum256(data)
		got := "sha256:" + hex.EncodeToString(sum[:])
		if got != entry.SHA256 {
			t.Fatalf("digest mismatch for %s", entry.Path)
		}
	}
}

func TestDisabledFlowPreservesExistingDashboard(t *testing.T) {
	app := newTestApp(t)
	session := Session{Subject: "user-1", Roles: []string{RoleViewer}, Expiry: time.Now().UTC().Add(time.Hour)}
	cookie := flowCookie(t, app, session)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("status=%d", out.Code)
	}
	body := out.Body.String()
	if strings.Contains(body, "inspr-flow-shell") || strings.Contains(body, "flow-host-bootstrap") {
		t.Fatal("disabled configuration must not wrap existing pages")
	}
	csp := out.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'none'") {
		t.Fatalf("disabled CSP changed: %s", csp)
	}
}

func TestInvalidFlowConfigFailsClosed(t *testing.T) {
	parent, key := privateFlowDir(t, "invalid")
	cfgPath := filepath.Join(parent, "flow.json")
	writePrivateFile(t, cfgPath, []byte(`{"schema":"wrong"}`))
	if _, err := loadFlowHostConfig(cfgPath); err == nil {
		t.Fatal("expected invalid config")
	}
	email := `{
		"schema":"inspr.janus.flow-host-config.v1",
		"schema_version":1,
		"enabled":true,
		"host_id":"janus-test",
		"paimos_origin":"https://paimos.example",
		"api_key_file":"` + key + `",
		"bindings":[{"project_id":17,"label":"Test","principal_refs":["user@example.test"]}]
	}`
	writePrivateFile(t, cfgPath, []byte(email))
	if _, err := loadFlowHostConfig(cfgPath); err == nil {
		t.Fatal("email principal binding must fail closed")
	}
}

func TestLoopbackOriginRequiresExplicitFlag(t *testing.T) {
	if _, err := parseFlowOrigin("https://paimos.example", false); err != nil {
		t.Fatal(err)
	}
	if _, err := parseFlowOrigin("http://127.0.0.1:9", true); err != nil {
		t.Fatal(err)
	}
	if _, err := parseFlowOrigin("http://127.0.0.1:9", false); err == nil {
		t.Fatal("loopback without flag")
	}
	if _, err := parseFlowOrigin("http://evil.example", true); err == nil {
		t.Fatal("non-loopback http")
	}
}

func TestFlowProjectionAndSafeNavigation(t *testing.T) {
	app, upstream := enabledFlowApp(t, sampleFlowState())
	defer upstream.Close()
	session := Session{Subject: "operator-a", Name: "Operator", Email: "hidden@example.test", Roles: []string{RoleViewer}, Expiry: time.Now().UTC().Add(time.Hour)}
	cookie := flowCookie(t, app, session)

	req := httptest.NewRequest(http.MethodGet, "/flow/shell-state.json", nil)
	req.AddCookie(cookie)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", out.Code, out.Body.String())
	}
	var payload flowShellResponse
	if json.Unmarshal(out.Body.Bytes(), &payload) != nil {
		t.Fatal(out.Body.String())
	}
	if !payload.Enabled || !payload.MountShell || payload.ShellState == nil {
		t.Fatalf("payload=%#v", payload)
	}
	wire := out.Body.String()
	if strings.Contains(wire, "shell_state") || strings.Contains(wire, "hidden@example.test") || strings.Contains(wire, "operator-a") || strings.Contains(wire, "api.key") {
		t.Fatalf("browser payload leaked identity or secret path: %s", wire)
	}
	identity, _ := payload.ShellState["identityContext"].(map[string]any)
	if identity["principal_kind"] != "local_host" || identity["actor_kind"] != "human" {
		t.Fatalf("identity=%v", identity)
	}
	header, _ := payload.ShellState["header"].(map[string]any)
	if header["userLabel"] != flowHostVerifiedHumanLabel || header["appName"] != "Janus" {
		t.Fatalf("header=%v", header)
	}
	delivery, _ := payload.ShellState["delivery"].(map[string]any)
	if delivery["viewedStage"] != float64(3) {
		t.Fatalf("janus stage not highlighted: %v", delivery["viewedStage"])
	}

	page := httptest.NewRequest(http.MethodGet, "/", nil)
	page.AddCookie(cookie)
	pageOut := httptest.NewRecorder()
	app.routes().ServeHTTP(pageOut, page)
	html := pageOut.Body.String()
	if !strings.Contains(html, `inspr-flow-shell`) || !strings.Contains(html, "/static/flow-host-bootstrap.mjs") {
		t.Fatalf("enabled page must mount published shell: %s", html[:min(400, len(html))])
	}
	if strings.Contains(pageOut.Header().Get("Content-Security-Policy"), "script-src 'none'") {
		t.Fatal("mounted shell must allow the nonce module")
	}

	intent := flowIntentPOST(t, app, session, cookie, `{"type":"flow:review-batch","identity":null,"detail":{"type":"flow:review-batch","detail":{"batchRef":"batch-test","executes":false}}}`)
	if intent.Code != http.StatusOK {
		t.Fatalf("intent=%d %s", intent.Code, intent.Body.String())
	}
	var result flowIntentResponse
	if json.Unmarshal(intent.Body.Bytes(), &result) != nil {
		t.Fatal(intent.Body.String())
	}
	if result.Executed || !strings.Contains(result.Location, "/projects/17?tab=overview#baseline-batch") {
		t.Fatalf("review navigation=%#v", result)
	}
}

func TestUnauthorizedPrincipalAndProject(t *testing.T) {
	app, upstream := enabledFlowApp(t, sampleFlowState())
	defer upstream.Close()
	unknown := Session{Subject: "operator-unknown", Roles: []string{RoleViewer}, Expiry: time.Now().UTC().Add(time.Hour)}
	cookie := flowCookie(t, app, unknown)
	req := httptest.NewRequest(http.MethodGet, "/flow/shell-state.json", nil)
	req.AddCookie(cookie)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if strings.Contains(out.Body.String(), "shellState") && strings.Contains(out.Body.String(), `"mountShell":true`) {
		t.Fatal("unknown principal must not mount")
	}
	if !strings.Contains(out.Body.String(), "no configured Flow binding") {
		t.Fatalf("body=%s", out.Body.String())
	}

	bound := Session{Subject: "operator-a", Roles: []string{RoleViewer}, Expiry: time.Now().UTC().Add(time.Hour)}
	boundCookie := flowCookie(t, app, bound)
	wrong := httptest.NewRequest(http.MethodGet, "/flow/shell-state.json?flow_project=99", nil)
	wrong.AddCookie(boundCookie)
	wrongOut := httptest.NewRecorder()
	app.routes().ServeHTTP(wrongOut, wrong)
	if strings.Contains(wrongOut.Body.String(), `"mountShell":true`) {
		t.Fatal("unbound project must fail closed")
	}
}

func TestMaliciousUpstreamPayloadIsRejected(t *testing.T) {
	state := sampleFlowState()
	state["identityContext"] = map[string]any{"project_ref": paimosProjectRef99, "email": "leaked@example.test"}
	app, upstream := enabledFlowApp(t, state)
	defer upstream.Close()
	session := Session{Subject: "operator-a", Roles: []string{RoleViewer}, Expiry: time.Now().UTC().Add(time.Hour)}
	cookie := flowCookie(t, app, session)
	req := httptest.NewRequest(http.MethodGet, "/flow/shell-state.json", nil)
	req.AddCookie(cookie)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if strings.Contains(out.Body.String(), `"mountShell":true`) {
		t.Fatal("wrong project_ref must not mount")
	}
	if !strings.Contains(out.Body.String(), "project binding mismatch") {
		t.Fatalf("body=%s", out.Body.String())
	}
}

func TestFlowStripsUpstreamIdentityFields(t *testing.T) {
	state := sampleFlowState()
	state["email"] = "leaked@example.test"
	state["token"] = "secret-token"
	app, upstream := enabledFlowApp(t, state)
	defer upstream.Close()
	session := Session{Subject: "operator-a", Roles: []string{RoleViewer}, Expiry: time.Now().UTC().Add(time.Hour)}
	cookie := flowCookie(t, app, session)
	req := httptest.NewRequest(http.MethodGet, "/flow/shell-state.json", nil)
	req.AddCookie(cookie)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	body := out.Body.String()
	if strings.Contains(body, "leaked@example.test") || strings.Contains(body, "secret-token") {
		t.Fatalf("leaked fields survived: %s", body)
	}
}

func TestMachineAuthorizationHeaderIsRejected(t *testing.T) {
	app, upstream := enabledFlowApp(t, sampleFlowState())
	defer upstream.Close()
	session := Session{Subject: "operator-a", Roles: []string{RoleViewer}, Expiry: time.Now().UTC().Add(time.Hour)}
	cookie := flowCookie(t, app, session)
	req := httptest.NewRequest(http.MethodGet, "/flow/shell-state.json", nil)
	req.AddCookie(cookie)
	req.Header.Set("Authorization", "Bearer machine-token")
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if strings.Contains(out.Body.String(), `"mountShell":true`) {
		t.Fatal("service token cannot act as a Flow human")
	}
}

func TestStaleIdentityBlocksStart(t *testing.T) {
	app, upstream := enabledFlowApp(t, sampleFlowState())
	defer upstream.Close()
	session := Session{Subject: "operator-a", Roles: []string{RoleViewer}, Expiry: time.Now().UTC().Add(time.Hour)}
	cookie := flowCookie(t, app, session)
	req := httptest.NewRequest(http.MethodGet, "/flow/shell-state.json", nil)
	req.AddCookie(cookie)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	var payload flowShellResponse
	if json.Unmarshal(out.Body.Bytes(), &payload) != nil {
		t.Fatal(out.Body.String())
	}
	identity, _ := payload.ShellState["identityContext"].(map[string]any)
	body := map[string]any{
		"type": "flow:start-intent",
		"identity": map[string]any{
			"status":           "present",
			"principal_ref":    identity["principal_ref"],
			"project_ref":      identity["project_ref"],
			"binding_ref":      identity["binding_ref"],
			"context_revision": identity["context_revision"],
			"actor_kind":       "human",
			"expires_at":       "2020-01-01T00:00:00Z",
			"fresh_until":      identity["fresh_until"],
		},
	}
	raw, _ := json.Marshal(body)
	intent := flowIntentPOST(t, app, session, cookie, string(raw))
	if intent.Code != http.StatusConflict {
		t.Fatalf("status=%d %s", intent.Code, intent.Body.String())
	}
	if !strings.Contains(intent.Body.String(), "expired") {
		t.Fatalf("body=%s", intent.Body.String())
	}
}

func TestStartDoesNotExecuteAndPreliminaryDoesNotClaimJanusApply(t *testing.T) {
	now := int64(1_700_000_000)
	state := sampleFlowState()
	state["prerequisites"] = map[string]any{
		"requirementsBaseline": sampleGate(now),
		"pharosTarget": map[string]any{
			"status":      "pass",
			"evidenceRef": "paimos:ev-target",
			"observedAt":  isoTimestamp(now),
			"freshUntil":  isoTimestamp(now + 600),
			"readiness":   "preliminary",
		},
	}
	app, upstream := enabledFlowApp(t, state)
	defer upstream.Close()
	app.flow.now = func() int64 { return now }
	session := Session{Subject: "operator-a", Roles: []string{RoleViewer}, Expiry: time.Now().UTC().Add(time.Hour)}
	cookie := flowCookie(t, app, session)
	req := httptest.NewRequest(http.MethodGet, "/flow/shell-state.json", nil)
	req.AddCookie(cookie)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	var payload flowShellResponse
	if json.Unmarshal(out.Body.Bytes(), &payload) != nil {
		t.Fatal(out.Body.String())
	}
	delivery, _ := payload.ShellState["delivery"].(map[string]any)
	if evidence, ok := delivery["stageEvidence"].([]any); ok && len(evidence) > 3 && evidence[3] == "performed" {
		t.Fatal("preliminary Pharos context must not claim Janus applied work")
	}
	identity, _ := payload.ShellState["identityContext"].(map[string]any)
	body := map[string]any{
		"type": "flow:start-intent",
		"identity": map[string]any{
			"status":           "present",
			"principal_ref":    identity["principal_ref"],
			"project_ref":      identity["project_ref"],
			"binding_ref":      identity["binding_ref"],
			"context_revision": identity["context_revision"],
			"actor_kind":       "human",
			"expires_at":       identity["expires_at"],
			"fresh_until":      identity["fresh_until"],
		},
		"detail": map[string]any{"action": "janus_apply"},
	}
	raw, _ := json.Marshal(body)
	intent := flowIntentPOST(t, app, session, cookie, string(raw))
	if intent.Code != http.StatusOK {
		t.Fatalf("status=%d %s", intent.Code, intent.Body.String())
	}
	var result flowIntentResponse
	if json.Unmarshal(intent.Body.Bytes(), &result) != nil {
		t.Fatal(intent.Body.String())
	}
	if result.Executed || result.Location != "" {
		t.Fatalf("start must not execute or navigate: %#v", result)
	}
	if !strings.Contains(result.Notice, "Start stays blocked") {
		t.Fatalf("notice=%q", result.Notice)
	}
}

func TestFlowIntentRequiresCSRF(t *testing.T) {
	app, upstream := enabledFlowApp(t, sampleFlowState())
	defer upstream.Close()
	session := Session{Subject: "operator-a", Roles: []string{RoleViewer}, Expiry: time.Now().UTC().Add(time.Hour)}
	cookie := flowCookie(t, app, session)
	req := httptest.NewRequest(http.MethodPost, "/flow/intents", strings.NewReader(`{"type":"flow:review-batch"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", app.cfg.PublicURL)
	req.AddCookie(cookie)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusForbidden {
		t.Fatalf("status=%d %s", out.Code, out.Body.String())
	}
}

func TestFlowCacheDoesNotMixPrincipals(t *testing.T) {
	hits := 0
	state := sampleFlowState()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(state)
	}))
	t.Cleanup(server.Close)
	app := newTestApp(t)
	app.flow = testFlowService(t, server.URL)
	app.flow.now = func() int64 { return 1_700_000_000 }
	first := Session{Subject: "operator-a", Roles: []string{RoleViewer}, Expiry: time.Now().UTC().Add(time.Hour)}
	second := Session{Subject: "operator-b", Roles: []string{RoleViewer}, Expiry: time.Now().UTC().Add(time.Hour)}
	for _, session := range []Session{first, second} {
		app.flow.config.Bindings[0].PrincipalRefs[session.Subject] = struct{}{}
		cookie := flowCookie(t, app, session)
		req := httptest.NewRequest(http.MethodGet, "/flow/shell-state.json", nil)
		req.AddCookie(cookie)
		out := httptest.NewRecorder()
		app.routes().ServeHTTP(out, req)
		if out.Code != http.StatusOK || !strings.Contains(out.Body.String(), `"mountShell":true`) {
			t.Fatalf("status=%d %s", out.Code, out.Body.String())
		}
	}
	if hits != 2 {
		t.Fatalf("cache mixed principals: hits=%d", hits)
	}
}

func TestFlowStaticAssetsAreExact(t *testing.T) {
	app := newTestApp(t)
	req := httptest.NewRequest(http.MethodGet, "/static/vendor/flow-shell/src/inspr-flow-shell.js", nil)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK || !strings.Contains(out.Header().Get("Content-Type"), "javascript") {
		t.Fatalf("status=%d type=%s", out.Code, out.Header().Get("Content-Type"))
	}
	missing := httptest.NewRequest(http.MethodGet, "/static/vendor/flow-shell/manifest.json", nil)
	missingOut := httptest.NewRecorder()
	app.routes().ServeHTTP(missingOut, missing)
	if missingOut.Code != http.StatusNotFound {
		t.Fatal("manifest must not be a public runtime route")
	}
}

func TestMultipleBindingsRequireProjectScope(t *testing.T) {
	service := &flowHostService{
		config: flowHostConfig{
			Enabled:      true,
			HostID:       "janus-test",
			PaimosOrigin: mustURL(t, "https://paimos.example"),
			APIKeyFile:   "/tmp/janus-flow-test.key",
			Bindings: []flowBinding{
				{ProjectID: 17, ExpectedProjectRef: paimosProjectRef17, Label: "A", PrincipalRefs: map[string]struct{}{"operator-a": {}}},
				{ProjectID: 18, ExpectedProjectRef: paimosProjectRef99, Label: "B", PrincipalRefs: map[string]struct{}{"operator-a": {}}},
			},
			ConfigDigest: "sha256:test",
		},
	}
	if _, err := service.selectBinding("operator-a", 0); err == nil {
		t.Fatal("ambiguous binding")
	}
	binding, err := service.selectBinding("operator-a", 17)
	if err != nil || binding.ProjectID != 17 {
		t.Fatalf("project 17: %v %#v", err, binding)
	}
}

func TestJanusApplyRequiresJanusGate(t *testing.T) {
	now := int64(1_700_000_000)
	shell := map[string]any{
		"evaluatedAt": isoTimestamp(now),
		"delivery": map[string]any{
			"status":         "draft",
			"batchRef":       "batch-test",
			"baselineRef":    "baseline-test",
			"baselineDigest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		"prerequisites": map[string]any{
			"requirementsBaseline": sampleGate(now),
			"pharosTarget": map[string]any{
				"status":      "pass",
				"evidenceRef": "paimos:ev-target",
				"observedAt":  isoTimestamp(now),
				"freshUntil":  isoTimestamp(now + 600),
				"readiness":   "live",
			},
		},
	}
	if startPermitted(shell, "janus_apply", now) {
		t.Fatal("janus_apply without janus gate")
	}
	prereq, _ := shell["prerequisites"].(map[string]any)
	prereq["janusGate"] = sampleGate(now)
	if !startPermitted(shell, "janus_apply", now) {
		t.Fatal("janus_apply should pass with gate")
	}
}

func TestSubmittedIdentityReadsNestedStartDetail(t *testing.T) {
	request := flowIntentRequest{
		Type:   "flow:start-intent",
		Detail: json.RawMessage(`{"type":"flow:start-intent","detail":{"identity":{"status":"present","principal_ref":"janus-test:prin-abc"}}}`),
	}
	extracted := submittedIdentity(request)
	if extracted["principal_ref"] != "janus-test:prin-abc" {
		t.Fatalf("%v", extracted)
	}
}

func TestBootstrapIsExternalModule(t *testing.T) {
	html, mounted := (&App{}).injectFlowShell(httptest.NewRequest(http.MethodGet, "/", nil), "<body><main></main></body>")
	if mounted {
		t.Fatal("nil flow must not mount")
	}
	if strings.Contains(html, "inspr-flow-shell") {
		t.Fatal(html)
	}
}

func flowCookie(t *testing.T, app *App, session Session) *http.Cookie {
	t.Helper()
	rr := httptest.NewRecorder()
	app.writeSession(rr, session)
	cookies := rr.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("missing session cookie")
	}
	return cookies[0]
}

func flowIntentPOST(t *testing.T, app *App, session Session, cookie *http.Cookie, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/flow/intents", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", app.cfg.PublicURL)
	req.Header.Set("X-CSRF-Token", app.csrfToken(session))
	req.AddCookie(cookie)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	return out
}

func enabledFlowApp(t *testing.T, state map[string]any) (*App, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/projects/17/baseline-batches/flow-state" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(state)
	}))
	app := newTestApp(t)
	app.flow = testFlowService(t, server.URL)
	app.flow.now = func() int64 { return 1_700_000_000 }
	return app, server
}

func testFlowService(t *testing.T, origin string) *flowHostService {
	t.Helper()
	_, key := privateFlowDir(t, "svc")
	parsed, err := url.Parse(origin)
	if err != nil {
		t.Fatal(err)
	}
	return &flowHostService{
		config: flowHostConfig{
			Enabled:       true,
			HostID:        "janus-test",
			PaimosOrigin:  parsed,
			APIKeyFile:    key,
			InstanceLabel: "Janus test",
			Bindings: []flowBinding{{
				ProjectID:          17,
				ExpectedProjectRef: paimosProjectRef17,
				Label:              "Test project",
				PrincipalRefs:      map[string]struct{}{"operator-a": {}},
			}},
			ConfigDigest: "sha256:test",
		},
		client: &http.Client{Timeout: flowRequestTimeout, CheckRedirect: func(*http.Request, []*http.Request) error {
			return errRedirect
		}},
		cache: &flowProjectionCache{entries: map[flowCacheKey]flowCachedProjection{}},
		now:   func() int64 { return 1_700_000_000 },
	}
}

var errRedirect = errString("redirect refused")

type errString string

func (e errString) Error() string { return string(e) }

func sampleGate(now int64) map[string]any {
	return map[string]any{
		"status":      "pass",
		"gateKind":    "requirements_baseline",
		"evidenceRef": "paimos:ev-test",
		"observedAt":  isoTimestamp(now),
		"freshUntil":  isoTimestamp(now + 600),
	}
}

func sampleFlowState() map[string]any {
	now := int64(1_700_000_000)
	return map[string]any{
		"evaluatedAt": isoTimestamp(now),
		"header":      map[string]any{"appName": "Paimos", "projectName": "Upstream", "userLabel": "Machine", "userInitials": "MC"},
		"health":      map[string]any{"status": "available"},
		"delivery": map[string]any{
			"status":         "draft",
			"batchRef":       "batch-test",
			"baselineRef":    "baseline-test",
			"baselineDigest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			"stageEvidence":  []any{"performed", "unknown", "unknown", "unknown"},
		},
		"prerequisites": map[string]any{
			"requirementsBaseline": sampleGate(now),
		},
		"progress":              map[string]any{},
		"executionModes":        []string{"manual"},
		"selectedExecutionMode": "manual",
		"selectedAction":        "build",
		"identityContext": map[string]any{
			"project_ref": paimosProjectRef17,
		},
	}
}

func privateFlowDir(t *testing.T, label string) (string, string) {
	t.Helper()
	parent := filepath.Join(t.TempDir(), "flow-"+label)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(parent, "api.key")
	writePrivateFile(t, key, []byte("01234567890123456789012345678901"))
	return parent, key
}

func writePrivateFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustURL(t *testing.T, value string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestCheckFlowShellVendorScript(t *testing.T) {
	cmd := exec.Command("bash", "../scripts/check-flow-shell-vendor.sh")
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("vendor check: %v %s", err, out)
	}
	if !strings.Contains(string(out), "flow-shell vendor manifest verified") {
		t.Fatalf("output=%s", out)
	}
}
