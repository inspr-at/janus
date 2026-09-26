package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
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
	if manifest.Version != "0.1.5" || manifest.SourceCommit != "4b10524cd2a22e136e750ebfef2bf12eb2b7db5a" {
		t.Fatalf("unexpected pin version=%s commit=%s", manifest.Version, manifest.SourceCommit)
	}
	if manifest.RuntimeTGZSHA256 != "sha256:17a56f0b2899c91847521672bc9b58b82e85e0259dd69f8e9f416949561641c7" {
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
	if !strings.Contains(csp, "script-src 'nonce-") || !strings.Contains(body, "calendar-version.mjs") {
		t.Fatalf("dashboard must enable only the nonce-bound version module: %s", csp)
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
				{Key: "17", ProjectID: 17, ExpectedProjectRef: paimosProjectRef17, Label: "A", PrincipalRefs: map[string]struct{}{"operator-a": {}}},
				{Key: "18", ProjectID: 18, ExpectedProjectRef: paimosProjectRef99, Label: "B", PrincipalRefs: map[string]struct{}{"operator-a": {}}},
			},
			ConfigDigest: "sha256:test",
		},
	}
	if _, err := service.selectBinding("operator-a", ""); err == nil {
		t.Fatal("ambiguous binding")
	}
	binding, err := service.selectBinding("operator-a", "17")
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
				Key:                "17",
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
		cache: &flowProjectionCache{entries: map[flowCacheKey]flowCachedProjection{}, revisions: map[string]uint64{}},
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

const (
	aeonProjectNodeID = "71d807c5-6ee1-4a18-8742-54ed5b74690d"
	aeonProjectKey    = "JANUS"
	aeonNodeKey       = "PRJ-12"
	aeonTenantSlug    = "inspr"
)

func TestFlowHostConfigV2(t *testing.T) {
	parent, key := privateFlowDir(t, "aeon")
	cfgPath := filepath.Join(parent, "flow.json")
	writePrivateFile(t, cfgPath, []byte(aeonConfigJSON(key, "")))
	cfg, err := loadFlowHostConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Upstream != flowUpstreamAeon || cfg.TenantSlug != aeonTenantSlug || !cfg.Enabled || len(cfg.Bindings) != 1 {
		t.Fatalf("%#v", cfg)
	}
	binding := cfg.Bindings[0]
	if binding.Key != aeonProjectNodeID || binding.ProjectID != 0 || binding.ProjectNodeID != aeonProjectNodeID || binding.ProjectKey != aeonProjectKey || binding.NodeKey != aeonNodeKey {
		t.Fatalf("%#v", binding)
	}
	if cfg.PaimosOrigin == nil || cfg.PaimosOrigin.Host != "aeon.example" || cfg.PaimosBrowserURL != nil {
		t.Fatalf("origin=%v browser=%v", cfg.PaimosOrigin, cfg.PaimosBrowserURL)
	}

	for _, raw := range []string{
		strings.Replace(aeonConfigJSON(key, ""), `"tenant_slug":"inspr"`, `"tenant_slug":"inspr","unexpected":true`, 1),
		strings.Replace(aeonConfigJSON(key, ""), aeonProjectNodeID, "71D807C5-6EE1-4A18-8742-54ED5B74690D", 1),
		strings.Replace(aeonConfigJSON(key, ""), `"project_key":"JANUS"`, `"project_key":"janus"`, 1),
		strings.Replace(aeonConfigJSON(key, ""), `"node_key":"PRJ-12"`, `"node_key":"PRJ-01"`, 1),
		strings.Replace(aeonConfigJSON(key, ""), `"tenant_slug":"inspr",`, "", 1),
		aeonConfigJSON(key, `{"project_node_id":"`+aeonProjectNodeID+`","project_key":"OTHER","node_key":"PRJ-13","label":"Other","principal_refs":["operator-a"]}`),
		aeonConfigJSON(key, `{"project_node_id":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee","project_key":"JANUS","node_key":"PRJ-13","label":"Other","principal_refs":["operator-a"]}`),
		strings.Replace(aeonConfigJSON(key, ""), `"upstream":"aeon"`, `"upstream":"paimos"`, 1),
	} {
		writePrivateFile(t, cfgPath, []byte(raw))
		if _, err := loadFlowHostConfig(cfgPath); err == nil {
			t.Fatalf("accepted invalid config: %s", raw)
		}
	}
}

func TestClassicFlowConfigV1StillLoads(t *testing.T) {
	parent, key := privateFlowDir(t, "classic")
	cfgPath := filepath.Join(parent, "flow.json")
	writePrivateFile(t, cfgPath, []byte(`{
		"schema":"inspr.janus.flow-host-config.v1",
		"schema_version":1,
		"enabled":true,
		"host_id":"janus-test",
		"paimos_origin":"https://paimos.example",
		"api_key_file":"`+key+`",
		"bindings":[{"project_id":17,"label":"Test","principal_refs":["operator-a"]}]
	}`))
	cfg, err := loadFlowHostConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Upstream != flowUpstreamClassic || len(cfg.Bindings) != 1 || cfg.Bindings[0].Key != "17" || cfg.Bindings[0].ProjectID != 17 || cfg.Bindings[0].ProjectNodeID != "" {
		t.Fatalf("%#v", cfg)
	}
}

func TestAeonJourneyFetchAndProjection(t *testing.T) {
	var method, path, auth, accept, userAgent string
	var body []byte
	journey := sampleAeonJourney()
	journey["project_node_id"] = strings.ToUpper(aeonProjectNodeID)
	journey["email"] = "leaked@example.test"
	journey["catalog"] = map[string]any{"secret": "no"}
	journey["raw_marker"] = "should-not-leak"
	journey["token"] = "secret-token"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		path = r.URL.RequestURI()
		auth = r.Header.Get("Authorization")
		accept = r.Header.Get("Accept")
		userAgent = r.Header.Get("User-Agent")
		body, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(journey)
	}))
	t.Cleanup(server.Close)
	app := newTestApp(t)
	app.flow = testAeonService(t, server.URL)
	app.flow.now = func() int64 { return 1_700_000_000 }
	session := Session{Subject: "operator-a", Roles: []string{RoleViewer}, Expiry: time.Now().UTC().Add(time.Hour)}
	cookie := flowCookie(t, app, session)
	req := httptest.NewRequest(http.MethodGet, "/flow/shell-state.json?flow_project="+aeonProjectNodeID, nil)
	req.AddCookie(cookie)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if method != http.MethodGet || path != "/api/projects/"+aeonProjectNodeID+"/journey" || auth != "Bearer 01234567890123456789012345678901" || len(body) != 0 {
		t.Fatalf("method=%s path=%s auth=%s body=%q accept=%s ua=%s", method, path, auth, body, accept, userAgent)
	}
	if accept != "application/json" || userAgent != flowUserAgent {
		t.Fatalf("accept=%s ua=%s", accept, userAgent)
	}
	var payload flowShellResponse
	if json.Unmarshal(out.Body.Bytes(), &payload) != nil || !payload.MountShell {
		t.Fatalf("body=%s", out.Body.String())
	}
	wire := out.Body.String()
	for _, forbidden := range []string{"leaked@example.test", "secret-token", "should-not-leak", "raw_marker", "current_release_id", "requirements_digest_sha256", "tenant_slug", "nested-diagnostic-marker", "nested-next-marker", "nested-stage-marker", "cccccccc-dddd", "approve_deploy", "progress"} {
		if strings.Contains(wire, forbidden) {
			t.Fatalf("raw journey field %s leaked: %s", forbidden, wire)
		}
	}
	for key := range payload.ShellState {
		switch key {
		case "evaluatedAt", "header", "health", "delivery", "prerequisites", "executionModes", "selectedExecutionMode", "selectedAction", "identityContext":
		default:
			t.Fatalf("unexpected shell field %s", key)
		}
	}
	delivery, _ := payload.ShellState["delivery"].(map[string]any)
	if delivery["status"] != "authorized" || delivery["batchRef"] != "release:aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" || delivery["baselineRef"] != "requirements:7" {
		t.Fatalf("delivery=%v", delivery)
	}
	// The bundled flow-shell consumes activeStage and stageEvidence; the
	// eight Aeon stages fold onto its four.
	if delivery["activeStage"] != float64(2) || delivery["batchStatusLabel"] != "Next in Aeon: Approve deploy" {
		t.Fatalf("delivery=%v", delivery)
	}
	evidence, _ := delivery["stageEvidence"].([]any)
	if len(evidence) != 4 || evidence[0] != "performed" || evidence[1] != "performed" || evidence[2] != "unknown" {
		t.Fatalf("stageEvidence=%v", evidence)
	}
	prereq, _ := payload.ShellState["prerequisites"].(map[string]any)
	pharos, _ := prereq["pharosTarget"].(map[string]any)
	if pharos["readiness"] != "preliminary" || pharos["evidenceRef"] != "aeon:deploy-bbbbbbbbcccc4ddd" {
		t.Fatalf("pharos=%v", pharos)
	}
	gate, _ := prereq["janusGate"].(map[string]any)
	// A journey approval id is history, not a live permit: never a pass.
	if gate["status"] != "unknown" || gate["evidenceRef"] != nil {
		t.Fatalf("gate=%v", gate)
	}
	if payload.ShellState["selectedAction"] != "janus_prepare" {
		t.Fatalf("selectedAction=%v", payload.ShellState["selectedAction"])
	}
	if payload.ProjectionMeta == nil || payload.ProjectionMeta.ProjectID != 0 || payload.ProjectionMeta.ProjectNodeID != aeonProjectNodeID || strings.Contains(wire, `"projectId"`) {
		t.Fatalf("meta=%#v", payload.ProjectionMeta)
	}

	page := httptest.NewRequest(http.MethodGet, "/?flow_project="+aeonProjectNodeID, nil)
	page.AddCookie(cookie)
	pageOut := httptest.NewRecorder()
	app.routes().ServeHTTP(pageOut, page)
	html := pageOut.Body.String()
	if !strings.Contains(html, `data-flow-upstream="aeon"`) || !strings.Contains(html, `data-flow-project-key="JANUS"`) || !strings.Contains(html, `data-flow-project="`+aeonProjectNodeID+`"`) {
		t.Fatalf("shell attrs missing: %s", html)
	}

	reviewer := Session{Subject: "operator-a", Roles: []string{RoleFlowViewer}, Expiry: time.Now().UTC().Add(time.Hour)}
	reviewPage := httptest.NewRequest(http.MethodGet, "/?flow_project="+aeonProjectNodeID, nil)
	reviewPage.AddCookie(flowCookie(t, app, reviewer))
	reviewOut := httptest.NewRecorder()
	app.routes().ServeHTTP(reviewOut, reviewPage)
	if !strings.Contains(reviewOut.Body.String(), "Open project in Aeon") || !strings.Contains(reviewOut.Body.String(), "/p/JANUS?view=journey") {
		t.Fatalf("viewer=%s", reviewOut.Body.String())
	}

	intent := flowIntentOn(t, app, session, cookie, "/flow/intents?flow_project="+aeonProjectNodeID, `{"type":"flow:review-batch","identity":null,"detail":{}}`)
	var result flowIntentResponse
	if json.Unmarshal(intent.Body.Bytes(), &result) != nil || result.Routed != "aeon-project-journey" || !strings.Contains(result.Location, "/p/JANUS?view=journey") || strings.Contains(result.Location, "#") {
		t.Fatalf("review=%#v", result)
	}
	if !strings.Contains(result.Notice, "Aeon") || strings.Contains(result.Notice, "Paimos") {
		t.Fatalf("notice=%q", result.Notice)
	}
	headerIntent := flowIntentOn(t, app, session, cookie, "/flow/intents?flow_project="+aeonProjectNodeID, `{"type":"flow:header-project"}`)
	var headerResult flowIntentResponse
	if json.Unmarshal(headerIntent.Body.Bytes(), &headerResult) != nil || headerResult.Routed != "aeon-project-journey" || headerResult.Location != result.Location || headerResult.Notice != "Project navigation stays in configured Aeon." {
		t.Fatalf("header=%#v", headerResult)
	}

	origin := app.flow.paimosBrowserString()
	if got := app.flow.validNavigationLocation(origin + "/p/JANUS?view=journey"); got == "" {
		t.Fatal("configured journey rejected")
	}
	withUser := *app.flow.paimosBrowser()
	withUser.User = url.UserPassword("user", "pass")
	withUser.Path = "/p/JANUS"
	withUser.RawQuery = "view=journey"
	for _, blocked := range []string{
		origin + "/projects/17?tab=overview#baseline-batch",
		origin + "/p/OTHER?view=journey",
		origin + "/p/JANUS?view=other",
		origin + "/p/JANUS?view=journey&stage=deploy",
		origin + "/p/JANUS?view=journey#live",
		"https://evil.example/p/JANUS?view=journey",
		withUser.String(),
	} {
		if app.flow.validNavigationLocation(blocked) != "" {
			t.Fatalf("accepted %s", blocked)
		}
	}
}

func TestAeonBindingMismatchesAndStatuses(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		mutate  func(map[string]any)
		message string
	}{
		{"project node", http.StatusOK, func(j map[string]any) { j["project_node_id"] = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee" }, "configured project binding mismatch"},
		{"project key", http.StatusOK, func(j map[string]any) { j["project_key"] = "OTHER" }, "configured project binding mismatch"},
		{"node key", http.StatusOK, func(j map[string]any) { j["node_key"] = "PRJ-99" }, "configured project binding mismatch"},
		{"tenant", http.StatusOK, func(j map[string]any) { j["tenant_slug"] = "other" }, "configured tenant binding mismatch"},
		{"forbidden", http.StatusForbidden, nil, "Configured Aeon key cannot read this project journey."},
		{"missing", http.StatusNotFound, nil, "Configured Aeon project journey is unavailable for this binding."},
		{"refused", http.StatusBadGateway, nil, "Configured Aeon journey refused the upstream request."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			journey := sampleAeonJourney()
			if tc.mutate != nil {
				tc.mutate(journey)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				if tc.status == http.StatusOK {
					_ = json.NewEncoder(w).Encode(journey)
				}
			}))
			t.Cleanup(server.Close)
			app := newTestApp(t)
			app.flow = testAeonService(t, server.URL)
			session := Session{Subject: "operator-a", Roles: []string{RoleViewer}, Expiry: time.Now().UTC().Add(time.Hour)}
			req := httptest.NewRequest(http.MethodGet, "/flow/shell-state.json", nil)
			req.AddCookie(flowCookie(t, app, session))
			out := httptest.NewRecorder()
			app.routes().ServeHTTP(out, req)
			if strings.Contains(out.Body.String(), `"mountShell":true`) || !strings.Contains(out.Body.String(), tc.message) {
				t.Fatalf("body=%s", out.Body.String())
			}
		})
	}
}

func TestAeonRevisionRegressionIsRefused(t *testing.T) {
	revision := 5
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		journey := sampleAeonJourney()
		journey["revision"] = revision
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(journey)
	}))
	t.Cleanup(server.Close)
	app := newTestApp(t)
	app.flow = testAeonService(t, server.URL)
	now := int64(1_700_000_000)
	app.flow.now = func() int64 { return now }
	session := Session{Subject: "operator-a", Roles: []string{RoleViewer}, Expiry: time.Now().UTC().Add(time.Hour)}
	cookie := flowCookie(t, app, session)
	first := httptest.NewRequest(http.MethodGet, "/flow/shell-state.json", nil)
	first.AddCookie(cookie)
	firstOut := httptest.NewRecorder()
	app.routes().ServeHTTP(firstOut, first)
	if !strings.Contains(firstOut.Body.String(), `"mountShell":true`) {
		t.Fatalf("first=%s", firstOut.Body.String())
	}
	revision = 4
	now = 1_700_000_400
	second := httptest.NewRequest(http.MethodGet, "/flow/shell-state.json", nil)
	second.AddCookie(cookie)
	secondOut := httptest.NewRecorder()
	app.routes().ServeHTTP(secondOut, second)
	if strings.Contains(secondOut.Body.String(), `"mountShell":true`) || !strings.Contains(secondOut.Body.String(), "older revision") {
		t.Fatalf("regression=%s", secondOut.Body.String())
	}
}

func TestFlowProjectSelectorAcceptsUUIDAndRejectsGarbage(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/?flow_project="+aeonProjectNodeID, nil)
	got, err := parseOptionalFlowProject(req)
	if err != nil || got != aeonProjectNodeID {
		t.Fatalf("uuid=%q %v", got, err)
	}
	classic := httptest.NewRequest(http.MethodGet, "/?flow_project=17", nil)
	got, err = parseOptionalFlowProject(classic)
	if err != nil || got != "17" {
		t.Fatalf("classic=%q %v", got, err)
	}
	absent := httptest.NewRequest(http.MethodGet, "/", nil)
	got, err = parseOptionalFlowProject(absent)
	if err != nil || got != "" {
		t.Fatalf("absent=%q %v", got, err)
	}
	// Classic keeps its original lenient decimal selector (JANUS-458).
	lenient := httptest.NewRequest(http.MethodGet, "/?flow_project=017", nil)
	if got, err := parseOptionalFlowProject(lenient); err != nil || got != "17" {
		t.Fatalf("classic lenient=%q %v", got, err)
	}
	if _, ok := safeReturnQuery("flow_project=017"); ok {
		t.Fatal("public path accepted non-canonical 017")
	}
	for _, raw := range []string{"0", "17abc", "71D807C5-6EE1-4A18-8742-54ED5B74690D", "not-a-uuid", "71d807c56ee14a18874254ed5b74690d"} {
		bad := httptest.NewRequest(http.MethodGet, "/?flow_project="+url.QueryEscape(raw), nil)
		if _, err := parseOptionalFlowProject(bad); err == nil {
			t.Fatalf("accepted %q", raw)
		}
		if _, ok := safeReturnQuery("flow_project=" + raw); ok {
			t.Fatalf("public path accepted %q", raw)
		}
	}
	query, ok := safeReturnQuery("flow_project=" + aeonProjectNodeID)
	if !ok || query != "flow_project="+aeonProjectNodeID {
		t.Fatalf("query=%q ok=%v", query, ok)
	}
	query, ok = safeReturnQuery("flow_project=17")
	if !ok || query != "flow_project=17" {
		t.Fatalf("classic query=%q ok=%v", query, ok)
	}
}

func aeonConfigJSON(key, extraBinding string) string {
	bindings := `{"project_node_id":"` + aeonProjectNodeID + `","project_key":"` + aeonProjectKey + `","node_key":"` + aeonNodeKey + `","label":"Janus","principal_refs":["operator-a"]}`
	if extraBinding != "" {
		bindings += "," + extraBinding
	}
	return `{
		"schema":"inspr.janus.flow-host-config.v2",
		"schema_version":2,
		"enabled":true,
		"host_id":"janus-test",
		"upstream":"aeon",
		"aeon_origin":"https://aeon.example",
		"aeon_public_url":null,
		"api_key_file":"` + key + `",
		"instance_label":null,
		"tenant_slug":"inspr",
		"bindings":[` + bindings + `]
	}`
}

func sampleAeonJourney() map[string]any {
	return map[string]any{
		"project_node_id":            aeonProjectNodeID,
		"project_key":                aeonProjectKey,
		"node_key":                   aeonNodeKey,
		"tenant_slug":                aeonTenantSlug,
		"revision":                   4,
		"stage":                      "deploy",
		"stage_source":               "aeon",
		"imported":                   false,
		"current_release_id":         "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
		"requirements_revision":      7,
		"requirements_digest_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"launch_readiness":           map[string]any{"can_admit": true, "reason": "", "email": "leaked@example.test", "diagnostic": "nested-diagnostic-marker"},
		"next_action":                map[string]any{"key": "approve_deploy", "label": "Approve deploy", "stage": "deploy", "available": true, "token": "secret-token", "raw_marker": "nested-next-marker"},
		"stages": []any{
			map[string]any{"key": "inspire", "state": "done"},
			map[string]any{"key": "shape", "state": "done"},
			map[string]any{"key": "requirements", "state": "done"},
			map[string]any{"key": "plan", "state": "done"},
			map[string]any{"key": "build", "state": "done"},
			map[string]any{"key": "deploy", "state": "current", "handoff_id": "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"},
			map[string]any{"key": "access", "state": "later", "gate_approval_id": "cccccccc-dddd-4eee-8fff-000000000000", "token": "secret-token", "stage_marker": "nested-stage-marker"},
			map[string]any{"key": "live", "state": "later"},
		},
	}
}

func testAeonService(t *testing.T, origin string) *flowHostService {
	t.Helper()
	service := testFlowService(t, origin)
	service.config.Upstream = flowUpstreamAeon
	service.config.TenantSlug = aeonTenantSlug
	service.config.Bindings = []flowBinding{{
		Key:           aeonProjectNodeID,
		ProjectNodeID: aeonProjectNodeID,
		ProjectKey:    aeonProjectKey,
		NodeKey:       aeonNodeKey,
		Label:         "Janus",
		PrincipalRefs: map[string]struct{}{"operator-a": {}},
	}}
	return service
}

func flowIntentOn(t *testing.T, app *App, session Session, cookie *http.Cookie, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", app.cfg.PublicURL)
	req.Header.Set("X-CSRF-Token", app.csrfToken(session))
	req.AddCookie(cookie)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	return out
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

func TestAeonShellStateUsesOnlyFlowShellValues(t *testing.T) {
	binding := flowBinding{ProjectNodeID: aeonProjectNodeID, ProjectKey: aeonProjectKey, Label: "Janus"}
	allStates := func(state string) []any {
		out := []any{}
		for _, key := range []string{"inspire", "shape", "requirements", "plan", "build", "deploy", "access", "live"} {
			out = append(out, map[string]any{"key": key, "state": state})
		}
		return out
	}
	live := aeonShellState(map[string]any{"stage": "live", "stages": allStates("done")}, binding, 1_700_000_000)
	delivery := live["delivery"].(map[string]any)
	if delivery["status"] != "completed" || delivery["activeStage"] != 3 {
		t.Fatalf("live delivery=%v", delivery)
	}
	for _, evidence := range delivery["stageEvidence"].([]any) {
		if evidence != "performed" {
			t.Fatalf("live evidence=%v", delivery["stageEvidence"])
		}
	}
	blockedStages := allStates("later")
	blockedStages[5] = map[string]any{"key": "deploy", "state": "blocked"}
	blockedStages[6] = map[string]any{"key": "access", "state": "skipped"}
	blocked := aeonShellState(map[string]any{"stage": "deploy", "stages": blockedStages, "next_action": map[string]any{"label": "<script>x</script>"}}, binding, 1_700_000_000)
	delivery = blocked["delivery"].(map[string]any)
	if delivery["status"] != "blocked" || delivery["activeStage"] != 2 || delivery["stageEvidence"].([]any)[3] != "not_in_batch" || delivery["batchStatusLabel"] != "Aeon journey" {
		t.Fatalf("blocked delivery=%v", delivery)
	}
	allowed := map[string]bool{"draft": true, "authorized": true, "in_progress": true, "blocked": true, "completed": true}
	for _, stage := range []string{"inspire", "shape", "requirements", "plan", "build", "deploy", "access", "live", ""} {
		shell := aeonShellState(map[string]any{"stage": stage}, binding, 1_700_000_000)
		if status := shell["delivery"].(map[string]any)["status"].(string); !allowed[status] {
			t.Fatalf("stage %q status %q", stage, status)
		}
	}
}
