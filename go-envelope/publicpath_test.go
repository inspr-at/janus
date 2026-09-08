package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestNormalizePublicBasePath(t *testing.T) {
	valid := []string{"", "/janus", "/inspr/janus"}
	for _, value := range valid {
		got, err := NormalizePublicBasePath(value)
		if err != nil || got != value {
			t.Fatalf("NormalizePublicBasePath(%q) got %q err=%v", value, got, err)
		}
	}
	invalid := []string{
		"/",
		"/janus/",
		"/janus//vault",
		"/./janus",
		"/../janus",
		"/janus/.",
		"/%2e%2e",
		"/janus?next=1",
		"/janus#frag",
		"janus",
		"//janus",
		"/janus\\x",
		"/janus foo",
		"/janus%2fextra",
	}
	for _, value := range invalid {
		if _, err := NormalizePublicBasePath(value); err == nil {
			t.Fatalf("NormalizePublicBasePath(%q) accepted", value)
		}
	}
}

func TestJoinPublicPath(t *testing.T) {
	got, err := JoinPublicPath("", "/oidc/callback")
	if err != nil || got != "/oidc/callback" {
		t.Fatalf("empty base: %q %v", got, err)
	}
	got, err = JoinPublicPath("/janus", "/")
	if err != nil || got != "/janus" {
		t.Fatalf("root under prefix: %q %v", got, err)
	}
	got, err = JoinPublicPath("/janus", "/oidc/callback")
	if err != nil || got != "/janus/oidc/callback" {
		t.Fatalf("join: %q %v", got, err)
	}
	if _, err := JoinPublicPath("/janus", "/janus/login"); err == nil {
		t.Fatal("double join must fail")
	}
}

func TestPublicBaseCoversSegmentBoundary(t *testing.T) {
	if PublicBaseCovers("/janusfoo", "/janus") || PublicBaseCovers("/login", "/janus") || PublicBaseCovers("/", "/janus") {
		t.Fatal("outside-mount paths must not match")
	}
	if !PublicBaseCovers("/janus", "/janus") || !PublicBaseCovers("/janus/login", "/janus") {
		t.Fatal("exact prefix and further segment must match")
	}
}

func TestParsePublicOriginRejectsPath(t *testing.T) {
	got, err := parsePublicOrigin("https://vault.barta.cm/")
	if err != nil || got != "https://vault.barta.cm" {
		t.Fatalf("trailing slash origin: %q %v", got, err)
	}
	if _, err := parsePublicOrigin("https://vault.barta.cm/janus"); err == nil {
		t.Fatal("origin must not include a path")
	}
}

func TestLoadConfigPublicBasePath(t *testing.T) {
	t.Setenv("JANUS_REQUIRE_AUTH", "false")
	t.Setenv("JANUS_PUBLIC_URL", "https://apps.fixture.test")
	t.Setenv("JANUS_PUBLIC_BASE_PATH", "/janus")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PublicURL != "https://apps.fixture.test" || cfg.PublicBasePath != "/janus" {
		t.Fatalf("cfg=%#v", cfg)
	}
	t.Setenv("JANUS_PUBLIC_BASE_PATH", "/janus/")
	if _, err := loadConfig(); err == nil {
		t.Fatal("trailing slash must fail closed")
	}
}

func TestPrefixedAppServesExactMountAndRejectsOutside(t *testing.T) {
	app := prefixedTestApp(t, "/janus")
	app.oauth = testOAuthConfig()
	app.oauth.RedirectURL = app.cfg.PublicURLFor("/oidc/callback")

	outside := httptest.NewRecorder()
	app.routes().ServeHTTP(outside, httptest.NewRequest(http.MethodGet, "/login", nil))
	if outside.Code != http.StatusNotFound {
		t.Fatalf("unprefixed login status=%d", outside.Code)
	}
	sibling := httptest.NewRecorder()
	app.routes().ServeHTTP(sibling, httptest.NewRequest(http.MethodGet, "/janusfoo/login", nil))
	if sibling.Code != http.StatusNotFound {
		t.Fatalf("sibling path status=%d", sibling.Code)
	}

	login := httptest.NewRecorder()
	app.routes().ServeHTTP(login, httptest.NewRequest(http.MethodGet, "/janus/login", nil))
	if login.Code != http.StatusFound {
		t.Fatalf("prefixed login status=%d body=%s", login.Code, login.Body.String())
	}
	location := login.Header().Get("Location")
	redirectURI := ""
	if parsed, err := url.Parse(location); err == nil {
		redirectURI = parsed.Query().Get("redirect_uri")
	}
	if redirectURI != "https://vault.barta.cm/janus/oidc/callback" {
		t.Fatalf("OIDC redirect_uri=%q location=%s", redirectURI, location)
	}
	for _, cookie := range login.Result().Cookies() {
		if cookie.Path != "/" || cookie.Domain != "" {
			t.Fatalf("cookie must stay Path=/ with no Domain: %#v", cookie)
		}
	}

	static := httptest.NewRecorder()
	app.routes().ServeHTTP(static, httptest.NewRequest(http.MethodGet, "/janus/static/janus.css", nil))
	if static.Code != http.StatusOK || !strings.Contains(static.Header().Get("Content-Type"), "text/css") {
		t.Fatalf("prefixed css status=%d type=%s", static.Code, static.Header().Get("Content-Type"))
	}

	root := httptest.NewRecorder()
	app.routes().ServeHTTP(root, httptest.NewRequest(http.MethodGet, "/janus", nil))
	if root.Code != http.StatusOK {
		t.Fatalf("prefixed root status=%d body=%s", root.Code, root.Body.String())
	}
	body := root.Body.String()
	for _, want := range []string{`href="/janus/login"`, `href="/janus/static/janus-logo.svg"`, `src="/janus/static/janus-logo.svg"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("prefixed landing missing %s", want)
		}
	}
	if strings.Contains(body, `href="/login"`) || strings.Contains(body, `href="/static/janus-logo.svg"`) {
		t.Fatal("prefixed landing leaked origin-root links")
	}
}

func TestPrefixedLoginReturnPreservesFlowProjectAndRejectsEscape(t *testing.T) {
	app := prefixedTestApp(t, "/janus")
	got, ok := app.safeLoginReturnPath("/janus/access?flow_project=17")
	if !ok || got != "/access?flow_project=17" {
		t.Fatalf("prefixed return got %q ok=%v", got, ok)
	}
	escaped, ok := app.safeLoginReturnPath("/login")
	if ok || escaped != "/" {
		t.Fatalf("login is not a return target: %q ok=%v", escaped, ok)
	}
	open, ok := app.safeLoginReturnPath("https://evil.example/janus")
	if ok || open != "/" {
		t.Fatalf("open redirect: %q ok=%v", open, ok)
	}

	app.oauth = testOAuthConfig()
	req := httptest.NewRequest(http.MethodGet, "/janus/access?flow_project=17", nil)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("landing status=%d", out.Code)
	}
	if !strings.Contains(out.Body.String(), `href="/janus/login?next=%2Faccess%3Fflow_project%3D17"`) {
		t.Fatalf("missing flow_project return: %s", out.Body.String())
	}
}

func TestPrefixedLogoutAndCSRFStayOriginBound(t *testing.T) {
	app := prefixedTestApp(t, "/janus")
	session := Session{Subject: "user-1", Roles: []string{RoleViewer}, Expiry: time.Now().UTC().Add(time.Hour)}
	cookieWriter := httptest.NewRecorder()
	app.writeSession(cookieWriter, session)
	sessionCookie := cookieWriter.Result().Cookies()[0]
	if sessionCookie.Path != "/" || sessionCookie.Domain != "" || !sessionCookie.Secure {
		t.Fatalf("session cookie %#v", sessionCookie)
	}

	csrf := app.csrfToken(session)
	cross := httptest.NewRequest(http.MethodPost, "/janus/logout", strings.NewReader("csrf_token="+csrf))
	cross.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	cross.Header.Set("Origin", "https://evil.example")
	cross.AddCookie(sessionCookie)
	crossOut := httptest.NewRecorder()
	app.routes().ServeHTTP(crossOut, cross)
	if crossOut.Code != http.StatusForbidden {
		t.Fatalf("cross-origin logout status=%d", crossOut.Code)
	}

	okReq := httptest.NewRequest(http.MethodPost, "/janus/logout", strings.NewReader("csrf_token="+url.QueryEscape(csrf)))
	okReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	okReq.Header.Set("Origin", app.cfg.PublicURL)
	okReq.AddCookie(sessionCookie)
	okOut := httptest.NewRecorder()
	app.routes().ServeHTTP(okOut, okReq)
	if okOut.Code != http.StatusFound || okOut.Header().Get("Location") != "/janus" {
		t.Fatalf("same-origin logout status=%d location=%q", okOut.Code, okOut.Header().Get("Location"))
	}
}

func TestPrefixedDoesNotTrustForwardedIdentity(t *testing.T) {
	app := prefixedTestApp(t, "/janus")
	app.oauth = testOAuthConfig()
	req := httptest.NewRequest(http.MethodGet, "/janus", nil)
	req.Header.Set("X-Forwarded-User", "spoofed-admin")
	req.Header.Set("X-Remote-User", "spoofed-admin")
	req.Header.Set("X-Forwarded-Prefix", "/other")
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK {
		t.Fatalf("status=%d", out.Code)
	}
	body := out.Body.String()
	if strings.Contains(body, "spoofed-admin") || !strings.Contains(body, `href="/janus/login"`) {
		t.Fatalf("forwarded identity must not authenticate: %s", body)
	}
}

func TestPrefixedFlowRoutesAndBrowserURL(t *testing.T) {
	app, upstream := enabledFlowApp(t, sampleFlowState())
	defer upstream.Close()
	browser, err := url.Parse("https://apps.fixture.test/paimos")
	if err != nil {
		t.Fatal(err)
	}
	app.flow.config.PaimosBrowserURL = browser
	app = withPublicBase(t, app, "/janus")
	session := Session{Subject: "operator-a", Name: "Operator", Roles: []string{RoleViewer}, Expiry: time.Now().UTC().Add(time.Hour)}
	cookie := flowCookie(t, app, session)

	state := httptest.NewRequest(http.MethodGet, "/janus/flow/shell-state.json?flow_project=17", nil)
	state.AddCookie(cookie)
	stateOut := httptest.NewRecorder()
	app.routes().ServeHTTP(stateOut, state)
	if stateOut.Code != http.StatusOK || !strings.Contains(stateOut.Body.String(), `"mountShell":true`) {
		t.Fatalf("prefixed flow state status=%d body=%s", stateOut.Code, stateOut.Body.String())
	}

	page := httptest.NewRequest(http.MethodGet, "/janus/?flow_project=17", nil)
	page.AddCookie(cookie)
	pageOut := httptest.NewRecorder()
	app.routes().ServeHTTP(pageOut, page)
	html := pageOut.Body.String()
	if !strings.Contains(html, `src="/janus/static/flow-host-bootstrap.mjs"`) {
		t.Fatalf("bootstrap src: %s", html[0:min(500, len(html))])
	}
	if !strings.Contains(html, `data-flow-paimos-origin="https://apps.fixture.test/paimos"`) {
		t.Fatalf("browser url: %s", html[0:min(500, len(html))])
	}
	if strings.Contains(html, `src="/static/flow-host-bootstrap.mjs"`) {
		t.Fatal("bootstrap stayed origin-root")
	}

	intent := httptest.NewRequest(http.MethodPost, "/janus/flow/intents?flow_project=17", strings.NewReader(`{"type":"flow:review-batch"}`))
	intent.Header.Set("Content-Type", "application/json")
	intent.Header.Set("Origin", app.cfg.PublicURL)
	intent.Header.Set("X-CSRF-Token", app.csrfToken(session))
	intent.AddCookie(cookie)
	intentOut := httptest.NewRecorder()
	app.routes().ServeHTTP(intentOut, intent)
	if intentOut.Code != http.StatusOK {
		t.Fatalf("intent status=%d %s", intentOut.Code, intentOut.Body.String())
	}
	if !strings.Contains(intentOut.Body.String(), "https://apps.fixture.test/paimos/projects/17?tab=overview") {
		t.Fatalf("prefixed paimos browser location: %s", intentOut.Body.String())
	}
	if strings.Contains(intentOut.Body.String(), upstream.URL+"/projects/") {
		t.Fatal("intent used upstream origin for browser navigation")
	}
}

func TestDisabledAndMissingFlowStayUnchangedOnStandalone(t *testing.T) {
	app := newTestApp(t)
	session := Session{Subject: "user-1", Roles: []string{RoleViewer}, Expiry: time.Now().UTC().Add(time.Hour)}
	cookie := flowCookie(t, app, session)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, req)
	if out.Code != http.StatusOK || strings.Contains(out.Body.String(), "inspr-flow-shell") {
		t.Fatalf("standalone disabled flow changed: status=%d", out.Code)
	}
}

func TestParseFlowBrowserURL(t *testing.T) {
	got, err := parseFlowBrowserURL("https://apps.fixture.test/paimos", false)
	if err != nil || got.Host != "apps.fixture.test" || got.Path != "/paimos" {
		t.Fatalf("got=%v err=%v", got, err)
	}
	if _, err := parseFlowBrowserURL("https://apps.fixture.test/paimos/", false); err == nil {
		t.Fatal("trailing slash")
	}
	if _, err := parseFlowBrowserURL("https://paimos.example/api?x=1", false); err == nil {
		t.Fatal("query")
	}
}

func prefixedTestApp(t *testing.T, base string) *App {
	t.Helper()
	return withPublicBase(t, newTestApp(t), base)
}

func withPublicBase(t *testing.T, app *App, base string) *App {
	t.Helper()
	normalized, err := NormalizePublicBasePath(base)
	if err != nil {
		t.Fatal(err)
	}
	app.cfg.PublicBasePath = normalized
	app.templates = templatesFor(normalized)
	if app.oauth != nil {
		app.oauth.RedirectURL = app.cfg.PublicURLFor("/oidc/callback")
	}
	return app
}

func TestLoadConfigRejectsPublicURLPath(t *testing.T) {
	t.Setenv("JANUS_REQUIRE_AUTH", "false")
	t.Setenv("JANUS_PUBLIC_URL", "https://vault.barta.cm/janus")
	if err := os.Unsetenv("JANUS_PUBLIC_BASE_PATH"); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(); err == nil {
		t.Fatal("path on JANUS_PUBLIC_URL must fail")
	}
}
