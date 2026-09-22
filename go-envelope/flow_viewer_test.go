package main

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestFlowViewerRoleIsExclusiveAndHasNoEnginePermission(t *testing.T) {
	policy := RolePolicy{
		FlowViewerSubjects: map[string]bool{"reviewer": true},
		FlowViewerGroups:   map[string]bool{"janus:flow_viewer": true},
		ViewerGroups:       map[string]bool{"janus:viewer": true},
	}
	for _, tc := range []struct {
		subject, email string
		claims         []string
	}{
		{"reviewer", "", nil}, {"different-subject", "", []string{"janus:flow_viewer"}},
	} {
		roles, err := DeriveRolesChecked(tc.subject, tc.email, tc.claims, policy)
		if err != nil || !reflect.DeepEqual(roles, []string{RoleFlowViewer}) {
			t.Fatalf("restricted role: %v %v", roles, err)
		}
		for permission := range allCanonicalPermissions() {
			if SessionHasPermission(Session{Roles: roles}, permission) {
				t.Fatalf("engine permission granted: %s", permission)
			}
		}
	}
	roles, err := DeriveRolesChecked("other", "reviewer", nil, policy)
	if err != nil || len(roles) != 0 {
		t.Fatal("email must not match restricted subject")
	}
	if _, err := DeriveRolesChecked("reviewer", "", []string{"janus:viewer"}, policy); err == nil {
		t.Fatal("mixed role accepted")
	}
	if _, err := DeriveRolesChecked("other", "", []string{"janus:flow_viewer", "janus:flow_viewer"}, policy); err == nil {
		t.Fatal("duplicate claim accepted")
	}
	if validateSessionRoles([]string{RoleFlowViewer, RoleViewer}) || !validateSessionRoles([]string{RoleFlowViewer}) {
		t.Fatal("session role ceiling")
	}
	roles, err = DeriveRolesChecked("ordinary", "", []string{"janus:viewer"}, policy)
	if err != nil || !reflect.DeepEqual(roles, []string{RoleViewer}) {
		t.Fatal("ordinary viewer changed")
	}
}

func TestFlowViewerReadsOnlyBoundProjectWithoutCatalog(t *testing.T) {
	app, upstream := enabledFlowApp(t, sampleFlowState())
	defer upstream.Close()
	session := Session{Subject: "operator-a", Roles: []string{RoleFlowViewer}, Expiry: time.Now().Add(time.Hour)}
	cookie := flowCookie(t, app, session)
	for _, path := range []string{"/", "/flow/shell-state.json", "/static/flow-host-bootstrap.mjs"} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		app.routes().ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status %d", path, w.Code)
		}
		if path == "/" && (!strings.Contains(w.Body.String(), "Flow review") || !strings.Contains(w.Body.String(), "inspr-flow-shell")) {
			t.Fatal("missing Flow landing")
		}
		for _, forbidden := range []string{"Janus Zitadel application", "csb1 age identity", "zitadel-janus-oidc", "secrets/csb1-"} {
			if strings.Contains(w.Body.String(), forbidden) {
				t.Fatalf("catalog in %s", path)
			}
		}
	}
	for _, tc := range []struct {
		subject, path string
		disabled      bool
	}{
		{"operator-a", "/?flow_project=99", false},
		{"unbound", "/", false},
		{"operator-a", "/", true},
		{"operator-a", "/flow/shell-state.json?flow_project=99", false},
	} {
		app.flow.config.Enabled = !tc.disabled
		r := httptest.NewRequest(http.MethodGet, tc.path, nil)
		session.Subject = tc.subject
		r.AddCookie(flowCookie(t, app, session))
		w := httptest.NewRecorder()
		app.routes().ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("unbound/disabled accepted: %s %d", tc.path, w.Code)
		}
	}
}

func TestFlowViewerDeniesEveryOtherRegisteredRouteAndFutureRoute(t *testing.T) {
	app, upstream := enabledFlowApp(t, sampleFlowState())
	defer upstream.Close()
	session := Session{Subject: "operator-a", Roles: []string{RoleFlowViewer}, Expiry: time.Now().Add(time.Hour)}
	cookie := flowCookie(t, app, session)
	allowed := map[string]bool{"GET /": true, "GET /flow/shell-state.json": true, "GET /static/": true, "GET /login": true, "GET /oidc/callback": true, "GET /auth/reset": true, "GET /favicon.ico": true, "POST /logout": true}
	for _, route := range app.routeSpecs() {
		if allowed[route.pattern] {
			continue
		}
		parts := strings.SplitN(route.pattern, " ", 2)
		path := parts[1]
		for strings.Contains(path, "{") {
			start, end := strings.Index(path, "{"), strings.Index(path, "}")
			path = path[:start] + "denied" + path[end+1:]
		}
		r := httptest.NewRequest(parts[0], path, nil)
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		app.routes().ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s returned %d", route.pattern, w.Code)
		}
	}
	called := false
	guard := app.flowViewerBoundary(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	for _, path := range []string{"/future-metadata", "/static/other.js"} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		guard.ServeHTTP(w, r)
		if called || w.Code != http.StatusForbidden {
			t.Fatal("future route escaped boundary")
		}
	}
	// Logout is an ordinary session action and retains its CSRF check.
	r := httptest.NewRequest(http.MethodPost, "/logout", nil)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	app.routes().ServeHTTP(w, r)
	if w.Code < 400 {
		t.Fatal("logout skipped CSRF")
	}
}

func TestFlowViewerDoesNotChangeOrdinaryViewerCatalog(t *testing.T) {
	app := newTestApp(t)
	session := Session{Subject: "viewer", Roles: []string{RoleViewer}, Expiry: time.Now().Add(time.Hour)}
	r := httptest.NewRequest(http.MethodGet, "/api/warden/descriptors", nil)
	r.AddCookie(flowCookie(t, app, session))
	w := httptest.NewRecorder()
	app.routes().ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "zitadel-janus-oidc") {
		t.Fatal("ordinary viewer catalog changed")
	}
}
