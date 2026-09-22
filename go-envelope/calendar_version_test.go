package main

import (
	"barta.cm/janus/internal/versioninfo"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCalendarAdapterIsActiveAndBoundToRelease(t *testing.T) {
	app, upstream := enabledFlowApp(t, sampleFlowState())
	defer upstream.Close()
	for _, roles := range [][]string{{RoleViewer}, {RoleFlowViewer}} {
		cookie := flowCookie(t, app, Session{Subject: "operator-a", Roles: roles, Expiry: time.Now().Add(time.Hour)})
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(cookie)
		out := httptest.NewRecorder()
		app.routes().ServeHTTP(out, req)
		if out.Code != 200 {
			t.Fatalf("status %d", out.Code)
		}
		for _, want := range []string{`data-janus-version`, `data-version="` + versioninfo.Current.Version + `"`, `data-scheme="inspr-calendar-v2"`, `calendar-version.mjs`, `value="pretty"`, `value="semver"`} {
			if !strings.Contains(out.Body.String(), want) {
				t.Fatal("missing", want)
			}
		}
		csp := out.Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "script-src 'nonce-") || strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
			t.Fatal("unsafe adapter CSP")
		}
		for _, path := range []string{"/static/calendar-version.mjs", "/static/vendor/calendar-version/version.js", "/static/vendor/calendar-version/display.json", "/static/vendor/calendar-version/schemes.json"} {
			r := httptest.NewRequest(http.MethodGet, path, nil)
			r.AddCookie(cookie)
			w := httptest.NewRecorder()
			app.routes().ServeHTTP(w, r)
			if w.Code != 200 {
				t.Fatal(path, w.Code)
			}
		}
	}
	if _, _, ok := calendarStaticAsset("vendor/calendar-version/manifest.json"); ok {
		t.Fatal("unnecessary manifest endpoint")
	}
	if _, _, ok := calendarStaticAsset("vendor/calendar-version/../release.json"); ok {
		t.Fatal("path traversal")
	}
	receipt := BuildProvenanceFor()
	if receipt.Version != versioninfo.Current.Version || receipt.VersionScheme != versioninfo.Scheme || receipt.ReleaseSequence != 1 || receipt.ReleaseChannel != "envelope-stable" {
		t.Fatal("release provenance incomplete")
	}
}
