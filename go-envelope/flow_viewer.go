package main

// JANUS-476: a browser-only reviewer must never enter the general Janus
// dashboard, catalog or mutation handlers. This closed boundary also applies
// to future routes, independently of their canonical engine permission.

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

func (app *App) flowViewerBoundary(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, ok := app.readSession(r)
		if !ok || !HasRole(session, RoleFlowViewer) {
			next.ServeHTTP(w, r)
			return
		}
		// Keep the real identity-provider login and ordinary logout contract.
		if r.Method == http.MethodGet && (r.URL.Path == "/login" || r.URL.Path == "/oidc/callback" || r.URL.Path == "/auth/reset" || r.URL.Path == "/favicon.ico") {
			next.ServeHTTP(w, r)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), sessionKey{}, session))
		if r.Method == http.MethodPost && r.URL.Path == "/logout" {
			app.handleLogout(w, r)
			return
		}
		if r.Method != http.MethodGet || !flowHumanSession(r, session) || app.flow == nil || !app.flow.config.Enabled {
			denyFlowViewer(w, r)
			return
		}
		projectKey, err := parseOptionalFlowProject(r)
		if err != nil {
			denyFlowViewer(w, r)
			return
		}
		bound, reason := app.flow.resolveContext(session, projectKey)
		if reason != "" {
			denyFlowViewer(w, r)
			return
		}
		switch r.URL.Path {
		case "/":
			app.renderFlowViewer(w, r, bound)
		case "/flow/shell-state.json":
			app.handleFlowShellState(w, r)
		default:
			if name, yes := strings.CutPrefix(r.URL.Path, "/static/"); yes {
				_, _, calendarAllowed := calendarStaticAsset(name)
				if _, _, allowed := flowStaticAsset(name); allowed || calendarAllowed {
					next.ServeHTTP(w, r)
					return
				}
			}
			denyFlowViewer(w, r)
		}
	})
}

func denyFlowViewer(w http.ResponseWriter, r *http.Request) {
	writeJSONError(w, r, http.StatusForbidden, "flow_scope_only", "This account can only read its configured Flow project.")
}

func (app *App) renderFlowViewer(w http.ResponseWriter, r *http.Request, bound flowResolvedContext) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Chromium sends Origin:null for a form under no-referrer. Preserve only
	// the origin so ordinary sign-out passes the unchanged same-origin CSRF gate.
	w.Header().Set("Referrer-Policy", "origin")
	// No dashboardData, catalog, readiness or general posture is evaluated here.
	linkLabel := "Open project in Paimos"
	if app.flow.config.Upstream == flowUpstreamAeon {
		linkLabel = "Open project in Aeon"
	}
	_, _ = fmt.Fprintf(w, `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Flow review · Janus</title><style nonce="%s">body{margin:0;background:#f7f7f5;color:#20252a;font:16px/1.6 system-ui,sans-serif}main{box-sizing:border-box;max-width:880px;margin:48px auto;padding:32px;background:white;border-radius:12px}h1{font-size:14px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:#626b73}h2{font-size:32px;line-height:1.2;margin:12px 0 24px}p{max-width:60ch}a{color:#245c70;text-underline-offset:3px}button{font:inherit;padding:6px 14px;background:white;border:1px solid #bcc6c9;border-radius:6px;cursor:pointer}@media(max-width:600px){main{margin:16px auto;padding:24px}h2{font-size:26px}}</style></head><body><main data-inspr-flow-reviewer><h1>Flow review</h1><h2>%s</h2><p>Read-only project context. This account has no access to secrets or operational actions.</p><p><a href="%s">%s</a></p><form method="post" action="%s"><input type="hidden" name="csrf_token" value="%s"><button type="submit">Sign out</button></form><p>%s</p></main></body></html>`, htmlEscapeAttr(cspNonceFromContext(r.Context())), htmlEscapeAttr(bound.binding.Label), htmlEscapeAttr(app.flow.projectOverviewURL(bound.binding)), htmlEscapeAttr(linkLabel), htmlEscapeAttr(app.cfg.PublicPath("/logout")), htmlEscapeAttr(app.csrfToken(currentSession(r.Context()))), calendarControl())
}
