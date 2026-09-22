package main

import (
	"barta.cm/janus/internal/versioninfo"
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"strings"
)

//go:embed ui/calendar-version.mjs ui/calendar-version.css
var calendarAssets embed.FS

func canonicalVersion() string { return versioninfo.Current.Version }
func canonicalScheme() string  { return versioninfo.Scheme }

func calendarControl() template.HTML {
	return template.HTML(fmt.Sprintf(`<span class="janus-version" data-janus-version data-version="%s" data-scheme="%s"><span data-coordinate>%s</span> <label><span class="janus-version-label">Version format</span><select data-version-format aria-label="Version format"><option value="pretty">Pretty</option><option value="semver">SemVer</option></select></label></span>`, versioninfo.Current.Version, versioninfo.Scheme, versioninfo.Current.Version))
}

// Only pages that explicitly render the product version adapter gain a nonce
// module. Error, authentication and non-HTML response CSP remains unchanged.
func (app *App) calendarPageWrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/" {
			next.ServeHTTP(w, r)
			return
		}
		capture := &flowCapture{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(capture, r)
		body := capture.body.String()
		if capture.status == http.StatusOK && strings.Contains(w.Header().Get("Content-Type"), "text/html") && strings.Contains(body, "data-janus-version") {
			app.allowFlowScripts(w, r)
			module := fmt.Sprintf(`<script type="module" nonce="%s" src="%s"></script>`, htmlEscapeAttr(cspNonceFromContext(r.Context())), htmlEscapeAttr(app.cfg.PublicPath("/static/calendar-version.mjs")))
			body = strings.Replace(body, "</body>", module+"</body>", 1)
			body = strings.Replace(body, "</head>", fmt.Sprintf(`<link rel="stylesheet" href="%s"></head>`, htmlEscapeAttr(app.cfg.PublicPath("/static/calendar-version.css"))), 1)
			w.Header().Del("Content-Length")
		}
		w.WriteHeader(capture.status)
		_, _ = w.Write([]byte(body))
	})
}
func calendarStaticAsset(name string) ([]byte, string, bool) {
	if name == "calendar-version.css" {
		raw, err := calendarAssets.ReadFile("ui/calendar-version.css")
		return raw, "text/css; charset=utf-8", err == nil
	}
	if name == "calendar-version.mjs" {
		raw, err := calendarAssets.ReadFile("ui/calendar-version.mjs")
		return raw, "text/javascript; charset=utf-8", err == nil
	}
	if key, ok := strings.CutPrefix(name, "vendor/calendar-version/"); ok {
		return versioninfo.Asset(key)
	}
	return nil, "", false
}
