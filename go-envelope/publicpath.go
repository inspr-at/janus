package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

var (
	errPublicBasePath = errors.New("public base path is invalid")
	errPublicOrigin   = errors.New("public origin is invalid")
	errPublicJoin     = errors.New("public path join is invalid")
	publicBaseSegment = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	publicOriginHost  = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?(?::[0-9]{1,5})?$`)
	encodedDotSegment = regexp.MustCompile(`(?i)(?:%2e|\.)(?:%2e|\.)`)
)

// NormalizePublicBasePath returns the canonical native mount: empty string or
// one or more /segment components matching [A-Za-z0-9_-]+.
func NormalizePublicBasePath(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	if strings.IndexFunc(value, func(r rune) bool {
		return r < 0x20 || r == 0x7f || unicode.IsSpace(r)
	}) >= 0 {
		return "", errPublicBasePath
	}
	if strings.ContainsAny(value, `%\#?`) || strings.Contains(value, "\\") {
		return "", errPublicBasePath
	}
	if strings.HasPrefix(value, "//") {
		return "", errPublicBasePath
	}
	if !strings.HasPrefix(value, "/") {
		return "", errPublicBasePath
	}
	if strings.HasSuffix(value, "/") {
		return "", errPublicBasePath
	}
	parts := strings.Split(value, "/")
	if len(parts) < 2 || parts[0] != "" {
		return "", errPublicBasePath
	}
	for _, part := range parts[1:] {
		if part == "" || part == "." || part == ".." || !publicBaseSegment.MatchString(part) {
			return "", errPublicBasePath
		}
	}
	return value, nil
}

// JoinPublicPath joins a configured public base path and an app-relative
// endpoint exactly once. Query and fragment stay outside the join.
func JoinPublicPath(base, endpoint string) (string, error) {
	normalized, err := NormalizePublicBasePath(base)
	if err != nil {
		return "", err
	}
	if err := validateAppRelativePath(endpoint); err != nil {
		return "", err
	}
	if normalized == "" {
		return endpoint, nil
	}
	if endpoint == "/" {
		return normalized, nil
	}
	if endpoint == normalized || strings.HasPrefix(endpoint, normalized+"/") {
		return "", errPublicJoin
	}
	return normalized + endpoint, nil
}

func validateAppRelativePath(endpoint string) error {
	if endpoint == "" || !strings.HasPrefix(endpoint, "/") {
		return errPublicJoin
	}
	if strings.ContainsAny(endpoint, "?#") || strings.Contains(endpoint, "\\") || strings.Contains(endpoint, "//") {
		return errPublicJoin
	}
	if strings.Contains(endpoint, "/.") || encodedDotSegment.FindStringIndex(endpoint) != nil {
		return errPublicJoin
	}
	if strings.IndexFunc(endpoint, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return errPublicJoin
	}
	return nil
}

// PublicBaseCovers reports whether requestPath is exactly the configured mount
// or continues with a further slash-delimited segment.
func PublicBaseCovers(requestPath, base string) bool {
	if base == "" {
		return true
	}
	return requestPath == base || strings.HasPrefix(requestPath, base+"/")
}

// AppPath strips a configured public base path using an exact segment boundary.
func AppPath(base, requestPath string) string {
	if base == "" {
		return requestPath
	}
	if requestPath == base || requestPath == base+"/" {
		return "/"
	}
	if strings.HasPrefix(requestPath, base+"/") {
		return requestPath[len(base):]
	}
	return requestPath
}

func parsePublicOrigin(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	parsed, err := url.ParseRequestURI(value)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errPublicOrigin, err)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errPublicOrigin
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", errPublicOrigin
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", errPublicOrigin
	}
	if parsed.Host == "" || !publicOriginHost.MatchString(parsed.Host) {
		return "", errPublicOrigin
	}
	return parsed.Scheme + "://" + parsed.Host, nil
}

func (c Config) PublicPath(endpoint string) string {
	joined, err := JoinPublicPath(c.PublicBasePath, endpoint)
	if err != nil {
		return endpoint
	}
	return joined
}

func (c Config) PublicURLFor(endpoint string) string {
	return strings.TrimRight(c.PublicURL, "/") + c.PublicPath(endpoint)
}

func (c Config) PublicHref(href string) string {
	if href == "" {
		return c.PublicPath("/")
	}
	if strings.HasPrefix(href, "//") {
		return href
	}
	parsed, err := url.Parse(href)
	if err != nil || parsed.IsAbs() || parsed.Host != "" {
		return href
	}
	joined, err := JoinPublicPath(c.PublicBasePath, parsed.Path)
	if err != nil {
		return href
	}
	parsed.Path = joined
	parsed.RawPath = ""
	return parsed.String()
}

func canonicalizeReturnPath(base, raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, "\r\n\t") || strings.HasPrefix(raw, "//") {
		return "/", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.IsAbs() || u.Host != "" {
		return "/", false
	}
	if u.Path == "" {
		return "/", false
	}
	appPath := AppPath(base, u.Path)
	cleanPath := strings.TrimSuffix(appPath, "/")
	if appPath == "/" || cleanPath == "" {
		cleanPath = "/"
	} else {
		cleanPath = "/" + strings.TrimPrefix(cleanPath, "/")
	}
	if strings.Contains(cleanPath, "/.") || strings.Contains(cleanPath, "//") {
		return "/", false
	}
	if !loginReturnPathAllowed(cleanPath) {
		return "/", false
	}
	query, ok := safeReturnQuery(u.RawQuery)
	if !ok {
		return "/", false
	}
	if query != "" {
		return cleanPath + "?" + query, true
	}
	return cleanPath, true
}

func safeReturnQuery(raw string) (string, bool) {
	if raw == "" {
		return "", true
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return "", false
	}
	project := strings.TrimSpace(values.Get("flow_project"))
	if project == "" {
		return "", true
	}
	if strings.Contains(project, "://") || strings.HasPrefix(project, "//") || encodedDotSegment.FindStringIndex(project) != nil {
		return "", false
	}
	parsed, err := strconv.ParseUint(project, 10, 64)
	if err != nil || parsed == 0 || strconv.FormatUint(parsed, 10) != project {
		return "", false
	}
	return "flow_project=" + project, true
}

func safeLoginReturnPath(raw string) (string, bool) {
	return canonicalizeReturnPath("", raw)
}

func (app *App) safeLoginReturnPath(raw string) (string, bool) {
	if app == nil {
		return canonicalizeReturnPath("", raw)
	}
	return canonicalizeReturnPath(app.cfg.PublicBasePath, raw)
}

func (app *App) loginRedirectTarget(r *http.Request) string {
	login := app.cfg.PublicPath("/login")
	if r == nil || r.URL == nil {
		return login
	}
	returnPath, ok := app.safeLoginReturnPath(r.URL.RequestURI())
	if !ok || returnPath == "/" {
		return login
	}
	return login + "?next=" + url.QueryEscape(returnPath)
}

func (app *App) stripPublicBase(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := app.cfg.PublicBasePath
		if base == "" {
			next.ServeHTTP(w, r)
			return
		}
		if !PublicBaseCovers(r.URL.Path, base) {
			app.renderSafeFailure(w, r, http.StatusNotFound, "route_not_found", "Janus does not expose that route.", nil)
			return
		}
		clone := r.Clone(r.Context())
		clone.URL.Path = AppPath(base, r.URL.Path)
		clone.URL.RawPath = ""
		next.ServeHTTP(w, clone)
	})
}
