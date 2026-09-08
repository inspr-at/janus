package main

// JANUS-458: opt-in bounded @inspr/flow-shell host with read-only Paimos
// projection, Janus-issued local_host identity, and guarded review navigation.

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	flowConfigEnv              = "JANUS_FLOW_CONFIG_FILE"
	flowLoopbackOriginEnv      = "JANUS_FLOW_ALLOW_LOOPBACK_ORIGIN"
	flowConfigSchema           = "inspr.janus.flow-host-config.v1"
	flowConfigSchemaVersion    = uint16(1)
	flowIdentityContract       = "inspr.flow-identity/0.1-draft"
	flowAuthorityDisclaimer    = "Schema validity is not authentication. Host must issue this context from a verified principal and revalidate on every consequential intent."
	flowUserAgent              = "janus-flow-host/1"
	flowMaxConfigBytes         = 256 * 1024
	flowMaxAPIKeyBytes         = 512
	flowMaxResponseBytes       = 256 * 1024
	flowRequestTimeout         = 15 * time.Second
	flowContextTTL             = 8 * time.Hour
	flowPaimosHostID           = "paimos"
	flowReviewFragment         = "#baseline-batch"
	flowHostVerifiedHumanLabel = "Host-verified human"
	flowEvaluationMaxAgeSecs   = int64(15 * 60)
	flowIntentMaxBytes         = 4 * 1024
)

//go:embed ui/flow-host-bootstrap.mjs ui/vendor/flow-shell
var flowAssetFS embed.FS

var flowFetchGeneration atomic.Uint64

type flowErrorKind int

const (
	flowErrConfiguration flowErrorKind = iota
	flowErrCredential
	flowErrTransport
	flowErrUnavailable
)

type flowError struct {
	kind    flowErrorKind
	message string
}

func (e flowError) Error() string { return e.message }

type flowConfigDocument struct {
	Schema        string                `json:"schema"`
	SchemaVersion uint16                `json:"schema_version"`
	Enabled       bool                  `json:"enabled"`
	HostID        string                `json:"host_id"`
	PaimosOrigin  string                `json:"paimos_origin"`
	APIKeyFile    string                `json:"api_key_file"`
	InstanceLabel *string               `json:"instance_label"`
	Bindings      []flowBindingDocument `json:"bindings"`
}

type flowBindingDocument struct {
	ProjectID     uint64   `json:"project_id"`
	ProjectRef    *string  `json:"project_ref"`
	Label         string   `json:"label"`
	PrincipalRefs []string `json:"principal_refs"`
}

type flowBinding struct {
	ProjectID          uint64
	ExpectedProjectRef string
	Label              string
	PrincipalRefs      map[string]struct{}
}

type flowHostConfig struct {
	Enabled       bool
	HostID        string
	PaimosOrigin  *url.URL
	APIKeyFile    string
	InstanceLabel string
	Bindings      []flowBinding
	ConfigDigest  string
}

type flowHostService struct {
	config flowHostConfig
	client *http.Client
	cache  *flowProjectionCache
	now    func() int64
}

type flowProjectionCache struct {
	mu      sync.Mutex
	entries map[flowCacheKey]flowCachedProjection
}

type flowCacheKey struct {
	projectID    uint64
	principalRef string
}

type flowCachedProjection struct {
	generation        uint64
	fetchedAt         int64
	sourceRevision    string
	shellState        map[string]any
	paimosEvaluatedAt string
}

type flowShellResponse struct {
	Enabled           bool                `json:"enabled"`
	MountShell        bool                `json:"mountShell"`
	UnavailableReason string              `json:"unavailableReason,omitempty"`
	ShellState        map[string]any      `json:"shellState,omitempty"`
	ProjectionMeta    *flowProjectionMeta `json:"projectionMeta,omitempty"`
}

type flowProjectionMeta struct {
	EvaluatedAt     string `json:"evaluatedAt"`
	FreshUntil      string `json:"freshUntil"`
	SourceRevision  string `json:"sourceRevision"`
	ContextRevision string `json:"contextRevision"`
	BindingRef      string `json:"bindingRef"`
	ProjectID       uint64 `json:"projectId"`
	Generation      uint64 `json:"generation"`
}

type flowIntentRequest struct {
	Type     string          `json:"type"`
	Identity json.RawMessage `json:"identity"`
	Detail   json.RawMessage `json:"detail"`
}

type flowIntentResponse struct {
	Executed      bool     `json:"executed"`
	Routed        string   `json:"routed,omitempty"`
	Location      string   `json:"location,omitempty"`
	Notice        string   `json:"notice,omitempty"`
	Error         string   `json:"error,omitempty"`
	Issues        []string `json:"issues,omitempty"`
	ValueReturned bool     `json:"value_returned"`
}

type flowResolvedContext struct {
	subject    string
	binding    flowBinding
	bindingRef string
}

func loadFlowHostService() (*flowHostService, error) {
	path := strings.TrimSpace(os.Getenv(flowConfigEnv))
	if path == "" {
		return nil, nil
	}
	cfg, err := loadFlowHostConfig(path)
	if err != nil {
		return nil, err
	}
	if !cfg.Enabled {
		return nil, nil
	}
	return newFlowHostService(cfg), nil
}

func newFlowHostService(cfg flowHostConfig) *flowHostService {
	return &flowHostService{
		config: cfg,
		client: &http.Client{
			Timeout: flowRequestTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("redirect refused")
			},
		},
		cache: &flowProjectionCache{entries: map[flowCacheKey]flowCachedProjection{}},
		now:   func() int64 { return time.Now().UTC().Unix() },
	}
}

func loadFlowHostConfig(path string) (flowHostConfig, error) {
	raw, err := readFlowPrivateFile(path, flowMaxConfigBytes)
	if err != nil {
		return flowHostConfig{}, errors.New("invalid flow host configuration")
	}
	var document flowConfigDocument
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&document); err != nil {
		return flowHostConfig{}, errors.New("invalid flow host configuration")
	}
	if document.Schema != flowConfigSchema || document.SchemaVersion != flowConfigSchemaVersion || !validFlowHostID(document.HostID) || len(document.Bindings) == 0 || len(document.Bindings) > 32 {
		return flowHostConfig{}, errors.New("invalid flow host configuration")
	}
	allowLoopback := envBoolTrue(flowLoopbackOriginEnv)
	origin, err := parseFlowOrigin(document.PaimosOrigin, allowLoopback)
	if err != nil {
		return flowHostConfig{}, errors.New("invalid flow host configuration")
	}
	if !filepath.IsAbs(document.APIKeyFile) {
		return flowHostConfig{}, errors.New("invalid flow host configuration")
	}
	bindings := make([]flowBinding, 0, len(document.Bindings))
	for _, item := range document.Bindings {
		binding, err := flowBindingFromDocument(item)
		if err != nil {
			return flowHostConfig{}, err
		}
		bindings = append(bindings, binding)
	}
	label := document.HostID
	if document.InstanceLabel != nil && strings.TrimSpace(*document.InstanceLabel) != "" {
		label = strings.TrimSpace(*document.InstanceLabel)
	}
	return flowHostConfig{
		Enabled:       document.Enabled,
		HostID:        document.HostID,
		PaimosOrigin:  origin,
		APIKeyFile:    document.APIKeyFile,
		InstanceLabel: label,
		Bindings:      bindings,
		ConfigDigest:  "sha256:" + hex.EncodeToString(sha256Sum(raw)),
	}, nil
}

func flowBindingFromDocument(document flowBindingDocument) (flowBinding, error) {
	if document.ProjectID == 0 || strings.TrimSpace(document.Label) == "" || len(document.PrincipalRefs) == 0 || len(document.PrincipalRefs) > 64 {
		return flowBinding{}, errors.New("invalid flow host configuration")
	}
	expected := paimosOpaqueRef("proj", strconv.FormatUint(document.ProjectID, 10))
	if document.ProjectRef != nil && strings.TrimSpace(*document.ProjectRef) != "" {
		expected = strings.TrimSpace(*document.ProjectRef)
	}
	if !strings.HasPrefix(expected, flowPaimosHostID+":proj-") {
		return flowBinding{}, errors.New("invalid flow host configuration")
	}
	refs := make(map[string]struct{}, len(document.PrincipalRefs))
	for _, raw := range document.PrincipalRefs {
		value := strings.TrimSpace(raw)
		if value == "" || strings.Contains(value, "@") || strings.ContainsAny(value, " \t\r\n") || len(value) > 128 {
			return flowBinding{}, errors.New("invalid flow host configuration")
		}
		refs[value] = struct{}{}
	}
	if len(refs) == 0 {
		return flowBinding{}, errors.New("invalid flow host configuration")
	}
	return flowBinding{
		ProjectID:          document.ProjectID,
		ExpectedProjectRef: expected,
		Label:              strings.TrimSpace(document.Label),
		PrincipalRefs:      refs,
	}, nil
}

func (app *App) handleFlowShellState(w http.ResponseWriter, r *http.Request) {
	session := currentSession(r.Context())
	if app.flow == nil {
		writeJSON(w, http.StatusOK, flowShellResponse{Enabled: false, MountShell: false})
		return
	}
	if !flowHumanSession(r, session) {
		writeJSON(w, http.StatusForbidden, flowShellResponse{
			Enabled:           true,
			MountShell:        false,
			UnavailableReason: "A verified human Janus session is required.",
		})
		return
	}
	projectID, err := parseOptionalFlowProject(r)
	if err != nil {
		writeJSON(w, http.StatusOK, flowShellResponse{
			Enabled:           true,
			MountShell:        false,
			UnavailableReason: "No configured Flow binding matches this principal.",
		})
		return
	}
	now := app.flow.clock()
	writeJSON(w, http.StatusOK, app.flow.shellState(session, projectID, now, app.envelopeReady()))
}

func (app *App) handleFlowIntent(w http.ResponseWriter, r *http.Request) {
	session := currentSession(r.Context())
	if !app.csrfAllowed(r, session) {
		app.audit(r, "flow.intent", "denied", session.Subject, "csrf failed")
		writeJSONError(w, r, http.StatusForbidden, "csrf_failed", "CSRF token required")
		return
	}
	if app.flow == nil {
		writeJSONError(w, r, http.StatusConflict, "flow_unavailable", "Flow is not configured.")
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, flowIntentMaxBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > flowIntentMaxBytes {
		writeJSONError(w, r, http.StatusBadRequest, "bad_json", "Request body must be JSON")
		return
	}
	var request flowIntentRequest
	if json.Unmarshal(raw, &request) != nil {
		writeJSONError(w, r, http.StatusBadRequest, "bad_json", "Request body must be JSON")
		return
	}
	projectID, err := parseOptionalFlowProject(r)
	if err != nil {
		writeJSON(w, http.StatusConflict, flowIntentResponse{Error: "No configured Flow binding matches this principal."})
		return
	}
	status, response := app.flow.handleIntent(r, session, projectID, request, app.flow.clock(), app.envelopeReady())
	writeJSON(w, status, response)
}

func (s *flowHostService) clock() int64 {
	if s.now != nil {
		return s.now()
	}
	return time.Now().UTC().Unix()
}

func (s *flowHostService) shellState(session Session, projectID uint64, now int64, envelopeReady bool) flowShellResponse {
	context, reason := s.resolveContext(session, projectID)
	if reason != "" {
		return flowShellResponse{Enabled: true, MountShell: false, UnavailableReason: reason}
	}
	projection, err := s.fetchProjection(context, now)
	if err != nil {
		message := "Configured Paimos projection is unavailable right now."
		var flowErr flowError
		if errors.As(err, &flowErr) && flowErr.kind == flowErrUnavailable {
			message = flowErr.message
		}
		return flowShellResponse{Enabled: true, MountShell: false, UnavailableReason: message}
	}
	contextRevision := contextRevisionFor(s.config, context, session, projection.sourceRevision)
	identity := issueFlowIdentity(s.config, context, contextRevision, now)
	shell := mergeShellState(projection.shellState, s.config, context, identity, envelopeReady, now)
	return flowShellResponse{
		Enabled:    true,
		MountShell: true,
		ShellState: shell,
		ProjectionMeta: &flowProjectionMeta{
			EvaluatedAt:     projection.paimosEvaluatedAt,
			FreshUntil:      isoTimestamp(nextTenMinuteBoundary(now)),
			SourceRevision:  projection.sourceRevision,
			ContextRevision: contextRevision,
			BindingRef:      context.bindingRef,
			ProjectID:       context.binding.ProjectID,
			Generation:      projection.generation,
		},
	}
}

func (s *flowHostService) handleIntent(r *http.Request, session Session, projectID uint64, request flowIntentRequest, now int64, envelopeReady bool) (int, flowIntentResponse) {
	_ = envelopeReady
	intentType := strings.TrimSpace(request.Type)
	if intentType == "" {
		return http.StatusBadRequest, flowIntentResponse{Error: "invalid flow intent"}
	}
	if !flowHumanSession(r, session) {
		return http.StatusForbidden, flowIntentResponse{
			Error:  "A human Janus session is required for Flow intents.",
			Issues: []string{"Machine operator credentials cannot act as a Flow human."},
		}
	}
	context, reason := s.resolveContext(session, projectID)
	if reason != "" {
		return http.StatusConflict, flowIntentResponse{Error: reason}
	}
	var projection *flowCachedProjection
	if intentType == "flow:start-intent" {
		fetched, err := s.fetchProjection(context, now)
		if err == nil {
			copy := fetched
			projection = &copy
		}
	}
	if requiresSubmittedIdentity(intentType) {
		sourceRevision := ""
		if projection != nil {
			sourceRevision = projection.sourceRevision
		}
		if issues := s.validateSubmittedIdentity(context, session, submittedIdentity(request), sourceRevision, now); len(issues) > 0 {
			status := http.StatusConflict
			for _, issue := range issues {
				if strings.Contains(issue, "human") {
					status = http.StatusForbidden
					break
				}
			}
			return status, flowIntentResponse{Error: issues[0], Issues: issues}
		}
	}
	reviewURL := s.reviewURL(context.binding.ProjectID)
	confirmed := confirmedStartAction(request)
	if confirmed == "" && projection != nil {
		confirmed = stringField(projection.shellState, "selectedAction", "selected_action")
	}
	if confirmed == "" {
		confirmed = "janus_prepare"
	}
	startAllowed := false
	if projection != nil {
		startAllowed = startPermitted(projection.shellState, confirmed, now)
	}
	switch intentType {
	case "flow:start-intent":
		if !startAllowed {
			return http.StatusOK, flowIntentResponse{
				Notice: "Start stays blocked until requirements and current context are fresh. Review remains available.",
			}
		}
		return http.StatusOK, flowIntentResponse{
			Routed:   "paimos-project-overview-baseline",
			Location: s.validNavigationLocation(reviewURL),
			Notice:   "Start stays on the configured Paimos project overview baseline controls. Janus does not start delivery.",
		}
	case "flow:review-batch", "flow:view-drafts", "flow:save-proposal":
		return http.StatusOK, flowIntentResponse{
			Routed:   "paimos-project-overview-baseline",
			Location: s.validNavigationLocation(reviewURL),
			Notice:   "Review stays on the configured Paimos project overview baseline controls.",
		}
	case "flow:header-project":
		location := s.projectOverviewURL(context.binding.ProjectID)
		return http.StatusOK, flowIntentResponse{
			Routed:   "paimos-project-overview",
			Location: s.validNavigationLocation(location),
			Notice:   "Project navigation stays in configured Paimos.",
		}
	case "flow:header-account":
		return http.StatusOK, flowIntentResponse{
			Notice: "Account controls stay in existing Janus session UI.",
		}
	default:
		return http.StatusOK, flowIntentResponse{
			Notice: "Stage navigation and header actions do not start delivery.",
		}
	}
}

func (s *flowHostService) resolveContext(session Session, projectID uint64) (flowResolvedContext, string) {
	binding, err := s.selectBinding(session.Subject, projectID)
	if err != nil {
		return flowResolvedContext{}, err.Error()
	}
	bindingRef := janusOpaqueRef(s.config.HostID, "bind", s.config.ConfigDigest, session.Subject, strconv.FormatUint(binding.ProjectID, 10))
	return flowResolvedContext{subject: session.Subject, binding: binding, bindingRef: bindingRef}, ""
}

func (s *flowHostService) selectBinding(subject string, projectID uint64) (flowBinding, error) {
	matches := make([]flowBinding, 0, 1)
	for _, binding := range s.config.Bindings {
		if _, ok := binding.PrincipalRefs[subject]; !ok {
			continue
		}
		if projectID != 0 && binding.ProjectID != projectID {
			continue
		}
		matches = append(matches, binding)
	}
	if len(matches) == 0 {
		return flowBinding{}, errors.New("no configured Flow binding matches this principal")
	}
	if len(matches) > 1 {
		return flowBinding{}, errors.New("multiple configured Flow bindings match; project scope is required")
	}
	return matches[0], nil
}

func (s *flowHostService) mountEnabledFor(session Session, r *http.Request) bool {
	if s == nil || !s.config.Enabled {
		return false
	}
	if !flowHumanSession(r, session) {
		return false
	}
	projectID, err := parseOptionalFlowProject(r)
	if err != nil {
		return false
	}
	_, reason := s.resolveContext(session, projectID)
	return reason == ""
}

func (s *flowHostService) fetchProjection(context flowResolvedContext, now int64) (flowCachedProjection, error) {
	key := flowCacheKey{projectID: context.binding.ProjectID, principalRef: context.subject}
	s.cache.mu.Lock()
	cached, ok := s.cache.entries[key]
	s.cache.mu.Unlock()
	if ok && cached.fetchedAt >= floorTenMinuteBoundary(now) {
		return cached, nil
	}
	fetched, err := s.fetchPaimosState(context)
	if err != nil {
		return flowCachedProjection{}, err
	}
	evaluatedAt := stringField(fetched, "evaluatedAt", "evaluated_at")
	if evaluatedAt == "" {
		evaluatedAt = isoTimestamp(now)
	}
	entry := flowCachedProjection{
		generation:        flowFetchGeneration.Add(1),
		fetchedAt:         now,
		sourceRevision:    janusOpaqueRef(s.config.HostID, "src", context.binding.ExpectedProjectRef, evaluatedAt),
		shellState:        fetched,
		paimosEvaluatedAt: evaluatedAt,
	}
	s.cache.mu.Lock()
	s.cache.entries[key] = entry
	s.cache.mu.Unlock()
	return entry, nil
}

func (s *flowHostService) fetchPaimosState(context flowResolvedContext) (map[string]any, error) {
	apiKey, err := readFlowAPIKey(s.config.APIKeyFile)
	if err != nil {
		return nil, flowError{kind: flowErrCredential, message: "credential"}
	}
	endpoint, err := url.JoinPath(strings.TrimRight(s.config.PaimosOrigin.String(), "/"), "api", "projects", strconv.FormatUint(context.binding.ProjectID, 10), "baseline-batches", "flow-state")
	if err != nil {
		return nil, flowError{kind: flowErrConfiguration, message: "configuration"}
	}
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, flowError{kind: flowErrTransport, message: "transport"}
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", flowUserAgent)
	req.Header.Set("Authorization", "Bearer "+apiKey)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, flowError{kind: flowErrTransport, message: "transport"}
	}
	defer resp.Body.Close()
	payload, err := boundedResponseBytes(resp.Body, resp.ContentLength)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusForbidden {
		return nil, flowError{kind: flowErrUnavailable, message: "Configured Paimos project projection is unavailable for this binding."}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, flowError{kind: flowErrUnavailable, message: "Configured Paimos projection refused the upstream request."}
	}
	var parsed any
	if json.Unmarshal(payload, &parsed) != nil {
		return nil, flowError{kind: flowErrTransport, message: "transport"}
	}
	object, ok := parsed.(map[string]any)
	if !ok {
		return nil, flowError{kind: flowErrUnavailable, message: "configured project binding mismatch"}
	}
	if err := validatePaimosProjectRef(object, context.binding.ExpectedProjectRef); err != nil {
		return nil, err
	}
	return stripPaimosIdentity(object), nil
}

func (s *flowHostService) validateSubmittedIdentity(context flowResolvedContext, session Session, submitted map[string]any, sourceRevision string, now int64) []string {
	if submitted == nil {
		return []string{"Host identity context is required before a consequential intent."}
	}
	status := stringValue(submitted, "status")
	if status == "" {
		status = "present"
	}
	if status != "present" {
		return []string{"Host identity context was rejected."}
	}
	current := issueFlowIdentity(s.config, context, contextRevisionFor(s.config, context, session, sourceRevision), now)
	var issues []string
	checks := []struct {
		label    string
		expected string
		fields   []string
	}{
		{"principal_ref", stringValue(current, "principal_ref"), []string{"principalRef", "principal_ref"}},
		{"project_ref", stringValue(current, "project_ref"), []string{"projectRef", "project_ref"}},
		{"binding_ref", stringValue(current, "binding_ref"), []string{"bindingRef", "binding_ref"}},
		{"context_revision", stringValue(current, "context_revision"), []string{"contextRevision", "context_revision"}},
		{"actor_kind", "human", []string{"actorKind", "actor_kind"}},
	}
	for _, check := range checks {
		got := firstString(submitted, check.fields...)
		if got != check.expected {
			issues = append(issues, "Host identity context mismatch for "+check.label+".")
		}
	}
	if expires := parseRFC3339(firstString(submitted, "expiresAt", "expires_at")); expires == 0 || now >= expires {
		issues = append(issues, "Host identity context has expired.")
	}
	if fresh := parseRFC3339(firstString(submitted, "freshUntil", "fresh_until")); fresh == 0 || now >= fresh {
		issues = append(issues, "Host identity context is stale.")
	}
	return issues
}

func (s *flowHostService) reviewURL(projectID uint64) string {
	return fmt.Sprintf("%s/projects/%d?tab=overview%s", strings.TrimRight(s.config.PaimosOrigin.String(), "/"), projectID, flowReviewFragment)
}

func (s *flowHostService) projectOverviewURL(projectID uint64) string {
	return fmt.Sprintf("%s/projects/%d?tab=overview", strings.TrimRight(s.config.PaimosOrigin.String(), "/"), projectID)
}

func (s *flowHostService) validNavigationLocation(location string) string {
	parsed, err := url.Parse(location)
	if err != nil {
		return ""
	}
	if parsed.Scheme != s.config.PaimosOrigin.Scheme || parsed.Host != s.config.PaimosOrigin.Host {
		return ""
	}
	tail, ok := strings.CutPrefix(parsed.Path, "/projects/")
	if !ok || tail == "" || strings.Contains(tail, "/") {
		return ""
	}
	if _, err := strconv.ParseUint(tail, 10, 64); err != nil {
		return ""
	}
	queryOK := false
	for _, part := range strings.Split(parsed.RawQuery, "&") {
		if part == "tab=overview" {
			queryOK = true
			break
		}
	}
	if !queryOK || parsed.User != nil {
		return ""
	}
	return location
}

func (app *App) injectFlowShell(r *http.Request, html string) (string, bool) {
	if app == nil || app.flow == nil {
		return html, false
	}
	session, ok := app.flowSession(r)
	if !ok || !app.flow.mountEnabledFor(session, r) {
		return html, false
	}
	if !strings.Contains(html, "<main") {
		return html, false
	}
	nonce := cspNonceFromContext(r.Context())
	if nonce == "" {
		return html, false
	}
	projectID, _ := parseOptionalFlowProject(r)
	context, reason := app.flow.resolveContext(session, projectID)
	if reason != "" {
		return html, false
	}
	origin := htmlEscapeAttr(app.flow.config.PaimosOrigin.String())
	project := htmlEscapeAttr(strconv.FormatUint(context.binding.ProjectID, 10))
	wrapped := strings.Replace(html, "<main", `<inspr-flow-shell layout-mode="bounded" content-padding="24px" data-flow-host data-flow-project="`+project+`" data-flow-paimos-origin="`+origin+`"><main`, 1)
	wrapped = strings.Replace(wrapped, "</main>", "</main></inspr-flow-shell>", 1)
	bootstrap := `<script type="module" src="/static/flow-host-bootstrap.mjs" nonce="` + nonce + `"></script>`
	if index := strings.LastIndex(wrapped, "</body>"); index >= 0 {
		return wrapped[:index] + bootstrap + wrapped[index:], true
	}
	return wrapped + bootstrap, true
}

func (app *App) allowFlowScripts(w http.ResponseWriter, r *http.Request) {
	nonce := cspNonceFromContext(r.Context())
	if nonce == "" {
		return
	}
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'nonce-"+nonce+"' 'strict-dynamic'; object-src 'none'; worker-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action "+app.formActionSources(r)+"; connect-src 'self'; font-src 'self'; img-src 'self' data:; manifest-src 'self'; style-src 'self' 'nonce-"+nonce+"'; upgrade-insecure-requests")
}

type flowCapture struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
	body        bytes.Buffer
}

func (c *flowCapture) WriteHeader(code int) {
	if !c.wroteHeader {
		c.status = code
		c.wroteHeader = true
	}
}

func (c *flowCapture) Write(p []byte) (int, error) {
	if !c.wroteHeader {
		c.WriteHeader(http.StatusOK)
	}
	return c.body.Write(p)
}

func (app *App) flowPageWrap(next http.Handler) http.Handler {
	if app == nil || app.flow == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			next.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/static/") || strings.HasPrefix(r.URL.Path, "/flow/") {
			next.ServeHTTP(w, r)
			return
		}
		capture := &flowCapture{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(capture, r)
		html := capture.body.String()
		if capture.status == http.StatusOK && strings.Contains(w.Header().Get("Content-Type"), "text/html") {
			if wrapped, mounted := app.injectFlowShell(r, html); mounted {
				app.allowFlowScripts(w, r)
				html = wrapped
			}
		}
		if !capture.wroteHeader {
			capture.status = http.StatusOK
		}
		w.WriteHeader(capture.status)
		_, _ = w.Write([]byte(html))
	})
}

func (app *App) flowSession(r *http.Request) (Session, bool) {
	if !app.cfg.RequireAuth {
		return Session{Subject: "dev-local", Name: "Local Dev", Roles: AllRoles(), Expiry: time.Now().UTC().Add(time.Hour)}, true
	}
	return app.readSession(r)
}

func (app *App) envelopeReady() bool {
	_, ready := app.readinessBody()
	return ready
}

func flowStaticAsset(name string) ([]byte, string, bool) {
	if strings.Contains(name, "..") || strings.Contains(name, "\\") {
		return nil, "", false
	}
	embedPath := ""
	contentType := ""
	switch name {
	case "flow-host-bootstrap.mjs":
		embedPath = "ui/flow-host-bootstrap.mjs"
		contentType = "text/javascript; charset=utf-8"
	case "vendor/flow-shell/src/inspr-flow-shell.js":
		embedPath = "ui/vendor/flow-shell/src/inspr-flow-shell.js"
		contentType = "text/javascript; charset=utf-8"
	case "vendor/flow-shell/src/flow-shell.css":
		embedPath = "ui/vendor/flow-shell/src/flow-shell.css"
		contentType = "text/css; charset=utf-8"
	case "vendor/flow-shell/src/adapter.js":
		embedPath = "ui/vendor/flow-shell/src/adapter.js"
		contentType = "text/javascript; charset=utf-8"
	case "vendor/flow-shell/src/forecast.js":
		embedPath = "ui/vendor/flow-shell/src/forecast.js"
		contentType = "text/javascript; charset=utf-8"
	case "vendor/flow-shell/src/gates.js":
		embedPath = "ui/vendor/flow-shell/src/gates.js"
		contentType = "text/javascript; charset=utf-8"
	case "vendor/flow-shell/src/host-layout.js":
		embedPath = "ui/vendor/flow-shell/src/host-layout.js"
		contentType = "text/javascript; charset=utf-8"
	case "vendor/flow-shell/src/identity.js":
		embedPath = "ui/vendor/flow-shell/src/identity.js"
		contentType = "text/javascript; charset=utf-8"
	case "vendor/flow-shell/src/intents.js":
		embedPath = "ui/vendor/flow-shell/src/intents.js"
		contentType = "text/javascript; charset=utf-8"
	case "vendor/flow-shell/src/sanitize.js":
		embedPath = "ui/vendor/flow-shell/src/sanitize.js"
		contentType = "text/javascript; charset=utf-8"
	case "vendor/flow-shell/src/stages.js":
		embedPath = "ui/vendor/flow-shell/src/stages.js"
		contentType = "text/javascript; charset=utf-8"
	case "vendor/flow-shell/src/state.js":
		embedPath = "ui/vendor/flow-shell/src/state.js"
		contentType = "text/javascript; charset=utf-8"
	case "vendor/flow-shell/src/assets/inspr-logo.svg":
		embedPath = "ui/vendor/flow-shell/src/assets/inspr-logo.svg"
		contentType = "image/svg+xml"
	default:
		return nil, "", false
	}
	data, err := flowAssetFS.ReadFile(embedPath)
	if err != nil {
		return nil, "", false
	}
	return data, contentType, true
}

func mergeShellState(upstream map[string]any, config flowHostConfig, context flowResolvedContext, identity map[string]any, envelopeReady bool, now int64) map[string]any {
	shell := cloneObject(upstream)
	delete(shell, "identityContext")
	header, _ := shell["header"].(map[string]any)
	if header == nil {
		header = map[string]any{}
	} else {
		header = cloneObject(header)
	}
	header["appName"] = "Janus"
	header["instanceLabel"] = config.InstanceLabel
	header["version"] = shortCommit(buildCommit)
	header["projectName"] = context.binding.Label
	header["projectSubtitle"] = "Janus host projection · upstream observations"
	header["userLabel"] = flowHostVerifiedHumanLabel
	if display, ok := identity["display"].(map[string]any); ok {
		if initials, ok := display["user_initials"].(string); ok && initials != "" {
			header["userInitials"] = initials
		}
	}
	shell["header"] = header
	health, _ := shell["health"].(map[string]any)
	if health == nil {
		health = map[string]any{}
	} else {
		health = cloneObject(health)
	}
	if envelopeReady {
		health["status"] = "available"
		health["label"] = "Janus envelope available"
	} else {
		health["status"] = "degraded"
		health["label"] = "Janus envelope degraded"
	}
	health["checkedLabel"] = "Local Janus envelope observation"
	delete(health, "url")
	shell["health"] = health
	delivery, _ := shell["delivery"].(map[string]any)
	if delivery == nil {
		delivery = map[string]any{}
	} else {
		delivery = cloneObject(delivery)
	}
	delivery["viewedStage"] = 3
	if !janusGatePassed(shell, now) {
		if evidence, ok := delivery["stageEvidence"].([]any); ok && len(evidence) > 3 {
			evidence[3] = "unknown"
			delivery["stageEvidence"] = evidence
		}
	}
	shell["delivery"] = delivery
	if stringField(shell, "selectedAction", "selected_action") == "" {
		shell["selectedAction"] = defaultJanusAction(shell)
	}
	shell["identityContext"] = identity
	return shell
}

func issueFlowIdentity(config flowHostConfig, context flowResolvedContext, contextRevision string, now int64) map[string]any {
	issued := isoTimestamp(now)
	principalRef := janusOpaqueRef(config.HostID, "prin", context.subject)
	projectRef := janusOpaqueRef(config.HostID, "proj", strconv.FormatUint(context.binding.ProjectID, 10))
	return map[string]any{
		"contract_version":     flowIdentityContract,
		"evaluated_at":         issued,
		"host_id":              config.HostID,
		"principal_kind":       "local_host",
		"principal_ref":        principalRef,
		"binding_ref":          context.bindingRef,
		"organization_ref":     nil,
		"project_ref":          projectRef,
		"actor_kind":           "human",
		"issued_at":            issued,
		"expires_at":           isoTimestamp(now + int64(flowContextTTL.Seconds())),
		"fresh_until":          isoTimestamp(nextTenMinuteBoundary(now)),
		"context_revision":     contextRevision,
		"authority_disclaimer": flowAuthorityDisclaimer,
		"display": map[string]any{
			"user_label":    flowHostVerifiedHumanLabel,
			"user_initials": initialsFromRef(principalRef),
			"project_label": context.binding.Label,
			"fixture_label": "Host-verified Janus human context. Not live Paimos identity.",
		},
	}
}

func stripPaimosIdentity(payload map[string]any) map[string]any {
	copy := cloneObject(payload)
	delete(copy, "identityContext")
	stripForbiddenKeys(copy)
	return copy
}

func stripForbiddenKeys(value any) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			lower := strings.ToLower(key)
			switch lower {
			case "email", "emails", "token", "access_token", "id_token", "refresh_token", "password", "secret", "client_secret", "subject", "sub", "api_key", "cookie", "authorization", "credential", "raw_subject", "catalog":
				delete(typed, key)
				continue
			}
			stripForbiddenKeys(child)
		}
	case []any:
		for _, child := range typed {
			stripForbiddenKeys(child)
		}
	}
}

func validatePaimosProjectRef(payload map[string]any, expected string) error {
	identity, _ := payload["identityContext"].(map[string]any)
	actual := firstString(identity, "project_ref", "projectRef")
	if actual != expected {
		return flowError{kind: flowErrUnavailable, message: "configured project binding mismatch"}
	}
	return nil
}

func flowHumanSession(r *http.Request, session Session) bool {
	if session.Subject == "" || len(session.Roles) == 0 {
		return false
	}
	if strings.TrimSpace(r.Header.Get("Authorization")) != "" {
		return false
	}
	return true
}

func requiresSubmittedIdentity(intentType string) bool {
	return intentType == "flow:start-intent"
}

func submittedIdentity(request flowIntentRequest) map[string]any {
	if object := jsonObject(request.Identity); object != nil {
		return object
	}
	detail := jsonObject(request.Detail)
	if detail == nil {
		return nil
	}
	if nested, ok := detail["identity"].(map[string]any); ok {
		return nested
	}
	if inner, ok := detail["detail"].(map[string]any); ok {
		if nested, ok := inner["identity"].(map[string]any); ok {
			return nested
		}
	}
	return nil
}

func confirmedStartAction(request flowIntentRequest) string {
	detail := jsonObject(request.Detail)
	if detail == nil {
		return ""
	}
	if inner, ok := detail["detail"].(map[string]any); ok {
		if action, _ := inner["action"].(string); action != "" {
			return action
		}
	}
	action, _ := detail["action"].(string)
	return action
}

func contextRevisionFor(config flowHostConfig, context flowResolvedContext, session Session, sourceRevision string) string {
	return janusOpaqueRef(config.HostID, "ctxrev",
		config.ConfigDigest,
		context.subject,
		session.Expiry.UTC().Format(time.RFC3339Nano),
		strconv.FormatUint(context.binding.ProjectID, 10),
		context.binding.ExpectedProjectRef,
		sourceRevision,
	)
}

func paimosOpaqueRef(kind string, parts ...string) string {
	return opaqueRef(flowPaimosHostID, kind, parts...)
}

func janusOpaqueRef(hostID, kind string, parts ...string) string {
	return opaqueRef(hostID, kind, parts...)
}

func opaqueRef(hostID, kind string, parts ...string) string {
	sum := sha256.New()
	sum.Write([]byte(hostID + ":" + kind + ":"))
	for _, part := range parts {
		sum.Write([]byte(part))
		sum.Write([]byte{0})
	}
	return hostID + ":" + kind + "-" + hex.EncodeToString(sum.Sum(nil)[:16])
}

func startPermitted(shellState map[string]any, action string, now int64) bool {
	delivery, _ := shellState["delivery"].(map[string]any)
	status := stringField(delivery, "status")
	if status == "" {
		status = "draft"
	}
	if status != "draft" && status != "authorized" {
		return false
	}
	if firstValue(delivery, "batchRef", "batch_ref") == nil {
		return false
	}
	if firstValue(delivery, "baselineRef", "baseline_ref") == nil {
		return false
	}
	if firstValue(delivery, "baselineDigest", "baseline_digest") == nil {
		return false
	}
	switch action {
	case "build", "deploy", "verify", "janus_prepare", "janus_apply":
	default:
		return false
	}
	if !evaluationUsable(stringField(shellState, "evaluatedAt", "evaluated_at"), now) {
		return false
	}
	prerequisites, _ := shellState["prerequisites"].(map[string]any)
	if !requiredGatePass(firstValue(prerequisites, "requirementsBaseline", "requirements_baseline"), now) {
		return false
	}
	pharos := firstValue(prerequisites, "pharosTarget", "pharos_target")
	switch action {
	case "deploy", "verify":
		if !requiredGatePass(firstValue(prerequisites, "deployArtifact", "deploy_artifact"), now) {
			return false
		}
		if !requiredTargetPass(pharos, []string{"ready", "live"}, now) {
			return false
		}
	case "janus_prepare":
		if !requiredTargetPass(pharos, []string{"preliminary", "ready", "live"}, now) {
			return false
		}
	case "janus_apply":
		if !requiredTargetPass(pharos, []string{"ready", "live"}, now) {
			return false
		}
		if !requiredGatePass(firstValue(prerequisites, "janusGate", "janus_gate"), now) {
			return false
		}
	}
	return true
}

func janusGatePassed(shell map[string]any, now int64) bool {
	prerequisites, _ := shell["prerequisites"].(map[string]any)
	return requiredGatePass(firstValue(prerequisites, "janusGate", "janus_gate"), now)
}

func defaultJanusAction(shell map[string]any) string {
	prerequisites, _ := shell["prerequisites"].(map[string]any)
	pharos, _ := firstValue(prerequisites, "pharosTarget", "pharos_target").(map[string]any)
	if stringField(pharos, "readiness") == "preliminary" {
		return "janus_prepare"
	}
	return "janus_apply"
}

func evaluationUsable(evaluatedAt string, now int64) bool {
	if evaluatedAt == "" {
		return false
	}
	evaluated := parseRFC3339(evaluatedAt)
	if evaluated == 0 || evaluated > now+5 {
		return false
	}
	return now-evaluated <= flowEvaluationMaxAgeSecs
}

func requiredGatePass(entry any, now int64) bool {
	object, ok := entry.(map[string]any)
	if !ok {
		return false
	}
	if stringField(object, "status") != "pass" {
		return false
	}
	if firstValue(object, "evidenceRef", "evidence_ref") == nil {
		return false
	}
	if firstValue(object, "observedAt", "observed_at") == nil {
		return false
	}
	return !gateStale(object, now)
}

func requiredTargetPass(entry any, allowed []string, now int64) bool {
	if !requiredGatePass(entry, now) {
		return false
	}
	object, _ := entry.(map[string]any)
	readiness := stringField(object, "readiness")
	for _, item := range allowed {
		if readiness == item {
			return true
		}
	}
	return false
}

func gateStale(entry map[string]any, now int64) bool {
	freshUntil := stringField(entry, "freshUntil", "fresh_until")
	if freshUntil == "" {
		return false
	}
	fresh := parseRFC3339(freshUntil)
	return fresh == 0 || now > fresh
}

func parseOptionalFlowProject(r *http.Request) (uint64, error) {
	raw := strings.TrimSpace(r.URL.Query().Get("flow_project"))
	if raw == "" {
		return 0, nil
	}
	id, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || id == 0 {
		return 0, errors.New("invalid project")
	}
	return id, nil
}

func htmlEscapeAttr(value string) string {
	replacer := strings.NewReplacer(`&`, "&amp;", `"`, "&quot;", `<`, "&lt;", `>`, "&gt;")
	return replacer.Replace(value)
}

func boundedResponseBytes(body io.Reader, contentLength int64) ([]byte, error) {
	if contentLength > flowMaxResponseBytes {
		return nil, flowError{kind: flowErrUnavailable, message: "projection response too large"}
	}
	data, err := io.ReadAll(io.LimitReader(body, flowMaxResponseBytes+1))
	if err != nil {
		return nil, flowError{kind: flowErrTransport, message: "transport"}
	}
	if len(data) > flowMaxResponseBytes {
		return nil, flowError{kind: flowErrUnavailable, message: "projection response too large"}
	}
	return data, nil
}

func initialsFromRef(reference string) string {
	digest := hex.EncodeToString(sha256Sum([]byte(reference)))
	var letters strings.Builder
	for _, ch := range digest {
		if ch >= 'a' && ch <= 'f' {
			letters.WriteRune(ch)
			if letters.Len() == 2 {
				return strings.ToUpper(letters.String())
			}
		}
	}
	if len(digest) >= 2 {
		return strings.ToUpper(digest[:2])
	}
	return "JH"
}

func nextTenMinuteBoundary(now int64) int64 {
	remainder := now % 600
	if remainder == 0 {
		return now + 600
	}
	return now + (600 - remainder)
}

func floorTenMinuteBoundary(now int64) int64 {
	return now - (now % 600)
}

func isoTimestamp(unix int64) string {
	return time.Unix(unix, 0).UTC().Format(time.RFC3339)
}

func parseRFC3339(value string) int64 {
	if value == "" {
		return 0
	}
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return parsed.UTC().Unix()
	}
	if parsed, err := time.Parse(time.RFC3339, value); err == nil {
		return parsed.UTC().Unix()
	}
	return 0
}

func validFlowHostID(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for i, ch := range value {
		if i == 0 && (ch < 'a' || ch > 'z') && (ch < 'A' || ch > 'Z') {
			return false
		}
		if (ch < 'a' || ch > 'z') && (ch < 'A' || ch > 'Z') && (ch < '0' || ch > '9') && ch != '.' && ch != '_' && ch != '-' {
			return false
		}
	}
	return true
}

func parseFlowOrigin(value string, allowLoopback bool) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil {
		return nil, err
	}
	if parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return nil, errors.New("invalid origin")
	}
	switch parsed.Scheme {
	case "https":
		return parsed, nil
	case "http":
		if allowLoopback && isLoopbackURL(parsed) {
			return parsed, nil
		}
		return nil, errors.New("invalid origin")
	default:
		return nil, errors.New("invalid origin")
	}
}

func isLoopbackURL(parsed *url.URL) bool {
	host := parsed.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func envBoolTrue(name string) bool {
	value := strings.TrimSpace(os.Getenv(name))
	return value == "1" || strings.EqualFold(value, "true")
}

func readFlowAPIKey(path string) (string, error) {
	key, err := readFlowPrivateFile(path, flowMaxAPIKeyBytes)
	if err != nil {
		return "", err
	}
	if len(key) < 32 || len(key) > flowMaxAPIKeyBytes {
		return "", errors.New("credential")
	}
	for _, b := range key {
		if b < 0x21 || b > 0x7e {
			return "", errors.New("credential")
		}
	}
	return string(key), nil
}

func readFlowPrivateFile(path string, maxBytes int64) ([]byte, error) {
	parent := filepath.Dir(path)
	if err := validatePrivateParent(parent); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("credential")
	}
	if err := validatePrivateFileInfo(info, maxBytes); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("credential")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, errors.New("credential")
	}
	if err := validatePrivateFileInfo(opened, maxBytes); err != nil {
		return nil, err
	}
	if sysA, ok := info.Sys().(*syscall.Stat_t); ok {
		if sysB, ok := opened.Sys().(*syscall.Stat_t); ok {
			if sysA.Dev != sysB.Dev || sysA.Ino != sysB.Ino {
				return nil, errors.New("credential")
			}
		}
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil || int64(len(data)) > maxBytes {
		return nil, errors.New("credential")
	}
	return data, nil
}

func validatePrivateParent(parent string) error {
	info, err := os.Stat(parent)
	if err != nil || !info.IsDir() {
		return errors.New("credential")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("credential")
	}
	if sys, ok := info.Sys().(*syscall.Stat_t); ok && int(sys.Uid) != os.Getuid() {
		return errors.New("credential")
	}
	return nil
}

func validatePrivateFileInfo(info os.FileInfo, maxBytes int64) error {
	if !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > maxBytes {
		return errors.New("credential")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("credential")
	}
	sys, ok := info.Sys().(*syscall.Stat_t)
	if ok {
		if int(sys.Uid) != os.Getuid() {
			return errors.New("credential")
		}
		if sys.Nlink != 1 {
			return errors.New("credential")
		}
	}
	return nil
}

func sha256Sum(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func cloneObject(input map[string]any) map[string]any {
	if input == nil {
		return map[string]any{}
	}
	raw, err := json.Marshal(input)
	if err != nil {
		out := make(map[string]any, len(input))
		for key, value := range input {
			out[key] = value
		}
		return out
	}
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return out
}

func jsonObject(raw json.RawMessage) map[string]any {
	if len(bytes.TrimSpace(raw)) == 0 || string(raw) == "null" {
		return nil
	}
	var object map[string]any
	if json.Unmarshal(raw, &object) != nil {
		return nil
	}
	return object
}

func stringField(object map[string]any, keys ...string) string {
	return firstString(object, keys...)
}

func stringValue(object map[string]any, key string) string {
	if object == nil {
		return ""
	}
	value, _ := object[key].(string)
	return value
}

func firstString(object map[string]any, keys ...string) string {
	if object == nil {
		return ""
	}
	for _, key := range keys {
		if value, ok := object[key].(string); ok {
			return value
		}
	}
	return ""
}

func firstValue(object map[string]any, keys ...string) any {
	if object == nil {
		return nil
	}
	for _, key := range keys {
		if value, ok := object[key]; ok && value != nil {
			return value
		}
	}
	return nil
}
