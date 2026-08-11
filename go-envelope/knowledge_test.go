package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func TestKnowledgeInventoryCoversCodeVocabularies(t *testing.T) {
	terms := knowledgeTerms()
	byID := make(map[string]KnowledgeTerm, len(terms))
	for _, term := range terms {
		if term.ID == "" || term.Name == "" || term.Plain == "" || term.Detail == "" || len(term.FlowSlugs) == 0 {
			t.Fatalf("knowledge term is incomplete: %#v", term)
		}
		if byID[term.ID].ID != "" {
			t.Fatalf("duplicate knowledge term %q", term.ID)
		}
		byID[term.ID] = term
	}

	expectedTerms := []string{"secret", "ref", "permit", "approval", "delegation", "role", "permission", "binding", "binding-source", "scope", "class", "egress-mode", "lifecycle", "plane", "runtime-action", "product-mode", "break-glass", "forge", "warden", "envelope", "engine"}
	for _, id := range expectedTerms {
		if byID[id].ID == "" {
			t.Fatalf("code-inventoried term %q is missing", id)
		}
	}

	assertKnowledgeValues(t, byID["class"].Values, []string{"low", "normal", "high_value", "break_glass"})
	assertKnowledgeValues(t, byID["egress-mode"].Values, []string{"connector", "sandboxed", "proxy_enforced", "hook_guarded", "declared_only"})
	assertKnowledgeValues(t, byID["lifecycle"].Values, []string{"draft", "active", "rotating", "deprecated", "disabled", "pending_delete", "destroyed"})
	assertKnowledgeValues(t, byID["plane"].Values, []string{"use", "admin"})
	assertKnowledgeValues(t, byID["binding-source"].Values, []string{"local_reviewed", "oidc_subject", "oidc_group", "unsafe_bootstrap"})
	assertKnowledgeValues(t, byID["product-mode"].Values, []string{"dev", "self_hosted", "production", "enterprise"})
	assertKnowledgeValues(t, byID["role"].Values, AllRoles())
	if len(byID["runtime-action"].Values) != 47 {
		t.Fatalf("runtime action glossary has %d values, want 47", len(byID["runtime-action"].Values))
	}
}

func TestKnowledgeRolesMatchSharedRoleMatrix(t *testing.T) {
	raw, err := os.ReadFile("../config/authorization/role-matrix-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var matrix struct {
		Roles []struct {
			Role        string   `json:"role"`
			Permissions []string `json:"permissions"`
		} `json:"roles"`
	}
	if err := json.Unmarshal(raw, &matrix); err != nil {
		t.Fatal(err)
	}
	roles := make([]string, 0, len(matrix.Roles))
	permissionSet := make(map[string]bool)
	for _, row := range matrix.Roles {
		roles = append(roles, row.Role)
		for _, permission := range row.Permissions {
			permissionSet[permission] = true
		}
	}
	permissions := make([]string, 0, len(permissionSet))
	for permission := range permissionSet {
		permissions = append(permissions, permission)
	}
	var roleTerm, permissionTerm KnowledgeTerm
	for _, term := range knowledgeTerms() {
		if term.ID == "role" {
			roleTerm = term
		}
		if term.ID == "permission" {
			permissionTerm = term
		}
	}
	assertKnowledgeValues(t, roleTerm.Values, roles)
	assertKnowledgeValues(t, permissionTerm.Values, permissions)
}

func TestKnowledgeClosedValuesMatchRustSources(t *testing.T) {
	terms := make(map[string]KnowledgeTerm)
	for _, term := range knowledgeTerms() {
		terms[term.ID] = term
	}
	tests := []struct {
		term       string
		path       string
		start, end string
	}{
		{term: "class", path: "../crates/janus-core/src/store.rs", start: "impl SecretClass {", end: "/// Safe model-facing risk hint"},
		{term: "lifecycle", path: "../crates/janus-core/src/store.rs", start: "impl SecretLifecycle {", end: "/// Value-free record"},
		{term: "egress-mode", path: "../crates/janus-core/src/policy.rs", start: "impl EgressMode {", end: "/// Stable profile identifier"},
		{term: "plane", path: "../crates/janus-core/src/plane.rs", start: "impl RuntimePlane {", end: "/// Closed catalog"},
		{term: "product-mode", path: "../crates/janus-core/src/release.rs", start: "impl ProductMode {", end: "/// Reviewable release-channel"},
		{term: "role", path: "../crates/janus-core/src/roles.rs", start: "Role {", end: "/// Closed permission vocabulary"},
		{term: "permission", path: "../crates/janus-core/src/roles.rs", start: "Permission {", end: "impl Permission"},
		{term: "binding-source", path: "../crates/janus-core/src/roles.rs", start: "RoleBindingSourceKind {", end: "/// Opaque integrity-bound source"},
	}
	for _, tc := range tests {
		t.Run(tc.term, func(t *testing.T) {
			assertKnowledgeValues(t, terms[tc.term].Values, rustWireValues(t, tc.path, tc.start, tc.end))
		})
	}
}

func TestKnowledgeRuntimeActionsMatchRustCatalog(t *testing.T) {
	raw, err := os.ReadFile("../crates/janus-core/src/plane.rs")
	if err != nil {
		t.Fatal(err)
	}
	block := string(raw)
	start := strings.Index(block, "pub const fn as_str(self) -> &'static str")
	if start < 0 {
		t.Fatal("could not locate RuntimeAction::as_str catalog")
	}
	end := strings.Index(block[start:], "/// Parse one exact catalog action")
	if end < 0 {
		t.Fatal("could not locate RuntimeAction::as_str catalog end")
	}
	re := regexp.MustCompile(`=> "((?:warden|use|admin)\.[a-z0-9_]+)"`)
	matches := re.FindAllStringSubmatch(block[start:start+end], -1)
	want := make([]string, 0, len(matches))
	for _, match := range matches {
		want = append(want, match[1])
	}
	var got []string
	for _, term := range knowledgeTerms() {
		if term.ID == "runtime-action" {
			for _, value := range term.Values {
				got = append(got, value.Code)
			}
		}
	}
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("knowledge runtime actions drifted from Rust catalog\ngot=%v\nwant=%v", got, want)
	}
}

func TestKnowledgePagesAreIllustratedTruthfulAndSelfContained(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false

	index := httptest.NewRecorder()
	app.routes().ServeHTTP(index, httptest.NewRequest(http.MethodGet, "/knowledge", nil))
	if index.Code != http.StatusOK {
		t.Fatalf("knowledge index got %d: %s", index.Code, index.Body.String())
	}
	body := index.Body.String()
	for _, want := range []string{"Knowledge", "CODE-INVENTORIED FIELD GUIDE", "Runtime action", "admin.dynamic_transport", `class="knowledge-illustration"`, `href="/knowledge/flows/break-glass"`, `aria-current="page"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("knowledge index should render %q", want)
		}
	}
	if count := strings.Count(body, `class="knowledge-illustration"`); count != len(knowledgeTerms()) {
		t.Fatalf("knowledge index has %d term illustrations, want %d", count, len(knowledgeTerms()))
	}

	for _, flow := range knowledgeFlows() {
		if len(flow.Steps) != 4 || flow.Enforced == "" || flow.Intended == "" || flow.Evidence == "" {
			t.Fatalf("knowledge flow is incomplete: %#v", flow)
		}
		if knowledgeFlowTitle(flow.Slug) != flow.Title {
			t.Fatalf("knowledge flow link title drifted for %q", flow.Slug)
		}
		out := httptest.NewRecorder()
		app.routes().ServeHTTP(out, httptest.NewRequest(http.MethodGet, "/knowledge/flows/"+flow.Slug, nil))
		if out.Code != http.StatusOK {
			t.Fatalf("flow %q got %d: %s", flow.Slug, out.Code, out.Body.String())
		}
		flowBody := out.Body.String()
		for _, want := range []string{flow.Title, "Enforced today", "Boundary and next layer", "EVIDENCE TO KEEP", `class="flow-illustration"`, "value-free guide"} {
			if !strings.Contains(flowBody, want) {
				t.Fatalf("flow %q should render %q", flow.Slug, want)
			}
		}
	}
}

func TestKnowledgeRejectsUnknownFlowWithoutEcho(t *testing.T) {
	app := newTestApp(t)
	app.cfg.RequireAuth = false
	const canary = "environment-specific-host-canary"
	out := httptest.NewRecorder()
	app.routes().ServeHTTP(out, httptest.NewRequest(http.MethodGet, "/knowledge/flows/"+canary, nil))
	if out.Code != http.StatusNotFound {
		t.Fatalf("unknown flow got %d", out.Code)
	}
	if strings.Contains(out.Body.String(), canary) {
		t.Fatal("unknown flow response echoed untrusted path")
	}
	assertRouteResponseValueFree(t, "unknown knowledge flow", out)
}

func TestKnowledgeContainsNoEnvironmentSpecificExamples(t *testing.T) {
	content := strings.ToLower(strings.Join(knowledgeTextFragments(), "\n"))
	for _, forbidden := range []string{"vault.barta.cm", "auth.inspr.at", "csb1", "hsb1", "agm1"} {
		if strings.Contains(content, forbidden) {
			t.Fatalf("knowledge content contains environment-specific example %q", forbidden)
		}
	}
}

func TestKnowledgeIllustrationsAreInlineAndAirGapSafe(t *testing.T) {
	raw, err := vaultTemplateFS.ReadFile("ui/knowledge.html")
	if err != nil {
		t.Fatal(err)
	}
	templateBody := strings.ToLower(string(raw))
	for _, forbidden := range []string{"<img", "http://", "https://", "<script", "<iframe"} {
		if strings.Contains(templateBody, forbidden) {
			t.Fatalf("knowledge template contains external or executable asset marker %q", forbidden)
		}
	}
	for _, required := range []string{"<svg", "<title", "<desc", "role=\"img\""} {
		if !strings.Contains(templateBody, required) {
			t.Fatalf("knowledge template is missing inline SVG accessibility marker %q", required)
		}
	}
}

func knowledgeTextFragments() []string {
	var out []string
	for _, term := range knowledgeTerms() {
		out = append(out, term.Name, term.Plain, term.Detail)
		for _, value := range term.Values {
			out = append(out, value.Code, value.Detail)
		}
	}
	for _, flow := range knowledgeFlows() {
		out = append(out, flow.Title, flow.Summary, flow.Enforced, flow.Intended, flow.Evidence)
		for _, step := range flow.Steps {
			out = append(out, step.Actor, step.Action, step.Checks, step.Evidence)
		}
	}
	return out
}

func assertKnowledgeValues(t *testing.T, values []KnowledgeValue, want []string) {
	t.Helper()
	got := make([]string, 0, len(values))
	for _, value := range values {
		if value.Code == "" || value.Detail == "" {
			t.Fatalf("knowledge value is incomplete: %#v", value)
		}
		got = append(got, value.Code)
	}
	gotSorted := append([]string(nil), got...)
	wantSorted := append([]string(nil), want...)
	sort.Strings(gotSorted)
	sort.Strings(wantSorted)
	if strings.Join(gotSorted, "\n") != strings.Join(wantSorted, "\n") {
		t.Fatalf("knowledge values differ\ngot=%v\nwant=%v", got, want)
	}
}

func rustWireValues(t *testing.T, path, startMarker, endMarker string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(raw)
	start := strings.Index(content, startMarker)
	if start < 0 {
		t.Fatalf("could not locate %q in %s", startMarker, path)
	}
	end := strings.Index(content[start:], endMarker)
	if end < 0 {
		t.Fatalf("could not locate %q after %q in %s", endMarker, startMarker, path)
	}
	re := regexp.MustCompile(`=> "([a-z0-9_.]+)"`)
	unique := make(map[string]bool)
	var values []string
	for _, match := range re.FindAllStringSubmatch(content[start:start+end], -1) {
		if !unique[match[1]] {
			unique[match[1]] = true
			values = append(values, match[1])
		}
	}
	if len(values) == 0 {
		t.Fatalf("no wire values found between %q and %q in %s", startMarker, endMarker, path)
	}
	return values
}
