package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestBootstrapZitadelEnvEnablesRoleAssertions(t *testing.T) {
	for _, existingApp := range []bool{false, true} {
		t.Run(map[bool]string{false: "create", true: "update"}[existingApp], func(t *testing.T) {
			var projectPayload map[string]any
			var appPayload map[string]any

			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				response.Header().Set("Content-Type", "application/json")
				if request.URL.Path != "/.well-known/openid-configuration" && request.Header.Get("Authorization") != "Bearer fixture-pat" {
					http.Error(response, `{"message":"missing fixture authorization"}`, http.StatusUnauthorized)
					return
				}

				switch request.Method + " " + request.URL.Path {
				case "GET /.well-known/openid-configuration":
					fmt.Fprint(response, `{}`)
				case "GET /management/v1/orgs/me":
					fmt.Fprint(response, `{"org":{"id":"org-fixture"}}`)
				case "POST /management/v1/projects/_search":
					if existingApp {
						fmt.Fprint(response, `{"result":[{"id":"project-fixture","name":"Janus Test"}]}`)
					} else {
						fmt.Fprint(response, `{"result":[]}`)
					}
				case "POST /management/v1/projects":
					decodeBootstrapPayload(t, request, &projectPayload)
					fmt.Fprint(response, `{"id":"project-fixture"}`)
				case "POST /management/v1/projects/project-fixture/apps/_search":
					if existingApp {
						fmt.Fprint(response, `{"result":[{"id":"app-fixture","name":"Janus Test App"}]}`)
					} else {
						fmt.Fprint(response, `{"result":[]}`)
					}
				case "POST /management/v1/projects/project-fixture/apps/oidc":
					decodeBootstrapPayload(t, request, &appPayload)
					fmt.Fprint(response, `{"appId":"app-fixture","clientId":"client-fixture","clientSecret":"secret-fixture"}`)
				case "PUT /management/v1/projects/project-fixture/apps/app-fixture/oidc_config":
					decodeBootstrapPayload(t, request, &appPayload)
					fmt.Fprint(response, `{}`)
				case "GET /management/v1/projects/project-fixture/apps/app-fixture":
					fmt.Fprint(response, `{"app":{"oidcConfig":{"clientId":"client-fixture"}}}`)
				case "POST /management/v1/projects/project-fixture/apps/app-fixture/oidc_config/_generate_client_secret":
					fmt.Fprint(response, `{"clientSecret":"secret-fixture"}`)
				default:
					http.Error(response, `{"message":"unexpected fixture request"}`, http.StatusNotFound)
				}
			}))
			defer server.Close()

			composeDir := t.TempDir()
			machineKeyDir := filepath.Join(composeDir, ".machinekey")
			if err := os.MkdirAll(machineKeyDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(machineKeyDir, "pat.txt"), []byte("fixture-pat\n"), 0o600); err != nil {
				t.Fatal(err)
			}

			command := exec.Command("bash", "bootstrap-zitadel-env.sh")
			command.Env = append(os.Environ(),
				"ZITADEL_BASE="+server.URL,
				"COMPOSE_DIR="+composeDir,
				"PROJECT_NAME=Janus Test",
				"APP_NAME=Janus Test App",
				"REDIRECT_URI=https://janus.test/oidc/callback",
				"POST_LOGOUT_URI=https://janus.test/",
			)
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			command.Stdout = &stdout
			command.Stderr = &stderr
			if err := command.Run(); err != nil {
				t.Fatalf("bootstrap failed: %v\nstderr:\n%s", err, stderr.String())
			}
			if !bytes.Contains(stdout.Bytes(), []byte("OIDC_CLIENT_ID=client-fixture\n")) ||
				!bytes.Contains(stdout.Bytes(), []byte("OIDC_CLIENT_SECRET=secret-fixture\n")) {
				t.Fatalf("bootstrap did not emit fixture credentials")
			}

			if !existingApp {
				assertBootstrapBool(t, projectPayload, "projectRoleAssertion", true)
				assertBootstrapBool(t, projectPayload, "projectRoleCheck", false)
				assertBootstrapBool(t, projectPayload, "hasProjectCheck", false)
			}
			assertBootstrapBool(t, appPayload, "idTokenRoleAssertion", true)
			assertBootstrapBool(t, appPayload, "idTokenUserinfoAssertion", true)
			assertBootstrapBool(t, appPayload, "accessTokenRoleAssertion", false)
		})
	}
}

func decodeBootstrapPayload(t *testing.T, request *http.Request, destination *map[string]any) {
	t.Helper()
	if err := json.NewDecoder(request.Body).Decode(destination); err != nil {
		t.Errorf("decode bootstrap payload: %v", err)
	}
}

func assertBootstrapBool(t *testing.T, payload map[string]any, key string, expected bool) {
	t.Helper()
	if actual, ok := payload[key].(bool); !ok || actual != expected {
		t.Errorf("bootstrap payload %s = %#v, want %t", key, payload[key], expected)
	}
}
