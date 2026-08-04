package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type managedDynamicTrackingReader struct {
	value   []byte
	offset  int
	exposed [][]byte
}

func (reader *managedDynamicTrackingReader) Read(target []byte) (int, error) {
	reader.exposed = append(reader.exposed, target)
	if reader.offset >= len(reader.value) {
		return 0, io.EOF
	}
	count := copy(target, reader.value[reader.offset:])
	reader.offset += count
	return count, nil
}

func managedDynamicAdmissionRequest(
	t *testing.T,
	app *App,
	session Session,
	sessionCookie *http.Cookie,
	proofCookie *http.Cookie,
	source string,
	encodedValue string,
) (*http.Request, *managedDynamicTrackingReader) {
	t.Helper()
	prefix := "csrf_token=" + app.csrfToken(session) +
		"&intent_ref=" + managedTestIntentRef +
		"&source=" + source +
		"&secret_value="
	body := []byte(prefix + encodedValue)
	reader := &managedDynamicTrackingReader{value: body}
	request := httptest.NewRequest(http.MethodPost, "/managed-environment/setup/admit", reader)
	request.ContentLength = int64(len(body))
	request.Header.Set("Content-Type", managedSecretFormMediaType)
	request.Header.Set("Origin", app.cfg.PublicURL)
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.AddCookie(sessionCookie)
	request.AddCookie(proofCookie)
	return request, reader
}

func managedDynamicAdmissionFixture(
	t *testing.T,
	source string,
) (*App, *fakeManagedDynamicIntentAuthority, Session, *http.Cookie, *http.Cookie) {
	t.Helper()
	app, authority, session, sessionCookie, _ := managedDynamicSessionFixture(t)
	authority.inspection.Intent.Source = source
	target := managedDynamicTargetFromInspection(authority.inspection)
	reservation, err := authority.Reserve(t.Context(), target.IntentRef, target.HumanSessionRef)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	proofWriter := httptest.NewRecorder()
	app.writeManagedDynamicStepUpProof(proofWriter, managedDynamicStepUpProof{
		Schema: managedDynamicStepUpProofDomain, Target: target,
		OperationRef: reservation.OperationRef, AuthenticatedAt: now.Unix(),
		ExpiresAt: now.Add(managedStepUpProofTTL).Unix(),
	})
	proofCookie := cookieByName(t, proofWriter.Result().Cookies(), hostDynamicProofCookie)
	return app, authority, session, sessionCookie, proofCookie
}

func TestManagedDynamicImportIsAdmittedOnceThenForgotten(t *testing.T) {
	app, authority, session, sessionCookie, proofCookie := managedDynamicAdmissionFixture(t, "import")
	canary := "bounded-once-canary"
	request, _ := managedDynamicAdmissionRequest(t, app, session, sessionCookie, proofCookie, "import", url.QueryEscape(canary))
	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/managed-environment/setup?intent="+managedTestIntentRef {
		t.Fatalf("bounded import did not reach the value-free receipt: status=%d location=%q body=%s", response.Code, response.Header().Get("Location"), response.Body.String())
	}
	if authority.beginCount != 1 || authority.completeCount != 1 || authority.reservation == nil || !authority.reservation.ValueAdmissionComplete {
		t.Fatalf("admission was not durably completed once: begin=%d complete=%d reservation=%#v", authority.beginCount, authority.completeCount, authority.reservation)
	}
	if strings.Contains(response.Body.String(), canary) || strings.Contains(response.Header().Get("Location"), canary) {
		t.Fatal("admitted value crossed the response boundary")
	}

	view := httptest.NewRequest(http.MethodGet, response.Header().Get("Location"), nil)
	view.AddCookie(sessionCookie)
	view.AddCookie(proofCookie)
	viewResponse := httptest.NewRecorder()
	app.routes().ServeHTTP(viewResponse, view)
	body := viewResponse.Body.String()
	if viewResponse.Code != http.StatusOK || !strings.Contains(body, "Value checked and forgotten") || !strings.Contains(body, "No value retained") || strings.Contains(body, `name="secret_value"`) || strings.Contains(body, canary) {
		t.Fatalf("value-free admission receipt is invalid: status=%d body=%s", viewResponse.Code, body)
	}
}

func TestManagedDynamicDuplicateAdmissionNeverReadsValueAgain(t *testing.T) {
	app, authority, session, sessionCookie, proofCookie := managedDynamicAdmissionFixture(t, "import")
	first, _ := managedDynamicAdmissionRequest(t, app, session, sessionCookie, proofCookie, "import", "first-value")
	firstResponse := httptest.NewRecorder()
	app.routes().ServeHTTP(firstResponse, first)
	if firstResponse.Code != http.StatusSeeOther {
		t.Fatalf("first admission failed: %d %s", firstResponse.Code, firstResponse.Body.String())
	}

	second, reader := managedDynamicAdmissionRequest(t, app, session, sessionCookie, proofCookie, "import", "must-not-be-read")
	secondResponse := httptest.NewRecorder()
	app.routes().ServeHTTP(secondResponse, second)
	prefixLength := len(reader.value) - len("must-not-be-read")
	if secondResponse.Code != http.StatusSeeOther || reader.offset != prefixLength || authority.completeCount != 1 {
		t.Fatalf("duplicate read value bytes or completed twice: status=%d read=%d prefix=%d complete=%d", secondResponse.Code, reader.offset, prefixLength, authority.completeCount)
	}
}

func TestManagedDynamicAdmissionRejectsInvalidImportAfterBurningOnce(t *testing.T) {
	tests := []struct {
		name    string
		encoded string
	}{
		{name: "empty", encoded: ""},
		{name: "newline", encoded: "line%0Asecond"},
		{name: "carriage return", encoded: "line%0Dsecond"},
		{name: "nul", encoded: "before%00after"},
		{name: "invalid utf8", encoded: "%FF"},
		{name: "malformed escape", encoded: "%GG"},
		{name: "extra field", encoded: "value&other=field"},
		{name: "oversized decoded value", encoded: strings.Repeat("x", managedDynamicImportMaxBytes+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			app, authority, session, sessionCookie, proofCookie := managedDynamicAdmissionFixture(t, "import")
			request, _ := managedDynamicAdmissionRequest(t, app, session, sessionCookie, proofCookie, "import", test.encoded)
			response := httptest.NewRecorder()
			app.routes().ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || authority.beginCount != 1 || authority.completeCount != 0 || authority.reservation == nil || !authority.reservation.ValueAdmissionStarted || authority.reservation.ValueAdmissionComplete {
				t.Fatalf("invalid value did not fail closed after one burn: status=%d begin=%d complete=%d reservation=%#v body=%s", response.Code, authority.beginCount, authority.completeCount, authority.reservation, response.Body.String())
			}
			if test.encoded != "" && strings.Contains(response.Body.String(), test.encoded) {
				t.Fatal("invalid value crossed the failure response")
			}
		})
	}
}

func TestManagedDynamicAdmissionChecksProofBeforeReadingValue(t *testing.T) {
	app, authority, session, sessionCookie, proofCookie := managedDynamicAdmissionFixture(t, "import")
	request, reader := managedDynamicAdmissionRequest(t, app, session, sessionCookie, proofCookie, "generated", "must-not-be-read")
	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)
	prefixLength := len(reader.value) - len("must-not-be-read")
	if response.Code != http.StatusForbidden || reader.offset != prefixLength || authority.beginCount != 0 || authority.completeCount != 0 {
		t.Fatalf("unbound request read value bytes or changed admission state: status=%d read=%d prefix=%d begin=%d complete=%d", response.Code, reader.offset, prefixLength, authority.beginCount, authority.completeCount)
	}
}

func TestManagedDynamicAdmissionBurnsIncompleteBodyWithoutCompletion(t *testing.T) {
	app, authority, session, sessionCookie, proofCookie := managedDynamicAdmissionFixture(t, "import")
	request, _ := managedDynamicAdmissionRequest(t, app, session, sessionCookie, proofCookie, "import", "partial")
	request.ContentLength++
	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || authority.beginCount != 1 || authority.completeCount != 0 || authority.reservation == nil || !authority.reservation.ValueAdmissionStarted || authority.reservation.ValueAdmissionComplete {
		t.Fatalf("incomplete body did not burn exactly one admission: status=%d begin=%d complete=%d reservation=%#v", response.Code, authority.beginCount, authority.completeCount, authority.reservation)
	}
}

func TestManagedDynamicGeneratedAdmissionRequiresEmptyBrowserValue(t *testing.T) {
	app, authority, session, sessionCookie, proofCookie := managedDynamicAdmissionFixture(t, "generated")
	request, _ := managedDynamicAdmissionRequest(t, app, session, sessionCookie, proofCookie, "generated", "")
	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || authority.completeCount != 1 || authority.reservation == nil || !authority.reservation.ValueAdmissionComplete {
		t.Fatalf("internal generation did not complete one admission: status=%d reservation=%#v body=%s", response.Code, authority.reservation, response.Body.String())
	}

	app, authority, session, sessionCookie, proofCookie = managedDynamicAdmissionFixture(t, "generated")
	request, _ = managedDynamicAdmissionRequest(t, app, session, sessionCookie, proofCookie, "generated", "browser-value")
	response = httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || authority.completeCount != 0 {
		t.Fatalf("generated mode accepted browser bytes: status=%d complete=%d", response.Code, authority.completeCount)
	}
}

func TestManagedDynamicValueProcessorZeroizesOwnedBuffers(t *testing.T) {
	requestReader := &managedDynamicTrackingReader{value: []byte("owned-import-value")}
	if err := processManagedDynamicValue(requestReader, int64(len(requestReader.value)), "import", bytes.NewReader(nil)); err != nil {
		t.Fatal(err)
	}
	if len(requestReader.exposed) == 0 || !allZero(requestReader.exposed[0]) {
		t.Fatal("owned import buffer was not zeroized")
	}

	randomReader := &managedDynamicTrackingReader{value: bytes.Repeat([]byte{0x5a}, managedDynamicGeneratedEntropyBytes)}
	if err := processManagedDynamicValue(bytes.NewReader(nil), 0, "generated", randomReader); err != nil {
		t.Fatal(err)
	}
	if len(randomReader.exposed) == 0 || !allZero(randomReader.exposed[0]) {
		t.Fatal("owned generator entropy buffer was not zeroized")
	}
}
