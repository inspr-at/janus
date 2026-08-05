package main

import (
	"bytes"
	"context"
	"errors"
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

type fakeManagedDynamicCustodyExecutor struct {
	count      int
	custodyErr error
	recoverErr error
	custodied  *managedDynamicCustodyResult
}

func managedDynamicCustodyTestResult(operationRef string) managedDynamicCustodyResult {
	return managedDynamicCustodyResult{
		OperationRef: operationRef, BindingRef: "bind_fixture0001",
		SecretRef: "sec_fixture0001", GenerationRef: "gen_fixture0001",
		Phase: "custodied", ReasonCode: "dynamic_custody_stored", ValueReturned: false,
	}
}

func managedDynamicDeliveryTestResult(operationRef string) managedDynamicDeliveryResult {
	return managedDynamicDeliveryResult{
		OperationRef: operationRef, PackageRef: "pkg_fixture0001", EnvelopeRef: "env_fixture0001",
		Phase: "prepared", ReasonCode: "dynamic_delivery_prepared",
	}
}

type fakeManagedDynamicDeliveryExecutor struct {
	prepareErr error
}

func (executor *fakeManagedDynamicDeliveryExecutor) Prepare(_ context.Context, _ managedDynamicStepUpTarget, operationRef string, custody managedDynamicCustodyResult) (managedDynamicDeliveryResult, error) {
	if executor.prepareErr != nil {
		return managedDynamicDeliveryResult{}, executor.prepareErr
	}
	if validateManagedDynamicCustodyResult(custody, operationRef) != nil {
		return managedDynamicDeliveryResult{}, managedDynamicDeliveryError("dynamic_delivery_request_invalid")
	}
	return managedDynamicDeliveryTestResult(operationRef), nil
}

func (executor *fakeManagedDynamicCustodyExecutor) Custody(_ context.Context, _ managedDynamicStepUpTarget, operationRef string, value []byte) (managedDynamicCustodyResult, error) {
	executor.count++
	if executor.custodyErr != nil {
		return managedDynamicCustodyResult{}, executor.custodyErr
	}
	if validateManagedDynamicValue(value) != nil {
		return managedDynamicCustodyResult{}, managedDynamicCustodyError("dynamic_custody_value_invalid")
	}
	result := managedDynamicCustodyTestResult(operationRef)
	executor.custodied = &result
	return result, nil
}

func (executor *fakeManagedDynamicCustodyExecutor) Recover(_ context.Context, _ managedDynamicStepUpTarget, operationRef string) (managedDynamicCustodyResult, error) {
	if executor.recoverErr != nil {
		return managedDynamicCustodyResult{}, executor.recoverErr
	}
	if executor.custodied == nil || executor.custodied.OperationRef != operationRef {
		return managedDynamicCustodyResult{}, managedDynamicCustodyError("dynamic_custody_not_found")
	}
	return *executor.custodied, nil
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
	return managedDynamicAdmissionFixtureForOperation(t, source, "create")
}

func managedDynamicAdmissionFixtureForOperation(
	t *testing.T,
	source string,
	operationKind string,
) (*App, *fakeManagedDynamicIntentAuthority, Session, *http.Cookie, *http.Cookie) {
	t.Helper()
	app, authority, session, sessionCookie, _ := managedDynamicSessionFixture(t)
	app.managedDynamicCustody = &fakeManagedDynamicCustodyExecutor{}
	app.managedDynamicDelivery = &fakeManagedDynamicDeliveryExecutor{}
	authority.inspection.Intent.Source = source
	authority.inspection.Intent.OperationKind = operationKind
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

func TestManagedDynamicImportReachesEncryptedCustodyOnce(t *testing.T) {
	app, authority, session, sessionCookie, proofCookie := managedDynamicAdmissionFixture(t, "import")
	transport := &fakeManagedDynamicTransport{status: managedDynamicActivationPending}
	app.managedDynamicTransport = transport
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
	if viewResponse.Code != http.StatusOK || !strings.Contains(body, "Waiting for the host") || strings.Contains(body, "Environment variable active") || !strings.Contains(body, "No value or packet returned") || !strings.Contains(body, authority.reservation.PackageRef) || strings.Contains(body, `name="secret_value"`) || strings.Contains(body, canary) {
		t.Fatalf("value-free admission receipt is invalid: status=%d body=%s", viewResponse.Code, body)
	}
	if transport.statusQuery.OperationRef != authority.reservation.OperationRef || transport.statusQuery.PackageRef != authority.reservation.PackageRef || transport.statusQuery.ReloadProfileRef != authority.inspection.Context.ReloadProfileRef || transport.statusQuery.HealthProfileRef != authority.inspection.Context.HealthProfileRef {
		t.Fatalf("activation lookup was not exact: %#v", transport.statusQuery)
	}

	transport.status = managedDynamicActivationActive
	activeResponse := httptest.NewRecorder()
	app.routes().ServeHTTP(activeResponse, view)
	activeBody := activeResponse.Body.String()
	if activeResponse.Code != http.StatusOK || !strings.Contains(activeBody, "Environment variable active") || !strings.Contains(activeBody, "fresh healthy observation") || strings.Contains(activeBody, canary) {
		t.Fatalf("exact host activation was not surfaced value-free: status=%d body=%s", activeResponse.Code, activeBody)
	}

	transport.status = managedDynamicActivationExpired
	expiredResponse := httptest.NewRecorder()
	app.routes().ServeHTTP(expiredResponse, view)
	if expiredResponse.Code != http.StatusOK || !strings.Contains(expiredResponse.Body.String(), "Package expired before activation") || strings.Contains(expiredResponse.Body.String(), "Environment variable active") {
		t.Fatalf("expired package was presented as active: status=%d body=%s", expiredResponse.Code, expiredResponse.Body.String())
	}

	transport.status = ""
	transport.statusErr = errors.New("dynamic transport unavailable")
	unavailableResponse := httptest.NewRecorder()
	app.routes().ServeHTTP(unavailableResponse, view)
	if unavailableResponse.Code != http.StatusOK || !strings.Contains(unavailableResponse.Body.String(), "Activation could not be checked") || strings.Contains(unavailableResponse.Body.String(), "Environment variable active") {
		t.Fatalf("unavailable activation evidence was presented as active: status=%d body=%s", unavailableResponse.Code, unavailableResponse.Body.String())
	}
}

func TestManagedDynamicReplacementShowsOnlyRecoveredRollbackStatus(t *testing.T) {
	app, authority, session, sessionCookie, proofCookie := managedDynamicAdmissionFixtureForOperation(t, "import", "replace")
	transport := &fakeManagedDynamicTransport{status: managedDynamicActivationRolledBack}
	app.managedDynamicTransport = transport
	canary := "replacement-rollback-canary"
	request, _ := managedDynamicAdmissionRequest(t, app, session, sessionCookie, proofCookie, "import", url.QueryEscape(canary))
	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("replacement admission failed: %d %s", response.Code, response.Body.String())
	}
	view := httptest.NewRequest(http.MethodGet, response.Header().Get("Location"), nil)
	view.AddCookie(sessionCookie)
	view.AddCookie(proofCookie)
	viewResponse := httptest.NewRecorder()
	app.routes().ServeHTTP(viewResponse, view)
	body := viewResponse.Body.String()
	if viewResponse.Code != http.StatusOK || !strings.Contains(body, "Replacement rolled back safely") || !strings.Contains(body, "Old value active") || !strings.Contains(body, "fresh recovered health") || strings.Contains(body, canary) || strings.Contains(body, "Environment variable active") {
		t.Fatalf("rollback status was not exact and value-free: status=%d body=%s", viewResponse.Code, body)
	}
	if transport.statusQuery.OperationKind != "replace" || transport.statusQuery.OperationRef != authority.reservation.OperationRef {
		t.Fatalf("rollback lookup was not replacement-bound: %#v", transport.statusQuery)
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

func TestManagedDynamicLostCustodyResponseRecoversWithoutReadingValueAgain(t *testing.T) {
	app, authority, session, sessionCookie, proofCookie := managedDynamicAdmissionFixture(t, "import")
	executor := app.managedDynamicCustody.(*fakeManagedDynamicCustodyExecutor)
	executor.custodyErr = managedDynamicCustodyError("dynamic_custody_unavailable")
	result := managedDynamicCustodyTestResult(authority.reservation.OperationRef)
	executor.custodied = &result
	first, _ := managedDynamicAdmissionRequest(t, app, session, sessionCookie, proofCookie, "import", "stored-before-response-loss")
	firstResponse := httptest.NewRecorder()
	app.routes().ServeHTTP(firstResponse, first)
	if firstResponse.Code != http.StatusSeeOther || authority.reservation == nil || !authority.reservation.ValueAdmissionComplete || authority.reservation.SecretRef != result.SecretRef {
		t.Fatalf("lost response recovery was not idempotent: status=%d reservation=%#v", firstResponse.Code, authority.reservation)
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
	value, err := processManagedDynamicValue(requestReader, int64(len(requestReader.value)), "import", bytes.NewReader(nil))
	if err != nil {
		t.Fatal(err)
	}
	zeroizeBytes(value)
	if len(requestReader.exposed) == 0 || !allZero(requestReader.exposed[0]) {
		t.Fatal("owned import buffer was not zeroized")
	}

	randomReader := &managedDynamicTrackingReader{value: bytes.Repeat([]byte{0x5a}, managedDynamicGeneratedEntropyBytes)}
	value, err = processManagedDynamicValue(bytes.NewReader(nil), 0, "generated", randomReader)
	if err != nil {
		t.Fatal(err)
	}
	zeroizeBytes(value)
	if len(randomReader.exposed) == 0 || !allZero(randomReader.exposed[0]) {
		t.Fatal("owned generator entropy buffer was not zeroized")
	}
}
