package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	dynamicTestHost       = "host_0123456789abcdef"
	dynamicTestService    = "svc_0123456789abcdef"
	dynamicTestPolicy     = "envpol_0123456789abcdef"
	dynamicTestOperation  = "op_0123456789abcdef"
	dynamicTestPackage    = "pkg_0123456789abcdef"
	dynamicTestEnvelope   = "env_0123456789abcdef"
	dynamicTestBinding    = "bind_0123456789abcdef"
	dynamicTestGeneration = "gen_0123456789abcdef"
	dynamicTestReload     = "reload_0123456789abcdef"
	dynamicTestHealth     = "health_0123456789abcdef"
)

func dynamicTestClaim() *managedDynamicPackageClaim {
	return &managedDynamicPackageClaim{
		HostRef: dynamicTestHost, ServiceRef: dynamicTestService,
		EnvironmentPolicyRef: dynamicTestPolicy, OperationRef: dynamicTestOperation,
		OperationKind: "create",
		PackageRef:    dynamicTestPackage, EnvelopeRef: dynamicTestEnvelope,
		BindingRef: dynamicTestBinding, GenerationRef: dynamicTestGeneration,
		ReloadProfileRef: dynamicTestReload, HealthProfileRef: dynamicTestHealth,
		Packet: []byte("synthetic-age-packet"),
	}
}

func dynamicTestReceipt() managedDynamicActivationReceipt {
	return managedDynamicActivationReceipt{
		HostRef: dynamicTestHost, ServiceRef: dynamicTestService,
		EnvironmentPolicyRef: dynamicTestPolicy, OperationRef: dynamicTestOperation,
		OperationKind: "create",
		PackageRef:    dynamicTestPackage, EnvelopeRef: dynamicTestEnvelope,
		BindingRef: dynamicTestBinding, GenerationRef: dynamicTestGeneration,
		ReloadProfileRef: dynamicTestReload, HealthProfileRef: dynamicTestHealth,
		Phase: "active", ReasonCode: "dynamic_host_environment_active",
		MaterializationReasonCode: "dynamic_host_environment_materialized",
		MaterializedAtUnixSecs:    1_800_000_000, ReloadedAtUnixSecs: 1_800_000_001,
		HeartbeatObservedAtUnixSecs: 1_800_000_002,
		ProcessObservedAtUnixSecs:   1_800_000_002,
		ProbeObservedAtUnixSecs:     1_800_000_002,
	}
}

func TestManagedDynamicRollbackReceiptRequiresExactDistinctPreviousGeneration(t *testing.T) {
	receipt := dynamicTestReceipt()
	receipt.OperationKind = "replace"
	receipt.Phase = "rolled_back"
	receipt.ReasonCode = "dynamic_host_replacement_rolled_back"
	receipt.MaterializationReasonCode = "dynamic_host_replacement_materialized"
	receipt.FailureReasonCode = "dynamic_host_health_failed"
	receipt.RestoredBindingRef = "bind_previous000001"
	receipt.RestoredGenerationRef = "gen_previous000001"
	if err := validateManagedDynamicActivationReceipt(receipt); err != nil {
		t.Fatalf("exact recovered rollback denied: %v", err)
	}
	receipt.RestoredGenerationRef = receipt.GenerationRef
	if validateManagedDynamicActivationReceipt(receipt) == nil {
		t.Fatal("replacement generation was accepted as its own rollback target")
	}
}

func TestManagedDynamicTransportClientUsesExactValueFreeFrames(t *testing.T) {
	clientConnection, serverConnection := net.Pipe()
	client := newManagedDynamicTransportClient("/run/janus/dynamic-transport.sock")
	client.dial = func(context.Context, string, string) (net.Conn, error) { return clientConnection, nil }
	client.now = func() time.Time { return time.Unix(1_800_000_000, 0) }
	done := make(chan error, 1)
	go func() {
		defer serverConnection.Close()
		body, err := readManagedTransactionFrame(serverConnection)
		if err != nil {
			done <- err
			return
		}
		var request managedDynamicTransportClaimRequest
		if decodeStrictJSON(body, &request) != nil || request.Action != "claim" || request.HostRef != dynamicTestHost || request.PacketReturned || request.ValueReturned {
			done <- errors.New("claim frame was not exact")
			return
		}
		claim := dynamicTestClaim()
		response := managedDynamicTransportResponse{
			Schema: managedDynamicTransportResponseSchema, SchemaVersion: managedDynamicTransportSchemaVersion, Action: "claim",
			HostRef: &claim.HostRef, ServiceRef: &claim.ServiceRef,
			EnvironmentPolicyRef: &claim.EnvironmentPolicyRef, OperationRef: &claim.OperationRef,
			OperationKind: &claim.OperationKind,
			PackageRef:    &claim.PackageRef, EnvelopeRef: &claim.EnvelopeRef,
			BindingRef: &claim.BindingRef, GenerationRef: &claim.GenerationRef,
			ReloadProfileRef: &claim.ReloadProfileRef, HealthProfileRef: &claim.HealthProfileRef,
			PacketBase64: stringPointer(base64.RawStdEncoding.EncodeToString(claim.Packet)),
			Phase:        "claimed", ReasonCode: "dynamic_transport_package_claimed", PacketReturned: true,
		}
		encoded, _ := json.Marshal(response)
		done <- writeManagedTransactionFrame(serverConnection, encoded)
	}()
	claim, err := client.Claim(t.Context(), dynamicTestHost)
	if err != nil || claim == nil || string(claim.Packet) != "synthetic-age-packet" || claim.OperationRef != dynamicTestOperation {
		t.Fatalf("exact claim failed: %#v %v", claim, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	clientConnection, serverConnection = net.Pipe()
	client.dial = func(context.Context, string, string) (net.Conn, error) { return clientConnection, nil }
	go func() {
		defer serverConnection.Close()
		body, err := readManagedTransactionFrame(serverConnection)
		if err != nil {
			done <- err
			return
		}
		var request managedDynamicTransportAcknowledgeRequest
		if decodeStrictJSON(body, &request) != nil || request.Action != "acknowledge" || request.Receipt.OperationRef != dynamicTestOperation || request.Receipt.PacketReturned || request.Receipt.ValueReturned {
			done <- errors.New("receipt frame was not exact and value-free")
			return
		}
		receipt := dynamicTestReceipt()
		response := managedDynamicTransportResponse{
			Schema: managedDynamicTransportResponseSchema, SchemaVersion: managedDynamicTransportSchemaVersion, Action: "acknowledge",
			HostRef: &receipt.HostRef, ServiceRef: &receipt.ServiceRef,
			EnvironmentPolicyRef: &receipt.EnvironmentPolicyRef, OperationRef: &receipt.OperationRef,
			OperationKind: &receipt.OperationKind,
			PackageRef:    &receipt.PackageRef, EnvelopeRef: &receipt.EnvelopeRef,
			BindingRef: &receipt.BindingRef, GenerationRef: &receipt.GenerationRef,
			ReloadProfileRef: &receipt.ReloadProfileRef, HealthProfileRef: &receipt.HealthProfileRef,
			Phase: "active", ReasonCode: "dynamic_transport_receipt_recorded",
		}
		encoded, _ := json.Marshal(response)
		done <- writeManagedTransactionFrame(serverConnection, encoded)
	}()
	if err := client.Acknowledge(t.Context(), dynamicTestReceipt()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	clientConnection, serverConnection = net.Pipe()
	client.dial = func(context.Context, string, string) (net.Conn, error) { return clientConnection, nil }
	go func() {
		defer serverConnection.Close()
		body, err := readManagedTransactionFrame(serverConnection)
		if err != nil {
			done <- err
			return
		}
		var request managedDynamicTransportStatusRequest
		if decodeStrictJSON(body, &request) != nil || request.Action != "status" || request.Query.OperationRef != dynamicTestOperation || request.Query.PacketReturned || request.Query.ValueReturned {
			done <- errors.New("status frame was not exact and value-free")
			return
		}
		query := dynamicTestActivationQuery()
		response := managedDynamicTransportResponse{
			Schema: managedDynamicTransportResponseSchema, SchemaVersion: managedDynamicTransportSchemaVersion, Action: "status",
			HostRef: &query.HostRef, ServiceRef: &query.ServiceRef,
			EnvironmentPolicyRef: &query.EnvironmentPolicyRef, OperationRef: &query.OperationRef,
			OperationKind: &query.OperationKind,
			PackageRef:    &query.PackageRef, EnvelopeRef: &query.EnvelopeRef,
			BindingRef: &query.BindingRef, GenerationRef: &query.GenerationRef,
			ReloadProfileRef: &query.ReloadProfileRef, HealthProfileRef: &query.HealthProfileRef,
			Phase: "active", ReasonCode: "dynamic_transport_environment_active",
		}
		encoded, _ := json.Marshal(response)
		done <- writeManagedTransactionFrame(serverConnection, encoded)
	}()
	status, err := client.Status(t.Context(), dynamicTestActivationQuery())
	if err != nil || status != managedDynamicActivationActive {
		t.Fatalf("exact activation status failed: %q %v", status, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func dynamicTestActivationQuery() managedDynamicActivationQuery {
	return managedDynamicActivationQuery{
		HostRef: dynamicTestHost, ServiceRef: dynamicTestService,
		EnvironmentPolicyRef: dynamicTestPolicy, OperationRef: dynamicTestOperation,
		OperationKind: "create",
		PackageRef:    dynamicTestPackage, EnvelopeRef: dynamicTestEnvelope,
		BindingRef: dynamicTestBinding, GenerationRef: dynamicTestGeneration,
		ReloadProfileRef: dynamicTestReload, HealthProfileRef: dynamicTestHealth,
	}
}

func TestManagedDynamicTransportClientAcceptsPacketFramesAboveTheControlLimit(t *testing.T) {
	clientConnection, serverConnection := net.Pipe()
	client := newManagedDynamicTransportClient("/run/janus/dynamic-transport.sock")
	client.dial = func(context.Context, string, string) (net.Conn, error) { return clientConnection, nil }
	done := make(chan error, 1)
	packet := bytes.Repeat([]byte("p"), managedTransactionMaxFrameBytes+1)
	go func() {
		defer serverConnection.Close()
		if _, err := readManagedTransactionFrame(serverConnection); err != nil {
			done <- err
			return
		}
		claim := dynamicTestClaim()
		response := managedDynamicTransportResponse{
			Schema: managedDynamicTransportResponseSchema, SchemaVersion: managedDynamicTransportSchemaVersion, Action: "claim",
			HostRef: &claim.HostRef, ServiceRef: &claim.ServiceRef,
			EnvironmentPolicyRef: &claim.EnvironmentPolicyRef, OperationRef: &claim.OperationRef,
			OperationKind: &claim.OperationKind,
			PackageRef:    &claim.PackageRef, EnvelopeRef: &claim.EnvelopeRef,
			BindingRef: &claim.BindingRef, GenerationRef: &claim.GenerationRef,
			ReloadProfileRef: &claim.ReloadProfileRef, HealthProfileRef: &claim.HealthProfileRef,
			PacketBase64: stringPointer(base64.RawStdEncoding.EncodeToString(packet)),
			Phase:        "claimed", ReasonCode: "dynamic_transport_package_claimed", PacketReturned: true,
		}
		encoded, _ := json.Marshal(response)
		done <- writeManagedTransactionFrameBounded(serverConnection, encoded, managedDynamicTransportMaxFrameBytes)
	}()
	claim, err := client.Claim(t.Context(), dynamicTestHost)
	if err != nil || claim == nil || len(claim.Packet) != len(packet) {
		t.Fatalf("bounded encrypted packet frame failed: claim=%#v err=%v", claim, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func stringPointer(value string) *string { return &value }

type fakeManagedDynamicTransport struct {
	claim          *managedDynamicPackageClaim
	claimedHost    string
	receipt        managedDynamicActivationReceipt
	statusQuery    managedDynamicActivationQuery
	status         managedDynamicActivationStatus
	claimErr       error
	acknowledgeErr error
	statusErr      error
}

func (fake *fakeManagedDynamicTransport) Claim(_ context.Context, hostRef string) (*managedDynamicPackageClaim, error) {
	fake.claimedHost = hostRef
	return fake.claim, fake.claimErr
}

func (fake *fakeManagedDynamicTransport) Acknowledge(_ context.Context, receipt managedDynamicActivationReceipt) error {
	fake.receipt = receipt
	return fake.acknowledgeErr
}

func (fake *fakeManagedDynamicTransport) Status(_ context.Context, query managedDynamicActivationQuery) (managedDynamicActivationStatus, error) {
	fake.statusQuery = query
	return fake.status, fake.statusErr
}

func TestManagedDynamicHostRoutesBindTokenHostAndReceipt(t *testing.T) {
	tokenDirectory := filepath.Join(t.TempDir(), "tokens")
	if err := os.Mkdir(tokenDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("host-token-", 4)
	writeManagedHostTokenGeneration(t, tokenDirectory, dynamicTestHost, token)
	fake := &fakeManagedDynamicTransport{claim: dynamicTestClaim()}
	app := newTestApp(t)
	app.managedDynamicTransport = fake
	app.managedDynamicHostTokens = &managedHostTokenVerifier{root: tokenDirectory}

	claimRequest := httptest.NewRequest(http.MethodGet, "/internal/managed-environment-host-packages/"+dynamicTestHost, nil)
	claimRequest.Header.Set("Authorization", "Bearer "+token)
	claimResponse := httptest.NewRecorder()
	app.routes().ServeHTTP(claimResponse, claimRequest)
	if claimResponse.Code != http.StatusOK || fake.claimedHost != dynamicTestHost || claimResponse.Header().Get("Cache-Control") != "no-store, no-transform" || bytes.Contains(claimResponse.Body.Bytes(), []byte("synthetic-age-packet")) {
		t.Fatalf("unexpected exact-host claim response: %d %q", claimResponse.Code, claimResponse.Body.String())
	}
	var claim managedDynamicHostClaimResponse
	if decodeStrictJSON(claimResponse.Body.Bytes(), &claim) != nil || claim.OperationRef != dynamicTestOperation || !claim.PacketReturned || claim.ValueReturned {
		t.Fatalf("invalid host claim: %#v", claim)
	}

	deniedRequest := httptest.NewRequest(http.MethodGet, "/internal/managed-environment-host-packages/"+dynamicTestHost, nil)
	deniedRequest.Header.Set("Authorization", "Bearer "+token+"wrong")
	deniedResponse := httptest.NewRecorder()
	app.routes().ServeHTTP(deniedResponse, deniedRequest)
	if deniedResponse.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token admitted: %d", deniedResponse.Code)
	}

	receipt := managedDynamicHostReceiptRequest{
		Schema: managedDynamicHostReceiptSchema, SchemaVersion: managedDynamicHostSchemaVersion,
		HostRef: dynamicTestHost, ServiceRef: dynamicTestService,
		EnvironmentPolicyRef: dynamicTestPolicy, OperationRef: dynamicTestOperation,
		OperationKind: "create",
		PackageRef:    dynamicTestPackage, EnvelopeRef: dynamicTestEnvelope,
		BindingRef: dynamicTestBinding, GenerationRef: dynamicTestGeneration,
		ReloadProfileRef: dynamicTestReload, HealthProfileRef: dynamicTestHealth,
		Phase: "active", ReasonCode: "dynamic_host_environment_active",
		MaterializationReasonCode: "dynamic_host_environment_materialized",
		MaterializedAtUnixSecs:    1_800_000_000, ReloadedAtUnixSecs: 1_800_000_001,
		HeartbeatObservedAtUnixSecs: 1_800_000_002,
		ProcessObservedAtUnixSecs:   1_800_000_002,
		ProbeObservedAtUnixSecs:     1_800_000_002,
	}
	body, _ := json.Marshal(receipt)
	receiptRequest := httptest.NewRequest(http.MethodPost, "/internal/managed-environment-host-packages/"+dynamicTestHost+"/"+dynamicTestOperation+"/receipt", bytes.NewReader(body))
	receiptRequest.Header.Set("Authorization", "Bearer "+token)
	receiptRequest.Header.Set("Content-Type", "application/json")
	receiptResponse := httptest.NewRecorder()
	app.routes().ServeHTTP(receiptResponse, receiptRequest)
	if receiptResponse.Code != http.StatusNoContent || fake.receipt.OperationRef != dynamicTestOperation || fake.receipt.HostRef != dynamicTestHost {
		t.Fatalf("receipt was not bound: %d %#v", receiptResponse.Code, fake.receipt)
	}

	receipt.HeartbeatObservedAtUnixSecs = receipt.ReloadedAtUnixSecs - 1
	body, _ = json.Marshal(receipt)
	staleRequest := httptest.NewRequest(http.MethodPost, "/internal/managed-environment-host-packages/"+dynamicTestHost+"/"+dynamicTestOperation+"/receipt", bytes.NewReader(body))
	staleRequest.Header.Set("Authorization", "Bearer "+token)
	staleRequest.Header.Set("Content-Type", "application/json")
	staleResponse := httptest.NewRecorder()
	app.routes().ServeHTTP(staleResponse, staleRequest)
	if staleResponse.Code != http.StatusBadRequest {
		t.Fatalf("stale health evidence admitted: %d", staleResponse.Code)
	}

	receipt.HeartbeatObservedAtUnixSecs = 1_800_000_002
	receipt.OperationRef = "op_attacker000001"
	body, _ = json.Marshal(receipt)
	mismatchRequest := httptest.NewRequest(http.MethodPost, "/internal/managed-environment-host-packages/"+dynamicTestHost+"/"+dynamicTestOperation+"/receipt", bytes.NewReader(body))
	mismatchRequest.Header.Set("Authorization", "Bearer "+token)
	mismatchRequest.Header.Set("Content-Type", "application/json")
	mismatchResponse := httptest.NewRecorder()
	app.routes().ServeHTTP(mismatchResponse, mismatchRequest)
	if mismatchResponse.Code != http.StatusBadRequest {
		t.Fatalf("cross-operation receipt admitted: %d", mismatchResponse.Code)
	}
}
