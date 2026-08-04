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
)

func dynamicTestClaim() *managedDynamicPackageClaim {
	return &managedDynamicPackageClaim{
		HostRef: dynamicTestHost, ServiceRef: dynamicTestService,
		EnvironmentPolicyRef: dynamicTestPolicy, OperationRef: dynamicTestOperation,
		PackageRef: dynamicTestPackage, EnvelopeRef: dynamicTestEnvelope,
		BindingRef: dynamicTestBinding, GenerationRef: dynamicTestGeneration,
		Packet: []byte("synthetic-age-packet"),
	}
}

func dynamicTestReceipt() managedDynamicMaterializationReceipt {
	return managedDynamicMaterializationReceipt{
		HostRef: dynamicTestHost, ServiceRef: dynamicTestService,
		EnvironmentPolicyRef: dynamicTestPolicy, OperationRef: dynamicTestOperation,
		PackageRef: dynamicTestPackage, EnvelopeRef: dynamicTestEnvelope,
		BindingRef: dynamicTestBinding, GenerationRef: dynamicTestGeneration,
		Phase: "materialized", ReasonCode: "dynamic_host_environment_materialized",
		ObservedAtUnixSecs: 1_800_000_000,
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
			Schema: managedDynamicTransportResponseSchema, SchemaVersion: 1, Action: "claim",
			HostRef: &claim.HostRef, ServiceRef: &claim.ServiceRef,
			EnvironmentPolicyRef: &claim.EnvironmentPolicyRef, OperationRef: &claim.OperationRef,
			PackageRef: &claim.PackageRef, EnvelopeRef: &claim.EnvelopeRef,
			BindingRef: &claim.BindingRef, GenerationRef: &claim.GenerationRef,
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
			Schema: managedDynamicTransportResponseSchema, SchemaVersion: 1, Action: "acknowledge",
			HostRef: &receipt.HostRef, ServiceRef: &receipt.ServiceRef,
			EnvironmentPolicyRef: &receipt.EnvironmentPolicyRef, OperationRef: &receipt.OperationRef,
			PackageRef: &receipt.PackageRef, EnvelopeRef: &receipt.EnvelopeRef,
			BindingRef: &receipt.BindingRef, GenerationRef: &receipt.GenerationRef,
			Phase: "materialized", ReasonCode: "dynamic_transport_receipt_recorded",
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
			Schema: managedDynamicTransportResponseSchema, SchemaVersion: 1, Action: "claim",
			HostRef: &claim.HostRef, ServiceRef: &claim.ServiceRef,
			EnvironmentPolicyRef: &claim.EnvironmentPolicyRef, OperationRef: &claim.OperationRef,
			PackageRef: &claim.PackageRef, EnvelopeRef: &claim.EnvelopeRef,
			BindingRef: &claim.BindingRef, GenerationRef: &claim.GenerationRef,
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
	receipt        managedDynamicMaterializationReceipt
	claimErr       error
	acknowledgeErr error
}

func (fake *fakeManagedDynamicTransport) Claim(_ context.Context, hostRef string) (*managedDynamicPackageClaim, error) {
	fake.claimedHost = hostRef
	return fake.claim, fake.claimErr
}

func (fake *fakeManagedDynamicTransport) Acknowledge(_ context.Context, receipt managedDynamicMaterializationReceipt) error {
	fake.receipt = receipt
	return fake.acknowledgeErr
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
		Schema: managedDynamicHostReceiptSchema, SchemaVersion: 1,
		HostRef: dynamicTestHost, ServiceRef: dynamicTestService,
		EnvironmentPolicyRef: dynamicTestPolicy, OperationRef: dynamicTestOperation,
		PackageRef: dynamicTestPackage, EnvelopeRef: dynamicTestEnvelope,
		BindingRef: dynamicTestBinding, GenerationRef: dynamicTestGeneration,
		Phase: "materialized", ReasonCode: "dynamic_host_environment_materialized",
		ObservedAtUnixSecs: 1_800_000_000,
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
