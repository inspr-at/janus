package main

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"
)

func managedDynamicCustodyRequestTarget() managedDynamicStepUpTarget {
	return managedDynamicStepUpTarget{
		OperationKind: "create", Source: "import",
		HostRef: "host_0123456789abcdef", ServiceRef: "svc_0123456789abcdef",
		EnvironmentPolicyRef:         "envpol_0123456789abcdef",
		EnvironmentPolicyFingerprint: "envpf_0123456789abcdef",
		DeclarationFingerprint:       "decl_0123456789abcdef",
		EnvironmentName:              "SERVICE_TOKEN",
	}
}

func writeManagedDynamicCustodyTestResponse(t *testing.T, connection net.Conn, response managedDynamicCustodyResponse) {
	t.Helper()
	body, err := json.Marshal(response)
	if err != nil || writeManagedTransactionFrame(connection, body) != nil {
		t.Errorf("write response: %v", err)
	}
}

func managedDynamicCustodyTestResponse(operationRef, phase string, expectsValue bool) managedDynamicCustodyResponse {
	response := managedDynamicCustodyResponse{
		Schema: managedDynamicCustodyResponseSchema, SchemaVersion: managedDynamicCustodySchemaVersion,
		OperationRef: &operationRef, Phase: phase, ExpectsValue: expectsValue,
		ReasonCode: "dynamic_custody_preflighted", ValueReturned: false,
	}
	if phase == "custodied" {
		bindingRef := "bind_fixture0001"
		secretRef := "sec_fixture0001"
		generationRef := "gen_fixture0001"
		response.BindingRef = &bindingRef
		response.SecretRef = &secretRef
		response.GenerationRef = &generationRef
		response.ReasonCode = "dynamic_custody_stored"
	}
	return response
}

func TestManagedDynamicCustodyClientPreflightsBeforeValueAndReturnsOnlyOpaqueRefs(t *testing.T) {
	clientConnection, serverConnection := net.Pipe()
	defer clientConnection.Close()
	client := newManagedDynamicCustodyClient("/run/janus/dynamic-custody.sock")
	client.dial = func(context.Context, string, string) (net.Conn, error) { return clientConnection, nil }
	client.now = func() time.Time { return time.Now().UTC() }
	operationRef := "op_0123456789abcdef"
	value := []byte("bounded-custody-canary")
	observed := make(chan []byte, 1)
	go func() {
		defer serverConnection.Close()
		if _, err := readManagedTransactionFrame(serverConnection); err != nil {
			return
		}
		writeManagedDynamicCustodyTestResponse(t, serverConnection, managedDynamicCustodyTestResponse(operationRef, "preflighted", true))
		body, err := readManagedTransactionFrame(serverConnection)
		if err != nil {
			return
		}
		observed <- append([]byte(nil), body...)
		writeManagedDynamicCustodyTestResponse(t, serverConnection, managedDynamicCustodyTestResponse(operationRef, "custodied", false))
	}()
	result, err := client.Custody(t.Context(), managedDynamicCustodyRequestTarget(), operationRef, value)
	if err != nil {
		t.Fatal(err)
	}
	if string(<-observed) != string(value) || validateManagedDynamicCustodyResult(result, operationRef) != nil || result.ValueReturned {
		t.Fatalf("custody result invalid: %#v", result)
	}
}

func TestManagedDynamicCustodyClientDuplicateDoesNotSendValueAgain(t *testing.T) {
	clientConnection, serverConnection := net.Pipe()
	defer clientConnection.Close()
	client := newManagedDynamicCustodyClient("/run/janus/dynamic-custody.sock")
	client.dial = func(context.Context, string, string) (net.Conn, error) { return clientConnection, nil }
	operationRef := "op_0123456789abcdef"
	go func() {
		defer serverConnection.Close()
		_, _ = readManagedTransactionFrame(serverConnection)
		writeManagedDynamicCustodyTestResponse(t, serverConnection, managedDynamicCustodyTestResponse(operationRef, "custodied", false))
	}()
	result, err := client.Custody(t.Context(), managedDynamicCustodyRequestTarget(), operationRef, []byte("must-not-cross"))
	if err != nil || validateManagedDynamicCustodyResult(result, operationRef) != nil {
		t.Fatalf("idempotent custody failed: %#v %v", result, err)
	}
}

func TestManagedDynamicCustodyClientRejectsValueReturningResponse(t *testing.T) {
	clientConnection, serverConnection := net.Pipe()
	defer clientConnection.Close()
	client := newManagedDynamicCustodyClient("/run/janus/dynamic-custody.sock")
	client.dial = func(context.Context, string, string) (net.Conn, error) { return clientConnection, nil }
	operationRef := "op_0123456789abcdef"
	go func() {
		defer serverConnection.Close()
		_, _ = readManagedTransactionFrame(serverConnection)
		response := managedDynamicCustodyTestResponse(operationRef, "custodied", false)
		response.ValueReturned = true
		writeManagedDynamicCustodyTestResponse(t, serverConnection, response)
	}()
	if _, err := client.Custody(t.Context(), managedDynamicCustodyRequestTarget(), operationRef, []byte("never-return")); err == nil || !isManagedDynamicCustodyError(err) {
		t.Fatalf("value-returning response was accepted: %v", err)
	}
}
