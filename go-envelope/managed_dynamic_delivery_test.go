package main

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"
)

func TestManagedDynamicDeliveryClientSendsOnlyCustodyReferences(t *testing.T) {
	clientConnection, serverConnection := net.Pipe()
	defer serverConnection.Close()
	client := newManagedDynamicDeliveryClient("/run/janus/dynamic-delivery.sock")
	client.dial = func(context.Context, string, string) (net.Conn, error) {
		return clientConnection, nil
	}
	client.now = func() time.Time { return time.Unix(1_800_000_000, 0) }
	target := managedDynamicCustodyRequestTarget()
	custody := managedDynamicCustodyTestResult("op_0123456789abcdef")
	done := make(chan error, 1)
	go func() {
		body, err := readManagedTransactionFrame(serverConnection)
		if err != nil {
			done <- err
			return
		}
		var request managedDynamicDeliveryRequest
		if decodeStrictJSON(body, &request) != nil || validateManagedDynamicDeliveryRequest(request) != nil {
			done <- managedDynamicDeliveryError("dynamic_delivery_request_invalid")
			return
		}
		var generic map[string]any
		_ = json.Unmarshal(body, &generic)
		for _, forbidden := range []string{"value", "ciphertext", "path", "filename", "packet"} {
			if _, exists := generic[forbidden]; exists {
				done <- managedDynamicDeliveryError("dynamic_delivery_request_invalid")
				return
			}
		}
		operationRef := request.OperationRef
		packageRef := "pkg_fixture0001"
		envelopeRef := "env_fixture0001"
		response := managedDynamicDeliveryResponse{
			Schema: managedDynamicDeliveryResponseSchema, SchemaVersion: 1,
			OperationRef: &operationRef, PackageRef: &packageRef, EnvelopeRef: &envelopeRef,
			Phase: "prepared", ReasonCode: "dynamic_delivery_prepared",
		}
		responseBody, _ := json.Marshal(response)
		done <- writeManagedTransactionFrame(serverConnection, responseBody)
	}()
	result, err := client.Prepare(t.Context(), target, custody.OperationRef, custody)
	if err != nil || validateManagedDynamicDeliveryResult(result, custody.OperationRef) != nil {
		t.Fatalf("delivery client did not return the exact value-free result: %#v %v", result, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
