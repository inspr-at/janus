package main

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"time"
)

const (
	managedDynamicDeliveryRequestSchema  = "inspr.janus.managed-dynamic-delivery-request.v1"
	managedDynamicDeliveryResponseSchema = "inspr.janus.managed-dynamic-delivery-response.v1"
	managedDynamicDeliverySchemaVersion  = 1
	managedDynamicDeliveryTimeout        = 10 * time.Second
)

type managedDynamicDeliveryRequest struct {
	Schema                       string `json:"schema"`
	SchemaVersion                int    `json:"schema_version"`
	OperationRef                 string `json:"operation_ref"`
	OperationKind                string `json:"operation_kind"`
	Source                       string `json:"source"`
	HostRef                      string `json:"host_ref"`
	ServiceRef                   string `json:"service_ref"`
	EnvironmentPolicyRef         string `json:"environment_policy_ref"`
	EnvironmentPolicyFingerprint string `json:"environment_policy_fingerprint"`
	DeclarationFingerprint       string `json:"declaration_fingerprint"`
	EnvironmentName              string `json:"environment_name"`
	BindingRef                   string `json:"binding_ref"`
	SecretRef                    string `json:"secret_ref"`
	GenerationRef                string `json:"generation_ref"`
}

type managedDynamicDeliveryResponse struct {
	Schema         string  `json:"schema"`
	SchemaVersion  int     `json:"schema_version"`
	OperationRef   *string `json:"operation_ref"`
	PackageRef     *string `json:"package_ref"`
	EnvelopeRef    *string `json:"envelope_ref"`
	Phase          string  `json:"phase"`
	ReasonCode     string  `json:"reason_code"`
	PacketReturned bool    `json:"packet_returned"`
	ValueReturned  bool    `json:"value_returned"`
}

type managedDynamicDeliveryResult struct {
	OperationRef   string
	PackageRef     string
	EnvelopeRef    string
	Phase          string
	ReasonCode     string
	PacketReturned bool
	ValueReturned  bool
}

type managedDynamicDeliveryExecutor interface {
	Prepare(context.Context, managedDynamicStepUpTarget, string, managedDynamicCustodyResult) (managedDynamicDeliveryResult, error)
}

type managedDynamicDeliveryClient struct {
	socketPath string
	dial       func(context.Context, string, string) (net.Conn, error)
	now        func() time.Time
}

func newManagedDynamicDeliveryClient(socketPath string) *managedDynamicDeliveryClient {
	dialer := &net.Dialer{Timeout: managedTransactionDialTimeout}
	return &managedDynamicDeliveryClient{socketPath: socketPath, dial: dialer.DialContext, now: time.Now}
}

func (client *managedDynamicDeliveryClient) Prepare(ctx context.Context, target managedDynamicStepUpTarget, operationRef string, custody managedDynamicCustodyResult) (managedDynamicDeliveryResult, error) {
	bindingRef, secretRef, generationRef := custody.BindingRef, custody.SecretRef, custody.GenerationRef
	if target.OperationKind == "remove" {
		bindingRef, secretRef, generationRef = target.BindingRef, target.SecretRef, target.GenerationRef
	}
	request := managedDynamicDeliveryRequest{
		Schema: managedDynamicDeliveryRequestSchema, SchemaVersion: managedDynamicDeliverySchemaVersion,
		OperationRef: operationRef, OperationKind: target.OperationKind, Source: target.Source,
		HostRef: target.HostRef, ServiceRef: target.ServiceRef,
		EnvironmentPolicyRef:         target.EnvironmentPolicyRef,
		EnvironmentPolicyFingerprint: target.EnvironmentPolicyFingerprint,
		DeclarationFingerprint:       target.DeclarationFingerprint, EnvironmentName: target.EnvironmentName,
		BindingRef: bindingRef, SecretRef: secretRef, GenerationRef: generationRef,
	}
	if client == nil || !managedDynamicCleanAbsolutePath(client.socketPath) ||
		(target.OperationKind != "remove" && validateManagedDynamicCustodyResult(custody, operationRef) != nil) ||
		validateManagedDynamicDeliveryRequest(request) != nil {
		return managedDynamicDeliveryResult{}, managedDynamicDeliveryError("dynamic_delivery_request_invalid")
	}
	connection, err := client.dial(ctx, "unix", client.socketPath)
	if err != nil {
		return managedDynamicDeliveryResult{}, managedDynamicDeliveryError("dynamic_delivery_unavailable")
	}
	defer connection.Close()
	deadline := client.now().Add(managedDynamicDeliveryTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if connection.SetDeadline(deadline) != nil {
		return managedDynamicDeliveryResult{}, managedDynamicDeliveryError("dynamic_delivery_unavailable")
	}
	body, err := json.Marshal(request)
	if err != nil || writeManagedTransactionFrame(connection, body) != nil {
		return managedDynamicDeliveryResult{}, managedDynamicDeliveryError("dynamic_delivery_unavailable")
	}
	responseBody, err := readManagedTransactionFrame(connection)
	if err != nil {
		return managedDynamicDeliveryResult{}, managedDynamicDeliveryError("dynamic_delivery_unavailable")
	}
	var response managedDynamicDeliveryResponse
	if len(responseBody) == 0 || len(responseBody) > managedTransactionMaxFrameBytes ||
		decodeStrictJSON(responseBody, &response) != nil ||
		response.Schema != managedDynamicDeliveryResponseSchema || response.SchemaVersion != managedDynamicDeliverySchemaVersion ||
		response.OperationRef == nil || *response.OperationRef != operationRef || response.PacketReturned || response.ValueReturned ||
		!strings.HasPrefix(response.ReasonCode, "dynamic_delivery_") {
		return managedDynamicDeliveryResult{}, managedDynamicDeliveryError("dynamic_delivery_protocol_invalid")
	}
	if response.Phase == "denied" {
		return managedDynamicDeliveryResult{}, managedDynamicDeliveryError(response.ReasonCode)
	}
	if response.Phase != "prepared" || response.ReasonCode != "dynamic_delivery_prepared" ||
		response.PackageRef == nil || response.EnvelopeRef == nil ||
		!validManagedRef("pkg_", *response.PackageRef) || !validManagedRef("env_", *response.EnvelopeRef) {
		return managedDynamicDeliveryResult{}, managedDynamicDeliveryError("dynamic_delivery_protocol_invalid")
	}
	return managedDynamicDeliveryResult{
		OperationRef: *response.OperationRef, PackageRef: *response.PackageRef, EnvelopeRef: *response.EnvelopeRef,
		Phase: response.Phase, ReasonCode: response.ReasonCode, PacketReturned: false, ValueReturned: false,
	}, nil
}

func validateManagedDynamicDeliveryRequest(request managedDynamicDeliveryRequest) error {
	if request.Schema != managedDynamicDeliveryRequestSchema || request.SchemaVersion != managedDynamicDeliverySchemaVersion ||
		!validManagedRef("op_", request.OperationRef) || !matchesManagedDynamicOperationSource(request.OperationKind, request.Source) ||
		!validManagedRef("host_", request.HostRef) ||
		!validManagedRef("svc_", request.ServiceRef) || !validManagedRef("envpol_", request.EnvironmentPolicyRef) ||
		!validManagedRef("envpf_", request.EnvironmentPolicyFingerprint) || !validManagedRef("decl_", request.DeclarationFingerprint) ||
		!validManagedEnvironmentName(request.EnvironmentName) || !validManagedRef("bind_", request.BindingRef) ||
		!validManagedRef("sec_", request.SecretRef) || !validManagedRef("gen_", request.GenerationRef) {
		return managedDynamicDeliveryError("dynamic_delivery_request_invalid")
	}
	return nil
}

func validateManagedDynamicDeliveryResult(result managedDynamicDeliveryResult, operationRef string) error {
	if result.OperationRef != operationRef || !validManagedRef("op_", result.OperationRef) ||
		!validManagedRef("pkg_", result.PackageRef) || !validManagedRef("env_", result.EnvelopeRef) ||
		result.Phase != "prepared" || result.ReasonCode != "dynamic_delivery_prepared" || result.PacketReturned || result.ValueReturned {
		return managedDynamicDeliveryError("dynamic_delivery_result_invalid")
	}
	return nil
}

type managedDynamicDeliveryError string

func (err managedDynamicDeliveryError) Error() string { return string(err) }
