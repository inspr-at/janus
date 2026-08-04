package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"time"
)

const (
	managedDynamicCustodyRequestSchema  = "inspr.janus.managed-dynamic-custody-request.v1"
	managedDynamicCustodyResponseSchema = "inspr.janus.managed-dynamic-custody-response.v1"
	managedDynamicCustodySchemaVersion  = 1
	managedDynamicCustodyTimeout        = 35 * time.Second
)

type managedDynamicCustodyRequest struct {
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
}

type managedDynamicCustodyResponse struct {
	Schema        string  `json:"schema"`
	SchemaVersion int     `json:"schema_version"`
	OperationRef  *string `json:"operation_ref"`
	BindingRef    *string `json:"binding_ref"`
	SecretRef     *string `json:"secret_ref"`
	GenerationRef *string `json:"generation_ref"`
	Phase         string  `json:"phase"`
	ReasonCode    string  `json:"reason_code"`
	ExpectsValue  bool    `json:"expects_value"`
	ValueReturned bool    `json:"value_returned"`
}

type managedDynamicCustodyResult struct {
	OperationRef  string
	BindingRef    string
	SecretRef     string
	GenerationRef string
	Phase         string
	ReasonCode    string
	ValueReturned bool
}

type managedDynamicCustodyExecutor interface {
	Custody(context.Context, managedDynamicStepUpTarget, string, []byte) (managedDynamicCustodyResult, error)
	Recover(context.Context, managedDynamicStepUpTarget, string) (managedDynamicCustodyResult, error)
}

type managedDynamicCustodyClient struct {
	socketPath string
	dial       func(context.Context, string, string) (net.Conn, error)
	now        func() time.Time
}

func newManagedDynamicCustodyClient(socketPath string) *managedDynamicCustodyClient {
	dialer := &net.Dialer{Timeout: managedTransactionDialTimeout}
	return &managedDynamicCustodyClient{
		socketPath: socketPath,
		dial:       dialer.DialContext,
		now:        time.Now,
	}
}

func (client *managedDynamicCustodyClient) Custody(ctx context.Context, target managedDynamicStepUpTarget, operationRef string, value []byte) (managedDynamicCustodyResult, error) {
	if validateManagedDynamicValue(value) != nil {
		return managedDynamicCustodyResult{}, managedDynamicCustodyError("dynamic_custody_request_invalid")
	}
	return client.execute(ctx, target, operationRef, value, true)
}

func (client *managedDynamicCustodyClient) Recover(ctx context.Context, target managedDynamicStepUpTarget, operationRef string) (managedDynamicCustodyResult, error) {
	return client.execute(ctx, target, operationRef, nil, false)
}

func (client *managedDynamicCustodyClient) execute(ctx context.Context, target managedDynamicStepUpTarget, operationRef string, value []byte, allowValue bool) (managedDynamicCustodyResult, error) {
	request := managedDynamicCustodyRequest{
		Schema:                       managedDynamicCustodyRequestSchema,
		SchemaVersion:                managedDynamicCustodySchemaVersion,
		OperationRef:                 operationRef,
		OperationKind:                target.OperationKind,
		Source:                       target.Source,
		HostRef:                      target.HostRef,
		ServiceRef:                   target.ServiceRef,
		EnvironmentPolicyRef:         target.EnvironmentPolicyRef,
		EnvironmentPolicyFingerprint: target.EnvironmentPolicyFingerprint,
		DeclarationFingerprint:       target.DeclarationFingerprint,
		EnvironmentName:              target.EnvironmentName,
	}
	if validateManagedDynamicCustodyRequest(request) != nil || client == nil || !managedDynamicCleanAbsolutePath(client.socketPath) {
		return managedDynamicCustodyResult{}, managedDynamicCustodyError("dynamic_custody_request_invalid")
	}
	connection, err := client.dial(ctx, "unix", client.socketPath)
	if err != nil {
		return managedDynamicCustodyResult{}, managedDynamicCustodyError("dynamic_custody_unavailable")
	}
	defer connection.Close()
	deadline := client.now().Add(managedDynamicCustodyTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if connection.SetDeadline(deadline) != nil {
		return managedDynamicCustodyResult{}, managedDynamicCustodyError("dynamic_custody_unavailable")
	}
	header, err := json.Marshal(request)
	if err != nil || writeManagedTransactionFrame(connection, header) != nil {
		return managedDynamicCustodyResult{}, managedDynamicCustodyError("dynamic_custody_unavailable")
	}
	first, err := readManagedDynamicCustodyResponse(connection, request)
	if err != nil {
		return managedDynamicCustodyResult{}, err
	}
	if first.Phase == "custodied" {
		return managedDynamicCustodyResultFromResponse(first), nil
	}
	if !allowValue {
		return managedDynamicCustodyResult{}, managedDynamicCustodyError("dynamic_custody_not_found")
	}
	if first.Phase != "preflighted" || !first.ExpectsValue || first.BindingRef != nil || first.SecretRef != nil || first.GenerationRef != nil {
		return managedDynamicCustodyResult{}, managedDynamicCustodyError("dynamic_custody_protocol_invalid")
	}
	if writeManagedTransactionFrame(connection, value) != nil {
		return managedDynamicCustodyResult{}, managedDynamicCustodyError("dynamic_custody_unavailable")
	}
	final, err := readManagedDynamicCustodyResponse(connection, request)
	if err != nil {
		return managedDynamicCustodyResult{}, err
	}
	if final.Phase != "custodied" || final.ExpectsValue {
		return managedDynamicCustodyResult{}, managedDynamicCustodyError("dynamic_custody_incomplete")
	}
	return managedDynamicCustodyResultFromResponse(final), nil
}

func validateManagedDynamicCustodyRequest(request managedDynamicCustodyRequest) error {
	if request.Schema != managedDynamicCustodyRequestSchema ||
		request.SchemaVersion != managedDynamicCustodySchemaVersion ||
		!validManagedRef("op_", request.OperationRef) ||
		(request.OperationKind != "create" && request.OperationKind != "replace") ||
		!validManagedSource(request.Source) || request.Source == "remove" ||
		!validManagedRef("host_", request.HostRef) ||
		!validManagedRef("svc_", request.ServiceRef) ||
		!validManagedRef("envpol_", request.EnvironmentPolicyRef) ||
		!validManagedRef("envpf_", request.EnvironmentPolicyFingerprint) ||
		!validManagedRef("decl_", request.DeclarationFingerprint) ||
		!validManagedEnvironmentName(request.EnvironmentName) {
		return managedDynamicCustodyError("dynamic_custody_request_invalid")
	}
	return nil
}

func readManagedDynamicCustodyResponse(connection net.Conn, request managedDynamicCustodyRequest) (managedDynamicCustodyResponse, error) {
	body, err := readManagedTransactionFrame(connection)
	if err != nil {
		return managedDynamicCustodyResponse{}, managedDynamicCustodyError("dynamic_custody_unavailable")
	}
	var response managedDynamicCustodyResponse
	if len(body) == 0 || len(body) > managedTransactionMaxFrameBytes || decodeStrictJSON(body, &response) != nil ||
		response.Schema != managedDynamicCustodyResponseSchema ||
		response.SchemaVersion != managedDynamicCustodySchemaVersion ||
		response.ValueReturned || response.OperationRef == nil || *response.OperationRef != request.OperationRef ||
		!strings.HasPrefix(response.ReasonCode, "dynamic_custody_") {
		return managedDynamicCustodyResponse{}, managedDynamicCustodyError("dynamic_custody_protocol_invalid")
	}
	if response.Phase == "denied" {
		return managedDynamicCustodyResponse{}, managedDynamicCustodyError(response.ReasonCode)
	}
	if response.Phase == "custodied" {
		if response.BindingRef == nil || response.SecretRef == nil || response.GenerationRef == nil ||
			!validManagedRef("bind_", *response.BindingRef) || !validManagedRef("sec_", *response.SecretRef) || !validManagedRef("gen_", *response.GenerationRef) {
			return managedDynamicCustodyResponse{}, managedDynamicCustodyError("dynamic_custody_protocol_invalid")
		}
	} else if response.BindingRef != nil || response.SecretRef != nil || response.GenerationRef != nil {
		return managedDynamicCustodyResponse{}, managedDynamicCustodyError("dynamic_custody_protocol_invalid")
	}
	return response, nil
}

func managedDynamicCustodyResultFromResponse(response managedDynamicCustodyResponse) managedDynamicCustodyResult {
	return managedDynamicCustodyResult{
		OperationRef:  *response.OperationRef,
		BindingRef:    *response.BindingRef,
		SecretRef:     *response.SecretRef,
		GenerationRef: *response.GenerationRef,
		Phase:         response.Phase,
		ReasonCode:    response.ReasonCode,
		ValueReturned: false,
	}
}

func validateManagedDynamicCustodyResult(result managedDynamicCustodyResult, operationRef string) error {
	if result.OperationRef != operationRef || !validManagedRef("op_", result.OperationRef) ||
		!validManagedRef("bind_", result.BindingRef) || !validManagedRef("sec_", result.SecretRef) ||
		!validManagedRef("gen_", result.GenerationRef) || result.Phase != "custodied" ||
		result.ReasonCode != "dynamic_custody_stored" || result.ValueReturned {
		return managedDynamicCustodyError("dynamic_custody_result_invalid")
	}
	return nil
}

type managedDynamicCustodyError string

func (err managedDynamicCustodyError) Error() string { return string(err) }

func isManagedDynamicCustodyError(err error) bool {
	var custody managedDynamicCustodyError
	return errors.As(err, &custody)
}
