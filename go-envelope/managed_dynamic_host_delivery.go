package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"strings"
)

const (
	managedDynamicHostClaimSchema   = "inspr.janus.managed-dynamic-host-package-claim.v1"
	managedDynamicHostReceiptSchema = "inspr.janus.managed-dynamic-host-receipt-submission.v1"
	managedDynamicHostMaxBytes      = int64(32 * 1024)
)

type managedDynamicHostClaimResponse struct {
	Schema               string `json:"schema"`
	SchemaVersion        int    `json:"schema_version"`
	HostRef              string `json:"host_ref"`
	ServiceRef           string `json:"service_ref"`
	EnvironmentPolicyRef string `json:"environment_policy_ref"`
	OperationRef         string `json:"operation_ref"`
	PackageRef           string `json:"package_ref"`
	EnvelopeRef          string `json:"envelope_ref"`
	BindingRef           string `json:"binding_ref"`
	GenerationRef        string `json:"generation_ref"`
	PacketBase64         string `json:"packet_base64"`
	Phase                string `json:"phase"`
	ReasonCode           string `json:"reason_code"`
	PacketReturned       bool   `json:"packet_returned"`
	ValueReturned        bool   `json:"value_returned"`
}

type managedDynamicHostReceiptRequest struct {
	Schema               string `json:"schema"`
	SchemaVersion        int    `json:"schema_version"`
	HostRef              string `json:"host_ref"`
	ServiceRef           string `json:"service_ref"`
	EnvironmentPolicyRef string `json:"environment_policy_ref"`
	OperationRef         string `json:"operation_ref"`
	PackageRef           string `json:"package_ref"`
	EnvelopeRef          string `json:"envelope_ref"`
	BindingRef           string `json:"binding_ref"`
	GenerationRef        string `json:"generation_ref"`
	Phase                string `json:"phase"`
	ReasonCode           string `json:"reason_code"`
	ObservedAtUnixSecs   int64  `json:"observed_at_unix_secs"`
	PacketReturned       bool   `json:"packet_returned"`
	ValueReturned        bool   `json:"value_returned"`
}

func (app *App) handleManagedDynamicHostPackage(w http.ResponseWriter, r *http.Request) {
	managedSecretResponseBoundary(w)
	hostRef := r.PathValue("hostRef")
	token, ok := exactBearerToken(r)
	if app.managedDynamicTransport == nil || app.managedDynamicHostTokens == nil {
		app.renderSafeFailure(w, r, http.StatusNotFound, "dynamic_transport_unavailable", "Dynamic host delivery is unavailable.", nil)
		return
	}
	if r.URL.RawQuery != "" || !ok || !validManagedRef("host_", hostRef) || !app.managedDynamicHostTokens.authorized(hostRef, token) {
		app.renderSafeFailure(w, r, http.StatusUnauthorized, "dynamic_transport_host_denied", "Dynamic host delivery was denied.", nil)
		return
	}
	claim, err := app.managedDynamicTransport.Claim(r.Context(), hostRef)
	if err != nil {
		app.renderSafeFailure(w, r, http.StatusServiceUnavailable, "dynamic_transport_unavailable", "Dynamic host delivery is unavailable.", nil)
		return
	}
	if claim == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	response := managedDynamicHostClaimResponse{
		Schema: managedDynamicHostClaimSchema, SchemaVersion: 1,
		HostRef: claim.HostRef, ServiceRef: claim.ServiceRef, EnvironmentPolicyRef: claim.EnvironmentPolicyRef,
		OperationRef: claim.OperationRef, PackageRef: claim.PackageRef, EnvelopeRef: claim.EnvelopeRef,
		BindingRef: claim.BindingRef, GenerationRef: claim.GenerationRef,
		PacketBase64: base64Raw(claim.Packet), Phase: "claimed", ReasonCode: "dynamic_transport_package_claimed",
		PacketReturned: true, ValueReturned: false,
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = json.NewEncoder(w).Encode(response)
}

func (app *App) handleManagedDynamicHostReceipt(w http.ResponseWriter, r *http.Request) {
	managedSecretResponseBoundary(w)
	hostRef := r.PathValue("hostRef")
	operationRef := r.PathValue("operationRef")
	token, ok := exactBearerToken(r)
	if app.managedDynamicTransport == nil || app.managedDynamicHostTokens == nil {
		app.renderSafeFailure(w, r, http.StatusNotFound, "dynamic_transport_unavailable", "Dynamic host evidence is unavailable.", nil)
		return
	}
	if r.URL.RawQuery != "" || r.Body == nil || len(r.TransferEncoding) != 0 || r.ContentLength <= 0 || r.ContentLength > managedDynamicHostMaxBytes || !ok || !validManagedRef("host_", hostRef) || !validManagedRef("op_", operationRef) || !app.managedDynamicHostTokens.authorized(hostRef, token) {
		app.renderSafeFailure(w, r, http.StatusUnauthorized, "dynamic_transport_receipt_denied", "Dynamic host evidence was denied.", nil)
		return
	}
	mediaType, parameters, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || len(parameters) != 0 {
		app.renderSafeFailure(w, r, http.StatusBadRequest, "dynamic_transport_receipt_invalid", "Dynamic host evidence was invalid.", nil)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, managedDynamicHostMaxBytes+1))
	if err != nil || int64(len(raw)) > managedDynamicHostMaxBytes || !requestBodyAtEOF(r.Body) {
		app.renderSafeFailure(w, r, http.StatusBadRequest, "dynamic_transport_receipt_invalid", "Dynamic host evidence was invalid.", nil)
		return
	}
	var request managedDynamicHostReceiptRequest
	if decodeStrictJSON(raw, &request) != nil || request.Schema != managedDynamicHostReceiptSchema || request.SchemaVersion != 1 || request.HostRef != hostRef || request.OperationRef != operationRef || request.PacketReturned || request.ValueReturned {
		app.renderSafeFailure(w, r, http.StatusBadRequest, "dynamic_transport_receipt_invalid", "Dynamic host evidence was invalid.", nil)
		return
	}
	receipt := managedDynamicMaterializationReceipt{
		HostRef: request.HostRef, ServiceRef: request.ServiceRef, EnvironmentPolicyRef: request.EnvironmentPolicyRef,
		OperationRef: request.OperationRef, PackageRef: request.PackageRef, EnvelopeRef: request.EnvelopeRef,
		BindingRef: request.BindingRef, GenerationRef: request.GenerationRef, Phase: request.Phase,
		ReasonCode: request.ReasonCode, ObservedAtUnixSecs: request.ObservedAtUnixSecs,
	}
	if validateManagedDynamicMaterializationReceipt(receipt) != nil {
		app.renderSafeFailure(w, r, http.StatusBadRequest, "dynamic_transport_receipt_invalid", "Dynamic host evidence was invalid.", nil)
		return
	}
	if err := app.managedDynamicTransport.Acknowledge(r.Context(), receipt); err != nil {
		app.renderSafeFailure(w, r, http.StatusServiceUnavailable, "dynamic_transport_receipt_unavailable", "Dynamic host evidence could not be recorded.", nil)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func managedDynamicHostPackagePath(path string) bool {
	rest, ok := strings.CutPrefix(path, "/internal/managed-environment-host-packages/")
	return ok && !strings.Contains(rest, "/") && validManagedRef("host_", rest)
}

func managedDynamicHostReceiptPath(path string) bool {
	rest, ok := strings.CutPrefix(path, "/internal/managed-environment-host-packages/")
	if !ok {
		return false
	}
	parts := strings.Split(rest, "/")
	return len(parts) == 3 && validManagedRef("host_", parts[0]) && validManagedRef("op_", parts[1]) && parts[2] == "receipt"
}

func base64Raw(value []byte) string {
	return base64.RawStdEncoding.EncodeToString(value)
}
