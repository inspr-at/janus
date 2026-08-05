package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"time"
)

const (
	managedDynamicTransportRequestSchema  = "inspr.janus.managed-dynamic-transport-request.v4"
	managedDynamicTransportResponseSchema = "inspr.janus.managed-dynamic-transport-response.v4"
	managedDynamicTransportSchemaVersion  = 4
	managedDynamicTransportTimeout        = 10 * time.Second
	managedDynamicTransportMaxFrameBytes  = 768 * 1024
	managedDynamicTransportMaxPacketBytes = 256 * 1024
)

type managedDynamicTransportClaimRequest struct {
	Schema         string `json:"schema"`
	SchemaVersion  int    `json:"schema_version"`
	Action         string `json:"action"`
	HostRef        string `json:"host_ref"`
	PacketReturned bool   `json:"packet_returned"`
	ValueReturned  bool   `json:"value_returned"`
}

type managedDynamicTransportAcknowledgeRequest struct {
	Schema        string                         `json:"schema"`
	SchemaVersion int                            `json:"schema_version"`
	Action        string                         `json:"action"`
	Receipt       managedDynamicTransportReceipt `json:"receipt"`
}

type managedDynamicTransportStatusRequest struct {
	Schema        string                             `json:"schema"`
	SchemaVersion int                                `json:"schema_version"`
	Action        string                             `json:"action"`
	Query         managedDynamicTransportStatusQuery `json:"query"`
}

type managedDynamicTransportStatusQuery struct {
	HostRef              string `json:"host_ref"`
	ServiceRef           string `json:"service_ref"`
	EnvironmentPolicyRef string `json:"environment_policy_ref"`
	OperationRef         string `json:"operation_ref"`
	OperationKind        string `json:"operation_kind"`
	PackageRef           string `json:"package_ref"`
	EnvelopeRef          string `json:"envelope_ref"`
	BindingRef           string `json:"binding_ref"`
	GenerationRef        string `json:"generation_ref"`
	ReloadProfileRef     string `json:"reload_profile_ref"`
	HealthProfileRef     string `json:"health_profile_ref"`
	PacketReturned       bool   `json:"packet_returned"`
	ValueReturned        bool   `json:"value_returned"`
}

type managedDynamicTransportReceipt struct {
	HostRef                     string `json:"host_ref"`
	ServiceRef                  string `json:"service_ref"`
	EnvironmentPolicyRef        string `json:"environment_policy_ref"`
	OperationRef                string `json:"operation_ref"`
	OperationKind               string `json:"operation_kind"`
	PackageRef                  string `json:"package_ref"`
	EnvelopeRef                 string `json:"envelope_ref"`
	BindingRef                  string `json:"binding_ref"`
	GenerationRef               string `json:"generation_ref"`
	ReloadProfileRef            string `json:"reload_profile_ref"`
	HealthProfileRef            string `json:"health_profile_ref"`
	Phase                       string `json:"phase"`
	ReasonCode                  string `json:"reason_code"`
	MaterializationReasonCode   string `json:"materialization_reason_code"`
	FailureReasonCode           string `json:"failure_reason_code,omitempty"`
	RestoredBindingRef          string `json:"restored_binding_ref,omitempty"`
	RestoredGenerationRef       string `json:"restored_generation_ref,omitempty"`
	MaterializedAtUnixSecs      int64  `json:"materialized_at_unix_secs"`
	ReloadedAtUnixSecs          int64  `json:"reloaded_at_unix_secs"`
	HeartbeatObservedAtUnixSecs int64  `json:"heartbeat_observed_at_unix_secs"`
	ProcessObservedAtUnixSecs   int64  `json:"process_observed_at_unix_secs"`
	ProbeObservedAtUnixSecs     int64  `json:"probe_observed_at_unix_secs"`
	PacketReturned              bool   `json:"packet_returned"`
	ValueReturned               bool   `json:"value_returned"`
}

type managedDynamicTransportResponse struct {
	Schema               string  `json:"schema"`
	SchemaVersion        int     `json:"schema_version"`
	Action               string  `json:"action"`
	HostRef              *string `json:"host_ref"`
	ServiceRef           *string `json:"service_ref"`
	EnvironmentPolicyRef *string `json:"environment_policy_ref"`
	OperationRef         *string `json:"operation_ref"`
	OperationKind        *string `json:"operation_kind"`
	PackageRef           *string `json:"package_ref"`
	EnvelopeRef          *string `json:"envelope_ref"`
	BindingRef           *string `json:"binding_ref"`
	GenerationRef        *string `json:"generation_ref"`
	ReloadProfileRef     *string `json:"reload_profile_ref"`
	HealthProfileRef     *string `json:"health_profile_ref"`
	PacketBase64         *string `json:"packet_base64"`
	Phase                string  `json:"phase"`
	ReasonCode           string  `json:"reason_code"`
	PacketReturned       bool    `json:"packet_returned"`
	ValueReturned        bool    `json:"value_returned"`
}

type managedDynamicPackageClaim struct {
	HostRef              string
	ServiceRef           string
	EnvironmentPolicyRef string
	OperationRef         string
	OperationKind        string
	PackageRef           string
	EnvelopeRef          string
	BindingRef           string
	GenerationRef        string
	ReloadProfileRef     string
	HealthProfileRef     string
	Packet               []byte
}

type managedDynamicActivationReceipt struct {
	HostRef                     string
	ServiceRef                  string
	EnvironmentPolicyRef        string
	OperationRef                string
	OperationKind               string
	PackageRef                  string
	EnvelopeRef                 string
	BindingRef                  string
	GenerationRef               string
	ReloadProfileRef            string
	HealthProfileRef            string
	Phase                       string
	ReasonCode                  string
	MaterializationReasonCode   string
	FailureReasonCode           string
	RestoredBindingRef          string
	RestoredGenerationRef       string
	MaterializedAtUnixSecs      int64
	ReloadedAtUnixSecs          int64
	HeartbeatObservedAtUnixSecs int64
	ProcessObservedAtUnixSecs   int64
	ProbeObservedAtUnixSecs     int64
}

type managedDynamicActivationQuery struct {
	HostRef              string
	ServiceRef           string
	EnvironmentPolicyRef string
	OperationRef         string
	OperationKind        string
	PackageRef           string
	EnvelopeRef          string
	BindingRef           string
	GenerationRef        string
	ReloadProfileRef     string
	HealthProfileRef     string
}

type managedDynamicActivationStatus string

const (
	managedDynamicActivationPending    managedDynamicActivationStatus = "pending"
	managedDynamicActivationActive     managedDynamicActivationStatus = "active"
	managedDynamicActivationRemoved    managedDynamicActivationStatus = "removed"
	managedDynamicActivationExpired    managedDynamicActivationStatus = "expired"
	managedDynamicActivationRolledBack managedDynamicActivationStatus = "rolled_back"
)

type managedDynamicTransportExecutor interface {
	Claim(context.Context, string) (*managedDynamicPackageClaim, error)
	Acknowledge(context.Context, managedDynamicActivationReceipt) error
	Status(context.Context, managedDynamicActivationQuery) (managedDynamicActivationStatus, error)
}

type managedDynamicTransportClient struct {
	socketPath string
	dial       func(context.Context, string, string) (net.Conn, error)
	now        func() time.Time
}

func newManagedDynamicTransportClient(socketPath string) *managedDynamicTransportClient {
	dialer := &net.Dialer{Timeout: managedTransactionDialTimeout}
	return &managedDynamicTransportClient{socketPath: socketPath, dial: dialer.DialContext, now: time.Now}
}

func (client *managedDynamicTransportClient) Claim(ctx context.Context, hostRef string) (*managedDynamicPackageClaim, error) {
	if client == nil || !managedDynamicCleanAbsolutePath(client.socketPath) || !validManagedRef("host_", hostRef) {
		return nil, errors.New("dynamic_transport_request_invalid")
	}
	response, err := client.request(ctx, managedDynamicTransportClaimRequest{
		Schema: managedDynamicTransportRequestSchema, SchemaVersion: managedDynamicTransportSchemaVersion,
		Action: "claim", HostRef: hostRef, PacketReturned: false, ValueReturned: false,
	})
	if err != nil {
		return nil, err
	}
	if response.Action != "claim" || response.ValueReturned || !strings.HasPrefix(response.ReasonCode, "dynamic_transport_") {
		return nil, errors.New("dynamic_transport_protocol_invalid")
	}
	if response.Phase == "empty" && response.ReasonCode == "dynamic_transport_no_package" && !response.PacketReturned && response.HostRef != nil && *response.HostRef == hostRef && response.ServiceRef == nil && response.EnvironmentPolicyRef == nil && response.OperationRef == nil && response.OperationKind == nil && response.PackageRef == nil && response.EnvelopeRef == nil && response.BindingRef == nil && response.GenerationRef == nil && response.ReloadProfileRef == nil && response.HealthProfileRef == nil && response.PacketBase64 == nil {
		return nil, nil
	}
	if response.Phase != "claimed" || response.ReasonCode != "dynamic_transport_package_claimed" || !response.PacketReturned || response.PacketBase64 == nil || response.HostRef == nil || *response.HostRef != hostRef || response.ServiceRef == nil || response.EnvironmentPolicyRef == nil || response.OperationRef == nil || response.OperationKind == nil || response.PackageRef == nil || response.EnvelopeRef == nil || response.BindingRef == nil || response.GenerationRef == nil || response.ReloadProfileRef == nil || response.HealthProfileRef == nil ||
		(*response.OperationKind != "create" && *response.OperationKind != "replace" && *response.OperationKind != "remove") ||
		!validManagedRef("svc_", *response.ServiceRef) || !validManagedRef("envpol_", *response.EnvironmentPolicyRef) || !validManagedRef("op_", *response.OperationRef) || !validManagedRef("pkg_", *response.PackageRef) || !validManagedRef("env_", *response.EnvelopeRef) || !validManagedRef("bind_", *response.BindingRef) || !validManagedRef("gen_", *response.GenerationRef) || !validManagedRef("reload_", *response.ReloadProfileRef) || !validManagedRef("health_", *response.HealthProfileRef) {
		return nil, errors.New("dynamic_transport_protocol_invalid")
	}
	packet, err := base64.RawStdEncoding.DecodeString(*response.PacketBase64)
	if err != nil || len(packet) == 0 || len(packet) > managedDynamicTransportMaxPacketBytes {
		return nil, errors.New("dynamic_transport_protocol_invalid")
	}
	return &managedDynamicPackageClaim{
		HostRef: hostRef, ServiceRef: *response.ServiceRef, EnvironmentPolicyRef: *response.EnvironmentPolicyRef,
		OperationRef: *response.OperationRef, OperationKind: *response.OperationKind, PackageRef: *response.PackageRef, EnvelopeRef: *response.EnvelopeRef,
		BindingRef: *response.BindingRef, GenerationRef: *response.GenerationRef,
		ReloadProfileRef: *response.ReloadProfileRef, HealthProfileRef: *response.HealthProfileRef, Packet: packet,
	}, nil
}

func (client *managedDynamicTransportClient) Acknowledge(ctx context.Context, receipt managedDynamicActivationReceipt) error {
	request := managedDynamicTransportAcknowledgeRequest{
		Schema: managedDynamicTransportRequestSchema, SchemaVersion: managedDynamicTransportSchemaVersion,
		Action: "acknowledge",
		Receipt: managedDynamicTransportReceipt{
			HostRef: receipt.HostRef, ServiceRef: receipt.ServiceRef,
			EnvironmentPolicyRef: receipt.EnvironmentPolicyRef, OperationRef: receipt.OperationRef, OperationKind: receipt.OperationKind,
			PackageRef: receipt.PackageRef, EnvelopeRef: receipt.EnvelopeRef, BindingRef: receipt.BindingRef,
			GenerationRef: receipt.GenerationRef, ReloadProfileRef: receipt.ReloadProfileRef,
			HealthProfileRef: receipt.HealthProfileRef, Phase: receipt.Phase, ReasonCode: receipt.ReasonCode,
			MaterializationReasonCode: receipt.MaterializationReasonCode,
			FailureReasonCode:         receipt.FailureReasonCode, RestoredBindingRef: receipt.RestoredBindingRef,
			RestoredGenerationRef:  receipt.RestoredGenerationRef,
			MaterializedAtUnixSecs: receipt.MaterializedAtUnixSecs, ReloadedAtUnixSecs: receipt.ReloadedAtUnixSecs,
			HeartbeatObservedAtUnixSecs: receipt.HeartbeatObservedAtUnixSecs,
			ProcessObservedAtUnixSecs:   receipt.ProcessObservedAtUnixSecs,
			ProbeObservedAtUnixSecs:     receipt.ProbeObservedAtUnixSecs,
			PacketReturned:              false, ValueReturned: false,
		},
	}
	if client == nil || !managedDynamicCleanAbsolutePath(client.socketPath) || validateManagedDynamicActivationReceipt(receipt) != nil {
		return errors.New("dynamic_transport_request_invalid")
	}
	response, err := client.request(ctx, request)
	if err != nil {
		return err
	}
	if response.Action != "acknowledge" || response.Phase != receipt.Phase || response.ReasonCode != "dynamic_transport_receipt_recorded" || response.PacketReturned || response.ValueReturned || response.PacketBase64 != nil ||
		response.HostRef == nil || *response.HostRef != receipt.HostRef || response.ServiceRef == nil || *response.ServiceRef != receipt.ServiceRef || response.EnvironmentPolicyRef == nil || *response.EnvironmentPolicyRef != receipt.EnvironmentPolicyRef || response.OperationRef == nil || *response.OperationRef != receipt.OperationRef || response.OperationKind == nil || *response.OperationKind != receipt.OperationKind || response.PackageRef == nil || *response.PackageRef != receipt.PackageRef || response.EnvelopeRef == nil || *response.EnvelopeRef != receipt.EnvelopeRef || response.BindingRef == nil || *response.BindingRef != receipt.BindingRef || response.GenerationRef == nil || *response.GenerationRef != receipt.GenerationRef || response.ReloadProfileRef == nil || *response.ReloadProfileRef != receipt.ReloadProfileRef || response.HealthProfileRef == nil || *response.HealthProfileRef != receipt.HealthProfileRef {
		return errors.New("dynamic_transport_protocol_invalid")
	}
	return nil
}

func (client *managedDynamicTransportClient) Status(ctx context.Context, query managedDynamicActivationQuery) (managedDynamicActivationStatus, error) {
	if client == nil || !managedDynamicCleanAbsolutePath(client.socketPath) || validateManagedDynamicActivationQuery(query) != nil {
		return "", errors.New("dynamic_transport_request_invalid")
	}
	response, err := client.request(ctx, managedDynamicTransportStatusRequest{
		Schema: managedDynamicTransportRequestSchema, SchemaVersion: managedDynamicTransportSchemaVersion,
		Action: "status",
		Query: managedDynamicTransportStatusQuery{
			HostRef: query.HostRef, ServiceRef: query.ServiceRef,
			EnvironmentPolicyRef: query.EnvironmentPolicyRef, OperationRef: query.OperationRef, OperationKind: query.OperationKind,
			PackageRef: query.PackageRef, EnvelopeRef: query.EnvelopeRef, BindingRef: query.BindingRef,
			GenerationRef: query.GenerationRef, ReloadProfileRef: query.ReloadProfileRef,
			HealthProfileRef: query.HealthProfileRef, PacketReturned: false, ValueReturned: false,
		},
	})
	if err != nil {
		return "", err
	}
	if response.Action != "status" || response.PacketReturned || response.ValueReturned || response.PacketBase64 != nil ||
		response.HostRef == nil || *response.HostRef != query.HostRef || response.ServiceRef == nil || *response.ServiceRef != query.ServiceRef || response.EnvironmentPolicyRef == nil || *response.EnvironmentPolicyRef != query.EnvironmentPolicyRef || response.OperationRef == nil || *response.OperationRef != query.OperationRef || response.OperationKind == nil || *response.OperationKind != query.OperationKind || response.PackageRef == nil || *response.PackageRef != query.PackageRef || response.EnvelopeRef == nil || *response.EnvelopeRef != query.EnvelopeRef || response.BindingRef == nil || *response.BindingRef != query.BindingRef || response.GenerationRef == nil || *response.GenerationRef != query.GenerationRef || response.ReloadProfileRef == nil || *response.ReloadProfileRef != query.ReloadProfileRef || response.HealthProfileRef == nil || *response.HealthProfileRef != query.HealthProfileRef {
		return "", errors.New("dynamic_transport_protocol_invalid")
	}
	switch {
	case response.Phase == "pending" && response.ReasonCode == "dynamic_transport_activation_pending":
		return managedDynamicActivationPending, nil
	case response.Phase == "active" && response.ReasonCode == "dynamic_transport_environment_active":
		return managedDynamicActivationActive, nil
	case query.OperationKind == "remove" && response.Phase == "removed" && response.ReasonCode == "dynamic_transport_environment_removed":
		return managedDynamicActivationRemoved, nil
	case response.Phase == "expired" && response.ReasonCode == "dynamic_transport_package_expired":
		return managedDynamicActivationExpired, nil
	case query.OperationKind == "replace" && response.Phase == "rolled_back" && response.ReasonCode == "dynamic_transport_replacement_rolled_back":
		return managedDynamicActivationRolledBack, nil
	case query.OperationKind == "remove" && response.Phase == "rolled_back" && response.ReasonCode == "dynamic_transport_removal_rolled_back":
		return managedDynamicActivationRolledBack, nil
	default:
		return "", errors.New("dynamic_transport_protocol_invalid")
	}
}

func (client *managedDynamicTransportClient) request(ctx context.Context, request any) (managedDynamicTransportResponse, error) {
	connection, err := client.dial(ctx, "unix", client.socketPath)
	if err != nil {
		return managedDynamicTransportResponse{}, errors.New("dynamic_transport_unavailable")
	}
	defer connection.Close()
	deadline := client.now().Add(managedDynamicTransportTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if connection.SetDeadline(deadline) != nil {
		return managedDynamicTransportResponse{}, errors.New("dynamic_transport_unavailable")
	}
	body, err := json.Marshal(request)
	if err != nil || writeManagedTransactionFrame(connection, body) != nil {
		return managedDynamicTransportResponse{}, errors.New("dynamic_transport_unavailable")
	}
	responseBody, err := readManagedTransactionFrameBounded(connection, managedDynamicTransportMaxFrameBytes)
	if err != nil || len(responseBody) == 0 || len(responseBody) > managedDynamicTransportMaxFrameBytes {
		return managedDynamicTransportResponse{}, errors.New("dynamic_transport_unavailable")
	}
	var response managedDynamicTransportResponse
	if decodeStrictJSON(responseBody, &response) != nil || response.Schema != managedDynamicTransportResponseSchema || response.SchemaVersion != managedDynamicTransportSchemaVersion || response.Phase == "denied" {
		return managedDynamicTransportResponse{}, errors.New("dynamic_transport_denied")
	}
	return response, nil
}

func validateManagedDynamicActivationReceipt(receipt managedDynamicActivationReceipt) error {
	materializationValid := (receipt.OperationKind == "create" && (receipt.MaterializationReasonCode == "dynamic_host_environment_materialized" || receipt.MaterializationReasonCode == "dynamic_host_materialization_idempotent")) ||
		(receipt.OperationKind == "replace" && (receipt.MaterializationReasonCode == "dynamic_host_replacement_materialized" || receipt.MaterializationReasonCode == "dynamic_host_materialization_idempotent")) ||
		(receipt.OperationKind == "remove" && receipt.MaterializationReasonCode == "dynamic_host_removal_materialized")
	outcomeValid := (receipt.Phase == "active" && receipt.OperationKind != "remove" && receipt.ReasonCode == "dynamic_host_environment_active" && receipt.FailureReasonCode == "" && receipt.RestoredBindingRef == "" && receipt.RestoredGenerationRef == "") ||
		(receipt.Phase == "removed" && receipt.OperationKind == "remove" && receipt.ReasonCode == "dynamic_host_environment_removed" && receipt.FailureReasonCode == "" && receipt.RestoredBindingRef == "" && receipt.RestoredGenerationRef == "") ||
		(receipt.Phase == "rolled_back" && (receipt.OperationKind == "replace" || receipt.OperationKind == "remove") && ((receipt.OperationKind == "replace" && receipt.ReasonCode == "dynamic_host_replacement_rolled_back") || (receipt.OperationKind == "remove" && receipt.ReasonCode == "dynamic_host_removal_rolled_back")) && (receipt.FailureReasonCode == "dynamic_host_reload_failed" || receipt.FailureReasonCode == "dynamic_host_health_failed") && validManagedRef("bind_", receipt.RestoredBindingRef) && validManagedRef("gen_", receipt.RestoredGenerationRef) && ((receipt.OperationKind == "replace" && receipt.RestoredBindingRef != receipt.BindingRef && receipt.RestoredGenerationRef != receipt.GenerationRef) || (receipt.OperationKind == "remove" && receipt.RestoredBindingRef == receipt.BindingRef && receipt.RestoredGenerationRef == receipt.GenerationRef)))
	if !validManagedRef("host_", receipt.HostRef) || !validManagedRef("svc_", receipt.ServiceRef) || !validManagedRef("envpol_", receipt.EnvironmentPolicyRef) || !validManagedRef("op_", receipt.OperationRef) || (receipt.OperationKind != "create" && receipt.OperationKind != "replace" && receipt.OperationKind != "remove") || !validManagedRef("pkg_", receipt.PackageRef) || !validManagedRef("env_", receipt.EnvelopeRef) || !validManagedRef("bind_", receipt.BindingRef) || !validManagedRef("gen_", receipt.GenerationRef) || !validManagedRef("reload_", receipt.ReloadProfileRef) || !validManagedRef("health_", receipt.HealthProfileRef) || !materializationValid || !outcomeValid || receipt.MaterializedAtUnixSecs <= 0 || receipt.ReloadedAtUnixSecs < receipt.MaterializedAtUnixSecs || receipt.HeartbeatObservedAtUnixSecs < receipt.ReloadedAtUnixSecs || receipt.ProcessObservedAtUnixSecs < receipt.ReloadedAtUnixSecs || receipt.ProbeObservedAtUnixSecs < receipt.ReloadedAtUnixSecs {
		return errors.New("dynamic_transport_receipt_invalid")
	}
	return nil
}

func validateManagedDynamicActivationQuery(query managedDynamicActivationQuery) error {
	if !validManagedRef("host_", query.HostRef) || !validManagedRef("svc_", query.ServiceRef) || !validManagedRef("envpol_", query.EnvironmentPolicyRef) || !validManagedRef("op_", query.OperationRef) || (query.OperationKind != "create" && query.OperationKind != "replace" && query.OperationKind != "remove") || !validManagedRef("pkg_", query.PackageRef) || !validManagedRef("env_", query.EnvelopeRef) || !validManagedRef("bind_", query.BindingRef) || !validManagedRef("gen_", query.GenerationRef) || !validManagedRef("reload_", query.ReloadProfileRef) || !validManagedRef("health_", query.HealthProfileRef) {
		return errors.New("dynamic_transport_status_invalid")
	}
	return nil
}
