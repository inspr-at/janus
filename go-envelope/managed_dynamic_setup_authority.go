package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
)

const (
	managedDynamicIntentDenialSchema = "inspr.pharos.managed-environment-setup-intent-delivery.v2"
	managedDynamicSetupEndpoint      = "/internal/managed-environment-setup-intents/"
	managedDynamicSetupEnabledEnv    = "JANUS_MANAGED_DYNAMIC_SETUP_ENABLED"
	managedDynamicSetupOriginEnv     = "JANUS_MANAGED_DYNAMIC_SETUP_CONTROL_PLANE_ORIGIN"
	managedDynamicSetupTokenFileEnv  = "JANUS_MANAGED_DYNAMIC_SETUP_INTERNAL_TOKEN_FILE"
	managedDynamicSetupKeyFileEnv    = "JANUS_MANAGED_DYNAMIC_SETUP_VERIFICATION_KEYS_FILE"
	managedDynamicSetupPathsEnv      = "JANUS_MANAGED_DYNAMIC_SETUP_DECLARATION_PATHS"
	managedDynamicCustodySocketEnv   = "JANUS_MANAGED_DYNAMIC_CUSTODY_SOCKET"
	managedDynamicDeliverySocketEnv  = "JANUS_MANAGED_DYNAMIC_DELIVERY_SOCKET"
	managedDynamicTransportSocketEnv = "JANUS_MANAGED_DYNAMIC_TRANSPORT_SOCKET"
	managedDynamicHostTokensEnv      = "JANUS_MANAGED_DYNAMIC_HOST_TOKEN_GENERATION_DIR"
)

// managedDynamicSetupRuntimeConfig is a separate, explicit capability gate.
// Existing v1 managed setup configuration never enables the v2 route.
type managedDynamicSetupRuntimeConfig struct {
	ControlPlaneOrigin     string
	InternalToken          string
	Keyring                managedIntentKeyring
	DeclarationPaths       []string
	CustodySocket          string
	DeliverySocket         string
	TransportSocket        string
	HostTokenGenerationDir string
}

func loadManagedDynamicSetupRuntimeConfigFromEnv() (*managedDynamicSetupRuntimeConfig, error) {
	enabledRaw := strings.TrimSpace(os.Getenv(managedDynamicSetupEnabledEnv))
	origin := strings.TrimSpace(os.Getenv(managedDynamicSetupOriginEnv))
	tokenFile := strings.TrimSpace(os.Getenv(managedDynamicSetupTokenFileEnv))
	keyFile := strings.TrimSpace(os.Getenv(managedDynamicSetupKeyFileEnv))
	declarationRaw := strings.TrimSpace(os.Getenv(managedDynamicSetupPathsEnv))
	custodySocket := strings.TrimSpace(os.Getenv(managedDynamicCustodySocketEnv))
	deliverySocket := strings.TrimSpace(os.Getenv(managedDynamicDeliverySocketEnv))
	transportSocket := strings.TrimSpace(os.Getenv(managedDynamicTransportSocketEnv))
	hostTokenGenerationDir := strings.TrimSpace(os.Getenv(managedDynamicHostTokensEnv))

	enabled := false
	switch enabledRaw {
	case "", "false":
	case "true":
		enabled = true
	default:
		return nil, errors.New("managed dynamic setup enable flag is invalid")
	}
	configured := origin != "" || tokenFile != "" || keyFile != "" || declarationRaw != "" || custodySocket != "" || deliverySocket != "" || transportSocket != "" || hostTokenGenerationDir != ""
	if !enabled {
		if configured {
			return nil, errors.New("managed dynamic setup configuration requires the explicit enable flag")
		}
		return nil, nil
	}
	if origin == "" || tokenFile == "" || keyFile == "" || declarationRaw == "" || custodySocket == "" || deliverySocket == "" || transportSocket == "" || hostTokenGenerationDir == "" {
		return nil, errors.New("managed dynamic setup configuration is partial")
	}
	if !managedDynamicCleanAbsolutePath(tokenFile) || !managedDynamicCleanAbsolutePath(keyFile) || !managedDynamicCleanAbsolutePath(custodySocket) || !managedDynamicCleanAbsolutePath(deliverySocket) || !managedDynamicCleanAbsolutePath(transportSocket) || !managedDynamicCleanAbsolutePath(hostTokenGenerationDir) || custodySocket == deliverySocket || custodySocket == transportSocket || deliverySocket == transportSocket {
		return nil, errors.New("managed dynamic setup configuration file path is invalid")
	}
	parsedOrigin, err := parseManagedOrigin(origin)
	if err != nil || parsedOrigin.Scheme != "https" {
		return nil, errors.New("managed dynamic setup control-plane origin is invalid")
	}
	tokenBytes, err := readBoundedPrivateFile(tokenFile, managedInternalTokenMaxBytes)
	if err != nil {
		return nil, errors.New("managed dynamic setup internal token is unavailable")
	}
	token := strings.TrimSpace(string(tokenBytes))
	if len(token) < 32 || strings.IndexFunc(token, unicode.IsSpace) >= 0 {
		return nil, errors.New("managed dynamic setup internal token contract is invalid")
	}
	keyring, err := loadManagedIntentKeyring(keyFile)
	if err != nil {
		return nil, err
	}
	declarationPaths, err := parseManagedDynamicDeclarationPaths(declarationRaw)
	if err != nil {
		return nil, err
	}
	return &managedDynamicSetupRuntimeConfig{
		ControlPlaneOrigin:     parsedOrigin.String(),
		InternalToken:          token,
		Keyring:                keyring,
		DeclarationPaths:       declarationPaths,
		CustodySocket:          custodySocket,
		DeliverySocket:         deliverySocket,
		TransportSocket:        transportSocket,
		HostTokenGenerationDir: hostTokenGenerationDir,
	}, nil
}

func parseManagedDynamicDeclarationPaths(raw string) ([]string, error) {
	var paths []string
	for _, item := range strings.Split(raw, ",") {
		paths = append(paths, strings.TrimSpace(item))
	}
	if validateManagedDynamicDeclarationPaths(paths) != nil {
		return nil, errors.New("managed dynamic setup declaration path contract is invalid")
	}
	return paths, nil
}

func validateManagedDynamicDeclarationPaths(paths []string) error {
	if len(paths) == 0 || len(paths) > 64 {
		return errors.New("managed dynamic setup declaration path contract is invalid")
	}
	seen := map[string]bool{}
	for _, path := range paths {
		if !managedDynamicCleanAbsolutePath(path) || seen[path] {
			return errors.New("managed dynamic setup declaration path contract is invalid")
		}
		seen[path] = true
	}
	return nil
}

func managedDynamicCleanAbsolutePath(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path
}

type managedDynamicHTTPAuthority struct {
	fetcher  *managedHTTPIntentFetcher
	consumer managedDynamicSetupIntentConsumer
	replays  *managedDynamicReplayStore
}

func newManagedDynamicSetupAuthority(
	config managedDynamicSetupRuntimeConfig,
	dataDir string,
	transport http.RoundTripper,
) (*managedDynamicHTTPAuthority, error) {
	parsedOrigin, err := parseManagedOrigin(config.ControlPlaneOrigin)
	if err != nil || parsedOrigin.Scheme != "https" {
		return nil, errors.New("managed_dynamic_setup_config_invalid")
	}
	fetcher, err := newManagedHTTPIntentFetcher(config.ControlPlaneOrigin, config.InternalToken, transport)
	if err != nil {
		return nil, err
	}
	if len(config.Keyring) == 0 ||
		validateManagedDynamicDeclarationPaths(config.DeclarationPaths) != nil {
		return nil, errors.New("managed_dynamic_setup_config_invalid")
	}
	if _, err := loadManagedDynamicDeclarations(config.DeclarationPaths); err != nil {
		return nil, errors.New("managed_dynamic_setup_config_invalid")
	}
	replays, err := newManagedDynamicReplayStore(filepath.Join(dataDir, managedDynamicReplayStoreFile))
	if err != nil {
		return nil, err
	}
	return &managedDynamicHTTPAuthority{
		fetcher: fetcher,
		consumer: managedDynamicSetupIntentConsumer{
			keyring:     config.Keyring,
			declaration: managedDynamicDeclarationResolver{paths: append([]string(nil), config.DeclarationPaths...)},
			issuerRef:   managedSetupExpectedIssuerRef,
			audienceRef: managedSetupExpectedAudienceRef,
			now:         time.Now,
		},
		replays: replays,
	}, nil
}

func (authority *managedDynamicHTTPAuthority) Inspect(
	ctx context.Context,
	intentRef string,
	humanSessionRef string,
) (managedDynamicSetupInspection, error) {
	if authority == nil || authority.fetcher == nil || authority.consumer.declaration == nil {
		return managedDynamicSetupInspection{}, managedIntentError("managed_intent_internal_failure")
	}
	envelope, err := authority.fetcher.fetch(
		ctx,
		intentRef,
		managedDynamicSetupEndpoint,
		managedDynamicIntentDenialSchema,
		managedDynamicContractVersion,
	)
	if err != nil {
		return managedDynamicSetupInspection{}, normalizeManagedIntentError(err)
	}
	return authority.consumer.Inspect(envelope, intentRef, humanSessionRef)
}

func (authority *managedDynamicHTTPAuthority) Reserve(
	ctx context.Context,
	intentRef string,
	humanSessionRef string,
) (managedDynamicSetupReservation, error) {
	if authority == nil || authority.replays == nil {
		return managedDynamicSetupReservation{}, managedIntentError("managed_intent_internal_failure")
	}
	inspection, err := authority.Inspect(ctx, intentRef, humanSessionRef)
	if err != nil {
		return managedDynamicSetupReservation{}, err
	}
	operationRef, err := authority.replays.reserve(inspection.Intent, authority.consumer.now().Unix())
	if err != nil {
		return managedDynamicSetupReservation{}, normalizeManagedIntentError(err)
	}
	return managedDynamicSetupReservation{Inspection: inspection, OperationRef: operationRef}, nil
}

func (authority *managedDynamicHTTPAuthority) RecoverReservation(
	ctx context.Context,
	intentRef string,
	humanSessionRef string,
	operationRef string,
) (managedDynamicSetupReservation, error) {
	if authority == nil || authority.replays == nil || !validManagedRef("op_", operationRef) {
		return managedDynamicSetupReservation{}, managedIntentError("managed_intent_recovery_unavailable")
	}
	inspection, err := authority.Inspect(ctx, intentRef, humanSessionRef)
	if err != nil {
		return managedDynamicSetupReservation{}, err
	}
	record, err := authority.replays.recover(inspection.Intent, operationRef, authority.consumer.now().Unix())
	if err != nil {
		return managedDynamicSetupReservation{}, normalizeManagedIntentError(err)
	}
	return managedDynamicReservationFromRecord(inspection, record), nil
}

func (authority *managedDynamicHTTPAuthority) BeginValueAdmission(
	ctx context.Context,
	expected managedDynamicStepUpTarget,
	operationRef string,
) (managedDynamicSetupReservation, error) {
	return authority.updateValueAdmission(ctx, expected, operationRef, false)
}

func (authority *managedDynamicHTTPAuthority) CompleteValueAdmission(
	ctx context.Context,
	expected managedDynamicStepUpTarget,
	operationRef string,
	custody managedDynamicCustodyResult,
	delivery managedDynamicDeliveryResult,
) (managedDynamicSetupReservation, error) {
	if validateManagedDynamicCustodyResult(custody, operationRef) != nil || validateManagedDynamicDeliveryResult(delivery, operationRef) != nil {
		return managedDynamicSetupReservation{}, managedIntentError("managed_intent_value_admission_unavailable")
	}
	if authority == nil || authority.replays == nil || !validManagedDynamicStepUpTarget(expected) || !validManagedRef("op_", operationRef) {
		return managedDynamicSetupReservation{}, managedIntentError("managed_intent_value_admission_unavailable")
	}
	inspection, err := authority.Inspect(ctx, expected.IntentRef, expected.HumanSessionRef)
	if err != nil {
		return managedDynamicSetupReservation{}, err
	}
	if managedDynamicTargetFromInspection(inspection) != expected {
		return managedDynamicSetupReservation{}, managedIntentError("managed_intent_declaration_drift")
	}
	record, err := authority.replays.completeValueAdmission(inspection.Intent, operationRef, custody, delivery, authority.consumer.now().Unix())
	if err != nil {
		return managedDynamicSetupReservation{}, normalizeManagedIntentError(err)
	}
	return managedDynamicReservationFromRecord(inspection, record), nil
}

func (authority *managedDynamicHTTPAuthority) updateValueAdmission(
	ctx context.Context,
	expected managedDynamicStepUpTarget,
	operationRef string,
	complete bool,
) (managedDynamicSetupReservation, error) {
	if authority == nil || authority.replays == nil ||
		!validManagedDynamicStepUpTarget(expected) || !validManagedRef("op_", operationRef) {
		return managedDynamicSetupReservation{}, managedIntentError("managed_intent_value_admission_unavailable")
	}
	inspection, err := authority.Inspect(ctx, expected.IntentRef, expected.HumanSessionRef)
	if err != nil {
		return managedDynamicSetupReservation{}, err
	}
	if managedDynamicTargetFromInspection(inspection) != expected {
		return managedDynamicSetupReservation{}, managedIntentError("managed_intent_declaration_drift")
	}
	var record managedDynamicReplayRecord
	if complete {
		return managedDynamicSetupReservation{}, managedIntentError("managed_intent_value_admission_unavailable")
	} else {
		record, err = authority.replays.beginValueAdmission(inspection.Intent, operationRef, authority.consumer.now().Unix())
	}
	if err != nil {
		return managedDynamicSetupReservation{}, normalizeManagedIntentError(err)
	}
	return managedDynamicReservationFromRecord(inspection, record), nil
}

func managedDynamicReservationFromRecord(inspection managedDynamicSetupInspection, record managedDynamicReplayRecord) managedDynamicSetupReservation {
	return managedDynamicSetupReservation{
		Inspection:             inspection,
		OperationRef:           record.OperationRef,
		ValueAdmissionStarted:  record.ValueAdmissionStartedUnixSecond != 0,
		ValueAdmissionComplete: record.ValueAdmissionDoneUnixSecond != 0,
		BindingRef:             record.BindingRef,
		SecretRef:              record.SecretRef,
		GenerationRef:          record.GenerationRef,
		PackageRef:             record.PackageRef,
		EnvelopeRef:            record.EnvelopeRef,
	}
}
