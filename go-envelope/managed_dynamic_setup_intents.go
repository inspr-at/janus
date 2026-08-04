package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"sort"
	"time"
)

const (
	managedDynamicSignedIntentSchema    = "inspr.janus.signed-managed-environment-setup-intent.v2"
	managedDynamicSetupIntentSchema     = "inspr.janus.managed-environment-setup-intent.v2"
	managedDynamicDeclarationSchema     = "inspr.janus.managed-service-declaration.v2"
	managedDynamicIntentSignatureDomain = "inspr.janus.signed-managed-environment-setup-intent.v2"
	managedDynamicContractVersion       = 2
	managedDynamicMaximumBindings       = 64
	managedDynamicMaximumReservedNames  = 64
)

// managedDynamicSetupIntent is deliberately value-free. The signed control
// plane handoff fixes every authority-bearing choice before a later boundary
// is allowed to ask the human for a secret value.
type managedDynamicSetupIntent struct {
	Schema                       string `json:"schema"`
	SchemaVersion                int    `json:"schema_version"`
	IntentRef                    string `json:"intent_ref"`
	OperationKind                string `json:"operation_kind"`
	Source                       string `json:"source"`
	HostRef                      string `json:"host_ref"`
	ServiceRef                   string `json:"service_ref"`
	EnvironmentPolicyRef         string `json:"environment_policy_ref"`
	EnvironmentPolicyFingerprint string `json:"environment_policy_fingerprint"`
	DeclarationFingerprint       string `json:"declaration_fingerprint"`
	EnvironmentName              string `json:"environment_name"`
	HumanSessionRef              string `json:"human_session_ref"`
	IssuerRef                    string `json:"issuer_ref"`
	AudienceRef                  string `json:"audience_ref"`
	NonceRef                     string `json:"nonce_ref"`
	IssuedAtUnixSeconds          int64  `json:"issued_at_unix_secs"`
	ExpiresAtUnixSeconds         int64  `json:"expires_at_unix_secs"`
	ReturnTarget                 string `json:"return_target"`
}

type managedDynamicDeclaration struct {
	Schema                   string                           `json:"schema"`
	SchemaVersion            int                              `json:"schema_version"`
	HostRef                  string                           `json:"host_ref"`
	ServiceRef               string                           `json:"service_ref"`
	DeclarationFingerprint   string                           `json:"declaration_fingerprint"`
	Slots                    []managedDynamicDeclarationSlot  `json:"slots"`
	DynamicEnvironmentPolicy *managedDynamicEnvironmentPolicy `json:"dynamic_environment_policy"`
}

type managedDynamicDeclarationSlot struct {
	SlotRef            string   `json:"slot_ref"`
	SafeLabel          string   `json:"safe_label"`
	ConsumerKind       string   `json:"consumer_kind"`
	DeliveryKind       string   `json:"delivery_kind"`
	DeliveryProfileRef string   `json:"delivery_profile_ref"`
	ReloadProfileRef   string   `json:"reload_profile_ref"`
	HealthProfileRef   string   `json:"health_profile_ref"`
	AllowedSources     []string `json:"allowed_sources"`
}

type managedDynamicEnvironmentPolicy struct {
	EnvironmentPolicyRef         string   `json:"environment_policy_ref"`
	EnvironmentPolicyFingerprint string   `json:"environment_policy_fingerprint"`
	ConsumerKind                 string   `json:"consumer_kind"`
	DeliveryKind                 string   `json:"delivery_kind"`
	DeliveryProfileRef           string   `json:"delivery_profile_ref"`
	ReloadProfileRef             string   `json:"reload_profile_ref"`
	HealthProfileRef             string   `json:"health_profile_ref"`
	AllowedSources               []string `json:"allowed_sources"`
	NamePolicy                   string   `json:"name_policy"`
	MaxActiveBindings            int      `json:"max_active_bindings"`
	AdditionalReservedNames      []string `json:"additional_reserved_names"`
}

type managedDynamicDeclarationContext struct {
	ConsumerKind                 string
	DeliveryKind                 string
	DeliveryProfileRef           string
	ReloadProfileRef             string
	HealthProfileRef             string
	AllowedSources               []string
	NamePolicy                   string
	MaxActiveBindings            int
	AdditionalReservedNames      []string
	EnvironmentPolicyRef         string
	EnvironmentPolicyFingerprint string
}

type managedDynamicDeclarationAuthority interface {
	Resolve(managedDynamicSetupIntent) (managedDynamicDeclarationContext, error)
}

type managedDynamicDeclarationResolver struct {
	paths []string
}

func (resolver managedDynamicDeclarationResolver) Resolve(intent managedDynamicSetupIntent) (managedDynamicDeclarationContext, error) {
	if len(resolver.paths) == 0 || len(resolver.paths) > 64 {
		return managedDynamicDeclarationContext{}, managedIntentError("managed_intent_declaration_unavailable")
	}
	var found *managedDynamicDeclarationContext
	seenServices := map[string]bool{}
	seenPolicies := map[string]bool{}
	for _, path := range resolver.paths {
		raw, err := readBoundedFile(path, managedManifestMaxBytes)
		if err != nil {
			return managedDynamicDeclarationContext{}, managedIntentError("managed_intent_declaration_unavailable")
		}
		var declaration managedDynamicDeclaration
		if decodeStrictJSON(raw, &declaration) != nil || validateManagedDynamicDeclaration(declaration) != nil {
			return managedDynamicDeclarationContext{}, managedIntentError("managed_intent_declaration_unavailable")
		}
		serviceKey := declaration.HostRef + "\x00" + declaration.ServiceRef
		if seenServices[serviceKey] {
			return managedDynamicDeclarationContext{}, managedIntentError("managed_intent_declaration_unavailable")
		}
		seenServices[serviceKey] = true
		policy := declaration.DynamicEnvironmentPolicy
		if policy == nil {
			continue
		}
		if seenPolicies[policy.EnvironmentPolicyRef] {
			return managedDynamicDeclarationContext{}, managedIntentError("managed_intent_declaration_unavailable")
		}
		seenPolicies[policy.EnvironmentPolicyRef] = true
		if declaration.HostRef != intent.HostRef ||
			declaration.ServiceRef != intent.ServiceRef ||
			declaration.DeclarationFingerprint != intent.DeclarationFingerprint ||
			policy.EnvironmentPolicyRef != intent.EnvironmentPolicyRef ||
			policy.EnvironmentPolicyFingerprint != intent.EnvironmentPolicyFingerprint ||
			!containsManagedSource(policy.AllowedSources, intent.Source) ||
			!managedDynamicPolicyAdmitsName(*policy, intent.EnvironmentName) {
			continue
		}
		allowedSources := append([]string(nil), policy.AllowedSources...)
		reservedNames := append([]string(nil), policy.AdditionalReservedNames...)
		sort.Strings(allowedSources)
		sort.Strings(reservedNames)
		context := managedDynamicDeclarationContext{
			ConsumerKind:                 policy.ConsumerKind,
			DeliveryKind:                 policy.DeliveryKind,
			DeliveryProfileRef:           policy.DeliveryProfileRef,
			ReloadProfileRef:             policy.ReloadProfileRef,
			HealthProfileRef:             policy.HealthProfileRef,
			AllowedSources:               allowedSources,
			NamePolicy:                   policy.NamePolicy,
			MaxActiveBindings:            policy.MaxActiveBindings,
			AdditionalReservedNames:      reservedNames,
			EnvironmentPolicyRef:         policy.EnvironmentPolicyRef,
			EnvironmentPolicyFingerprint: policy.EnvironmentPolicyFingerprint,
		}
		found = &context
	}
	if found == nil {
		return managedDynamicDeclarationContext{}, managedIntentError("managed_intent_declaration_drift")
	}
	return *found, nil
}

type managedDynamicSetupInspection struct {
	Intent  managedDynamicSetupIntent
	Context managedDynamicDeclarationContext
}

type managedDynamicSetupIntentConsumer struct {
	keyring     managedIntentKeyring
	declaration managedDynamicDeclarationAuthority
	issuerRef   string
	audienceRef string
	now         func() time.Time
}

func decodeManagedDynamicSignedIntent(raw []byte) (managedSignedIntent, error) {
	if len(raw) == 0 || int64(len(raw)) > managedIntentMaxEnvelopeBytes {
		return managedSignedIntent{}, managedIntentError("managed_intent_envelope_invalid")
	}
	var envelope managedSignedIntent
	if decodeStrictJSON(raw, &envelope) != nil {
		return managedSignedIntent{}, managedIntentError("managed_intent_envelope_invalid")
	}
	return envelope, nil
}

func (consumer managedDynamicSetupIntentConsumer) Inspect(
	envelope managedSignedIntent,
	intentRef string,
	humanSessionRef string,
) (managedDynamicSetupInspection, error) {
	if !validManagedRef("intent_", intentRef) || !validManagedRef("hsn_", humanSessionRef) {
		return managedDynamicSetupInspection{}, managedIntentError("managed_intent_invalid_request")
	}
	intent, err := verifyManagedDynamicSetupIntent(envelope, consumer.keyring)
	if err != nil {
		return managedDynamicSetupInspection{}, err
	}
	if intent.IntentRef != intentRef {
		return managedDynamicSetupInspection{}, managedIntentError("managed_intent_reference_mismatch")
	}
	if intent.IssuerRef != consumer.issuerRef {
		return managedDynamicSetupInspection{}, managedIntentError("managed_intent_wrong_issuer")
	}
	if intent.AudienceRef != consumer.audienceRef {
		return managedDynamicSetupInspection{}, managedIntentError("managed_intent_wrong_audience")
	}
	if intent.HumanSessionRef != humanSessionRef {
		return managedDynamicSetupInspection{}, managedIntentError("managed_intent_wrong_user")
	}
	now := consumer.now().Unix()
	if intent.IssuedAtUnixSeconds > now+managedIntentClockSkewSeconds {
		return managedDynamicSetupInspection{}, managedIntentError("managed_intent_not_yet_valid")
	}
	if now >= intent.ExpiresAtUnixSeconds {
		return managedDynamicSetupInspection{}, managedIntentError("managed_intent_expired")
	}
	context, err := consumer.declaration.Resolve(intent)
	if err != nil {
		return managedDynamicSetupInspection{}, normalizeManagedIntentError(err)
	}
	return managedDynamicSetupInspection{Intent: intent, Context: context}, nil
}

func verifyManagedDynamicSetupIntent(envelope managedSignedIntent, keyring managedIntentKeyring) (managedDynamicSetupIntent, error) {
	if envelope.Schema != managedDynamicSignedIntentSchema ||
		envelope.SchemaVersion != managedDynamicContractVersion ||
		!validManagedRef("key_", envelope.KeyID) {
		return managedDynamicSetupIntent{}, managedIntentError("managed_intent_version_unsupported")
	}
	publicKey, exists := keyring[envelope.KeyID]
	if !exists {
		return managedDynamicSetupIntent{}, managedIntentError("managed_intent_signing_key_unknown")
	}
	payload, err := base64.RawURLEncoding.DecodeString(envelope.PayloadBase64URL)
	if err != nil || len(payload) == 0 || int64(len(payload)) > managedIntentMaxEnvelopeBytes {
		return managedDynamicSetupIntent{}, managedIntentError("managed_intent_envelope_invalid")
	}
	signature, err := base64.RawURLEncoding.DecodeString(envelope.SignatureBase64URL)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(publicKey, managedIntentSignatureMessageForDomain(
			managedDynamicIntentSignatureDomain,
			envelope.KeyID,
			payload,
		), signature) {
		return managedDynamicSetupIntent{}, managedIntentError("managed_intent_signature_invalid")
	}
	var intent managedDynamicSetupIntent
	if decodeStrictJSON(payload, &intent) != nil || validateManagedDynamicSetupIntent(intent) != nil {
		return managedDynamicSetupIntent{}, managedIntentError("managed_intent_payload_invalid")
	}
	return intent, nil
}

func validateManagedDynamicSetupIntent(intent managedDynamicSetupIntent) error {
	ttl := intent.ExpiresAtUnixSeconds - intent.IssuedAtUnixSeconds
	if intent.Schema != managedDynamicSetupIntentSchema ||
		intent.SchemaVersion != managedDynamicContractVersion ||
		!validManagedRef("intent_", intent.IntentRef) ||
		(intent.OperationKind != "create" && intent.OperationKind != "replace") ||
		!validManagedSource(intent.Source) || intent.Source == "remove" ||
		!validManagedRef("host_", intent.HostRef) ||
		!validManagedRef("svc_", intent.ServiceRef) ||
		!validManagedRef("envpol_", intent.EnvironmentPolicyRef) ||
		!validManagedRef("envpf_", intent.EnvironmentPolicyFingerprint) ||
		!validManagedRef("decl_", intent.DeclarationFingerprint) ||
		!validManagedEnvironmentName(intent.EnvironmentName) ||
		!validManagedRef("hsn_", intent.HumanSessionRef) ||
		!validManagedRef("sys_", intent.IssuerRef) ||
		!validManagedRef("sys_", intent.AudienceRef) ||
		!validManagedRef("nonce_", intent.NonceRef) ||
		intent.IssuedAtUnixSeconds <= 0 ||
		ttl <= 0 || ttl > managedIntentMaxTTLSeconds ||
		intent.ReturnTarget != "pharos_service" {
		return errors.New("managed_intent_payload_invalid")
	}
	return nil
}

func validateManagedDynamicDeclaration(declaration managedDynamicDeclaration) error {
	if declaration.Schema != managedDynamicDeclarationSchema ||
		declaration.SchemaVersion != managedDynamicContractVersion ||
		!validManagedRef("host_", declaration.HostRef) ||
		!validManagedRef("svc_", declaration.ServiceRef) ||
		!validManagedRef("decl_", declaration.DeclarationFingerprint) ||
		declaration.Slots == nil ||
		len(declaration.Slots) > 64 ||
		(len(declaration.Slots) == 0 && declaration.DynamicEnvironmentPolicy == nil) {
		return errors.New("managed_intent_declaration_invalid")
	}
	seenSlots := map[string]bool{}
	for _, slot := range declaration.Slots {
		if !validManagedRef("slot_", slot.SlotRef) || seenSlots[slot.SlotRef] ||
			!validManagedSafeLabel(slot.SafeLabel) ||
			slot.ConsumerKind != "managed_service" ||
			slot.DeliveryKind != "private_env_file" ||
			!validManagedRef("delivery_", slot.DeliveryProfileRef) ||
			!validManagedRef("reload_", slot.ReloadProfileRef) ||
			!validManagedRef("health_", slot.HealthProfileRef) ||
			!validManagedSourcePolicyUnordered(slot.AllowedSources) {
			return errors.New("managed_intent_declaration_invalid")
		}
		seenSlots[slot.SlotRef] = true
	}
	if declaration.DynamicEnvironmentPolicy == nil {
		return nil
	}
	policy := declaration.DynamicEnvironmentPolicy
	if !validManagedRef("envpol_", policy.EnvironmentPolicyRef) ||
		!validManagedRef("envpf_", policy.EnvironmentPolicyFingerprint) ||
		policy.ConsumerKind != "managed_service" ||
		policy.DeliveryKind != "private_env_file" ||
		!validManagedRef("delivery_", policy.DeliveryProfileRef) ||
		!validManagedRef("reload_", policy.ReloadProfileRef) ||
		!validManagedRef("health_", policy.HealthProfileRef) ||
		!validManagedSourcePolicyUnordered(policy.AllowedSources) ||
		policy.NamePolicy != "portable_secret_env_v1" ||
		policy.MaxActiveBindings <= 0 || policy.MaxActiveBindings > managedDynamicMaximumBindings ||
		policy.AdditionalReservedNames == nil ||
		len(policy.AdditionalReservedNames) > managedDynamicMaximumReservedNames {
		return errors.New("managed_intent_declaration_invalid")
	}
	seenReservedNames := map[string]bool{}
	for _, name := range policy.AdditionalReservedNames {
		if !validManagedEnvironmentName(name) || seenReservedNames[name] {
			return errors.New("managed_intent_declaration_invalid")
		}
		seenReservedNames[name] = true
	}
	return nil
}

func validManagedSourcePolicyUnordered(sources []string) bool {
	if len(sources) == 0 || len(sources) > 2 {
		return false
	}
	seen := map[string]bool{}
	for _, source := range sources {
		if (source != "generated" && source != "import") || seen[source] {
			return false
		}
		seen[source] = true
	}
	return true
}

var managedReservedEnvironmentNames = map[string]struct{}{
	"BASHOPTS": {}, "BASH_ENV": {}, "CDPATH": {}, "ENV": {}, "GLOBIGNORE": {},
	"HOME": {}, "HOSTALIASES": {}, "IFS": {}, "JAVA_TOOL_OPTIONS": {}, "NODE_OPTIONS": {},
	"OLDPWD": {}, "PATH": {}, "PERL5LIB": {}, "PERL5OPT": {}, "PROMPT_COMMAND": {},
	"PS4": {}, "PWD": {}, "PYTHONHOME": {}, "PYTHONPATH": {}, "PYTHONSTARTUP": {},
	"RUBYOPT": {}, "SHELL": {}, "SHELLOPTS": {}, "USER": {}, "ZDOTDIR": {},
}

var managedReservedEnvironmentPrefixes = []string{"DYLD_", "GIT_CONFIG_", "JANUS_", "LD_", "NIX_"}

func validManagedEnvironmentName(value string) bool {
	if len(value) == 0 || len(value) > 128 || value[0] < 'A' || value[0] > 'Z' {
		return false
	}
	for _, character := range []byte(value[1:]) {
		if (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	if _, reserved := managedReservedEnvironmentNames[value]; reserved {
		return false
	}
	for _, prefix := range managedReservedEnvironmentPrefixes {
		if len(value) >= len(prefix) && value[:len(prefix)] == prefix {
			return false
		}
	}
	return true
}

func managedDynamicPolicyAdmitsName(policy managedDynamicEnvironmentPolicy, name string) bool {
	if !validManagedEnvironmentName(name) {
		return false
	}
	reservedNames := append([]string(nil), policy.AdditionalReservedNames...)
	sort.Strings(reservedNames)
	index := sort.SearchStrings(reservedNames, name)
	return index == len(reservedNames) || reservedNames[index] != name
}
