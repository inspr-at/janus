package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	managedDynamicReplayStoreSchema = "inspr.janus.managed-environment-setup-replay-store.v2"
	managedDynamicReplayStoreFile   = "managed-dynamic-setup-replays.json"
)

type managedDynamicReplayStore struct {
	path     string
	mu       sync.Mutex
	document managedDynamicReplayDocument
}

type managedDynamicReplayDocument struct {
	Schema        string                                `json:"schema"`
	SchemaVersion int                                   `json:"schema_version"`
	Reservations  map[string]managedDynamicReplayRecord `json:"reservations"`
	Nonces        map[string]string                     `json:"nonces"`
}

type managedDynamicReplayRecord struct {
	OperationRef                    string `json:"operation_ref"`
	TargetFingerprint               string `json:"target_fingerprint"`
	ReservedAtUnixSecond            int64  `json:"reserved_at_unix_secs"`
	ValueAdmissionStartedUnixSecond int64  `json:"value_admission_started_at_unix_secs,omitempty"`
	ValueAdmissionDoneUnixSecond    int64  `json:"value_admission_done_at_unix_secs,omitempty"`
	ExpiresAtUnixSecond             int64  `json:"expires_at_unix_secs"`
}

func newManagedDynamicReplayStore(path string) (*managedDynamicReplayStore, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("managed_intent_replay_store_unavailable")
	}
	document := newManagedDynamicReplayDocument()
	loaded, err := readManagedDynamicReplayDocument(path)
	if err == nil {
		document = loaded
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return &managedDynamicReplayStore{path: path, document: document}, nil
}

func readManagedDynamicReplayDocument(path string) (managedDynamicReplayDocument, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return managedDynamicReplayDocument{}, err
		}
		return managedDynamicReplayDocument{}, errors.New("managed_intent_replay_store_unavailable")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return managedDynamicReplayDocument{}, errors.New("managed_intent_replay_store_unavailable")
	}
	raw, err := readBoundedPrivateFile(path, managedReplayMaxBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return managedDynamicReplayDocument{}, err
		}
		return managedDynamicReplayDocument{}, errors.New("managed_intent_replay_store_unavailable")
	}
	var document managedDynamicReplayDocument
	if decodeStrictJSON(raw, &document) != nil || validateManagedDynamicReplayDocument(document) != nil {
		return managedDynamicReplayDocument{}, errors.New("managed_intent_replay_store_invalid")
	}
	return document, nil
}

func newManagedDynamicReplayDocument() managedDynamicReplayDocument {
	return managedDynamicReplayDocument{
		Schema:        managedDynamicReplayStoreSchema,
		SchemaVersion: managedDynamicContractVersion,
		Reservations:  map[string]managedDynamicReplayRecord{},
		Nonces:        map[string]string{},
	}
}

func (store *managedDynamicReplayStore) reserve(intent managedDynamicSetupIntent, now int64) (string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()

	if durable, err := readManagedDynamicReplayDocument(store.path); err == nil {
		store.document = durable
	} else if !errors.Is(err, os.ErrNotExist) || len(store.document.Reservations) != 0 {
		return "", managedIntentError("managed_intent_replay_store_unavailable")
	}
	if validateManagedDynamicSetupIntent(intent) != nil {
		return "", managedIntentError("managed_intent_payload_invalid")
	}
	if intent.IssuedAtUnixSeconds > now+managedIntentClockSkewSeconds {
		return "", managedIntentError("managed_intent_not_yet_valid")
	}
	if now >= intent.ExpiresAtUnixSeconds {
		return "", managedIntentError("managed_intent_expired")
	}
	targetFingerprint, err := managedDynamicIntentFingerprint(intent)
	if err != nil {
		return "", managedIntentError("managed_intent_replay_store_unavailable")
	}
	candidate := cloneManagedDynamicReplayDocument(store.document)
	pruneManagedDynamicReplayDocument(&candidate, now)
	if _, exists := candidate.Reservations[intent.IntentRef]; exists {
		return "", managedIntentError("managed_intent_replayed")
	}
	if _, exists := candidate.Nonces[intent.NonceRef]; exists {
		return "", managedIntentError("managed_intent_replayed")
	}
	if len(candidate.Reservations) >= managedReplayMaximumEntries {
		return "", managedIntentError("managed_intent_replay_capacity")
	}
	operationRef, err := randomManagedRef("op_")
	if err != nil {
		return "", managedIntentError("managed_intent_replay_store_unavailable")
	}
	for _, record := range candidate.Reservations {
		if record.OperationRef == operationRef {
			return "", managedIntentError("managed_intent_replay_store_unavailable")
		}
	}
	candidate.Reservations[intent.IntentRef] = managedDynamicReplayRecord{
		OperationRef:         operationRef,
		TargetFingerprint:    targetFingerprint,
		ReservedAtUnixSecond: now,
		ExpiresAtUnixSecond:  intent.ExpiresAtUnixSeconds,
	}
	candidate.Nonces[intent.NonceRef] = intent.IntentRef
	if err := atomicWriteManagedJSON(store.path, candidate); err != nil {
		if managedFinalFileReplaced(err) {
			store.document = candidate
		}
		return "", managedIntentError("managed_intent_replay_store_unavailable")
	}
	store.document = candidate
	return operationRef, nil
}

func (store *managedDynamicReplayStore) recover(intent managedDynamicSetupIntent, operationRef string, now int64) (managedDynamicReplayRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()

	durable, err := readManagedDynamicReplayDocument(store.path)
	if err != nil {
		return managedDynamicReplayRecord{}, managedIntentError("managed_intent_recovery_unavailable")
	}
	store.document = durable
	targetFingerprint, err := managedDynamicIntentFingerprint(intent)
	if err != nil {
		return managedDynamicReplayRecord{}, managedIntentError("managed_intent_recovery_unavailable")
	}
	record, exists := store.document.Reservations[intent.IntentRef]
	if !exists ||
		now < record.ReservedAtUnixSecond ||
		record.ExpiresAtUnixSecond <= now ||
		record.OperationRef != operationRef ||
		record.TargetFingerprint != targetFingerprint ||
		store.document.Nonces[intent.NonceRef] != intent.IntentRef {
		return managedDynamicReplayRecord{}, managedIntentError("managed_intent_recovery_unavailable")
	}
	return record, nil
}

func (store *managedDynamicReplayStore) beginValueAdmission(intent managedDynamicSetupIntent, operationRef string, now int64) (managedDynamicReplayRecord, error) {
	return store.updateValueAdmission(intent, operationRef, now, false)
}

func (store *managedDynamicReplayStore) completeValueAdmission(intent managedDynamicSetupIntent, operationRef string, now int64) (managedDynamicReplayRecord, error) {
	return store.updateValueAdmission(intent, operationRef, now, true)
}

func (store *managedDynamicReplayStore) updateValueAdmission(intent managedDynamicSetupIntent, operationRef string, now int64, complete bool) (managedDynamicReplayRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()

	durable, err := readManagedDynamicReplayDocument(store.path)
	if err != nil {
		return managedDynamicReplayRecord{}, managedIntentError("managed_intent_value_admission_unavailable")
	}
	store.document = durable
	if validateManagedDynamicSetupIntent(intent) != nil || !validManagedRef("op_", operationRef) {
		return managedDynamicReplayRecord{}, managedIntentError("managed_intent_payload_invalid")
	}
	targetFingerprint, err := managedDynamicIntentFingerprint(intent)
	if err != nil {
		return managedDynamicReplayRecord{}, managedIntentError("managed_intent_value_admission_unavailable")
	}
	record, exists := store.document.Reservations[intent.IntentRef]
	if !exists ||
		now < record.ReservedAtUnixSecond ||
		record.ExpiresAtUnixSecond <= now ||
		record.OperationRef != operationRef ||
		record.TargetFingerprint != targetFingerprint ||
		store.document.Nonces[intent.NonceRef] != intent.IntentRef {
		return managedDynamicReplayRecord{}, managedIntentError("managed_intent_value_admission_unavailable")
	}
	if complete {
		if record.ValueAdmissionStartedUnixSecond == 0 ||
			now < record.ValueAdmissionStartedUnixSecond ||
			record.ValueAdmissionDoneUnixSecond != 0 {
			return managedDynamicReplayRecord{}, managedIntentError("managed_intent_value_admission_unavailable")
		}
		record.ValueAdmissionDoneUnixSecond = now
	} else {
		if record.ValueAdmissionStartedUnixSecond != 0 {
			return record, managedIntentError("managed_intent_value_replayed")
		}
		record.ValueAdmissionStartedUnixSecond = now
	}
	candidate := cloneManagedDynamicReplayDocument(store.document)
	candidate.Reservations[intent.IntentRef] = record
	if validateManagedDynamicReplayDocument(candidate) != nil {
		return managedDynamicReplayRecord{}, managedIntentError("managed_intent_value_admission_unavailable")
	}
	if err := atomicWriteManagedJSON(store.path, candidate); err != nil {
		if managedFinalFileReplaced(err) {
			store.document = candidate
		}
		return managedDynamicReplayRecord{}, managedIntentError("managed_intent_value_admission_unavailable")
	}
	store.document = candidate
	return record, nil
}

func managedDynamicIntentFingerprint(intent managedDynamicSetupIntent) (string, error) {
	raw, err := encodeManagedCanonicalJSON(intent)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return "intentfp_" + hex.EncodeToString(digest[:]), nil
}

func cloneManagedDynamicReplayDocument(document managedDynamicReplayDocument) managedDynamicReplayDocument {
	clone := newManagedDynamicReplayDocument()
	for intentRef, record := range document.Reservations {
		clone.Reservations[intentRef] = record
	}
	for nonceRef, intentRef := range document.Nonces {
		clone.Nonces[nonceRef] = intentRef
	}
	return clone
}

func pruneManagedDynamicReplayDocument(document *managedDynamicReplayDocument, now int64) {
	for intentRef, record := range document.Reservations {
		if record.ExpiresAtUnixSecond <= now {
			delete(document.Reservations, intentRef)
		}
	}
	for nonceRef, intentRef := range document.Nonces {
		if _, exists := document.Reservations[intentRef]; !exists {
			delete(document.Nonces, nonceRef)
		}
	}
}

func validateManagedDynamicReplayDocument(document managedDynamicReplayDocument) error {
	if document.Schema != managedDynamicReplayStoreSchema ||
		document.SchemaVersion != managedDynamicContractVersion ||
		document.Reservations == nil ||
		document.Nonces == nil ||
		len(document.Reservations) > managedReplayMaximumEntries ||
		len(document.Nonces) != len(document.Reservations) {
		return errors.New("managed_intent_replay_store_invalid")
	}
	intentNonces := make(map[string]int, len(document.Reservations))
	operationRefs := make(map[string]bool, len(document.Reservations))
	for nonceRef, intentRef := range document.Nonces {
		if !validManagedRef("nonce_", nonceRef) {
			return errors.New("managed_intent_replay_store_invalid")
		}
		if _, exists := document.Reservations[intentRef]; !exists {
			return errors.New("managed_intent_replay_store_invalid")
		}
		intentNonces[intentRef]++
	}
	for intentRef, record := range document.Reservations {
		if !validManagedRef("intent_", intentRef) ||
			!validManagedRef("op_", record.OperationRef) ||
			!strings.HasPrefix(record.TargetFingerprint, "intentfp_") ||
			!isLowerHexString(strings.TrimPrefix(record.TargetFingerprint, "intentfp_"), sha256.Size*2) ||
			record.ReservedAtUnixSecond <= 0 ||
			record.ExpiresAtUnixSecond <= record.ReservedAtUnixSecond ||
			record.ValueAdmissionStartedUnixSecond < 0 ||
			record.ValueAdmissionStartedUnixSecond != 0 &&
				(record.ValueAdmissionStartedUnixSecond < record.ReservedAtUnixSecond ||
					record.ValueAdmissionStartedUnixSecond >= record.ExpiresAtUnixSecond) ||
			record.ValueAdmissionDoneUnixSecond < 0 ||
			record.ValueAdmissionDoneUnixSecond != 0 &&
				(record.ValueAdmissionStartedUnixSecond == 0 ||
					record.ValueAdmissionDoneUnixSecond < record.ValueAdmissionStartedUnixSecond ||
					record.ValueAdmissionDoneUnixSecond >= record.ExpiresAtUnixSecond) ||
			intentNonces[intentRef] != 1 ||
			operationRefs[record.OperationRef] {
			return errors.New("managed_intent_replay_store_invalid")
		}
		operationRefs[record.OperationRef] = true
	}
	return nil
}
