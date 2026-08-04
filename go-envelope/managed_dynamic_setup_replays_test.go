package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestManagedDynamicReservationIsDurableSingleUseAndTargetBound(t *testing.T) {
	path := filepath.Join(t.TempDir(), managedDynamicReplayStoreFile)
	store, err := newManagedDynamicReplayStore(path)
	if err != nil {
		t.Fatal(err)
	}
	intent := managedDynamicTestIntent()
	now := managedDynamicTestNow + 1
	operationRef, err := store.reserve(intent, now)
	if err != nil || !validManagedRef("op_", operationRef) {
		t.Fatalf("exact intent was not reserved: op=%q err=%v", operationRef, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("replay state must be a private regular file: info=%#v err=%v", info, err)
	}
	if err := store.recover(intent, operationRef, now); err != nil {
		t.Fatalf("fresh exact reservation was not recoverable: %v", err)
	}
	if _, err := store.reserve(intent, now); err == nil || err.Error() != "managed_intent_replayed" {
		t.Fatalf("intent replay was accepted: %v", err)
	}

	sameNonce := intent
	sameNonce.IntentRef = "intent_fedcba9876543210"
	if _, err := store.reserve(sameNonce, now); err == nil || err.Error() != "managed_intent_replayed" {
		t.Fatalf("nonce replay was accepted: %v", err)
	}

	restarted, err := newManagedDynamicReplayStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.recover(intent, operationRef, now); err != nil {
		t.Fatalf("reservation did not survive restart: %v", err)
	}
	changed := intent
	changed.EnvironmentName = "ROTATED_DATABASE_PASSWORD"
	if err := restarted.recover(changed, operationRef, now); err == nil || err.Error() != "managed_intent_recovery_unavailable" {
		t.Fatalf("changed target recovered an existing operation: %v", err)
	}
	if err := restarted.recover(intent, "op_fedcba9876543210", now); err == nil || err.Error() != "managed_intent_recovery_unavailable" {
		t.Fatalf("wrong operation recovered an existing reservation: %v", err)
	}
	if err := restarted.recover(intent, operationRef, intent.ExpiresAtUnixSeconds); err == nil || err.Error() != "managed_intent_recovery_unavailable" {
		t.Fatalf("expired reservation remained recoverable: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := restarted.recover(intent, operationRef, now); err == nil || err.Error() != "managed_intent_recovery_unavailable" {
		t.Fatalf("missing durable state fell back to memory: %v", err)
	}
}

func TestManagedDynamicReservationAllowsOnlyOneConcurrentWinner(t *testing.T) {
	store, err := newManagedDynamicReplayStore(filepath.Join(t.TempDir(), managedDynamicReplayStoreFile))
	if err != nil {
		t.Fatal(err)
	}
	intent := managedDynamicTestIntent()
	var successes atomic.Int32
	var unexpected atomic.Int32
	var workers sync.WaitGroup
	for range 24 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if _, err := store.reserve(intent, managedDynamicTestNow+1); err == nil {
				successes.Add(1)
			} else if err.Error() != "managed_intent_replayed" {
				unexpected.Add(1)
			}
		}()
	}
	workers.Wait()
	if successes.Load() != 1 || unexpected.Load() != 0 {
		t.Fatalf("concurrent reservation winners=%d unexpected=%d", successes.Load(), unexpected.Load())
	}
}

func TestManagedDynamicReservationReloadsDurableStateBeforeWriting(t *testing.T) {
	path := filepath.Join(t.TempDir(), managedDynamicReplayStoreFile)
	first, err := newManagedDynamicReplayStore(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := newManagedDynamicReplayStore(path)
	if err != nil {
		t.Fatal(err)
	}
	intent := managedDynamicTestIntent()
	if _, err := first.reserve(intent, managedDynamicTestNow+1); err != nil {
		t.Fatal(err)
	}
	if _, err := second.reserve(intent, managedDynamicTestNow+1); err == nil || err.Error() != "managed_intent_replayed" {
		t.Fatalf("stale process-local state overwrote a durable reservation: %v", err)
	}
}

func TestManagedDynamicReplayStoreFailsClosedOnCorruptionPermissionsCapacityAndWriteFailure(t *testing.T) {
	if _, err := newManagedDynamicReplayStore("relative/replays.json"); err == nil {
		t.Fatal("relative replay path was accepted")
	}

	t.Run("corrupt", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), managedDynamicReplayStoreFile)
		raw := []byte(`{"schema":"inspr.janus.managed-environment-setup-replay-store.v2","schema_version":2,"reservations":{},"nonces":{},"unknown":true}`)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := newManagedDynamicReplayStore(path); err == nil || err.Error() != "managed_intent_replay_store_invalid" {
			t.Fatalf("unknown replay state was accepted: %v", err)
		}
	})

	t.Run("permissions", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), managedDynamicReplayStoreFile)
		raw := []byte(`{"schema":"inspr.janus.managed-environment-setup-replay-store.v2","schema_version":2,"reservations":{},"nonces":{}}`)
		if err := os.WriteFile(path, raw, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := newManagedDynamicReplayStore(path); err == nil || err.Error() != "managed_intent_replay_store_unavailable" {
			t.Fatalf("public replay state was accepted: %v", err)
		}
	})

	t.Run("symlink", func(t *testing.T) {
		directory := t.TempDir()
		target := filepath.Join(directory, "target.json")
		path := filepath.Join(directory, managedDynamicReplayStoreFile)
		raw := []byte(`{"schema":"inspr.janus.managed-environment-setup-replay-store.v2","schema_version":2,"reservations":{},"nonces":{}}`)
		if err := os.WriteFile(target, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if _, err := newManagedDynamicReplayStore(path); err == nil || err.Error() != "managed_intent_replay_store_unavailable" {
			t.Fatalf("symlinked replay state was accepted: %v", err)
		}
	})

	t.Run("corruption after reservation", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), managedDynamicReplayStoreFile)
		store, err := newManagedDynamicReplayStore(path)
		if err != nil {
			t.Fatal(err)
		}
		intent := managedDynamicTestIntent()
		operationRef, err := store.reserve(intent, managedDynamicTestNow+1)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(`{"schema":"corrupt"}`), 0600); err != nil {
			t.Fatal(err)
		}
		if err := store.recover(intent, operationRef, managedDynamicTestNow+1); err == nil || err.Error() != "managed_intent_recovery_unavailable" {
			t.Fatalf("corrupt durable state fell back to memory: %v", err)
		}
	})

	t.Run("capacity", func(t *testing.T) {
		store, err := newManagedDynamicReplayStore(filepath.Join(t.TempDir(), managedDynamicReplayStoreFile))
		if err != nil {
			t.Fatal(err)
		}
		for index := range managedReplayMaximumEntries {
			intentRef := fmt.Sprintf("intent_%08d", index)
			nonceRef := fmt.Sprintf("nonce_%08d", index)
			store.document.Reservations[intentRef] = managedDynamicReplayRecord{
				OperationRef:         fmt.Sprintf("op_%08d", index),
				TargetFingerprint:    "intentfp_" + strings.Repeat("a", 64),
				ReservedAtUnixSecond: managedDynamicTestNow,
				ExpiresAtUnixSecond:  managedDynamicTestNow + 300,
			}
			store.document.Nonces[nonceRef] = intentRef
		}
		if err := atomicWriteManagedJSON(store.path, store.document); err != nil {
			t.Fatal(err)
		}
		if _, err := store.reserve(managedDynamicTestIntent(), managedDynamicTestNow+1); err == nil || err.Error() != "managed_intent_replay_capacity" {
			t.Fatalf("full replay store admitted another reservation: %v", err)
		}
	})

	t.Run("write failure does not consume memory", func(t *testing.T) {
		directory := t.TempDir()
		path := filepath.Join(directory, managedDynamicReplayStoreFile)
		store, err := newManagedDynamicReplayStore(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		intent := managedDynamicTestIntent()
		if _, err := store.reserve(intent, managedDynamicTestNow+1); err == nil || err.Error() != "managed_intent_replay_store_unavailable" {
			t.Fatalf("write failure did not fail closed: %v", err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if _, err := store.reserve(intent, managedDynamicTestNow+1); err != nil {
			t.Fatalf("failed write consumed in-memory reservation: %v", err)
		}
	})
}

func TestManagedDynamicReservationRejectsExpiredAndNotYetValidIntent(t *testing.T) {
	store, err := newManagedDynamicReplayStore(filepath.Join(t.TempDir(), managedDynamicReplayStoreFile))
	if err != nil {
		t.Fatal(err)
	}
	intent := managedDynamicTestIntent()
	if _, err := store.reserve(intent, intent.ExpiresAtUnixSeconds); err == nil || err.Error() != "managed_intent_expired" {
		t.Fatalf("expired intent was reserved: %v", err)
	}
	if _, err := store.reserve(intent, intent.IssuedAtUnixSeconds-managedIntentClockSkewSeconds-1); err == nil || err.Error() != "managed_intent_not_yet_valid" {
		t.Fatalf("not-yet-valid intent was reserved: %v", err)
	}
}
