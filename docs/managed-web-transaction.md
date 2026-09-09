# Managed-service web transaction boundary

`janusd-web-transactiond` is the only local bridge from the authenticated Go
web envelope to Janus lifecycle entry. It is not an HTTP API and it does not
dispatch admin commands. The binary accepts no arguments and listens on one
private Unix socket.

The web peer may submit only these signed-intent fields:

- an opaque operation reference;
- create/replace with a generated/import source, or value-free removal;
- opaque host, service, and slot references; and
- the exact declaration fingerprint.

The daemon resolves that tuple in a root-owned reviewed catalog. The catalog,
not the peer, supplies the secret reference, scope, manifest/profile/backend
paths, consumer, probes, hooks, generation policy, state directory, audit
sink, activation reason, and host-delivery binding. Version 2 admits create,
safe replacement, and explicit removal after a reviewed declaration detach.

## Protocol

Frames use a four-byte big-endian length followed by bytes. The first frame is
strict JSON with schema
`inspr.janus.managed-web-transaction-request.v2`. The daemon replies with
strict, value-free JSON:

- `preflighted` before it will read an import value;
- `prepared` after encrypted host delivery is durably staged;
- `completed` only after fresh host activation evidence is accepted;
- `completed` for removal only after exact stopped/runtime-absent/quarantined
  evidence is accepted;
- `destroyed` only after the recovery deadline and tombstone write;
- `rolled_back` for an already reconciled operation; or
- `denied` with a stable reason code.

An import uses exactly one bounded raw frame after the preflight response.
Generated material is created inside Rust and has no value frame. Removal also
has no value frame: it carries only the reviewed target, active generation,
recovery deadline, and value-free absence evidence. Responses
contain only opaque operation/secret references, mode, phase, reason code,
`expects_value`, and `value_returned=false`.

Disconnect before or during import rolls the transaction back. Apply failures
use the lifecycle rollback. On startup, the daemon scans nonterminal journals
that still bind to its reviewed catalog. A valid, unexpired prepared host
delivery remains resumable; incomplete or expired create/replace work is
rolled back. A nonterminal removal is preserved and resumed explicitly;
process restart never restores a detached service secret. A duplicate terminal
operation returns its existing status without applying again. Integrity-checked
terminal journals from a predecessor release remain immutable history: startup
does not resume them, while their generations still prevent attempt-number
reuse after an upgrade. A nonterminal predecessor journal remains fail-closed.

Web journals use a deterministic `webtx_` namespace derived from the external
`op_` reference. Startup recovery ignores lifecycle-entry journals from other
entry points, so starting the daemon cannot take over an operator CLI
transaction.

Accepting the complete import frame is only the preparation point. It is not a
claim that the service uses the value. The host installs a signed, encrypted
packet, reloads the declared service, and submits fresh generation-bound
health evidence through Pharos. Janus then commits the central transaction.
Lost responses are retry-safe because the journal, host outbox, bridge state,
and host executor all use the same operation and generation binding.

## Optional Paimos completion producer

One generated create may opt into a completion-only producer by installing
`/etc/janus/managed-completion-paimos-binding.json`. Absence of that fixed file
preserves the previous behavior and emits no Paimos report. There is no argv,
environment, executable, callback, URL, or reporter-config path selector.

The binding is strict schema
`inspr.janus.managed-completion-paimos-binding.v1`: one exact operation,
create/generated catalog key, secret and scope, delivery generation and
revocation epoch, plan and target fingerprints, producer key ID, and one
`inspr.janus.paimos-dependency-reporter-binding.v1` value. The nested reporter
binding pins the canonical digest of the existing fixed reporter config plus
its handoff ID, dependency/stage/execution, plan/predecessor/context digests,
authority and credential epochs, expiry, evidence kind, and original reporter
observation timestamp. A different current reporter config is refused; Janus
never writes or replaces it.

Before lifecycle activation, and only after the existing generation-bound
host evidence validation succeeds, Janus fsyncs one integrity-protected
`completion.json` record in the fixed
`/var/lib/janus/managed-completion-dispatch` directory. The record retains the
original heartbeat, process, and probe timestamps, their accepted-at time,
the preparation and preflight times, generation, and binding digest. It never
contains the generated value, ciphertext, packet, credential, reporter URL,
or reporter payload. A retry with the same evidence reuses the record and its
original times; conflicting evidence or binding fails closed.

The background worker considers only that one binding-derived record and its
exact integrity-checked lifecycle journal. It never scans completed journal
history or stamps an old completion with the current time. Eligibility is
exactly `completed` with reason `entry_external_activation_ok`, create,
generated source, and matching operation, secret, generation, plan, target,
and preflight receipt. Prepared, failed, rolled-back, local-hook completion,
wrong-generation, wrong-target, or missing-record states cause no reporter
mutation.

Dispatch is outside the Unix request, serialized by a private process lock,
and retried at most three times per notification. It calls the existing fixed
Paimos reporter in-process, which retains its own per-handoff lock, exact
accept-1/terminal-2 request journal, and idempotency keys. A reporter failure
does not roll back or change the successful secret transaction; restart or an
idempotent duplicate finalize can notify it again. Because reporting begins
only after durable Janus completion and the lifecycle transaction has no
Paimos wait edge, the transaction cannot wait on the dependency it satisfies.

The binding and reporter config must be root-owned mode `0600`, regular,
single-link files. The completion record directory must already exist,
root-owned mode `0700`, and may contain only `.completion.lock` and the single
bounded record. The record and lock are mode `0600`, regular, single-link
files. Symlinks, hardlinks, owner/mode changes, oversized input, extra files,
duplicate/unknown JSON fields, or an ambiguous catalog match are refused.

## Replacement safety

Replace is admitted only for an exact reviewed declaration with a current
healthy generation. Before changing the central ciphertext, Janus records a
deterministic rollback identifier in the integrity-protected journal and
preserves the old encrypted ciphertext in a private rollback file. The host
likewise retains exactly one previous encrypted generation while it stages the
new generation.

The new generation becomes final only after install, declared reload, and
fresh process, probe, and heartbeat evidence all agree. Janus commits the
central transaction before the host destroys its previous generation. If
packet delivery, reload, verification, restart recovery, or evidence checking
fails, the host must prove that the previous generation is healthy; Pharos
then reports `rolled_back`, and Janus restores the matching central
ciphertext. If recovery cannot be proven, the operation remains uncertain and
no new generation is accepted as active.

Create and replacement attempt generations increase monotonically. Removal
targets the generation that is actually active; after a failed replacement
this is the proven restored generation, not the larger failed-attempt number.
Create and replace for the same secret/slot cannot overlap. Replacement never
exposes a reveal or arbitrary edit API, and neither journals, responses,
Pharos state, nor audit events contain the secret value.

For a rolling upgrade, install the replacement-capable host agent before
Pharos starts issuing replacement leases. The new agent treats a predecessor
lease without `operation_kind` as create and omits empty replacement-only
evidence, so create remains compatible during that step. Upgrade Pharos and
the Janus bridge next, with the bridge before Pharos, then add reviewed
replacement catalog entries last.
Until the final step, Replace stays fail-closed.

## Removal safety

Removal is never inferred from a missing value, host cache, or service. The
Nix-owned declaration must first move the slot from `required` to `detached`,
clear its creation sources, retain an exact `compose_stop_and_verify` profile,
and be deployed. Only that reviewed declaration can produce a short-lived,
passwordless-confirmed removal intent.

Janus first disables active delivery without deleting ciphertext. The host
agent stops the exact declared Compose service, verifies both the Compose
service and reviewed container are stopped, removes runtime plaintext, and
moves the exact active encrypted packet into operation-bound quarantine.
Pharos accepts only fresh stopped/runtime-absent/quarantined evidence for the
same active generation. Janus then moves central ciphertext into deterministic
quarantine and records `pending_delete`.

The browser bridge uses a fixed 24-hour recovery deadline. Cancellation may
restore active delivery before quarantine. Once quarantine starts, rollback is
denied: failures stop for operator review rather than guessing that restore is
safe. At the deadline, host and central workers independently retry their exact
idempotent purge. Central purge writes a retained tombstone before deleting
quarantine material and persists lifecycle `destroyed`. Reveal and copy-back
remain unavailable throughout.

For rollout, deploy schema-v2 readers and the host agent before publishing v2
declarations. Keep slots `required` until create/replace compatibility is
green. Detach one canary slot in a separate reviewed Nix change, verify removal
and recovery evidence, then expand. A schema-v1 declaration is read as
`required` and can never authorize removal.

Up to 16 private peers may be processed concurrently. Further connections
remain in the kernel socket backlog until capacity is available; each accepted
request and value wait is bounded.

## Runtime configuration

The daemon requires:

```text
JANUS_MANAGED_WEB_TRANSACTION_SOCKET=/run/janus/web-transaction/transaction.sock
JANUS_MANAGED_WEB_TRANSACTION_CATALOG_FILE=/etc/janus/managed-web-transactions.json
JANUS_MANAGED_WEB_TRANSACTION_ALLOWED_UID=65532
JANUS_LIFECYCLE_TOMBSTONE_DIR=/var/lib/janus/tombstones
```

The optional completion producer uses only the fixed binding path documented
above and the reporter's existing fixed
`/run/janus-paimos-dependency-reporter/config.json`; neither path is accepted
from the web peer.

It also uses the same exact-scope, Age backend, release-admission, migration,
and scope-transfer environment as lifecycle entry. The socket parent and
catalog must be private. The socket is mode `0600`, and the kernel-reported
peer UID must equal the configured UID.

The Go envelope requires the same
`JANUS_MANAGED_WEB_TRANSACTION_SOCKET` alongside its all-or-nothing managed
setup intent configuration. Filesystem access to that socket is its sole
lifecycle capability; it receives no admin binary, plan path, backend path, or
hook selector.

Startup intentionally fails closed if a nonterminal `webtx_` journal no longer
matches a current, non-stale catalog entry. Retire or replace catalog entries
only after the lifecycle queue shows no nonterminal web transaction. For
create/replace, restore the reviewed entry and let startup rollback finish.
For removal, restore the exact reviewed removal entry so it can resume; startup
deliberately does not roll it back.

## Catalog contract

The catalog is strict JSON:

```json
{
  "schema": "inspr.janus.managed-web-transaction-catalog.v2",
  "schema_version": 2,
  "entries": [
    {
      "host_ref": "host_opaque0001",
      "service_ref": "svc_opaque0001",
      "slot_ref": "slot_opaque0001",
      "declaration_fingerprint": "decl_opaque0001",
      "operation_kind": "create",
      "plan": {
        "operation_id": "web-transaction-template"
      },
      "delivery": {
        "schema": "inspr.janus.managed-host-delivery-plan.v1",
        "schema_version": 1,
        "host_recipient": "ssh-ed25519 reviewed-host-key",
        "producer_key_id": "key_opaque0001",
        "producer_signing_key_file": "/run/credentials/janus/signing-key.json",
        "outbox_dir": "/var/lib/janus/managed-host-outbox",
        "generation": 1,
        "revocation_epoch": 1,
        "envelope_ttl_seconds": 900
      }
    }
  ]
}
```

`plan` is the complete existing lifecycle-entry plan; the abbreviated object
above is illustrative and intentionally not deployable. `delivery` is the
reviewed host-encryption plan. Replacement and removal are separate catalog
entries with the same declaration tuple and `"operation_kind": "replace"` or
`"operation_kind": "remove"`. For removal, the daemon forces plan source
`remove`; no generated/import source or value frame is accepted. The daemon
replaces only the fixed template `operation_id`, using the validated opaque
operation reference. Every other field is validated at daemon startup and
remains server-owned.

Run `scripts/assure-engine-release.sh` to exercise the real Age store,
manifest/profile binding, preflight-before-value ordering, validation,
create, restart-safe replacement rollback, monotonic replacement commit,
cancel-before-quarantine, restart-safe removal, active-generation targeting,
deadline-bound quarantine/purge, tombstone retention, duplicate idempotency,
malformed request denial, and canary leak checks across output, audit, journal,
ciphertext, and daemon failure output.
