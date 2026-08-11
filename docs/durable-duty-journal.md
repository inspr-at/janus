# Durable duty journal foundation

Status: implemented foundation for JANUS-428. This is slice two of the accepted
`authenticated-principal-duty-history-v1` contract. It does **not** wire every
runtime surface and cannot advertise `enforced_recorded`; that cutover remains
JANUS-429.

## Authority boundary

`RoleDecisionInput` no longer accepts a caller-created duty slice. A decision is
explicitly either `AccountabilityLegacy` or `Recorded`. The recorded variant
requires both:

- a `PolicyDutyCandidate` derived from a fresh, single-use, domain-service-signed
  authoritative operation reference; and
- a `VerifiedOperationView` produced only after the complete epoch and journal
  chains verify.

The append API additionally requires the opaque `BrokerAuthenticatedActorV1`.
External crates can name that type but cannot construct or deserialize it. The
candidate scope and admitted release must exactly match the broker-authenticated
actor context.

Current runtime call sites use the conspicuous `AccountabilityLegacy` variant.
They cannot provide an empty recorded view and the release must not claim durable
separation until JANUS-429 wires every registered surface.

## Signed operation lineage

`AuthoritativeOperationRefV1` binds the exact domain service, opaque operation
reference, scope, typed conflict domain, policy-derived duty, state revision,
policy revision, time window, nonce, audience, and admitted release. The stateful
verifier checks its pinned Ed25519 key, enforces a maximum five-minute lifetime,
and consumes the nonce exactly once before creating an opaque verified operation.

An operation reference is derived from the authoritative domain lineage; no
client string becomes authority. Forged, changed, expired, replayed,
wrong-service, wrong-audience, wrong-release, or duty/domain-mismatched references
fail before journal lookup.

## Storage and locking

`FileDutyJournal` owns four private files under a mode-`0700` directory:

| File | Contract |
| --- | --- |
| `epochs.jsonl` | Strict Ed25519 epoch chain; every rotation is signed by the old and new keys. |
| `journal.jsonl` | Immutable JSONL duty admissions with monotonic sequence, predecessor hash, record hash, epoch key, signature, release, and audit linkage. |
| `index.json` | Non-authoritative exact-operation index derived from the fully verified journal. |
| `journal.lock` | OS-managed exclusive advisory lock for verify/evaluate/append/index transactions. |

Files are mode `0600`, regular, non-symlink, and bounded. Append uses write-all,
flush, data/file sync, atomic index replacement, and parent-directory sync. The
lock is released by the OS if the broker exits. It never spans the later domain
mutation.

The journal never truncates an incomplete tail and never compacts or deletes
authority history automatically. An unknown schema, sequence gap, predecessor
mismatch, invalid signature, unknown/stale epoch, incomplete tail, missing
component, over-capacity state, or index disagreement makes history unavailable.

## Conflict lookup and transaction result

Lookup identity is exactly the authenticated actor, scope, conflict domain, and
opaque operation reference. Policy and record revisions remain verified
provenance but do not partition the lookup, so changing policy during one lineage
cannot erase an earlier duty.

The journal lock serializes concurrent phases. A conflicting candidate writes a
value-free denial audit and appends nothing. An allowed candidate is appended and
synced before its authorization audit. If that audit fails, the conservative duty
remains and the caller receives an error, so the domain mutation cannot proceed.
Retries of the same compatible duty remain safe; incompatible later phases stay
denied after restart.

## Capacity, backup, and recovery

V1 bounds individual records, global records, and records per exact operation.
Reaching a bound denies before append. There is no automatic compaction.

`backup_to` holds the lock, verifies the complete journal and index, and writes a
new private bundle with release, sequence, head hash, and epoch-count bindings.
`restore_from_backup` accepts only an absent destination, verifies the source
bundle and current signing key, copies private files, syncs the directory, and
reopens the restored journal through normal verification.

The only online recovery operation is explicit index rebuild. It verifies every
signed epoch and admission before replacing the derived index. It never changes
the journal. Legacy duty import is always rejected; an empty new journal cannot
stand in for an active legacy operation.

Key rotation appends a cross-signed epoch certificate before the new key may
sign admissions. A process holding the old key fails as stale after rotation.
Trust-root recovery and any future history compaction require a separate reviewed
offline migration and cannot silently restore an enforcement claim.

## Verification

Focused checks:

```sh
python3 scripts/check-duty-journal-boundary.py --self-test
python3 scripts/check-duty-journal-boundary.py
cargo test -p janus-core duty --no-fail-fast
cargo test -p janus-core roles --no-fail-fast
cargo test -p janus-local duty --no-fail-fast
```

Tests cover all nine conflict pairs, policy revision changes, restart, concurrent
incompatible phases, signed key rotation, malformed and replayed operation state,
tamper/gap/schema/signature/tail/index failures, stale keys, OS lock release,
audit failure after duty sync, legacy import denial, backup/restore, and
value-free outputs.
