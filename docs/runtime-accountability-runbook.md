# Runtime accountability rollout and recovery

JANUS-429 closes the Rust runtime catalog behind the `janusd-identityd`
authority transaction. Every CLI command, Warden tool call, and registered
private daemon transaction obtains a fresh, signed, value-free admission before
role authorization or domain work. The reviewed mapping is
`config/authorization/duty-surface-manifest-v1.json`; CI compares it exactly
with the runtime and Warden catalogs.

## Explicit posture

`JANUS_ACCOUNTABILITY_POSTURE` is mandatory and accepts exactly:

- `accountability_legacy`: kernel-peer authentication and signed action
  admission are active, but no durable-separation claim is made. A recorded
  operation reference is not required.
- `authenticated_observe`: the complete journal is verified and candidate
  duties are durably recorded. Conflicts produce critical observation evidence
  but do not deny.
- `enforced_recorded`: the complete journal is verified and all nine conflict
  pairs deny for the same stable subject. Startup also requires exact cutover
  evidence and at least two independently enrolled active subjects.

There is no missing-value default and no fallback. Clients check that the
signed admission posture equals their configured posture.

## Broker configuration

All processes need the authority socket, duty manifest, pinned public key,
audience, release digest, scope, and explicit posture:

`JANUS_IDENTITY_SOCKET`, `JANUS_DUTY_SURFACE_MANIFEST`,
`JANUS_RUNTIME_AUTHORITY_VERIFYING_KEY_FILE`,
`JANUS_RUNTIME_AUTHORITY_AUDIENCE`, `JANUS_RELEASE_DIGEST`, the
`JANUS_SCOPE_*` fields, and `JANUS_ACCOUNTABILITY_POSTURE`.

The broker additionally requires its identity registry, identity manifest,
private signing key, trust domain, identity audience, operation-domain service,
operation audience, pinned operation verifying key, and private value-free
authority audit. Observe/enforced postures also require
`JANUS_DUTY_JOURNAL_ROOT` and `JANUS_DUTY_SIGNING_KEY_FILE`. Enforced posture
requires `JANUS_ACCOUNTABILITY_CUTOVER_FILE`.

Recorded actions in observe/enforced posture require a fresh, single-use,
domain-service-signed `AuthoritativeOperationRefV1` supplied through the private
reviewed `JANUS_RUNTIME_OPERATION_REFERENCE_FILE`. The caller cannot submit an
actor, UID, duty, transport, or posture. No-conflict actions reject operation
authority and still require a healthy verified journal.

## Migration and cutover

Before changing from observe to enforced:

1. map every active legacy binding to one enrolled stable subject and review
   aliases/shared OS accounts;
2. durably close or cancel every legacy authority operation so
   `active_legacy_operations` is zero—an empty new journal is not evidence;
3. confirm at least two active enrolled subjects and complete the observation
   window with no unexplained mapping or duty mismatch;
4. back up the subject registry, broker trust material, duty epochs/journal,
   index, and audit linkage as one release/scope-bound set;
5. complete a restore rehearsal and record its fingerprint; and
6. create the strict cutover record with the exact release, scope, duty-surface
   fingerprint, migration/backup/restore/observation fingerprints, zero open
   trust-root recovery, and supported rollback actor/duty schemas.

The broker independently verifies journal/index integrity, active subject
count, and every cutover field at startup. Any mismatch blocks readiness.

## Recovery and rollback

Restore into an absent private directory and verify the epoch chain, every
journal signature/hash/sequence, and the rebuilt index before readiness. A
lost or unverifiable history fails closed; never create an empty replacement.
A trust-root recovery keeps the deployment non-enforcing until an independent
subject reviews and closes it. A solo installation cannot close that event or
claim `enforced_recorded`.

Code rollback after enforcement must retain actor schema 1, duty schema 1, the
subject registry, journal, audit, and broker. If an incident forces a change to
`accountability_legacy`, stop conflict-bearing operations first, record the
critical incident, keep all recorded history, and require independent closure.
Never delete history to make an older binary start.

## Verification

Run `scripts/assure-engine-release.sh`. Its accountability gate checks exact
catalog coverage and production call-site wiring, then exercises the complete
nine-conflict matrix, different-subject success, observation behavior, journal
tamper/restart/concurrency/recovery, value-free output, and socket authentication.
The release may be described as `enforced_recorded` only after the exact merged
artifact is deployed and a live broker admission reports that posture.
