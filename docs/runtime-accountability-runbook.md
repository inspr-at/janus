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

## Broker sidecar lifecycle

`janusd-identityd` is commonly run as a short-lived sidecar around a render
cycle. Its state must outlive the sidecar, its socket must not:

- Keep `JANUS_IDENTITY_REGISTRY_ROOT` and `JANUS_RUNTIME_AUTHORITY_AUDIT_FILE`
  on persistent private storage (0700 directory, 0600 files) outside any
  container-ephemeral layer. The registry directory may contain only
  `.registry.lock`, `<act_ref>.json`, and `<act_ref>.revoked.json`; any other
  entry (a backup, a note) makes the whole registry unavailable and every peer
  is denied. Keep backups elsewhere.
- On start the broker reclaims a **dead** socket left by a previous instance —
  a real socket, owned like its private parent directory, refusing connections
  (probed up to ten times over half a second, so a predecessor that is still
  exiting is not mistaken for a live broker) — and serves on the same path. A live broker, a symlink, a non-socket file, or a
  socket owned by another user stops startup with `identity_socket_occupied`.
- Readiness is **accept-connect**, never file existence: a leftover socket file
  exists before the broker listens. Gate Warden and `janusd-use` on a successful
  `AF_UNIX` connect as the peer UID that will use the socket; optionally send
  `{"schema_version":1,"scope_ref":"scp_…","surface":"janusd-use"}` and expect
  any value-free reply. `scripts/smoke-janusd-identity.sh` is the reference.
- The broker holds a shared lifecycle lock beside the registry
  (`<registry-root>.lifecycle.lock`, owner-only) for its lifetime;
  `janusd-identity-admin` mutations need the exclusive lock and fail closed
  with `identity_broker_running` while the broker runs. If the lock cannot be
  created the broker reports it and still starts; the administrator then
  refuses. Optionally pin `JANUS_ACCOUNTABILITY_CONFIG_FILE`; when set, the
  broker requires it to agree with `JANUS_ACCOUNTABILITY_POSTURE`
  (`runtime_authority_posture_config_mismatch`), and the administrator reads
  its posture from the same file.
- On `SIGTERM`/`SIGINT` and on any exit path the broker unlinks its own socket
  (only if the path is still a socket) and exits 0. A lifecycle that stops the
  sidecar with `SIGKILL` should still unlink the path itself; the next start
  reclaims it either way.

## Reason codes and denial evidence

Every broker decision leaves one `RuntimeAuthorityAuditV1` line in
`JANUS_RUNTIME_AUTHORITY_AUDIT_FILE`: admissions with `outcome` `allowed` or
`observed_conflict`, denials with `outcome` `denied` and the specific value-free
`reason_code`. A denial records `actor_subject_ref` as `unresolved` and only the
request fields the broker could verify (scope, action, surface, transport);
never a UID, PID, path, or value. A frame that never became a request is audited
as `runtime_authority_request_invalid`. The first `allowed` line for a freshly
enrolled subject is the enrollment proof. Do not wait for a denial code before
enrolling: an empty registry denies every peer by design.

The peer receives the same reason code in its value-free reply, and clients
separate three failure classes before any broker code is considered:

| Client reason code | Meaning | Typical cause |
| --- | --- | --- |
| `runtime_authority_unavailable` | The broker was never reached or the client configuration is incomplete | missing socket/manifest/key variables, broker sidecar not running, stale socket file, connect or read timeout |
| `runtime_authority_reply_invalid` | The broker answered, but not with a value-free v1 reply | version skew, a foreign process on the socket |
| `runtime_authority_denied` | The broker answered `ok:false`; `broker_reason_code` carries its code | see broker codes below |

Broker codes (returned and audited): `subject_not_enrolled`,
`runtime_authority_request_context_mismatch` (scope or audit linkage),
`runtime_authority_transport_mismatch`, `runtime_authority_operation_missing`,
`runtime_authority_operation_unexpected`, `runtime_authority_operation_mismatch`,
`runtime_authority_request_invalid`, and `runtime_authority_request_denied`
(no runtime authority attached to the socket). Startup codes stop the broker
before it serves and are printed by `janusd-identityd` as
`reason_code=<code> value_returned=false`: `runtime_authority_audience_invalid`,
`runtime_authority_ttl_invalid`, `runtime_authority_release_digest_invalid`,
`runtime_authority_manifest_fingerprint_mismatch` (the duty-surface manifest
does not bind the loaded identity-transport manifest, usually a reformatted
vendored JSON), `runtime_authority_surface_mismatch`,
`runtime_authority_cutover_unexpected`, `enforced_recorded_not_ready`,
`enforced_recorded_subjects_mismatch`, and `identity_socket_occupied` (the socket
path holds a live broker, a symlink, a non-socket file, or a socket owned by
another user; a dead socket left by a previous broker is reclaimed).
`janusd-identity-admin` (offline enrollment, see
[`identity-shadow-runbook.md`](identity-shadow-runbook.md#first-host-enrollment-janusd-identity-admin))
reports `identity_admin_caller_invalid`, `identity_registry_security_invalid`,
`identity_broker_running`, `identity_posture_unknown`,
`identity_posture_mutation_forbidden`, `identity_review_invalid`,
`identity_review_signature_invalid`, `identity_review_context_mismatch`,
`identity_review_expired`, `identity_review_replayed`,
`identity_admin_audit_unavailable`, and the registry's own
`subject_already_enrolled`, `subject_not_enrolled`, `subject_already_revoked`. Warden structured errors expose
`reason_code` and, when the broker answered, `broker_reason_code`; the CLI
prints the code inside its error chain. No code is ever accompanied by a secret
value, a credential path, or free text from the wire.

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
