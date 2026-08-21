# Authenticated actor identity-shadow runbook

Status: implemented foundation for JANUS-427. This slice authenticates local
kernel peers and emits signed, value-free observations. JANUS-428 adds the
separate [durable duty journal foundation](durable-duty-journal.md), but runtime
surfaces still use the legacy posture. Identity shadow does **not** grant runtime
authority or make separation of duties `enforced`.

## What is active

`janusd-identityd` listens only on a private filesystem Unix socket. For every
request, it obtains the connected peer credentials from the kernel, resolves
the UID through the private subject registry, creates a fresh broker-internal
actor assertion, and returns a signed observation. Requests contain only an
opaque scope and a release-reviewed surface; there is no actor, UID, account,
principal, model, or session field a caller can substitute.

Every output is fixed to posture `identity_shadow_only`, authority `none`, and
`value_returned=false`. An observation is short-lived, audience- and
release-bound, channel-bound, and signed over every field.
`IdentityObservationVerifier::verify_once` also checks the closed transport
manifest and consumes the nonce, so replay, copied surfaces, wrong transports,
stale releases, wrong audiences, forged signatures, expiry, and unknown
endpoints fail closed.

## Private state

Run the broker as a dedicated account. Its socket directory, subject registry,
and signing-key directory must be mode `0700`; sockets and files must be mode
`0600`. The registry rejects symlinks, unknown entries, public permissions,
malformed records, orphan revocations, duplicate active UIDs, and excessive
inventory. Enrollment and revocation records are immutable. Revoking and later
re-enrolling the same UID creates a new `ActorSubjectRef`; the old ref is never
reassigned.

Raw local UIDs exist only in private enrollment records and broker memory.
Public inventory, errors, debug output, observations, CLI/MCP output, and
migration evidence contain opaque refs only. Subject enrollment and revocation
are library control-plane operations in this slice; do not hand-author registry
JSON. A reviewed operator surface that can safely determine a subject from its
own authenticated channel is intentionally deferred instead of accepting a raw
UID on argv, MCP, or an environment variable.

## Broker configuration

The daemon accepts no arguments. It requires these environment variables:

| Variable | Meaning |
| --- | --- |
| `JANUS_IDENTITY_SOCKET` | New private Unix socket path; an occupied path is denied. |
| `JANUS_IDENTITY_REGISTRY_ROOT` | Private subject-record directory. |
| `JANUS_IDENTITY_SIGNING_KEY_FILE` | Private raw Ed25519 key; created once if absent. |
| `JANUS_IDENTITY_TRANSPORT_MANIFEST` | Exact reviewed V1 manifest path. |
| `JANUS_IDENTITY_TRUST_DOMAIN` | Stable local deployment trust domain. |
| `JANUS_IDENTITY_AUDIENCE` | Exact observation consumer audience. |
| `JANUS_RELEASE_DIGEST` | Admitted `sha256:` release digest. |
| `JANUS_IDENTITY_ASSERTION_TTL_SECONDS` | Optional lifetime, default 60 and maximum 300. |

The released container installs the manifest at
`/etc/janus/identity-transport-manifest-v1.json`, provides private mount points
at `/run/janus/identity` and `/var/lib/janus/identity`, and exposes no network
port. A deployment still needs reviewed enrollment through an embedding
control plane before a peer can receive an observation; an empty registry
denies every request. On start the broker reclaims a dead socket left by a
previous instance and refuses a live or foreign one (`identity_socket_occupied`);
on `SIGTERM`/`SIGINT` it unlinks its socket and exits 0. Readiness is a
successful connect, not the socket file's existence — see
[`runtime-accountability-runbook.md`](runtime-accountability-runbook.md#broker-sidecar-lifecycle).

## First host enrollment (`janusd-identity-admin`)

Enrollment is a reviewed, offline, authority-side operation — never a
hand-written registry file. `janusd-identity-admin` ships beside
`janusd-identityd`, runs as the registry owner while the broker is stopped,
consumes signed operation-bound review evidence, and writes a fail-closed
write-ahead audit. It is not a runtime-plane action and needs no broker
admission, which is what makes the first subject possible.

Reviewer side (the person who approves, on their own machine):

1. `janusd-identity-admin review-keys --signing-key-file reviewer.key --verifying-key-file reviewer.pub`
   creates the reviewer key once and prints its `reviewer_key_ref`. Pin
   `reviewer.pub` on the host as `JANUS_IDENTITY_REVIEW_VERIFYING_KEY_FILE`
   through the deployment controller; the private key never leaves the
   reviewer.
2. Write the request as a private file — never on argv:
   `{"schema_version":1,"verb":"enroll","trust_domain":"<exact JANUS_IDENTITY_TRUST_DOMAIN>","local_uid":65532,"subject_class":"system","ttl_seconds":3600,"reviewer":"NIX-377 …"}`
   (`verb:"revoke"` takes `subject_ref` instead of `local_uid`/`subject_class`).
3. `janusd-identity-admin review-sign --request-file req.json --signing-key-file reviewer.key --out evidence.json`
   produces the signed envelope: verb, trust-domain fingerprint, target, a
   single-use nonce, validity window (at most seven days), and the reviewer
   key reference. Hand `evidence.json` to the host.

Host side (as the broker's UID, broker stopped):

- Environment: `JANUS_IDENTITY_REGISTRY_ROOT`, `JANUS_IDENTITY_TRUST_DOMAIN`,
  `JANUS_IDENTITY_REVIEW_VERIFYING_KEY_FILE`, `JANUS_IDENTITY_ADMIN_AUDIT_FILE`,
  and either the pinned `JANUS_ACCOUNTABILITY_CONFIG_FILE`
  (`{"schema_version":1,"posture":"accountability_legacy"}`, read-only, owned
  by root or the broker UID) or `JANUS_ACCOUNTABILITY_POSTURE`.
- `janusd-identity-admin enroll --review-evidence-file evidence.json` prints a
  value-free outcome (`subject_ref`, class, status, `review_fingerprint`).
  `revoke` writes an immutable revocation record; `list` prints opaque refs,
  class, and status and also works while the broker runs.
- Guards, all fail closed: real UID must equal effective UID and the registry
  root's owner; the root must be a pre-owned `0700` directory (never created
  by the tool); the shared lifecycle lock beside the registry must be free
  (`identity_broker_running` otherwise); the posture must not be
  `enforced_recorded` (`identity_posture_mutation_forbidden`); the evidence
  must be a bounded regular file, signed by the pinned reviewer key, bound to
  this trust domain and verb, unexpired, and never consumed before
  (`identity_review_invalid`, `identity_review_signature_invalid`,
  `identity_review_context_mismatch`, `identity_review_expired`,
  `identity_review_replayed`); the `authorized` audit line must be durable
  before the record is written (`identity_admin_audit_unavailable`).
- Proof: the first `allowed` line in `JANUS_RUNTIME_AUTHORITY_AUDIT_FILE`
  after the broker restarts. Keep the registry directory free of anything but
  records and `.registry.lock`; keep backups elsewhere.

Each newline-delimited JSON request is bounded to 16 KiB:

```json
{"schema_version":1,"scope_ref":"scp_...","surface":"janusd-use"}
```

Unknown fields, malformed frames, unregistered surfaces, unenrolled or
ambiguous peers, and over-capacity connections return or cause a value-free
denial. A long-lived channel is registry-resolved again for every request, so
revocation takes effect without trusting session metadata. Runtime-authority
requests (frames carrying an `action`) are answered with their specific
value-free reason code — an unenrolled peer sees `subject_not_enrolled` — and
every such denial is audited; the code table lives in
[`runtime-accountability-runbook.md`](runtime-accountability-runbook.md#reason-codes-and-denial-evidence).

## Closed surface manifest

[`config/identity/transport-manifest-v1.json`](../config/identity/transport-manifest-v1.json)
lists every current CLI, Warden/MCP, and daemon surface and binds the complete
runtime endpoint catalog fingerprint. There are no remote authorizing
transports. Adding, removing, renaming, or changing a runtime endpoint without
updating and reviewing the identity manifest makes manifest loading fail.

The manifest records adapter readiness; it does not mean those runtime
surfaces consume identity observations yet. Until the durable journal slice and
all call-site wiring are complete, deployment posture remains
`identity_shadow_only`.

## Legacy binding migration preflight

`IdentityBindingMigrationManifestV1` maps every current opaque role-binding id
to one active enrolled subject ref and the exact fingerprint of its preserved
technical principal binding. `preflight_identity_binding_migration` is
read-only and rejects missing or extra bindings, duplicate binding mappings,
inactive subjects, and fingerprint drift. Its result always states
`authority_imported=false` and `value_returned=false`; it cannot promote a
legacy alias into actor authority or mutate the role registry.

## Verification

Run the focused foundation checks with:

```sh
cargo test -p janus-core identity --no-fail-fast
cargo test -p janus-local identity --no-fail-fast
cargo test -p janusd --no-fail-fast
```

The tests cover stable opaque subject selection across request/session changes,
distinct and shared OS identities, immutable revoke/re-enroll behavior,
private-file rejection, kernel-connected peer derivation, per-request
reauthentication on long-lived channels, signature/channel/surface tampering,
nonce replay, value-free failures, the closed manifest, and non-mutating
migration preflight.

## Claims that remain forbidden

Do not report `authenticated_observe`, `enforced_recorded`, or enforced
separation from this slice. Signed operation lineage, durable duty admission,
and journal recovery now exist as a broker-only foundation, but the broker does
not yet own every runtime authorization transaction and all-surface cutover.
Those remaining requirements are tracked by JANUS-429 under the accepted
[authenticated principals and durable duty history contract](authenticated-principal-duty-history.md).
