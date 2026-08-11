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
denies every request.

Each newline-delimited JSON request is bounded to 16 KiB:

```json
{"schema_version":1,"scope_ref":"scp_...","surface":"janusd-use"}
```

Unknown fields, malformed frames, unregistered surfaces, unenrolled or
ambiguous peers, and over-capacity connections return or cause a value-free
denial. A long-lived channel is registry-resolved again for every request, so
revocation takes effect without trusting session metadata.

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
