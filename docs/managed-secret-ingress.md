# Managed-service secret web ingress

JANUS-357 adds Janus's only human value-bearing web boundary. It is a
first-party browser flow for a Pharos-issued, signed, declaration-bound setup
intent. It does not add a value-bearing API, Warden method, Pharos method, CLI
argument, JSON request, or agent tool.

## Additive dynamic-environment ingress contract

JANUS-392 defines the value-free Janus ingress contract for a future dynamic
environment binding beneath a pre-approved service policy. JANUS-393 adds a
separate, guarded review and fresh-passkey session for that exact v2 target.
JANUS-395 adds the durable, single-use reservation that burns the exact intent
and nonce only after the passkey and current target have been revalidated.
JANUS-396 adds one bounded, single-use value-admission window after that
reservation. JANUS-397 carries that value across a private, preflight-first
Unix socket into one independently Age-encrypted custody object and persists
only opaque, value-free custody references. JANUS-398 then reopens that exact
custody object inside a second private daemon, creates a separately signed Age
packet for the declared host, and persists it in a private Janus outbox.
JANUS-399 adds the corresponding local host acceptance boundary: a strict
version 2 executor configuration may accept a `create` packet only for an
exact root-owned dynamic service policy and atomically rebuild that service's
private aggregate environment file. JANUS-400 adds the separate transport
boundary: the enrolled host agent may claim only its exact package through the
existing host-token model, install it with the v2 executor only when no v1
lease is pending, and return a strict value-free materialization receipt.
JANUS-401 binds that claim to the exact pre-approved reload and health profiles,
force-recreates the fixed Compose service, and returns a strict value-free
active receipt only after a fresh bounded healthy observation. It still
performs no replacement, removal, deployment enablement, or Pharos/nixcfg
change.
The existing v1 declared-slot flow described below remains unchanged and is
still the only production value-bearing path.

The additive v2 handoff uses the schemas
`inspr.janus.signed-managed-environment-setup-intent.v2` and
`inspr.janus.managed-environment-setup-intent.v2`, with a distinct Ed25519
signature domain. The producer-facing, value-free payload fixture is
`contracts/managed-dynamic-env-setup-intent-v2.json`. Before any later boundary
may ask for a value, Janus verifies
the signing key, signature, version, opaque intent and nonce, human session,
issuer, audience, bounded lifetime, and fixed Pharos return kind. It then
re-resolves a root-owned `inspr.janus.managed-service-declaration.v2` and
requires exact equality for:

- host, service, declaration fingerprint, environment-policy reference, and
  environment-policy fingerprint;
- operation kind (`create` or `replace`) and one policy-allowed source;
- the environment name, byte-for-byte, under `portable_secret_env_v1`, including
  global execution-critical and service-specific reserved-name denial; and
- the policy-owned delivery, reload, health, capacity, and source constraints.

Strict JSON rejects unknown fields on the outer envelope, signed payload, and
local declaration. In particular, the signed payload cannot carry a secret,
ciphertext, path, command, callback URL, delivery/reload/health profile, or slot
override. Policy absence and every target or generation mismatch fail closed.

The v2 browser slice exposes only:

- `GET /managed-environment/setup?intent=intent_…` to re-inspect and display
  the exact signed host, service, policy, declaration, variable, source, and
  operation; and
- `POST /managed-environment/setup/step-up` to start a fresh passwordless OIDC
  authorization-code + PKCE flow for that exact target; and
- `POST /managed-environment/setup/admit` to place exactly one proof-bound
  import or internal generation into Janus-only encrypted custody after the
  durable reservation.

The dynamic flow, retry breadcrumb, and proof use distinct v2 signature
domains and cookie names. Each carries the complete value-free signed intent
identity and target, including issuer, audience, nonce, validity window, fixed
return kind, and the one-way human-session reference. Janus re-inspects the authoritative signed
intent before step-up and again at the OIDC callback. Only after the fresh
passkey and exact current target pass does Janus atomically reserve the intent
and nonce, then bind the resulting opaque operation reference into the signed
proof. Every confirmed-page load re-inspects the target and recovers that same
durable reservation before accepting the proof. Any field or policy drift,
mixed v1/v2 flow state, stale assertion, different identity, non-passkey AMR,
copied link, replayed nonce, missing reservation, or changed operation fails
closed. The confirmed page exposes the value form only while the exact proof
and reservation are current and the single-use admission window is unspent.

JANUS-394 provides the production construction seam for the v2 intent
authority, but it is a separate capability that defaults off. Existing v1
managed-setup configuration cannot enable it. The v2 authority is constructed
only when all of the following are present:

| Environment variable | Contract |
| --- | --- |
| `JANUS_MANAGED_DYNAMIC_SETUP_ENABLED` | Must be exactly `true`; unset or `false` keeps the capability off. |
| `JANUS_MANAGED_DYNAMIC_SETUP_CONTROL_PLANE_ORIGIN` | One origin-only HTTPS URL. |
| `JANUS_MANAGED_DYNAMIC_SETUP_INTERNAL_TOKEN_FILE` | Absolute deployment-selected file containing a whitespace-free token of at least 32 bytes; the file is bounded and must not be group/world accessible. |
| `JANUS_MANAGED_DYNAMIC_SETUP_VERIFICATION_KEYS_FILE` | Absolute path to a bounded strict verification-key document used for Ed25519 key rotation. |
| `JANUS_MANAGED_DYNAMIC_SETUP_DECLARATION_PATHS` | Comma-separated, unique absolute paths to the root-owned v2 service declarations. |
| `JANUS_MANAGED_DYNAMIC_CUSTODY_SOCKET` | Absolute path to the private custody-only Rust daemon socket. |
| `JANUS_MANAGED_DYNAMIC_DELIVERY_SOCKET` | Different absolute path to the private host-package preparation socket. |
| `JANUS_MANAGED_DYNAMIC_TRANSPORT_SOCKET` | Third, distinct absolute path to the private outbox-claim and receipt daemon socket. |
| `JANUS_MANAGED_DYNAMIC_HOST_TOKEN_GENERATION_DIR` | Absolute private directory containing the existing enrolled-host token generation. |

Detail configuration without the exact enable flag, an invalid flag, partial
configuration, a non-HTTPS origin, an unsafe token file, an invalid key
document, or an invalid declaration-path set fails startup. This is deliberate:
operators cannot mistake staged detail configuration for an enabled
capability.

When enabled, Janus derives a fixed
`/internal/managed-environment-setup-intents/<intent_ref>` path only from the
validated opaque reference. The fetch is bearer-authenticated, requests JSON
with identity encoding and no storage, times out after five seconds, refuses
redirects, and bounds the response to 64 KiB. Janus accepts only the strict
signed v2 envelope or the strict value-free
`inspr.pharos.managed-environment-setup-intent-delivery.v2` denial. It then
performs the existing signature, identity, lifetime, and local declaration
resolution before returning an inspection to the passkey flow.

The enabled authority stores reservations separately from v1 in
`<JANUS_DATA_DIR>/managed-dynamic-setup-replays.json`. The strict v3 replay document
contains only intent, nonce, opaque operation, exact-target fingerprint,
bounded timestamps, and—after successful package preparation—opaque binding,
secret, generation, package, and envelope references. It is private, size- and entry-bounded, atomically
replaced, validated on restart, and prunes expired entries only as part of a
successful new reservation. Concurrent intent or nonce reservation has one
winner. A store that is missing after proof issuance, corrupt, unsafe, full,
or unwritable fails closed; it never falls back to browser state.

No current deployment configuration enables this capability. Janus can create
encrypted custody and a host-bound package in its private outbox, and the
enrolled host agent can claim that package for the exact host, ask the version
2 executor to materialize the pre-approved service's private aggregate, and
return value-free active evidence after force-recreating the exact
outbox-bound service and observing it healthy. There is still no Pharos
operation registration, replacement, or removal claim. Each remains a
separate reviewed slice.

## Dynamic value admission boundary

The v2 admission form uses the same fixed field order as the reviewed v1
boundary: `csrf_token`, `intent_ref`, `source`, then `secret_value`. Janus
validates the same-origin Fetch Metadata and exact Origin, strict form media
type, fixed and bounded content length, current authenticated human session,
CSRF, signed proof, exact proof target, source, operation reference, current
declaration, and durable reservation before reading bytes after the
`secret_value=` delimiter.

An imported value must decode in place to 1–1024 bytes of valid UTF-8 and must
not contain NUL, CR, or LF. Malformed escapes, extra fields, incomplete bodies,
unsupported sources, and encoded or decoded overflow fail closed. Generated
mode requires an empty browser value and creates 32 bytes of operating-system
randomness encoded with unpadded URL-safe Base64 inside Janus. The entropy,
generated value, encoded request bytes, and decoded import share owned mutable
buffers that are zeroized on every return path.

Before reading or generating a value, Janus durably marks the reserved
operation's admission window as started. That gives concurrent requests one
winner and intentionally burns malformed, interrupted, or disconnected
submissions. The Go envelope then sends a strict value-free request to
`janusd-dynamic-custodyd`. The daemon re-resolves the same root-owned v2
declaration before replying `preflighted`; only then does Go send one bounded
raw value frame. Both sides zeroize owned plaintext buffers on every path.

The daemon derives deterministic opaque `bind_`, `sec_`, and `gen_` references
from the reserved operation and uses only the `sec_` reference to derive the
private ciphertext filename. It accepts no path or friendly filename. The Age
provider installs ciphertext with create-new semantics, so it can never
overwrite an existing object. A separate strict receipt records the exact
target, source, operation kind, opaque references, `phase=custodied`, bounded
timestamps, and `value_returned=false`; it contains no value, value digest,
ciphertext, or path. If a response is lost after encryption, the same request
reconstructs or reloads that receipt from the deterministic ciphertext
reference without accepting the value again.

After custody succeeds, Go sends only the exact target and three custody
references to `janusd-dynamic-deliveryd`. That daemon independently re-resolves
the current declaration, custody receipt, ciphertext, and root-owned delivery
profile. It decrypts custody only in bounded memory, encrypts a distinct
dynamic payload to the profile's single host recipient, signs it with the
profile's Ed25519 producer key under a dynamic-only signature domain, and
installs one create-new outbox record. The payload binds the target, policy,
declaration, variable name, custody references, delivery/reload/health profile
references, revocation epoch, and bounded validity window. Neither packet nor
value is returned over the socket.

Only after the delivery daemon returns the opaque `pkg_` and `env_` references
does Go mark admission complete with all five references. The replay document contains no
value, ciphertext, digest, browser body, generated bytes, or filesystem path.
A duplicate browser POST does not read value bytes and resolves to the existing
safe state.

The completed page clears first-party cache and storage, then asks the private
transport for the exact operation, package, envelope, binding, generation,
policy, reload profile, and health profile. It says **Waiting for the host**
while no receipt exists, reports expiry or an unavailable check without
claiming success, and says **Environment variable active** only when the exact
integrity-bound host receipt exists. The browser receives no packet, value,
runtime path, command, probe, or evidence detail. The capability remains
explicitly default-off.

The custody daemon is separately configured and has no HTTP listener, Pharos
client, host-delivery outbox, or lifecycle bridge:

| Environment variable | Contract |
| --- | --- |
| `JANUS_MANAGED_DYNAMIC_CUSTODY_SOCKET` | Absolute private Unix-socket path; shared with the Go envelope. |
| `JANUS_MANAGED_DYNAMIC_CUSTODY_ALLOWED_UID` | Exact kernel-reported UID permitted to connect. |
| `JANUS_MANAGED_DYNAMIC_CUSTODY_DECLARATION_PATHS` | Comma-separated unique absolute v2 declaration paths re-resolved by Rust. |
| `JANUS_MANAGED_DYNAMIC_CUSTODY_STORE_DIR` | Absolute private root for independently encrypted `.age` objects. |
| `JANUS_MANAGED_DYNAMIC_CUSTODY_RECEIPT_DIR` | Different absolute private root for strict value-free receipts. |
| `JANUS_AGE_RECIPIENT` or `JANUS_AGE_RECIPIENTS_FILE` | Existing reviewed native-Age or SSH-Ed25519 recipient configuration. |

The delivery daemon is a second no-argv process with no HTTP listener, Pharos
client, host executor, reload, or health code:

| Environment variable | Contract |
| --- | --- |
| `JANUS_MANAGED_DYNAMIC_DELIVERY_SOCKET` | Absolute private Unix-socket path; shared with the Go envelope and distinct from custody. |
| `JANUS_MANAGED_DYNAMIC_DELIVERY_ALLOWED_UID` | Exact kernel-reported UID permitted to connect. |
| `JANUS_MANAGED_DYNAMIC_DELIVERY_DECLARATION_PATHS` | Comma-separated unique absolute v2 declarations re-resolved by Rust. |
| `JANUS_MANAGED_DYNAMIC_DELIVERY_PROFILE_FILE` | Strict private catalog binding host, service, delivery profile, one host recipient, signing-key file, revocation epoch, TTL, and private outbox. |
| `JANUS_MANAGED_DYNAMIC_DELIVERY_CUSTODY_STORE_DIR` | Exact private custody root; filenames are derived only from validated `sec_` references. |
| `JANUS_MANAGED_DYNAMIC_DELIVERY_CUSTODY_RECEIPT_DIR` | Exact private receipt root; filenames are derived only from validated `op_` references. |
| `JANUS_AGE_IDENTITY_FILE` or `JANUS_AGE_IDENTITY_FILES` | Existing private Age identity configuration used only to open the exact custody object. |

The daemon also requires the normal release-admission, migration-ready, and
scope-transfer-ready environment used by Janus lifecycle entry. Startup or a
request fails closed if any boundary, declaration, recipient, directory,
receipt, ciphertext, peer identity, or release gate is invalid.

The transport daemon is a third no-argv process. It never decrypts a packet,
contacts a host, reloads a service, or inspects health. Its version 3 private
wire contract exposes only exact host claim, exact activation-receipt, and
exact value-free status operations to the Go envelope. The persisted receipt
contract remains version 2 so existing active receipts stay readable. Every
status lookup revalidates the private outbox record and all outbox-bound
references before returning only `pending`, `expired`, or `active`:

| Environment variable | Contract |
| --- | --- |
| `JANUS_MANAGED_DYNAMIC_TRANSPORT_SOCKET` | Absolute private Unix-socket path; shared with the Go envelope and distinct from custody and delivery. |
| `JANUS_MANAGED_DYNAMIC_TRANSPORT_ALLOWED_UID` | Exact kernel-reported UID permitted to connect. |
| `JANUS_MANAGED_DYNAMIC_TRANSPORT_PROFILE_FILE` | Existing strict delivery catalog used to locate and revalidate the exact host outbox. |
| `JANUS_MANAGED_DYNAMIC_TRANSPORT_RECEIPT_DIR` | Separate private root for integrity-bound, create-new, value-free active receipts. |

When the dynamic capability is enabled, the Go envelope also requires
`JANUS_MANAGED_DYNAMIC_HOST_TOKEN_GENERATION_DIR`, the existing private
host-token generation directory. The host agent authenticates its exact
`host_` reference, receives only the still-encrypted packet, calls
`install-dynamic`, validates the returned identity and materialized outcome,
resolves the exact fixed runtime target from the outbox-bound reload and health
references, force-recreates that service, and submits a receipt containing no
packet or value only after a fresh bounded healthy observation. Lost responses
retry idempotently; invalid earlier outbox state, cross-host claims, unknown or
ambiguous runtime targets, mismatched outcomes, stale health, and conflicting
receipts fail closed.

## Route and trust boundary

The four v1 declared-slot UI-only routes are:

- `GET /managed-service/setup?intent=intent_…` — inspect the signed intent and
  render value-free context.
- `POST /managed-service/setup/step-up` — require the authenticated
  `lifecycle.entry` permission, exact `Origin`, same-origin Fetch Metadata,
  strict CSRF, and a body containing only the CSRF token, intent reference, and
  one source selected from the intent's signed declaration policy.
- `POST /managed-service/setup/execute` — require the same controls plus a
  fresh signed step-up proof, consume the intent, and only then read the
  value-bearing field.
- `GET /managed-service/setup/complete/op_…` — require the same authenticated
  human session plus a short-lived signed completion receipt, render the
  value-free **Check** state, and continue to the exact Pharos operation.

The setup intent is kept across an ordinary login in a short-lived signed,
HttpOnly, SameSite=Lax cookie. It contains only the opaque intent reference and
timestamps. The normal login flow clears a stale setup cookie.

Pharos gives the signed outer setup intent a maximum fifteen-minute lifetime.
Janus independently rejects any longer lifetime. This allows bounded page
review plus a complete five-minute passwordless step-up without making the
step-up proof reusable: that proof still expires after five minutes, and intent
consumption remains the single-use authority before any value byte is read.

All managed setup responses are `no-store, no-transform` with identity content
encoding. The global Janus boundary also supplies a no-script, no-third-party
CSP, framing isolation, and same-origin resource policy. Managed form pages use
an origin-only referrer so Chromium supplies the non-null exact `Origin`
required by the same-origin POST gate without forwarding an intent-bearing
path.

## Passwordless step-up

Step-up starts a new authorization-code + PKCE flow with a new state, nonce,
`prompt=login`, and `max_age=0`. The pre-step-up browser session is bound through
a signed flow cookie containing only the intent reference, selected source, a
one-way human session reference, the state hash, and timestamps.

Janus accepts the callback only when:

- the signed flow, OIDC state, nonce, PKCE, issuer, audience, token signature,
  subject, and current role mapping are valid;
- the new subject hashes to the same human-session reference;
- `auth_time` is no more than five minutes old, allowing only the reviewed clock
  skew; and
- the ZITADEL `amr` set is exactly `user` plus `mfa`.

ZITADEL's OIDC implementation maps a passwordless passkey to `user` + `mfa`.
A password with U2F also contains `pwd`, so exact matching prevents that flow
from satisfying this passwordless gate. See the
[ZITADEL claims reference](https://zitadel.com/docs/apis/openidoauth/claims) and
the [ZITADEL AMR mapping](https://github.com/zitadel/zitadel/blob/ca6595f8c59299d1aa971b06d098b839b4edd959/internal/api/oidc/amr.go).

The resulting proof is signed, HttpOnly, SameSite=Strict, bound to the exact
intent, selected source, and human-session reference, and expires no later than
five minutes after the asserted authentication time. Changing Generate to Paste
or Paste to Generate after step-up fails before any value byte is read. Logout
and clean auth reset clear all flow, proof, and managed-login cookies.

OIDC state, nonce, PKCE, and the authoritative step-up flow still expire after
five minutes. A separate signed, HttpOnly, SameSite=Lax retry breadcrumb lasts
at most fifteen minutes and contains only the exact intent reference, a hash of
the one-time OIDC state, and timestamps. It is not a passkey proof and cannot
consume an intent or execute a transaction. If the OIDC cookies expire, Janus
accepts the breadcrumb only for the callback carrying that exact one-time state,
then consumes it and returns to the exact **Confirm** screen. Unrelated, invalid,
or expired callbacks fail closed.

Successful login and step-up callbacks render a value-free Janus continuation
document before entering the protected target. The document continues
immediately and provides a same-origin fallback link. This ends the cross-site
OIDC navigation before the next protected request, so browsers can send the
host-only SameSite=Strict session and step-up cookies without
weakening either cookie to Lax. Continuation targets are limited to the normal
login allowlist or one exact managed setup intent; absolute URLs, extra query
keys, fragments, control characters, and unknown continuation kinds fail
closed.

## Simple managed-service UI

Pharos is the entry point. Its service detail renders only reviewed declarations
and gives a missing slot one primary action: **Add missing secret**. The browser
does not provide editable host, service, slot, path, command, callback, or
source fields to Pharos. Pharos signs the slot's complete reviewed source
policy and sends only the opaque intent reference to Janus.

Janus re-resolves that declaration and renders one compact locked-target card
with the safe service, managed host, and slot labels. The four-stage rail stays
**Target → Confirm → Add/Replace/Remove → Check**. Each page presents one
decision or primary action; repeated trust prose and technical references are
collapsed. Janus offers Generate and/or Paste only when present in the signed
source policy, and generated remains the recommended default. The chosen
option is then bound to the fresh passkey flow described above.

The ordinary Vault presents managed records as **Service secret** with
consumer, host, lifecycle, age, rotation, and health metadata; it never renders
reveal or copy actions. `/vault/new` is labelled **Advanced manual setup** and
remains a configuration-only fallback.

## V1 one-time custody path

The browser submits a regular HTML form in this exact field order:

1. `csrf_token`
2. `intent_ref`
3. `source`
4. `secret_value`

Janus reads only the bounded value-free prefix first. It checks the exact
content type, fixed content length, absence of transfer/content encoding,
same-origin headers, CSRF token, signed step-up proof, session binding, intent
reference, and proof-bound source. It then durably consumes the signed setup
intent and replay nonce before reading the first value byte.

For import, the remaining `application/x-www-form-urlencoded` bytes are decoded
in place in one owned byte buffer. Extra fields and malformed escapes fail
closed. That buffer is passed once to the typed local Rust transaction client
and zeroized on every return path. Generated mode requires an empty value field
and passes no value bytes.

The UI uses a masked, single-line, bounded input with autocomplete, spellcheck,
capitalization, and common password-manager capture disabled. It has no reveal
or copy action and no script. Completion clears first-party browser cache and
storage without clearing the authenticated session.

After one accepted transaction, Janus writes a signed, host-only, HttpOnly,
Secure, SameSite=Strict completion receipt. It contains only the exact intent,
operation, operation kind, selected source, one-way human-session reference,
and bounded timestamps. The POST redirects to a same-origin GET completion
page before the browser leaves Janus. That page marks **Check** current,
announces concise value-free progress, automatically opens the exact Pharos
operation after one second, and retains an ordinary fallback link.

This same-origin POST/Redirect/GET handoff is deliberate. Chromium applies
`form-action` across form-response redirects, so a direct POST redirect to the
separate Pharos origin can be blocked after the operation already succeeded.
The completion page fixes navigation without allowlisting Pharos as a form
destination, adding browser script, weakening `script-src 'none'`, or retaining
the value.

## Retry and failure semantics

- A malformed or unauthenticated request cannot consume an intent or read the
  value field.
- Once the intent is consumed, any incomplete body, disconnect, timeout, or
  downstream failure intentionally burns that intent. This is a
  security-over-availability choice: recovery starts with a new Pharos intent
  so no retry can replay a value after Janus has admitted it into memory.
- Refresh, back, an interrupted cross-origin navigation, and an immediate
  repeated POST resolve through the exact completion receipt to the already
  created operation. The receipt expires after ten minutes; replay storage
  remains the durable boundary preventing a second typed transaction or second
  import.
- Successful completion redirects with HTTP 303 to the same-origin completion
  GET, which then opens the configured Pharos operation URL. Both URLs contain
  only the opaque operation reference.
- Responses and audit contain controlled reason classes, request/operation/
  secret references where appropriate, and `value_returned=false`; they never
  contain the submitted bytes.

The client boundary admits signed `create` and `replace` operation kinds.
Replacement uses the staged JANUS-362 executor only when Rust finds an exact
reviewed replacement catalog entry and a current active generation. A denied
replacement never causes the client to send the imported value frame; the
Rust catalog resolver independently proves `replace` is denied without that
exact entry.
