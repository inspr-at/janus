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
reservation. It validates and immediately zeroizes an import or internally
generated value while persisting only a value-free admission receipt.
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
- `POST /managed-environment/setup/admit` to admit exactly one proof-bound
  import or internal generation after the durable reservation, without custody
  or a downstream transaction.

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
`<JANUS_DATA_DIR>/managed-dynamic-setup-replays.json`. The strict v2 document
contains only intent, nonce, opaque operation, exact-target fingerprint, and
bounded timestamps. It is private, size- and entry-bounded, atomically replaced,
validated on restart, and prunes expired entries only as part of a successful
new reservation. Concurrent intent or nonce reservation has one winner. A
store that is missing after proof issuance, corrupt, unsafe, full, or
unwritable fails closed; it never falls back to browser state.

No current deployment configuration enables this capability. This slice does
not create custody records, materialize an environment file, contact a host,
restart a service, or expose a Pharos API. The staged admission boundary
accepts one value only to prove the browser-to-memory contract, erases it before
writing the value-free completion state, and cannot recover or deliver it.
Custody and every host effect require separate reviewed slices.

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
submissions. After validation and zeroization, a second durable write marks the
value-free admission receipt complete. Restart and refresh recover only
`started`/`complete` state; the replay document contains no value, ciphertext,
digest, browser body, or generated bytes. A duplicate POST does not read value
bytes and resolves to the existing safe state.

The completed page says **Value checked and forgotten**, clears first-party
cache and storage, and contains no value input, reveal, copy, custody, delivery,
reload, or health claim. The capability remains explicitly default-off.

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
