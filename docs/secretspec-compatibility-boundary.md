# Secretspec compatibility boundary (0.20 landscape)

This page is the durable, reviewed record of where upstream
[secretspec](https://secretspec.dev/) 0.20 sits relative to Janus's
compatibility boundary, and why the boundary stays where it is. It
complements, and does not replace, the membership-subset reference that
JANUS-448 / PR #94 owns (the exact field grammar Janus's parser accepts).
This page covers the parts of upstream secretspec Janus deliberately does
**not** speak, and the reasoning for each refusal.

The manifest is an allowlist and membership input, never an authority or
value source. Everything below restates or extends that boundary; it does
not loosen it.

## What upstream secretspec 0.20 added

Upstream secretspec has grown considerably since the JANUS-317 subset was
cut. None of the following is available through Janus's manifest parser:

- **No plugin, exec, or socket provider API.** New providers are compiled-in
  Rust code implementing the upstream `Provider` trait, merged into the
  `secretspec` project itself (see
  [Adding providers](https://secretspec.dev/development/adding-providers)).
  There is no dynamic loading, no subprocess handoff, and no local-socket
  provider protocol to worry about — but there is also no way for a manifest
  alone to select a provider Janus hasn't reviewed and shipped as an
  explicit adapter.
- **`age://` provider.** One age-encrypted file holds a dotenv-style
  `KEY=value` blob for an entire profile; secretspec encrypts it to one or
  more recipients and decrypts it with an identity from a provider
  credential, `AGE_IDENTITY`, or an `?identity=<path>` query parameter (see
  [age provider](https://secretspec.dev/providers/age)). This is
  **explicitly not agenix- or sops-nix/sops-age-compatible**: agenix and
  sops-age manage per-secret or per-document encrypted files with their own
  recipient/rotation model, while secretspec's `age://` re-encrypts one
  whole-profile blob under its own URI and query-parameter conventions.
  Janus's own encrypted production path is the native `SecretStore`
  age-provider crate (JANUS-317), not this URI.
- **Audit and `require_reason`.** Secretspec can log accesses as plain
  JSONL (default shape under a path like `~/.local/state/secretspec/audit.log`
  on the operator's own machine — not a Janus host path) and can set
  `[project].require_reason = "agents"` (or `true`/`false`) to ask a caller
  to state a reason before an access. Both are advisory: the actor field is
  informational (OS user / detected agent, never an authenticated identity),
  audit failures never block access, and there is no cryptographic binding
  between the stated reason and the value released. Janus rejects
  `require_reason` from the manifest for this reason (see below).
- **`[scopes]`, `refs`, `[providers]` aliases, `extends`,
  `composed`/`extract`/`encoding`/`prompt`/`generate`.** Upstream scopes are
  membership-only view filters, matched by JANUS-448's own
  `[scopes.<name>]` (see that ticket / PR #94). Everything else in this list
  is authority- or value-shaping configuration — provider selection or
  fallback, secret-reference coordinates, format transforms, interactive
  prompting, or generation — and stays rejected; see "Why the rejected
  fields stay rejected" below.
- **`systemd-credential://` provider.** Read-only; it reads
  `$CREDENTIALS_DIRECTORY`, the directory systemd populates from
  `LoadCredential=`, `LoadCredentialEncrypted=`, or `SetCredentialEncrypted=`
  unit directives, and keys each credential by its filename (see
  [systemd-credential provider](https://secretspec.dev/providers/systemd-credential)).
  Janus does not implement this provider; see "systemd-credential pattern"
  below for the documented (non-runtime) way a Janus projection can feed
  one.

## The Janus position

Janus speaks **membership semantics only**: which secrets exist in a
profile, how profiles inherit and override each other, and which named
subset a scope exposes (JANUS-448 — non-default profiles are `default ∪
own` with the profile's own `description`/`required` winning,
`[profiles.X.defaults] inherit = false` opts a profile out of that
inheritance, and `[scopes.<name>] secrets = [...]` is a closed-world
membership filter over the already-selected profile; unknown, empty, or
out-of-profile scope members fail closed without naming values). The
`dotenv:<path>` and `dotenv://<absolute-path>` provider forms are 448-landed
parity for the one explicit dotenv backend Janus ships; relative or
authority-looking `dotenv://` forms fail closed.

Janus does not speak **authority or value fields**: no provider selection,
provider fallback chains, or provider aliasing (`providers`, `[providers]`);
no reference coordinates into external stores (`ref`, `refs`); no
manifest-driven config composition (`extends`); no generation
(`generate`/`type`); no default-value fallback (`default`); no derived or
transformed values (`composed`, `extract`, `encoding`); no interactive
prompting (`prompt`); no path-materialization side channel (`as_path`); and
no reason-stapled access gate (`[project].require_reason`,
`defaults.default`, `defaults.providers`). `deny_unknown_fields` rejects all
of these at parse time, value-free.

### Why the rejected fields stay rejected

The common thread is authority or value crossing into the manifest layer,
which is exactly the layer Janus lets an unreviewed party (a checked-in
file, a generated profile, an agent editing a repo) influence:

- `providers` / `[providers]` / `ref` / `refs` would let manifest content
  choose or address a backend Janus hasn't reviewed for that profile,
  turning the parser into a provider-selection surface.
- `extends` would let a manifest pull in configuration from outside the
  reviewed file, defeating manifest-diff review.
- `generate` / `type` / `default` would let the manifest mint or supply
  values itself, which is Forge's job under policy, not a parser's.
- `composed` / `extract` / `encoding` would let the manifest describe value
  transforms, which requires seeing the value — something the membership
  parser never does and must not start doing.
- `prompt` assumes an interactive human at resolution time; Janus's
  resolution paths are unattended service and agent paths.
- `as_path` writes resolved material to a new location outside Janus's
  tracked handoff surfaces.
- `[project].require_reason` (and secretspec's audit log generally) is
  advisory and unauthenticated upstream — informational only, never blocking,
  never signed. Speaking it here would imply Janus treats an unauthenticated
  self-reported reason as policy, which it does not; Janus's evidence is
  signed and value-free by construction instead.

None of this is a statement that these fields are unsafe to use with
upstream secretspec directly — they are reasonable features for secretspec's
own advisory, local-trust model. They are out of scope for a manifest that
Janus treats as an allowlist input inside a brokered, policy-gated boundary.

## JANUS-12 stays cancelled

JANUS-12 ("expose Janus as a secretspec provider") stays cancelled. The hard
reason, restated for 0.20: secretspec has no plugin API — a provider is
compiled-in Rust code — and a provider's `get()` call hands the resolved
value directly into the calling process's memory. That is exactly the L1
boundary Janus refuses to cross: Janus's supported paths return opaque
references and permits, or write reviewed, permissioned materializations
(`env-file`, capability-named projections); they never hand a raw value back
to an arbitrary caller through a generic provider interface. Reactivation
still requires a named consumer, a threat model, a non-reveal contract, and
a conformance owner, per JANUS-12's original acceptance criteria — none of
which secretspec 0.20 changes.

## systemd-credential pattern (documented option, not a runtime path)

JANUS-446 supplies the Janus-side `managed-service-environment` projection.
The dependent NIX-391 ticket owns the fleet-secret NixOS module that pairs
that projection with systemd's own credential plumbing instead of adding a
Janus-native systemd-credential provider:

1. Janus issues the exact `managed-service-environment` capability for a
   reviewed host profile and materializes the private credential env file on
   the host. Only its audit, outcome, and immutable generation evidence are
   value-free; the generation is value-independent and is not a credential
   verifier.
2. The host's systemd unit picks that file up with `LoadCredential=` (or
   `LoadCredentialEncrypted=` / `SetCredentialEncrypted=` if the unit adds
   its own systemd-level encryption on top).
3. The application inside that unit consumes the credential the normal
   secretspec way — the secretspec SDK or `secretspec run`, addressing it
   through the `systemd-credential://` provider, keyed by the credential
   filename, reading `$CREDENTIALS_DIRECTORY` as systemd populates it.

Janus's role stops at step 1: producing the reviewed file that becomes the
`LoadCredential=` source. Janus does not grow a `systemd-credential`
provider, a plugin mechanism, or a new runtime path. JANUS-446 ends at that
Janus projection contract; NIX-391 owns the reusable module and the unit's
one-line `LoadCredential=` consumer. Neither ticket changes secretspec.

## Positioning

Secretspec is converging on agent-aware governance — audit logging,
`require_reason`, scopes — but that governance remains advisory and
local-trust: unauthenticated actor fields, non-blocking audit, no signed
evidence, no brokered value boundary. Janus is the brokered, policy tier
underneath: profiles and scopes gate *membership*, permits and approvals
gate *use*, and every event is signed, value-free evidence tied to a
kernel-verified peer identity. The two are complementary layers, not
competing ones — secretspec is a fine human-facing declaration format for
what secrets a project needs; Janus is what actually custodies and releases
the values behind that declaration.
