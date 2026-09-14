# Agenix write paths

When Janus already holds an approved value in process, it performs the agenix
encryption itself and writes a new name-derived ciphertext for the configured
public-key recipients. Existing ciphertext is never overwritten, operator
private keys are never used, and this path never returns or reveals the value.
The absolute export root must be a Janus-private directory: Janus enforces its
private permissions and keeps its write lock there.

For bootstrap cases where no value exists yet, the reviewed admin command
`janusd-admin forge create-generated` accepts only a canonical shape such as
`env:API_KEY=b64:24,PORT=hex:2`, a reason label, a recipients file, and an
absolute export root. It generates entropy inside Forge, writes the new
ciphertext only when the target is absent, and never accepts a value through
CLI, HTTP, or remote input.

An issuer field uses the canonical form
`NAME=issuer:zitadel-oidc-client:AGM Platform/zulip` or
`NAME=issuer:tofu-output:<directory>/<output>`. The alias is an opaque key into
the reviewed closed `janus.issuer-connectors.v1` catalog; it is never treated
as a path, URL, or command. The issuer resolver returns a zeroizing
`SecretValue` and value-free `{kind,alias_digest}` evidence to Forge. The
provider first creates a durable, exclusive reservation journal containing
only shape, recipient, and alias digests. A reserved journal blocks automatic
re-issuance after interruption; recovery requires an explicit reviewed action.
The final provider operation remains create-only and never overwrites an
existing ciphertext.

A ZITADEL connector may add one private PKI trust anchor with the paired
`ca_file` and `ca_sha256` fields. Janus accepts only an absolute file path and
verifies the certificate bytes against the configured SHA-256 before each
provider request. The pinned certificate extends the normal public root set;
omitting both fields preserves the public trust configuration. Partial pairs,
changed certificate bytes, invalid PEM, and TLS chains signed by another CA
fail closed. This option does not disable certificate name or time checks.

For a configured ZITADEL alias, `janusd-admin forge invalidate-issuer` provides
the separate provider cleanup boundary. It first reserves an operator-supplied
idempotency reference in a private state directory, regenerates the exact
application client secret, then immediately zeroizes and discards the returned
replacement. An interrupted reservation cannot be retried automatically. A
committed exact replay returns unchanged without contacting the provider, and
any changed alias, connector configuration, principal, or reason is refused.
The result proves that the previously active credential was invalidated. It
does not claim that the provider stores no current secret.

The command emits only the action, changed flag, target name, shape SHA-256,
recipient-set SHA-256, optional issuer-alias SHA-256, reason, and
`value_returned=false`. The durable audit record carries the same value-free
evidence. This is an Admin-plane operation:
the caller must use the reviewed `janusd-admin` role/runtime authority path,
with the recipients and export root supplied by the reviewed deployment
profile. `janusd-use` deliberately cannot invoke this command because its
process plane is restricted to permit-bound service use.
