# Authenticated principals and durable duty history

Status: accepted design contract for JANUS-425. JANUS-427 implements the local
authenticated-actor identity-shadow foundation described in the
[identity-shadow runbook](identity-shadow-runbook.md); the durable duty journal,
authoritative operation lineage, runtime cutover, and enforced separation claim
remain unimplemented.

## Decision

Janus will separate three concepts that the current `PrincipalChain` blends:

1. the **accountable subject** whose prior duties can conflict;
2. the **technical principal chain** that constrains the current execution; and
3. descriptive **session context** such as an agent model or caller label.

Only an accountable subject authenticated by a configured trust adapter may
participate in a separation decision. Environment variables, CLI flags, MCP
arguments, agent/session labels, email addresses, display names, and the
current `PrincipalChain::binding_key()` are not authenticated subject evidence.
They may remain value-free context, but changing them must never create a new
actor for separation purposes.

The second prerequisite is an integrity-protected, append-only duty journal.
Every conflict-bearing action must load its exact operation history from that
journal and add its candidate duty before the domain mutation can proceed. A
caller cannot provide a duty slice. Missing, truncated, corrupt, ambiguous,
over-capacity, stale-key, or unavailable history denies the action.

Janus may report separation of duties as `enforced` only after both prerequisites
are active on every relevant runtime surface. Until then the existing direct
principal-binding comparisons remain accountability controls only.

## Current gap

The nine conflict rules in `janus-core` are compiled and unit-tested, but both
production call sites currently pass an empty duty slice. The direct checks
that do run compare `PrincipalChain::binding_key()` values assembled from
environment variables and CLI input. Those checks are useful evidence, but a
physical operator who controls several pre-bound aliases can satisfy them.

The current `DutyEvidence` also matches only actor fingerprint plus scope. That
is insufficient for durable enforcement: a person who requested one use must
not be barred from approving every unrelated use in the same scope. Every duty
must additionally bind the exact conflict domain or operation lineage.

## Threat model

### Protected against

- changing an executor, human, workload, admin, agent, model, or session label
  to appear to be a different accountable subject;
- replaying a valid identity assertion on a different local channel, host,
  audience, scope, or after expiry;
- copying a bearer-style assertion from another OS subject or workload;
- omitting, reordering, duplicating, truncating, replacing, or corrupting duty
  records or their indexes;
- restarting between request, approval, execution, review, or recovery phases;
- racing incompatible duties from separate processes;
- treating an empty or unreadable history as evidence that no conflict exists;
- using an agent or technical executor identity to hide the human or workload
  that is accountable for the action; and
- silently downgrading an enforced deployment to caller-asserted identity.

### Trusted boundary

- the host kernel, booted system configuration, and the local identity broker's
  dedicated service account and signing key;
- configured OIDC issuer keys and exact client/audience policy for human
  assertions;
- configured workload trust bundles and selectors; and
- reviewed subject mappings, role bindings, release admission, and recovery
  manifests.

Host root, the kernel, and an identity-provider administrator remain above this
boundary: they can replace binaries, mappings, keys, or credentials. Such
control is not disguised as application-level separation. Root or trust-root
recovery is a critical break-glass event that suspends the `enforced` claim
until independent review closes it.

## Authenticated accountable subjects

### Stable subject identifier

The policy key is `ActorSubjectRef`, an opaque fingerprint over:

```text
subject schema | trust-adapter kind | trust-domain/issuer | stable subject id
```

For OIDC humans, the stable source is the exact `(iss, sub)` pair. Email,
preferred username, groups, and display name are attributes, never identity.
For local humans and service accounts, a private reviewed registry maps the
kernel-observed peer UID to a generated, non-reassignable subject id. UID reuse
does not reuse the subject: deletion revokes the mapping and re-enrollment
creates a new subject id. For attested workloads, the stable source is the
verified workload identifier in its trust domain, such as a SPIFFE ID.

The durable journal stores only `ActorSubjectRef` and safe provenance enums. It
does not store raw OIDC subjects, Unix account names, SPIFFE paths, tokens,
certificates, email addresses, or principal chains.

### Local identity broker

The first implementation is a narrow local identity broker on a filesystem
Unix-domain socket. It runs as a dedicated account, owns the subject registry,
signing key, and duty journal, and obtains connected-process credentials from
the kernel. Socket-directory and socket permissions restrict which processes
may connect. The broker maps observed credentials to exactly one reviewed
subject and never accepts a requested subject from the client.

Inside the broker, the transport adapter creates a short-lived
`AuthenticatedActorV1` assertion containing:

- schema and trust-adapter kind;
- opaque subject ref and subject class (`human`, `workload`, or `system`);
- broker/trust-domain and key id;
- assurance class and credential-evidence fingerprint;
- issue and expiry times, one nonce, and the exact Janus audience;
- host, scope, and connected-peer/channel binding; and
- a broker signature covering every field.

The assertion is accepted only by the broker authorization transaction and
only for the channel and peer for which it was created. The client cannot
submit, receive, or relay a serialized assertion: it receives only a signed,
opaque admission result bound to the operation, peer, channel, and admitted
release. Assertions are not read from environment variables or CLI flags and
are never printed or persisted in application logs. The broker rejects
unmapped, multiply mapped, privileged credential spoofing, expired, replayed,
wrong-host, wrong-audience, wrong-scope, or wrong-channel assertions.

The broker owns actor verification, journal verification, conflict evaluation,
and duty admission as one authorization RPC. A client cannot ask the broker to
sign an actor and then evaluate policy locally. Authoritative operation state
used to derive the candidate duty and operation ref must be broker-readable or
carried in a domain-state reference signed by the authoritative domain service
with a broker-pinned key. That service creates and durably persists one opaque
operation ref when the lineage begins, reuses it for every later phase, and
never signs a caller-chosen ref. The closed reference schema binds the domain
service, operation ref, scope, action/state revision, issue/expiry time, nonce,
audience, and admitted release. The broker verifies the signature, signer,
freshness, nonce, current state transition, and all bindings before deriving a
duty; a forged, replayed, stale, unknown, or mismatched reference fails closed.

### Trust adapters

| Surface | Accountable-subject source | Required rule |
| --- | --- | --- |
| Local human/admin CLI | Kernel peer credentials mapped by the local broker | One reviewed OS account maps to one stable subject; shared accounts cannot claim separation. |
| Warden stdio / local MCP | Broker-authenticated launcher subject, or an attested workload when no human is present | Agent session/model fields are context only and cannot replace the launcher/workload subject. |
| `janusd-use` execution | The authenticated beneficiary or initiating workload already bound into the permit | The executor remains a separate technical binding and cannot become the accountable actor. |
| Role/delegation administration | Authenticated grantor plus a registry-resolved recipient subject | A CLI-supplied recipient label cannot define the recipient identity. |
| Break glass and recovery | Separately authenticated subjects for each required phase | Alias changes, executor changes, or fresh sessions do not create another actor. |
| OIDC human adapter | Verified issuer signature, exact issuer/client/audience/nonce/time checks, then `(iss, sub)` | Email, role claims, or groups may authorize attributes but never identify the actor. |
| Workload adapter | Verified trust-domain credential and workload id; X.509 channel binding is preferred | A caller cannot choose its SPIFFE/workload id; a JWT-style bearer credential alone is insufficient for local channel binding. |

OIDC and workload adapters plug into the same `AuthenticatedActorV1` boundary.
They do not change separation policy or journal semantics.

The currently registered authorizing transports are local process CLI,
Warden's local stdio MCP channel, and local Janus daemon sockets. There is no
remote authorizing MCP or CLI transport in the accepted V1 scope. The closed
surface manifest records both endpoint and transport; an unknown transport, a
remote listener, or a newly registered endpoint without a trust adapter makes
`enforced_recorded` readiness fail. A future remote transport requires a new
accepted mutual-authentication and channel-binding adapter before admission.

Every authorizing request on a long-lived channel creates a fresh internal
assertion with a deployment-configured lifetime capped at five minutes; an
expired assertion is never refreshed from session metadata. Kernel credentials
cannot distinguish two people sharing one OS account or handing off an open
channel. Such an account/channel is one accountable subject, may not evidence
separation, and must not be handed between operators while privileged. Human
handoff that needs distinct accountability requires a separately enrolled OS
or OIDC subject and a new authenticated channel.

### Accountable actor selection

Each duty has one accountable subject selected by closed policy:

- request: initiating authenticated human, otherwise the authenticated
  workload;
- approve: the authenticated approver human/admin;
- execute/use: the authenticated permit beneficiary or initiating workload,
  not the managed executor process;
- grant/manage: the authenticated grantor or policy administrator;
- receive: the registry-resolved recipient subject;
- break-glass/recovery phases: the authenticated subject performing that exact
  phase.

Agent and executor components remain covered by permit, profile, destination,
scope, and audit bindings. They cannot partition one human into several actors.
If policy cannot select exactly one accountable subject, the action is denied.

## Durable duty journal

### Conflict domain

`DutyEvidence` becomes a store-produced record bound to all of:

```text
schema | duty | actor subject ref | exact scope | conflict-domain kind
| opaque operation ref | authority/policy revision | admitted time
```

The operation ref is mandatory and typed. The lookup identity is exactly
`{actor subject ref, exact scope, conflict-domain kind, opaque operation ref}`.
Within that exact operation identity, the closed separation matrix compares the
candidate duty with every recorded duty; conflicting duties are deliberately
different values. Schema, authority/policy revision, admitted time, sequence,
and signature are verified provenance but do not partition conflict lookup. A
policy revision during an active lineage therefore cannot erase an earlier
duty. Scope-only or prefix matching is forbidden.

| Conflict | Conflict domain / operation lineage |
| --- | --- |
| request use / approve use | One use-request and resulting permit lineage |
| approve use / execute use | The same use-request/permit lineage |
| grant / receive delegation | One delegation grant id |
| grant / receive role | One role-binding id |
| manage policy / receive benefit | One policy-change id plus the exact affected subject/binding set |
| activate / approve break glass | One break-glass request/activation lineage |
| activate / use break glass | The same break-glass lineage |
| use / review break glass | The same break-glass lineage |
| operate / review recovery | One recovery operation or drill id |

An action that lacks its authoritative operation ref cannot enter
`enforced_recorded` mode.

### Record and storage contract

`DutyAdmissionV1` is an immutable admission fact, not a mutable status row. Its
id covers every authorization-relevant field plus the previous journal hash.
The broker signs the record and appends it under an exclusive lock using
write-all, flush, data sync, and parent-directory sync. Journal files and keys
are private, non-symlink, bounded, and owned separately from ordinary CLI
processes.

The journal has monotonically increasing sequence numbers, signed hash-chain
epochs, and explicit cross-signed key rotation. A derived per-operation index
may accelerate lookup, but the index grants no authority and is rebuilt only
from a completely verified journal.

Unlike the general audit log's safe recovery of an unterminated tail, authority
history never discards a tail automatically. An incomplete record, sequence
gap, unknown version, invalid signature, wrong predecessor, ambiguous epoch,
or index disagreement makes history unavailable and denies conflict-bearing
actions until explicit recovery succeeds.

### Authorization transaction

For every mapped runtime action, the broker owns steps 1 through 7 and returns
only the opaque admission result to the domain process:

1. obtain and verify the authenticated actor on the trusted channel;
2. read authoritative domain state or verify its domain-service-signed state
   reference, failing closed before journal lookup on any mismatch;
3. derive the closed duty and exact operation ref from that verified state, not
   request text;
4. lock and verify the complete duty journal and rebuild/verify the operation
   view;
5. evaluate trusted role bindings and the candidate duty against that view;
6. on conflict, write the required value-free denial audit and perform no
   domain mutation;
7. on allow, append and sync the duty admission, then release the journal lock
   before returning the admission result;
8. write the required value-free authorization audit; if it fails, do not
   perform the domain mutation, but retain the conservative duty admission;
9. perform the domain mutation and its existing evidence flow.

The journal lock is an OS-managed exclusive advisory lock held by the broker.
It is automatically released if the broker process exits or crashes and never
spans the domain mutation or an external call. The synced conservative duty
record, not a long-held lock, serializes incompatible phases. Broker restart
verifies the complete journal before accepting another transaction.

An admitted duty remains conflict-bearing even when the later action fails or
the process crashes. Retrying the same compatible duty is safe; an incompatible
duty remains denied. A new operation ref cannot be used to continue an existing
lineage.

### Policy API boundary

Production policy must no longer accept `&[DutyEvidence]` from a caller.
`RoleDecisionInput` receives an opaque verified operation view that can only be
constructed by the duty-store verifier, plus one policy-derived candidate.
Tests may use an explicit fixture constructor that is unavailable in production
build paths.

Every runtime action is classified as one duty or explicitly `no_conflict` in
a closed table. `enforced_recorded` requires a healthy verified journal even
for `no_conflict` actions so the deployment cannot report enforcement while
one surface silently bypasses the authority service. No production caller may
substitute an empty view.

### Retention and capacity

V1 performs no automatic deletion or compaction. Active and terminal operation
history is retained with the authorization audit so restart, delayed review,
and recovery cannot erase a conflict. The journal enforces reviewed per-record,
per-operation, and global bounds; reaching a bound fails closed with a stable
operator-action reason before a new duty is admitted.

Any future compaction is a separate offline, reviewed migration. It must retain
a signed summary that preserves operation refs, actor refs, duties, scope,
sequence range, epoch roots, and audit linkage for at least the configured audit
retention period. Deleting a record that can still affect an active operation
is forbidden.

## Runtime posture and single-operator behavior

The rollout exposes three explicit postures:

| Posture | Meaning |
| --- | --- |
| `accountability_legacy` | Current caller-assembled chains and direct comparisons; never reported as enforced separation. |
| `authenticated_observe` | Broker authentication and durable journal are live, but matrix conflicts emit critical observation evidence rather than denying. |
| `enforced_recorded` | Every relevant surface uses authenticated actors and verified operation history; matrix conflicts hard-deny. |

There is no implicit fallback between postures. A deployment in
`enforced_recorded` fails readiness when the broker, trust registry, key,
journal, audit sink, or surface-coverage manifest is unavailable or mismatched.

A single physical operator cannot satisfy a multi-actor policy. A solo
installation may remain honestly in `accountability_legacy` or
`authenticated_observe`, or it will be denied when a workflow requires a
distinct subject. It may not mint aliases, switch executor labels, or use
several roles bound to one subject to simulate separation. Break-glass recovery
is not a routine substitute for a second actor.

## Migration, rollout, rollback, and recovery

### Migration

Existing role/delegation/break-glass records bind caller-assembled principal
keys and cannot be automatically promoted. A versioned reviewed migration
manifest maps each old binding id to one enrolled `ActorSubjectRef` and the
remaining technical-chain constraints. Preflight rejects missing, duplicate,
many-subject, or alias-derived mappings and produces only value-free evidence.

Cutover to `enforced_recorded` requires:

- a healthy broker, trust registry, signing epoch, journal, and audit sink;
- every active binding and configured surface mapped to the new schema;
- all implementation assurance tests passing on the exact admitted release;
- no active authority operation from the legacy era: V1 has no import path for
  caller-created or reconstructed duty evidence, so each legacy operation must
  durably reach a terminal state or be cancelled and restarted under the new
  authority path;
- a verified backup/recovery bundle and a successful restore rehearsal; and
- an observation window with no unexplained subject or duty mismatch.

An empty new journal is never proof that a legacy active operation has no prior
duty.

### Rollback

Before enforcement, observation mode may roll back without changing authority.
After enforcement, code rollback must retain support for the authenticated
subject and duty schemas and keep the broker/journal online. Falling back to
legacy identity requires a declared critical incident, stops new
conflict-bearing actions, changes reported posture to accountability, and
requires independent closure. Recorded history is never deleted to make an old
binary start.

### Recovery

Recovery backs up the subject registry, broker public trust data, signed duty
epochs, operation indexes, and audit linkage as one scope/release-bound set.
Restore verifies signatures and the complete chain before readiness. Lost or
unverifiable history denies authorization; operators do not hand-create an
empty journal.

Trust-root or host-root recovery appends a critical epoch transition, identifies
the reviewed recovery manifest, requires a fresh broker key, and leaves the
deployment non-enforcing until an independent subject reviews and closes the
event. Raw subjects, tokens, private keys, and credentials remain outside
tickets and exported evidence.

A solo deployment with no independent enrolled subject cannot close that event
or return to `enforced_recorded`; it remains explicitly capped at
`accountability_legacy` until a second subject is provisioned and performs the
review. Recovery availability does not weaken the distinct-subject rule.

## Verification matrix

Implementation is incomplete until automated tests prove all of the following:

| Case | Required result |
| --- | --- |
| Same authenticated subject requests then approves one use | Denied with `separation_requester_approver`, including after restart. |
| Same authenticated subject approves then executes one use | Denied with `separation_approver_executor`, including through a different executor label/session. |
| Same OS subject changes every principal environment variable | Actor ref stays identical; conflict still denies. |
| Different reviewed OS subjects perform compatible phases | Allowed when roles and every other policy input match. |
| OIDC session refresh or changed email/group/display claims | `(iss, sub)` actor ref stays identical. |
| Agent model/session changes under one launcher | Actor ref stays identical; agent metadata cannot evade conflict. |
| Policy revision changes between phases of one operation | Earlier duty remains in the same lookup identity and the conflict still denies. |
| Workload credential from wrong trust domain/audience/channel | Denied before journal lookup. |
| Copied, expired, replayed, or wrong-channel actor assertion | Denied before journal lookup. |
| Long-lived channel exceeds assertion lifetime | A fresh broker-side assertion is required; session metadata cannot refresh identity. |
| Domain-state reference is forged, replayed, stale, wrong-release, or changes the operation ref | Denied before journal lookup; no duty or domain mutation is written. |
| Journal record/tail/index/signature/sequence is tampered | Readiness and authorizing action fail closed without domain mutation. |
| Crash after duty sync but before domain mutation | Duty survives and incompatible phase remains denied. |
| Broker is killed while holding the journal lock | OS releases the lock; restart verifies history and preserves the admitted duty or fails closed. |
| Concurrent incompatible phases | Exclusive transaction admits at most one side; the other is denied. |
| Legacy active operation with empty new journal | Enforcement cutover is denied. |
| Attempted legacy-duty import | Rejected; V1 accepts duties only from a live broker authorization transaction. |
| Journal or audit persistence failure | No domain mutation and no value-bearing output. |
| Debug, CLI, MCP, audit, migration, and recovery output | Only opaque refs, stable reasons, and `value_returned=false`; no raw identity credential or subject. |
| Solo deployment with one subject | Cannot claim/enact distinct-actor workflows; posture remains truthful. |

The release gate must exercise every runtime surface and compare a closed
surface-to-duty manifest against the registered command/MCP endpoint catalog.
A new authorizing surface without an identity adapter and duty classification
fails CI.

## Implementation slices

Implementation begins only through separate reviewed tickets:

1. authenticated actor types, local identity broker, subject registry, and
   binding migration/observation mode;
2. signed durable duty journal, operation-domain model, and policy API that
   cannot accept caller-created evidence; and
3. complete runtime-surface wiring, enforced posture, recovery, release
   assurance, and staged production activation.

No slice may advertise enforced separation before the third slice is deployed
and live-verified.

## Standards alignment

- Linux connected Unix sockets expose kernel-observed peer credentials through
  `SO_PEERCRED`: <https://man7.org/linux/man-pages/man7/unix.7.html>.
- OpenID Connect defines the `(iss, sub)` pair as the stable end-user identity;
  other claims are not unique identity: <https://openid.net/specs/openid-connect-core-1_0-18.html>.
- SPIFFE defines workload ids within cryptographic trust domains and recommends
  local workload endpoints; X.509-SVID channel authentication is preferred over
  replayable bearer assertions: <https://spiffe.io/docs/latest/spiffe-specs/>.

These standards supply trust-adapter inputs. Janus's accountable-subject,
operation-domain, journal, migration, and separation policy remain Janus-owned.
