# Role authorization contract

Janus authorization is default-deny. Roles come only from a checked binding
source; a role or claim supplied by the caller is never authority. The shared,
versioned matrix is `config/authorization/role-matrix-v1.json`, and
`janus-core` rejects any snapshot that broadens the immutable code ceiling.

## Role boundaries

| Role | Intended authority | Hard boundary |
| --- | --- | --- |
| `viewer` | Value-free descriptors, health, lifecycle posture | No use or mutation |
| `operator` | Reviewed normal secret-use paths | No approval, policy, custody, or broadening |
| `owner` | Lifecycle, recovery, migration, retention, and exact delegation | No normal secret use or approval |
| `approver` | Exact approval issue, permit, read, and revoke | No execution or policy administration |
| `auditor` | Value-free evidence and policy inspection | No secret use or mutation except independent review |
| `security_admin` | Role bindings, authorization policy, emergency workflow administration | No secret use or backend custody |
| `break_glass_admin` | Eligibility marker only | No ordinary permission; an exact activation is still required |
| `service_admin` | Lifecycle administration for one exact service target | No untargeted or cross-target authority |
| `workload_admin` | Lifecycle administration for one exact workload target | No untargeted or cross-target authority |

The permission vocabulary intentionally has no permission for audit
suppression, backend custody, arbitrary command execution, blanket reveal, or
cross-scope bypass.

## Exact decision inputs

Every decision binds the current principal chain, opaque scope, action, time,
optional exact service/workload target, current owner fingerprint, secret class
and lifecycle, approval/delegation fingerprints, audit posture, and recorded
duties. Missing, expired, cross-scope, malformed, or ambiguous facts deny.

Service and workload administrator bindings are invalid without one exact
target. Other roles cannot carry a target constraint. Policy snapshots may
remove a permission from a role, but cannot add one outside its compiled
ceiling.

## Runtime modes

`JANUS_ROLE_AUTHORIZATION_MODE` selects the posture and must be set explicitly;
a missing value is a hard error.

| Mode | Meaning |
| --- | --- |
| `enforced` | Bindings are required and checked. The production posture. |
| `unsafe_disabled_dev` | Visibly unsafe development fixture. Rejected for `production` and `enterprise` product modes, and role administration is unavailable while it is set. |

Enforced mode also needs `JANUS_ROLE_BINDINGS_ROOT` (registry directory) and
`JANUS_ROLE_AUDIT_FILE` (audit sink). Both are strict-private, `0700`/`0600`.

### Bootstrapping the first binding

Role administration is itself an authorized action, so an empty registry in
enforced mode cannot issue its own first binding. `role-binding issue
--bootstrap` is the one command that runs without loaded authorization:

```bash
JANUS_ROLE_BOOTSTRAP_ACK=bootstrap-role-authorization \
janusd-admin role-binding issue --bootstrap \
  --role security_admin \
  --expires-in-seconds 900 \
  --source-reference "<reviewed source record>" \
  --reason "initial role authorization bootstrap"
```

Note there is no `--principal-binding`: bootstrap always binds the principal
that runs it, and passing one is rejected. That is deliberate rather than a
convenience — a binding key embeds an opaque scope reference the operator
cannot compute by hand, so naming a principal would let a typo consume the
one-shot empty-registry window and lock the deployment out with no recovery
short of emptying the registry by hand.

It fails closed on every one of these, by design:

- the exact `JANUS_ROLE_BOOTSTRAP_ACK` value must be present, so a stray flag or
  a replayed shell history cannot trigger it;
- the registry must be provably **empty** — bootstrap is not a standing
  administrative backdoor, and an exclusive lock plus a post-write recount
  means two concurrent attempts cannot both mint authority;
- the role must be `security_admin` — exactly enough authority to issue
  reviewed bindings, and nothing else;
- the TTL is capped at **one hour**, so a bootstrap binding expires instead of
  becoming a permanent hidden grant.

The resulting binding records `source_kind = unsafe_bootstrap` permanently, so
`role-binding list` and every audit consumer can always tell a bootstrapped
grant from a reviewed one. The audit record uses reason code
`role_binding_bootstrapped`.

The self-grant separation check does **not** apply here: bootstrap binds the
operator who runs it, which is the point, and there is by definition no other
principal to ask. Issue the durable reviewed bindings promptly and let the
bootstrap binding expire; to recover from a mistaken or compromised bootstrap,
revoke the binding and re-bootstrap against an emptied registry.

## Separation of duties

The intended model is that the following same-actor loops are denied within one
exact scope:

- request and approve the same use;
- approve and execute the same use;
- grant and receive the same delegation;
- grant and receive a role, or change policy for personal benefit;
- activate and approve or use the same break-glass grant;
- use and review the same break-glass grant;
- operate and review the same recovery.

**What is enforced at runtime today is narrower than that list, and operators
should plan against the narrower reality.** The nine-conflict matrix is
compiled and unit-tested, but the runtime call sites currently pass no duty
evidence to it, so it denies nothing in production paths. The checks that do
run are four direct comparisons of the principal binding key:

- the approver of a permit may not be its recipient;
- the grantor of a role binding may not be its subject;
- the grantor of a delegation may not be its delegate;
- break-glass activation, approval, benefit and review must be four distinct
  principals.

Those comparisons are only as strong as principal identity itself, which is
derived from environment and CLI input rather than an authenticated credential.
Under enforced authorization an alternate principal still requires its own
matching binding, so this is not a one-variable bypass — but one physical
operator holding several pre-bound identities can satisfy all four checks.
Treat separation of duties as an accountability aid, not as a control that
survives a determined single operator. Closing that gap requires authenticated
principals and duty history derived from recorded evidence rather than caller
assertion.

Decisions and their JSON/debug representations contain only closed vocabulary,
opaque references/fingerprints, and stable reason codes. Every checked action
must write audit evidence; an unavailable audit sink blocks the action.

The separate emergency lifecycle, one-action execution path, recovery rules,
and mandatory independent closure are documented in the
[break-glass runbook](break-glass-runbook.md).
