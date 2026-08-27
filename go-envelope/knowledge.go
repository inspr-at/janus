package main

import "strings"

type KnowledgeValue struct {
	Code   string
	Detail string
}

type KnowledgeTerm struct {
	ID     string
	Name   string
	Plain  string
	Detail string
	// Icon selects a term-specific illustration glyph. Empty renders the
	// default two-node relationship glyph; kinds group terms that share a
	// visual shape (closed catalog, state cycle, protected value, layer
	// boundary) so illustrations vary without hand-drawing one per term.
	Icon      string
	Values    []KnowledgeValue
	FlowSlugs []string
}

type KnowledgeStep struct {
	Number   string
	Actor    string
	Action   string
	Checks   string
	Evidence string
}

type KnowledgeFlow struct {
	Slug     string
	Title    string
	Summary  string
	Enforced string
	Intended string
	Evidence string
	Steps    []KnowledgeStep
}

func kv(code, detail string) KnowledgeValue {
	return KnowledgeValue{Code: code, Detail: detail}
}

func knowledgeTerms() []KnowledgeTerm {
	return []KnowledgeTerm{
		{ID: "secret", Name: "Secret", Plain: "A governed value that Janus handles without exposing it to the control plane.", Detail: "The catalog describes a secret by safe metadata. A provider owns the stored value; reviewed use paths may deliver it only to a fixed consumer.", Icon: "shield", FlowSlugs: []string{"manual-secret-entry", "generated-rotation", "approved-use", "env-file-handoff"}},
		{ID: "ref", Name: "Reference", Plain: "An opaque identifier that names governed state without containing the value.", Detail: "References such as sec_, use_, appr_, and rbd_ let people and processes coordinate safely. They are identifiers, not bearer secrets and not proof of authority.", FlowSlugs: []string{"approved-use", "managed-service-onboarding", "role-binding-lifecycle"}},
		{ID: "permit", Name: "Permit", Plain: "Short-lived, single-use authority for one reviewed secret operation.", Detail: "A permit binds the secret, profile, purpose, principal chain, destination, executor, scope, and expiry. The use plane consumes it once; callers cannot broaden its policy fields.", FlowSlugs: []string{"approved-use", "env-file-handoff"}},
		{ID: "approval", Name: "Approval", Plain: "A reviewed authorization record that can mint an approval-required permit.", Detail: "Break-glass and weak-egress high-value use require this separate admin-plane record. Low, normal, and strong-egress high-value use can use the direct policy-derived permit path.", FlowSlugs: []string{"approved-use", "break-glass"}},
		{ID: "delegation", Name: "Delegation", Plain: "A scoped grant to perform one exact use on someone else's behalf.", Detail: "Delegation is immutable, expiring, revocable, and bound to an exact scope and use context. It does not create a role or broaden the reviewed profile.", FlowSlugs: []string{"approved-use"}},
		{ID: "role", Name: "Role", Plain: "A closed bundle of maximum permissions, narrowed by reviewed bindings and policy.", Detail: "The Rust ceiling and the shared role matrix agree on nine roles. A policy may remove authority but cannot add permissions beyond the compiled ceiling.", Icon: "catalog", Values: roleKnowledgeValues(), FlowSlugs: []string{"approved-use", "break-glass", "role-binding-lifecycle"}},
		{ID: "permission", Name: "Permission", Plain: "One exact operation category that the role matrix may authorize.", Detail: "Permissions are the shared language between runtime actions and roles. The matrix assigns only this compiled set; it deliberately contains no reveal, audit suppression, arbitrary command, custody, or cross-scope bypass permission.", Icon: "catalog", Values: permissionKnowledgeValues(), FlowSlugs: []string{"approved-use", "generated-rotation", "env-file-handoff", "host-retirement", "break-glass", "role-binding-lifecycle"}},
		{ID: "binding", Name: "Role binding", Plain: "A durable link between one principal, role, exact scope, and reviewed source.", Detail: "Bindings expire and can be revoked. Service and workload administrators also require one exact target; other roles cannot carry a target constraint.", FlowSlugs: []string{"role-binding-lifecycle", "break-glass"}},
		{ID: "binding-source", Name: "Binding source", Plain: "The closed provenance label attached to a role binding.", Detail: "The source reference is stored only as an opaque fingerprint. Unsafe bootstrap remains permanently distinguishable from reviewed and OIDC-derived authority.", Values: []KnowledgeValue{kv("local_reviewed", "Locally reviewed source record."), kv("oidc_subject", "Exact OIDC subject mapping."), kv("oidc_group", "Exact OIDC group mapping."), kv("unsafe_bootstrap", "One-shot empty-registry bootstrap provenance.")}, FlowSlugs: []string{"role-binding-lifecycle"}},
		{ID: "scope", Name: "Scope", Plain: "The exact organizational boundary within which authority is valid.", Detail: "Rust derives an opaque scope from organization, project, repository, environment, and optional namespace/workload. The envelope additionally filters descriptors through its configured scope allowlist; neither path grants cross-scope inheritance.", FlowSlugs: []string{"approved-use", "env-file-handoff", "role-binding-lifecycle"}},
		{ID: "class", Name: "Secret class", Plain: "A closed risk category that selects permit and egress requirements.", Detail: "Class is policy input, not a cosmetic tag. Higher-risk paths tighten egress and TTL requirements, while break-glass always needs separate approval.", Values: []KnowledgeValue{kv("low", "Low-risk local or development secret."), kv("normal", "Ordinary production secret."), kv("high_value", "Elevated controls; strong egress or explicit approval."), kv("break_glass", "Emergency-only; approval required and TTL capped.")}, FlowSlugs: []string{"approved-use", "break-glass"}},
		{ID: "egress-mode", Name: "Egress mode", Plain: "How Janus constrains where a secret-bearing operation can go.", Detail: "Connector, sandbox, and proxy enforcement are strong modes. Hook guarding is weaker, while declared-only records intent without technically enforcing the destination.", Values: []KnowledgeValue{kv("connector", "Janus-owned narrow connector."), kv("sandboxed", "Runner sandbox enforces destination."), kv("proxy_enforced", "Network proxy enforces destination."), kv("hook_guarded", "Hook guard only; not strong egress."), kv("declared_only", "Declaration only; local/dev or low risk.")}, FlowSlugs: []string{"approved-use", "generated-rotation", "env-file-handoff"}},
		{ID: "lifecycle", Name: "Lifecycle", Plain: "The closed state machine that decides whether normal use is allowed.", Detail: "Only active and rotating allow normal approved use. Destruction is a value-free metadata and tombstone workflow; it does not claim provider-side deletion.", Icon: "cycle", Values: []KnowledgeValue{kv("draft", "Metadata exists; normal use blocked."), kv("active", "Normal reviewed use allowed."), kv("rotating", "Rotation underway; approved use may continue."), kv("deprecated", "Migration required; normal use blocked."), kv("disabled", "Normal use blocked."), kv("pending_delete", "Awaiting destroy evidence; normal use blocked."), kv("destroyed", "Value-free tombstone/metadata only.")}, FlowSlugs: []string{"generated-rotation", "host-retirement"}},
		{ID: "plane", Name: "Runtime plane", Plain: "A process boundary separating secret use from governance administration.", Detail: "Use processes can request and consume bounded authority. Admin processes approve, rotate, migrate, recover, and manage policy; one process belongs to exactly one plane.", Values: []KnowledgeValue{kv("use", "Reference discovery and permit-bound execution."), kv("admin", "Approval, lifecycle, rotation, migration, recovery, and policy.")}, FlowSlugs: []string{"approved-use", "generated-rotation", "role-binding-lifecycle"}},
		{ID: "runtime-action", Name: "Runtime action", Plain: "One member of the release-reviewed operation catalog.", Detail: "Unknown actions are rejected. Every action maps to exactly one runtime plane and one maximum role permission; this page lists the code's complete catalog.", Icon: "catalog", Values: runtimeActionKnowledgeValues(), FlowSlugs: []string{"approved-use", "generated-rotation", "env-file-handoff", "break-glass", "role-binding-lifecycle"}},
		{ID: "product-mode", Name: "Product mode", Plain: "The deployment posture used for release and readiness claims.", Detail: "Production and enterprise require trusted-release admission. Development is explicitly non-production; self-hosted is the secure local mode and does not make enterprise claims.", Values: []KnowledgeValue{kv("dev", "Explicit development posture."), kv("self_hosted", "Secure local/self-hosted posture."), kv("production", "Trusted-release admission required."), kv("enterprise", "Trusted-release admission and enterprise gates required.")}, FlowSlugs: []string{"managed-service-onboarding", "role-binding-lifecycle"}},
		{ID: "break-glass", Name: "Break glass", Plain: "Loud emergency authority for one exact reviewed action.", Detail: "Eligibility alone grants nothing. Activation, approval, use, and independent closure are durable steps with critical value-free evidence and distinct-principal checks.", FlowSlugs: []string{"break-glass"}},
		{ID: "forge", Name: "Forge", Plain: "The admin-plane component that creates a replacement value for generated rotation.", Detail: "Forge rotates only a reviewed generated secret, then drives the declared reload and validation hooks. Failure returns the workflow to a safe recorded outcome.", FlowSlugs: []string{"generated-rotation"}},
		{ID: "warden", Name: "Warden", Plain: "The value-free discovery and permit-request surface for governed use.", Detail: "Warden lists or describes safe metadata, checks health, and requests policy-derived permits. It never offers a general reveal method.", FlowSlugs: []string{"approved-use"}},
		{ID: "envelope", Name: "Envelope", Plain: "The authenticated Go control-plane UI around Janus governance.", Detail: "The envelope presents catalog, posture, access, evidence, and narrowly reviewed setup transactions. Its normal pages and APIs remain value-free except the dedicated guarded ingress boundary.", FlowSlugs: []string{"manual-secret-entry", "managed-service-onboarding"}},
		{ID: "engine", Name: "Engine", Plain: "The Rust policy and execution core that enforces Janus contracts.", Detail: "The engine owns closed vocabularies, permits, lifecycle transitions, split planes, provider operations, and value-free evidence rules. The envelope explains those contracts but does not replace them.", FlowSlugs: []string{"generated-rotation", "approved-use", "env-file-handoff", "host-retirement", "break-glass", "role-binding-lifecycle"}},
		{ID: "secretspec", Name: "Secretspec", Plain: "A declarative manifest format and local CLI/library for naming the secrets a project needs, per profile and per provider, then resolving them on the caller's own machine at run time.", Detail: "Janus and secretspec sit at different layers. Secretspec is declaration and local resolution; Janus is the brokered layer, and a value never crosses into an unreviewed caller. Janus's manifest parser reads a secretspec-shaped file as a membership allowlist only — project identity, named profiles, and each secret's description and required flag — and rejects any field that would select a provider, supply a generated value, or otherwise cross the value boundary. The value-bearing backend behind an allow-listed name is chosen separately, by the Janus operator, never by the manifest file itself.", Icon: "boundary", FlowSlugs: []string{"generated-rotation", "host-retirement"}},
	}
}

func roleKnowledgeValues() []KnowledgeValue {
	return []KnowledgeValue{
		kv("viewer", "Value-free descriptors, health, and lifecycle posture."),
		kv("operator", "Reviewed normal-use paths; no approval or policy power."),
		kv("owner", "Lifecycle, recovery, migration, retention, and delegation; no normal use."),
		kv("approver", "Exact approvals and approval-backed permits; no execution."),
		kv("auditor", "Value-free evidence and independent review."),
		kv("security_admin", "Authorization policy, bindings, and emergency administration; no secret use."),
		kv("break_glass_admin", "Eligibility marker with no ordinary permission."),
		kv("service_admin", "Lifecycle administration for one exact service."),
		kv("workload_admin", "Lifecycle administration for one exact workload."),
	}
}

func permissionKnowledgeValues() []KnowledgeValue {
	return []KnowledgeValue{
		kv("descriptor.list", "List value-free secret descriptors."), kv("descriptor.read", "Read one value-free descriptor."), kv("health.read", "Read safe runtime health."),
		kv("secret.use", "Request an exact policy-derived secret use."), kv("managed_run.use", "Execute a reviewed managed command."), kv("env_file.use", "Render a reviewed private environment file."),
		kv("approval.issue", "Create an exact approval."), kv("approval.permit", "Mint a permit from an approval."), kv("approval.read", "Inspect value-free approval state."), kv("approval.revoke", "Revoke an approval."),
		kv("delegation.issue", "Create an exact delegation."), kv("delegation.read", "Inspect delegation state."), kv("delegation.revoke", "Revoke a delegation."),
		kv("lifecycle.transition", "Move metadata through an allowed lifecycle edge."), kv("lifecycle.read", "Inspect lifecycle state and queues."),
		kv("destroy.record", "Record a value-free destroy tombstone."), kv("destroy.finalize", "Finalize destroyed metadata."), kv("destroy.reconcile", "Check metadata against tombstones."),
		kv("rotation.manage", "Run reviewed generated rotation."), kv("lifecycle.entry", "Create or import through a reviewed lifecycle transaction."),
		kv("migration.manage", "Run a versioned approval migration."), kv("scope_transfer.manage", "Run an offline exact-scope transfer."), kv("recovery.drill", "Run a sealed recovery drill."), kv("retention.manage", "Run the evidence-retention cycle."),
		kv("pharos.retire", "Retire a Pharos host credential."), kv("pharos.reconcile", "Reconcile retirement evidence."),
		kv("role_binding.issue", "Issue one durable role binding."), kv("role_binding.read", "List value-free role binding state."), kv("role_binding.revoke", "Revoke a role binding."), kv("role_binding.status", "Inspect one exact binding."),
		kv("authorization_policy.read", "Inspect checked authorization policy."), kv("authorization_policy.manage", "Administer authorization policy within the code ceiling."),
		kv("break_glass.activate", "Request an exact emergency activation."), kv("break_glass.read", "Inspect emergency lifecycle state."), kv("break_glass.revoke", "Revoke emergency authority."), kv("break_glass.review", "Independently close emergency review."),
	}
}

func runtimeActionKnowledgeValues() []KnowledgeValue {
	use := []string{"warden.list_secrets", "warden.describe_secret", "warden.request_use", "warden.health", "use.run_preflight", "use.run", "use.env_file_preflight", "use.env_file", "use.permit_issue", "use.projection_preflight", "use.projection_issue"}
	admin := []string{
		"admin.approval_issue", "admin.approval_permit", "admin.approval_list", "admin.approval_revoke",
		"admin.delegation_issue", "admin.delegation_list", "admin.delegation_inspect", "admin.delegation_revoke",
		"admin.lifecycle_transition", "admin.lifecycle_stale_report", "admin.lifecycle_destroy_record", "admin.lifecycle_destroy_finalize", "admin.lifecycle_destroy_reconcile",
		"admin.forge_rotate_generated", "admin.lifecycle_entry", "admin.lifecycle_action_queue", "admin.migration", "admin.scope_transfer", "admin.recovery_drill", "admin.retention",
		"admin.pharos_retire", "admin.pharos_reconcile", "admin.pharos_detach_metadata",
		"admin.role_binding_issue", "admin.role_binding_list", "admin.role_binding_revoke", "admin.role_binding_status", "admin.authorization_policy_status",
		"admin.break_glass_request", "admin.break_glass_approve", "admin.break_glass_list", "admin.break_glass_status", "admin.break_glass_revoke", "admin.break_glass_review",
		"admin.web_transaction", "admin.dynamic_custody", "admin.dynamic_delivery", "admin.dynamic_transport",
	}
	values := make([]KnowledgeValue, 0, len(use)+len(admin))
	for _, action := range use {
		values = append(values, kv(action, "use plane"))
	}
	for _, action := range admin {
		values = append(values, kv(action, "admin plane"))
	}
	return values
}

// knowledgeRuntimeActionCount reports the size of the code-inventoried
// runtime action catalog so page copy never hardcodes a number that can
// drift from the source of truth.
func knowledgeRuntimeActionCount() int {
	return len(runtimeActionKnowledgeValues())
}

func knowledgeFlows() []KnowledgeFlow {
	return []KnowledgeFlow{
		{
			Slug: "manual-secret-entry", Title: "Manual secret entry", Summary: "A human enters one value through the guarded declared-slot web transaction; every surrounding message remains value-free.",
			Enforced: "The production v1 path verifies a signed, single-use Pharos intent, exact root-owned declaration, authenticated session, fresh passkey, CSRF/origin, bounded body, and current target before reading the value. The transaction runs over a private daemon socket and records value-free phases.",
			Intended: "This is deliberately narrow, not a general create-secret form. Dynamic environment admission exists in code but defaults off and is not enabled by current deployment configuration.",
			Evidence: "Opaque intent and operation references, target fingerprint, timestamps, phase/reason code, and explicit value_returned=false/request_body_returned=false invariants.",
			Steps: []KnowledgeStep{
				{Number: "01", Actor: "Pharos + service owner", Action: "Issue a signed setup intent for one declared slot.", Checks: "Exact host, service, slot, declaration fingerprint, audience, nonce, and bounded lifetime.", Evidence: "Signed value-free intent."},
				{Number: "02", Actor: "Envelope + human", Action: "Inspect the target and complete fresh passkey step-up.", Checks: "Authenticated identity, PKCE, exact target, current declaration, and replay state.", Evidence: "Proof bound to the human session and target."},
				{Number: "03", Actor: "Human + envelope", Action: "Submit the one bounded value form once.", Checks: "Origin, CSRF, media type, field order, size, proof, and single-use reservation before value bytes.", Evidence: "Opaque operation state; no request body retained."},
				{Number: "04", Actor: "Rust transaction + host", Action: "Install, reload, validate, and return completion.", Checks: "Private socket, fixed declaration, signed host envelope, reviewed reload/health, terminal replay rules.", Evidence: "Value-free materialized, reloaded, healthy, or failed phase."},
			},
		},
		{
			Slug: "generated-rotation", Title: "Generated rotation", Summary: "Forge generates a replacement inside Janus, updates the provider, then runs the reviewed consumer reload and validation sequence.",
			Enforced: "The admin plane checks role, exact scope, active manifest/profile, generated-rotation capability, approval contract, release admission, audit availability, reviewed reload hook, and validation probe. Hook commands come from a separate strict manifest, not CLI text.",
			Intended: "Automation readiness depends on the provider and consumer contract. Manual or unsupported reload methods are not automation-ready; a configured label is only as useful as the operator-supplied hook implementation behind it.",
			Evidence: "Rotation phases, opaque secret and consumer references, reload/validation labels, stable reason code, timestamps, and value_returned=false.",
			Steps: []KnowledgeStep{
				{Number: "01", Actor: "Owner", Action: "Invoke forge rotate-generated for a reviewed secret and consumer.", Checks: "Admin plane, rotation permission, scope, class/lifecycle, policy and approval inputs.", Evidence: "Rotation-start audit record."},
				{Number: "02", Actor: "Forge + provider", Action: "Generate and store the next value without printing it.", Checks: "Provider capability, strategy, manifest identity, and bounded generation contract.", Evidence: "Generated/stored phase only."},
				{Number: "03", Actor: "Hook runner", Action: "Run the policy-selected reload method.", Checks: "Exact reload label resolves in the strict hook manifest; timeout and output stay bounded.", Evidence: "Reload phase and scrubbed result."},
				{Number: "04", Actor: "Validator", Action: "Run the named validation probe and finalize outcome.", Checks: "Exact probe label, bounded command, successful result, and required audit write.", Evidence: "Validated or failed terminal rotation phase."},
			},
		},
		{
			Slug: "approved-use", Title: "Approved use end to end", Summary: "A reviewed profile fixes the operation; policy chooses direct permit issuance or the separate approval path before one bounded use.",
			Enforced: "Low, normal, and strong-egress high-value profiles can mint policy-derived permits directly through Warden or janusd-use. Break-glass and weak-egress high-value use require an approval. Permits are exact, expiring, principal-bound, scope-bound, and single-use.",
			Intended: "The compiled duty-conflict matrix is not a claim of authenticated-person separation. Current direct principal comparisons and role bindings provide accountability, but principal identity is still supplied by the runtime environment rather than a cryptographic human credential.",
			Evidence: "Request/approval/permit identifiers, policy fingerprints, decision reason codes, consumption outcome, lifecycle evidence, and value_returned=false control-plane output.",
			Steps: []KnowledgeStep{
				{Number: "01", Actor: "Operator or Warden", Action: "Request the exact profile, secret reference, and purpose.", Checks: "Use plane, operator authority, scope, lifecycle, class, profile, executor, destination, and audit posture.", Evidence: "Value-free request decision."},
				{Number: "02", Actor: "Policy / approver", Action: "Issue directly or create and separately convert an approval.", Checks: "Class and egress policy, TTL ceiling, recipient binding, and approver/recipient inequality.", Evidence: "Approval and/or single-use permit record."},
				{Number: "03", Actor: "Use process", Action: "Consume the permit for the one reviewed operation.", Checks: "Current principal, exact profile/scope, expiry, unused state, release and recovery posture.", Evidence: "Atomic admitted-attempt consumption."},
				{Number: "04", Actor: "Consumer + auditor", Action: "Complete the operation and retain only safe results.", Checks: "Destination/executor enforcement depends on the declared egress mode; audit must remain available.", Evidence: "Outcome, timestamps, safe labels, hashes, and lifecycle evidence."},
			},
		},
		{
			Slug: "env-file-handoff", Title: "Env-file handoff", Summary: "A permit-bound use process renders one reviewed environment binding into a private file for a non-LLM service consumer.",
			Enforced: "Preflight validates the reviewed profile and target without reading the secret. Execution derives path and environment name from policy, requires a permit or emergency activation, writes private regular files atomically, and consumes authority once.",
			Intended: "The repo fixture proves the contract, not a specific host deployment. Operators still own service wiring, reload, validation, and deliberate cleanup unless those actions are covered by another reviewed automation path.",
			Evidence: "Preflight result, permit path used, mode/path checks, consumer validation, lifecycle record, stable reason code, and value_returned=false.",
			Steps: []KnowledgeStep{
				{Number: "01", Actor: "Service owner", Action: "Review the consumer profile and private output target.", Checks: "Secret reference, executor, destination, environment name, absolute path, reload, probe, and scope.", Evidence: "Reviewed profile change."},
				{Number: "02", Actor: "Operator", Action: "Run value-free preflight and obtain the required authority.", Checks: "Private parent/file, no symlink, class/egress policy, role, lifecycle, and scope.", Evidence: "Preflight plus direct permit or approval trail."},
				{Number: "03", Actor: "janusd-use", Action: "Render the exact binding to the policy-owned path.", Checks: "Permit or activation identity, single use, current profile, provider, atomic private-file rules.", Evidence: "Value-free handoff outcome and consumed authority."},
				{Number: "04", Actor: "Service operator", Action: "Reload or start the consumer and validate it.", Checks: "Reviewed service procedure; never copy file contents into logs or tickets.", Evidence: "File mode/path and value-free consumer health result."},
			},
		},
		{
			Slug: "managed-service-onboarding", Title: "Managed-service onboarding", Summary: "Operators establish a value-free service policy and host trust before any guarded value admission is possible.",
			Enforced: "Startup rejects partial or unsafe managed setup configuration. Signed intents cannot choose paths, commands, callback URLs, reload, or health behavior; root-owned declarations and reviewed profiles own those fields.",
			Intended: "The dynamic v2 pipeline can create, replace, remove, deliver, reload, and health-check an exact environment binding, but it defaults off and no current deployment enables it. Pharos registration and production enablement remain separate reviewed work.",
			Evidence: "Reviewed declaration/policy fingerprints, verification-key identity, host enrollment generation, intent inspection, operation phases, and value-free health receipts.",
			Steps: []KnowledgeStep{
				{Number: "01", Actor: "Service + security owners", Action: "Review a fixed service declaration and environment policy.", Checks: "Exact host/service, allowed names and sources, delivery, reload, health, capacity, and ownership.", Evidence: "Versioned value-free policy and fingerprints."},
				{Number: "02", Actor: "Host operator", Action: "Enroll the host and install the root-owned executor policy.", Checks: "Host key/token generation, private paths, fixed service target, revocation epoch, and permissions.", Evidence: "Enrollment and deployment evidence."},
				{Number: "03", Actor: "Envelope", Action: "Enable only a complete managed setup capability.", Checks: "Explicit enable flag, HTTPS control origin, private token/key files, declarations, distinct private sockets.", Evidence: "Readiness posture without configuration values."},
				{Number: "04", Actor: "Pharos + human", Action: "Begin the signed-intent setup flow for one exact target.", Checks: "Current policy/declaration, session step-up, replay controls, and selected source.", Evidence: "Intent, proof, and terminal value-free operation receipt."},
			},
		},
		{
			Slug: "host-retirement", Title: "Host retirement", Summary: "Retire a host's Pharos identity and every secret relationship it could legitimately consume, preserving value-free evidence.",
			Enforced: "The admin retirement path is scope- and role-checked, reconciles durable intent/state, publishes a generation that excludes the host, and can detach destroyed metadata only after exact tombstone and manifest conditions hold. A retired executor refuses restore and install.",
			Intended: "Janus cannot remotely erase a lost or compromised machine. Operators must also raise the revocation epoch, rotate every exposed secret, remove declarations only after retirement completes, and perform provider deletion separately when required.",
			Evidence: "Retirement intent/state, token generation, lifecycle transitions, tombstones, reconcile result, successor/disposition metadata, and value_returned=false/provider_deleted=false.",
			Steps: []KnowledgeStep{
				{Number: "01", Actor: "Owner", Action: "Record the reviewed host disposition and successor plan.", Checks: "Exact host, scope, profiles, manifest membership, retention, and reason label.", Evidence: "Durable value-free retirement intent."},
				{Number: "02", Actor: "Janus admin", Action: "Retire the host identity and reconcile the generation.", Checks: "Admin plane, role, release/audit posture, current state, and generation integrity.", Evidence: "Retirement state and generation fingerprint."},
				{Number: "03", Actor: "Secret owners", Action: "Disable, rotate, or destroy every affected secret relationship.", Checks: "Consumer migration, lifecycle transitions, provider-specific rotation, tombstone prerequisites.", Evidence: "Rotation/lifecycle outcomes and tombstones."},
				{Number: "04", Actor: "Operator + auditor", Action: "Raise revocation, remove completed declarations, and reconcile metadata.", Checks: "Executor retired, no manifest references, exact tombstones, complete retirement, no unrelated drift.", Evidence: "Reconcile and metadata-detach receipts."},
			},
		},
		{
			Slug: "break-glass", Title: "Break-glass activation and closure", Summary: "Four distinct roles create, approve, use, and independently close one emergency action.",
			Enforced: "Only managed-run or env-file use can be activated. Eligibility, exact scope/target, 15-minute request ceiling, separate approval, exact beneficiary use, one admitted attempt, revocation/expiry, critical audit, and independent reviewer comparisons are enforced and durable.",
			Intended: "The distinct-principal checks compare Janus principal binding keys, not cryptographically authenticated physical people. Treat them as strong workflow accountability, not proof that one human cannot control multiple pre-bound identities.",
			Evidence: "Request, activation, admitted attempt, completion/revocation, findings, remediation, terminal closure, and critical value-free audit chain.",
			Steps: []KnowledgeStep{
				{Number: "01", Actor: "Security admin", Action: "Request one short activation for an eligible beneficiary.", Checks: "Active break_glass_admin binding, scope, permission, target, reason, expiry, and audit.", Evidence: "Pending emergency request."},
				{Number: "02", Actor: "Approver", Action: "Approve the exact unexpired request.", Checks: "Approver differs from activator and beneficiary; approval authority and audit are current.", Evidence: "One exact activation."},
				{Number: "03", Actor: "Beneficiary", Action: "Perform the one reviewed managed-run or env-file action.", Checks: "Exact beneficiary/profile/scope/action; activation is consumed before execution completes.", Evidence: "Admitted attempt and completion or review-required state."},
				{Number: "04", Actor: "Independent auditor", Action: "Record findings, remediation, and terminal closure.", Checks: "Reviewer differs from activator, approver, and beneficiary; closure vocabulary is strict.", Evidence: "closed_no_findings or closed_remediated review."},
			},
		},
		{
			Slug: "role-binding-lifecycle", Title: "Role binding lifecycle and bootstrap", Summary: "An empty enforced registry receives one narrow bootstrap binding, then normal reviewed role administration takes over.",
			Enforced: "Bootstrap works only for an exactly empty locked registry, the exact acknowledgement, the current principal, security_admin, and at most one hour. Normal issue checks scope, target rules, code ceiling, policy matrix, grantor/recipient inequality, expiry, source, audit, and release posture.",
			Intended: "Issue durable reviewed bindings promptly and let bootstrap expire. OIDC and local binding sources still depend on deployment identity quality; the broader duty matrix must not be presented as authenticated-person separation.",
			Evidence: "Opaque binding id, role, scope, source-kind fingerprint, validity, status/revocation, role_binding_bootstrapped or normal decision reason, and audit record.",
			Steps: []KnowledgeStep{
				{Number: "01", Actor: "Bootstrap operator", Action: "Create the first short security_admin binding.", Checks: "Explicit enforced mode, private registry/audit paths, exact ack, empty registry lock, current principal, one-hour cap.", Evidence: "unsafe_bootstrap binding and critical bootstrap audit."},
				{Number: "02", Actor: "Security admin", Action: "Issue reviewed bindings for operational roles.", Checks: "Role matrix ceiling, exact scope, service/workload target rules, grantor differs from subject, TTL and source.", Evidence: "local_reviewed or OIDC-sourced binding records."},
				{Number: "03", Actor: "Runtime", Action: "Resolve active bindings for every protected action.", Checks: "Principal, scope, target, role, permission, lifecycle/class, expiry, revocation, audit, release posture.", Evidence: "Value-free authorization decision and reason code."},
				{Number: "04", Actor: "Security admin + auditor", Action: "Revoke stale grants and inspect exact status.", Checks: "Immutable revocation, binding integrity, current policy, independent review of bootstrap residue.", Evidence: "Status/list result and revocation audit."},
			},
		},
	}
}

func knowledgeFlowBySlug(slug string) (KnowledgeFlow, bool) {
	for _, flow := range knowledgeFlows() {
		if flow.Slug == slug {
			return flow, true
		}
	}
	return KnowledgeFlow{}, false
}

func knowledgeFlowTitle(slug string) string {
	switch slug {
	case "manual-secret-entry":
		return "Manual secret entry"
	case "generated-rotation":
		return "Generated rotation"
	case "approved-use":
		return "Approved use end to end"
	case "env-file-handoff":
		return "Env-file handoff"
	case "managed-service-onboarding":
		return "Managed-service onboarding"
	case "host-retirement":
		return "Host retirement"
	case "break-glass":
		return "Break-glass activation and closure"
	case "role-binding-lifecycle":
		return "Role binding lifecycle and bootstrap"
	default:
		return strings.ReplaceAll(slug, "-", " ")
	}
}
