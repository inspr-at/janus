/**
 * Host-issued Flow identity/context. Schema validity is not authentication.
 * Opaque refs are host-scoped; display labels are untrusted. Tokens, email,
 * roles, raw OIDC subjects, and session secrets are rejected, not stripped.
 */
import { sanitizeText } from './sanitize.js';

export const IDENTITY_CONTRACT_VERSION = 'inspr.flow-identity/0.1-draft';
export const AUTHORITY_DISCLAIMER =
  'Schema validity is not authentication. Host must issue this context from a verified principal and revalidate on every consequential intent.';
export const PRINCIPAL_KINDS = Object.freeze(['local_host', 'oidc_backed']);
export const ACTOR_KINDS = Object.freeze(['human', 'agent']);
export const IDENTITY_SKEW_MS = 60 * 1000;

const HOST_ID = /^[A-Za-z][A-Za-z0-9._-]{0,63}$/;
const OPAQUE_REF = /^[A-Za-z][A-Za-z0-9._:-]{0,159}$/;
const MAX_REF_LENGTH = 160;
const FORBIDDEN_KEY = /(token|secret|cookie|email|session|subject|^sub$|^role$|^roles$|password|authorization|bearer|csrf)/i;
const JWTISH = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const VALIDATED_IDENTITY = new WeakSet();

const DISPLAY_KEYS = new Set([
  'user_label',
  'user_initials',
  'project_label',
  'organization_label',
  'issuer_label',
  'fixture_label',
]);

function collectForbiddenKeys(value, path, found) {
  if (Array.isArray(value)) {
    value.forEach((child, index) => collectForbiddenKeys(child, `${path}[${index}]`, found));
    return;
  }
  if (!value || typeof value !== 'object') return;
  for (const [key, child] of Object.entries(value)) {
    if (FORBIDDEN_KEY.test(key)) found.push(`${path}.${key}`);
    collectForbiddenKeys(child, `${path}.${key}`, found);
  }
}

function walkStrings(value, visit) {
  if (typeof value === 'string') visit(value);
  else if (Array.isArray(value)) value.forEach((child) => walkStrings(child, visit));
  else if (value && typeof value === 'object') Object.values(value).forEach((child) => walkStrings(child, visit));
}

function brandIdentity(identity) {
  if (identity.value && typeof identity.value === 'object') {
    if (identity.value.display) Object.freeze(identity.value.display);
    Object.freeze(identity.value);
  }
  Object.freeze(identity.reasons);
  Object.freeze(identity);
  VALIDATED_IDENTITY.add(identity);
  return identity;
}

export function isValidatedIdentity(identity) {
  return Boolean(identity) && typeof identity === 'object' && VALIDATED_IDENTITY.has(identity);
}

function hostScoped(hostId, ref) {
  if (typeof ref !== 'string' || ref.length > MAX_REF_LENGTH || !OPAQUE_REF.test(ref)) return null;
  if (!hostId) return null;
  if (ref.includes('@') || (ref.match(/\./g) ?? []).length > 1) return null;
  const prefix = `${hostId}:`;
  if (!ref.startsWith(prefix) || ref === prefix) return null;
  return ref;
}

function parseTime(value) {
  if (typeof value !== 'string') return null;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? null : { text: value, ms: parsed };
}

/**
 * @returns {{
 *   status: 'absent' | 'rejected' | 'present',
 *   reasons: string[],
 *   value: object | null,
 * }}
 */
export function normalizeIdentityContext(input) {
  if (input == null || input === false) {
    return brandIdentity({ status: 'absent', reasons: [], value: null });
  }
  if (typeof input !== 'object' || Array.isArray(input)) {
    return brandIdentity({
      status: 'rejected',
      reasons: ['Host identity context is malformed.'],
      value: null,
    });
  }

  const reasons = [];
  const forbidden = [];
  collectForbiddenKeys(input, '$', forbidden);
  if (forbidden.length) {
    reasons.push('Host identity context contains forbidden credential or secret fields.');
  }
  walkStrings(input, (text) => {
    if (JWTISH.test(text.trim())) reasons.push('Host identity context must not carry JWT-like values.');
  });

  const allowed = new Set([
    'contract_version',
    'evaluated_at',
    'host_id',
    'principal_kind',
    'principal_ref',
    'binding_ref',
    'issuer_descriptor',
    'organization_ref',
    'project_ref',
    'actor_kind',
    'issued_at',
    'expires_at',
    'fresh_until',
    'context_revision',
    'authority_disclaimer',
    'display',
  ]);
  const unknown = Object.keys(input).filter((key) => !allowed.has(key));
  if (unknown.length) reasons.push('Host identity context contains unknown fields.');

  if (input.contract_version !== IDENTITY_CONTRACT_VERSION) {
    reasons.push('Unsupported Flow identity contract version.');
  }
  if (input.authority_disclaimer !== AUTHORITY_DISCLAIMER) {
    reasons.push('Identity context must keep the non-auth disclaimer.');
  }

  const evaluated = parseTime(input.evaluated_at);
  if (!evaluated) reasons.push('evaluated_at is missing or invalid.');

  const hostId = typeof input.host_id === 'string' && HOST_ID.test(input.host_id) ? input.host_id : '';
  if (!hostId) reasons.push('host_id is missing or not a namespace.');

  const principalKind = PRINCIPAL_KINDS.includes(input.principal_kind) ? input.principal_kind : '';
  if (!principalKind) reasons.push('principal_kind must be local_host or oidc_backed.');

  const actorKind = ACTOR_KINDS.includes(input.actor_kind) ? input.actor_kind : '';
  if (!actorKind) reasons.push('actor_kind must be human or agent.');

  const principalRef = hostScoped(hostId, input.principal_ref);
  const bindingRef = hostScoped(hostId, input.binding_ref);
  const projectRef = hostScoped(hostId, input.project_ref);
  const contextRevision = hostScoped(hostId, input.context_revision);
  if (!principalRef) reasons.push('principal_ref must be host-scoped and opaque.');
  if (!bindingRef) reasons.push('binding_ref must be host-scoped and opaque.');
  if (!projectRef) reasons.push('project_ref must be host-scoped.');
  if (!contextRevision) reasons.push('context_revision must be host-scoped.');

  let organizationRef = null;
  if (input.organization_ref !== undefined && input.organization_ref !== null) {
    organizationRef = hostScoped(hostId, input.organization_ref);
    if (!organizationRef) reasons.push('organization_ref must be host-scoped when present.');
    else if (organizationRef === projectRef || organizationRef === hostId) {
      reasons.push('organization_ref cannot be invented from project or host.');
    } else if (organizationRef.split(':').slice(1).join(':').includes('.')) {
      reasons.push('organization_ref cannot be invented from a domain.');
    }
  }

  let issuerRef = null;
  if (principalKind === 'local_host' && input.issuer_descriptor != null) {
    reasons.push('local_host context must not claim an issuer descriptor.');
  }
  if (principalKind === 'oidc_backed') {
    const descriptor = input.issuer_descriptor;
    if (!descriptor || typeof descriptor !== 'object' || descriptor.kind !== 'verified_issuer_descriptor') {
      reasons.push('oidc_backed context requires a verified issuer descriptor.');
    } else {
      issuerRef = hostScoped(hostId, descriptor.issuer_ref);
      if (!issuerRef) reasons.push('issuer_ref must be host-scoped and opaque.');
      const extra = Object.keys(descriptor).filter((key) => key !== 'kind' && key !== 'issuer_ref');
      if (extra.length) reasons.push('issuer descriptor contains unknown fields.');
    }
  }

  const issued = parseTime(input.issued_at);
  const expires = parseTime(input.expires_at);
  const freshUntil = parseTime(input.fresh_until);
  if (!issued || !expires || !freshUntil) reasons.push('Identity context times are missing or invalid.');
  else if (issued.ms >= expires.ms || issued.ms >= freshUntil.ms) {
    reasons.push('Identity context times are inconsistent.');
  }
  if (evaluated && issued && issued.ms > evaluated.ms) {
    reasons.push('Host identity context is not yet valid.');
  }
  if (evaluated && expires && evaluated.ms >= expires.ms) {
    reasons.push('Host identity context has expired.');
  }
  if (evaluated && freshUntil && evaluated.ms >= freshUntil.ms) {
    reasons.push('Host identity context is stale.');
  }

  const displayInput =
    input.display && typeof input.display === 'object' && !Array.isArray(input.display) ? input.display : {};
  const extraDisplay = Object.keys(displayInput).filter((key) => !DISPLAY_KEYS.has(key));
  if (extraDisplay.length) reasons.push('Identity display contains unknown fields.');
  const fixtureLabel = sanitizeText(displayInput.fixture_label, { maxLength: 240 });
  if (!fixtureLabel) reasons.push('Labelled identity fixtures must declare they are not live identity.');
  else if (
    fixtureLabel.toLowerCase().includes('live identity') &&
    !fixtureLabel.toLowerCase().includes('no live') &&
    !fixtureLabel.toLowerCase().includes('not live')
  ) {
    reasons.push('Labelled identity fixtures must declare they are not live identity.');
  }
  for (const value of Object.values(displayInput)) {
    if (typeof value !== 'string' || value.includes('@')) {
      reasons.push('Identity display must not carry email or forbidden identity material.');
      break;
    }
  }

  const unique = [...new Set(reasons)];
  if (unique.length) return brandIdentity({ status: 'rejected', reasons: unique, value: null });

  return brandIdentity({
    status: 'present',
    reasons: [],
    value: {
      contractVersion: IDENTITY_CONTRACT_VERSION,
      hostId,
      principalKind,
      principalRef,
      bindingRef,
      issuerRef,
      organizationRef,
      projectRef,
      actorKind,
      issuedAt: issued.text,
      expiresAt: expires.text,
      freshUntil: freshUntil.text,
      contextRevision,
      display: {
        userLabel: sanitizeText(displayInput.user_label, { maxLength: 80 }),
        userInitials: sanitizeText(displayInput.user_initials, { maxLength: 8 }),
        projectLabel: sanitizeText(displayInput.project_label, { maxLength: 80 }),
        organizationLabel: sanitizeText(displayInput.organization_label, { maxLength: 80 }),
        issuerLabel: sanitizeText(displayInput.issuer_label, { maxLength: 80 }),
        fixtureLabel,
      },
    },
  });
}

export function identityBinding(identity) {
  if (!identity || identity.status !== 'present' || !identity.value) {
    return { status: identity?.status ?? 'absent' };
  }
  const value = identity.value;
  return {
    status: 'present',
    hostId: value.hostId,
    principalKind: value.principalKind,
    principalRef: value.principalRef,
    bindingRef: value.bindingRef,
    issuerRef: value.issuerRef,
    organizationRef: value.organizationRef,
    projectRef: value.projectRef,
    actorKind: value.actorKind,
    contextRevision: value.contextRevision,
    issuedAt: value.issuedAt,
    expiresAt: value.expiresAt,
    freshUntil: value.freshUntil,
  };
}

export function identityFreshnessIssues(identity, now = Date.now()) {
  if (!identity || identity.status === 'absent') {
    return ['Host identity context is required before a consequential start.'];
  }
  if (identity.status !== 'present' || !identity.value) {
    return identity.reasons?.length
      ? [...identity.reasons]
      : ['Host identity context was rejected.'];
  }
  const value = identity.value;
  const issued = Date.parse(value.issuedAt);
  const expires = Date.parse(value.expiresAt);
  const freshUntil = Date.parse(value.freshUntil);
  const reasons = [];
  if (Number.isNaN(issued) || issued > now + IDENTITY_SKEW_MS) {
    reasons.push('Host identity context is not yet valid.');
  }
  if (Number.isNaN(expires) || now >= expires) {
    reasons.push('Host identity context has expired.');
  }
  if (Number.isNaN(freshUntil) || now >= freshUntil) {
    reasons.push('Host identity context is stale.');
  }
  return reasons;
}

export function identityStartIssues(identity, { now = Date.now(), requireHuman = true } = {}) {
  const reasons = identityFreshnessIssues(identity, now);
  if (
    requireHuman &&
    identity?.status === 'present' &&
    identity.value &&
    identity.value.actorKind !== 'human'
  ) {
    reasons.push('A human host principal is required for this start.');
  }
  return [...new Set(reasons)];
}

export function rejectUntrustedIdentity() {
  return brandIdentity({
    status: 'rejected',
    reasons: ['Host identity context must come from a host-issued identityContext.'],
    value: null,
  });
}
