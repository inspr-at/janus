import {
  sanitizeAction,
  sanitizeDigest,
  sanitizeExecutionMode,
  sanitizeInitials,
  sanitizeRef,
  sanitizeText,
  sanitizeTimestamp,
  sanitizeUrl,
} from './sanitize.js';
import { ACTIONS } from './stages.js';
import { identityBinding, isValidatedIdentity, normalizeIdentityContext, rejectUntrustedIdentity } from './identity.js';

const DEFAULT_EXECUTION_MODES = ['manual', 'assisted', 'automatic'];
export const CONFIRMATION_TTL_MS = 5 * 60 * 1000;
export const EVALUATION_MAX_AGE_MS = 15 * 60 * 1000;
export const CLOCK_SKEW_MS = 60 * 1000;
export const CLOCK_AGING_MIN_INTERVAL_MS = 10 * 60 * 1000;

const READINESS = ['preliminary', 'ready', 'live', 'blocked', 'unknown'];
const STAGE_EVIDENCE = ['performed', 'not_in_batch', 'unknown'];
const ARTIFACT_ORIGINS = ['produced', 'imported'];

function normalizeGate(entry, fallbackMessage, fallbackKind) {
  const status = ['pass', 'fail', 'unknown'].includes(entry?.status) ? entry.status : 'unknown';
  const readinessRaw = sanitizeText(entry?.readiness, { maxLength: 32 });
  const originRaw = sanitizeText(entry?.origin, { maxLength: 32 });
  return {
    status,
    message: sanitizeText(entry?.message ?? fallbackMessage, { maxLength: 400 }),
    readiness: READINESS.includes(readinessRaw) ? readinessRaw : undefined,
    gateKind: sanitizeRef(entry?.gateKind) ?? sanitizeRef(fallbackKind) ?? null,
    evidenceRef: sanitizeRef(entry?.evidenceRef) ?? null,
    observedAt: sanitizeTimestamp(entry?.observedAt),
    freshUntil: sanitizeTimestamp(entry?.freshUntil),
    targetRef: sanitizeRef(entry?.targetRef) ?? null,
    digest: sanitizeDigest(entry?.digest),
    origin: ARTIFACT_ORIGINS.includes(originRaw) ? originRaw : null,
    producingTaskRef: sanitizeRef(entry?.producingTaskRef) ?? null,
    importReceiptRef: sanitizeRef(entry?.importReceiptRef) ?? null,
  };
}

function evidenceBinding(entry) {
  return {
    status: entry?.status ?? 'unknown',
    gateKind: entry?.gateKind ?? null,
    evidenceRef: entry?.evidenceRef ?? null,
    observedAt: entry?.observedAt ?? null,
    freshUntil: entry?.freshUntil ?? null,
    targetRef: entry?.targetRef ?? null,
    readiness: entry?.readiness ?? null,
    digest: entry?.digest ?? null,
    origin: entry?.origin ?? null,
    producingTaskRef: entry?.producingTaskRef ?? null,
    importReceiptRef: entry?.importReceiptRef ?? null,
  };
}

function normalizeSnapshot(entry) {
  if (!entry || typeof entry !== 'object') return null;
  return {
    progress: entry.progress && typeof entry.progress === 'object' ? { ...entry.progress } : null,
    forecast: entry.forecast && typeof entry.forecast === 'object' ? { ...entry.forecast } : null,
    ...(sanitizeRef(entry.task_ref) ? { task_ref: sanitizeRef(entry.task_ref) } : {}),
  };
}

export function confirmationBinding(shellState, { action, executionMode } = {}) {
  return {
    batchRef: shellState.delivery.batchRef,
    baselineRef: shellState.delivery.baselineRef,
    baselineDigest: shellState.delivery.baselineDigest,
    evaluatedAt: shellState.evaluatedAt ?? null,
    executionMode: executionMode ?? shellState.selectedExecutionMode ?? null,
    action: action ?? shellState.selectedAction ?? null,
    scopeItems: [...(shellState.delivery.scopeItems ?? [])],
    identity: identityBinding(shellState.identity),
    evidence: {
      requirementsBaseline: evidenceBinding(shellState.prerequisites.requirementsBaseline),
      deployArtifact: evidenceBinding(shellState.prerequisites.deployArtifact),
      pharosTarget: evidenceBinding(shellState.prerequisites.pharosTarget),
      janusGate: evidenceBinding(shellState.prerequisites.janusGate),
    },
  };
}

export function normalizeShellState(input = {}) {
  const executionModes = Array.isArray(input.executionModes)
    ? input.executionModes
        .map((mode) => sanitizeExecutionMode(mode, DEFAULT_EXECUTION_MODES))
        .filter(Boolean)
    : DEFAULT_EXECUTION_MODES;
  const selectedExecutionMode =
    sanitizeExecutionMode(input.selectedExecutionMode, executionModes) ?? executionModes[0];
  const selectedAction = sanitizeAction(input.selectedAction, ACTIONS) ?? 'build';

  const delivery = input.delivery ?? {};
  const progress = input.progress ?? {};

  return {
    header: {
      appName: sanitizeText(input.header?.appName ?? 'INSPR', { maxLength: 40 }) || 'INSPR',
      instanceLabel: sanitizeText(input.header?.instanceLabel, { maxLength: 80 }),
      version: sanitizeText(input.header?.version, { maxLength: 40 }),
      userInitials: sanitizeInitials(input.header?.userInitials ?? '?'),
      userLabel: sanitizeText(input.header?.userLabel, { maxLength: 80 }),
      projectName: sanitizeText(input.header?.projectName ?? 'Project', { maxLength: 80 }) || 'Project',
      projectSubtitle: sanitizeText(input.header?.projectSubtitle, { maxLength: 120 }),
    },
    health: {
      status: ['available', 'degraded', 'unknown'].includes(input.health?.status)
        ? input.health.status
        : 'unknown',
      label: sanitizeText(input.health?.label ?? 'Service status unknown', { maxLength: 120 }),
      checkedLabel: sanitizeText(input.health?.checkedLabel, { maxLength: 120 }),
      url: sanitizeUrl(input.health?.url),
    },
    delivery: {
      liveReleaseLabel: sanitizeText(delivery.liveReleaseLabel ?? 'Live product', { maxLength: 80 }),
      batchTitle: sanitizeText(delivery.batchTitle ?? 'Delivery batch', { maxLength: 120 }),
      batchSummary: sanitizeText(delivery.batchSummary, { maxLength: 160 }),
      draftCount: Number.isFinite(delivery.draftCount) ? Math.max(0, Math.floor(delivery.draftCount)) : 0,
      mapDetail: sanitizeText(delivery.mapDetail, { maxLength: 800 }),
      batchRef: sanitizeRef(delivery.batchRef),
      baselineRef: sanitizeRef(delivery.baselineRef),
      baselineDigest: sanitizeDigest(delivery.baselineDigest),
      status: ['draft', 'authorized', 'in_progress', 'blocked', 'completed'].includes(delivery.status)
        ? delivery.status
        : 'draft',
      activeStage: Number.isFinite(delivery.activeStage)
        ? Math.min(3, Math.max(0, Math.floor(delivery.activeStage)))
        : 0,
      activeTaskRef: sanitizeRef(delivery.activeTaskRef),
      activeOperation: sanitizeText(delivery.activeOperation, { maxLength: 32 }),
      stageEvidence: Array.isArray(delivery.stageEvidence)
        ? [0, 1, 2, 3].map((index) =>
            STAGE_EVIDENCE.includes(delivery.stageEvidence[index]) ? delivery.stageEvidence[index] : 'unknown',
          )
        : ['unknown', 'unknown', 'unknown', 'unknown'],
      viewedStage: Number.isFinite(delivery.viewedStage)
        ? Math.min(3, Math.max(0, Math.floor(delivery.viewedStage)))
        : Number.isFinite(delivery.activeStage)
          ? Math.min(3, Math.max(0, Math.floor(delivery.activeStage)))
          : 0,
      batchStatusLabel: sanitizeText(delivery.batchStatusLabel ?? 'Ready to begin', { maxLength: 80 }),
      scopeItems: Array.isArray(delivery.scopeItems)
        ? delivery.scopeItems
            .map((item) => sanitizeText(item, { maxLength: 160 }))
            .filter(Boolean)
            .slice(0, 12)
        : [],
    },
    prerequisites: {
      requirementsBaseline: normalizeGate(
        input.prerequisites?.requirementsBaseline,
        'Requirements baseline evidence is required before delivery work.',
        'requirements_baseline',
      ),
      deployArtifact: normalizeGate(
        input.prerequisites?.deployArtifact,
        'Deployable artifact evidence is required before deployment intent.',
        'artifact',
      ),
      pharosTarget: normalizeGate(
        input.prerequisites?.pharosTarget,
        'Pharos target readiness must be observed before dependent work.',
        'target_readiness',
      ),
      janusGate: normalizeGate(
        input.prerequisites?.janusGate,
        'Janus access application requires a ready or live Pharos target and access evidence.',
        'access',
      ),
    },
    progress: {
      taskLabel: sanitizeText(progress.taskLabel ?? 'Current task', { maxLength: 120 }),
      overallLabel: sanitizeText(progress.overallLabel ?? 'Overall', { maxLength: 80 }),
      task: normalizeSnapshot(progress.task),
      overall: normalizeSnapshot(progress.overall),
      freshnessLabel: sanitizeText(progress.freshnessLabel, { maxLength: 160 }),
    },
    executionModes,
    selectedExecutionMode,
    selectedAction,
    evaluatedAt: sanitizeTimestamp(input.evaluatedAt),
    mapExpanded: Boolean(input.mapExpanded),
    identity: resolveIdentity(input),
  };
}

function resolveIdentity(input) {
  if (Object.prototype.hasOwnProperty.call(input, 'identityContext')) {
    return normalizeIdentityContext(input.identityContext);
  }
  if (isValidatedIdentity(input.identity)) {
    return input.identity;
  }
  if (input.identity != null) {
    return rejectUntrustedIdentity();
  }
  return normalizeIdentityContext(null);
}

export function withIdentityContext(shellState, identityContext) {
  return normalizeShellState({
    ...shellState,
    identityContext,
  });
}

export function confirmationSnapshot(
  shellState,
  { now = Date.now(), ttlMs = CONFIRMATION_TTL_MS, action, executionMode } = {},
) {
  return {
    ...confirmationBinding(shellState, {
      action: sanitizeAction(action, ACTIONS) ?? shellState.selectedAction,
      executionMode:
        sanitizeExecutionMode(executionMode, shellState.executionModes) ?? shellState.selectedExecutionMode,
    }),
    capturedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + ttlMs).toISOString(),
  };
}

function omitTemporal(snapshot) {
  if (!snapshot) return null;
  const { capturedAt, expiresAt, ...binding } = snapshot;
  return binding;
}

export function snapshotsMatch(current, captured) {
  if (!current || !captured) return false;
  return JSON.stringify(omitTemporal(current)) === JSON.stringify(omitTemporal(captured));
}

export function isConfirmationExpired(snapshot, now = Date.now()) {
  if (!snapshot?.expiresAt) return true;
  const expires = Date.parse(snapshot.expiresAt);
  if (Number.isNaN(expires)) return true;
  return now > expires;
}

export function isEvaluatedAtUsable(evaluatedAt, now = Date.now()) {
  const parsed = Date.parse(evaluatedAt);
  if (Number.isNaN(parsed)) return false;
  if (parsed > now + CLOCK_SKEW_MS) return false;
  if (now - parsed > EVALUATION_MAX_AGE_MS) return false;
  return true;
}

function parseBoundaryMs(value) {
  if (!value) return null;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? null : parsed;
}

function freshUntilMs(entry) {
  if (!entry || typeof entry !== 'object') return null;
  return parseBoundaryMs(entry.freshUntil ?? entry.fresh_until);
}

function collectIdentityBoundaries(identity, boundaries) {
  if (identity?.status !== 'present' || !identity.value) return;
  const value = identity.value;
  for (const field of [value.freshUntil, value.expiresAt]) {
    const parsed = parseBoundaryMs(field);
    if (parsed != null) boundaries.push({ instant: parsed, inclusive: true });
  }
}

function pushExclusiveBoundary(boundaries, boundaryMs) {
  if (boundaryMs == null) return;
  boundaries.push({ instant: boundaryMs + 1, inclusive: false });
}

function collectProgressWakeBoundaries(progressState, boundaries) {
  for (const snapshot of [progressState?.task, progressState?.overall]) {
    pushExclusiveBoundary(boundaries, freshUntilMs(snapshot?.progress));
    pushExclusiveBoundary(boundaries, parseBoundaryMs(snapshot?.forecast?.estimated_finish));
  }
}

function collectGateWakeBoundaries(prerequisites, boundaries) {
  for (const gate of Object.values(prerequisites ?? {})) {
    pushExclusiveBoundary(boundaries, freshUntilMs(gate));
  }
}

export function collectClockAgingBoundaries(shellState, { now = Date.now(), extraBoundaries = [] } = {}) {
  const boundaries = [];
  const evaluatedAt = parseBoundaryMs(shellState?.evaluatedAt);
  if (evaluatedAt != null) pushExclusiveBoundary(boundaries, evaluatedAt + EVALUATION_MAX_AGE_MS);
  collectProgressWakeBoundaries(shellState?.progress, boundaries);
  collectGateWakeBoundaries(shellState?.prerequisites, boundaries);
  collectIdentityBoundaries(shellState?.identity, boundaries);
  for (const boundary of extraBoundaries) {
    pushExclusiveBoundary(boundaries, parseBoundaryMs(boundary));
  }
  return boundaries
    .map((entry) => entry.instant)
    .filter((instant) => instant > now);
}

export function nextClockAgingDelayMs(shellState, { now = Date.now(), extraBoundaries = [] } = {}) {
  const upcoming = collectClockAgingBoundaries(shellState, { now, extraBoundaries });
  if (upcoming.length === 0) return CLOCK_AGING_MIN_INTERVAL_MS;
  const delay = Math.min(...upcoming) - now;
  if (delay <= 0) return 0;
  return Math.min(delay, CLOCK_AGING_MIN_INTERVAL_MS);
}

export function withViewedStage(shellState, stageIndex) {
  const next = normalizeShellState(shellState);
  next.delivery.viewedStage = Math.min(3, Math.max(0, stageIndex));
  return next;
}

export function withMapExpanded(shellState, expanded) {
  const next = normalizeShellState(shellState);
  next.mapExpanded = Boolean(expanded);
  return next;
}

export function withExecutionMode(shellState, mode) {
  const next = normalizeShellState(shellState);
  const picked = sanitizeExecutionMode(mode, next.executionModes);
  if (picked) next.selectedExecutionMode = picked;
  return next;
}

export function withSelectedAction(shellState, action) {
  const next = normalizeShellState(shellState);
  const picked = sanitizeAction(action, ACTIONS);
  if (picked) next.selectedAction = picked;
  return next;
}
