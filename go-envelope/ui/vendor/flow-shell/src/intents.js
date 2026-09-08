import { ACTIONS } from './stages.js';
import { canEmitStartIntent } from './gates.js';
import {
  confirmationSnapshot,
  isConfirmationExpired,
  snapshotsMatch,
} from './state.js';
import { identityBinding } from './identity.js';
import { sanitizeAction, sanitizeExecutionMode, sanitizeRef, sanitizeText } from './sanitize.js';

export const INTENT_TYPES = {
  NAVIGATE_STAGE: 'flow:navigate-stage',
  TOGGLE_MAP: 'flow:toggle-map',
  REVIEW_BATCH: 'flow:review-batch',
  SAVE_PROPOSAL: 'flow:save-proposal',
  START_INTENT: 'flow:start-intent',
  HEADER_IDENTITY: 'flow:header-identity',
  HEADER_PROJECT: 'flow:header-project',
  HEADER_ACCOUNT: 'flow:header-account',
  HEALTH: 'flow:health',
  VIEW_DRAFTS: 'flow:view-drafts',
};

function baseIntent(type, detail) {
  return {
    type,
    detail,
    emittedAt: new Date().toISOString(),
    authorityNote:
      'Host must revalidate authority. UI gates are advisory; this component is not a security or auth backend.',
  };
}

export function createNavigateStageIntent(stageIndex) {
  return baseIntent(INTENT_TYPES.NAVIGATE_STAGE, {
    stageIndex,
    executes: false,
  });
}

export function createToggleMapIntent(expanded) {
  return baseIntent(INTENT_TYPES.TOGGLE_MAP, { expanded, executes: false });
}

export function createReviewBatchIntent(shellState) {
  return baseIntent(INTENT_TYPES.REVIEW_BATCH, {
    batchRef: shellState.delivery.batchRef,
    baselineRef: shellState.delivery.baselineRef,
    baselineDigest: shellState.delivery.baselineDigest,
    action: shellState.selectedAction,
    executes: false,
  });
}

export function createSaveProposalIntent(text) {
  const proposal = sanitizeText(text, { maxLength: 2000 });
  if (!proposal) return { error: 'Proposal text is empty after sanitization.' };
  return baseIntent(INTENT_TYPES.SAVE_PROPOSAL, {
    proposal,
    executes: false,
  });
}

export function createStartIntent(
  shellState,
  { confirmed, executionMode, capturedSnapshot, action, now = Date.now() } = {},
) {
  const mode = sanitizeExecutionMode(executionMode, shellState.executionModes);
  const selectedAction = sanitizeAction(action, ACTIONS) ?? sanitizeAction(shellState.selectedAction, ACTIONS);
  const currentSnapshot = confirmationSnapshot(shellState, {
    now,
    action: selectedAction,
    executionMode: mode,
  });

  if (!capturedSnapshot || isConfirmationExpired(capturedSnapshot, now)) {
    return {
      error: 'Confirmation snapshot has expired. Refresh the review dialog and confirm again.',
      stale: true,
      expected: currentSnapshot,
      captured: capturedSnapshot,
    };
  }

  if (!snapshotsMatch(currentSnapshot, capturedSnapshot)) {
    return {
      error: 'Confirmation snapshot is stale. Refresh the review dialog and confirm again.',
      stale: true,
      expected: currentSnapshot,
      captured: capturedSnapshot,
    };
  }

  const gate = canEmitStartIntent(shellState, {
    confirmed,
    executionMode: mode,
    action: selectedAction,
    now,
  });
  if (!gate.allowed) {
    return { error: gate.reasons.join(' '), reasons: gate.reasons };
  }

  return baseIntent(INTENT_TYPES.START_INTENT, {
    batchRef: sanitizeRef(shellState.delivery.batchRef),
    baselineRef: sanitizeRef(shellState.delivery.baselineRef),
    baselineDigest: shellState.delivery.baselineDigest,
    executionMode: mode,
    action: selectedAction,
    snapshot: capturedSnapshot,
    identity: identityBinding(shellState.identity),
    executes: false,
    hostMust: [
      'revalidate authority',
      'verify baseline digest',
      'revalidate host identity context',
      'persist authorization record',
    ],
  });
}

export function createHeaderIntent(kind) {
  const map = {
    identity: INTENT_TYPES.HEADER_IDENTITY,
    project: INTENT_TYPES.HEADER_PROJECT,
    account: INTENT_TYPES.HEADER_ACCOUNT,
  };
  return baseIntent(map[kind] ?? INTENT_TYPES.HEADER_IDENTITY, { executes: false });
}

export function createHealthIntent(url) {
  return baseIntent(INTENT_TYPES.HEALTH, { url: url ?? null, executes: false });
}

export function createViewDraftsIntent(count) {
  return baseIntent(INTENT_TYPES.VIEW_DRAFTS, {
    draftCount: Number.isFinite(count) ? Math.max(0, Math.floor(count)) : 0,
    executes: false,
  });
}
