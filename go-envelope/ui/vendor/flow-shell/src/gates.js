import { ACTIONS, STAGES } from './stages.js';
import { isEvaluatedAtUsable } from './state.js';
import { identityStartIssues } from './identity.js';

function gateMessage(entry, fallback) {
  return entry?.message || fallback;
}

export function evaluatePrerequisites(prerequisites = {}) {
  const requirements = prerequisites.requirementsBaseline ?? { status: 'unknown' };
  const artifact = prerequisites.deployArtifact ?? { status: 'unknown' };
  const pharos = prerequisites.pharosTarget ?? { status: 'unknown', readiness: 'unknown' };
  const janus = prerequisites.janusGate ?? { status: 'unknown' };

  return {
    requirements,
    artifact,
    pharos,
    janus,
    messages: {
      requirements: gateMessage(
        requirements,
        'Requirements baseline evidence is required before delivery work.',
      ),
      artifact: gateMessage(artifact, 'Deployable artifact evidence is required before deployment intent.'),
      pharos: gateMessage(pharos, 'Pharos target readiness must be observed before dependent work.'),
      janus: gateMessage(
        janus,
        'Janus access application requires a ready or live Pharos target and access evidence.',
      ),
    },
  };
}

function isGateStale(entry, now) {
  if (!entry) return true;
  if (!entry.freshUntil) return false;
  const parsed = Date.parse(entry.freshUntil);
  if (Number.isNaN(parsed)) return true;
  return now > parsed;
}

function qualify(label, text) {
  if (!text) return `${label} evidence is not pass.`;
  return text.toLowerCase().includes(String(label).toLowerCase()) ? text : `${label}: ${text}`;
}

function requiredGateReasons(entry, label, now, message) {
  const reasons = [];
  if (entry?.status !== 'pass') reasons.push(qualify(label, message));
  if (!entry?.evidenceRef) reasons.push(`${label} evidence reference is missing.`);
  if (!entry?.observedAt) reasons.push(`${label} observation time is missing.`);
  if (isGateStale(entry, now)) reasons.push(`${label} evidence is stale.`);
  return reasons;
}

function requiredTargetReasons(entry, allowedReadiness, now, message) {
  const reasons = requiredGateReasons(entry, 'Pharos target', now, message);
  if (!allowedReadiness.includes(entry?.readiness)) reasons.push(message);
  return [...new Set(reasons)];
}

export function actionEvidenceIssues(shellState, action, now = Date.now()) {
  const reasons = [];
  const prereq = evaluatePrerequisites(shellState.prerequisites);

  if (!ACTIONS.includes(action)) {
    reasons.push('Choose an action before starting.');
    return reasons;
  }

  reasons.push(
    ...requiredGateReasons(prereq.requirements, 'requirements', now, prereq.messages.requirements),
  );

  if (action === 'deploy' || action === 'verify') {
    reasons.push(...requiredGateReasons(prereq.artifact, 'artifact', now, prereq.messages.artifact));
    reasons.push(
      ...requiredTargetReasons(prereq.pharos, ['ready', 'live'], now, 'Deployment requires a ready or live Pharos target.'),
    );
  } else if (action === 'janus_prepare') {
    reasons.push(
      ...requiredTargetReasons(
        prereq.pharos,
        ['preliminary', 'ready', 'live'],
        now,
        'Janus preparation requires a defined preliminary, ready, or live Pharos target.',
      ),
    );
  } else if (action === 'janus_apply') {
    reasons.push(
      ...requiredTargetReasons(
        prereq.pharos,
        ['ready', 'live'],
        now,
        'Janus application requires a ready or live Pharos target.',
      ),
    );
    reasons.push(...requiredGateReasons(prereq.janus, 'access', now, prereq.messages.janus));
  }

  return [...new Set(reasons)];
}

export function getStageGate(stageIndex, shellState, { now = Date.now() } = {}) {
  const prereq = evaluatePrerequisites(shellState.prerequisites);
  const stage = STAGES[stageIndex] ?? STAGES[0];
  const active = shellState.delivery?.activeStage ?? 0;
  const batchStatus = shellState.delivery?.status ?? 'draft';

  if (stageIndex === 0) {
    const issues = requiredGateReasons(
      prereq.requirements,
      'requirements',
      now,
      prereq.messages.requirements,
    );
    return {
      gated: issues.length > 0,
      explorable: true,
      allowedActions: [],
      reason: issues[0] ?? null,
      product: stage.product,
    };
  }

  if (stageIndex === 1) {
    const issues = actionEvidenceIssues(shellState, 'build', now);
    const allowed = issues.length === 0 ? ['build', 'test'] : [];
    return {
      gated: issues.length > 0 || batchStatus === 'draft' || batchStatus === 'authorized',
      explorable: true,
      allowedActions: allowed,
      reason: issues[0]
        ? issues[0]
        : batchStatus === 'draft' || batchStatus === 'authorized'
          ? 'Build is gated until you review the batch and explicitly start delivery.'
          : null,
      product: stage.product,
      attention: batchStatus === 'blocked',
    };
  }

  if (stageIndex === 2) {
    const issues = actionEvidenceIssues(shellState, 'deploy', now);
    return {
      gated: issues.length > 0 || active < 2,
      explorable: true,
      allowedActions: issues.length === 0 ? ['deploy', 'verify'] : [],
      reason: issues[0]
        ? issues[0]
        : active < 2
          ? 'Deliver opens after build produces deployable evidence.'
          : null,
      product: stage.product,
      attention: batchStatus === 'blocked',
    };
  }

  if (stageIndex === 3) {
    const prepareIssues = actionEvidenceIssues(shellState, 'janus_prepare', now);
    const applyIssues = actionEvidenceIssues(shellState, 'janus_apply', now);
    const allowedActions = [
      ...(prepareIssues.length === 0 ? ['janus_prepare'] : []),
      ...(applyIssues.length === 0 ? ['janus_apply'] : []),
    ];
    const readiness = prereq.pharos?.readiness;
    let reason = null;
    if (allowedActions.includes('janus_apply')) {
      reason = active < 3 ? 'Access application waits on completed delivery evidence.' : null;
    } else if (allowedActions.includes('janus_prepare')) {
      reason =
        readiness === 'preliminary'
          ? 'A preliminary Pharos target supports Janus preparation only, not access application.'
          : applyIssues[0];
    } else {
      reason = prepareIssues[0] ?? applyIssues[0];
    }
    return {
      gated: allowedActions.length === 0 || active < 3,
      explorable: true,
      allowedActions,
      reason,
      product: stage.product,
    };
  }

  return { gated: true, explorable: true, allowedActions: [], reason: 'Unknown stage.', product: stage.product };
}

export function canEmitStartIntent(
  shellState,
  { confirmed = false, executionMode = null, action = null, now = Date.now() } = {},
) {
  const reasons = [];
  const batch = shellState.delivery ?? {};
  const status = batch.status ?? 'draft';

  if (status !== 'draft' && status !== 'authorized') {
    reasons.push('Selected batch is not awaiting an explicit start.');
  }
  if (!ACTIONS.includes(action)) reasons.push('Choose an action before starting.');
  if (!executionMode) reasons.push('Choose an execution mode before starting.');
  if (!confirmed) reasons.push('Explicit confirmation is required.');
  if (!batch.batchRef) reasons.push('Batch reference is missing.');
  if (!batch.baselineRef) reasons.push('Requirements baseline reference is missing.');
  if (!batch.baselineDigest) reasons.push('Requirements baseline digest is missing.');
  if (!isEvaluatedAtUsable(shellState.evaluatedAt, now)) {
    reasons.push('Evaluation snapshot has expired. Refresh evidence before starting.');
  }
  reasons.push(...identityStartIssues(shellState.identity, { now, requireHuman: true }));
  if (ACTIONS.includes(action)) {
    reasons.push(...actionEvidenceIssues(shellState, action, now));
  }

  return { allowed: reasons.length === 0, reasons: [...new Set(reasons)] };
}

export function stageCompletion(stageIndex, shellState) {
  const evidence = shellState.delivery?.stageEvidence?.[stageIndex];
  return evidence === 'performed';
}

export function buildStagePresentation(stageIndex, shellState, viewedStage, { now = Date.now() } = {}) {
  const gate = getStageGate(stageIndex, shellState, { now });
  const evidence = shellState.delivery?.stageEvidence?.[stageIndex] ?? 'unknown';
  const done = stageCompletion(stageIndex, shellState);
  const notInBatch = evidence === 'not_in_batch';
  const unknown = evidence === 'unknown' && !done;
  const active = shellState.delivery?.activeStage ?? 0;
  const isActive = stageIndex === active;
  const isViewed = stageIndex === viewedStage;
  const attention = gate.attention || (isActive && shellState.delivery?.status === 'blocked');
  const statusLabel = notInBatch
    ? 'not in this batch'
    : done
      ? 'performed'
      : unknown && !isActive
        ? 'unknown'
        : isActive
          ? shellState.delivery?.batchStatusLabel ?? 'current'
          : 'gated, explore prerequisites';

  return {
    ...gate,
    done,
    notInBatch,
    unknown,
    evidence,
    isActive,
    isViewed,
    attention,
    ariaLabel: `${STAGES[stageIndex].label} (${STAGES[stageIndex].product}) — ${statusLabel}`,
  };
}
