/**
 * Documented adapter boundary from draft delivery-stream JSON to shell state.
 * This does not duplicate the backend validator in delivery-contracts; hosts may
 * validate upstream and pass normalized state, or use this lightweight mapper
 * for fixtures and examples only. JSON claims are not runtime authority.
 */
import { normalizeShellState } from './state.js';
import { sanitizeRef, sanitizeText } from './sanitize.js';

const ACTIVE_STATUSES = new Set(['in_progress', 'blocked']);
const PHAROS_OPERATIONS = new Set(['deploy', 'verify']);
const JANUS_OPERATIONS = new Set(['janus_prepare', 'apply']);

export function stageForOperation(operation) {
  switch (operation) {
    case 'requirements':
      return 0;
    case 'build':
    case 'test':
      return 1;
    case 'deploy':
    case 'verify':
      return 2;
    case 'janus_prepare':
    case 'apply':
      return 3;
    default:
      return 0;
  }
}

export function actionForOperation(operation) {
  switch (operation) {
    case 'test':
      return 'test';
    case 'deploy':
      return 'deploy';
    case 'verify':
      return 'verify';
    case 'janus_prepare':
      return 'janus_prepare';
    case 'apply':
      return 'janus_apply';
    default:
      return 'build';
  }
}

function isObservationUsable(observedAt, evaluatedAt) {
  if (!observedAt || !evaluatedAt) return false;
  const observed = Date.parse(observedAt);
  const evaluated = Date.parse(evaluatedAt);
  if (Number.isNaN(observed) || Number.isNaN(evaluated)) return false;
  return observed <= evaluated;
}

function findBaseline(contract, batch) {
  const ref = batch?.baseline?.baseline_ref;
  const entry = (contract.requirements_baselines ?? []).find((item) => item.baseline_ref === ref) ?? null;
  if (!entry) return null;
  const digest = batch?.baseline?.content_digest;
  if (digest && entry.content_digest !== digest) return null;
  return entry;
}

function mapGate(gate, fallbackKind, fallbackMessage, evaluatedAt) {
  if (!gate) {
    return {
      status: 'unknown',
      gateKind: fallbackKind,
      message: fallbackMessage ?? `${fallbackKind} gate not reported.`,
      evidenceRef: null,
      observedAt: null,
      freshUntil: null,
      targetRef: null,
    };
  }
  const observedAt = gate.observed_at ?? null;
  if (!isObservationUsable(observedAt, evaluatedAt)) {
    return {
      status: 'unknown',
      gateKind: gate.gate_kind ?? fallbackKind,
      message: sanitizeText(`${fallbackKind} observation is missing or invalid.`, { maxLength: 200 }),
      evidenceRef: null,
      observedAt: null,
      freshUntil: gate.fresh_until ?? null,
      targetRef: gate.target_ref ?? null,
    };
  }
  return {
    status: gate.status === 'pass' ? 'pass' : gate.status === 'fail' ? 'fail' : 'unknown',
    gateKind: gate.gate_kind ?? fallbackKind,
    message: sanitizeText(`${gate.gate_kind}: ${gate.status}`, { maxLength: 200 }),
    evidenceRef: gate.evidence_ref ?? null,
    observedAt,
    freshUntil: gate.fresh_until ?? null,
    targetRef: gate.target_ref ?? null,
  };
}

function gateFromBatch(batch, gateKind, evaluatedAt) {
  const gate = (batch?.prerequisite_gates ?? []).find((item) => item.gate_kind === gateKind);
  return mapGate(gate, gateKind, `${gateKind} gate not reported.`, evaluatedAt);
}

function unknownTarget(kind, requestedRef, message) {
  return {
    status: 'unknown',
    readiness: 'unknown',
    gateKind: 'target_readiness',
    message: message
      ? sanitizeText(message, { maxLength: 160 })
      : requestedRef
        ? sanitizeText(`${kind} target ${requestedRef} is not in this document.`, { maxLength: 160 })
        : `${kind} target not reported.`,
    evidenceRef: null,
    observedAt: null,
    targetRef: requestedRef ?? null,
  };
}

function mapSpecificTarget(target, evaluatedAt) {
  const readiness = target.readiness;
  const observedAt = target.observed_at ?? null;
  if (!isObservationUsable(observedAt, evaluatedAt)) {
    return {
      status: 'unknown',
      readiness: 'unknown',
      gateKind: 'target_readiness',
      evidenceRef: null,
      observedAt: null,
      targetRef: target.target_ref ?? null,
      message: sanitizeText('Pharos target observation is missing or invalid.', { maxLength: 160 }),
    };
  }
  const status = ['preliminary', 'ready', 'live'].includes(readiness)
    ? 'pass'
    : readiness === 'blocked'
      ? 'fail'
      : 'unknown';
  return {
    status,
    readiness,
    gateKind: 'target_readiness',
    evidenceRef: target.evidence_ref ?? null,
    observedAt,
    targetRef: target.target_ref ?? null,
    message: sanitizeText(`deployment target ${readiness}`, { maxLength: 160 }),
  };
}

function batchNeedsDeploymentTarget(batch) {
  return (batch?.tasks ?? []).some(
    (task) => PHAROS_OPERATIONS.has(task.operation) || JANUS_OPERATIONS.has(task.operation),
  );
}

function mapTarget(contract, task, batch, evaluatedAt) {
  const targets = contract.targets ?? [];
  if (task?.target_ref) {
    const target = targets.find((item) => item.target_ref === task.target_ref);
    if (!target) return unknownTarget('requested', task.target_ref);
    if (target.kind !== 'deployment') {
      return unknownTarget(
        'deployment',
        target.target_ref,
        `${target.kind} target ${target.target_ref} cannot satisfy a Pharos deployment gate.`,
      );
    }
    return mapSpecificTarget(target, evaluatedAt);
  }
  const taskNeedsTarget =
    PHAROS_OPERATIONS.has(task?.operation) || JANUS_OPERATIONS.has(task?.operation) || batchNeedsDeploymentTarget(batch);
  if (!taskNeedsTarget) {
    return unknownTarget(
      'deployment',
      null,
      'Deployment target evidence is not reported for this batch.',
    );
  }
  const target = targets.find((item) => item.kind === 'deployment');
  if (!target) return unknownTarget('deployment');
  return mapSpecificTarget(target, evaluatedAt);
}

function artifactCatalog(contract) {
  const catalog = [...(contract.artifacts ?? [])];
  for (const release of contract.releases ?? []) {
    catalog.push(...(release.artifacts ?? []));
  }
  return catalog;
}

function unknownArtifact(message) {
  return {
    status: 'unknown',
    gateKind: 'artifact',
    message,
    evidenceRef: null,
    observedAt: null,
    digest: null,
    origin: null,
    producingTaskRef: null,
    importReceiptRef: null,
  };
}

function tasksByRef(contract) {
  const found = new Map();
  for (const item of contract.batches ?? []) {
    for (const task of item.tasks ?? []) {
      if (!found.has(task.task_ref)) found.set(task.task_ref, []);
      found.get(task.task_ref).push(task);
    }
  }
  return found;
}

function provenanceEvidence(artifact, contract) {
  const provenance = artifact?.provenance;
  if (!provenance || typeof provenance !== 'object') {
    return { ok: false, message: `Artifact ${artifact.artifact_ref} has no producing or imported provenance claim.` };
  }
  const observedAt = provenance.observed_at ?? null;
  const evidenceRef = provenance.evidence_ref ?? null;
  if (!evidenceRef) {
    return { ok: false, message: `Artifact ${artifact.artifact_ref} evidence reference is missing.` };
  }
  if (!isObservationUsable(observedAt, contract.evaluated_at)) {
    return { ok: false, message: `Artifact ${artifact.artifact_ref} observation time is missing or invalid.` };
  }
  if (provenance.origin === 'produced') {
    const producingTaskRef = provenance.producing_task_ref;
    const matches = tasksByRef(contract).get(producingTaskRef) ?? [];
    const producer = matches.length === 1 ? matches[0] : null;
    if (!producer || producer.operation !== 'build' || producer.status !== 'done' || !producer.completion_evidence_ref) {
      return {
        ok: false,
        message: `Artifact ${artifact.artifact_ref} producing build is not evidenced in this document.`,
      };
    }
    return {
      ok: true,
      origin: 'produced',
      producingTaskRef,
      importReceiptRef: null,
      observedAt,
      evidenceRef,
      message: `Artifact ${artifact.artifact_ref} produced by ${producingTaskRef}.`,
    };
  }
  if (provenance.origin === 'imported') {
    const importReceiptRef = provenance.import_receipt_ref;
    if (!importReceiptRef) {
      return { ok: false, message: `Artifact ${artifact.artifact_ref} import receipt is missing.` };
    }
    return {
      ok: true,
      origin: 'imported',
      producingTaskRef: null,
      importReceiptRef,
      observedAt,
      evidenceRef,
      message: `Artifact ${artifact.artifact_ref} imported with receipt ${importReceiptRef}.`,
    };
  }
  return { ok: false, message: `Artifact ${artifact.artifact_ref} provenance origin is unknown.` };
}

function boundArtifact(artifact, contract) {
  if (!artifact?.artifact_ref || !artifact?.digest) {
    return unknownArtifact('Requested artifact is not bound in this document.');
  }
  const provenance = provenanceEvidence(artifact, contract);
  if (!provenance.ok) {
    return unknownArtifact(provenance.message);
  }
  return {
    status: 'pass',
    gateKind: 'artifact',
    message: sanitizeText(provenance.message, { maxLength: 160 }),
    evidenceRef: provenance.evidenceRef,
    observedAt: provenance.observedAt,
    digest: artifact.digest,
    origin: provenance.origin,
    producingTaskRef: provenance.producingTaskRef,
    importReceiptRef: provenance.importReceiptRef,
  };
}

function artifactEvidence(contract, batch, task) {
  const catalog = artifactCatalog(contract);
  const requested = task?.artifact_ref ?? null;
  if (requested) {
    const artifact = catalog.find((item) => item.artifact_ref === requested);
    if (!artifact) {
      return unknownArtifact(`Requested artifact ${requested} is not bound in this document.`);
    }
    return boundArtifact(artifact, contract);
  }
  if (PHAROS_OPERATIONS.has(task?.operation)) {
    return unknownArtifact('Deployable artifact evidence is not reported.');
  }
  const release = (contract.releases ?? []).filter((item) => item.batch_ref === batch.batch_ref).at(-1);
  const artifact = release?.artifacts?.[0];
  if (!artifact) {
    return unknownArtifact('Deployable artifact evidence is not reported.');
  }
  return boundArtifact(artifact, contract);
}

function latestProgress(contract, batchRef) {
  const reports = (contract.progress_reports ?? []).filter((item) => item.batch_ref === batchRef);
  return reports.at(-1) ?? null;
}

function mapSnapshot(item) {
  if (!item) return null;
  return {
    progress: item.progress ?? null,
    forecast: item.forecast ?? null,
    ...(item.task_ref ? { task_ref: item.task_ref } : {}),
  };
}

function mapBatchStatus(status) {
  switch (status) {
    case 'authorized':
      return 'draft';
    case 'in_progress':
      return 'in_progress';
    case 'blocked':
      return 'blocked';
    case 'completed':
      return 'completed';
    default:
      return 'draft';
  }
}

function currentWork(tasks = []) {
  const active = tasks.filter((task) => ACTIVE_STATUSES.has(task.status));
  if (active.length) return active;
  return tasks.filter((task) => task.status === 'done');
}

export function deriveActiveWork(batch) {
  const tasks = batch?.tasks ?? [];
  const pool = currentWork(tasks);
  let selected = null;
  let stage = 0;
  for (const task of pool) {
    const next = stageForOperation(task.operation);
    if (!selected || next >= stage) {
      selected = task;
      stage = next;
    }
  }
  return { stage, task: selected, operation: selected?.operation ?? 'requirements' };
}

function requirementsBaselineEvidence(batch, contract) {
  const baseline = findBaseline(contract, batch);
  if (!baseline) return false;
  const gate = (batch?.prerequisite_gates ?? []).find((item) => item.gate_kind === 'requirements_baseline');
  return (
    gate?.status === 'pass' &&
    Boolean(gate.evidence_ref) &&
    isObservationUsable(gate.observed_at, contract.evaluated_at)
  );
}

export function stageEvidenceFor(batch, contract) {
  const evidence = ['unknown', 'unknown', 'unknown', 'unknown'];
  const present = [false, false, false, false];
  present[0] = true;
  const tasks = batch?.tasks ?? [];
  for (const task of tasks) {
    present[stageForOperation(task.operation)] = true;
  }
  for (let stage = 0; stage <= 3; stage += 1) {
    if (!present[stage]) {
      evidence[stage] = 'not_in_batch';
      continue;
    }
    if (stage === 0) {
      const baselineOk = requirementsBaselineEvidence(batch, contract);
      const requirementsTasks = tasks.filter((task) => task.operation === 'requirements');
      if (requirementsTasks.length === 0) {
        evidence[0] = baselineOk ? 'performed' : 'unknown';
      } else {
        const taskOk =
          requirementsTasks.length > 0 &&
          requirementsTasks.every((task) => task.status === 'done' && task.completion_evidence_ref);
        evidence[0] = baselineOk && taskOk ? 'performed' : 'unknown';
      }
      continue;
    }
    const stageTasks = tasks.filter((task) => stageForOperation(task.operation) === stage);
    const performed =
      stageTasks.length > 0 &&
      stageTasks.every((task) => task.status === 'done' && task.completion_evidence_ref);
    evidence[stage] = performed ? 'performed' : 'unknown';
  }
  return evidence;
}

function selectBatch(contract, options) {
  const batches = contract.batches ?? [];
  if (Object.prototype.hasOwnProperty.call(options, 'batchRef')) {
    const requested = options.batchRef;
    const batchRef = sanitizeRef(requested);
    const batch = batchRef ? batches.find((item) => item.batch_ref === batchRef) : null;
    if (!batch) {
      throw new Error(`Delivery contract batch not found: ${requested}`);
    }
    return batch;
  }
  const batch = batches.at(-1);
  if (!batch) {
    throw new Error('Delivery contract batch not found for adapter mapping.');
  }
  return batch;
}

export function fromDeliveryContract(contract, options = {}) {
  const batch = selectBatch(contract, options);
  const active = deriveActiveWork(batch);
  const baseline = findBaseline(contract, batch);
  const report = latestProgress(contract, batch.batch_ref);
  const pharos = mapTarget(contract, active.task, batch, contract.evaluated_at);
  const requirementsGate = gateFromBatch(batch, 'requirements_baseline', contract.evaluated_at);
  const accessGate = gateFromBatch(batch, 'access', contract.evaluated_at);
  const artifact = artifactEvidence(contract, batch, active.task);
  const scopeItems = (baseline?.requirements ?? []).map((req) => req.statement);
  const overall = mapSnapshot(report?.overall);
  const taskEntry = (report?.tasks ?? []).find((item) => item.task_ref === active.task?.task_ref) ?? report?.tasks?.[0];
  const task = mapSnapshot(taskEntry);

  return normalizeShellState({
    header: options.header ?? {},
    health: options.health ?? {},
    evaluatedAt: contract.evaluated_at,
    selectedAction: options.selectedAction ?? actionForOperation(active.operation),
    selectedExecutionMode: options.selectedExecutionMode ?? batch.authorization?.autonomy_mode,
    delivery: {
      batchRef: batch.batch_ref,
      baselineRef: batch.baseline?.baseline_ref,
      baselineDigest: batch.baseline?.content_digest,
      status: mapBatchStatus(batch.status),
      activeStage: active.stage,
      activeTaskRef: active.task?.task_ref ?? null,
      activeOperation: active.operation,
      stageEvidence: stageEvidenceFor(batch, contract),
      batchTitle: options.batchTitle ?? sanitizeText(batch.batch_ref.replace(/_/g, ' '), { maxLength: 120 }),
      batchSummary: options.batchSummary,
      scopeItems,
      batchStatusLabel: options.batchStatusLabel ?? batch.status,
      draftCount: options.draftCount ?? 0,
      mapDetail: options.mapDetail,
    },
    prerequisites: {
      requirementsBaseline: requirementsGate,
      deployArtifact: artifact,
      pharosTarget: pharos,
      janusGate: accessGate,
    },
    progress: {
      taskLabel: task?.task_ref ?? taskEntry?.task_ref ?? 'Current task',
      overallLabel: 'Overall',
      task,
      overall,
    },
    executionModes: options.executionModes,
  });
}

export const ADAPTER_BOUNDARY = {
  source: 'inspr.delivery-stream/0.1-draft (read-only unreleased contract draft)',
  scope: 'Map known contract fields into shell state for display and gating hints only.',
  notIncluded:
    'JSON Schema validation, semantic validator, authorization, workflow execution, Janus reporter, provider calls, authenticated artifact attestations, host identity context (supplied separately; delivery parties are not runtime identity)',
};

export { PHAROS_OPERATIONS, JANUS_OPERATIONS };
