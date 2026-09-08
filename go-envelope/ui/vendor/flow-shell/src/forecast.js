import { escapeHtml } from './sanitize.js';

export const CONSERVATIVE_FALLBACK_ETA_MINUTES = 45;

function minutesUntil(iso, now = Date.now()) {
  if (!iso) return null;
  const target = Date.parse(iso);
  if (Number.isNaN(target)) return null;
  return Math.max(0, Math.round((target - now) / 60000));
}

function observationBasisLabel(kind) {
  switch (kind) {
    case 'observed_work':
      return 'observed work';
    case 'task_assessment':
      return 'task assessment';
    case 'work_breakdown':
      return 'work breakdown';
    case 'manual_estimate':
      return 'manual estimate';
    default:
      return null;
  }
}

function forecastBasisLabel(kind) {
  switch (kind) {
    case 'worker_assessment':
      return 'worker assessment';
    case 'work_breakdown':
      return 'work breakdown';
    case 'manual_estimate':
      return 'manual estimate';
    case 'elapsed_revision':
      return 'elapsed revision';
    default:
      return null;
  }
}

function forecastKindLabel(kind) {
  if (kind === 'worker_estimate') return 'worker estimate';
  if (kind === 'educated_guess') return 'educated guess';
  return null;
}

function integerPercent(value) {
  return Number.isInteger(value) && value >= 0 && value <= 100 ? value : null;
}

export function resolveFreshness(progressPoint, now = Date.now()) {
  if (!progressPoint) return 'unknown';
  const until = progressPoint.fresh_until ?? progressPoint.freshUntil ?? null;
  if (until) {
    const parsed = Date.parse(until);
    if (!Number.isNaN(parsed) && now > parsed) return 'stale';
  }
  if (progressPoint.freshness === 'stale') return 'stale';
  if (progressPoint.freshness === 'fresh' || progressPoint.freshness === 'unknown') {
    return progressPoint.freshness;
  }
  return 'unknown';
}

export function isStaleSnapshot(snapshot, now = Date.now()) {
  return resolveFreshness(snapshot?.progress, now) === 'stale';
}

export function formatFreshnessLabel(progressPoint, now = Date.now()) {
  if (!progressPoint) return 'Freshness missing';
  switch (resolveFreshness(progressPoint, now)) {
    case 'fresh':
      return 'Updated recently';
    case 'stale':
      return 'Stale observations';
    case 'unknown':
      return 'Freshness unknown';
    default:
      return 'Freshness missing';
  }
}

function formatEtaLabel(etaMinutes) {
  if (etaMinutes != null) return `ETA ~${etaMinutes} min`;
  return `ETA ~${CONSERVATIVE_FALLBACK_ETA_MINUTES} min conservative fallback`;
}

export function formatProgressLine(snapshot, { now = Date.now(), prefix = '' } = {}) {
  if (!snapshot) {
    return `${prefix}0% · ${formatEtaLabel(null)} · conservative fallback · missing basis · guess is not completion`;
  }

  const progress = snapshot.progress ?? null;
  const forecast = snapshot.forecast ?? null;
  const stale = resolveFreshness(progress, now) === 'stale';
  const forecastPercent = integerPercent(forecast?.percent_complete);
  const displayPercent = forecastPercent ?? 0;
  const etaMinutes = minutesUntil(forecast?.estimated_finish, now);
  const kind = forecastKindLabel(forecast?.kind) ?? 'conservative fallback';
  const basis =
    forecastBasisLabel(forecast?.basis?.kind) ??
    observationBasisLabel(progress?.basis?.kind) ??
    'missing basis';

  const parts = [`${displayPercent}%`];
  parts.push(formatEtaLabel(etaMinutes));
  if (forecastPercent == null) parts.push('conservative fallback');
  parts.push(kind);
  parts.push(basis);
  if (forecastPercent != null) parts.push('forecast');
  if (progress?.percent_complete == null) parts.push('observed percent missing');
  else parts.push(`observed ${progress.percent_complete}%`);
  if (progress?.eta == null) parts.push('observed ETA missing');
  if (stale) parts.push('stale observation');
  const evidencedDone =
    progress?.status === 'done' &&
    progress?.basis?.kind &&
    progress.basis.kind !== 'unknown' &&
    Boolean(progress?.basis?.evidence_ref);
  if (evidencedDone) parts.push('observed done');
  else if (forecastPercent === 100) parts.push('guess is not completion');

  return `${prefix}${parts.join(' · ')}`;
}

export function renderProgressHtml(snapshot, options) {
  return escapeHtml(formatProgressLine(snapshot, options));
}
