const REF_PATTERN = /^[A-Za-z][A-Za-z0-9._:-]{0,159}$/;
const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;

const HTML_ESCAPE = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

export function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (char) => HTML_ESCAPE[char]);
}

export function sanitizeText(value, { maxLength = 500 } = {}) {
  if (value == null) return '';
  const trimmed = String(value).trim().replace(/\s+/g, ' ');
  if (!trimmed) return '';
  return trimmed.slice(0, maxLength);
}

export function sanitizeRef(value) {
  const text = sanitizeText(value, { maxLength: 160 });
  if (!text || !REF_PATTERN.test(text)) return null;
  return text;
}

export function sanitizeDigest(value) {
  const text = sanitizeText(value, { maxLength: 71 });
  if (!text || !DIGEST_PATTERN.test(text)) return null;
  return text;
}

export function sanitizeUrl(value) {
  const text = sanitizeText(value, { maxLength: 2048 });
  if (!text) return null;
  try {
    const url = new URL(text);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
    return url.href;
  } catch {
    return null;
  }
}

export function sanitizeInitials(value) {
  const text = sanitizeText(value, { maxLength: 3 }).replace(/[^A-Za-z0-9]/g, '');
  return text ? text.slice(0, 2).toUpperCase() : '?';
}

export function sanitizeExecutionMode(value, allowed = ['manual', 'assisted', 'automatic']) {
  const text = sanitizeText(value, { maxLength: 32 });
  return allowed.includes(text) ? text : null;
}

export function sanitizeTimestamp(value) {
  const text = sanitizeText(value, { maxLength: 64 });
  if (!text) return null;
  const parsed = Date.parse(text);
  if (Number.isNaN(parsed)) return null;
  return text;
}

export function sanitizeAction(value, allowed = ['build', 'test', 'deploy', 'verify', 'janus_prepare', 'janus_apply']) {
  const text = sanitizeText(value, { maxLength: 32 });
  return allowed.includes(text) ? text : null;
}
