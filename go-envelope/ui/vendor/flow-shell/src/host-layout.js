export const LAYOUT_MODES = Object.freeze(['viewport', 'bounded']);
export const CONTENT_LAYOUTS = Object.freeze(['document', 'fill']);

export function resolveLayoutMode(value) {
  return value === 'bounded' ? 'bounded' : 'viewport';
}

export function resolveContentLayout(value) {
  return value === 'fill' ? 'fill' : 'document';
}

export function applyBoundedGeometry(host, rect) {
  host.style.setProperty('--shell-fixed-left', `${Math.round(rect.left)}px`);
  host.style.setProperty('--shell-fixed-width', `${Math.round(rect.width)}px`);
}

export function clearBoundedGeometry(host) {
  host.style.removeProperty('--shell-fixed-left');
  host.style.removeProperty('--shell-fixed-width');
}

export function applyFooterSpace(host, height) {
  host.style.setProperty('--shell-footer-space', `${Math.ceil(height)}px`);
}

export function applyFillFooterCap(host, reservedHeight, maxHeight) {
  host.style.setProperty('--shell-footer-space', `${Math.ceil(reservedHeight)}px`);
  host.style.setProperty('--shell-footer-max-height', `${Math.ceil(maxHeight)}px`);
}

export function clearFillFooterCap(host) {
  host.style.removeProperty('--shell-footer-max-height');
}

export function resolveFillFooterCapacity(hostHeight, minContentHeight) {
  const minContent = Math.max(0, minContentHeight);
  return Math.max(0, hostHeight - minContent);
}

export function resolveFillFooterReservation(measuredFooter, maxCapacity) {
  const capacity = Math.max(0, maxCapacity);
  return Math.min(Math.max(0, measuredFooter), capacity);
}

export function resolveFillFooterHeight(hostHeight, measuredFooter, minContentHeight) {
  const capacity = resolveFillFooterCapacity(hostHeight, minContentHeight);
  return resolveFillFooterReservation(measuredFooter, capacity);
}

export function measureHostLocalTopOffset(hostRect, targetRect) {
  return Math.max(0, targetRect.top - hostRect.top);
}

export function measureFillContentMinimumFromMetrics({
  chromeAboveSlot,
  slottedFixedHeight,
  scrollReserve = 48,
  customMin = null,
}) {
  if (Number.isFinite(customMin) && customMin > 0) return customMin;
  return chromeAboveSlot + slottedFixedHeight + scrollReserve;
}
