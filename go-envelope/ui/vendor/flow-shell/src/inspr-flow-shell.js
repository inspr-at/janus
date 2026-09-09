import { STAGES, defaultActionForStage } from './stages.js';
import { buildStagePresentation, getStageGate, canEmitStartIntent } from './gates.js';
import { formatProgressLine, formatFreshnessLabel, isStaleSnapshot, resolveFreshness } from './forecast.js';
import {
  normalizeShellState,
  confirmationSnapshot,
  isConfirmationExpired,
  nextClockAgingDelayMs,
  withViewedStage,
  withMapExpanded,
  withExecutionMode,
  withSelectedAction,
} from './state.js';
import { identityFreshnessIssues } from './identity.js';
import {
  createNavigateStageIntent,
  createToggleMapIntent,
  createReviewBatchIntent,
  createSaveProposalIntent,
  createStartIntent,
  createHeaderIntent,
  createHealthIntent,
  createViewDraftsIntent,
} from './intents.js';
import { escapeHtml } from './sanitize.js';
import {
  applyBoundedGeometry,
  applyFooterSpace,
  applyFillFooterCap,
  clearBoundedGeometry,
  clearFillFooterCap,
  resolveContentLayout,
  resolveFillFooterCapacity,
  resolveFillFooterReservation,
  measureHostLocalTopOffset,
  measureFillContentMinimumFromMetrics,
  resolveLayoutMode,
} from './host-layout.js';

const MARKER_ICON = {
  done: '<svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true"><path d="M2 6.5 4.8 9 10 3" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>',
  active: '<svg width="8" height="8" viewBox="0 0 8 8" aria-hidden="true"><circle cx="4" cy="4" r="3" fill="currentColor"/></svg>',
  attention: '<svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true"><path d="M5 1.5 9 8.5H1Z" fill="none" stroke="currentColor" stroke-width="1.2"/><circle cx="5" cy="6.3" r="0.7" fill="currentColor"/></svg>',
  future: '<svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true"><rect x="2" y="4" width="6" height="1.4" rx="0.7" fill="currentColor"/></svg>',
  absent: '<svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true"><circle cx="6" cy="6" r="4" fill="none" stroke="currentColor" stroke-width="1.4" stroke-dasharray="1.6 1.4"/></svg>',
  unknown: '<svg width="12" height="12" viewBox="0 0 12 12" aria-hidden="true"><circle cx="6" cy="6" r="4" fill="none" stroke="currentColor" stroke-width="1.4"/><path d="M4.6 4.8c.2-.9 1.6-1.1 1.8-.1.15.7-.5.9-.7 1.4-.15.35-.05.9.6.9" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/><circle cx="6" cy="8.6" r="0.6" fill="currentColor"/></svg>',
};

const HOST_LAYOUT_VARS = {
  'content-padding': '--shell-content-padding-inline',
  'footer-space': '--shell-footer-space',
};

export class InsprFlowShell extends HTMLElement {
  static get observedAttributes() {
    return ['logo-src', 'content-padding', 'footer-space', 'layout-mode', 'content-layout'];
  }

  #state = normalizeShellState({});
  #reviewSnapshot = null;
  #noticeTimer = null;
  #clockTimer = null;
  #eventsBound = false;
  #footerObserver = null;
  #hostObserver = null;
  #geometryFrame = null;
  #onWindowGeometryChange = () => this.#scheduleGeometrySync();
  #onVisibilityChange = () => {
    if (this.ownerDocument?.visibilityState === 'visible') {
      this.#refreshClockPresentation();
    }
  };

  constructor() {
    super();
    this.attachShadow({ mode: 'open' });
    this.#ensureEventsBound();
  }

  connectedCallback() {
    this.#syncHostLayoutVars();
    this.render();
    this.#bindClockAging();
  }

  disconnectedCallback() {
    this.#teardownClockAging();
    this.#teardownLayoutObservers();
  }

  attributeChangedCallback(name) {
    if (name in HOST_LAYOUT_VARS) {
      this.#syncHostLayoutVars();
      if (name === 'footer-space') {
        this.#syncFooterSpace();
      }
      return;
    }
    if (name === 'layout-mode') {
      this.#syncLayoutMode();
      return;
    }
    if (name === 'content-layout') {
      this.#syncContentLayout();
      return;
    }
    this.render();
  }

  #layoutMode() {
    return resolveLayoutMode(this.getAttribute('layout-mode'));
  }

  #contentLayout() {
    return resolveContentLayout(this.getAttribute('content-layout'));
  }

  #isFillLayout() {
    return this.#contentLayout() === 'fill';
  }

  #isBounded() {
    return this.#layoutMode() === 'bounded';
  }

  #syncLayoutMode() {
    if (this.#isBounded()) {
      this.#bindLayoutObservers();
      this.#syncBoundedGeometry();
      return;
    }
    clearBoundedGeometry(this);
    if (this.#isFillLayout()) {
      this.#bindLayoutObservers();
      return;
    }
    this.#teardownBoundedObservers();
  }

  #syncContentLayout() {
    if (!this.#isFillLayout()) {
      clearFillFooterCap(this);
    }
    this.#bindLayoutObservers();
    this.#syncFooterSpace();
  }

  #scheduleGeometrySync() {
    if (!this.#isBounded()) return;
    if (this.#geometryFrame != null) return;
    this.#geometryFrame = requestAnimationFrame(() => {
      this.#geometryFrame = null;
      this.#syncBoundedGeometry();
    });
  }

  #syncBoundedGeometry() {
    if (!this.isConnected || !this.#isBounded()) return;
    applyBoundedGeometry(this, this.getBoundingClientRect());
  }

  #footerSpaceSyncing = false;

  #syncFooterSpace() {
    if (!this.isConnected || this.#footerSpaceSyncing) return;
    if (this.hasAttribute('footer-space')) {
      if (!this.#isFillLayout()) {
        clearFillFooterCap(this);
      }
      return;
    }
    const footer = this.shadowRoot?.querySelector('.shell-footer');
    if (!footer) return;

    this.#footerSpaceSyncing = true;
    try {
      if (this.#isFillLayout()) {
        const minContent = this.#measureFillContentMinimum();
        const hostHeight = this.#hostLayoutHeight();
        if (hostHeight > 0) {
          const maxCapacity = resolveFillFooterCapacity(hostHeight, minContent);
          const natural = this.#measureFooterNaturalHeight(footer);
          const reserved = resolveFillFooterReservation(natural, maxCapacity);
          applyFillFooterCap(this, reserved, maxCapacity);
          return;
        }
      }
      clearFillFooterCap(this);
      applyFooterSpace(this, footer.getBoundingClientRect().height);
    } finally {
      this.#footerSpaceSyncing = false;
    }
  }

  #measureFooterNaturalHeight(footer) {
    const previous = this.style.getPropertyValue('--shell-footer-max-height');
    this.style.removeProperty('--shell-footer-max-height');
    const rectHeight = footer.getBoundingClientRect().height;
    const scaffold = footer.querySelector('.shell-footer-scaffold');
    const measured = Math.max(rectHeight, scaffold?.scrollHeight ?? 0);
    if (previous) {
      this.style.setProperty('--shell-footer-max-height', previous);
    }
    return measured;
  }

  #hostLayoutHeight() {
    if (this.clientHeight > 0) return this.clientHeight;
    const rect = this.getBoundingClientRect();
    if (rect.height > 0) return rect.height;
    return this.offsetHeight;
  }

  #hostComputedStyle() {
    const view = this.ownerDocument?.defaultView;
    if (!view?.getComputedStyle) return null;
    return view.getComputedStyle(this);
  }

  #measureFillContentMinimum() {
    const computed = this.#hostComputedStyle();
    const custom = Number.parseFloat(computed?.getPropertyValue('--shell-fill-content-min') ?? '');
    const scrollMin = Number.parseFloat(computed?.getPropertyValue('--shell-fill-scroll-min') ?? '');
    const scrollReserve = Number.isFinite(scrollMin) && scrollMin > 0 ? scrollMin : 48;

    const hostRect = this.getBoundingClientRect();
    const hostSlot = this.shadowRoot?.querySelector('.host-slot');
    const chromeAboveSlot = hostSlot
      ? measureHostLocalTopOffset(hostRect, hostSlot.getBoundingClientRect())
      : 0;

    let slottedFixed = 0;
    for (const child of this.children) {
      const region = child.getAttribute('data-flow-host-region');
      if (region === 'toolbar' || region === 'footer') {
        slottedFixed += child.getBoundingClientRect().height;
        continue;
      }
      const footer = child.querySelector?.(
        '[data-flow-host-region="footer"], .project-footer, footer#project-footer, footer.project-footer',
      );
      if (footer) slottedFixed += footer.getBoundingClientRect().height;
      if (!region) {
        const toolbar = child.querySelector?.('[data-flow-host-region="toolbar"], .host-toolbar');
        if (toolbar) slottedFixed += toolbar.getBoundingClientRect().height;
      }
    }

    return measureFillContentMinimumFromMetrics({
      chromeAboveSlot,
      slottedFixedHeight: slottedFixed,
      scrollReserve,
      customMin: custom,
    });
  }

  #bindBoundedGeometryListeners() {
    if (!this.isConnected || !this.#isBounded()) return;
    window.removeEventListener('resize', this.#onWindowGeometryChange);
    window.removeEventListener('scroll', this.#onWindowGeometryChange);
    window.addEventListener('resize', this.#onWindowGeometryChange);
    window.addEventListener('scroll', this.#onWindowGeometryChange, { passive: true });
  }

  #teardownBoundedObservers() {
    this.#hostObserver?.disconnect();
    this.#hostObserver = null;
    window.removeEventListener('resize', this.#onWindowGeometryChange);
    window.removeEventListener('scroll', this.#onWindowGeometryChange);
    if (this.#geometryFrame != null) {
      cancelAnimationFrame(this.#geometryFrame);
      this.#geometryFrame = null;
    }
  }

  #teardownLayoutObservers() {
    this.#footerObserver?.disconnect();
    this.#footerObserver = null;
    this.#teardownBoundedObservers();
  }

  #bindLayoutObservers() {
    if (!this.isConnected) return;

    const footer = this.shadowRoot?.querySelector('.shell-footer');
    const hasResizeObserver = typeof ResizeObserver === 'function';

    if (!footer) {
      if (this.#isBounded()) {
        this.#bindBoundedGeometryListeners();
        this.#syncBoundedGeometry();
      }
      return;
    }

    if (hasResizeObserver) {
      if (!this.#footerObserver) {
        this.#footerObserver = new ResizeObserver(() => {
          if (!this.isConnected) return;
          this.#syncFooterSpace();
        });
      }
      this.#footerObserver.disconnect();
      this.#footerObserver.observe(footer);
    }

    this.#syncFooterSpace();

    if (!this.#isBounded() && !this.#isFillLayout()) {
      this.#teardownBoundedObservers();
      clearBoundedGeometry(this);
      return;
    }

    if (hasResizeObserver) {
      if (!this.#hostObserver) {
        this.#hostObserver = new ResizeObserver(() => {
          if (!this.isConnected) return;
          if (this.#isBounded()) {
            this.#scheduleGeometrySync();
          }
          if (this.#isFillLayout()) {
            this.#syncFooterSpace();
          }
        });
      }
      this.#hostObserver.disconnect();
      this.#hostObserver.observe(this);
    }

    if (this.#isBounded()) {
      this.#bindBoundedGeometryListeners();
      this.#syncBoundedGeometry();
    }
  }

  #syncHostLayoutVars() {
    for (const [attribute, cssVar] of Object.entries(HOST_LAYOUT_VARS)) {
      const value = this.getAttribute(attribute);
      if (value) {
        this.style.setProperty(cssVar, value);
      } else {
        this.style.removeProperty(cssVar);
      }
    }
  }

  get shellState() {
    return this.#state;
  }

  set shellState(next) {
    this.#state = normalizeShellState(next);
    this.render();
    this.#scheduleClockAging();
  }

  emitIntent(intent) {
    this.dispatchEvent(
      new CustomEvent('flow-intent', {
        bubbles: true,
        composed: true,
        detail: intent.error ? { error: intent.error, ...intent } : intent,
      }),
    );
  }

  showNotice(text) {
    const notice = this.shadowRoot.querySelector('.notice');
    if (!notice) return;
    notice.textContent = text;
    notice.hidden = false;
    clearTimeout(this.#noticeTimer);
    this.#noticeTimer = setTimeout(() => {
      notice.hidden = true;
    }, 4500);
  }

  #bindClockAging() {
    if (!this.isConnected) return;
    this.#teardownClockAging();
    const doc = this.ownerDocument;
    doc?.addEventListener('visibilitychange', this.#onVisibilityChange);
    this.#scheduleClockAging();
  }

  #teardownClockAging() {
    clearTimeout(this.#clockTimer);
    this.#clockTimer = null;
    this.ownerDocument?.removeEventListener('visibilitychange', this.#onVisibilityChange);
  }

  #scheduleClockAging() {
    if (!this.isConnected) return;
    clearTimeout(this.#clockTimer);
    const extraBoundaries = this.#reviewSnapshot?.expiresAt ? [this.#reviewSnapshot.expiresAt] : [];
    const delay = nextClockAgingDelayMs(this.#state, { extraBoundaries });
    this.#clockTimer = setTimeout(() => {
      this.#clockTimer = null;
      if (!this.isConnected) return;
      this.#refreshClockPresentation();
    }, delay);
  }

  #identityCaption(now = Date.now()) {
    const identity = this.#state.identity;
    const freshnessIssues = identity?.status === 'present' ? identityFreshnessIssues(identity, now) : [];
    if (freshnessIssues.length) return freshnessIssues.join(' ');
    if (identity?.status === 'present') {
      return (
        identity.value.display.fixtureLabel ||
        `Host-scoped binding ${identity.value.bindingRef}. Host must revalidate. Labels are untrusted.`
      );
    }
    if (identity?.status === 'rejected') return identity.reasons.join(' ');
    return 'No host identity context. Read-only navigation remains available; start intent is blocked.';
  }

  #reviewGateState({ confirmed, executionMode, now = Date.now() } = {}) {
    const gate = canEmitStartIntent(this.#state, {
      confirmed,
      executionMode,
      action: this.#state.selectedAction,
      now,
    });
    const snapshotExpired = Boolean(this.#reviewSnapshot && isConfirmationExpired(this.#reviewSnapshot, now));
    const allowed = gate.allowed && !snapshotExpired;
    const reasons = [...gate.reasons];
    if (snapshotExpired) {
      reasons.push('Confirmation snapshot has expired. Refresh the review dialog and confirm again.');
    }
    return { allowed, reasons: [...new Set(reasons)] };
  }

  #refreshReviewDialogClock(now = Date.now()) {
    const dialog = this.shadowRoot?.querySelector('dialog[data-shell-dialog]');
    if (!dialog?.open) return;
    const confirm = dialog.querySelector('[data-review-confirm]');
    const mode = dialog.querySelector('[data-action="execution-mode"]');
    const start = dialog.querySelector('[data-action="confirm-start"]');
    if (!confirm || !start) return;

    const gate = this.#reviewGateState({
      confirmed: confirm.checked,
      executionMode: mode?.value ?? this.#state.selectedExecutionMode,
      now,
    });
    const reasonEl = dialog.querySelector('[data-review-gate-reason]');
    if (reasonEl) {
      reasonEl.textContent = gate.reasons.join(' ') || 'Ready to emit start intent after confirmation.';
    }
    const identityCaption = dialog.querySelector('[data-identity-caption]');
    if (identityCaption) identityCaption.textContent = this.#identityCaption(now);
    start.disabled = !confirm.checked || !gate.allowed;
  }

  #preserveFocusedStage(update) {
    const root = this.shadowRoot;
    const active = root.activeElement;
    const stage = active?.dataset?.stage;
    update();
    if (stage != null) {
      root.querySelector(`[data-action="stage"][data-stage="${stage}"]`)?.focus();
      return;
    }
    if (active?.isConnected) active.focus();
  }

  #refreshClockPresentation() {
    if (!this.isConnected) return;
    const root = this.shadowRoot;
    if (!root?.querySelector('.shell-footer')) return;

    this.#preserveFocusedStage(() => {
      const steps = root.querySelector('.steps');
      if (steps) steps.innerHTML = this.renderSteps();
      const progress = root.querySelector('[data-shell-clock-progress]');
      if (progress) progress.innerHTML = this.renderProgress();
    });
    this.#refreshReviewDialogClock();
    this.#scheduleClockAging();
  }

  #ensureEventsBound() {
    if (this.#eventsBound) return;
    this.#eventsBound = true;
    const root = this.shadowRoot;
    root.addEventListener('click', (event) => this.#handleClick(event));
    root.addEventListener('change', (event) => this.#handleChange(event));
  }

  #handleClick(event) {
    const dialog = this.shadowRoot.querySelector('dialog[data-shell-dialog]');
    if (dialog?.open && event.target === dialog) {
      dialog.close();
      return;
    }

    const target = event.target.closest('[data-action]');
    if (!target) return;
    const action = target.dataset.action;
    switch (action) {
      case 'identity':
        this.emitIntent(createHeaderIntent('identity'));
        break;
      case 'project':
        this.emitIntent(createHeaderIntent('project'));
        break;
      case 'account':
        this.emitIntent(createHeaderIntent('account'));
        break;
      case 'health':
        this.emitIntent(createHealthIntent(this.#state.health.url));
        break;
      case 'toggle-map':
        this.#state = withMapExpanded(this.#state, !this.#state.mapExpanded);
        this.emitIntent(createToggleMapIntent(this.#state.mapExpanded));
        this.render();
        break;
      case 'collapse-map':
        this.#state = withMapExpanded(this.#state, false);
        this.emitIntent(createToggleMapIntent(false));
        this.render();
        break;
      case 'review-batch':
        if (dialog?.open) dialog.close();
        this.openReviewDialog();
        break;
      case 'modal-close':
        dialog?.close();
        break;
      case 'view-drafts':
        this.emitIntent(createViewDraftsIntent(this.#state.delivery.draftCount));
        break;
      case 'stage': {
        const stageIndex = Number(target.dataset.stage);
        this.#state = withSelectedAction(
          withViewedStage(this.#state, stageIndex),
          defaultActionForStage(stageIndex, this.#state),
        );
        this.emitIntent(createNavigateStageIntent(stageIndex));
        this.render();
        this.openStageDialog(stageIndex);
        break;
      }
      default:
        break;
    }
  }

  #handleChange(event) {
    if (event.target.matches('[data-action="footer-execution-mode"]')) {
      this.#state = withExecutionMode(this.#state, event.target.value);
      this.render();
    }
  }

  openStageDialog(stageIndex) {
    const now = Date.now();
    const gate = getStageGate(stageIndex, this.#state, { now });
    const stage = STAGES[stageIndex];
    const html = `
      <button class="modal-close" type="button" data-action="modal-close" aria-label="Close dialog">×</button>
      <span class="eyebrow">LOOKING AT ${escapeHtml(stage.label.toUpperCase())} · ${escapeHtml(stage.product.toUpperCase())}</span>
      <h2>${escapeHtml(stage.label)} via ${escapeHtml(stage.product)}</h2>
      <p>${escapeHtml(stage.summary)}</p>
      <p>${escapeHtml(gate.reason ?? 'Explore current evidence for this stage. Navigation never starts delivery.')}</p>
      <p class="muted" style="font-size:11px">Viewing a step is separate from readiness. Stage clicks and proposals never execute work. Allowed actions: ${escapeHtml(
        (gate.allowedActions ?? []).join(', ') || 'none',
      )}.</p>
      <div class="actions">
        <button class="primary" type="button" data-action="review-batch">Review prerequisites</button>
        <button class="text-button" type="button" data-action="modal-close">Back</button>
      </div>`;
    this.openDialog(html, {
      ariaLabel: `${stage.label} stage details`,
    });
  }

  openReviewDialog() {
    const now = Date.now();
    const action = this.#state.selectedAction ?? 'build';
    this.#reviewSnapshot = confirmationSnapshot(this.#state, {
      now,
      action,
      executionMode: this.#state.selectedExecutionMode,
    });
    this.#scheduleClockAging();
    this.emitIntent(createReviewBatchIntent(this.#state));
    const items = this.#state.delivery.scopeItems
      .map((item) => `<div><strong>${escapeHtml(item)}</strong><span>Included</span></div>`)
      .join('');
    const gate = canEmitStartIntent(this.#state, {
      confirmed: false,
      executionMode: this.#state.selectedExecutionMode,
      action,
      now,
    });
    const identityCaption = this.#identityCaption(now);
    const html = `
      <button class="modal-close" type="button" data-action="modal-close" aria-label="Close dialog">×</button>
      <span class="eyebrow">REVIEW BEFORE YOU BEGIN</span>
      <h2>${escapeHtml(this.#state.delivery.batchTitle)}</h2>
      <p>Explicit start binds to action <code>${escapeHtml(action)}</code>, batch <code>${escapeHtml(this.#state.delivery.batchRef ?? 'missing')}</code>, and baseline digest below. The host must revalidate authority. Confirmation expires at <span data-review-expiry>${escapeHtml(this.#reviewSnapshot.expiresAt)}</span>.</p>
      <p class="muted" style="font-size:11px" data-identity-caption>${escapeHtml(identityCaption)}</p>
      <div class="detail-list">${items || '<div><strong>Scope items not supplied</strong><span>Host</span></div>'}</div>
      <p style="font-size:11px">UI gates and identity schema checks are advisory. This dialog emits intent only; it is not a security or auth backend.</p>
      <label class="checklist"><input type="checkbox" data-review-confirm> I confirm this scope, selected action, execution mode, and evidence snapshot.</label>
      <label class="checklist">Execution mode
        <select data-action="execution-mode">${this.#state.executionModes
          .map(
            (mode) =>
              `<option value="${escapeHtml(mode)}" ${mode === this.#state.selectedExecutionMode ? 'selected' : ''}>${escapeHtml(mode)}</option>`,
          )
          .join('')}</select>
      </label>
      <p class="muted" style="font-size:11px" data-review-gate-reason>${escapeHtml(gate.reasons.join(' ') || 'Ready to emit start intent after confirmation.')}</p>
      <div class="actions">
        <button class="primary" type="button" data-action="confirm-start" disabled>Emit start intent</button>
        <button class="text-button" type="button" data-action="modal-close">Keep as draft</button>
      </div>`;
    this.openDialog(html, {
      ariaLabel: 'Review batch before start',
      afterOpen: () => this.wireReviewDialog(),
    });
  }

  wireReviewDialog() {
    const root = this.shadowRoot;
    const dialog = root.querySelector('dialog[data-shell-dialog]');
    const confirm = dialog.querySelector('[data-review-confirm]');
    const start = dialog.querySelector('[data-action="confirm-start"]');
    const mode = dialog.querySelector('[data-action="execution-mode"]');

    const refresh = () => {
      const gate = this.#reviewGateState({
        confirmed: confirm.checked,
        executionMode: mode.value,
        now: Date.now(),
      });
      const reasonEl = dialog.querySelector('[data-review-gate-reason]');
      if (reasonEl) {
        reasonEl.textContent = gate.reasons.join(' ') || 'Ready to emit start intent after confirmation.';
      }
      start.disabled = !confirm.checked || !gate.allowed;
    };

    confirm?.addEventListener('change', refresh);
    mode?.addEventListener('change', (event) => {
      this.#state = withExecutionMode(this.#state, event.target.value);
      this.#reviewSnapshot = confirmationSnapshot(this.#state, {
        now: Date.now(),
        action: this.#state.selectedAction,
        executionMode: event.target.value,
      });
      this.#scheduleClockAging();
      const footerMode = root.querySelector('[data-action="footer-execution-mode"]');
      if (footerMode) footerMode.value = event.target.value;
      const expiry = dialog.querySelector('[data-review-expiry]');
      if (expiry) expiry.textContent = this.#reviewSnapshot.expiresAt;
      if (confirm) confirm.checked = false;
      refresh();
    });
    start?.addEventListener('click', () => {
      const intent = createStartIntent(this.#state, {
        confirmed: confirm.checked,
        executionMode: mode.value,
        action: this.#state.selectedAction,
        capturedSnapshot: this.#reviewSnapshot,
        now: Date.now(),
      });
      if (intent.error) {
        this.showNotice(intent.error);
        this.emitIntent(intent);
        if (intent.stale) dialog.close();
        return;
      }
      dialog.close();
      this.emitIntent(intent);
      this.showNotice('Start intent emitted. Host must revalidate authority before execution.');
    });
    refresh();
  }

  openDialog(html, { afterOpen, ariaLabel } = {}) {
    const dialog = this.shadowRoot.querySelector('dialog[data-shell-dialog]');
    if (ariaLabel) dialog.setAttribute('aria-label', ariaLabel);
    dialog.innerHTML = html;
    dialog.showModal();
    afterOpen?.();
    const firstFocusable = dialog.querySelector(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
    );
    firstFocusable?.focus();
  }

  renderSteps(now = Date.now()) {
    return STAGES.map((stage) => {
      const view = buildStagePresentation(stage.index, this.#state, this.#state.delivery.viewedStage, { now });
      const marker = view.done
        ? MARKER_ICON.done
        : view.notInBatch
          ? MARKER_ICON.absent
          : view.unknown && !view.isActive
            ? MARKER_ICON.unknown
            : view.attention
              ? MARKER_ICON.attention
              : view.isActive
                ? MARKER_ICON.active
                : MARKER_ICON.future;
      const classes = [
        'step-button',
        view.done ? 'done' : '',
        view.notInBatch ? 'not-in-batch' : '',
        view.unknown && !view.isActive && !view.done ? 'unknown-evidence' : '',
        view.isActive ? 'active' : '',
        view.attention ? 'attention' : '',
      ]
        .filter(Boolean)
        .join(' ');
      return `<button type="button" class="${classes}" data-action="stage" data-stage="${stage.index}" aria-label="${escapeHtml(view.ariaLabel)}" ${view.isViewed ? 'aria-current="step"' : ''}>
        <span class="step-marker">${marker}</span>
        <span><span class="step-label">${escapeHtml(stage.label)}</span><span class="product-tag">${escapeHtml(stage.product)}</span></span>
      </button>`;
    }).join('');
  }

  renderProgress(now = Date.now()) {
    const taskStale = isStaleSnapshot(this.#state.progress.task, now);
    const overallStale = isStaleSnapshot(this.#state.progress.overall, now);
    const taskLine = formatProgressLine(this.#state.progress.task, { prefix: '', now });
    const overallLine = formatProgressLine(this.#state.progress.overall, { prefix: '', now });
    const computedFresh = formatFreshnessLabel(
      this.#state.progress.overall?.progress ?? this.#state.progress.task?.progress,
      now,
    );
    const computedStale =
      resolveFreshness(this.#state.progress.overall?.progress ?? this.#state.progress.task?.progress, now) ===
      'stale';
    const hostLabel = this.#state.progress.freshnessLabel;
    const fresh = computedStale ? computedFresh : hostLabel || computedFresh;
    return `
      <div class="${taskStale ? 'stale' : ''}"><strong>${escapeHtml(this.#state.progress.taskLabel)}</strong> · <span class="progress-value ${taskStale ? 'stale' : ''}">${escapeHtml(taskLine)}</span></div>
      <div class="${overallStale ? 'stale' : ''}"><strong>${escapeHtml(this.#state.progress.overallLabel)}</strong> · <span class="progress-value ${overallStale ? 'stale' : ''}">${escapeHtml(overallLine)}</span></div>
      <div>${escapeHtml(fresh)}</div>`;
  }

  render() {
    const logoSrc = this.getAttribute('logo-src') || new URL('./assets/inspr-logo.svg', import.meta.url).href;
    const projectTitle = escapeHtml(this.#state.header.projectName);
    const subtitle = this.#state.header.projectSubtitle
      ? `<span class="subtitle">${escapeHtml(this.#state.header.projectSubtitle)}</span>`
      : '';
    const projectLabel = `${this.#state.header.projectName}${this.#state.header.projectSubtitle ? ` ${this.#state.header.projectSubtitle}` : ''}`;
    const instance = this.#state.header.instanceLabel
      ? `<span class="shell-label shell-label-context" title="${escapeHtml(this.#state.header.instanceLabel)}">${escapeHtml(this.#state.header.instanceLabel)}</span>`
      : '';
    const version = this.#state.header.version
      ? `<span class="shell-label shell-label-context" title="${escapeHtml(this.#state.header.version)}">${escapeHtml(this.#state.header.version)}</span>`
      : '';
    const healthDot = this.#state.health.status === 'available' ? 'dot' : `dot ${this.#state.health.status}`;
    const mapDetail = this.#state.delivery.mapDetail || 'Requirements baseline gates delivery work. Stage exploration never executes.';
    const draftLabel = `${this.#state.delivery.draftCount} ideas waiting outside this delivery`;

    this.shadowRoot.innerHTML = `
      <link rel="stylesheet" href="${new URL('./flow-shell.css', import.meta.url).href}" data-shell-css="true">
      <div class="shell-root">
      <div class="shell-scaffold">
      <header class="shell-header">
        <button type="button" class="identity" data-action="identity" aria-label="About ${escapeHtml(this.#state.header.appName)} shell">
          <img src="${escapeHtml(logoSrc)}" alt="">
          <span>${escapeHtml(this.#state.header.appName)}</span>
        </button>
        <span class="header-divider"></span>
        <button type="button" class="project" data-action="project" title="${escapeHtml(projectLabel)}" aria-label="Project: ${escapeHtml(projectLabel)}">
          <span class="project-name">${projectTitle}</span>${subtitle}
        </button>
        <div class="header-end">
          ${instance}
          ${version}
          <span class="shell-label">Flow shell · intent boundary</span>
          <button type="button" class="avatar" data-action="account" aria-label="Account and authority">${escapeHtml(this.#state.header.userInitials)}</button>
        </div>
      </header>
      <div class="shell-main">
        <div class="health">
          <span class="${healthDot}"></span>
          ${escapeHtml(this.#state.health.label)}
          <span class="muted">·</span>
          <button type="button" data-action="health">${escapeHtml(this.#state.health.checkedLabel || 'Check host health')}</button>
        </div>
        <div class="host-slot"><slot></slot></div>
      </div>
      </div>
      </div>
      <div class="notice shell-chrome-fixed" role="status" hidden></div>
      <footer class="shell-footer shell-chrome-fixed">
      <div class="shell-footer-root">
      <div class="shell-footer-scaffold">
        <section class="expanded-panel" ${this.#state.mapExpanded ? '' : 'hidden'}>
          <div class="expanded-heading">
            <div>
              <span class="eyebrow">YOUR DELIVERY MAP</span>
              <h2>One live product. A considered next step.</h2>
            </div>
            <button type="button" class="text-button" data-action="collapse-map" aria-label="Collapse delivery map">Close</button>
          </div>
          <div class="branch-map">
            <div class="live-row">
              <span class="node live-node">${MARKER_ICON.done}</span>
              <span>${escapeHtml(this.#state.delivery.liveReleaseLabel)} <small>Current release</small></span>
              <div class="live-line"></div>
              <span class="muted">Next release</span>
            </div>
            <div class="branch-curve"></div>
            <div class="batch-row">
              <span class="node">${MARKER_ICON.active}</span>
              <div>
                <strong>${escapeHtml(this.#state.delivery.batchTitle)}</strong>
                <small>${escapeHtml(this.#state.delivery.batchSummary || 'Selected delivery batch')}</small>
              </div>
              <span class="pill">${escapeHtml(this.#state.delivery.batchStatusLabel)}</span>
            </div>
            <div class="map-detail">${escapeHtml(mapDetail)}</div>
            <div class="draft-row">
              <span>${MARKER_ICON.future}</span>
              <span>${escapeHtml(draftLabel)}</span>
              <button type="button" class="text-button" data-action="view-drafts">View drafts</button>
            </div>
          </div>
        </section>
        <div class="bar-heading">
          <button type="button" data-action="toggle-map" aria-expanded="${this.#state.mapExpanded}" aria-controls="delivery-expanded">
            <span class="eyebrow">DELIVERY</span>
            <strong>${escapeHtml(this.#state.delivery.batchTitle)}</strong>
            <span class="expand-symbol" aria-hidden="true">${this.#state.mapExpanded ? '↓' : '↑'}</span>
          </button>
          <span class="bar-context">${escapeHtml(this.#state.header.projectName)} · one stream</span>
        </div>
        <nav class="steps" aria-label="Delivery stages">${this.renderSteps()}</nav>
        <div class="bar-bottom">
          <div class="clock-progress" data-shell-clock-progress>${this.renderProgress()}</div>
          <label class="mode-label">Execution mode
            <select data-action="footer-execution-mode">${this.#state.executionModes
              .map(
                (mode) =>
                  `<option value="${escapeHtml(mode)}" ${mode === this.#state.selectedExecutionMode ? 'selected' : ''}>${escapeHtml(mode)}</option>`,
              )
              .join('')}</select>
          </label>
          <button type="button" class="text-button" data-action="review-batch">Review batch</button>
        </div>
      </div>
      </div>
      </footer>
      <dialog data-shell-dialog></dialog>`;
    this.#bindLayoutObservers();
    this.#scheduleClockAging();
  }
}

if (!customElements.get('inspr-flow-shell')) {
  customElements.define('inspr-flow-shell', InsprFlowShell);
}

export { fromDeliveryContract, ADAPTER_BOUNDARY, deriveActiveWork, stageForOperation, actionForOperation, stageEvidenceFor } from './adapter.js';
export {
  normalizeShellState,
  confirmationSnapshot,
  withViewedStage,
  withMapExpanded,
  withExecutionMode,
  withSelectedAction,
  withIdentityContext,
} from './state.js';
export {
  normalizeIdentityContext,
  identityBinding,
  identityStartIssues,
  IDENTITY_CONTRACT_VERSION,
  AUTHORITY_DISCLAIMER,
} from './identity.js';
export { STAGES, ACTIONS, defaultActionForStage } from './stages.js';
export * from './intents.js';
export * from './gates.js';
export * from './forecast.js';
export * from './sanitize.js';
export {
  applyBoundedGeometry,
  applyFooterSpace,
  applyFillFooterCap,
  clearBoundedGeometry,
  clearFillFooterCap,
  resolveLayoutMode,
  resolveContentLayout,
  resolveFillFooterHeight,
  resolveFillFooterCapacity,
  resolveFillFooterReservation,
  measureHostLocalTopOffset,
  measureFillContentMinimumFromMetrics,
  LAYOUT_MODES,
  CONTENT_LAYOUTS,
} from './host-layout.js';
