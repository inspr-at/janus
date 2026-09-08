import '/static/vendor/flow-shell/src/inspr-flow-shell.js';

const shell = document.querySelector('inspr-flow-shell[data-flow-host]');
if (shell) {
  const projectId = shell.dataset.flowProject || '';
  const paimosOrigin = shell.dataset.flowPaimosOrigin || '';
  let generation = 0;
  let refreshTimer = null;
  let mainUnwrapped = false;

  function unwrapMainFromShell() {
    if (mainUnwrapped) {
      return;
    }
    const main = shell.querySelector('main');
    if (!main || !shell.parentNode) {
      return;
    }
    shell.parentNode.insertBefore(main, shell);
    mainUnwrapped = true;
    shell.style.display = 'none';
  }

  function wrapMainIntoShell() {
    if (!mainUnwrapped) {
      return;
    }
    let main = shell.previousElementSibling;
    if (!main?.matches('main')) {
      main = document.querySelector('main');
    }
    if (main) {
      shell.appendChild(main);
    }
    mainUnwrapped = false;
    shell.style.display = '';
  }

  function unmountShellChrome() {
    shell.setAttribute('data-flow-host-unavailable', 'true');
    unwrapMainFromShell();
  }

  function mountShellChrome() {
    shell.removeAttribute('data-flow-host-unavailable');
    wrapMainIntoShell();
    if (refreshTimer === null) {
      scheduleBoundaryRefresh();
    }
  }

  function clearShell() {
    shell.shellState = {
      evaluatedAt: null,
      header: {},
      health: { status: 'unknown', label: 'Flow unavailable' },
      delivery: { status: 'draft' },
      prerequisites: {},
      progress: {},
      executionModes: ['manual'],
      selectedExecutionMode: 'manual',
      selectedAction: 'janus_prepare',
      identityContext: null,
    };
  }

  function csrfToken() {
    return document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
  }

  function shellStateUrl() {
    const url = new URL('/flow/shell-state.json', document.baseURI);
    if (projectId) {
      url.searchParams.set('flow_project', projectId);
    }
    return url;
  }

  function intentsUrl() {
    const url = new URL('/flow/intents', document.baseURI);
    if (projectId) {
      url.searchParams.set('flow_project', projectId);
    }
    return url;
  }

  function extractIntentIdentity(detail) {
    const nested = detail?.detail?.identity ?? detail?.identity;
    if (nested && typeof nested === 'object') {
      return nested;
    }
    const identity = shell.shellState?.identity;
    if (identity?.status === 'present' && identity?.value) {
      return identity.value;
    }
    return null;
  }

  function msUntilNextTenMinuteBoundary(now = Date.now()) {
    const seconds = Math.floor(now / 1000);
    const remainder = seconds % 600;
    const deltaSeconds = remainder === 0 ? 600 : 600 - remainder;
    return deltaSeconds * 1000 - (now % 1000);
  }

  function scheduleBoundaryRefresh() {
    if (refreshTimer !== null) {
      clearTimeout(refreshTimer);
    }
    refreshTimer = setTimeout(() => {
      refresh().finally(scheduleBoundaryRefresh);
    }, msUntilNextTenMinuteBoundary());
  }

  async function refresh() {
    const next = ++generation;
    try {
      const response = await fetch(shellStateUrl(), {
        credentials: 'same-origin',
        cache: 'no-store',
      });
      if (generation !== next) {
        return;
      }
      if (!response.ok) {
        clearShell();
        unmountShellChrome();
        return;
      }
      const payload = await response.json();
      if (generation !== next) {
        return;
      }
      if (!payload.enabled || !payload.mountShell || payload.unavailableReason) {
        clearShell();
        unmountShellChrome();
        return;
      }
      mountShellChrome();
      if (payload.shellState) {
        shell.shellState = payload.shellState;
      } else {
        clearShell();
        unmountShellChrome();
      }
    } catch {
      if (generation === next) {
        clearShell();
        unmountShellChrome();
      }
    }
  }

  function navigationAllowed(location) {
    if (!location || typeof location !== 'string') {
      return false;
    }
    let target;
    try {
      target = new URL(location);
    } catch {
      return false;
    }
    if (!paimosOrigin) {
      return false;
    }
    let allowed;
    try {
      allowed = new URL(paimosOrigin);
    } catch {
      return false;
    }
    if (target.origin !== allowed.origin) {
      return false;
    }
    return /^\/projects\/\d+$/.test(target.pathname);
  }

  shell.addEventListener('flow-intent', async (event) => {
    const detail = event.detail ?? {};
    const intentType = detail.type ?? detail.intentType;
    const identity = extractIntentIdentity(detail);
    try {
      const response = await fetch(intentsUrl(), {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken(),
        },
        body: JSON.stringify({
          type: intentType,
          identity,
          detail,
        }),
      });
      const result = await response.json();
      if (result.notice && typeof result.notice === 'string') {
        shell.showNotice?.(result.notice);
      }
      if (result.error && typeof result.error === 'string') {
        shell.showNotice?.(result.error);
        return;
      }
      if (navigationAllowed(result.location)) {
        window.location.assign(result.location);
      }
    } catch {
      shell.showNotice?.('Flow intent could not be completed.');
    }
  });

  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) {
      refresh();
    }
  });

  refresh();
  scheduleBoundaryRefresh();
}
