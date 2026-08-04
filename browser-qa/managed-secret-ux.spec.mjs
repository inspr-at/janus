import { randomBytes } from "node:crypto";
import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

function runtimeCanary(label) {
  return `janus-${label}-${randomBytes(24).toString("hex")}`;
}

async function expectCanariesAbsent(page, canaries) {
  const surface = await page.evaluate(() => ({
    url: window.location.href,
    html: document.documentElement.outerHTML,
    accessibility: document.querySelector("main")?.innerText ?? "",
    localStorage: { ...window.localStorage },
    sessionStorage: { ...window.sessionStorage },
    historyState: window.history.state,
  }));
  const cookies = await page.context().cookies();
  const encoded = JSON.stringify({ surface, cookies });
  for (const canary of canaries) {
    expect(encoded.includes(canary)).toBe(false);
  }
}

async function submitImportedValue(page, canary) {
  await page
    .locator('form[action="/managed-service/setup/execute"]')
    .evaluate((form, value) => {
      const input = form.querySelector('input[name="secret_value"]');
      if (!(input instanceof HTMLInputElement)) {
        throw new Error("managed secret input unavailable");
      }
      input.value = value;
      try {
        form.requestSubmit();
      } finally {
        // Keep a later Playwright failure from retaining the runtime canary in
        // its automatic accessibility/error context.
        input.value = "";
      }
    }, canary);
}

test("login hero keeps the split trust story clear and value-free", async ({
  page,
}) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Open Janus" })).toBeVisible();
  await expect(page.getByText("Looks back", { exact: true })).toBeVisible();
  await expect(page.getByText("Looks forward", { exact: true })).toBeVisible();
  await expect(
    page.getByText(/Vault & evidence: what exists, who touched it/),
  ).toBeVisible();
  await expect(
    page.getByText(/Forge issues new credentials only after policy/),
  ).toBeVisible();
  await expect(page.getByText("value_returned=false")).toBeVisible();

  const layout = await page.evaluate(() => {
    const rectangle = (selector) => {
      const bounds = document.querySelector(selector).getBoundingClientRect();
      return {
        left: bounds.left,
        top: bounds.top,
        right: bounds.right,
        bottom: bounds.bottom,
      };
    };
    const overlaps = (left, right) =>
      left.left < right.right &&
      left.right > right.left &&
      left.top < right.bottom &&
      left.bottom > right.top;
    const card = rectangle(".auth-card");
    const back = rectangle(".auth-rail.back");
    const forward = rectangle(".auth-rail.forward");
    const hero = getComputedStyle(document.querySelector("main"), "::before");
    return {
      heroInset: hero.inset,
      heroMask: hero.maskImage,
      backOverlapsCard: overlaps(back, card),
      forwardOverlapsCard: overlaps(forward, card),
      horizontalOverflow:
        document.documentElement.scrollWidth - window.innerWidth,
    };
  });
  expect(layout).toEqual({
    heroInset: "0px",
    heroMask: "none",
    backOverlapsCard: false,
    forwardOverlapsCard: false,
    horizontalOverflow: 0,
  });

  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(
    accessibility.violations.filter(({ impact }) =>
      ["serious", "critical"].includes(impact),
    ),
  ).toEqual([]);
});

test("passwordless import shows Check, forgets the value, and recovers navigation", async ({
  page,
}) => {
  const messages = [];
  page.on("console", (message) => messages.push(message.text()));
  page.on("pageerror", (error) => messages.push(error.message));

  await page.goto("/__managed-browser/session?kind=create");
  await expect(
    page.getByRole("heading", { name: "Add service secret" }),
  ).toBeVisible();
  await expect(page.locator('input[name="secret_value"]')).toHaveCount(0);
  await expect(page.getByText("Reveal", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Copy", { exact: true })).toHaveCount(0);
  await expect(page.locator(".managed-source-choice")).toHaveCount(2);
  await expect(page.locator(".managed-source-choice").first()).toHaveCSS(
    "display",
    "grid",
  );

  await page
    .getByRole("radio", { name: /Use my own value/ })
    .check();
  const authorizationRequest = page.waitForRequest(
    (request) =>
      new URL(request.url()).pathname === "/__managed-browser/authorize",
  );
  const callbackResponse = page.waitForResponse(
    (response) => new URL(response.url()).pathname === "/oidc/callback",
  );
  await page.getByRole("button", { name: "Confirm with passkey" }).click();
  expect(new URL((await authorizationRequest).url()).hostname).toBe("localhost");
  const callback = await callbackResponse;
  expect(callback.status()).toBe(200);
  expect(callback.headers().refresh).toBe(
    "0; url=/managed-service/setup?intent=intent_0123456789abcdef",
  );
  await expect(
    page.getByRole("heading", { name: "Ready to add" }),
  ).toBeVisible();

  const canary = runtimeCanary("import");
  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(
    accessibility.violations.filter(({ impact }) =>
      ["serious", "critical"].includes(impact),
    ),
  ).toEqual([]);

  const completionNavigation = page.waitForURL(
    /\/managed-service\/setup\/complete\/op_[a-z0-9]+$/,
  );
  await submitImportedValue(page, canary);
  await completionNavigation;
  await expect(
    page.getByRole("heading", { name: "Checking service" }),
  ).toBeVisible();
  await expect(page.getByRole("status")).toContainText("Secret accepted");
  await expect(page.getByText("Opening service status…")).toBeVisible();
  await expectCanariesAbsent(page, [canary]);
  const completionAccessibility = await new AxeBuilder({ page }).analyze();
  expect(
    completionAccessibility.violations.filter(({ impact }) =>
      ["serious", "critical"].includes(impact),
    ),
  ).toEqual([]);

  await expect(
    page.getByRole("heading", { name: "Operation registered" }),
  ).toBeVisible({ timeout: 5_000 });
  await expectCanariesAbsent(page, [canary]);
  expect((await page.locator("main").ariaSnapshot()).includes(canary)).toBe(
    false,
  );

  const evidence = await (
    await page.request.get("/__managed-browser/evidence")
  ).text();
  expect(evidence.includes(canary)).toBe(false);
  expect(JSON.parse(evidence)).toMatchObject({
    executions: 1,
    last_value_byte_count: canary.length,
    authority_kind: "test_fixture",
  });

  await page.goBack({ waitUntil: "domcontentloaded" });
  await expect(
    page.getByRole("heading", { name: "Operation registered" }),
  ).toBeVisible({ timeout: 5_000 });
  await expect(page.locator('input[name="secret_value"]')).toHaveCount(0);
  await expectCanariesAbsent(page, [canary]);
  await page.reload();
  await expectCanariesAbsent(page, [canary]);

  const finalEvidence = await (
    await page.request.get("http://127.0.0.1:18082/__managed-browser/evidence")
  ).text();
  expect(JSON.parse(finalEvidence).executions).toBe(1);
  expect(
    messages.some((message) => message.includes(canary)),
  ).toBe(false);
});

test("dynamic target is locked to a fresh passkey before any value field", async ({
  page,
}) => {
  await page.goto("/__managed-browser/session?kind=dynamic");
  await expect(
    page.getByRole("heading", { name: "Add environment variable" }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "DATABASE_PASSWORD" }),
  ).toBeVisible();
  await expect(page.getByText("host_0123456789abcdef")).toBeVisible();
  await expect(page.getByText("svc_0123456789abcdef")).toBeVisible();
  await expect(page.getByText("Target locked")).toBeVisible();
  await expect(page.locator('input[name="secret_value"]')).toHaveCount(0);
  await expect(page.locator('input[type="password"]')).toHaveCount(0);
  await expect(
    page.locator('form[action="/managed-environment/setup/execute"]'),
  ).toHaveCount(0);

  const callbackResponse = page.waitForResponse(
    (response) => new URL(response.url()).pathname === "/oidc/callback",
  );
  await page.getByRole("button", { name: "Confirm with passkey" }).click();
  const callback = await callbackResponse;
  expect(callback.status()).toBe(200);
  expect(callback.headers().refresh).toBe(
    "0; url=/managed-environment/setup?intent=intent_13579bdf2468ace0",
  );
  await expect(
    page.getByRole("heading", { name: "Exact request reserved" }),
  ).toBeVisible();
  await expect(page.getByText(/No value accepted yet/)).toBeVisible();
  await expect(page.locator('input[name="secret_value"]')).toHaveCount(0);
  await expect(
    page.locator('form[action="/managed-environment/setup/step-up"]'),
  ).toHaveCount(0);

  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(
    accessibility.violations.filter(({ impact }) =>
      ["serious", "critical"].includes(impact),
    ),
  ).toEqual([]);
});

test("compact generated flow works from the keyboard", async ({ page }) => {
  await page.goto("/__managed-browser/session?kind=create");
  await expect(
    page.getByRole("heading", { name: "Add service secret" }),
  ).toBeVisible();
  await expect(page.getByRole("radio", { name: /Generate securely/ })).toBeChecked();
  await expect(
    page.getByRole("heading", { name: "Managed browser canary" }),
  ).toBeVisible();
  await expect(page.getByText("Managed host")).toBeVisible();
  await expect(
    page.getByText("Service credential", { exact: true }),
  ).toBeVisible();
  await expect(page.getByText("Target locked")).toBeVisible();

  const confirm = page.getByRole("button", { name: "Confirm with passkey" });
  await confirm.focus();
  await confirm.press("Enter");
  await expect(
    page.getByRole("heading", { name: "Ready to add" }),
  ).toBeVisible();
  await expect(page.locator('input[name="secret_value"]')).toHaveCount(1);
  await expect(
    page.locator('input[name="secret_value"]'),
  ).toHaveAttribute("type", "hidden");

  const add = page.getByRole("button", { name: "Add secret" });
  await add.focus();
  await add.press("Enter");
  await expect(
    page.getByRole("heading", { name: "Checking service" }),
  ).toBeVisible();
  await expect(page.getByRole("status")).toContainText("Secret accepted");
  await expect(
    page.getByRole("heading", { name: "Operation registered" }),
  ).toBeVisible({ timeout: 5_000 });

  const evidence = await (
    await page.request.get("http://127.0.0.1:18082/__managed-browser/evidence")
  ).json();
  expect(evidence).toMatchObject({
    executions: 1,
    last_value_byte_count: 0,
  });
});

test("accepted operation survives a lost completion and step-up cookie", async ({
  page,
}) => {
  await page.goto("/__managed-browser/session?kind=create");
  await page.getByRole("button", { name: "Confirm with passkey" }).click();
  await expect(
    page.getByRole("heading", { name: "Ready to add" }),
  ).toBeVisible();

  const executeForm = page.locator(
    'form[action="/managed-service/setup/execute"]',
  );
  const csrf = await executeForm
    .locator('input[name="csrf_token"]')
    .inputValue();
  const intent = await executeForm
    .locator('input[name="intent_ref"]')
    .inputValue();
  const source = await executeForm
    .locator('input[name="source"]')
    .inputValue();
  const formBody = new URLSearchParams([
    ["csrf_token", csrf],
    ["intent_ref", intent],
    ["source", source],
    ["secret_value", ""],
  ]).toString();
  const firstSubmission = await page.request.post(
    "/managed-service/setup/execute",
    {
      data: formBody,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Origin: new URL(page.url()).origin,
        "Sec-Fetch-Site": "same-origin",
      },
      maxRedirects: 0,
    },
  );
  expect(firstSubmission.status()).toBe(303);
  await expect
    .poll(async () => {
      const evidence = await page.request.get("/__managed-browser/evidence");
      return (await evidence.json()).executions;
    })
    .toBe(1);

  const context = page.context();
  await expect
    .poll(async () =>
      (await context.cookies()).some(
        ({ name }) => name === "janus_managed_completion",
      ),
    )
    .toBe(true);
  await context.clearCookies({ name: "janus_managed_completion" });
  expect(
    (await context.cookies()).some(
      ({ name }) => name === "janus_managed_stepup_proof",
    ),
  ).toBe(false);

  await page.getByRole("button", { name: "Add secret" }).click();
  await expect(
    page.getByRole("heading", { name: "Checking service" }),
  ).toBeVisible();
  await expect(page.getByRole("status")).toContainText("Secret accepted");
  await expect(
    page.getByRole("heading", { name: "Operation registered" }),
  ).toBeVisible({ timeout: 5_000 });

  const evidence = await (
    await page.request.get("http://127.0.0.1:18082/__managed-browser/evidence")
  ).json();
  expect(evidence.executions).toBe(1);
});

test("expired step-up and logout never preserve a value field", async ({
  page,
}) => {
  await page.goto("/__managed-browser/expired");
  await expect(
    page.getByRole("button", { name: "Confirm with passkey" }),
  ).toBeVisible();
  await expect(page.locator('input[name="secret_value"]')).toHaveCount(0);

  await page
    .getByRole("radio", { name: /Use my own value/ })
    .check();
  await page.getByRole("button", { name: "Confirm with passkey" }).click();
  await expect(page.locator('input[name="secret_value"]')).toBeVisible();
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByText("Continue with Zitadel")).toBeVisible();
  await page.goto(
    "/managed-service/setup?intent=intent_0123456789abcdef",
  );
  await expect(page.locator('input[name="secret_value"]')).toHaveCount(0);
});

test("expired OIDC state returns to exact Confirm without authority", async ({
  page,
}) => {
  await page.goto("/__managed-browser/expired-oidc");
  await expect(
    page.getByRole("heading", { name: "Add service secret" }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Confirm with passkey" }),
  ).toBeVisible();
  await expect(page.locator('input[name="secret_value"]')).toHaveCount(0);
  await expect(page.getByText("Safe boundary")).toHaveCount(0);
  expect(
    (await page.context().cookies()).some(
      ({ name }) => name === "janus_managed_stepup_retry",
    ),
  ).toBe(false);

  const evidence = await (
    await page.request.get("http://127.0.0.1:18082/__managed-browser/evidence")
  ).json();
  expect(evidence.executions).toBe(0);

  const accessibility = await new AxeBuilder({ page }).analyze();
  expect(
    accessibility.violations.filter(({ impact }) =>
      ["serious", "critical"].includes(impact),
    ),
  ).toEqual([]);
});

test("lost step-up proof returns to Confirm without executing", async ({
  page,
}) => {
  await page.goto("/__managed-browser/session?kind=create");
  await page.getByRole("button", { name: "Confirm with passkey" }).click();
  await expect(
    page.getByRole("heading", { name: "Ready to add" }),
  ).toBeVisible();

  await page
    .context()
    .clearCookies({ name: "janus_managed_stepup_proof" });
  await page.getByRole("button", { name: "Add secret" }).click();

  await expect(
    page.getByRole("button", { name: "Confirm with passkey" }),
  ).toBeVisible();
  await expect(page.locator('input[name="secret_value"]')).toHaveCount(0);
  await expect(page.getByText("Safe boundary")).toHaveCount(0);

  const evidence = await (
    await page.request.get("http://127.0.0.1:18082/__managed-browser/evidence")
  ).json();
  expect(evidence.executions).toBe(0);

  await page.getByRole("button", { name: "Confirm with passkey" }).click();
  await expect(
    page.getByRole("heading", { name: "Ready to add" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Add secret" }).click();
  await expect(
    page.getByRole("heading", { name: "Operation registered" }),
  ).toBeVisible({ timeout: 5_000 });

  const recovered = await (
    await page.request.get("http://127.0.0.1:18082/__managed-browser/evidence")
  ).json();
  expect(recovered.executions).toBe(1);
});

test("reviewed removal stays value-free and explains the recovery boundary", async ({
  page,
}) => {
  await page.goto("/__managed-browser/session?kind=remove");
  await expect(
    page.getByRole("heading", { name: "Remove service secret" }),
  ).toBeVisible();
  await expect(page.locator('input[name="secret_value"]')).toHaveCount(0);
  await expect(page.getByText("Never revealed.")).toBeVisible();
  await page.getByRole("button", { name: "Confirm with passkey" }).click();
  await expect(
    page.getByRole("heading", { name: "Ready to remove" }),
  ).toBeVisible();
  await expect(page.getByText("24-hour recovery window")).toBeVisible();
  await expect(page.getByText("Reveal", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Copy", { exact: true })).toHaveCount(0);
  await page
    .getByRole("button", { name: "Remove secret safely" })
    .click();
  await expect(
    page.getByRole("heading", { name: "Checking service" }),
  ).toBeVisible();
  await expect(page.getByRole("status")).toContainText("Removal accepted");
  await expect(
    page.getByRole("heading", { name: "Operation registered" }),
  ).toBeVisible({ timeout: 5_000 });
});
