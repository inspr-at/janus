import { expect, test } from "@playwright/test";

test("Flow reviewer signs out through the browser with a same-origin form", async ({ page, context }) => {
  const landing = await page.goto("/__managed-browser/flow-session");
  await expect(page.locator("main[data-inspr-flow-reviewer]")).toBeVisible();
  const origin = new URL(page.url()).origin;
  const logout = page.waitForResponse(response =>
    new URL(response.url()).pathname === "/janus/logout" &&
    response.request().method() === "POST",
  );
  // Do not set request headers: Chromium must supply the real form Origin.
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  const response = await logout;
  expect(response.status()).toBe(302);
  expect(await response.request().headerValue("origin")).toBe(origin);
  expect(await landing.headerValue("referrer-policy")).toBe("origin");
  await expect(page.getByRole("heading", { name: "Open Janus" })).toBeVisible();
  await expect(page.locator("main[data-inspr-flow-reviewer]")).toHaveCount(0);
  const cookies = await context.cookies();
  expect(cookies.some(cookie => cookie.name.includes("session"))).toBe(false);
  // A reload must stay signed out instead of restoring the restricted view.
  await page.reload();
  await expect(page.getByRole("heading", { name: "Open Janus" })).toBeVisible();
});
