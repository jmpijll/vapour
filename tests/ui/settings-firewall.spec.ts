import { test, expect } from "@playwright/test";

test("Settings theme and capture preferences persist in preview", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Settings", exact: true }).click();

  const dark = page.getByRole("button", { name: "Dark", exact: true });
  const light = page.getByRole("button", { name: "Light", exact: true });
  await dark.click();
  await expect(dark).toHaveAttribute("aria-pressed", "true");
  await expect(light).toHaveAttribute("aria-pressed", "false");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");

  const colorIcons = page.getByRole("switch", { name: "Color app icons", exact: true });
  const unavailable = page.getByRole("switch", { name: "Show unavailable capture interfaces", exact: true });
  await colorIcons.click();
  await unavailable.click();
  await expect(colorIcons).toHaveAttribute("aria-checked", "true");
  await expect(unavailable).toHaveAttribute("aria-checked", "true");
  await expect(page.locator("html")).toHaveAttribute("data-icons", "color");

  await page.reload();
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  await expect(dark).toHaveAttribute("aria-pressed", "true");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await expect(colorIcons).toHaveAttribute("aria-checked", "true");
  await expect(unavailable).toHaveAttribute("aria-checked", "true");
});

test("Preview app block is presented in Firewall and can be removed", async ({ page }) => {
  const chromePath = String.raw`C:\Program Files\Google\Chrome\Application\chrome.exe`;

  await page.goto("/");
  await expect(page.locator("main.preview")).toBeVisible();
  await page.locator(".process-row").filter({ hasText: "Chrome" }).click();
  await page.getByRole("button", { name: "Block app", exact: true }).click();
  await page.getByRole("button", { name: "Firewall", exact: true }).click();

  await expect(page.getByRole("heading", { name: "Blocks", exact: true })).toBeVisible();
  await expect(page.getByText("chrome.exe", { exact: true })).toBeVisible();
  await expect(page.getByText("All outgoing traffic", { exact: true })).toBeVisible();
  await expect(page.getByText(chromePath, { exact: true })).toBeHidden();

  await page.getByRole("button", { name: "Advanced mode", exact: true }).click();
  await expect(page.getByText(chromePath, { exact: true })).toBeVisible();
  const unblock = page.getByRole("button", { name: `Unblock ${chromePath}`, exact: true });
  await unblock.click();
  await expect(page.getByText("No Vapour blocks", { exact: true })).toBeVisible();
});
