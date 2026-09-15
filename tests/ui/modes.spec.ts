import { test, expect } from "@playwright/test";

test("Destination tags stay compact and unknown destinations do not gain labels", async ({page}) => {
  await page.goto("/");
  await page.locator(".process-row").filter({hasText: "Chrome"}).click();
  const endpoint = page.locator(".endpoint").filter({hasText: "video.google.com"});
  await expect(endpoint.getByText("Google LLC", {exact: true})).toBeVisible();
  await expect(endpoint.getByText("US", {exact: true})).toBeVisible();
  await expect(endpoint.getByText("AS15169", {exact: true})).toBeHidden();
  await page.getByRole("button", {name: "Advanced mode", exact: true}).click();
  await expect(endpoint.getByText("AS15169", {exact: true})).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.locator(".back-button").click();
  await page.locator(".process-row").filter({hasText: "Discord"}).click();
  await expect(page.locator(".endpoint")).toHaveCount(1);
  await expect(page.locator(".destination-tag")).toHaveCount(0);
});

for (const theme of ["light", "dark"]) {
  test(`Basic/Advanced persists and changes detail visibility in ${theme}`, async ({page}) => {
    await page.addInitScript(theme => {
      if (!localStorage.getItem("vapour.appearance.v2")) localStorage.setItem("vapour.appearance.v2", JSON.stringify({theme, advanced: false}));
    }, theme);
    await page.goto("/");
    const mode = page.getByRole("button", {name: "Advanced mode", exact: true});
    await expect(mode).toHaveAttribute("aria-pressed", "false");
    await page.getByRole("button", {name: "Interface statistics", exact: true}).click();
    await expect(page.locator(".adapter-details")).toHaveCount(0);
    await mode.click();
    await page.getByText("Driver", {exact:true}).click();
    await expect(page.getByText("Example adapter vendor", {exact:true})).toBeVisible();
    await expect(page.getByText("1.2.3.4", {exact:true})).toBeVisible();
    await page.getByText("IP configuration", {exact:true}).click();
    await expect(page.getByText("192.0.2.10/24", {exact:true})).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.reload();
    await expect(mode).toHaveAttribute("aria-pressed", "true");
    await page.getByRole("button", {name:"Speedtest",exact:true}).click();
    await expect(page.getByText("Measurement",{exact:true})).toBeVisible();
    await mode.click();
    await expect(page.getByText("Measurement",{exact:true})).toBeHidden();
    await page.getByRole("button",{name:"Capture",exact:true}).click();
    await expect(page.getByText("Diagnostics",{exact:true})).toBeHidden();
    await mode.focus(); await page.keyboard.press("Space");
    await expect(page.getByText("Diagnostics",{exact:true})).toBeVisible();
  });
}

test("Threat protection exposes an accessible switch without Basic source details",async({page})=>{
  await page.goto("/");
  await page.getByRole("button",{name:"Firewall",exact:true}).click();
  const toggle=page.getByRole("switch",{name:"Threat protection",exact:true});
  await expect(toggle).toHaveAttribute("aria-checked","false");
  await expect(page.getByText(/Feodo Tracker/)).toBeHidden();
  await toggle.focus();await page.keyboard.press("Space");
  await expect(toggle).toHaveAttribute("aria-checked","true");
  await page.getByRole("button",{name:"Advanced mode",exact:true}).click();
  await expect(page.getByText(/Feodo Tracker/)).toBeVisible();
  await expect(toggle).toHaveAttribute("aria-checked","true");
});
