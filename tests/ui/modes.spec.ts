import { test, expect } from "@playwright/test";

test.beforeEach(async ({page}) => {
  page.on("pageerror", error => { throw error; });
  page.on("console", message => {
    if (message.type() === "error") throw new Error(message.text());
  });
});

test.afterEach(async ({page}, testInfo) => {
  await expect(page).toHaveTitle("Vapour");
  await expect(page.locator("main")).toBeVisible();
  await expect(page.locator("vite-error-overlay")).toHaveCount(0);
  await page.screenshot({path: testInfo.outputPath("final-state.png")});
});

test("Interface menu opens at the last option with ArrowUp and returns focus on Escape", async ({page}) => {
  await page.goto("/");
  const trigger = page.getByRole("button", {name: "Network interface", exact: true});
  await trigger.focus();
  await page.keyboard.press("ArrowUp");
  const options = page.getByRole("menuitemradio");
  await expect(options.last()).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(trigger).toBeFocused();
  await expect(trigger).toHaveAttribute("aria-expanded", "false");
});

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
    await page.getByText("Routes · 1", {exact:true}).click();
    await expect(page.getByText("0.0.0.0/0 → 192.0.2.1", {exact:true})).toBeVisible();
    await expect(page.getByText("Default · Metric 0", {exact:true})).toBeVisible();
    await page.getByText("Counters", {exact:true}).click();
    await expect(page.getByText("450000000", {exact:true})).toBeVisible();
    const wifi = page.locator("details").filter({has: page.locator("summary").filter({hasText: /^Wi-Fi$/})});
    await wifi.locator("summary").click();
    await expect(wifi.getByText("Unavailable", {exact:true})).toBeVisible();
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
