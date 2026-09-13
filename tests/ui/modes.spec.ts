import { test, expect } from "@playwright/test";
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
