import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "./tests/ui",
  use: { baseURL: "http://127.0.0.1:1423", channel: "msedge", viewport: {width: 360, height: 760} },
  webServer: { command: "pnpm dev --host 127.0.0.1 --port 1423 --strictPort", url: "http://127.0.0.1:1423", reuseExistingServer: false },
});
