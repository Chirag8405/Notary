import { defineConfig } from "@playwright/test";
import { existsSync } from "node:fs";
import { delimiter, join } from "node:path";

/**
 * End-to-end smoke tests (`pnpm e2e`). They are NOT part of the default gate (`turbo run lint
 * typecheck test build`): they start the real server and the real web app and drive a real
 * browser. No browser is downloaded: the tests use one that is already installed.
 *
 * Browser: `E2E_BROWSER_PATH` if set, else the first Chromium-family browser on the PATH.
 * Ports: the server must be on :8000 and the web app on :3000, because the server only allows
 * the origin http://localhost:3000. A server that is already running there is reused.
 */
const CANDIDATES = [
  "chromium",
  "chromium-browser",
  "google-chrome-stable",
  "google-chrome",
  "brave",
  "brave-browser",
];

function findBrowser(): string {
  const fromEnv = process.env.E2E_BROWSER_PATH;
  if (fromEnv !== undefined && fromEnv !== "") return fromEnv;
  const dirs = (process.env.PATH ?? "").split(delimiter);
  for (const name of CANDIDATES) {
    for (const dir of dirs) {
      const path = join(dir, name);
      if (existsSync(path)) return path;
    }
  }
  throw new Error(
    `No Chromium-family browser found on the PATH (looked for ${CANDIDATES.join(", ")}). ` +
      "Set E2E_BROWSER_PATH to one.",
  );
}

export default defineConfig({
  testDir: "e2e",
  testMatch: "**/*.e2e.ts",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 60_000,
  expect: { timeout: 15_000 },
  reporter: [["list"]],
  use: {
    baseURL: "http://localhost:3000",
    headless: true,
    launchOptions: { executablePath: findBrowser() },
  },
  webServer: [
    {
      command:
        "uv run --no-sync uvicorn notary_server.app:app --ws websockets --host 127.0.0.1 --port 8000",
      cwd: "../server",
      env: { NOTARY_ANCHOR_DB: ":memory:" },
      url: "http://127.0.0.1:8000/health",
      reuseExistingServer: true,
      timeout: 60_000,
    },
    {
      command: "pnpm dev",
      url: "http://localhost:3000/playground",
      reuseExistingServer: true,
      timeout: 120_000,
    },
  ],
});
