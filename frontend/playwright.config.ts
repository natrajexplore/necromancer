import { defineConfig, devices } from "@playwright/test";

/**
 * Smoke tests against the real engine and the real UI (graveyard-ui task 9). Playwright starts both:
 * the API from backend/ (`uv run python -m uvicorn api.main:app --port 8000`) and the Vite dev
 * server, which proxies /v1 to it. Chromium only. Run `npm run e2e:install` once, then `npm run e2e`.
 *
 * The API allows 10 POSTs a minute per client. The ritual makes more than that, so the engine is
 * started with NECRO_RATE_PER_MINUTE raised. It is read by api/main.py and only lifts the limit
 * for this local run.
 */
const env = (extra: Record<string, string>): Record<string, string> => ({
  ...Object.fromEntries(Object.entries(process.env).filter((entry): entry is [string, string] => entry[1] !== undefined)),
  ...extra,
});

export default defineConfig({
  testDir: "e2e",
  testMatch: "**/*.spec.ts",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 90_000,
  expect: { timeout: 20_000 },
  reporter: [["list"]],
  outputDir: "test-results",
  use: {
    baseURL: "http://localhost:5173",
    // No animation waits: the rise and fog are covered by the reduced-motion test and by vitest.
    reducedMotion: "reduce",
    trace: "retain-on-failure",
    acceptDownloads: true,
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"], viewport: { width: 1280, height: 900 } } }],
  webServer: [
    {
      command: "uv run python -m uvicorn api.main:app --port 8000",
      cwd: "../backend",
      url: "http://127.0.0.1:8000/healthz",
      timeout: 120_000,
      reuseExistingServer: !process.env.CI,
      env: env({ UV_PYTHON_PREFERENCE: "only-system", NECRO_RATE_PER_MINUTE: "10000" }),
    },
    {
      command: "npm run dev",
      url: "http://localhost:5173",
      timeout: 60_000,
      reuseExistingServer: !process.env.CI,
      env: env({ NECRO_API_PROXY: "http://127.0.0.1:8000" }),
    },
  ],
});
