/// <reference types="vitest/config" />
import { fileURLToPath } from "node:url";

import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { configDefaults } from "vitest/config";
import { defineConfig } from "vite";

// The repository root: the bundled sample configs are imported from ../samples with `?raw`.
const repoRoot = fileURLToPath(new URL("..", import.meta.url));
// The necro API (backend, `uv run python -m uvicorn api.main:app --port 8000`).
const apiTarget = process.env.NECRO_API_PROXY ?? "http://localhost:8000";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    strictPort: true,
    fs: { allow: [repoRoot] },
    proxy: {
      "/v1": { target: apiTarget, changeOrigin: true },
      "/healthz": { target: apiTarget, changeOrigin: true },
    },
  },
  build: {
    sourcemap: false,
    // Fonts and images stay separate files, so a strict CSP needs no data: URLs.
    assetsInlineLimit: 0,
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    restoreMocks: true,
    // Playwright specs under e2e/ run with `npm run e2e`, not in vitest.
    exclude: [...configDefaults.exclude, "e2e/**"],
    css: false,
    // jsdom gives modules a non-file import.meta.url, so tests that read repo files get the root here.
    env: { NECRO_REPO_ROOT: repoRoot },
  },
});
