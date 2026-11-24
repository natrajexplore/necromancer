import "@testing-library/jest-dom/vitest";

import { cleanup } from "@testing-library/react";
import { afterEach, beforeEach, vi } from "vitest";

/** jsdom has no matchMedia. Tests flip `reducedMotion.matches` and call `reducedMotion.emit()`. */
export const reducedMotion = {
  matches: false,
  listeners: new Set<() => void>(),
  emit() {
    for (const listener of this.listeners) listener();
  },
};

beforeEach(() => {
  reducedMotion.matches = false;
  reducedMotion.listeners.clear();
  vi.stubGlobal(
    "matchMedia",
    vi.fn((query: string) => ({
      get matches() {
        return query === "(prefers-reduced-motion: reduce)" && reducedMotion.matches;
      },
      media: query,
      onchange: null,
      addEventListener: (_type: string, listener: () => void) => reducedMotion.listeners.add(listener),
      removeEventListener: (_type: string, listener: () => void) =>
        reducedMotion.listeners.delete(listener),
      addListener: vi.fn(),
      removeListener: vi.fn(),
      dispatchEvent: vi.fn(),
    })),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});
