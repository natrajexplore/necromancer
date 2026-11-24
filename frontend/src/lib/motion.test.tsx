import { act, renderHook } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { reducedMotion } from "../test/setup";
import { motionSeconds, prefersReducedMotion, usePrefersReducedMotion } from "./motion";

describe("reduced motion", () => {
  it("reads the user's setting", () => {
    expect(prefersReducedMotion()).toBe(false);
    reducedMotion.matches = true;
    expect(prefersReducedMotion()).toBe(true);
  });

  it("re-renders when the setting changes", () => {
    const { result, unmount } = renderHook(() => usePrefersReducedMotion());
    expect(result.current).toBe(false);
    act(() => {
      reducedMotion.matches = true;
      reducedMotion.emit();
    });
    expect(result.current).toBe(true);
    unmount();
    expect(reducedMotion.listeners.size).toBe(0);
  });

  it("drops every animation duration to zero when motion is reduced", () => {
    expect(motionSeconds(2.5, false)).toBe(2.5);
    expect(motionSeconds(2.5, true)).toBe(0);
  });
});
