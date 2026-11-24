import { useSyncExternalStore } from "react";

/**
 * Reduced-motion utility. CSS turns every animation off under `prefers-reduced-motion`
 * (styles.css); JavaScript-driven motion (the resurrection rise) asks this hook instead.
 */
export const REDUCED_MOTION_QUERY = "(prefers-reduced-motion: reduce)";

function query(): MediaQueryList | null {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") return null;
  return window.matchMedia(REDUCED_MOTION_QUERY);
}

export function prefersReducedMotion(): boolean {
  return query()?.matches ?? false;
}

function subscribe(onChange: () => void): () => void {
  const list = query();
  if (!list) return () => undefined;
  list.addEventListener("change", onChange);
  return () => list.removeEventListener("change", onChange);
}

/** True while the user asks for reduced motion; re-renders when the setting changes. */
export function usePrefersReducedMotion(): boolean {
  return useSyncExternalStore(subscribe, prefersReducedMotion, () => false);
}

/** The duration to animate for: none at all when motion is reduced. */
export function motionSeconds(seconds: number, reduced: boolean): number {
  return reduced ? 0 : seconds;
}
