import { useEffect, useRef, type RefObject } from "react";

/**
 * Where keyboard and screen-reader users land after a step finishes. A button that was pressed
 * is often disabled or replaced while the engine works, and focus would fall back to the page.
 * This returns a ref for the element that should take focus (give it `tabIndex={-1}`), and moves
 * focus there when `value` changes to something truthy. The first render never moves focus.
 */
export function useFocusOnChange<T extends HTMLElement>(value: unknown): RefObject<T> {
  const ref = useRef<T>(null);
  const first = useRef(true);
  useEffect(() => {
    if (first.current) {
      first.current = false;
      return;
    }
    if (value) ref.current?.focus();
  }, [value]);
  return ref;
}
