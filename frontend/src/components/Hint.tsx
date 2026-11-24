import { useId, type ReactNode } from "react";

/**
 * A themed label with its plain-English meaning (haunted-ui steering: the theme never hides
 * information). The explanation shows on hover and on keyboard focus, and screen readers get it
 * as the label's description.
 */
export function Hint({ children, explain }: { children: ReactNode; explain: string }) {
  const id = useId();
  return (
    <span className="group/hint relative inline-flex">
      <span
        tabIndex={0}
        aria-describedby={id}
        className="cursor-help underline decoration-ash decoration-dotted underline-offset-4"
      >
        {children}
      </span>
      <span
        id={id}
        role="tooltip"
        className="invisible absolute top-full left-0 z-30 mt-2 w-72 rounded-md border border-stone bg-crypt px-3 py-2 text-left font-sans text-sm font-normal tracking-normal normal-case text-bone shadow-lg group-focus-within/hint:visible group-hover/hint:visible"
      >
        {explain}
      </span>
    </span>
  );
}
