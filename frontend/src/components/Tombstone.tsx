import type { ReactNode } from "react";

/** The headstone outline, drawn by hand for this project (no third-party artwork). */
function Headstone({ selected }: { selected: boolean }) {
  return (
    <svg
      aria-hidden="true"
      focusable="false"
      viewBox="0 0 160 200"
      preserveAspectRatio="none"
      className="absolute inset-0 h-full w-full"
    >
      <path
        d="M14 196 V74 C14 30 42 8 80 8 C118 8 146 30 146 74 V196 Z"
        fill="var(--color-stone)"
        stroke={selected ? "var(--color-spectral)" : "var(--color-ash)"}
        strokeOpacity={selected ? 1 : 0.35}
        strokeWidth={selected ? 3 : 1.5}
        vectorEffect="non-scaling-stroke"
      />
      <path d="M80 30 V58 M68 40 H92" stroke="var(--color-ash)" strokeOpacity="0.5" strokeWidth="2" />
      <path d="M2 197 H158" stroke="var(--color-ash)" strokeOpacity="0.25" strokeWidth="2" />
    </svg>
  );
}

export interface TombstoneProps {
  title: string;
  lines: ReactNode[];
  /** The full plain-English description read by screen readers instead of the visible lines. */
  label: string;
  selected: boolean;
  onSelect: () => void;
}

/** One config in the graveyard. A real button: clickable, focusable, Enter/Space to open. */
export function Tombstone({ title, lines, label, selected, onSelect }: TombstoneProps) {
  return (
    <button
      type="button"
      onClick={onSelect}
      aria-pressed={selected}
      aria-label={label}
      className="relative flex h-64 w-full cursor-pointer flex-col items-center justify-end text-center transition-transform duration-200 hover:-translate-y-1"
    >
      <Headstone selected={selected} />
      <span className="relative z-10 flex flex-col items-center gap-1 px-7 pb-7">
        <span className="font-display text-xl leading-tight break-all text-bone">{title}</span>
        {lines.map((line, index) => (
          <span key={index} className="text-sm text-ash">
            {line}
          </span>
        ))}
      </span>
    </button>
  );
}
