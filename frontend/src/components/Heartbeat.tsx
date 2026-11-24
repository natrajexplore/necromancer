export type BeatState = "idle" | "checking" | "alive" | "dead";

// One normalised path in a 0..100 by 0..30 box: flat, then a pulse, then flat.
const PULSE = "M0 15 H30 L35 15 L40 3 L47 27 L52 9 L56 15 H100";
const FLAT = "M0 15 H100";

const LABEL: Record<BeatState, string> = {
  idle: "No proof run yet",
  checking: "Checking flows",
  alive: "Proof passed: the heartbeat is steady",
  dead: "Proof failed: the heartbeat stopped",
};

/**
 * The heartbeat line. A passing proof draws the pulse in green. A failing proof draws a flat
 * red line. The state is also written out in words, so colour is never the only signal.
 */
export function Heartbeat({ state }: { state: BeatState }) {
  const color = state === "dead" ? "#e5484d" : state === "idle" ? "#b3ad9f" : "#7cf5b0";
  return (
    <figure className="m-0">
      <svg viewBox="0 0 100 30" className="h-16 w-full max-w-xl" role="img" aria-label={LABEL[state]}>
        <path
          d={state === "alive" || state === "checking" ? PULSE : FLAT}
          pathLength={1}
          fill="none"
          stroke={color}
          strokeWidth="1.5"
          strokeLinejoin="round"
          className={state === "alive" || state === "checking" ? "beat" : ""}
          key={state}
        />
      </svg>
      <figcaption className="mt-1 text-bone">{LABEL[state]}</figcaption>
    </figure>
  );
}
