import type { Finding, Severity } from "../api/types";
import { Hint } from "./Hint";

const SEVERITY_STYLE: Record<Severity, string> = {
  critical: "border-blood text-blood",
  high: "border-blood text-blood",
  medium: "border-candle text-candle",
  low: "border-ash text-ash",
};

/** The plain name of each finding type, shown next to the themed label. */
export function typeName(type: string): string {
  return type.replace(/-/g, " ");
}

/** A ghost: the themed label with its plain meaning, the plain type and the severity. */
export function GhostBadge({ finding }: { finding: Finding }) {
  return (
    <span
      className={`inline-flex items-center gap-2 rounded-full border px-2.5 py-0.5 text-sm ${SEVERITY_STYLE[finding.severity]}`}
      data-severity={finding.severity}
    >
      <span aria-hidden="true">👻</span>
      <Hint explain={`${typeName(finding.type)}: ${finding.explanation}`}>{finding.label}</Hint>
      <span className="text-bone">
        {typeName(finding.type)}, {finding.severity}, {finding.id}
      </span>
    </span>
  );
}
