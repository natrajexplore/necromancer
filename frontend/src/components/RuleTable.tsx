import { useState } from "react";

import type { Finding } from "../api/types";
import { GhostBadge } from "./GhostBadge";

export interface RuleRow {
  id: string; // rule id "<acl>#<seq>", or a finding's non-rule reference
  findings: Finding[];
}

export const ROW_HEIGHT = 72;
export const VIEWPORT_HEIGHT = 480;
const OVERSCAN = 6;

/** The slice of rows to render for a scroll position (exported for tests). */
export function visibleRange(scrollTop: number, total: number): [number, number] {
  const first = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN);
  const last = Math.min(total, Math.ceil((scrollTop + VIEWPORT_HEIGHT) / ROW_HEIGHT) + OVERSCAN);
  return [first, last];
}

/**
 * The rules in order, with their ghost badges. Only the rows in view are in the DOM, because an
 * ACL can hold thousands of rules. Choosing a row marks the rules it names in `related` (the
 * rules that shadow it, or that make it redundant).
 */
export function RuleTable({ rows, label }: { rows: RuleRow[]; label: string }) {
  const [scrollTop, setScrollTop] = useState(0);
  const [chosen, setChosen] = useState<string | null>(null);
  const related = new Set(
    rows.find((row) => row.id === chosen)?.findings.flatMap((finding) => finding.related) ?? [],
  );
  const [first, last] = visibleRange(scrollTop, rows.length);

  return (
    <div
      role="region"
      aria-label={label}
      tabIndex={0}
      onScroll={(event) => setScrollTop(event.currentTarget.scrollTop)}
      className="overflow-y-auto rounded-md border border-stone bg-crypt"
      style={{ height: Math.min(VIEWPORT_HEIGHT, rows.length * ROW_HEIGHT) || ROW_HEIGHT }}
    >
      <ul role="list" className="relative" style={{ height: rows.length * ROW_HEIGHT }}>
        {rows.slice(first, last).map((row, offset) => {
          const index = first + offset;
          const isChosen = row.id === chosen;
          const isRelated = related.has(row.id);
          return (
            <li
              key={row.id}
              aria-setsize={rows.length}
              aria-posinset={index + 1}
              data-related={isRelated}
              className={`absolute inset-x-0 border-b border-stone px-3 ${isRelated ? "bg-stone ring-2 ring-spectral ring-inset" : ""}`}
              style={{ top: index * ROW_HEIGHT, height: ROW_HEIGHT }}
            >
              <button
                type="button"
                aria-pressed={isChosen}
                onClick={() => setChosen(isChosen ? null : row.id)}
                className="flex h-full w-full flex-wrap content-center items-center gap-x-3 gap-y-1 text-left"
              >
                <span className="w-12 text-sm text-ash">{index + 1}</span>
                <code className="font-mono text-bone">{row.id}</code>
                {row.findings.length === 0 && <span className="text-sm text-ash">no findings</span>}
                {row.findings.slice(0, 2).map((finding) => (
                  <GhostBadge key={finding.id} finding={finding} />
                ))}
                {row.findings.length > 2 && (
                  <span className="text-sm text-ash">+{row.findings.length - 2} more</span>
                )}
                {isRelated && <span className="text-sm text-spectral">related to {chosen}</span>}
              </button>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
