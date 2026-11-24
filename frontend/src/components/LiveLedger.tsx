import type { LedgerEntry } from "../api/types";
import { Hint } from "./Hint";

export type Decision = "accepted" | "rejected";
export type Decisions = Record<string, Decision>;

/** The state an entry shows: the person's decision this session, else what the engine says. */
export function stateOf(entry: LedgerEntry, decisions: Decisions): LedgerEntry["approval"] {
  return decisions[entry.id] ?? entry.approval;
}

export function tally(entries: LedgerEntry[], decisions: Decisions) {
  const counts = { pending: 0, accepted: 0, rejected: 0 };
  for (const entry of entries) counts[stateOf(entry, decisions)] += 1;
  return counts;
}

/**
 * The exorcism ledger: every intentional, documented difference from the source. It updates as
 * remediations are accepted or rejected in the tightening panel.
 */
export function LiveLedger({ entries, decisions }: { entries: LedgerEntry[]; decisions: Decisions }) {
  const counts = tally(entries, decisions);
  return (
    <section aria-labelledby="ledger-title" className="mt-8">
      <h3 id="ledger-title" className="font-display text-xl text-bone">
        <Hint explain="Exorcism ledger: the list of every place where the new config intentionally behaves differently from the old one, with the reason.">
          Exorcism ledger
        </Hint>
      </h3>
      <p className="mt-2 text-bone" aria-live="polite" role="status">
        {entries.length} {entries.length === 1 ? "entry" : "entries"}: {counts.pending} pending,{" "}
        {counts.accepted} accepted, {counts.rejected} rejected
      </p>
      {entries.length === 0 ? (
        <p className="mt-2 text-ash">No intentional differences: the baseline behaves like the source.</p>
      ) : (
        <ul className="mt-3 space-y-3">
          {entries.map((entry) => (
            <li key={entry.id} className="rounded-md border border-stone bg-crypt px-4 py-3">
              <p className="text-bone">
                <code className="font-mono">{entry.id}</code>, {entry.class.replace(/-/g, " ")}, in{" "}
                <code className="font-mono">{entry.context}</code>:{" "}
                <span className={entry.old_action === entry.new_action ? "text-bone" : "text-candle"}>
                  {entry.old_action} becomes {entry.new_action}
                </span>
                . Status: {stateOf(entry, decisions)}
                {entry.informational ? " (informational)" : ""}.
              </p>
              <p className="mt-1 text-ash">{entry.reason}</p>
              <p className="mt-1 text-sm text-ash">Affects: {entry.affected}</p>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
