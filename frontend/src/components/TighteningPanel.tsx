import type { LedgerEntry } from "../api/types";
import { stateOf, type Decision, type Decisions } from "./LiveLedger";

/**
 * Zero-trust tightening: each remediation is accepted or rejected on its own. The baseline
 * migration is like-for-like, so proposals only appear when the engine lists entries of class
 * "tightening". Decisions live in this browser session and update the ledger below at once.
 */
export function TighteningPanel({
  entries,
  decisions,
  onDecide,
}: {
  entries: LedgerEntry[];
  decisions: Decisions;
  onDecide: (id: string, decision: Decision | null) => void;
}) {
  const proposals = entries.filter((entry) => entry.class === "tightening");
  return (
    <section aria-labelledby="tightening-title" className="mt-8">
      <h3 id="tightening-title" className="font-display text-xl text-bone">
        Zero-trust tightening
      </h3>
      {proposals.length === 0 ? (
        <p className="mt-2 max-w-3xl text-ash">
          No tightening is proposed for this config. The baseline above is like-for-like: it keeps
          the source behaviour, and every intentional difference is in the ledger. Tightened
          output is a separate artifact with its own ledger and proof.
        </p>
      ) : (
        <ul className="mt-3 space-y-3">
          {proposals.map((entry) => {
            const state = stateOf(entry, decisions);
            return (
              <li key={entry.id} className="rounded-md border border-stone bg-crypt px-4 py-3">
                <p className="text-bone">
                  <code className="font-mono">{entry.id}</code>: {entry.reason}
                </p>
                <p className="mt-1 text-sm text-ash">
                  {entry.affected}. {entry.old_action} becomes {entry.new_action}. Status: {state}.
                </p>
                <div className="mt-2 flex gap-3">
                  <button
                    type="button"
                    aria-pressed={state === "accepted"}
                    onClick={() => onDecide(entry.id, state === "accepted" ? null : "accepted")}
                    className="rounded-md border border-spectral px-3 py-1.5 text-spectral aria-pressed:bg-spectral aria-pressed:text-void"
                  >
                    Accept {entry.id}
                  </button>
                  <button
                    type="button"
                    aria-pressed={state === "rejected"}
                    onClick={() => onDecide(entry.id, state === "rejected" ? null : "rejected")}
                    className="rounded-md border border-blood px-3 py-1.5 text-blood aria-pressed:bg-blood aria-pressed:text-void"
                  >
                    Reject {entry.id}
                  </button>
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
