import { useId, useState } from "react";

import type { LedgerDecision, LedgerEntry } from "../api/types";

/**
 * The pending ledger entries of the artifact being judged, each to accept or reject. A decision
 * needs a named approver and a reason. Decisions live in this session's memory and travel as the
 * sidecar of the next gate run: the engine stores nothing.
 */
export function LedgerDecisions({
  artifact,
  entries,
  decisions,
  approver,
  onApprover,
  onDecide,
}: {
  artifact: string; // "baseline" or "tightened", for the heading
  entries: LedgerEntry[];
  decisions: Record<string, LedgerDecision>;
  approver: string;
  onApprover: (name: string) => void;
  onDecide: (id: string, decision: LedgerDecision | null) => void;
}) {
  const approverId = useId();
  const [reasons, setReasons] = useState<Record<string, string>>({});
  const pending = entries.filter((entry) => entry.approval === "pending");
  const undecided = pending.filter((entry) => decisions[entry.id] === undefined).length;
  return (
    <section className="mt-6" aria-labelledby="ledger-decisions-title">
      <h3 id="ledger-decisions-title" className="text-xl font-semibold">
        Pending ledger entries ({artifact} artifact)
      </h3>
      {pending.length === 0 ? (
        <p className="mt-2 text-ash">No ledger entry of the {artifact} artifact is pending.</p>
      ) : (
        <>
          <p className="mt-2 max-w-3xl text-ash">
            Each entry is a documented difference from the source. A named person accepts or
            rejects it and gives a reason. The decisions are sent with the next run of the gates and
            are not stored. {undecided} of {pending.length} still need a decision.
          </p>
          <div className="mt-3">
            <label htmlFor={approverId} className="block text-sm text-ash">
              Approver name (required)
            </label>
            <input
              id={approverId}
              type="text"
              value={approver}
              onChange={(event) => onApprover(event.target.value)}
              autoComplete="off"
              className="mt-1 w-64 rounded-md border border-stone bg-void px-3 py-2 text-bone"
            />
          </div>
          <ul className="mt-3 space-y-3">
            {pending.map((entry) => (
              <EntryRow
                key={entry.id}
                entry={entry}
                decision={decisions[entry.id] ?? null}
                reason={reasons[entry.id] ?? ""}
                approver={approver}
                onReason={(text) => setReasons((current) => ({ ...current, [entry.id]: text }))}
                onDecide={onDecide}
              />
            ))}
          </ul>
        </>
      )}
    </section>
  );
}

function EntryRow({
  entry,
  decision,
  reason,
  approver,
  onReason,
  onDecide,
}: {
  entry: LedgerEntry;
  decision: LedgerDecision | null;
  reason: string;
  approver: string;
  onReason: (text: string) => void;
  onDecide: (id: string, decision: LedgerDecision | null) => void;
}) {
  const reasonId = useId();
  const ready = approver.trim() !== "" && reason.trim() !== "";
  const choose = (approval: LedgerDecision["approval"]) => {
    if (decision?.approval === approval) {
      onDecide(entry.id, null);
      return;
    }
    onDecide(entry.id, {
      approval,
      approver: approver.trim(),
      decided_at: new Date().toISOString(),
      reason: reason.trim(),
    });
  };
  return (
    <li className="rounded-md border border-stone bg-crypt px-4 py-3">
      <p className="text-bone">
        <code className="font-mono">{entry.id}</code>, {entry.class.replace(/-/g, " ")}, in{" "}
        <code className="font-mono">{entry.context}</code>: {entry.old_action} becomes {entry.new_action}.
        {decision ? ` Your decision: ${decision.approval} by ${decision.approver}.` : " Pending."}
      </p>
      <p className="mt-1 text-sm text-ash">{entry.reason}</p>
      <p className="mt-1 text-sm text-ash">Affects: {entry.affected}</p>
      <div className="mt-2">
        <label htmlFor={reasonId} className="block text-sm text-ash">
          Reason for {entry.id} (required)
        </label>
        <input
          id={reasonId}
          type="text"
          value={reason}
          onChange={(event) => onReason(event.target.value)}
          autoComplete="off"
          className="mt-1 w-full max-w-xl rounded-md border border-stone bg-void px-3 py-2 text-bone"
        />
      </div>
      <div className="mt-2 flex gap-3">
        <button
          type="button"
          aria-pressed={decision?.approval === "accepted"}
          disabled={!ready && decision === null}
          onClick={() => choose("accepted")}
          className="rounded-md border border-spectral px-3 py-1.5 text-spectral aria-pressed:bg-spectral aria-pressed:text-void disabled:opacity-50"
        >
          Accept {entry.id}
        </button>
        <button
          type="button"
          aria-pressed={decision?.approval === "rejected"}
          disabled={!ready && decision === null}
          onClick={() => choose("rejected")}
          className="rounded-md border border-blood px-3 py-1.5 text-blood aria-pressed:bg-blood aria-pressed:text-void disabled:opacity-50"
        >
          Reject {entry.id}
        </button>
      </div>
    </li>
  );
}
