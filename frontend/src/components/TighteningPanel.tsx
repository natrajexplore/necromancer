import { useId, type RefObject } from "react";

import type { Proposal, TightenedResult } from "../api/types";
import { plural } from "../lib/format";
import {
  REMEDIATION_LABEL,
  type FindingDecision,
  type FindingDecisions,
  type NetworkText,
} from "../lib/tightening";
import { CounterexampleCard } from "./CounterexampleCard";
import { LiveLedger } from "./LiveLedger";

/**
 * Zero-trust tightening. The baseline above is like-for-like. Each proposal here comes from one
 * autopsy finding and is accepted or rejected on its own. "Prove the tightened artifact" sends the
 * decisions to the engine, which emits a separate PAN-OS config with its own ledger and proof. The
 * baseline never changes.
 */
export function TighteningPanel({
  proposals,
  decisions,
  networks,
  approver,
  onDecide,
  onNetworks,
  onApprover,
  onProve,
  proving,
  problem,
  tightened,
  summaryRef,
}: {
  proposals: Proposal[];
  decisions: FindingDecisions;
  networks: NetworkText;
  approver: string;
  onDecide: (findingId: string, decision: FindingDecision | null) => void;
  onNetworks: (findingId: string, text: string) => void;
  onApprover: (name: string) => void;
  onProve: () => void;
  proving: boolean;
  problem: string | null;
  tightened: TightenedResult | null;
  summaryRef?: RefObject<HTMLHeadingElement>;
}) {
  const approverId = useId();
  const accepted = proposals.filter((p) => decisions[p.finding_id] === "accepted").length;
  const rejected = proposals.filter((p) => decisions[p.finding_id] === "rejected").length;
  return (
    <section aria-labelledby="tightening-title" className="mt-8">
      <h3 id="tightening-title" className="font-display text-xl text-bone">
        Zero-trust tightening
      </h3>
      <p className="mt-2 max-w-3xl text-ash">
        Tightening is a separate change. It only removes access, and it never touches the baseline
        above. Accepted proposals go into a second PAN-OS config with its own ledger and proof.
      </p>
      {proposals.length === 0 ? (
        <p className="mt-2 max-w-3xl text-ash">No tightening is proposed for this config.</p>
      ) : (
        <>
          <ul className="mt-3 space-y-3">
            {proposals.map((p) => (
              <ProposalRow
                key={p.finding_id}
                proposal={p}
                decision={decisions[p.finding_id] ?? null}
                networkText={networks[p.finding_id] ?? ""}
                onDecide={onDecide}
                onNetworks={onNetworks}
              />
            ))}
          </ul>
          <div className="mt-4 flex flex-wrap items-end gap-4">
            <div>
              <label htmlFor={approverId} className="block text-sm text-ash">
                Approver (a named person records each decision)
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
            <button
              type="button"
              onClick={onProve}
              disabled={proving}
              className="rounded-md bg-spectral px-5 py-2.5 font-semibold text-void disabled:opacity-60"
            >
              {proving ? "Proving the tightened artifact…" : "Prove the tightened artifact"}
            </button>
            <p className="text-sm text-ash" role="status">
              {accepted} accepted, {rejected} rejected, {proposals.length - accepted - rejected}{" "}
              undecided
            </p>
          </div>
          {problem !== null && (
            <p role="alert" className="mt-3 text-candle">
              {problem}
            </p>
          )}
        </>
      )}
      {tightened && <TightenedSummary tightened={tightened} headingRef={summaryRef} />}
    </section>
  );
}

function ProposalRow({
  proposal: p,
  decision,
  networkText,
  onDecide,
  onNetworks,
}: {
  proposal: Proposal;
  decision: FindingDecision | null;
  networkText: string;
  onDecide: (findingId: string, decision: FindingDecision | null) => void;
  onNetworks: (findingId: string, text: string) => void;
}) {
  const networkId = useId();
  return (
    <li className="rounded-md border border-stone bg-crypt px-4 py-3">
      <p className="text-bone">
        <code className="font-mono">{p.rule_ref}</code>: {REMEDIATION_LABEL[p.kind]}{" "}
        <span className="text-sm text-ash">
          ({p.finding_type.replace(/-/g, " ")}, {p.severity}, finding {p.finding_id})
        </span>
      </p>
      <p className="mt-1 text-sm text-ash">{p.summary}</p>
      {p.needs_networks && (
        <div className="mt-2">
          <label htmlFor={networkId} className="block text-sm text-ash">
            Confirmed networks for {p.rule_ref} (comma separated, for example an object group's
            members)
          </label>
          <input
            id={networkId}
            type="text"
            value={networkText}
            onChange={(event) => onNetworks(p.finding_id, event.target.value)}
            autoComplete="off"
            spellCheck={false}
            className="mt-1 w-full max-w-md rounded-md border border-stone bg-void px-3 py-2 font-mono text-bone"
          />
        </div>
      )}
      <div className="mt-2 flex gap-3">
        <button
          type="button"
          aria-pressed={decision === "accepted"}
          onClick={() => onDecide(p.finding_id, decision === "accepted" ? null : "accepted")}
          className="rounded-md border border-spectral px-3 py-1.5 text-spectral aria-pressed:bg-spectral aria-pressed:text-void"
        >
          Accept {p.finding_id}
        </button>
        <button
          type="button"
          aria-pressed={decision === "rejected"}
          onClick={() => onDecide(p.finding_id, decision === "rejected" ? null : "rejected")}
          className="rounded-md border border-blood px-3 py-1.5 text-blood aria-pressed:bg-blood aria-pressed:text-void"
        >
          Reject {p.finding_id}
        </button>
      </div>
    </li>
  );
}

/** The proof and ledger of the tightened artifact. Always shown with its ledger (governance R1). */
export function TightenedSummary({
  tightened,
  headingRef,
}: {
  tightened: TightenedResult;
  headingRef?: RefObject<HTMLHeadingElement> | undefined;
}) {
  const proof = tightened.proof;
  const example = proof?.counterexample ?? proof?.golden.failures[0] ?? null;
  return (
    <div className="mt-6" data-testid="tightened-summary">
      <h4 ref={headingRef} tabIndex={-1} className="font-display text-lg text-bone">
        Tightened artifact (separate change)
      </h4>
      <p className="mt-1 text-bone">
        {plural(tightened.config_lines, "line")} of PAN-OS config,{" "}
        {plural(tightened.applied.length, "remediation")} applied. Proof of Life:{" "}
        <strong className={tightened.passed ? "text-spectral" : "text-blood"}>
          {proof === null ? "could not run" : tightened.passed ? "passed" : "failed"}
        </strong>
        {proof &&
          `, ${plural(proof.budget, "example")} per context, seed ${proof.seed}, golden flows ${proof.golden.passed} of ${proof.golden.total}`}
        .
      </p>
      {tightened.proof_error && <p className="mt-1 text-candle">{tightened.proof_error}</p>}
      {tightened.validation_errors.map((error) => (
        <p key={error} className="mt-1 text-blood">
          Static check failed: {error}
        </p>
      ))}
      {tightened.skipped.map((s) => (
        <p key={s.finding_id} className="mt-1 text-candle">
          Not applied, {s.finding_id}: {s.reason}.
        </p>
      ))}
      {tightened.notes.map((note) => (
        <p key={note} className="mt-1 text-ash">
          {note}
        </p>
      ))}
      {example && (
        <div className="mt-4">
          <CounterexampleCard example={example} />
        </div>
      )}
      <LiveLedger
        entries={tightened.ledger}
        decisions={{}}
        title="Tightened ledger"
        idPrefix="tightened-ledger"
      />
    </div>
  );
}
