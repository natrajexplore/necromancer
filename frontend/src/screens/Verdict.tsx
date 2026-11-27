import { useMemo, useState } from "react";

import { useGrimoire, useResurrect, useTightened, useTighteningSelection, type Crypt } from "../api/hooks";
import type {
  GateResult,
  GrimoireResult,
  LedgerDecision,
  TightenedResult,
  Verdict as VerdictResult,
  VerdictValue,
} from "../api/types";
import { ErrorNotice } from "../components/ErrorNotice";
import { LedgerDecisions } from "../components/LedgerDecisions";
import { RunbookView } from "../components/RunbookView";
import { download, printHtml, stem } from "../lib/download";
import { useFocusOnChange } from "../lib/focus";
import { parseRunbook } from "../lib/runbook";

const VERDICT_TEXT: Record<VerdictValue, string> = {
  GO: "No gate blocks this migration, and nothing is left open.",
  CONDITIONAL: "No gate blocks this migration, but conditions must be met first.",
  "NO-GO": "At least one gate blocks this migration. The reasons are listed below.",
};

const VERDICT_STYLE: Record<VerdictValue, string> = {
  GO: "border-spectral text-spectral",
  CONDITIONAL: "border-candle text-candle",
  "NO-GO": "border-blood text-blood",
};

function List({ title, items }: { title: string; items: string[] }) {
  if (items.length === 0) return null;
  return (
    <section className="mt-4">
      <h4 className="font-semibold">{title}</h4>
      <ul className="mt-1 list-disc pl-6">
        {items.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>
    </section>
  );
}

function gateFindings(gate: GateResult): string[] {
  const problems = gate.checks.filter((check) => !check.ok).map((check) => `${check.id}: ${check.detail}`);
  return problems.length > 0 ? problems : [`All ${gate.checks.length} checks passed.`];
}

function GateTable({ gates }: { gates: GateResult[] }) {
  return (
    <table className="mt-2 w-full text-left">
      <caption className="sr-only">Gates G1 to G6</caption>
      <thead className="text-sm text-ash">
        <tr>
          <th scope="col" className="py-2 pr-4 font-normal">Gate</th>
          <th scope="col" className="py-2 pr-4 font-normal">Status</th>
          <th scope="col" className="py-2 font-normal">What it found</th>
        </tr>
      </thead>
      <tbody>
        {gates.map((gate) => (
          <tr key={gate.gate} className="border-t border-stone align-top">
            <th scope="row" className="py-2 pr-4 font-semibold">{gate.gate}</th>
            <td className={`py-2 pr-4 font-semibold ${gate.status === "fail" ? "text-blood" : "text-spectral"}`}>
              {gate.status === "pass" ? "Pass" : gate.status === "waived" ? "Pass, with waiver" : "Fail"}
            </td>
            <td className="py-2">
              <ul>
                {gateFindings(gate).map((line, index) => (
                  <li key={index}>{line}</li>
                ))}
              </ul>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function Downloads({
  crypt,
  report,
  baseline,
  tightened,
}: {
  crypt: Crypt;
  report: GrimoireResult;
  baseline: string | undefined;
  tightened: TightenedResult | null;
}) {
  const name = stem(crypt.name);
  const button = "rounded-md border border-stone px-4 py-2 hover:border-spectral";
  // A tightened config is only offered once its own proof passed, and always with its ledger.
  const provedTightened = tightened !== null && tightened.passed ? tightened : null;
  return (
    <section className="mt-8" aria-labelledby="downloads-title">
      <h3 id="downloads-title" className="text-xl font-semibold">Downloads</h3>
      <div className="mt-3 flex flex-wrap gap-3">
        <button type="button" className={button} onClick={() => download(`${name}-grimoire.md`, report.markdown, "text/markdown")}>
          Download report (Markdown)
        </button>
        <button type="button" className={button} onClick={() => download(`${name}-grimoire.html`, report.html, "text/html")}>
          Download report (HTML)
        </button>
        <button type="button" className={button} onClick={() => printHtml(report.html)}>
          Print or save as PDF
        </button>
        <button
          type="button"
          className={`${button} disabled:opacity-60`}
          disabled={baseline === undefined}
          onClick={() => baseline !== undefined && download(`${name}-baseline-panos.txt`, baseline, "text/plain")}
        >
          Download baseline PAN-OS config (.txt)
        </button>
      </div>
      <section className="mt-6" aria-labelledby="tightened-downloads-title">
        <h4 id="tightened-downloads-title" className="font-semibold">Tightened artifact (separate change)</h4>
        {provedTightened ? (
          <>
            <p className="mt-1 text-sm text-ash">
              Its own proof passed
              {provedTightened.proof ? ` (${provedTightened.proof.budget} examples per context, seed ${provedTightened.proof.seed})` : ""}.
              It is a separate change from the baseline above and comes with its own ledger.
              {provedTightened.ledger.some((entry) => entry.approval === "pending")
                ? " Some ledger entries are still pending approval."
                : ""}
            </p>
            <div className="mt-3 flex flex-wrap gap-3">
              <button
                type="button"
                className={button}
                onClick={() => download(`${name}-tightened-panos.txt`, provedTightened.config, "text/plain")}
              >
                Download tightened PAN-OS config (.txt)
              </button>
              <button
                type="button"
                className={button}
                onClick={() =>
                  download(`${name}-tightened-ledger.json`, JSON.stringify(provedTightened.ledger, null, 2), "application/json")
                }
              >
                Download tightened ledger (.json)
              </button>
            </div>
          </>
        ) : (
          <p className="mt-1 text-sm text-ash">
            {tightened
              ? "A tightened config exists, but its proof did not pass, so it is not offered."
              : "No tightened config yet. Accept proposals on the Resurrection screen and prove the tightened artifact first. It is never mixed into the baseline."}
          </p>
        )}
      </section>
      <p className="mt-4 text-sm text-ash">
        The shared secrets on the source device should be considered exposed and rotated at
        decommission. Downloads hold the redacted source only.
      </p>
    </section>
  );
}

type Artifact = "baseline" | "tightened";

const ARTIFACT_LABEL: Record<Artifact, string> = {
  baseline: "baseline artifact (like for like)",
  tightened: "tightened artifact (separate change)",
};

/** What the verdict section shows: the verdict of one artifact with the proof facts it rests on. */
interface View {
  artifact: Artifact;
  verdict: VerdictResult;
  proofPassed: boolean | null;
  goldenPassed: number;
  goldenTotal: number;
}

function viewOf(report: GrimoireResult, artifact: Artifact): View | null {
  if (artifact === "baseline") {
    return {
      artifact,
      verdict: report.verdict,
      proofPassed: report.proof_passed,
      goldenPassed: report.golden_passed,
      goldenTotal: report.golden_total,
    };
  }
  const gate = report.tightened;
  if (!gate) return null;
  return {
    artifact,
    verdict: gate.verdict,
    proofPassed: gate.proof_passed,
    goldenPassed: gate.golden_passed,
    goldenTotal: gate.golden_total,
  };
}

/** Which artifact the gates judge. The tightened one is selectable only once its proof passed. */
function JudgeSwitch({
  judge,
  onJudge,
  accepted,
  available,
}: {
  judge: Artifact;
  onJudge: (artifact: Artifact) => void;
  accepted: number;
  available: boolean;
}) {
  const button = "rounded-md border px-3 py-1.5 aria-pressed:bg-spectral aria-pressed:text-void disabled:opacity-50";
  return (
    <div role="group" aria-label="Judge" className="mt-4 flex flex-wrap items-center gap-3">
      <span className="text-ash">Judge:</span>
      <button
        type="button"
        aria-pressed={judge === "baseline"}
        onClick={() => onJudge("baseline")}
        className={`${button} border-stone`}
      >
        baseline
      </button>
      <button
        type="button"
        aria-pressed={judge === "tightened"}
        disabled={!available}
        onClick={() => onJudge("tightened")}
        className={`${button} border-stone`}
      >
        tightened ({accepted} accepted)
      </button>
      {!available && (
        <span className="text-sm text-ash">
          Prove a tightened artifact on the Resurrection screen to judge it here.
        </span>
      )}
    </div>
  );
}

/**
 * Verdict and Grimoire. Plain on purpose: no theme labels, verdict and gate table first. This
 * is evidence for a reviewer to weigh, not an approval to deploy.
 */
export function Verdict({ crypt }: { crypt: Crypt }) {
  const grimoire = useGrimoire(crypt);
  const resurrected = useResurrect(crypt);
  const tightened = useTightened(crypt);
  const selection = useTighteningSelection(crypt);
  const [judge, setJudge] = useState<Artifact>("baseline");
  const [decisions, setDecisions] = useState<Record<string, LedgerDecision>>({});
  const [approver, setApprover] = useState("");
  const report = grimoire.data;
  const headingRef = useFocusOnChange<HTMLHeadingElement>(report);
  const runbook = useMemo(() => (report ? parseRunbook(report.markdown) : []), [report]);
  // a tightened artifact counts only after its own proof passed
  const proved = tightened.data?.passed ? tightened.data : null;
  const accepted = selection.data
    ? Object.values(selection.data.approvals).filter((d) => d.approval === "accepted").length
    : (proved?.applied.length ?? 0);
  const artifact: Artifact = judge === "tightened" && proved ? "tightened" : "baseline";
  const view = report ? viewOf(report, artifact) : null;
  const entries = artifact === "tightened" && proved ? proved.ledger : (resurrected.data?.ledger ?? []);
  const decide = (id: string, decision: LedgerDecision | null) =>
    setDecisions((current) => {
      const next = { ...current };
      if (decision) next[id] = decision;
      else delete next[id];
      return next;
    });
  const run = () =>
    grimoire.mutate({ tightening: proved ? (selection.data ?? null) : null, decisions });

  return (
    <div className="font-sans">
      <p className="max-w-3xl text-ash">
        The readiness verdict comes from gates G1 to G6. It supports evidence for a decision by
        the change approver. It does not say the config is safe to deploy.
      </p>
      <JudgeSwitch judge={artifact} onJudge={setJudge} accepted={accepted} available={proved !== null} />
      <LedgerDecisions
        artifact={artifact}
        entries={entries}
        decisions={decisions}
        approver={approver}
        onApprover={setApprover}
        onDecide={decide}
      />
      <button
        type="button"
        onClick={run}
        disabled={grimoire.isPending}
        className="mt-4 rounded-md bg-spectral px-5 py-2.5 font-semibold text-void disabled:opacity-60"
      >
        {grimoire.isPending ? "Running the gates…" : report ? "Run the gates again" : "Run the gates"}
      </button>
      {grimoire.isPending && (
        <p role="status" className="mt-3">
          Running the gates and the proof. This can take a while on large configs.
        </p>
      )}
      <div aria-live="polite">
        {grimoire.isError && <ErrorNotice error={grimoire.error} what="assessed" />}
        {report && view === null && (
          <p role="status" className="mt-6 text-candle">
            These results do not cover the tightened artifact. Run the gates again to judge it.
          </p>
        )}
        {report && view !== null && (
          <>
            <section className="mt-6" aria-labelledby="verdict-title">
              <h3 id="verdict-title" ref={headingRef} tabIndex={-1} className="text-xl font-semibold">Readiness verdict</h3>
              <p className={`mt-2 inline-block rounded-md border-2 px-4 py-2 ${VERDICT_STYLE[view.verdict.value]}`}>
                <span className="text-3xl font-bold">{view.verdict.value}</span>{" "}
                <span className="text-sm" data-testid="verdict-artifact">
                  for the {ARTIFACT_LABEL[view.artifact]}
                </span>
              </p>
              <p className="mt-2">{VERDICT_TEXT[view.verdict.value]}</p>
              {report.tightened && (
                <p className="mt-1 text-sm text-ash">
                  Baseline: {report.verdict.value}. Tightened (separate change): {report.tightened.verdict.value}.
                </p>
              )}
              <List title="Blocking reasons" items={view.verdict.blocking_reasons} />
              <List title="Conditions" items={view.verdict.conditions} />
              <List title="Notes" items={view.verdict.notes} />
              <h3 className="mt-6 text-xl font-semibold">Gates</h3>
              <GateTable gates={view.verdict.gates} />
              <p className="mt-3 text-sm text-ash">
                Proof: {view.proofPassed === null ? "could not run" : view.proofPassed ? "passed" : "failed"},{" "}
                {report.examples_per_context.toLocaleString("en-US")} examples per context, seed {report.seed}.
                Golden flows: {view.goldenPassed} of {view.goldenTotal} passed.
              </p>
            </section>

            <section className="mt-8" aria-labelledby="runbook-title">
              <h3 id="runbook-title" className="text-xl font-semibold">Runbook</h3>
              <div className="mt-3">
                <RunbookView parts={runbook} />
              </div>
            </section>

            <Downloads
              crypt={crypt}
              report={report}
              baseline={resurrected.data?.config}
              tightened={tightened.data ?? null}
            />

            <details className="mt-8">
              <summary className="cursor-pointer text-xl font-semibold">Report preview (Markdown)</summary>
              <pre tabIndex={0} className="mt-3 max-h-[32rem] overflow-auto rounded-md border border-stone bg-crypt p-3 font-mono text-sm whitespace-pre-wrap">
                {report.markdown}
              </pre>
            </details>
          </>
        )}
      </div>
    </div>
  );
}
