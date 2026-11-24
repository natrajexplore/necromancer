import { useMemo } from "react";

import { useGrimoire, useResurrect, type Crypt } from "../api/hooks";
import type { GateResult, GrimoireResult, VerdictValue } from "../api/types";
import { ErrorNotice } from "../components/ErrorNotice";
import { RunbookView } from "../components/RunbookView";
import { download, printHtml, stem } from "../lib/download";
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

function Downloads({ crypt, report, baseline }: { crypt: Crypt; report: GrimoireResult; baseline: string | undefined }) {
  const name = stem(crypt.name);
  const button = "rounded-md border border-stone px-4 py-2 hover:border-spectral";
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
      <p className="mt-2 text-sm text-ash">
        No tightened config is offered: the engine does not produce one yet. When it does, it will
        be a separate file with its own ledger and proof.
      </p>
      <p className="mt-2 text-sm text-ash">
        The shared secrets on the source device should be considered exposed and rotated at
        decommission. Downloads hold the redacted source only.
      </p>
    </section>
  );
}

/**
 * Verdict and Grimoire. Plain on purpose: no theme labels, verdict and gate table first. This
 * is evidence for a reviewer to weigh, not an approval to deploy.
 */
export function Verdict({ crypt }: { crypt: Crypt }) {
  const grimoire = useGrimoire(crypt);
  const resurrected = useResurrect(crypt);
  const report = grimoire.data;
  const runbook = useMemo(() => (report ? parseRunbook(report.markdown) : []), [report]);

  return (
    <div className="font-sans">
      <p className="max-w-3xl text-ash">
        The readiness verdict comes from gates G1 to G6. It supports evidence for a decision by
        the change approver. It does not say the config is safe to deploy.
      </p>
      <button
        type="button"
        onClick={() => grimoire.mutate()}
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
        {report && (
          <>
            <section className="mt-6" aria-labelledby="verdict-title">
              <h3 id="verdict-title" className="text-xl font-semibold">Readiness verdict</h3>
              <p className={`mt-2 inline-block rounded-md border-2 px-4 py-2 text-3xl font-bold ${VERDICT_STYLE[report.verdict.value]}`}>
                {report.verdict.value}
              </p>
              <p className="mt-2">{VERDICT_TEXT[report.verdict.value]}</p>
              <List title="Blocking reasons" items={report.verdict.blocking_reasons} />
              <List title="Conditions" items={report.verdict.conditions} />
              <List title="Notes" items={report.verdict.notes} />
              <h3 className="mt-6 text-xl font-semibold">Gates</h3>
              <GateTable gates={report.verdict.gates} />
              <p className="mt-3 text-sm text-ash">
                Proof: {report.proof_passed === null ? "could not run" : report.proof_passed ? "passed" : "failed"},{" "}
                {report.examples_per_context.toLocaleString("en-US")} examples per context, seed {report.seed}.
                Golden flows: {report.golden_passed} of {report.golden_total} passed.
              </p>
            </section>

            <section className="mt-8" aria-labelledby="runbook-title">
              <h3 id="runbook-title" className="text-xl font-semibold">Runbook</h3>
              <div className="mt-3">
                <RunbookView parts={runbook} />
              </div>
            </section>

            <Downloads crypt={crypt} report={report} baseline={resurrected.data?.config} />

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
