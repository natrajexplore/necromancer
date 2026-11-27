import { useId, useState, type ReactNode } from "react";

import { useProve, type Crypt } from "../api/hooks";
import type { ContextProof, ProveResult } from "../api/types";
import { CounterexampleCard } from "../components/CounterexampleCard";
import { ErrorNotice } from "../components/ErrorNotice";
import { Heartbeat, type BeatState } from "../components/Heartbeat";
import { Hint } from "../components/Hint";
import { useFocusOnChange } from "../lib/focus";
import { plural } from "../lib/format";

function Stat({ term, children }: { term: string; children: ReactNode }) {
  return (
    <div>
      <dt className="text-sm text-ash">{term}</dt>
      <dd className="mt-0.5 text-lg text-bone">{children}</dd>
    </div>
  );
}

function Stats({ result }: { result: ProveResult }) {
  const { proof } = result;
  const flows = proof.contexts.reduce((sum, c) => sum + c.examples, 0);
  const divergences =
    proof.contexts.filter((c) => c.counterexample !== null).length + proof.golden.failures.length;
  const rules = (side: "original" | "resurrected") => {
    const total = proof.contexts.reduce((sum, c) => sum + c[side].rules, 0);
    const hit = proof.contexts.reduce((sum, c) => sum + c[side].hit, 0);
    return total === 0 ? "no rules" : `${hit} of ${total} rules hit (${Math.round((hit / total) * 100)}%)`;
  };
  return (
    <dl className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <Stat term="Generated flows checked">{flows.toLocaleString("en-US")}</Stat>
      <Stat term="Divergences found">{divergences}</Stat>
      <Stat term="Rule coverage, original">{rules("original")}</Stat>
      <Stat term="Rule coverage, resurrected">{rules("resurrected")}</Stat>
      <Stat term="Golden flows (hand-verified)">
        {proof.golden.passed} of {proof.golden.total} passed
      </Stat>
      <Stat term="Seed and budget">
        {proof.seed}, {plural(proof.budget, "example")} per context
      </Stat>
    </dl>
  );
}

function ContextTable({ contexts }: { contexts: ContextProof[] }) {
  return (
    <table className="mt-2 w-full text-left">
      <caption className="sr-only">Proof result for each context</caption>
      <thead className="text-sm text-ash">
        <tr>
          <th scope="col" className="py-2 pr-4 font-normal">Context</th>
          <th scope="col" className="py-2 pr-4 font-normal">Flows</th>
          <th scope="col" className="py-2 pr-4 font-normal">Result</th>
          <th scope="col" className="py-2 pr-4 font-normal">Rules hit, original</th>
          <th scope="col" className="py-2 font-normal">Rules hit, resurrected</th>
        </tr>
      </thead>
      <tbody>
        {contexts.map((c) => (
          <tr key={c.context} className="border-t border-stone">
            <th scope="row" className="py-2 pr-4 font-normal text-bone">
              <code className="font-mono">{c.context}</code>
              {c.implicit && (
                <span className="ml-2 text-sm text-ash">
                  <Hint explain="Implicit context: an interface with no ACL bound. The device's built-in defaults decide there, and the proof checks them too.">
                    implicit
                  </Hint>
                </span>
              )}
            </th>
            <td className="py-2 pr-4 text-bone">{c.examples.toLocaleString("en-US")}</td>
            <td className={`py-2 pr-4 ${c.passed ? "text-spectral" : "text-blood"}`}>
              {c.passed ? "Passed" : "Diverged"}
            </td>
            <td className="py-2 pr-4 text-bone">
              {c.original.hit} of {c.original.rules}
            </td>
            <td className="py-2 text-bone">
              {c.resurrected.hit} of {c.resurrected.rules}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/** Proof of Life: generated flows compared between the original and the candidate. */
export function ProofOfLife({ crypt }: { crypt: Crypt }) {
  const prove = useProve(crypt);
  const [haunt, setHaunt] = useState(false);
  const [askedHaunt, setAskedHaunt] = useState(false);
  const hauntId = useId();
  const resultRef = useFocusOnChange<HTMLParagraphElement>(prove.data);

  const run = () => {
    setAskedHaunt(haunt);
    prove.mutate({ profile: "dev", ...(haunt ? { haunt: true } : {}) });
  };
  const data = prove.data;
  const state: BeatState = prove.isPending ? "checking" : data ? (data.passed ? "alive" : "dead") : "idle";
  const example = data?.proof.counterexample ?? data?.proof.golden.failures[0] ?? null;

  return (
    <div>
      <p className="max-w-3xl text-ash">
        Proof of Life replays generated packets against the original and the PAN-OS candidate and
        compares the two answers. Hand-verified golden flows are counted separately.
      </p>
      <div className="mt-4 flex flex-wrap items-center gap-6">
        <button
          type="button"
          onClick={run}
          disabled={prove.isPending}
          className="rounded-md bg-spectral px-5 py-2.5 font-semibold text-void disabled:opacity-60"
        >
          {prove.isPending ? "Proving…" : "Prove"}
        </button>
        <div className="flex items-center gap-2">
          <input
            id={hauntId}
            type="checkbox"
            checked={haunt}
            onChange={(event) => setHaunt(event.target.checked)}
            className="size-5 accent-blood"
          />
          <label htmlFor={hauntId} className="text-bone">
            <Hint explain="Haunt it is a demo switch. It proves a deliberately broken candidate, so you can see what a failed proof looks like. It never changes the config you download.">
              Haunt it
            </Hint>{" "}
            (demo: prove a deliberately broken candidate)
          </label>
        </div>
      </div>

      <div className="mt-6">
        <Heartbeat state={state} />
      </div>

      <div aria-live="polite">
        {prove.isError && <ErrorNotice error={prove.error} what="proved" />}
        {data && askedHaunt && data.haunted !== true && (
          <p role="alert" className="mt-4 rounded-md border border-candle px-4 py-3 text-candle">
            Haunting was requested, but this engine did not apply it. The result below is for the
            real candidate.
          </p>
        )}
        {data && data.haunted === true && (
          <p className="mt-4 rounded-md border border-candle px-4 py-3 text-candle">
            Haunted: this result is for a deliberately broken candidate. Do not use it for a
            migration.
          </p>
        )}
        {data && (
          <>
            <p ref={resultRef} tabIndex={-1} className="mt-4 text-lg text-bone">
              {data.passed
                ? "The resurrected config behaved like the original on every flow checked."
                : "The resurrected config diverged from the original."}
            </p>
            <Stats result={data} />
            <h3 className="mt-8 font-display text-xl text-bone">Results by context</h3>
            <ContextTable contexts={data.proof.contexts} />
            {example && (
              <div className="mt-8">
                <CounterexampleCard example={example} />
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
