import { useEffect, useId, useRef, useState, type ReactNode, type RefObject } from "react";

import { useExhume, type Crypt } from "../api/hooks";
import type { ExhumeResult } from "../api/types";
import { confidence, dialectLabel, percent, plural } from "../lib/format";
import { Autopsy } from "../screens/Autopsy";
import { ProofOfLife } from "../screens/ProofOfLife";
import { Resurrection } from "../screens/Resurrection";
import { Verdict } from "../screens/Verdict";
import { ErrorNotice } from "./ErrorNotice";
import { UnquietLines } from "./UnquietLines";

/** Governance gate G1 needs a dialect detection confidence of at least 0.9. */
const MIN_CONFIDENCE = 0.9;

function Fact({ term, children }: { term: string; children: ReactNode }) {
  return (
    <div>
      <dt className="text-sm text-ash">{term}</dt>
      <dd className="mt-0.5 text-bone">{children}</dd>
    </div>
  );
}

function Summary({ result }: { result: ExhumeResult }) {
  const { coverage } = result;
  const relevant = result.unparsed.filter((line) => line.security_relevant).length;
  const rules = result.acls.reduce((sum, acl) => sum + acl.rules, 0);
  return (
    <dl className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
      <Fact term="Dialect">{dialectLabel(result.dialect, result.os_version)}</Fact>
      <Fact term="Detection confidence">
        {confidence(result.detection_confidence)}
        {result.detection_confidence < MIN_CONFIDENCE && (
          <span className="block text-sm text-candle">
            Below 0.90: the input-integrity gate (G1) will not pass without a reviewer confirming
            the dialect.
          </span>
        )}
      </Fact>
      <Fact term="Mode and address space">
        {result.mode}, {result.address_space} addresses
      </Fact>
      <Fact term="Coverage">
        {percent(coverage.ratio)}
        <span className="block text-sm text-ash">
          {coverage.handled} of {plural(coverage.security_relevant, "security-relevant line")}{" "}
          migrated or handled
        </span>
      </Fact>
      <Fact term="Lines not migrated">
        {result.unparsed.length}
        {relevant > 0 && <span className="block text-sm text-candle">{relevant} security-relevant</span>}
      </Fact>
      <Fact term="Contents">
        {plural(result.interfaces.length, "interface")}, {plural(result.acls.length, "ACL")} (
        {plural(rules, "rule")}), {plural(result.nat_rules, "NAT rule")}
      </Fact>
    </dl>
  );
}

type Stage = "exhume" | "autopsy" | "resurrect" | "prove" | "verdict";

const STAGES: { id: Stage; label: string; plain: string }[] = [
  { id: "exhume", label: "Exhume", plain: "what the config contains" },
  { id: "autopsy", label: "Autopsy", plain: "ghost rules" },
  { id: "resurrect", label: "Resurrect", plain: "PAN-OS candidate" },
  { id: "prove", label: "Proof of Life", plain: "equivalence check" },
  { id: "verdict", label: "Verdict", plain: "readiness gates and report" },
];

/** One crypt, through the ritual: exhume, autopsy, resurrect, prove, verdict. */
export function CryptDetails({ crypt }: { crypt: Crypt }) {
  const [stage, setStage] = useState<Stage>("exhume");
  const headingId = useId();
  const headingRef = useRef<HTMLHeadingElement>(null);
  // Opening a crypt and changing stage both land on the new heading, so keyboard and screen
  // reader users start at the top of what they chose.
  useEffect(() => {
    headingRef.current?.focus();
  }, [stage]);
  return (
    <div className="mt-10">
      <nav aria-label="Stages of the ritual">
        <ol className="flex flex-wrap gap-2">
          {STAGES.map((entry, index) => (
            <li key={entry.id}>
              <button
                type="button"
                aria-current={stage === entry.id ? "step" : undefined}
                onClick={() => setStage(entry.id)}
                className={`rounded-md border px-4 py-2 text-left ${stage === entry.id ? "border-spectral bg-crypt text-spectral" : "border-stone text-bone hover:border-ash"}`}
              >
                {index + 1}. {entry.label}
                <span className="block text-sm text-ash">{entry.plain}</span>
              </button>
            </li>
          ))}
        </ol>
      </nav>
      {stage === "exhume" ? (
        <ExhumeStage crypt={crypt} headingRef={headingRef} />
      ) : (
        <section aria-labelledby={headingId} className="mt-4 rounded-lg border border-stone bg-crypt p-6">
          <h2 id={headingId} ref={headingRef} tabIndex={-1} className="font-display text-2xl text-bone">
            {crypt.name}: {STAGES.find((entry) => entry.id === stage)?.label}
          </h2>
          <div className="mt-4">
            {stage === "autopsy" && <Autopsy crypt={crypt} />}
            {stage === "resurrect" && <Resurrection crypt={crypt} />}
            {stage === "prove" && <ProofOfLife crypt={crypt} />}
            {stage === "verdict" && <Verdict crypt={crypt} />}
          </div>
        </section>
      )}
    </div>
  );
}

/** What exhume found in one crypt: the summary, then every unquiet line. */
function ExhumeStage({ crypt, headingRef }: { crypt: Crypt; headingRef: RefObject<HTMLHeadingElement> }) {
  const headingId = useId();
  const exhumed = useExhume(crypt);
  return (
    <section aria-labelledby={headingId} className="mt-4 rounded-lg border border-stone bg-crypt p-6">
      <h2 id={headingId} ref={headingRef} tabIndex={-1} className="font-display text-2xl text-bone">
        {crypt.name}
      </h2>
      <div className="mt-4" aria-live="polite">
        {exhumed.isPending && <p role="status">Exhuming…</p>}
        {exhumed.isError && <ErrorNotice error={exhumed.error} />}
        {exhumed.isSuccess && (
          <>
            <Summary result={exhumed.data} />
            <UnquietLines lines={exhumed.data.unparsed} />
          </>
        )}
      </div>
    </section>
  );
}
