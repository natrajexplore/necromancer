import { useId, type ReactNode } from "react";

import { useExhume, type Crypt } from "../api/hooks";
import type { ExhumeResult } from "../api/types";
import { dialectLabel, percent, plural } from "../lib/format";
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
        {result.detection_confidence.toFixed(2)}
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

/** What exhume found in one crypt: the summary, then every unquiet line. */
export function CryptDetails({ crypt }: { crypt: Crypt }) {
  const headingId = useId();
  const exhumed = useExhume(crypt);
  return (
    <section aria-labelledby={headingId} className="mt-10 rounded-lg border border-stone bg-crypt p-6">
      <h2 id={headingId} className="font-display text-2xl text-bone">
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
