import { useId, useMemo, useState } from "react";

import { useAutopsy, useExhume, useResurrect, type Crypt } from "../api/hooks";
import type { Finding, Severity } from "../api/types";
import { typeName } from "../components/GhostBadge";
import { ErrorNotice } from "../components/ErrorNotice";
import { RuleTable, type RuleRow } from "../components/RuleTable";
import { ZoneMapping } from "../components/ZoneMapping";
import { plural } from "../lib/format";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];

/** Rules in ACL order (from exhume), each with its findings; findings about other things last. */
export function buildRows(
  acls: { name: string; rules: number }[],
  findings: Finding[],
): { rules: RuleRow[]; other: Finding[] } {
  const byRef = new Map<string, Finding[]>();
  for (const finding of findings) byRef.set(finding.rule_ref, [...(byRef.get(finding.rule_ref) ?? []), finding]);
  const rules: RuleRow[] = [];
  const known = new Set<string>();
  for (const acl of acls) {
    for (let seq = 1; seq <= acl.rules; seq += 1) {
      const id = `${acl.name}#${seq}`;
      known.add(id);
      rules.push({ id, findings: byRef.get(id) ?? [] });
    }
  }
  return { rules, other: findings.filter((finding) => !known.has(finding.rule_ref)) };
}

function FilterSelect({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: string[];
  onChange: (value: string) => void;
}) {
  const id = useId();
  return (
    <div className="flex flex-col gap-1">
      <label htmlFor={id} className="text-sm text-ash">
        {label}
      </label>
      <select
        id={id}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="rounded-md border border-stone bg-void px-3 py-2 text-bone"
      >
        <option value="">All</option>
        {options.map((option) => (
          <option key={option} value={option}>
            {typeName(option)}
          </option>
        ))}
      </select>
    </div>
  );
}

function OtherFindings({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) return null;
  return (
    <section className="mt-6" aria-label="Findings about more than one rule">
      <h4 className="font-display text-xl text-bone">Findings not tied to one rule</h4>
      <ul className="mt-2 space-y-3">
        {findings.map((finding) => (
          <li key={finding.id} className="rounded-md border border-stone bg-crypt px-4 py-3">
            <p className="text-bone">
              <code className="font-mono">{finding.rule_ref}</code>, {typeName(finding.type)},{" "}
              {finding.severity} (source line {finding.source_line})
            </p>
            <p className="mt-1 text-ash">{finding.explanation}</p>
            <p className="mt-1 text-bone">{finding.recommendation}</p>
          </li>
        ))}
      </ul>
    </section>
  );
}

/** Ghost rules of one crypt: filters, the rule list, and the zone mapping. */
export function Autopsy({ crypt }: { crypt: Crypt }) {
  const exhumed = useExhume(crypt);
  const autopsy = useAutopsy(crypt);
  const resurrected = useResurrect(crypt);
  const [type, setType] = useState("");
  const [severity, setSeverity] = useState("");

  const findings = autopsy.data?.findings;
  const shown = useMemo(
    () => (findings ?? []).filter((f) => (!type || f.type === type) && (!severity || f.severity === severity)),
    [findings, type, severity],
  );
  const { rules, other } = useMemo(
    () => buildRows(exhumed.data?.acls ?? [], shown),
    [exhumed.data, shown],
  );
  const filtering = type !== "" || severity !== "";
  // With a filter on, show only the rules that have a matching finding.
  const rows = filtering ? rules.filter((row) => row.findings.length > 0) : rules;

  if (autopsy.isError) return <ErrorNotice error={autopsy.error} what="autopsied" />;
  if (exhumed.isError) return <ErrorNotice error={exhumed.error} what="exhumed" />;
  if (!autopsy.data || !exhumed.data) return <p role="status">Performing the autopsy…</p>;

  const { by_severity: bySeverity, by_type: byType } = autopsy.data;
  return (
    <div>
      <p className="max-w-3xl text-ash">
        A ghost rule is a rule that is shadowed, redundant, too broad, insecure or unused. Choose a
        rule to see the rules it is related to.
      </p>
      <p className="mt-3 text-bone" aria-live="polite">
        {plural(autopsy.data.findings.length, "finding")}:{" "}
        {SEVERITIES.filter((s) => bySeverity[s]).map((s) => `${bySeverity[s]} ${s}`).join(", ") || "none"}
      </p>
      <div className="mt-4 flex flex-wrap gap-4">
        <FilterSelect label="Finding type" value={type} options={Object.keys(byType)} onChange={setType} />
        <FilterSelect label="Severity" value={severity} options={SEVERITIES} onChange={setSeverity} />
      </div>
      <h3 className="mt-6 mb-2 font-display text-xl text-bone">Rules in order</h3>
      {rows.length === 0 ? (
        <p className="text-ash">No rules match.</p>
      ) : (
        <RuleTable rows={rows} label="Rules and their findings" />
      )}
      <OtherFindings findings={other} />
      <ZoneMapping
        interfaces={exhumed.data.interfaces}
        panos={resurrected.data?.config ?? ""}
        findings={autopsy.data.findings}
        loading={resurrected.isPending}
      />
    </div>
  );
}
