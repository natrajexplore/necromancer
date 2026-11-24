"""Grimoire sections 4 to 6: coverage, findings (with the rule inventory), and the ledger."""

from __future__ import annotations

from collections import Counter

from necro.assessment import Assessment
from necro.controls import SEVERITY_MODEL, plain
from necro.findings import Finding, Severity
from necro.gates import find_waiver
from necro.ir import Policy, Rule
from necro.ledger import Approval, LedgerEntry
from necro.report_doc import Block, Heading, Para, Section, Table
from necro.rule_text import match_text

CLASSIFICATIONS = ("migrated", "not-policy", "management-plane", "out-of-scope", "unparsed")
SEVERITY_ORDER = (Severity.critical, Severity.high, Severity.medium, Severity.low)
NO_JUSTIFICATION = "No justification recorded"


# -- 4 coverage --------------------------------------------------------------------------------


def _line_status(a: Assessment, line_no: int, waiver_id: str, relevant: bool) -> str:
    if waiver_id:
        return f"waived in the config ({waiver_id})"
    waiver, note = find_waiver(a.sidecar.waivers, f"line:{line_no}", a.today)
    if waiver is not None:
        return f"waived by {waiver.approver} until {waiver.expires_on.isoformat()}: {waiver.reason}"
    if relevant:
        return f"open: blocks the verdict{note}"
    return "not security relevant"


def coverage_section(a: Assessment) -> Section:
    """Section 4: line classification counts and every unparsed, waived or out-of-scope line."""
    core = a.core
    cov = core.coverage
    counts = tuple((name, str(cov.counts.get(name, 0))) for name in CLASSIFICATIONS)
    attention = tuple(
        (
            str(r.line_no),
            r.classification,
            "yes" if r.security_relevant else "no",
            r.reason or "none",
            _line_status(a, r.line_no, r.waiver_id, r.security_relevant),
            r.text.strip(),
        )
        for r in sorted(core.policy.line_records, key=lambda r: r.line_no)
        if r.classification in ("unparsed", "out-of-scope") or r.waiver_id
    )
    emission = core.emission
    blocks: list[Block] = [
        Heading("Line classification"),
        Table(("Classification", "Lines"), (*counts, ("total", str(cov.total_lines)))),
        Para(
            f"Security-relevant lines: {cov.security_relevant}. Handled (migrated or "
            f"management-plane): {cov.handled}. Waived: {cov.waived}. Blocking: {cov.blocking}. "
            f"Coverage: {cov.ratio * 100:.1f}%."
        ),
        Heading("Unparsed, waived and out-of-scope lines"),
        Table(
            ("Line", "Classification", "Security relevant", "Reason", "Status", "Text"),
            attention,
            empty="Every line is migrated, not policy, or management-plane.",
        ),
        Heading("Not expressed in the candidate"),
        Table(
            ("Item",),
            tuple((item,) for item in emission.unsupported),
            empty="Everything the parser accepted is expressed in the candidate.",
        ),
    ]
    if emission.notes:
        blocks += [
            Heading("Differences that change no decision"),
            Table(("Note",), tuple((n,) for n in emission.notes)),
        ]
    return Section(4, "Coverage", tuple(blocks))


# -- 5 findings and rule inventory -------------------------------------------------------------


def _decision(a: Assessment, finding: Finding) -> str:
    risk, note = find_waiver(a.sidecar.accepted_risks, f"finding:{finding.id}", a.today)
    if risk is not None:
        return f"Accepted by {risk.approver} until {risk.expires_on.isoformat()}: {risk.reason}"
    if finding.severity in (Severity.critical, Severity.high):
        return f"Open: fix, accept with an expiry, or carry forward{note}"
    return "Review with the rule owner"


def _finding_rows(a: Assessment, findings: list[Finding]) -> tuple[tuple[str, ...], ...]:
    return tuple(
        (
            f.id,
            f.type.value,
            f.rule_ref,
            str(f.source_line) if f.source_line else "n/a",
            f.zone or "n/a",
            f.explanation,
            f.recommendation,
            _decision(a, f),
        )
        for f in findings
    )


def _bound_to(policy: Policy) -> dict[str, str]:
    bound: dict[str, list[str]] = {}
    for b in policy.bindings:
        where = "global" if b.global_acl else f"{b.interface} {b.direction}"
        bound.setdefault(b.acl_name, []).append(where)
    return {name: ", ".join(places) for name, places in bound.items()}


def _inventory_row(
    acl_name: str, rule: Rule, bound: dict[str, str], by_rule: dict[str, list[str]]
) -> tuple[str, ...]:
    action = rule.action.value + (" (inactive)" if rule.inactive else "")
    return (
        rule.id,
        bound.get(acl_name, "not bound"),
        str(rule.source_line) if rule.source_line else "n/a",
        action,
        match_text(rule.match),
        rule.remark.strip() or NO_JUSTIFICATION,
        ", ".join(by_rule.get(rule.id, [])) or "none",
    )


def findings_section(a: Assessment) -> Section:
    """Section 5: the severity model, findings by severity, and the rule inventory."""
    findings = a.core.findings
    by_severity = Counter(f.severity for f in findings)
    blocks: list[Block] = [
        Heading("Severity model"),
        Table(
            ("Severity", "Meaning", "Examples"),
            tuple((r.severity, plain(r.meaning), plain(r.examples)) for r in SEVERITY_MODEL),
        ),
        Para(
            "Findings: "
            + ", ".join(f"{by_severity.get(s, 0)} {s.value}" for s in SEVERITY_ORDER)
            + "."
        ),
    ]
    headers = ("ID", "Type", "Rule", "Line", "Zone", "Explanation", "Recommendation", "Decision")
    for severity in SEVERITY_ORDER:
        chosen = [f for f in findings if f.severity == severity]
        blocks += [
            Heading(f"{severity.value.capitalize()} findings"),
            Table(headers, _finding_rows(a, chosen)),
        ]
    by_rule: dict[str, list[str]] = {}
    for f in findings:
        for ref in dict.fromkeys([f.rule_ref, *f.related]):
            by_rule.setdefault(ref, []).append(f.id)
    bound = _bound_to(a.core.policy)
    inventory = tuple(
        _inventory_row(acl_name, rule, bound, by_rule)
        for acl_name, rules in a.core.policy.acls.items()
        for rule in rules
    )
    blocks += [
        Heading("Rule inventory"),
        Para(
            "Every rule of the source with the justification found in its remark. To support "
            "evidence for a business-need review (PCI DSS 4.0 requirement 1.2.5), the rule "
            "owners confirm or complete the justification column."
        ),
        Table(
            ("Rule", "Bound to", "Line", "Action", "Match", "Justification", "Findings"),
            inventory,
        ),
    ]
    return Section(5, "Findings", tuple(blocks))


# -- 6 exorcism ledger -------------------------------------------------------------------------

_LEDGER_HEADERS = (
    "ID",
    "Class",
    "Reason",
    "Affected match",
    "Context",
    "Old decision",
    "New decision",
    "Finding",
    "Approval",
)


def _approval(entry: LedgerEntry) -> str:
    if entry.approval == Approval.pending:
        return "pending"
    who = f" by {entry.approver}" if entry.approver else ""
    when = f" on {entry.decided_at}" if entry.decided_at else ""
    return f"{entry.approval.value}{who}{when}"


def ledger_rows(entries: list[LedgerEntry]) -> tuple[tuple[str, ...], ...]:
    """One row per ledger entry: class, reason, affected flows, decisions and approval."""
    return tuple(
        (
            e.id,
            e.entry_class.value + (" (informational)" if e.informational else ""),
            e.reason,
            e.affected,
            e.context,
            e.old_action.value,
            e.new_action.value,
            e.finding_ref or "none",
            _approval(e),
        )
        for e in entries
    )


def _tally(entries: list[LedgerEntry]) -> str:
    counts = Counter(e.approval for e in entries)
    return (
        f"{len(entries)} entries: {counts.get(Approval.pending, 0)} pending, "
        f"{counts.get(Approval.accepted, 0)} accepted, {counts.get(Approval.rejected, 0)} rejected."
    )


def ledger_section(a: Assessment) -> Section:
    """Section 6: every ledger entry of the baseline, and of the tightened candidate if any."""
    blocks: list[Block] = [
        Heading("Baseline (like for like)"),
        Para(
            "Each entry is a place where the candidate does not behave exactly like the source, "
            "or where equivalence rests on a separate argument. A pending entry blocks a GO "
            "verdict. " + _tally(a.ledger)
        ),
        Table(_LEDGER_HEADERS, ledger_rows(a.ledger), empty="The ledger is empty."),
    ]
    if a.tightened is not None:
        blocks += [
            Heading("Tightened candidate (separate change)"),
            Para(
                "A tightening is its own change with its own ledger and proof. "
                + _tally(a.tightened.ledger)
            ),
            Table(_LEDGER_HEADERS, ledger_rows(a.tightened.ledger), empty="The ledger is empty."),
        ]
    return Section(6, "Exorcism ledger", tuple(blocks))
