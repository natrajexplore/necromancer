"""The governance tables of ``.kiro/steering/migration-governance.md`` as constants.

The Grimoire prints them (phases, severity model, control mapping). They are copied cell for cell
from the steering document, and ``tests/test_report.py`` parses that document and asserts that each
row here matches it, so the two cannot drift apart (migration-governance design, "Report").

Wording rule: the tool "supports evidence for" a control and makes no stronger claim.
Control applicability is always decided by the organization's own assessor.
"""

from __future__ import annotations

from typing import NamedTuple


class Phase(NamedTuple):
    id: str
    name: str
    exit_criterion: str
    tool_support: str


class SeverityRow(NamedTuple):
    severity: str
    meaning: str
    examples: str


class ControlRow(NamedTuple):
    framework: str
    controls: str
    evidence: str


PHASES: tuple[Phase, ...] = (
    Phase(
        "P0",
        "Scope & inventory",
        "Signed scope listing in-scope and out-of-scope features (VPN, dynamic routing, AAA, "
        "IPS, QoS are **out** of policy migration)",
        "Exhume detects version, mode and features. Out-of-scope features are listed",
    ),
    Phase(
        "P1",
        "Baseline capture",
        "Baseline is less than 7 days old at cutover, or re-captured",
        "Input SHA-256 in every report. Hit counts optional (Phase 2)",
    ),
    Phase(
        "P2",
        "Pre-migration hygiene (autopsy)",
        "Every critical/high finding has a decision: fix, accept (with an expiry) or carry forward",
        "Autopsy findings with severity, plus a decision column",
    ),
    Phase(
        "P3",
        "Translation (like-for-like)",
        "Candidate config with zero unexplained divergences",
        "Resurrect (baseline output)",
    ),
    Phase(
        "P4",
        "Validation",
        "Verdict = GO, or CONDITIONAL with named waivers",
        "Gates engine + Proof of Life",
    ),
    Phase(
        "P5",
        "Peer review & CAB",
        "CAB approval reference recorded",
        "Grimoire is the evidence pack. The change ID and approver are recorded on the verdict",
    ),
    Phase(
        "P6",
        "Pre-cutover checks",
        "All pre-checks ticked, with evidence attached",
        "Runbook generates the pre-check list",
    ),
    Phase(
        "P7",
        "Cutover",
        "All verification flows match the expected decisions",
        "Runbook generates both command lists from the golden flows plus a sample of oracle flows",
    ),
    Phase(
        "P8",
        "Post-checks & hypercare",
        "Owners sign off. No unexplained denies",
        "Report lists the rules to watch (ledger entries, low-coverage rules)",
    ),
    Phase(
        "P9",
        "Rollback",
        "Rollback tested or walked through before the window",
        "Runbook includes a rollback section with triggers",
    ),
    Phase(
        "P10",
        "Optimization (separate changes)",
        "Each tightening change has a ledger and a passing proof",
        "Tighten produces a separate output and ledger",
    ),
    Phase(
        "P11",
        "Decommission",
        "Decommission record",
        "Report checklist item",
    ),
)

SEVERITY_MODEL: tuple[SeverityRow, ...] = (
    SeverityRow(
        "critical",
        "Exposure from an untrusted zone (security level 0, or an interface named "
        "outside/internet/partner) to sensitive services, or `permit ip any any` from untrusted",
        "telnet/rsh/tftp/snmp v1-v2c/RDP/SMB from outside, any-any from outside",
    ),
    SeverityRow(
        "high",
        "Broad or insecure access between internal zones; cleartext management; unfiltered "
        "interfaces",
        "any-any from DMZ, ftp from outside, telnet on vty, interface without an ACL",
    ),
    SeverityRow(
        "medium",
        "Hygiene that hides intent or risk",
        "shadowed/redundant rules, partial overlaps with the opposite action, return-traffic rules",
    ),
    SeverityRow(
        "low",
        "Housekeeping",
        "unused objects, rules without a remark (no business justification)",
    ),
)

CONTROL_MAP: tuple[ControlRow, ...] = (
    ControlRow(
        "PCI DSS v4.0",
        "1.2.1 configuration standards for NSCs; 1.2.2 changes approved per change control; "
        "1.2.5 services/ports identified, approved, with business need; 1.2.6 insecure services "
        "secured; 1.2.7 NSC rules reviewed at least every six months; 1.2.8 config files secured",
        "Rule inventory with remark/justification column, insecure-service findings, proof plus "
        "change record fields, redacted config handling",
    ),
    ControlRow(
        "NIST SP 800-41 Rev. 1",
        "Firewall policy lifecycle (plan, configure, test, deploy, manage); default-deny",
        "Phases P0–P11, explicit final deny, test evidence",
    ),
    ControlRow(
        "NIST SP 800-53 Rev. 5",
        "CM-3 configuration change control; CM-4 impact analysis; AC-4 information flow "
        "enforcement; SC-7 boundary protection",
        "Ledger (impact of each change), equivalence proof, zone-to-zone matrix",
    ),
    ControlRow(
        "ISO/IEC 27001:2022 Annex A",
        "8.9 configuration management; 8.20 networks security; 8.32 change management",
        "Deterministic baseline, hashes, change record, gates",
    ),
    ControlRow(
        "CIS Controls v8",
        "4 secure configuration; 12 network infrastructure management; 13 network monitoring "
        "and defense",
        "Insecure-management findings, logging on all rules, final deny with logging",
    ),
)

CONTROL_NOTE = (
    "This table is guidance for auditors. It lists what this report supports evidence for. "
    "Control applicability is always decided by the organization's own assessor."
)

SECRET_ROTATION_NOTE = (
    "Shared secrets found on the source device (pre-shared keys, SNMP communities, TACACS and "
    "RADIUS keys, passwords) were redacted before analysis and are not in this report. "
    "Consider them exposed and rotate them at decommission."
)

# The section titles of governance steering section 5, in order.
SECTION_TITLES: tuple[str, ...] = (
    "Verdict",
    "Audit header",
    "Scope and assumptions",
    "Coverage",
    "Findings",
    "Exorcism ledger",
    "Proof of Life",
    "Zone-to-zone matrix",
    "Runbook",
    "Appendix",
)


def plain(text: str) -> str:
    """A steering table cell without its Markdown emphasis and code marks."""
    return text.replace("**", "").replace("`", "")
