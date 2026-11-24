"""Task 7: the Grimoire report in Markdown and HTML (migration-governance requirements 4.1 to 4.6).

The ten sections in order, the zone mapping and matrix, the rule inventory with its justification
column, the control mapping with the "supports evidence for" wording, the secret-rotation advice,
redacted text only, escaping of everything that comes from the input, and the governance tables
checked against the steering document. Determinism (property P11) is in
``test_report_determinism.py``.
"""

from __future__ import annotations

import re
from datetime import timedelta
from pathlib import Path

import pytest

from necro import report
from necro.assessment import (
    BASELINE_OUTPUT,
    SOURCE_OUTPUT,
    TIGHTENED_OUTPUT,
    Assessment,
    Core,
    assemble,
)
from necro.controls import (
    CONTROL_MAP,
    PHASES,
    SECRET_ROTATION_NOTE,
    SECTION_TITLES,
    SEVERITY_MODEL,
    plain,
)
from necro.findings import Severity
from necro.gate_models import ChangeMeta, RunbookOverrides, Sidecar, Waiver
from necro.gates import CI_BUDGET
from necro.ledger import Approval
from necro.report_doc import md_cell, md_text, one_line
from necro.tighten import ApprovalDecision, Choice
from tests.gov_helpers import (
    BROKEN,
    FAR,
    FORBIDDEN,
    GO_CONFIG,
    NAMES,
    NOW,
    STEERING,
    TODAY,
    assessment_of,
    core_for,
    core_of,
    decisions,
    full_sidecar,
    golden_of,
    secret_tokens,
    text_of,
)

NECRO = Path(report.__file__).parent
HEADING = re.compile(r"^## (\d+)\. (.+)$")
REPORT_MODULES = (
    "assessment.py",
    "audit.py",
    "controls.py",
    "report.py",
    "report_doc.py",
    "report_findings.py",
    "report_proof.py",
    "report_verdict.py",
    "rule_text.py",
    "runbook.py",
    "runbook_commands.py",
    "runbook_doc.py",
    "secret_counts.py",
    "zone_matrix.py",
)


def headings(markdown: str) -> list[tuple[int, str]]:
    """The numbered ``##`` headings outside code fences."""
    found: list[tuple[int, str]] = []
    fenced = False
    for line in markdown.splitlines():
        if line.startswith("```"):
            fenced = not fenced
        elif not fenced and (m := HEADING.match(line)):
            found.append((int(m.group(1)), m.group(2)))
    return found


def first_page(markdown: str) -> str:
    return markdown.split("\n## 2. ", 1)[0]


def broken_core() -> Core:
    text = (BROKEN / "ios-unsupported-constructs.cfg").read_text(encoding="utf-8")
    return core_for(text, "ios", name="broken.cfg")


def unparsed_lines(core: Core) -> list[int]:
    return [r.line_no for r in core.policy.line_records if r.classification == "unparsed"]


# -- the ten sections, in order ----------------------------------------------------------------


@pytest.mark.parametrize("name", NAMES)
def test_the_ten_sections_appear_in_the_governance_order(name: str) -> None:
    a = assessment_of(name)
    assert headings(report.render_md(a)) == list(enumerate(SECTION_TITLES, start=1))
    page = report.render_html(a)
    assert re.findall(r"<h2>(\d+)\. ([^<]+)</h2>", page) == [
        (str(n), t) for n, t in enumerate(SECTION_TITLES, start=1)
    ]
    assert re.findall(r'<section id="s(\d+)">', page) == [str(n) for n in range(1, 11)]


def test_the_section_titles_are_the_ones_in_the_governance_steering() -> None:
    text = STEERING.read_text(encoding="utf-8")
    block = text.split("## 5. Grimoire report: required sections (in order)", 1)[1]
    names = re.findall(r"^\d+\. \*\*([^*]+)\*\*", block, flags=re.MULTILINE)
    assert [n.lower().replace("&", "and").rstrip(":") for n in names] == [
        "verdict page",
        "audit header",
        "scope and assumptions",
        "coverage",
        "findings",
        "exorcism ledger",
        "proof of life",
        "zone-to-zone matrix",
        "runbook",
        "appendix",
    ]
    assert SECTION_TITLES[0] == "Verdict"
    assert [t.lower() for t in SECTION_TITLES[1:]] == [
        n.lower().replace("&", "and").rstrip(":") for n in names[1:]
    ]


@pytest.mark.parametrize("name", NAMES)
def test_markdown_and_html_carry_the_same_tables_and_blocks(name: str) -> None:
    a = assessment_of(name)
    md, page = report.render_md(a), report.render_html(a)
    assert len(re.findall(r"^\|---", md, flags=re.MULTILINE)) == page.count("<table>")
    assert len(re.findall(r"^### ", md, flags=re.MULTILINE)) == page.count("<h3>")
    fences = [line for line in md.splitlines() if line.startswith("```")]
    assert len(fences) // 2 == page.count("<pre>")


def test_the_title_names_the_input() -> None:
    markdown = report.render_md(assessment_of("pix-2006-hq"))
    assert markdown.startswith("# Grimoire: migration evidence report: pix-2006-hq.cfg\n")


# -- first page: verdict, blocking reasons, waivers, change record -----------------------------


def test_the_first_page_has_the_verdict_gates_blocking_reasons_and_rotation_advice() -> None:
    a = assessment_of("pix-2006-hq")
    page = first_page(report.render_md(a))
    assert f"Readiness verdict: {a.verdict.value}." in page
    for gate in a.verdict.gates:
        assert re.search(rf"^\| {gate.gate} \| [^|]+ \| {gate.status} \|", page, flags=re.MULTILINE)
    assert a.verdict.blocking_reasons
    for reason in a.verdict.blocking_reasons:
        assert md_text(f"- {reason}") in page
    assert SECRET_ROTATION_NOTE in page
    for field in ("Change ID", "Peer reviewer", "CAB approval reference"):
        assert f"| {field} | not recorded |" in page


def test_blocking_reasons_come_in_gate_order() -> None:
    reasons = assessment_of("ios-12-edge").verdict.blocking_reasons
    gates = [r.split(":", 1)[0] for r in reasons]
    assert gates == sorted(gates) and len(set(gates)) > 1


def test_every_waiver_in_use_and_the_change_record_are_on_the_first_page() -> None:
    core = broken_core()
    lines = unparsed_lines(core)
    assert len(lines) == 6
    waivers = [
        Waiver(
            target=f"line:{n}",
            reason=f"reviewed with the rule owner, item {n}",
            approver="Sam Waiver-Approver",
            expires_on=FAR,
        )
        for n in lines
    ]
    sidecar = full_sidecar(core).model_copy(update={"waivers": waivers})
    a = assemble(core, sidecar, TODAY, NOW)
    page = first_page(report.render_md(a))
    assert len(a.verdict.waivers_used) == len(lines)
    for n in lines:
        row = f"| line:{n} | Sam Waiver-Approver | {FAR.isoformat()} | reviewed with the rule owner"
        assert row in page
    assert a.verdict.conditions
    for condition in a.verdict.conditions:
        assert md_text(f"- {condition}") in page
    for needle in ("CHG-1001", "Robin Reviewer", "Alex Engineer", "CAB-77"):
        assert needle in page


def test_the_change_record_and_approvers_are_in_the_first_html_section() -> None:
    a = assessment_of("pix-2006-hq", full_sidecar(core_of("pix-2006-hq")))
    section_one = report.render_html(a).split('<section id="s2">', 1)[0]
    assert "CHG-1001" in section_one and "Dana Approver" in section_one


@pytest.mark.parametrize("name", NAMES)
def test_the_governance_steps_say_what_is_evidenced_and_what_a_human_owes(name: str) -> None:
    md = report.render_md(assessment_of(name))
    steps = md.split("### Governance steps", 1)[1].split("### Shared secrets", 1)[0]
    rows = re.findall(r"^\| (P\d+) \| [^|]+ \| ([^|]+) \| ", steps, flags=re.MULTILINE)
    assert [r[0] for r in rows] == [p.id for p in PHASES]
    statuses = {r[1] for r in rows}
    assert "Owed by a human" in statuses and "Evidenced by the tool" in statuses


# -- coverage ----------------------------------------------------------------------------------


def test_every_unparsed_line_is_listed_with_its_reason_and_status() -> None:
    core = broken_core()
    md = report.render_md(assemble(core, Sidecar(), TODAY, NOW))
    coverage = md.split("## 4. Coverage", 1)[1].split("## 5. Findings", 1)[0]
    records = [r for r in core.policy.line_records if r.classification == "unparsed"]
    assert len(records) == 6
    for record in records:
        pattern = (
            rf"^\| {record.line_no} \| unparsed \| yes \| {re.escape(record.reason)} \| (.+?) \|"
        )
        row = re.search(pattern, coverage, flags=re.MULTILINE)
        assert row and row.group(1) == "open: blocks the verdict"


def test_a_waived_line_names_the_approver_and_an_expired_waiver_shows_as_expired() -> None:
    core = broken_core()
    first, second = unparsed_lines(core)[:2]
    sidecar = Sidecar(
        waivers=[
            Waiver(target=f"line:{first}", reason="accepted", approver="Pat", expires_on=TODAY),
            Waiver(
                target=f"line:{second}",
                reason="old",
                approver="Pat",
                expires_on=TODAY - timedelta(days=1),
            ),
        ]
    )
    md = report.render_md(assemble(core, sidecar, TODAY, NOW))
    assert "waived by Pat until 2026-11-24: accepted" in md
    assert f"the waiver for line:{second} expired on 2026-11-23" in md


def test_the_line_counts_add_up_to_the_total() -> None:
    a = assessment_of("asa-8.2-branch")
    md = report.render_md(a)
    table = md.split("### Line classification", 1)[1].split("Security-relevant lines:", 1)[0]
    rows = re.findall(r"^\| ([a-z-]+) \| (\d+) \|", table, flags=re.MULTILINE)
    counts = {name: int(value) for name, value in rows}
    assert counts.pop("total") == sum(counts.values()) == a.core.coverage.total_lines


# -- findings, rule inventory, ledger ----------------------------------------------------------


@pytest.mark.parametrize("name", NAMES)
def test_every_finding_and_every_rule_is_in_the_report(name: str) -> None:
    a = assessment_of(name)
    findings = report.render_md(a).split("## 5. Findings", 1)[1].split("## 6.", 1)[0]
    for finding in a.core.findings:
        assert f"| {finding.id} | {finding.type.value} |" in findings
    inventory = findings.split("### Rule inventory", 1)[1]
    remarks = 0
    missing = False
    for rules in a.core.policy.acls.values():
        for rule in rules:
            assert f"| {md_cell(rule.id)} |" in inventory
            if rule.remark.strip():
                remarks += 1
                assert md_cell(rule.remark.strip()) in inventory
            else:
                missing = True
    assert ("No justification recorded" in inventory) == missing
    assert remarks or missing


def test_findings_are_grouped_by_severity_with_a_decision_column() -> None:
    core = core_of("pix-2006-hq")
    md = report.render_md(assessment_of("pix-2006-hq", full_sidecar(core)))
    order = [md.index(f"### {s.value.capitalize()} findings") for s in Severity]
    assert order == sorted(order)
    assert "| Decision |" in md
    critical = next(f for f in core.findings if f.severity == Severity.critical)
    assert f"| {critical.id} |" in md and "Accepted by Dana Approver until 2027-12-31" in md
    assert "Open: fix, accept with an expiry, or carry forward" in report.render_md(
        assessment_of("pix-2006-hq")
    )


def test_the_severity_model_and_the_control_mapping_are_in_the_report() -> None:
    md = report.render_md(assessment_of("pix-2006-hq"))
    for row in SEVERITY_MODEL:
        assert md_cell(plain(row.meaning)) in md and md_cell(plain(row.examples)) in md
    for control in CONTROL_MAP:
        assert md_cell(control.framework) in md and md_cell(control.evidence) in md
    assert "supports evidence for" in md.lower()
    assert "decided by the organization's own assessor" in md


@pytest.mark.parametrize("name", NAMES)
def test_every_ledger_entry_is_in_the_report_with_its_class_and_a_pending_approval(
    name: str,
) -> None:
    a = assessment_of(name)
    ledger = report.render_md(a).split("## 6. Exorcism ledger", 1)[1].split("## 7.", 1)[0]
    assert a.ledger
    for entry in a.ledger:
        pattern = rf"^\| {entry.id} \| {re.escape(entry.entry_class.value)}[^|]* \|(.+)$"
        row = re.search(pattern, ledger, flags=re.MULTILINE)
        assert row and row.group(1).rstrip().endswith("| pending |")


def test_a_ledger_decision_from_the_sidecar_shows_with_its_approver_and_date() -> None:
    core = core_of("pix-2006-hq")
    sidecar = Sidecar(ledger_decisions=decisions(core, "Quinn Approver"))
    md = report.render_md(assemble(core, sidecar, TODAY, NOW))
    ledger = md.split("## 6. Exorcism ledger", 1)[1].split("## 7.", 1)[0]
    rows = [line for line in ledger.splitlines() if re.match(r"^\| LED-\d+ \|", line)]
    assert len(rows) == len(core.emission.ledger)
    assert all(
        row.rstrip().endswith("| accepted by Quinn Approver on 2026-11-23 |") for row in rows
    )


# -- proof, matrix, runbook, appendix ----------------------------------------------------------


@pytest.mark.parametrize("name", NAMES)
def test_the_proof_section_has_the_seed_examples_coverage_and_golden_results(name: str) -> None:
    a = assessment_of(name)
    proof = report.render_md(a).split("## 7. Proof of Life", 1)[1].split("## 8.", 1)[0]
    assert a.core.proof is not None
    assert f"Seed {a.core.seed}. {a.core.budget} examples per context" in proof
    for context in a.core.proof.contexts:
        assert f"| {context.context} |" in proof
    golden = a.core.proof.golden
    assert f"{golden.passed} of {golden.total} hand-verified flows pass" in proof
    for vector in golden_of(name):
        assert f"| {vector.id} |" in proof


def test_a_missing_proof_is_stated_and_blocks_g4() -> None:
    bad = golden_of("pix-2006-hq")[0].model_copy(update={"context": "nowhere:in"})
    core = core_for(text_of("pix-2006-hq"), "pix", golden=(bad,))
    a = assemble(core, Sidecar(), TODAY, NOW)
    assert core.proof is None and core.proof_error
    md = report.render_md(a)
    assert "The equivalence proof did not run" in md
    assert "G4: no equivalence proof was run" in md
    assert a.verdict.value == "NO-GO"


@pytest.mark.parametrize("name", NAMES)
def test_the_matrix_section_has_before_and_after(name: str) -> None:
    md = report.render_md(assessment_of(name))
    matrix = md.split("## 8. Zone-to-zone matrix", 1)[1].split("## 9.", 1)[0]
    assert "### Before (source policy)" in matrix and "### After (baseline candidate)" in matrix
    assert "| From zone | To zone | Allowed services |" in matrix
    assert "### Differences, baseline candidate" in matrix


def test_the_zone_mapping_table_has_interface_nameif_level_zone_and_the_address_model() -> None:
    md = report.render_md(assessment_of("asa-8.2-branch"))
    assert (
        "| Interface | Nameif | Security level | PAN-OS zone | Placeholder port | Address |" in md
    )
    assert "| Ethernet0/0 | outside | 0 | outside | ethernet1/1 | 198.51.100.2/29 |" in md
    assert "mapped (global) addresses" in md
    ios = report.render_md(assessment_of("ios-12-edge"))
    assert "n/a (no security levels)" in ios and "applied as written" in ios


def test_the_appendix_has_the_config_the_redacted_source_and_the_control_mapping() -> None:
    a = assessment_of("pix-2006-hq")
    appendix = report.render_md(a).split("## 10. Appendix", 1)[1]
    assert a.core.emission.text.rstrip("\n") in appendix
    assert a.core.redacted_source.rstrip("\n") in appendix
    assert f"({BASELINE_OUTPUT})" in appendix
    assert "### Control mapping (supports evidence for)" in appendix
    assert TIGHTENED_OUTPUT not in appendix


@pytest.mark.parametrize("name", NAMES)
def test_the_runbook_section_is_the_runbook(name: str) -> None:
    a = assessment_of(name)
    section = report.render_md(a).split("## 9. Runbook", 1)[1].split("## 10.", 1)[0]
    for item in a.runbook.commands.target:
        assert md_cell(item.command) in section
    assert "### Rollback (P9)" in section and "### Pre-cutover checks (P6)" in section


# -- redaction, wording, escaping --------------------------------------------------------------


@pytest.mark.parametrize("name", NAMES)
def test_no_secret_value_appears_in_any_output(name: str) -> None:
    a = assessment_of(name, full_sidecar(core_of(name)))
    tokens = secret_tokens(text_of(name))
    assert tokens or name == "asa-9.8-dc"
    outputs = [
        report.render_md(a),
        report.render_html(a),
        a.verdict.model_dump_json(),
        a.runbook.model_dump_json(),
        a.core.emission.text,
    ]
    for token in tokens:
        for output in outputs:
            assert token not in output, token
    assert "<redacted>" in outputs[0] and "&lt;redacted&gt;" in outputs[1]


@pytest.mark.parametrize("name", NAMES)
def test_the_report_never_says_compliant_or_safe_to_deploy(name: str) -> None:
    for sidecar in (Sidecar(), full_sidecar(core_of(name))):
        a = assessment_of(name, sidecar)
        assert not FORBIDDEN.search(report.render_md(a))
        assert not FORBIDDEN.search(report.render_html(a))


def test_the_report_modules_never_use_the_forbidden_words() -> None:
    for module in REPORT_MODULES:
        assert not FORBIDDEN.search((NECRO / module).read_text(encoding="utf-8")), module


def test_hostile_text_cannot_add_markup_or_a_heading() -> None:
    core = core_of("pix-2006-hq")
    sidecar = Sidecar(
        change=ChangeMeta(
            change_id="<script>alert(1)</script>",
            requested_by="Eve|Mallory\n## 11. A forged section",
            peer_reviewer='"><img src=x onerror=alert(1)>',
            cab_reference="CAB&1 `tick`",
        ),
        ledger_decisions={
            e.id: ApprovalDecision(
                approval=Approval.accepted, approver="<b>Bob</b>", decided_at="d|e"
            )
            for e in core.emission.ledger
        },
        runbook=RunbookOverrides(rollback_triggers=["# not a heading\n| not | a | table |"]),
    )
    a = assemble(core, sidecar, TODAY, NOW)
    md, page = report.render_md(a), report.render_html(a)
    assert headings(md) == list(enumerate(SECTION_TITLES, start=1))
    assert not re.search(r"(?<!\\)<(script|img|b)\b", first_page(md))
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    for tag in ("<script", "<img", "<b>"):
        assert tag not in page
    assert "Eve\\|Mallory ## 11. A forged section" in md  # one line, pipe escaped


def test_the_html_is_self_contained_and_print_ready() -> None:
    page = report.render_html(assessment_of("pix-2006-hq"))
    assert page.startswith("<!DOCTYPE html>\n") and page.endswith("</html>\n")
    assert "default-src 'none'" in page and "@media print" in page
    assert not re.search(r"<script|<link|<img|<iframe|src=|href=|https?://", page)
    assert "break-before: page" in page


def test_the_markdown_helpers_escape_for_markdown() -> None:
    assert one_line(" a \n\t b  ") == "a b"
    assert md_text("x <redacted> y") == "x \\<redacted> y"
    assert md_cell("a|b\nc") == "a\\|b c"


# -- the governance tables mirror the steering document ----------------------------------------


def steering_rows() -> list[list[str]]:
    rows = []
    for line in STEERING.read_text(encoding="utf-8").splitlines():
        if line.startswith("|") and not set(line) <= set("|-: "):
            rows.append([c.strip() for c in line.strip().strip("|").split("|")])
    return rows


def test_the_phase_table_matches_the_steering_document() -> None:
    rows = [r for r in steering_rows() if re.fullmatch(r"P\d+", r[0])]
    assert [(r[0], r[1], r[3], r[4]) for r in rows] == [tuple(p) for p in PHASES]


def test_the_severity_table_matches_the_steering_document() -> None:
    names = {s.value for s in Severity}
    rows = [r for r in steering_rows() if r[0] in names and len(r) == 3]
    assert [tuple(r) for r in rows] == [tuple(s) for s in SEVERITY_MODEL]


def test_the_control_mapping_matches_the_steering_document() -> None:
    starts = ("PCI DSS", "NIST SP", "ISO/IEC", "CIS Controls")
    rows = [r for r in steering_rows() if r[0].startswith(starts) and len(r) == 3]
    assert [tuple(r) for r in rows] == [tuple(c) for c in CONTROL_MAP]


# -- a tightened candidate is a separate artifact with its own ledger and proof -----------------


def tightened_core() -> Core:
    return core_for(
        text_of("pix-2006-hq"),
        "pix",
        name="pix-2006-hq.cfg",
        golden=tuple(golden_of("pix-2006-hq")),
        choices=[Choice(finding_id="AUT-0007")],
    )


def test_a_tightened_candidate_has_its_own_ledger_proof_matrix_and_hash() -> None:
    core = tightened_core()
    assert core.tightened is not None
    a = assemble(core, Sidecar(), TODAY, NOW)
    assert a.tightened is not None
    md = report.render_md(a)
    pattern = r"^## (\d+)\. [^\n]*\n(.*?)(?=^## \d+\. |\Z)"
    sections = dict(re.findall(pattern, md, flags=re.S | re.M))
    assert "### Tightened candidate (separate change)" in sections["1"]
    assert "### Tightened candidate (separate change)" in sections["6"]
    assert "### Tightened candidate (separate proof)" in sections["7"]
    assert "### After (tightened candidate, separate change)" in sections["8"]
    assert f"({TIGHTENED_OUTPUT})" in sections["10"]
    ledger = md.split("## 6. Exorcism ledger", 1)[1].split("## 7.", 1)[0]
    baseline_part, tightened_part = ledger.split("### Tightened candidate")
    assert "TGT-0001" in tightened_part and "TGT-0001" not in baseline_part
    assert core.tightened.artifact.emission.text.rstrip("\n") in md.split("## 10.", 1)[1]
    outputs = a.audit.outputs
    assert TIGHTENED_OUTPUT in outputs and BASELINE_OUTPUT in outputs and SOURCE_OUTPUT in outputs
    assert outputs[TIGHTENED_OUTPUT] != outputs[BASELINE_OUTPUT]
    assert "Never use it without that ledger" in md


def test_a_tightening_leaves_the_baseline_candidate_and_verdict_alone() -> None:
    tight = assemble(tightened_core(), Sidecar(), TODAY, NOW)
    base = assemble(core_of("pix-2006-hq"), Sidecar(), TODAY, NOW)
    assert tight.core.emission.text == base.core.emission.text
    assert tight.verdict.value == base.verdict.value
    assert tight.tightened is not None and tight.tightened.ledger[0].id == "TGT-0001"
    assert base.tightened is None and "Tightened candidate" not in report.render_md(base)


def test_a_pending_tightening_entry_blocks_go_for_the_tightened_candidate_only() -> None:
    a = assemble(tightened_core(), Sidecar(), TODAY, NOW)
    assert a.tightened is not None
    assert any("TGT-0001" in r for r in a.tightened.verdict.blocking_reasons)
    assert not any("TGT-0001" in r for r in a.verdict.blocking_reasons)


# -- GO and CONDITIONAL reports ----------------------------------------------------------------


def go_assessment(**change: str) -> Assessment:
    """The lab config at the ci budget with every decision recorded."""
    core = core_for(GO_CONFIG, "asa", budget=CI_BUDGET)
    return assemble(core, full_sidecar(core, **change), TODAY, NOW)


def test_a_go_report_says_go_with_no_blocking_reasons() -> None:
    a = go_assessment()
    assert a.verdict.value == "GO", a.verdict.blocking_reasons
    page = first_page(report.render_md(a))
    assert "Readiness verdict: GO." in page and "### Blocking reasons\n\nNone." in page
    assert "No waivers are in use." in page


def test_a_four_eyes_violation_is_conditional_and_on_the_first_page() -> None:
    a = go_assessment(peer_reviewer="alex  engineer")
    assert a.verdict.value == "CONDITIONAL"
    page = first_page(report.render_md(a))
    assert "Readiness verdict: CONDITIONAL." in page and "four-eyes" in page
