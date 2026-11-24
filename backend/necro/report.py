"""The Grimoire: the migration evidence report (migration-governance requirements 3 and 4).

``render_md`` and ``render_html`` produce the ten sections of governance steering section 5, in
that order, from one ``Assessment``. They share one document model (``report_doc``), so both
formats carry the same content. There is no template engine, and every value from the input is
escaped by the renderer.

Determinism (property P11, requirement 3.2): the same input, options and seed give a byte-identical
body. The only value that changes between runs is the UTC time in the audit header, and
``mask_time=True`` replaces it so that the body can be compared and hashed (``body_sha256``).

Only redacted text appears in the report: the source config in the appendix is rebuilt from the
parser's line records, which are made from the redacted text (requirement 3.3).
"""

from __future__ import annotations

from necro.assessment import BASELINE_OUTPUT, TIGHTENED_OUTPUT, Assessment
from necro.audit import sha256_text
from necro.controls import CONTROL_MAP, CONTROL_NOTE, PHASES, plain
from necro.report_doc import Block, Code, Heading, Para, Section, Table
from necro.report_doc import render_html as _render_html
from necro.report_doc import render_md as _render_md
from necro.report_findings import coverage_section, findings_section, ledger_section
from necro.report_proof import matrix_section, proof_section
from necro.report_verdict import audit_section, scope_section, verdict_section
from necro.runbook_doc import runbook_blocks

TITLE = "Grimoire: migration evidence report"


def title_of(a: Assessment) -> str:
    return f"{TITLE}: {a.core.input_name}"


def runbook_section(a: Assessment) -> Section:
    """Section 9: pre-checks, cutover, verification commands, rollback and post-checks."""
    return Section(9, "Runbook", runbook_blocks(a.runbook))


def appendix_section(a: Assessment) -> Section:
    """Section 10: control mapping, the governance phases, the configs and the redacted source."""
    core = a.core
    blocks: list[Block] = [
        Heading("Control mapping (supports evidence for)"),
        Table(
            ("Framework", "Control", "How this report supports evidence"),
            tuple((r.framework, r.controls, r.evidence) for r in CONTROL_MAP),
        ),
        Para(CONTROL_NOTE),
        Heading("Governance phases"),
        Table(
            ("Phase", "Name", "Exit criterion", "Tool support"),
            tuple((p.id, p.name, plain(p.exit_criterion), plain(p.tool_support)) for p in PHASES),
        ),
        Heading(f"PAN-OS candidate config, baseline ({BASELINE_OUTPUT})"),
        Para(
            "A candidate for humans to review. It is never pushed to a device. Read it together "
            "with the ledger in section 6."
        ),
        Code(core.emission.text),
    ]
    if core.tightened is not None:
        blocks += [
            Heading(f"PAN-OS candidate config, tightened ({TIGHTENED_OUTPUT})"),
            Para(
                "A separate change with its own ledger (section 6) and proof (section 7). Never "
                "use it without that ledger."
            ),
            Code(core.tightened.artifact.emission.text),
        ]
    blocks += [
        Heading("Source config, redacted"),
        Para(
            "Secrets are replaced with <redacted>. The original is not part of any artifact. "
            "Rotate the redacted secrets at decommission."
        ),
        Code(core.redacted_source),
    ]
    return Section(10, "Appendix", tuple(blocks))


def build_sections(a: Assessment, *, mask_time: bool = False) -> list[Section]:
    """The ten sections, in the order of governance steering section 5."""
    return [
        verdict_section(a),
        audit_section(a, mask_time=mask_time),
        scope_section(a),
        coverage_section(a),
        findings_section(a),
        ledger_section(a),
        proof_section(a),
        matrix_section(a),
        runbook_section(a),
        appendix_section(a),
    ]


def render_md(a: Assessment, *, mask_time: bool = False) -> str:
    """The Grimoire as Markdown."""
    return _render_md(title_of(a), build_sections(a, mask_time=mask_time))


def render_html(a: Assessment, *, mask_time: bool = False) -> str:
    """The Grimoire as one print-friendly HTML document with no external assets."""
    return _render_html(title_of(a), build_sections(a, mask_time=mask_time))


def body_sha256(a: Assessment) -> str:
    """SHA-256 of the Markdown body with the time masked: equal for equal input and seed."""
    return sha256_text(render_md(a, mask_time=True))
