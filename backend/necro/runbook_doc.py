"""The runbook as document blocks: section 9 of the Grimoire, and the per-sample snapshots."""

from __future__ import annotations

from necro.report_doc import Block, Bullets, Heading, Para, Section, Table, render_md
from necro.runbook import Runbook, Step, Verification

RUNBOOK_SECTION = 9


def _steps(steps: list[Step]) -> Table:
    return Table(("Done", "ID", "Step"), tuple(("[ ]", s.id, s.text) for s in steps))


def _commands(items: list[Verification], *, with_note: bool) -> Table:
    headers = ("ID", "Origin", "Context", "Command", "Expected result")
    rows = []
    for item in items:
        expected = f"{item.expected} ({item.note})" if with_note and item.note else item.expected
        rows.append((item.id, item.origin, item.context, item.command, expected))
    return Table(headers, tuple(rows))


def runbook_blocks(rb: Runbook) -> tuple[Block, ...]:
    """Pre-checks, cutover, verification commands, rollback, post-checks and hypercare."""
    commands = rb.commands
    blocks: list[Block] = [
        Heading("Pre-cutover checks (P6)"),
        _steps(rb.prechecks),
        Heading("Cutover steps (P7)"),
        _steps(rb.cutover),
        Heading("Verification commands on the target (PAN-OS)"),
        Para(
            "Run each command in operational mode on the target after the commit. Each one is "
            "followed by the result it must give. Golden flows come first, then one oracle "
            "flow for every pair of source rule and candidate rule."
        ),
        _commands(commands.target, with_note=True),
    ]
    if commands.omitted:
        blocks.append(
            Para(f"{commands.omitted} further commands were left out by the cap of 200 commands.")
        )
    blocks.append(Heading("Verification commands on the source (ASA packet-tracer)"))
    if commands.source:
        blocks += [
            Para(
                "Run these on the source before the freeze ends, to compare with the baseline. "
                "packet-tracer exists from ASA 7.2."
            ),
            _commands(commands.source, with_note=False),
        ]
    else:
        blocks.append(Para(commands.source_note or "No source commands apply."))
    blocks.append(Heading("Checks that need another method"))
    blocks.append(
        Table(
            ("ID", "Origin", "Context", "Flow", "Expected result", "Why"),
            tuple((m.id, m.origin, m.context, m.flow, m.expected, m.why) for m in commands.manual),
        )
    )
    blocks += [
        Heading("Rollback (P9)"),
        Para(
            f"The change owner decides within {rb.decision_minutes} minutes of a trigger. Triggers:"
        ),
        Bullets(tuple(rb.rollback_triggers)),
        _steps(rb.rollback_steps),
        Heading("Post-checks and hypercare (P8, P11)"),
        _steps(rb.postchecks),
        Para(f"Hypercare lasts {rb.hypercare_days} business days. Rules and entries to watch:"),
        Table(("Subject", "Reason"), tuple((w.subject, w.reason) for w in rb.watch)),
    ]
    return tuple(blocks)


def render_runbook_md(rb: Runbook) -> str:
    """The runbook alone as Markdown (used for the golden snapshot of each sample)."""
    return render_md("Runbook", [Section(RUNBOOK_SECTION, "Runbook", runbook_blocks(rb))])
