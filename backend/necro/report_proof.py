"""Grimoire sections 7 and 8: the Proof of Life, and the zone-to-zone matrix."""

from __future__ import annotations

from collections.abc import Sequence

from necro.assessment import Assessment
from necro.gates import CI_BUDGET
from necro.golden import GoldenVector
from necro.ir import Decision
from necro.proof_types import ContextProof, Counterexample, ProofResult
from necro.report_doc import Block, Bullets, Heading, Para, Section, Table
from necro.rule_text import flow_text
from necro.zone_matrix import ZoneMatrix


def _decision(d: Decision) -> str:
    where = f" to {d.to_zone}" if d.to_zone else ""
    return f"{d.action.value} by {d.rule_id}{where}"


def _coverage(hit: int, rules: int, percent: float) -> str:
    return f"{hit}/{rules} ({percent:g}%)"


def _context_row(c: ContextProof) -> tuple[str, ...]:
    return (
        c.context,
        "yes" if c.implicit else "no",
        str(c.examples),
        "pass" if c.passed else "FAIL",
        str(c.ledger_covered),
        _coverage(c.original.hit, c.original.rules, c.original.percent),
        _coverage(c.resurrected.hit, c.resurrected.rules, c.resurrected.percent),
    )


def _counterexample_row(cx: Counterexample) -> tuple[str, ...]:
    return (
        cx.vector_id or cx.source,
        cx.context,
        flow_text(cx.flow),
        _decision(cx.original),
        _decision(cx.resurrected),
        cx.reason,
        ", ".join(cx.ledger_ids) or "none",
    )


def _golden_rows(vectors: Sequence[GoldenVector], failed: set[str]) -> tuple[tuple[str, ...], ...]:
    return tuple(
        (
            v.id,
            v.context,
            flow_text(v.flow),
            f"{v.expect_action.value} by {v.expect_rule} to {v.expect_to_zone}",
            "FAIL" if v.id in failed else "pass",
        )
        for v in vectors
    )


def _proof_blocks(
    proof: ProofResult | None, error: str, vectors: Sequence[GoldenVector]
) -> list[Block]:
    if proof is None:
        return [Para(f"The equivalence proof did not run: {error}.")]
    outcome = "PASS" if proof.passed else "FAIL"
    context_headers = (
        "Context",
        "Implicit",
        "Examples",
        "Result",
        "Ledger-covered",
        "Source rules hit",
        "Candidate rules hit",
    )
    blocks: list[Block] = [
        Para(
            f"Equivalence proof: {outcome}. Seed {proof.seed}. {proof.budget} examples per "
            f"context ({proof.examples} flows checked in total). A GO verdict needs at least "
            f"{CI_BUDGET} examples per context."
        ),
        Heading("Contexts"),
        Table(
            context_headers,
            tuple(_context_row(c) for c in proof.contexts),
            empty="No context was checked.",
        ),
        Heading("Divergences"),
        Table(
            ("Origin", "Context", "Flow", "Source", "Candidate", "Reason", "Ledger"),
            (_counterexample_row(proof.counterexample),) if proof.counterexample else (),
            empty="No divergence outside the ledger.",
        ),
    ]
    unhit = [
        f"{c.context}: {side} rules never hit: {', '.join(cover.unhit)}"
        for c in proof.contexts
        for side, cover in (("source", c.original), ("candidate", c.resurrected))
        if cover.unhit
    ]
    failed = {cx.vector_id for cx in proof.golden.failures}
    blocks += [
        Heading("Active rules not hit"),
        Bullets(tuple(unhit)) if unhit else Para("Every active rule was hit."),
        Heading("Golden flows"),
        Para(f"{proof.golden.passed} of {proof.golden.total} hand-verified flows pass."),
        Table(
            ("Flow", "Context", "Packet", "Expected on the source", "Result"),
            _golden_rows(vectors, failed),
            empty="No golden flows were supplied for this config.",
        ),
    ]
    return blocks


def proof_section(a: Assessment) -> Section:
    """Section 7: per-context examples, divergences, rule coverage, golden flows and the seed."""
    core = a.core
    blocks: list[Block] = [
        Heading("Baseline (like for like)"),
        *_proof_blocks(core.proof, core.proof_error, core.golden),
    ]
    if core.tightened is not None:
        blocks += [
            Heading("Tightened candidate (separate proof)"),
            *_proof_blocks(core.tightened.proof, core.tightened.proof_error, core.golden),
        ]
    return Section(7, "Proof of Life", tuple(blocks))


def _matrix_blocks(title: str, matrix: ZoneMatrix) -> list[Block]:
    return [
        Heading(title),
        Table(
            ("From zone", "To zone", "Allowed services"),
            tuple((r.from_zone, r.to_zone, "; ".join(r.services)) for r in matrix.rows),
            empty="No traffic is allowed between zones.",
        ),
        Bullets(tuple(matrix.notes)),
    ]


def _differences(before: ZoneMatrix, after: ZoneMatrix) -> tuple[tuple[str, str, str], ...]:
    old = {(r.from_zone, r.to_zone): "; ".join(r.services) for r in before.rows}
    new = {(r.from_zone, r.to_zone): "; ".join(r.services) for r in after.rows}
    pairs = [*old, *(pair for pair in new if pair not in old)]
    return tuple(
        (f"{pair[0]} to {pair[1]}", old.get(pair, "nothing"), new.get(pair, "nothing"))
        for pair in pairs
        if old.get(pair) != new.get(pair)
    )


def matrix_section(a: Assessment) -> Section:
    """Section 8: allowed services between each zone pair, before and after."""
    core = a.core
    blocks: list[Block] = [
        Para(
            "A service is listed when the zone pair allows it for at least some source and "
            "destination addresses. The rule inventory and the equivalence proof carry the exact "
            "decisions. Each difference between before and after should have a ledger entry in "
            "section 6."
        ),
        *_matrix_blocks("Before (source policy)", core.matrix_before),
        *_matrix_blocks("After (baseline candidate)", core.matrix_after),
        Heading("Differences, baseline candidate"),
        Table(
            ("Zone pair", "Before", "After"),
            _differences(core.matrix_before, core.matrix_after),
            empty="No difference between the source and the baseline candidate.",
        ),
    ]
    if core.tightened is not None:
        blocks += [
            *_matrix_blocks("After (tightened candidate, separate change)", core.tightened.matrix),
            Heading("Differences, tightened candidate"),
            Table(
                ("Zone pair", "Before", "After"),
                _differences(core.matrix_before, core.tightened.matrix),
                empty="No difference between the source and the tightened candidate.",
            ),
        ]
    return Section(8, "Zone-to-zone matrix", tuple(blocks))
