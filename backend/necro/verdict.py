"""The readiness verdict from the six gate results (requirements 2.1 and 2.3).

``NO-GO`` when any gate fails, with every blocking reason in gate order. ``CONDITIONAL`` when
all gates pass but only because of valid waivers or accepted risks, or when the four-eyes rule is
broken (the peer reviewer is the requester). ``GO`` otherwise. Waivers never apply to G1, G3 or
G4: a gate there that reports ``waived`` blocks.

The verdict says what the evidence supports. It makes no claim about the change itself.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Literal

from necro.gate_models import GATE_IDS, AuditHeader, ChangeMeta, GateResult, Verdict, Waiver

WAIVABLE = frozenset({"G2", "G5", "G6"})


def same_person(first: str, second: str) -> bool:
    """Names compared the way a reviewer would: case and extra spaces don't matter."""
    return " ".join(first.split()).casefold() == " ".join(second.split()).casefold()


def _ordered(gates: Sequence[GateResult]) -> list[GateResult]:
    seen = [g.gate for g in gates]
    duplicates = sorted({g for g in seen if seen.count(g) > 1})
    if duplicates:
        raise ValueError(f"each gate is evaluated once; repeated: {', '.join(duplicates)}")
    return sorted(gates, key=lambda g: GATE_IDS.index(g.gate))


def _blocking(gates: list[GateResult]) -> list[str]:
    reasons: list[tuple[int, str]] = []  # (gate index, reason): sorted by gate, stable within
    present = {g.gate for g in gates}
    for index, gate_id in enumerate(GATE_IDS):
        if gate_id not in present:
            reasons.append((index, f"{gate_id}: the gate was not evaluated"))
    for gate in gates:
        index = GATE_IDS.index(gate.gate)
        if gate.status == "fail":
            texts = [f"{gate.gate}: {r}" for r in gate.blocking_reasons]
            reasons += [(index, t) for t in texts or [f"{gate.gate}: the gate failed"]]
        elif gate.status == "waived" and gate.gate not in WAIVABLE:
            reasons.append((index, f"{gate.gate}: waivers do not apply to this gate"))
    return [text for _, text in sorted(reasons, key=lambda pair: pair[0])]


def _waived(gates: list[GateResult]) -> tuple[list[str], list[Waiver]]:
    conditions: list[str] = []
    used: list[Waiver] = []
    for gate in gates:
        if gate.gate not in WAIVABLE:
            continue
        for check in gate.checks:
            if check.ok or check.severity != "error" or check.waiver is None:
                continue
            waiver = check.waiver
            conditions.append(
                f"{gate.gate}: {check.detail} (waived by {waiver.approver} until "
                f"{waiver.expires_on.isoformat()}: {waiver.reason})"
            )
            if waiver not in used:
                used.append(waiver)
    return conditions, used


def _change_checks(change: ChangeMeta) -> tuple[list[str], list[str]]:
    """(conditions, notes) from the change record."""
    conditions: list[str] = []
    notes: list[str] = []
    requester, reviewer = change.requested_by or "", change.peer_reviewer or ""
    if requester.strip() and reviewer.strip() and same_person(requester, reviewer):
        conditions.append(
            f"four-eyes: the peer reviewer ({reviewer.strip()}) is also the requester; "
            "an engineer who did not do the translation must review it"
        )
    if not reviewer.strip():
        notes.append("no peer reviewer is recorded; the four-eyes review (P5) is still owed")
    if not requester.strip():
        notes.append("no requester is recorded on the change")
    if not (change.change_id or "").strip():
        notes.append("no change ID is recorded")
    if not (change.cab_reference or "").strip():
        notes.append("no CAB approval reference is recorded")
    return conditions, notes


def compute_verdict(
    gates: Sequence[GateResult], change: ChangeMeta, audit: AuditHeader | None = None
) -> Verdict:
    """GO, CONDITIONAL or NO-GO from the gate results and the change record."""
    ordered = _ordered(gates)
    blocking = _blocking(ordered)
    conditions, used = _waived(ordered)
    four_eyes, notes = _change_checks(change)
    conditions += four_eyes
    value: Literal["GO", "CONDITIONAL", "NO-GO"] = (
        "NO-GO" if blocking else "CONDITIONAL" if conditions else "GO"
    )
    return Verdict(
        value=value,
        gates=ordered,
        blocking_reasons=blocking,
        conditions=conditions,
        waivers_used=used,
        notes=notes,
        audit=audit,
    )
