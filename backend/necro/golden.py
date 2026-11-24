"""Hand-verified golden flows, run as part of every proof (requirement 6.8).

The vectors in ``samples/golden-flows/*.toml`` were worked out by hand from policy-semantics.md and
are independent of ``evaluate.py``. This module loads them and runs each against both sides:

* the original side must give exactly the stated action, rule id and egress zone;
* the resurrected side must give the stated action (or the action declared by the ledger entry that
  covers the flow) and the stated egress zone, and a vector with ``expect_ledger`` must be covered
  by an entry of that class.

A failure is reported as a ``Counterexample`` with both decisions. Golden flows run before the
search, and a failure ends the proof (the vector is the counterexample).
"""

from __future__ import annotations

import ipaddress
import tomllib
from collections.abc import Sequence
from pathlib import Path

from pydantic import BaseModel

from necro.ir import Action, Flow
from necro.oracle_core import Sides, Verdict
from necro.proof_types import Counterexample, GoldenResult

_PROTOCOLS = {"tcp": 6, "udp": 17, "icmp": 1}
_KEYS = {
    "id",
    "note",
    "context",
    "protocol",
    "src",
    "sport",
    "dst",
    "dport",
    "icmp_type",
    "established",
    "expect_action",
    "expect_rule",
    "expect_to_zone",
    "expect_panos_dst",
    "expect_ledger",
}


class GoldenVector(BaseModel):
    """One hand-verified flow and the decision it must get."""

    id: str
    note: str = ""
    context: str
    flow: Flow
    panos_dst: ipaddress.IPv4Address | None = None  # when a PAN-OS rule matches another dst
    expect_action: Action
    expect_rule: str
    expect_to_zone: str
    expect_ledger: str | None = None


def _vector(raw: dict[str, object]) -> GoldenVector:
    unknown = set(raw) - _KEYS
    if unknown:
        raise ValueError(f"golden flow {raw.get('id')}: unknown keys {sorted(unknown)}")
    proto = raw["protocol"]
    flow = Flow(
        src=ipaddress.IPv4Address(str(raw["src"])),
        dst=ipaddress.IPv4Address(str(raw["dst"])),
        proto=_PROTOCOLS[proto] if isinstance(proto, str) else int(str(proto)),
        src_port=int(str(raw.get("sport", 0))),
        dst_port=int(str(raw.get("dport", 0))),
        icmp_type=int(str(raw["icmp_type"])) if "icmp_type" in raw else None,
        established=bool(raw.get("established", False)),
    )
    panos_dst = raw.get("expect_panos_dst")
    expect_ledger = raw.get("expect_ledger")
    return GoldenVector(
        id=str(raw["id"]),
        note=str(raw.get("note", "")),
        context=str(raw["context"]),
        flow=flow,
        panos_dst=ipaddress.IPv4Address(str(panos_dst)) if panos_dst is not None else None,
        expect_action=Action(str(raw["expect_action"])),
        expect_rule=str(raw["expect_rule"]),
        expect_to_zone=str(raw["expect_to_zone"]),
        expect_ledger=str(expect_ledger) if expect_ledger is not None else None,
    )


def load_golden(path: Path) -> list[GoldenVector]:
    """The vectors of one ``*.toml`` file, in file order."""
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    return [_vector(raw) for raw in data.get("flow", [])]


def check_golden(sides: Sides, vectors: Sequence[GoldenVector]) -> GoldenResult:
    """Run every vector on both sides and collect the failures."""
    failures: list[Counterexample] = []
    for vector in vectors:
        ctx = sides.context(vector.context)
        verdict = sides.check(ctx, vector.flow, vector.panos_dst)
        reason = _failure(sides, vector, verdict)
        if reason:
            failures.append(sides.counterexample("golden", ctx, verdict, reason, vector.id))
    return GoldenResult(total=len(vectors), passed=len(vectors) - len(failures), failures=failures)


def _failure(sides: Sides, vector: GoldenVector, verdict: Verdict) -> str:
    """Why the vector fails on either side, or an empty string when it passes."""
    got = verdict.original
    want = (vector.expect_action, vector.expect_rule, vector.expect_to_zone)
    if (got.action, got.rule_id, got.to_zone) != want:
        return (
            f"{vector.id}: the source gives {got.action.value} by {got.rule_id} to {got.to_zone}; "
            f"the hand-verified vector says {want[0].value} by {want[1]} to {want[2]}"
        )
    classes = {e.entry_class.value for e in verdict.entries}
    if vector.expect_ledger is not None and vector.expect_ledger not in classes:
        return f"{vector.id}: no {vector.expect_ledger} ledger entry covers this flow"
    expected = verdict.expected_action if verdict.entries else vector.expect_action
    resurrected = verdict.resurrected
    if resurrected.action != expected:
        return (
            f"{vector.id}: the resurrected policy gives {resurrected.action.value}, "
            f"expected {expected.value}"
        )
    zone = sides.zone_name(vector.expect_to_zone)
    if resurrected.to_zone != zone:
        return f"{vector.id}: the resurrected egress zone is {resurrected.to_zone}, expected {zone}"
    return ""
