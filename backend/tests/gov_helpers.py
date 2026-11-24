"""Shared inputs for the report, runbook and interface tests (migration-governance 6 to 9)."""

from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import UTC, date, datetime
from functools import cache
from pathlib import Path

from necro import service
from necro.assessment import Assessment, Core, assemble, compute_core
from necro.audit import sha256_text
from necro.findings import Severity
from necro.gate_models import ChangeMeta, Sidecar, Waiver
from necro.golden import GoldenVector, load_golden
from necro.ledger import Approval
from necro.redact import redact
from necro.tighten import ApprovalDecision, Choice

ROOT = Path(__file__).resolve().parents[2]
SAMPLES = ROOT / "samples" / "dead-configs"
BROKEN = ROOT / "samples" / "broken-configs"
GOLDEN = ROOT / "samples" / "golden-flows"
STEERING = ROOT / ".kiro" / "steering" / "migration-governance.md"
SNAPSHOTS = Path(__file__).resolve().parent / "snapshots"

DIALECTS = {
    "pix-2006-hq": "pix",
    "asa-8.2-branch": "asa",
    "asa-9.8-dc": "asa",
    "ios-12-edge": "ios",
}
NAMES = tuple(DIALECTS)
NOW = datetime(2026, 11, 24, 12, 0, tzinfo=UTC)
TODAY = date(2026, 11, 24)
FAR = date(2027, 12, 31)
FORBIDDEN = re.compile(r"compliant|safe\s+to\s+deploy", re.IGNORECASE)
FAST_BUDGET = 60  # examples per context for tests that do not need a verdict above NO-GO

# A lab config with no critical finding: with its two to-the-box entries decided it reaches GO.
GO_CONFIG = """ASA Version 8.2(5)
hostname lab-fw
interface Ethernet0/0
 nameif outside
 security-level 0
 ip address 198.51.100.1 255.255.255.0
interface Ethernet0/1
 nameif inside
 security-level 100
 ip address 10.0.0.1 255.255.255.0
access-list IN_OUT remark web browsing from the lab network
access-list IN_OUT extended permit tcp 10.0.0.0 255.255.255.0 any eq 443
access-list IN_OUT extended deny ip any any log
access-list OUT_IN remark nothing is allowed in
access-list OUT_IN extended deny ip any any log
access-group IN_OUT in interface inside
access-group OUT_IN in interface outside
"""


def text_of(name: str) -> str:
    return (SAMPLES / f"{name}.cfg").read_text(encoding="utf-8")


def golden_of(name: str) -> list[GoldenVector]:
    return load_golden(GOLDEN / f"{name}.toml")


def core_for(
    text: str,
    dialect: str,
    *,
    name: str = "config",
    budget: int = FAST_BUDGET,
    seed: int = 7,
    golden: tuple[GoldenVector, ...] = (),
    choices: Sequence[Choice] = (),
) -> Core:
    policy = service.load(text, dialect)
    return compute_core(
        policy,
        original_sha256=sha256_text(text),
        input_name=name,
        budget=budget,
        seed=seed,
        profile="custom",
        golden=golden,
        options={"dialect": f"{dialect} (stated)"},
        choices=choices,
    )


@cache
def core_of(name: str, budget: int = FAST_BUDGET, seed: int = 7) -> Core:
    """A sample's core, computed once per (sample, budget, seed)."""
    return core_for(
        text_of(name),
        DIALECTS[name],
        name=f"{name}.cfg",
        budget=budget,
        seed=seed,
        golden=tuple(golden_of(name)),
    )


def assessment_of(
    name: str, sidecar: Sidecar | None = None, *, budget: int = FAST_BUDGET, today: date = TODAY
) -> Assessment:
    return assemble(core_of(name, budget), sidecar or Sidecar(), today, NOW)


def decisions(core: Core, approver: str = "Dana Approver") -> dict[str, ApprovalDecision]:
    """An accepted decision for every ledger entry of the baseline."""
    return {
        e.id: ApprovalDecision(
            approval=Approval.accepted, approver=approver, decided_at="2026-11-23"
        )
        for e in core.emission.ledger
    }


def change(
    requested_by: str = "Alex Engineer", peer_reviewer: str = "Robin Reviewer"
) -> ChangeMeta:
    return ChangeMeta(
        change_id="CHG-1001",
        requested_by=requested_by,
        peer_reviewer=peer_reviewer,
        cab_reference="CAB-77",
    )


def full_sidecar(core: Core, **kwargs: str) -> Sidecar:
    """Every ledger entry decided, every critical finding accepted, the change record complete."""
    risks = [
        Waiver(
            target=f"finding:{f.id}",
            reason="Accepted for the migration window",
            approver="Dana Approver",
            expires_on=FAR,
        )
        for f in core.findings
        if f.severity == Severity.critical
    ]
    return Sidecar(ledger_decisions=decisions(core), accepted_risks=risks, change=change(**kwargs))


def sidecar_json(sidecar: Sidecar) -> str:
    return sidecar.model_dump_json(exclude_defaults=True)


def secret_tokens(text: str) -> set[str]:
    """Secret values the redactor removed: tokens of a line that its redacted form lacks."""
    tokens: set[str] = set()
    for original, redacted in zip(text.splitlines(), redact(text).splitlines(), strict=False):
        if original != redacted:
            tokens |= set(original.split()) - set(redacted.split())
    return {t for t in tokens if len(t) >= 6}
