"""The readiness verdict: the gate-outcome matrix, ordering, waivers, four-eyes and wording."""

from __future__ import annotations

import itertools
import re
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest

from necro.autopsy import analyze
from necro.emitters.panos import PanosEmission, emit_panos
from necro.findings import Finding, Severity
from necro.gate_models import (
    GATE_IDS,
    AuditHeader,
    ChangeMeta,
    Check,
    GateId,
    GateResult,
    Sidecar,
    Verdict,
    Waiver,
)
from necro.gates import CI_BUDGET, evaluate
from necro.golden import load_golden
from necro.ir import Dialect, Policy
from necro.ledger import Approval
from necro.oracle import prove
from necro.parsers import parse_config
from necro.proof_types import ProofResult
from necro.tighten import ApprovalDecision
from necro.validate_panos import Validation, validate_panos
from necro.verdict import WAIVABLE, compute_verdict, same_person
from tests.panos_helpers import SAMPLES

TODAY = date(2026, 11, 21)
NECRO = Path(__file__).resolve().parents[1] / "necro"
GOLDEN = Path(__file__).resolve().parents[2] / "samples" / "golden-flows"
FORBIDDEN = re.compile(r"compliant|safe\s+to\s+deploy", re.IGNORECASE)
CHANGE = ChangeMeta(change_id="CHG-0042", requested_by="Alex Engineer",
                    peer_reviewer="Robin Reviewer", cab_reference="CAB-7")  # fmt: skip
STATUSES = ("pass", "fail", "waived")


def waiver(target: str, expires_on: date = TODAY) -> Waiver:
    return Waiver(target=target, reason="tracked in CHG-0042", approver="Dana Reviewer",
                  expires_on=expires_on)  # fmt: skip


def gate(gate_id: GateId, status: str) -> GateResult:
    if status == "pass":
        check = Check(id=f"{gate_id}-x", ok=True, severity="error", detail="fine")
        return GateResult(gate=gate_id, status="pass", checks=[check], blocking_reasons=[])
    if status == "fail":
        check = Check(id=f"{gate_id}-x", ok=False, severity="error", detail="broken")
        return GateResult(gate=gate_id, status="fail", checks=[check], blocking_reasons=["broken"])
    check = Check(id=f"{gate_id}-x", ok=False, severity="error", detail="accepted",
                  waiver=waiver(f"line:{GATE_IDS.index(gate_id) + 1}"))  # fmt: skip
    return GateResult(gate=gate_id, status="waived", checks=[check], blocking_reasons=[])


def all_pass() -> list[GateResult]:
    return [gate(g, "pass") for g in GATE_IDS]


# -- the matrix --------------------------------------------------------------------------------


def expected(statuses: tuple[str, ...]) -> str:
    by_gate = dict(zip(GATE_IDS, statuses, strict=True))
    if any(s == "fail" for s in statuses):
        return "NO-GO"
    if any(s == "waived" and g not in WAIVABLE for g, s in by_gate.items()):
        return "NO-GO"
    return "CONDITIONAL" if "waived" in statuses else "GO"


@pytest.mark.parametrize("statuses", list(itertools.product(STATUSES, repeat=len(GATE_IDS))))
def test_every_combination_of_gate_outcomes_maps_to_the_documented_verdict(
    statuses: tuple[str, ...],
) -> None:
    verdict = compute_verdict([gate(g, s) for g, s in zip(GATE_IDS, statuses, strict=True)], CHANGE)
    assert verdict.value == expected(statuses)
    assert (verdict.value == "NO-GO") == bool(verdict.blocking_reasons)
    waived = [g for g, s in zip(GATE_IDS, statuses, strict=True) if s == "waived" and g in WAIVABLE]
    assert [c.split(":", 1)[0] for c in verdict.conditions] == waived
    assert len(verdict.waivers_used) == len(waived)
    assert not FORBIDDEN.search(verdict.model_dump_json())


def test_all_gates_passing_is_go_with_no_reasons() -> None:
    verdict = compute_verdict(all_pass(), CHANGE)
    assert verdict.value == "GO"
    assert verdict.blocking_reasons == verdict.conditions == verdict.notes == []
    assert verdict.waivers_used == []


# -- ordering and robustness -------------------------------------------------------------------


def test_blocking_reasons_are_ordered_by_gate_whatever_the_input_order() -> None:
    gates = all_pass()
    gates[5] = gate("G6", "fail").model_copy(update={"blocking_reasons": ["f6a", "f6b"]})
    gates[1] = gate("G2", "fail")
    gates[3] = gate("G4", "waived")
    verdict = compute_verdict(list(reversed(gates)), CHANGE)
    assert [g.gate for g in verdict.gates] == list(GATE_IDS)
    assert verdict.blocking_reasons == [
        "G2: broken",
        "G4: waivers do not apply to this gate",
        "G6: f6a",
        "G6: f6b",
    ]


def test_a_missing_gate_blocks_and_a_repeated_gate_is_an_error() -> None:
    verdict = compute_verdict(all_pass()[1:], CHANGE)
    assert verdict.value == "NO-GO"
    assert verdict.blocking_reasons == ["G1: the gate was not evaluated"]
    with pytest.raises(ValueError, match="repeated: G2"):
        compute_verdict([*all_pass(), gate("G2", "pass")], CHANGE)


def test_a_failed_gate_without_reasons_still_says_why() -> None:
    gates = all_pass()
    gates[2] = GateResult(gate="G3", status="fail", checks=[], blocking_reasons=[])
    assert compute_verdict(gates, CHANGE).blocking_reasons == ["G3: the gate failed"]


def test_conditions_name_the_approver_expiry_and_reason_and_waivers_are_listed_once() -> None:
    shared = waiver("line:9")
    checks = [
        Check(id="g2-line", ok=False, severity="error", detail=f"line {n}", waiver=shared)
        for n in (9, 9)
    ]
    gates = all_pass()
    gates[1] = GateResult(gate="G2", status="waived", checks=checks, blocking_reasons=[])
    verdict = compute_verdict(gates, CHANGE)
    assert verdict.value == "CONDITIONAL"
    assert verdict.conditions[0] == (
        "G2: line 9 (waived by Dana Reviewer until 2026-11-21: tracked in CHG-0042)"
    )
    assert verdict.waivers_used == [shared]


def test_the_audit_header_is_carried_on_the_verdict() -> None:
    audit = AuditHeader(tool_version="0.1.0", git_commit="abc1234", inputs={"cfg": "0" * 64},
                        dialect="asa", os_version="8.2(5)",
                        generated_at=datetime(2026, 11, 21, tzinfo=UTC))  # fmt: skip
    assert compute_verdict(all_pass(), CHANGE, audit).audit == audit


# -- four-eyes ---------------------------------------------------------------------------------


@pytest.mark.parametrize("reviewer", ["Alex Engineer", "alex engineer", "  ALEX   Engineer "])
def test_the_requester_reviewing_their_own_change_is_conditional(reviewer: str) -> None:
    change = CHANGE.model_copy(update={"peer_reviewer": reviewer})
    verdict = compute_verdict(all_pass(), change)
    assert verdict.value == "CONDITIONAL"
    assert verdict.conditions[0].startswith("four-eyes: the peer reviewer")


def test_four_eyes_is_listed_on_a_no_go_too() -> None:
    gates = all_pass()
    gates[0] = gate("G1", "fail")
    change = CHANGE.model_copy(update={"peer_reviewer": "Alex Engineer"})
    verdict = compute_verdict(gates, change)
    assert verdict.value == "NO-GO" and verdict.conditions[0].startswith("four-eyes")


def test_a_different_reviewer_keeps_go() -> None:
    assert not same_person("Alex Engineer", "Alexa Engineer")
    assert compute_verdict(all_pass(), CHANGE).value == "GO"


def test_missing_change_details_are_notes_and_do_not_change_the_verdict() -> None:
    verdict = compute_verdict(all_pass(), ChangeMeta())
    assert verdict.value == "GO"
    assert verdict.notes == [
        "no peer reviewer is recorded; the four-eyes review (P5) is still owed",
        "no requester is recorded on the change",
        "no change ID is recorded",
        "no CAB approval reference is recorded",
    ]
    only_reviewer = compute_verdict(all_pass(), ChangeMeta(peer_reviewer="Robin Reviewer"))
    assert only_reviewer.value == "GO" and only_reviewer.conditions == []


# -- evaluate() end to end ---------------------------------------------------------------------


class Run:
    """The ASA 8.2 sample, resurrected and proven once at the ci budget."""

    def __init__(self) -> None:
        text = (SAMPLES / "asa-8.2-branch.cfg").read_text(encoding="utf-8")
        self.policy: Policy = parse_config(text, Dialect.asa)
        self.emission: PanosEmission = emit_panos(self.policy)
        self.validation: Validation = validate_panos(self.emission.text, self.emission.ledger)
        self.findings: list[Finding] = analyze(self.policy)
        golden = load_golden(GOLDEN / "asa-8.2-branch.toml")
        self.proof: ProofResult = prove(self.policy, self.emission.text, self.emission.ledger,
                                        budget=CI_BUDGET, golden=golden)  # fmt: skip
        self.critical = [f.id for f in self.findings if f.severity == Severity.critical]

    def sidecar(self, risk_expires: date | None = TODAY, **update: object) -> Sidecar:
        decision = ApprovalDecision(approval=Approval.accepted, approver="Sam Approver",
                                    decided_at="2026-11-20")  # fmt: skip
        risks = [] if risk_expires is None else [
            waiver(f"finding:{fid}", risk_expires) for fid in self.critical
        ]  # fmt: skip
        sidecar = Sidecar(ledger_decisions={e.id: decision for e in self.emission.ledger},
                          accepted_risks=risks, change=CHANGE)  # fmt: skip
        return sidecar.model_copy(update=update)

    def verdict(
        self,
        sidecar: Sidecar,
        today: date = TODAY,
        findings: list[Finding] | None = None,
        without_proof: bool = False,
    ) -> Verdict:
        return evaluate(
            self.policy,
            self.findings if findings is None else findings,
            self.emission,
            self.validation,
            None if without_proof else self.proof,
            self.emission.ledger,
            sidecar,
            today,
        )


@pytest.fixture(scope="module")
def run() -> Run:
    return Run()


def test_the_sample_with_every_decision_and_an_accepted_risk_is_conditional(run: Run) -> None:
    assert run.critical, "the sample seeds a critical finding"
    verdict = run.verdict(run.sidecar())
    assert verdict.value == "CONDITIONAL", verdict.blocking_reasons
    assert [g.status for g in verdict.gates] == ["pass", "pass", "pass", "pass", "pass", "waived"]
    assert [w.target for w in verdict.waivers_used] == [f"finding:{f}" for f in run.critical]
    assert verdict.notes == []


def test_the_sample_without_critical_findings_is_go(run: Run) -> None:
    others = [f for f in run.findings if f.severity != Severity.critical]
    assert run.verdict(run.sidecar(None), findings=others).value == "GO"


def test_the_sample_without_decisions_is_no_go_with_reasons_in_gate_order(run: Run) -> None:
    verdict = run.verdict(Sidecar(change=CHANGE), without_proof=True)
    assert verdict.value == "NO-GO"
    gates = [r.split(":", 1)[0] for r in verdict.blocking_reasons]
    assert gates == sorted(gates, key=GATE_IDS.index)
    assert set(gates) == {"G4", "G5", "G6"}
    assert verdict.blocking_reasons[0] == "G4: no equivalence proof was run"


def test_an_accepted_risk_that_expires_today_holds_and_one_that_expired_yesterday_blocks(
    run: Run,
) -> None:
    assert run.verdict(run.sidecar(TODAY), today=TODAY).value == "CONDITIONAL"
    expired = run.verdict(run.sidecar(TODAY), today=TODAY + timedelta(days=1))
    assert expired.value == "NO-GO"
    assert all(r.startswith("G6: critical finding") for r in expired.blocking_reasons)
    assert all("expired on 2026-11-21" in r for r in expired.blocking_reasons)
    assert expired.waivers_used == []


def test_the_requester_as_reviewer_downgrades_go_to_conditional(run: Run) -> None:
    others = [f for f in run.findings if f.severity != Severity.critical]
    self_review = CHANGE.model_copy(update={"peer_reviewer": "alex engineer"})
    verdict = run.verdict(run.sidecar(None, change=self_review), findings=others)
    assert verdict.value == "CONDITIONAL"
    assert verdict.conditions == [
        "four-eyes: the peer reviewer (alex engineer) is also the requester; "
        "an engineer who did not do the translation must review it"
    ]


# -- wording -----------------------------------------------------------------------------------


def test_verdicts_on_the_sample_never_use_the_forbidden_words(run: Run) -> None:
    for verdict in (
        run.verdict(run.sidecar()),
        run.verdict(Sidecar(), without_proof=True),
        run.verdict(run.sidecar(TODAY), today=TODAY + timedelta(days=1)),
    ):
        assert not FORBIDDEN.search(verdict.model_dump_json())


@pytest.mark.parametrize(
    "module", ["gates.py", "verdict.py", "validate_panos.py", "gate_models.py"]
)
def test_the_governance_modules_never_use_the_forbidden_words(module: str) -> None:
    assert not FORBIDDEN.search((NECRO / module).read_text(encoding="utf-8"))


def test_the_forbidden_words_pattern_catches_what_it_should() -> None:
    for text in ("Compliant", "non-compliant", "SAFE TO DEPLOY", "safe  to\ndeploy"):
        assert FORBIDDEN.search(text)
    assert not FORBIDDEN.search("supports evidence for PCI DSS 1.2.1")
