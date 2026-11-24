"""Gates G3 and G4: static validation and the equivalence proof plus golden flows."""

from __future__ import annotations

import ipaddress
from pathlib import Path

import pytest

from necro.emitters.panos import emit_panos
from necro.gate_models import Check
from necro.gates import CI_BUDGET, gate_g3, gate_g4
from necro.golden import load_golden
from necro.ir import Action, Decision, Dialect, Flow
from necro.oracle import PROFILE_BUDGETS, prove
from necro.parsers import parse_config
from necro.proof_types import ContextProof, Counterexample, GoldenResult, ProofResult, SideCoverage
from necro.validate_panos import Validation, validate_panos
from tests.panos_helpers import SAMPLES

GOLDEN = Path(__file__).resolve().parents[2] / "samples" / "golden-flows"
FLOW = Flow(src=ipaddress.IPv4Address("198.51.100.7"), dst=ipaddress.IPv4Address("10.1.1.10"),
            proto=6, src_port=40000, dst_port=23)  # fmt: skip


def cover(unhit: list[str] | None = None) -> SideCoverage:
    unhit = unhit or []
    return SideCoverage(rules=3, hit=3 - len(unhit), percent=100.0, unhit=unhit)


def counterexample(vector_id: str = "") -> Counterexample:
    return Counterexample(
        source="golden" if vector_id else "search",
        context="outside:in",
        flow=FLOW,
        panos_flow=FLOW,
        original=Decision(action=Action.deny, rule_id="implicit-deny"),
        resurrected=Decision(action=Action.permit, rule_id="OUTSIDE_IN-2"),
        original_zone="inside",
        expected_action=Action.deny,
        reason="action differs",
        vector_id=vector_id,
    )


def context(name: str = "outside:in", examples: int = CI_BUDGET, **update: object) -> ContextProof:
    base = ContextProof(context=name, implicit=False, examples=examples, passed=True,
                        original=cover(), resurrected=cover(), ledger_covered=0)  # fmt: skip
    return base.model_copy(update=update)


def proof(
    *contexts: ContextProof, golden: GoldenResult | None = None, **update: object
) -> ProofResult:
    base = ProofResult(
        passed=True,
        seed=1,
        budget=CI_BUDGET,
        golden=golden or GoldenResult(total=4, passed=4),
        contexts=list(contexts) if contexts else [context()],
    )
    return base.model_copy(update=update)


def errors(checks: list[Check]) -> list[str]:
    return [c.id for c in checks if not c.ok and c.severity == "error"]


def warnings(checks: list[Check]) -> list[str]:
    return [c.id for c in checks if not c.ok and c.severity == "warning"]


# -- G3 ----------------------------------------------------------------------------------------


def test_g3_passes_on_an_emitted_sample_and_lists_its_warnings() -> None:
    policy = parse_config((SAMPLES / "ios-12-edge.cfg").read_text(encoding="utf-8"), Dialect.ios)
    emission = emit_panos(policy)
    gate = gate_g3(validate_panos(emission.text, emission.ledger))
    assert gate.status == "pass" and gate.blocking_reasons == []
    assert warnings(gate.checks) == ["g3-broad-allow"]


def test_g3_fails_on_a_validation_error_and_is_not_waivable() -> None:
    gate = gate_g3(validate_panos("set rulebase security rules r1 from LAN"))
    assert gate.status == "fail" and gate.blocking_reasons
    assert all(c.waiver is None for c in gate.checks)


def test_g3_with_only_warnings_passes() -> None:
    warning = Check(id="g3-logging", ok=False, severity="warning", detail="no log")
    assert gate_g3(Validation(checks=[warning])).status == "pass"


# -- G4 ----------------------------------------------------------------------------------------


def test_the_ci_budget_matches_the_oracle_profile() -> None:
    assert PROFILE_BUDGETS["ci"] == CI_BUDGET


def test_g4_passes_at_the_ci_budget_with_every_golden_flow() -> None:
    gate = gate_g4(proof())
    assert gate.status == "pass"
    assert [c.detail for c in gate.checks] == [
        f"context outside:in: {CI_BUDGET} examples, no divergence",
        "all 4 golden flows pass",
    ]


def test_g4_fails_without_a_proof() -> None:
    gate = gate_g4(None)
    assert gate.status == "fail" and gate.blocking_reasons == ["no equivalence proof was run"]


@pytest.mark.parametrize("budget", [PROFILE_BUDGETS["dev"], CI_BUDGET - 1])
def test_g4_fails_below_the_ci_budget(budget: int) -> None:
    gate = gate_g4(proof(budget=budget))
    assert gate.status == "fail" and errors(gate.checks) == ["g4-budget"]
    assert f"budget of {budget}" in gate.blocking_reasons[0]


def test_g4_passes_above_the_ci_budget() -> None:
    gate = gate_g4(proof(context(examples=PROFILE_BUDGETS["demo"]), budget=PROFILE_BUDGETS["demo"]))
    assert gate.status == "pass"


def test_g4_fails_when_a_context_checked_fewer_examples_than_the_ci_budget() -> None:
    gate = gate_g4(proof(context("inside:in", examples=CI_BUDGET - 1)))
    assert gate.status == "fail" and errors(gate.checks) == ["g4-budget"]
    assert gate.blocking_reasons == [f"context inside:in: {CI_BUDGET - 1} examples, below 5000"]


def test_g4_fails_when_no_context_was_checked() -> None:
    empty = ProofResult(passed=True, seed=1, budget=CI_BUDGET,
                        golden=GoldenResult(total=1, passed=1), contexts=[])  # fmt: skip
    assert errors(gate_g4(empty).checks) == ["g4-contexts"]


def test_g4_fails_on_a_divergence_outside_the_ledger_and_shows_the_counterexample() -> None:
    bad = context(passed=False, examples=12, counterexample=counterexample())
    gate = gate_g4(proof(bad, passed=False, counterexample=counterexample()))
    assert gate.status == "fail" and errors(gate.checks) == ["g4-divergence"]
    assert gate.blocking_reasons == [
        "context outside:in: proto 6 198.51.100.7:40000 -> 10.1.1.10:23 is deny on the source "
        "and permit on the candidate (action differs)"
    ]


def test_g4_a_failed_context_without_a_counterexample_still_fails() -> None:
    gate = gate_g4(proof(context(passed=False), passed=False))
    assert gate.blocking_reasons == ["context outside:in: divergence outside the ledger"]


def test_g4_fails_on_a_golden_flow_failure() -> None:
    golden = GoldenResult(total=4, passed=3, failures=[counterexample("A82-03")])
    gate = gate_g4(proof(golden=golden, passed=False))
    assert gate.status == "fail" and errors(gate.checks) == ["g4-golden"]
    assert gate.blocking_reasons[0].startswith("golden flow A82-03: proto 6")


def test_g4_fails_when_the_golden_count_disagrees_without_failures() -> None:
    gate = gate_g4(proof(golden=GoldenResult(total=4, passed=3)))
    assert gate.blocking_reasons == ["1 golden flows failed"]


def test_g4_an_explicit_golden_result_replaces_the_one_in_the_proof() -> None:
    failed = GoldenResult(total=2, passed=1, failures=[counterexample("IOS-01")])
    assert gate_g4(proof(), golden=failed).status == "fail"
    assert gate_g4(proof(golden=failed), golden=GoldenResult(total=2, passed=2)).status == "pass"


def test_g4_no_golden_flows_is_a_warning() -> None:
    gate = gate_g4(proof(golden=GoldenResult(total=0, passed=0)))
    assert gate.status == "pass" and warnings(gate.checks) == ["g4-golden"]


def test_g4_lists_active_rules_never_hit_on_either_side_as_warnings() -> None:
    unhit = context(original=cover(["OUTSIDE_IN#4"]), resurrected=cover(["OUTSIDE_IN-4", "x"]))
    gate = gate_g4(proof(unhit))
    assert gate.status == "pass" and warnings(gate.checks) == ["g4-unhit", "g4-unhit"]
    details = [c.detail for c in gate.checks if c.id == "g4-unhit"]
    assert details == [
        "context outside:in: source rules never hit: OUTSIDE_IN#4",
        "context outside:in: candidate rules never hit: OUTSIDE_IN-4, x",
    ]


def test_g4_a_proof_that_did_not_pass_for_another_reason_fails() -> None:
    assert gate_g4(proof(passed=False)).blocking_reasons == ["the proof did not pass"]
    with_cx = gate_g4(proof(passed=False, counterexample=counterexample()))
    assert with_cx.blocking_reasons[0].startswith("context outside:in: proto 6")


@pytest.mark.parametrize(
    ("flow", "text"),
    [
        (FLOW.model_copy(update={"proto": 1, "icmp_type": 8}), "icmp-type 8"),
        (FLOW.model_copy(update={"proto": 47}), "proto 47 198.51.100.7 -> 10.1.1.10 is"),
    ],
)
def test_g4_describes_icmp_and_other_protocols(flow: Flow, text: str) -> None:
    cx = counterexample().model_copy(update={"flow": flow})
    gate = gate_g4(proof(context(passed=False, counterexample=cx), passed=False))
    assert text in gate.blocking_reasons[0]


def test_g4_passes_on_a_real_proof_at_the_ci_budget() -> None:
    text = (SAMPLES / "asa-8.2-branch.cfg").read_text(encoding="utf-8")
    policy = parse_config(text, Dialect.asa)
    emission = emit_panos(policy)
    golden = load_golden(GOLDEN / "asa-8.2-branch.toml")
    result = prove(policy, emission.text, emission.ledger, budget=CI_BUDGET, golden=golden)
    gate = gate_g4(result)
    assert gate.status == "pass", gate.blocking_reasons
    assert "all 13 golden flows pass" in [c.detail for c in gate.checks]
