"""Task 8.3: the mutation sanity suite (requirement 6.7, pbt-playbook).

The oracle is only evidence if it can fail. Each mutant is a deliberately broken candidate; P2 must
refuse every one with a shrunk counterexample, at the budget of the active Hypothesis profile
(500 / 5,000 / 10,000 flows per context). Every fixture is first proved equivalent unbroken, so a
refusal can only come from the mutation.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from pathlib import Path

import pytest

from necro.ir import Action, Flow
from necro.oracle import budget_for_profile, prove
from necro.oracle_core import Sides
from necro.oracle_flows import flow_space, shrink_flow
from necro.proof_types import Counterexample
from tests.mutants import CONFIGS, MUTANTS, PLAYBOOK, Mutant, fixture

PLAYBOOK_FILE = Path(__file__).resolve().parents[2] / ".kiro" / "steering" / "pbt-playbook.md"


def _addr(text: str) -> ipaddress.IPv4Address:
    return ipaddress.IPv4Address(text)


def _widened(cex: Counterexample) -> bool:
    """The candidate permits what the source denies."""
    return cex.original.action == Action.deny and cex.resurrected.action == Action.permit


def _tcp(cex: Counterexample) -> bool:
    return cex.flow.proto == 6 and cex.original.action != cex.resurrected.action


# What each mutant must look like when the oracle finds it: the counterexample points at the
# planted defect, not at some incidental difference.
EXPECTED: dict[str, Callable[[Counterexample], bool]] = {
    "lt and gt swapped": _tcp,
    "range upper bound off by one": lambda c: (
        c.flow.proto == 6 and c.flow.dst_port == 8101 and _widened(c)
    ),
    "neq emitted as eq": lambda c: c.flow.proto == 17 and c.original.action != c.resurrected.action,
    "subnet mask emitted as wildcard": _widened,
    "rule order reversed for two overlapping rules": lambda c: (
        c.flow.src == _addr("203.0.113.9") and c.flow.dst_port == 22 and _widened(c)
    ),
    "final deny dropped": lambda c: c.resurrected.rule_id == "intrazone-default" and _widened(c),
    "inactive rule emitted as enabled": lambda c: (
        c.flow.dst == _addr("10.1.0.9") and c.flow.dst_port == 3389 and _widened(c)
    ),
    "ICMP echo-reply widened to the ping App-ID": lambda c: (
        c.flow.proto == 1 and c.flow.icmp_type == 8 and _widened(c)
    ),
    "8.3+ real destination left untranslated": lambda c: (
        c.context == "outside:in"
        and c.flow.dst == _addr("10.1.0.50")
        and c.panos_flow.dst == _addr("192.0.2.50")
        and c.original.action == Action.permit
        and c.resurrected.action == Action.deny
    ),
    "to-zone forced to any": lambda c: c.context in {"inside:in", "dmz:in"} and _widened(c),
}


def test_the_suite_has_every_mutant_of_the_playbook() -> None:
    assert [m.name for m in MUTANTS] == list(PLAYBOOK)
    assert set(EXPECTED) == set(PLAYBOOK)
    # the steering doc lists the mutants separated by middle dots; count them there too
    text = PLAYBOOK_FILE.read_text(encoding="utf-8")
    after = text.split("P2 must fail with a shrunk counterexample:", 1)[1]
    listed = after.split("\n\n", 1)[0].replace("\n", " ").split("·")
    assert len(listed) == len(MUTANTS), listed


@pytest.mark.pbt
@pytest.mark.parametrize("name", list(CONFIGS))
def test_the_unbroken_candidate_proves_equivalent(name: str) -> None:
    fx = fixture(name)
    result = prove(fx.original, fx.correct, fx.ledger, budget=budget_for_profile())
    assert result.passed, result.counterexample
    assert all(c.passed for c in result.contexts)


@pytest.mark.pbt
@pytest.mark.parametrize("mutant", MUTANTS, ids=lambda m: m.name)
def test_p2_fails_with_a_shrunk_counterexample_for_every_mutant(mutant: Mutant) -> None:
    fx = fixture(mutant.fixture)
    candidate = mutant.build(fx)
    assert candidate.text != fx.correct, "the mutation changed nothing"

    result = prove(fx.original, candidate.text, candidate.ledger, budget=budget_for_profile())

    assert not result.passed, f"the oracle accepted the mutant {mutant.name!r}"
    cex = result.counterexample
    assert cex is not None
    assert cex.source == "search"  # shrunk by Hypothesis, not a golden vector
    assert cex.reason and cex.context
    assert cex.original != cex.resurrected  # both decisions are reported
    assert EXPECTED[mutant.name](cex), (mutant.name, cex.model_dump(mode="json"))

    # the counterexample is a real divergence: the oracle's own comparison reproduces it
    sides = Sides(fx.original, candidate.text, candidate.ledger)
    verdict = sides.check(sides.context(cex.context), cex.flow)
    assert verdict.problem == cex.reason
    assert (verdict.original, verdict.resurrected) == (cex.original, cex.resurrected)
    assert any(c.counterexample == cex for c in result.contexts if not c.passed)

    # shrunk: no single-field reduction of the flow still fails the same way
    ctx = sides.context(cex.context)

    def same_failure(flow: Flow) -> bool:
        return sides.check(ctx, flow).problem == cex.reason

    assert shrink_flow(flow_space(fx.original, ctx), cex.flow, same_failure) == cex.flow


@pytest.mark.pbt
@pytest.mark.parametrize("mutant", MUTANTS, ids=lambda m: m.name)
def test_every_mutant_is_found_at_other_seeds_too(mutant: Mutant) -> None:
    """The catch does not hinge on one lucky seed."""
    fx = fixture(mutant.fixture)
    candidate = mutant.build(fx)
    for seed in (1, 20260101):
        result = prove(
            fx.original, candidate.text, candidate.ledger, budget=budget_for_profile(), seed=seed
        )
        assert not result.passed and result.counterexample is not None, (mutant.name, seed)
        assert EXPECTED[mutant.name](result.counterexample), (mutant.name, seed)
