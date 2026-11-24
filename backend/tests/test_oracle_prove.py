"""Task 8.2: ``prove()`` per context, golden flows first (requirements 6.3, 6.4, 6.6, 6.8).

Property P2 is checked two ways. ``prove`` runs the whole oracle on the three sample configs and
on deliberately broken emissions. The property test runs the same one-flow comparison
(``Sides.check``) over generated policies with the production flow strategy.
"""

from __future__ import annotations

import ipaddress

import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from necro.autopsy import analyze
from necro.emitters import PanosEmission, emit_panos
from necro.findings import FindingType
from necro.golden import check_golden, load_golden
from necro.ir import Action, Flow, NatRule, NatType, Policy
from necro.oracle import (
    BATCH,
    DEFAULT_SEED,
    MAX_BUDGET,
    PROFILE_BUDGETS,
    ProofInputError,
    _coverage,
    _Run,
    _sweep,
    budget_for_profile,
    prove,
)
from necro.oracle_core import Sides
from necro.oracle_flows import flow_space, flow_strategy
from necro.proof_types import ProofResult
from necro.sets import AddrSet
from tests.ir_strategies import ios_policies, pix_asa_policies
from tests.panos_helpers import SAMPLES, policy_of

GOLDEN = SAMPLES.parent / "golden-flows"
CONFIGS = {
    "pix-2006-hq.cfg": "pix-2006-hq.toml",
    "asa-8.2-branch.cfg": "asa-8.2-branch.toml",
    "ios-12-edge.cfg": "ios-12-edge.toml",
}
BUDGET = PROFILE_BUDGETS["dev"]


def _emit(name: str) -> tuple[Policy, PanosEmission]:
    policy = policy_of(name)
    return policy, emit_panos(policy)


def _prove(
    name: str,
    text: str | None = None,
    budget: int = BUDGET,
    seed: int = DEFAULT_SEED,
    golden: bool = True,
) -> ProofResult:
    policy, emission = _emit(name)
    vectors = load_golden(GOLDEN / CONFIGS[name]) if golden else []
    return prove(
        policy, text or emission.text, emission.ledger, budget=budget, seed=seed, golden=vectors
    )


def _break(text: str, rule: str, attribute: str, old: str, new: str) -> str:
    """Rewrite one attribute of one emitted rule."""
    line = f"set rulebase security rules {rule} {attribute} {old}"
    assert line in text, line
    return text.replace(line, f"set rulebase security rules {rule} {attribute} {new}")


# -- the samples ------------------------------------------------------------------------------


@pytest.mark.parametrize("name", list(CONFIGS))
def test_every_sample_proves_equivalent_with_its_golden_flows(name: str) -> None:
    result = _prove(name)
    assert result.passed and result.counterexample is None, result.counterexample
    assert result.golden.all_passed and result.golden.total >= 13
    assert result.seed == DEFAULT_SEED and result.budget == BUDGET
    assert all(c.passed and c.examples >= BUDGET for c in result.contexts)
    assert result.examples == sum(c.examples for c in result.contexts)


@pytest.mark.parametrize("name", list(CONFIGS))
def test_only_shadowed_rules_are_left_unhit_on_the_source_side(name: str) -> None:
    """Every rule of the source that can fire is exercised; the rest are the seeded ghosts."""
    policy, _emission = _emit(name)
    shadowed = {f.rule_ref for f in analyze(policy) if f.type == FindingType.shadowed}
    result = _prove(name, budget=2_000)
    for c in result.contexts:
        assert set(c.original.unhit) <= shadowed, (c.context, c.original.unhit)
        assert c.original.hit + len(c.original.unhit) == c.original.rules
        expected = (
            100.0 if c.original.rules == 0 else round(100 * c.original.hit / c.original.rules, 1)
        )
        assert c.original.percent == expected


def test_the_proof_includes_the_implicit_contexts() -> None:
    result = _prove("pix-2006-hq.cfg")
    by_name = {c.context: c for c in result.contexts}
    assert set(by_name) == {"outside:in", "inside:in", "dmz:in"}
    inside = by_name["inside:in"]  # no ACL: the security-level behaviour is what is proven
    assert inside.implicit and inside.examples >= BUDGET and inside.passed
    assert not by_name["outside:in"].implicit
    ios = {c.context: c.implicit for c in _prove("ios-12-edge.cfg").contexts}
    assert ios == {
        "FastEthernet0/0:in": False,
        "FastEthernet0/1:in": False,
        "FastEthernet0/2:in": True,
    }


def test_flows_decided_by_the_ledger_are_counted() -> None:
    result = _prove("ios-12-edge.cfg")
    assert sum(c.ledger_covered for c in result.contexts) > 0


def test_the_same_seed_gives_the_same_result() -> None:
    first = _prove("asa-8.2-branch.cfg", budget=300, seed=7)
    second = _prove("asa-8.2-branch.cfg", budget=300, seed=7)
    assert first.model_dump_json() == second.model_dump_json()
    assert first.seed == 7


# -- a broken emission ------------------------------------------------------------------------


def test_a_broken_rule_gives_a_shrunk_counterexample_with_both_decisions() -> None:
    _policy, emission = _emit("pix-2006-hq.cfg")
    broken = _break(emission.text, "outside_in-1", "action", "allow", "deny")
    result = _prove("pix-2006-hq.cfg", broken, golden=False)
    assert not result.passed
    cex = result.counterexample
    assert cex is not None and cex.source == "search" and cex.context == "outside:in"
    assert cex.original.action == Action.permit and cex.original.rule_id == "outside_in#1"
    assert cex.resurrected.action == Action.deny
    assert cex.original.to_zone == "dmz" and cex.original_zone == "dmz"
    assert "gives deny" in cex.reason and "requires permit" in cex.reason
    # shrunk: the fields the rule does not look at are at their smallest value
    assert cex.flow.proto == 6 and cex.flow.src_port == 0
    assert result.contexts[0].counterexample == cex
    assert result.contexts[0].examples <= BUDGET + BATCH  # found within the budget


def test_every_context_is_searched_even_after_one_fails() -> None:
    _policy, emission = _emit("pix-2006-hq.cfg")
    broken = _break(emission.text, "dmz_in-3", "action", "allow", "deny")
    result = _prove("pix-2006-hq.cfg", broken, golden=False)
    assert [c.passed for c in result.contexts] == [True, True, False]
    assert result.counterexample is not None and result.counterexample.context == "dmz:in"


def test_a_golden_failure_ends_the_proof_with_that_vector() -> None:
    vectors = load_golden(GOLDEN / CONFIGS["pix-2006-hq.cfg"])
    wrong = vectors[0].model_copy(update={"expect_action": Action.deny})
    policy, emission = _emit("pix-2006-hq.cfg")
    result = prove(policy, emission.text, emission.ledger, budget=BUDGET, golden=[wrong])
    assert not result.passed and result.contexts == []
    cex = result.counterexample
    assert cex is not None and cex.source == "golden" and cex.vector_id == wrong.id
    assert "hand-verified" in cex.reason and result.golden.failures == [cex]
    assert result.golden.passed == 0 and not result.golden.all_passed


def test_golden_flows_also_check_the_resurrected_side() -> None:
    policy, emission = _emit("pix-2006-hq.cfg")
    broken = _break(emission.text, "outside_in-1", "action", "allow", "deny")
    sides = Sides(policy, broken, emission.ledger)
    result = check_golden(sides, load_golden(GOLDEN / CONFIGS["pix-2006-hq.cfg"]))
    assert result.failures and all("resurrected" in f.reason for f in result.failures)
    assert result.passed + len(result.failures) == result.total


def test_golden_checks_cover_ledger_class_zone_and_rule_expectations() -> None:
    policy, emission = _emit("ios-12-edge.cfg")
    sides = Sides(policy, emission.text, emission.ledger)
    vectors = load_golden(GOLDEN / CONFIGS["ios-12-edge.cfg"])
    assert check_golden(sides, vectors).all_passed
    with_ledger = next(v for v in vectors if v.expect_ledger)
    cases = {
        "ledger entry covers": with_ledger.model_copy(update={"expect_ledger": "time-range"}),
        "source gives": vectors[0].model_copy(update={"expect_rule": "nope#1"}),
    }
    for fragment, vector in cases.items():
        failures = check_golden(sides, [vector]).failures
        assert failures and fragment in failures[0].reason, (fragment, failures)


def test_a_zone_that_is_missing_from_the_emitted_text_is_an_input_error() -> None:
    policy, emission = _emit("pix-2006-hq.cfg")
    text = "\n".join(line for line in emission.text.splitlines() if "set zone dmz " not in line)
    with pytest.raises(ProofInputError, match="no zone dmz"):
        prove(policy, text, emission.ledger, budget=BUDGET)


def test_a_golden_vector_for_an_unknown_context_is_an_input_error() -> None:
    policy, emission = _emit("pix-2006-hq.cfg")
    vector = load_golden(GOLDEN / CONFIGS["pix-2006-hq.cfg"])[0].model_copy(
        update={"context": "nowhere:in"}
    )
    with pytest.raises(ProofInputError, match="no context nowhere:in"):
        prove(policy, emission.text, emission.ledger, budget=BUDGET, golden=[vector])


# -- limits and profiles ----------------------------------------------------------------------


@pytest.mark.parametrize("budget", [0, -1, MAX_BUDGET + 1])
def test_the_budget_is_limited(budget: int) -> None:
    policy, emission = _emit("pix-2006-hq.cfg")
    with pytest.raises(ValueError, match="between 1 and 20000"):
        prove(policy, emission.text, emission.ledger, budget=budget)


def test_the_largest_budget_is_the_documented_cap() -> None:
    assert MAX_BUDGET == 20_000 and PROFILE_BUDGETS == {"dev": 500, "ci": 5_000, "demo": 10_000}


def test_profiles_map_to_budgets(monkeypatch: pytest.MonkeyPatch) -> None:
    assert [budget_for_profile(p) for p in ("dev", "ci", "demo")] == [500, 5_000, 10_000]
    monkeypatch.setenv("HYPOTHESIS_PROFILE", "ci")
    assert budget_for_profile() == 5_000
    monkeypatch.delenv("HYPOTHESIS_PROFILE")
    assert budget_for_profile() == 500
    with pytest.raises(ValueError, match="unknown profile"):
        budget_for_profile("turbo")


def test_coverage_of_no_rules_is_complete() -> None:
    empty = _coverage([], set())
    assert (empty.rules, empty.hit, empty.percent, empty.unhit) == (0, 0, 100.0, [])
    some = _coverage(["a", "b", "c"], {"a", "c", "zzz"})
    assert (some.hit, some.percent, some.unhit) == (2, 66.7, ["b"])


# -- P2 over generated policies ---------------------------------------------------------------


def _tuned(policy: Policy, *, no_egress: bool, translate_everything: bool) -> Policy:
    """Let the ACL logic through: generated policies are dominated by outbound ACLs and by
    nat-control denies. ``translate_everything`` adds the catch-all ``nat (iface) 1 0 0``."""
    update: dict[str, object] = {}
    if no_egress:
        update["egress_acls"] = {}
    if translate_everything:
        catch_all = [
            NatRule(nat_type=NatType.dynamic, real_interface=i.nameif, real_addr=AddrSet.any())
            for i in policy.interfaces
        ]
        update["nat_rules"] = [*policy.nat_rules, *catch_all]
    return policy.model_copy(update=update)


@pytest.mark.pbt
@settings(deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])
@given(data=st.data())
def test_p2_generated_policies_resurrect_to_the_same_decisions(data: st.DataObject) -> None:
    policy = _tuned(
        data.draw(st.one_of(pix_asa_policies(), ios_policies())),
        no_egress=data.draw(st.booleans()),
        translate_everything=data.draw(st.booleans()),
    )
    emission = emit_panos(policy)
    assume(not emission.unsupported)  # unsupported constructs block the verdict instead
    sides = Sides(policy, emission.text, emission.ledger)
    assume(sides.contexts)
    # Generating and emitting a policy costs far more than checking a flow, so check every
    # context (the implicit ones too) with a few flows each instead of one flow in one context.
    for ctx in sides.contexts:
        flows = data.draw(st.lists(flow_strategy(flow_space(policy, ctx)), min_size=3, max_size=3))
        for flow in flows:
            verdict = sides.check(ctx, flow)
            assert verdict.problem == "", (ctx.name, flow, verdict)


def test_the_oracle_compares_against_the_text_not_the_emitters_model() -> None:
    """Dropping a rule from the text changes the verdict even though the emission object, with its
    own bookkeeping, is untouched: the oracle only trusts what ``read_panos`` reads back."""
    policy, emission = _emit("asa-8.2-branch.cfg")
    kept = [ln for ln in emission.text.splitlines() if " OUTSIDE_IN-2 " not in ln]
    assert len(kept) < len(emission.text.splitlines())
    result = prove(policy, "\n".join(kept) + "\n", emission.ledger, budget=BUDGET)
    assert not result.passed
    cex = result.counterexample
    assert cex is not None and cex.original.rule_id.endswith("#2")


def _opposite(action: Action) -> Action:
    return Action.permit if action == Action.deny else Action.deny


def test_a_ledger_entry_that_contradicts_the_emitted_policy_is_a_divergence() -> None:
    """A flow covered by an entry must get the entry's declared action."""
    policy, emission = _emit("ios-12-edge.cfg")
    entry = next(e for e in emission.ledger if e.regions and not e.informational)
    liar = entry.model_copy(update={"new_action": _opposite(entry.new_action)})
    ledger = [liar if e is entry else e for e in emission.ledger]
    result = prove(policy, emission.text, ledger, budget=BUDGET)
    assert not result.passed
    assert result.counterexample is not None and result.counterexample.ledger_ids


def test_two_entries_that_declare_different_actions_conflict() -> None:
    policy, emission = _emit("ios-12-edge.cfg")
    entry = next(e for e in emission.ledger if e.regions and not e.informational)
    twin = entry.model_copy(update={"id": "LED-9999", "new_action": _opposite(entry.new_action)})
    result = prove(policy, emission.text, [*emission.ledger, twin], budget=BUDGET)
    assert not result.passed
    assert result.counterexample is not None
    assert "declare different actions" in result.counterexample.reason


def _flow(src: str, dst: str, dport: int) -> Flow:
    return Flow(
        src=ipaddress.IPv4Address(src),
        dst=ipaddress.IPv4Address(dst),
        proto=6,
        src_port=40000,
        dst_port=dport,
    )


def test_a_single_flow_is_compared_in_the_address_space_of_the_source() -> None:
    policy, emission = _emit("pix-2006-hq.cfg")
    sides = Sides(policy, emission.text, emission.ledger)
    ctx = sides.context("outside:in")
    flow = _flow("203.0.113.7", "192.168.50.10", 80)
    verdict = sides.check(ctx, flow)
    assert verdict.problem == "" and verdict.original.rule_id == "outside_in#1"
    assert verdict.resurrected.rule_id == "outside_in-1" and verdict.entries == ()
    assert verdict.panos_flow == flow


# -- the witness sweep ------------------------------------------------------------------------


@pytest.mark.parametrize("name", list(CONFIGS))
@pytest.mark.parametrize("seed", [0, 1, 7, 12345])
def test_every_reachable_rule_is_exercised_whatever_the_seed_and_even_at_a_tiny_budget(
    name: str, seed: int
) -> None:
    """The sweep, not luck, makes the rules of the source and of the candidate that can fire hit."""
    policy, _emission = _emit(name)
    shadowed = {f.rule_ref for f in analyze(policy) if f.type == FindingType.shadowed}
    result = _prove(name, budget=1, seed=seed)
    assert result.passed
    for c in result.contexts:
        assert set(c.original.unhit) <= shadowed, (seed, c.context, c.original.unhit)
        # the PAN-OS rules left unhit are the translations of those shadowed rules, the rules
        # that apply to other zones, and the final deny (which only the leftovers reach)
        assert c.examples > 1


def test_the_sweep_alone_finds_a_broken_rule() -> None:
    policy, emission = _emit("pix-2006-hq.cfg")
    broken = _break(emission.text, "outside_in-2", "action", "allow", "deny")
    sides = Sides(policy, broken, emission.ledger)
    ctx = sides.context("outside:in")
    run = _Run()
    _sweep(sides, ctx, flow_space(policy, ctx), run)
    assert run.swept is not None and 0 < run.found_at <= run.examples
    assert run.swept.source == "search" and run.swept.context == "outside:in"
    assert run.swept.original.action != run.swept.resurrected.action
    assert run.examples == len(flow_space(policy, ctx).witnesses)  # every witness is checked


def test_a_clean_sweep_records_hits_and_no_failure() -> None:
    policy, emission = _emit("ios-12-edge.cfg")
    sides = Sides(policy, emission.text, emission.ledger)
    ctx = sides.context("FastEthernet0/0:in")
    run = _Run()
    _sweep(sides, ctx, flow_space(policy, ctx), run)
    assert run.swept is None and run.found_at == 0
    assert run.ledger_covered > 0  # the established rule and the to-the-box flows
    assert "110#2" in run.original_hits and "110-2" in run.resurrected_hits
