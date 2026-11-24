"""Proof of Life: property P2 over generated flows (requirements 6.1 to 6.8).

``prove`` checks that the PAN-OS config re-read from the emitted text behaves like the source
policy, modulo the exorcism ledger (policy-semantics 7), for every ingress context. That includes
the implicit contexts, the interfaces with no ACL, whose security-level behaviour has to be
reproduced too.

The proof runs in this order:

1. The golden flows (hand-verified vectors) run first. If one fails, it is the counterexample and
   the search is skipped.
2. For each context, every *witness* flow (a corner of the region that reaches each rule, plus the
   corners of the rules that are not reached) and every *probe* (a corner moved by one in one
   field, just inside or just outside its region) is checked once. This sweep is deterministic,
   so each rule of the source and of the candidate that can fire is exercised, and each range
   edge is tested on both sides, whatever the seed. It does not count against ``budget``.
3. Then Hypothesis searches ``budget`` boundary-biased flows (``oracle_flows``) with
   ``hypothesis.target()`` steering toward flows that sit on several boundaries at once. The
   search is seeded, so the same input, budget and seed give the same result.
4. A divergence the sweep finds is minimised field by field (``shrink_flow``) and the random search
   of that context is skipped, since the context has failed. A divergence the search finds is
   shrunk by Hypothesis. The result carries the shrunk flow, the context, both
   decisions with rule ids and egress zones, and the ledger entries that apply.
5. A passing context reports its example count, the share of active rules hit on each side, and the
   rules that were not hit.

The budget is per context. The caps and profiles match the security steering: 500 / 5,000 /
10,000 examples for ``dev`` / ``ci`` / ``demo``, and never more than 20,000 per request.
"""

from __future__ import annotations

import contextlib
import os
from collections.abc import Sequence
from dataclasses import dataclass, field

from hypothesis import HealthCheck, Phase, Verbosity, given, settings, target
from hypothesis import seed as hypothesis_seed
from hypothesis import strategies as st

from necro.golden import GoldenVector, check_golden
from necro.ir import Context, Flow, Policy, Rule
from necro.ledger import LedgerEntry
from necro.oracle_core import ProofInputError, Sides
from necro.oracle_flows import FlowSpace, flow_space, flow_strategy, shrink_flow
from necro.parsers.panos_reader import RULEBASE
from necro.proof_types import ContextProof, Counterexample, ProofResult, SideCoverage

DEFAULT_SEED = 0x4E454352  # fixed so that reports are deterministic (governance R6)
MAX_BUDGET = 20_000
PROFILE_BUDGETS = {"dev": 500, "ci": 5_000, "demo": 10_000}
# Hypothesis spends about 230 microseconds of bookkeeping per example, more than it takes to draw
# and check a flow. Each Hypothesis example therefore checks a batch of flows, drawn one at a time
# and stopping at the first divergence. The shrinker still works on every field of every flow.
BATCH = 32

__all__ = [
    "DEFAULT_SEED",
    "MAX_BUDGET",
    "PROFILE_BUDGETS",
    "ProofInputError",
    "budget_for_profile",
    "prove",
]


def budget_for_profile(name: str | None = None) -> int:
    """Examples per context for a Hypothesis profile (``HYPOTHESIS_PROFILE``, default ``dev``)."""
    profile = name or os.environ.get("HYPOTHESIS_PROFILE", "dev")
    try:
        return PROFILE_BUDGETS[profile]
    except KeyError:
        raise ValueError(f"unknown profile {profile!r}; use dev, ci or demo") from None


class _Divergence(Exception):
    """Raised inside the property so that Hypothesis shrinks the flow."""


@dataclass
class _Run:
    """What one context's search observed. The last recorded failure is the shrunk one."""

    examples: int = 0
    ledger_covered: int = 0
    found_at: int = 0
    failure: Counterexample | None = None
    swept: Counterexample | None = None  # first divergence of the sweep, if any
    original_hits: set[str] = field(default_factory=set)
    resurrected_hits: set[str] = field(default_factory=set)


def _active_ids(rules: list[Rule], zone: str | None = None) -> list[str]:
    """Ids of the rules that can fire: active, and (for PAN-OS) applying to ``zone``."""
    return [
        r.id
        for r in rules
        if not r.inactive and (zone is None or not r.from_zones or zone in r.from_zones)
    ]


def _coverage(ids: list[str], hits: set[str]) -> SideCoverage:
    hit = [i for i in ids if i in hits]
    percent = round(100.0 * len(hit) / len(ids), 1) if ids else 100.0
    return SideCoverage(
        rules=len(ids), hit=len(hit), percent=percent, unhit=[i for i in ids if i not in hits]
    )


def _sweep(sides: Sides, ctx: Context, space: FlowSpace, run: _Run) -> None:
    """Check every witness and probe once. A divergence is kept; the search then shrinks it."""
    for flow in (*space.witnesses, *space.probes):
        run.examples += 1
        verdict = sides.check(ctx, flow)
        run.original_hits.add(verdict.original.rule_id)
        run.resurrected_hits.add(verdict.resurrected.rule_id)
        if verdict.entries:
            run.ledger_covered += 1
        if verdict.problem and run.swept is None:
            run.found_at = run.examples
            run.swept = sides.counterexample("search", ctx, verdict, verdict.problem)


def _minimise(
    sides: Sides, ctx: Context, space: FlowSpace, found: Counterexample
) -> Counterexample:
    """The simplest flow that still diverges the same way, starting from the one the sweep found.

    "The same way" is the same reason (the same actions, zones and ledger basis). Without it a
    smaller flow can fail for a different defect, and the counterexample would stop pointing at
    the one that was found.
    """

    def fails(flow: Flow) -> bool:
        return sides.check(ctx, flow).problem == found.reason

    verdict = sides.check(ctx, shrink_flow(space, found.flow, fails))
    return sides.counterexample("search", ctx, verdict, verdict.problem)


def _random_search(
    sides: Sides, ctx: Context, space: FlowSpace, run: _Run, budget: int, seed_value: int
) -> None:
    """Hypothesis searches ``budget`` boundary-biased flows and shrinks the first divergence."""
    flows = flow_strategy(space)

    def prop(data: st.DataObject) -> None:
        boundaries = 0.0
        for _ in range(BATCH):
            flow = data.draw(flows)
            run.examples += 1
            boundaries += space.score(flow)
            verdict = sides.check(ctx, flow)
            run.original_hits.add(verdict.original.rule_id)
            run.resurrected_hits.add(verdict.resurrected.rule_id)
            if verdict.entries:
                run.ledger_covered += 1
            if verdict.problem:
                if run.failure is None:
                    run.found_at = run.examples
                run.failure = sides.counterexample("search", ctx, verdict, verdict.problem)
                raise _Divergence
        target(boundaries / BATCH, label="boundaries")

    config = settings(
        max_examples=-(-budget // BATCH),
        derandomize=False,
        database=None,
        deadline=None,
        suppress_health_check=list(HealthCheck),
        phases=[Phase.generate, Phase.target, Phase.shrink],
        report_multiple_bugs=False,
        verbosity=Verbosity.quiet,
        print_blob=False,
    )
    search = hypothesis_seed(seed_value)(config(given(data=st.data())(prop)))
    with contextlib.suppress(_Divergence):
        search()


def _search(sides: Sides, ctx: Context, budget: int, seed_value: int) -> ContextProof:
    space = flow_space(sides.original, ctx)
    run = _Run()
    _sweep(sides, ctx, space, run)
    if run.swept is not None:  # this context already fails: minimise the flow, skip the search
        run.failure = _minimise(sides, ctx, space, run.swept)
    else:
        _random_search(sides, ctx, space, run, budget, seed_value)
    failure = run.failure
    zone = sides.zones.of_context(sides.original, ctx)
    acl_rules = [
        r for name in (ctx.acl_name, ctx.global_acl_name) for r in sides.original.acls.get(name, [])
    ]
    panos_rules = sides.resurrected.acls.get(RULEBASE, [])
    return ContextProof(
        context=ctx.name,
        implicit=not ctx.acl_name and not ctx.global_acl_name,
        examples=run.found_at or run.examples,
        passed=failure is None,
        original=_coverage(_active_ids(acl_rules), run.original_hits),
        resurrected=_coverage(_active_ids(panos_rules, zone), run.resurrected_hits),
        ledger_covered=run.ledger_covered,
        counterexample=failure,
    )


def prove(
    original: Policy,
    emitted_text: str,
    ledger: Sequence[LedgerEntry],
    *,
    budget: int,
    seed: int = DEFAULT_SEED,
    golden: Sequence[GoldenVector] = (),
) -> ProofResult:
    """Prove (or refute) that ``emitted_text`` behaves like ``original``, modulo ``ledger``.

    ``budget`` is the number of generated flows per context, between 1 and 20,000.
    Raises ``ProofInputError`` when the emitted text cannot be compared with the original, and
    ``ParseError`` when it is not valid PAN-OS ``set`` syntax.
    """
    if not 1 <= budget <= MAX_BUDGET:
        raise ValueError(f"budget must be between 1 and {MAX_BUDGET}, got {budget}")
    sides = Sides(original, emitted_text, ledger)
    golden_result = check_golden(sides, golden)
    if golden_result.failures:
        return ProofResult(
            passed=False,
            seed=seed,
            budget=budget,
            golden=golden_result,
            contexts=[],
            counterexample=golden_result.failures[0],
        )
    proofs = [_search(sides, ctx, budget, seed) for ctx in sides.contexts]
    first = next((p.counterexample for p in proofs if p.counterexample is not None), None)
    return ProofResult(
        passed=first is None,
        seed=seed,
        budget=budget,
        golden=golden_result,
        contexts=proofs,
        counterexample=first,
    )
