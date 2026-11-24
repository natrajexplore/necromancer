"""Task 8.4: performance checks (requirements 6.5 and 8.1).

* 6.5: a 10,000-example proof of each sample config completes in under 15 s.
* 8.1: parsing and autopsy of a 5,000-rule config complete in under 5 s.

The targets are for the Lambda profile (1,769 MB, one vCPU). These tests run on whatever machine
runs the suite, so each measures CPU time of the current process (not wall time, which a busy
CI runner inflates) and asserts the target directly. A slower runner than the Lambda only makes
the tests stricter. ``NECRO_PERF_SLACK`` (default 1.0) multiplies the limits for a machine known
to be slower; it never lowers them.

The work is never reduced to pass: budgets, sizes and examples are the ones the requirements
state. The proofs must still pass and autopsy must still find what it found before.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable

import pytest

from necro.autopsy import analyze
from necro.emitters import emit_panos
from necro.findings import Finding, FindingType
from necro.golden import load_golden
from necro.ir import Policy
from necro.oracle import prove
from necro.parsers import parse_config
from tests.panos_helpers import SAMPLES, policy_of
from tests.synthetic import synthetic_config

PROOF_LIMIT_S = 15.0  # requirement 6.5
AUTOPSY_LIMIT_S = 5.0  # requirement 8.1
PROOF_BUDGET = 10_000
RULES = 5_000
GOLDEN = SAMPLES.parent / "golden-flows"
CONFIGS = {
    "pix-2006-hq.cfg": "pix-2006-hq.toml",
    "asa-8.2-branch.cfg": "asa-8.2-branch.toml",
    "ios-12-edge.cfg": "ios-12-edge.toml",
}

pytestmark = pytest.mark.perf


def _slack() -> float:
    return max(1.0, float(os.environ.get("NECRO_PERF_SLACK", "1.0")))


def _cpu[R](work: Callable[[], R]) -> tuple[R, float]:
    start = time.process_time()
    result = work()
    return result, time.process_time() - start


def _autopsy(policy: Policy) -> Callable[[], list[Finding]]:
    return lambda: analyze(policy)


@pytest.mark.parametrize("name", list(CONFIGS))
def test_a_10000_example_proof_of_each_sample_takes_under_15_seconds(name: str) -> None:
    policy = policy_of(name)
    emission = emit_panos(policy)
    vectors = load_golden(GOLDEN / CONFIGS[name])

    result, seconds = _cpu(
        lambda: prove(policy, emission.text, emission.ledger, budget=PROOF_BUDGET, golden=vectors)
    )

    assert result.passed, result.counterexample
    assert result.budget == PROOF_BUDGET
    assert all(c.examples >= PROOF_BUDGET for c in result.contexts)  # the full budget ran
    assert seconds < PROOF_LIMIT_S * _slack(), f"{name}: {seconds:.2f} s"


def test_parse_and_autopsy_of_a_5000_rule_config_take_under_5_seconds() -> None:
    text = synthetic_config(RULES)

    def work() -> tuple[Policy, list[Finding]]:
        policy = parse_config(text)
        return policy, analyze(policy)

    (policy, findings), seconds = _cpu(work)

    assert sum(len(rules) for rules in policy.acls.values()) >= RULES - 10
    kinds = {f.type for f in findings}
    assert {FindingType.shadowed, FindingType.redundant, FindingType.insecure_service} <= kinds
    assert seconds < AUTOPSY_LIMIT_S * _slack(), f"{seconds:.2f} s"


def test_autopsy_cost_grows_close_to_linearly_with_the_rule_count() -> None:
    """Four times the rules must cost well under the sixteen times a quadratic algorithm would."""
    small = parse_config(synthetic_config(RULES // 4))
    large = parse_config(synthetic_config(RULES))
    _, small_s = _cpu(_autopsy(small))
    _, large_s = _cpu(_autopsy(large))
    assert large_s / max(small_s, 0.05) < 8.0, (small_s, large_s)


def test_a_heavily_overlapping_5000_rule_acl_still_finishes_and_finds_its_shadows() -> None:
    """Stress shape: about 165 real overlapping rule pairs per rule, so the work is large by
    nature (any exact method must look at each pair). It must finish, and correctly."""
    policy = parse_config(synthetic_config(RULES, shape="dense"))
    findings, seconds = _cpu(_autopsy(policy))
    shadowed = sum(1 for f in findings if f.type == FindingType.shadowed)
    assert shadowed > RULES // 2
    assert seconds < 120.0 * _slack(), f"{seconds:.2f} s"
