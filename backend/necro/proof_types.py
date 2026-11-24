"""Result models of the Proof of Life oracle (requirements 6.3, 6.4, 6.8).

``ProofResult`` is what the gates, the report, the API and the CLI read. It carries no timestamps
and no machine-specific values, so the same input, options and seed give the same result.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from necro.ir import Action, Decision, Flow


class Counterexample(BaseModel):
    """One flow on which the original and the resurrected policy disagree.

    ``flow`` is in the source config's address space and ``panos_flow`` is the same flow as a
    PAN-OS rule sees it (policy-semantics 1.5). ``original_zone`` is the egress zone the source
    gave, translated to the PAN-OS zone name for comparison with ``resurrected.to_zone``.
    """

    source: Literal["golden", "search"]
    context: str
    flow: Flow
    panos_flow: Flow
    original: Decision
    resurrected: Decision
    original_zone: str
    expected_action: Action
    ledger_ids: list[str] = Field(default_factory=list)
    reason: str
    vector_id: str = ""


class SideCoverage(BaseModel):
    """How many of the active rules one side exercised, and which it did not (requirement 6.4)."""

    rules: int
    hit: int
    percent: float
    unhit: list[str]


class ContextProof(BaseModel):
    """The outcome of the search for one ingress context."""

    context: str
    implicit: bool  # no ACL is bound: the implicit behaviour of the source is what is proven
    examples: int  # flows checked (up to and including the first divergence)
    passed: bool
    original: SideCoverage
    resurrected: SideCoverage
    ledger_covered: int  # examples decided by a ledger entry instead of the source decision
    counterexample: Counterexample | None = None


class GoldenResult(BaseModel):
    """The hand-verified flows run against both sides (requirement 6.8)."""

    total: int
    passed: int
    failures: list[Counterexample] = Field(default_factory=list)

    @property
    def all_passed(self) -> bool:
        return not self.failures


class ProofResult(BaseModel):
    """Evidence for or against equivalence of the resurrected policy (property P2)."""

    passed: bool
    seed: int
    budget: int  # examples per context
    golden: GoldenResult
    contexts: list[ContextProof]
    counterexample: Counterexample | None = None  # the first divergence, golden flows first

    @property
    def examples(self) -> int:
        return sum(c.examples for c in self.contexts)
