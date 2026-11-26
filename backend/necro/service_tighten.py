"""Remediation proposals and the tightened artifact behind ``resurrect`` (requirement 5).

Kept apart from ``service`` so the baseline path stays small. Nothing here changes the baseline:
the tightened PAN-OS candidate is emitted from a copy of the policy, gets its own ledger, its own
static validation and its own proof (governance R1, property P6). Errors are ``ValueError``s that
``service`` turns into ``NecroError``.
"""

from __future__ import annotations

from collections.abc import Sequence

from necro.findings import Finding, Severity
from necro.golden import GoldenVector
from necro.ir import ParseError, Policy
from necro.oracle import DEFAULT_SEED, ProofInputError
from necro.oracle import prove as run_prove
from necro.schemas import Proposal, TightenedResult, TighteningSelection
from necro.tighten import RemediationKind, offer_remediations, resurrect_tightened
from necro.validate_panos import validate_panos

_ORDER = {Severity.critical: 0, Severity.high: 1, Severity.medium: 2, Severity.low: 3}


def proposals_for(findings: Sequence[Finding]) -> list[Proposal]:
    """The remediation offered for each finding, most severe first, then in finding order."""
    by_id = {f.id: f for f in findings}
    offered = [
        Proposal(
            finding_id=o.finding_id,
            finding_type=by_id[o.finding_id].type.value,
            severity=by_id[o.finding_id].severity.value,
            kind=o.kind,
            rule_ref=o.rule_ref,
            summary=o.summary,
            needs_networks=o.kind == RemediationKind.narrow_any,
        )
        for o in offer_remediations(list(findings))
    ]
    return sorted(offered, key=lambda p: _ORDER[Severity(p.severity)])  # stable sort


def tightened_for(
    policy: Policy,
    findings: list[Finding],
    selection: TighteningSelection,
    *,
    budget: int,
    seed: int | None,
    golden: Sequence[GoldenVector],
) -> TightenedResult:
    """Tighten with the chosen remediations, validate and prove the result on its own.

    Raises ``ValueError`` for an unknown or duplicated finding id.
    """
    artifact = resurrect_tightened(policy, findings, selection.choices, selection.approvals)
    emission = artifact.emission
    ledger = artifact.ledger
    proof = None
    error = ""
    try:
        proof = run_prove(
            policy,
            emission.text,
            ledger,
            budget=budget,
            seed=DEFAULT_SEED if seed is None else seed,
            golden=golden,
        )
    except (ProofInputError, ParseError) as exc:
        error = str(exc)
    validation = validate_panos(emission.text, ledger)
    return TightenedResult(
        config=emission.text,
        config_lines=len(emission.lines),
        ledger=ledger,
        applied=artifact.result.applied,
        skipped=artifact.result.skipped,
        notes=artifact.result.notes,
        validation_errors=[f"{c.id}: {c.detail}" for c in validation.errors],
        proof=proof,
        proof_error=error,
        passed=proof is not None and proof.passed,
    )
