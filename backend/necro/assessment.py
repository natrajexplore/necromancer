"""Everything the verdict and the Grimoire are built from, computed once.

The work splits in two so that it can be repeated cheaply:

* ``compute_core`` does the expensive, sidecar-independent work: findings, the PAN-OS candidate, its
  static validation, the equivalence proof, the zone matrices and the verification commands.
* ``assemble`` adds what the human supplied (waivers, accepted risks, ledger decisions, change
  record) and the clock: the gates, the verdict, the runbook and the audit header. It is cheap
  and pure, so a test can assemble the same core thousands of times (property P11).

Baseline and tightened candidates stay separate artifacts, each with its own proof, ledger and
verdict (governance rule R1). The tightened candidate exists only when the caller chose
remediations.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime

from necro.audit import build_audit, sha256_text
from necro.autopsy import analyze
from necro.coverage import Coverage, compute_coverage
from necro.emitters import PanosEmission, emit_panos
from necro.findings import Finding
from necro.gate_models import AuditHeader, Sidecar, Verdict
from necro.gates import evaluate
from necro.golden import GoldenVector
from necro.ir import ParseError, Policy
from necro.ledger import LedgerEntry
from necro.oracle import prove as run_prove
from necro.oracle_core import ProofInputError
from necro.proof_types import ProofResult
from necro.runbook import Commands, Runbook, build_commands, build_runbook
from necro.secret_counts import count_secrets
from necro.tighten import ApprovalDecision, Choice, TightenedArtifact, resurrect_tightened
from necro.validate_panos import Validation, validate_panos
from necro.zone_matrix import ZoneMatrix, matrix_after, matrix_before

BASELINE_OUTPUT = "panos-baseline.set"
TIGHTENED_OUTPUT = "panos-tightened.set"
SOURCE_OUTPUT = "source-redacted.cfg"


@dataclass(frozen=True)
class TightenedCore:
    """The tightened candidate and its own evidence (a separate change, governance P10)."""

    artifact: TightenedArtifact
    validation: Validation
    proof: ProofResult | None
    proof_error: str
    matrix: ZoneMatrix


@dataclass(frozen=True)
class Core:
    """The sidecar-independent results for one source config."""

    input_name: str
    original_sha256: str
    policy: Policy
    findings: list[Finding]
    emission: PanosEmission
    validation: Validation
    proof: ProofResult | None
    proof_error: str
    golden: tuple[GoldenVector, ...]
    coverage: Coverage
    matrix_before: ZoneMatrix
    matrix_after: ZoneMatrix
    commands: Commands
    secrets: dict[str, int]
    redacted_source: str
    options: dict[str, str]
    seed: int
    budget: int
    profile: str
    tightened: TightenedCore | None


@dataclass(frozen=True)
class TightenedAssessment:
    core: TightenedCore
    verdict: Verdict
    ledger: list[LedgerEntry]


@dataclass(frozen=True)
class Assessment:
    """A core plus the sidecar and the clock: what the report is rendered from."""

    core: Core
    sidecar: Sidecar
    today: date
    verdict: Verdict
    ledger: list[LedgerEntry]
    runbook: Runbook
    tightened: TightenedAssessment | None

    @property
    def audit(self) -> AuditHeader:
        assert self.verdict.audit is not None  # assemble always sets it
        return self.verdict.audit


def redacted_source(policy: Policy) -> str:
    """The redacted config rebuilt from the parser's line records (one text per source line)."""
    records = sorted(policy.line_records, key=lambda r: r.line_no)
    return "".join(f"{r.text}\n" for r in records)


def apply_decisions(ledger: Sequence[LedgerEntry], sidecar: Sidecar) -> list[LedgerEntry]:
    """The ledger with the sidecar's decisions applied, for display. Gates read the sidecar."""
    out: list[LedgerEntry] = []
    for entry in ledger:
        decision = sidecar.ledger_decisions.get(entry.id)
        if decision is None:
            out.append(entry)
        else:
            update = {
                "approval": decision.approval,
                "approver": decision.approver,
                "decided_at": decision.decided_at,
            }
            out.append(entry.model_copy(update=update))
    return out


def _prove(
    policy: Policy,
    emission_text: str,
    ledger: Sequence[LedgerEntry],
    budget: int,
    seed: int,
    golden: Sequence[GoldenVector],
) -> tuple[ProofResult | None, str]:
    """The proof, or None and the reason when the candidate cannot be compared."""
    try:
        proof = run_prove(policy, emission_text, ledger, budget=budget, seed=seed, golden=golden)
    except (ProofInputError, ParseError) as exc:
        return None, str(exc)
    return proof, ""


def _commands(policy: Policy, emission: PanosEmission, golden: Sequence[GoldenVector]) -> Commands:
    try:
        return build_commands(policy, emission, golden)
    except (ProofInputError, ParseError) as exc:
        return Commands(source_note=f"Verification commands could not be built: {exc}.")


def _tighten(
    policy: Policy,
    findings: list[Finding],
    choices: Sequence[Choice],
    approvals: Mapping[str, ApprovalDecision],
    budget: int,
    seed: int,
    golden: Sequence[GoldenVector],
) -> TightenedCore:
    artifact = resurrect_tightened(policy, findings, list(choices), dict(approvals))
    proof, error = _prove(policy, artifact.emission.text, artifact.ledger, budget, seed, golden)
    return TightenedCore(
        artifact=artifact,
        validation=validate_panos(artifact.emission.text, artifact.ledger),
        proof=proof,
        proof_error=error,
        matrix=matrix_after(artifact.emission.text),
    )


def compute_core(
    policy: Policy,
    *,
    original_sha256: str,
    input_name: str,
    budget: int,
    seed: int,
    profile: str,
    golden: Sequence[GoldenVector] = (),
    options: Mapping[str, str] | None = None,
    choices: Sequence[Choice] = (),
    approvals: Mapping[str, ApprovalDecision] | None = None,
) -> Core:
    """Run the engine on a parsed policy: findings, candidate, validation, proof, matrices."""
    findings = analyze(policy)
    emission = emit_panos(policy)
    proof, proof_error = _prove(policy, emission.text, emission.ledger, budget, seed, golden)
    tightened = (
        _tighten(policy, findings, choices, approvals or {}, budget, seed, golden)
        if choices
        else None
    )
    return Core(
        input_name=input_name,
        original_sha256=original_sha256,
        policy=policy,
        findings=findings,
        emission=emission,
        validation=validate_panos(emission.text, emission.ledger),
        proof=proof,
        proof_error=proof_error,
        golden=tuple(golden),
        coverage=compute_coverage(policy),
        matrix_before=matrix_before(policy, emission.zones),
        matrix_after=matrix_after(emission.text),
        commands=_commands(policy, emission, golden),
        secrets=count_secrets(r.text for r in policy.line_records),
        redacted_source=redacted_source(policy),
        options=dict(options or {}),
        seed=seed,
        budget=budget,
        profile=profile,
        tightened=tightened,
    )


def _audit(core: Core, generated_at: datetime) -> AuditHeader:
    outputs = {
        BASELINE_OUTPUT: sha256_text(core.emission.text),
        SOURCE_OUTPUT: sha256_text(core.redacted_source),
    }
    if core.tightened is not None:
        outputs[TIGHTENED_OUTPUT] = sha256_text(core.tightened.artifact.emission.text)
    return build_audit(
        core.policy,
        original_sha256=core.original_sha256,
        outputs=dict(sorted(outputs.items())),
        options=core.options,
        seed=core.seed,
        budget=core.budget,
        profile=core.profile,
        generated_at=generated_at,
        input_name=core.input_name,
    )


def assemble(core: Core, sidecar: Sidecar, today: date, generated_at: datetime) -> Assessment:
    """Gates, verdict, runbook and audit header for a core. Pure: the clock is passed in."""
    audit = _audit(core, generated_at)
    verdict = evaluate(
        core.policy,
        core.findings,
        core.emission,
        core.validation,
        core.proof,
        core.emission.ledger,
        sidecar,
        today,
        audit=audit,
    )
    tightened: TightenedAssessment | None = None
    tightening_entries: list[LedgerEntry] = []
    if core.tightened is not None:
        artifact = core.tightened.artifact
        tightening_entries = artifact.result.ledger
        tightened = TightenedAssessment(
            core.tightened,
            evaluate(
                core.policy,
                core.findings,
                artifact.emission,
                core.tightened.validation,
                core.tightened.proof,
                artifact.ledger,
                sidecar,
                today,
                audit=audit,
            ),
            apply_decisions(artifact.ledger, sidecar),
        )
    runbook = build_runbook(
        core.policy,
        core.emission,
        core.commands,
        core.emission.ledger,
        core.proof,
        sidecar,
        secret_total=sum(core.secrets.values()),
        tightened_ledger=tightening_entries,
    )
    return Assessment(
        core=core,
        sidecar=sidecar,
        today=today,
        verdict=verdict,
        ledger=apply_decisions(core.emission.ledger, sidecar),
        runbook=runbook,
        tightened=tightened,
    )
