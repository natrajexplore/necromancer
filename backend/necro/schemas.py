"""Versioned (v1) request and response schemas shared by the API, the MCP server and the CLI.

Responses carry redacted text only: line texts come from the parser's line records, which are
built from the redacted source (security steering, "Secret redaction on ingest").
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator

from necro.findings import Finding
from necro.gate_models import Sidecar, Verdict
from necro.ledger import LedgerEntry
from necro.proof_types import ProofResult
from necro.tighten import ApprovalDecision, Choice, RemediationKind, Skipped

API_VERSION = "v1"
MAX_BUDGET = 20_000  # security steering: oracle capped at 20,000 examples per request
MAX_GOLDEN_CHARS = 512 * 1024  # golden flows are small; the request body is capped anyway

DialectName = Literal["pix", "asa", "ios"]


class ConfigRequest(BaseModel):
    """A config to work on. ``dialect`` overrides detection."""

    config: str
    dialect: DialectName | None = None


class TighteningSelection(BaseModel):
    """The remediations a human chose, one ``Choice`` per finding, and their decisions.

    ``approvals`` maps a finding id to a decision on that finding's ledger entries. A rejected
    one stays in the ledger but its change is left out of the tightened artifact."""

    choices: list[Choice] = Field(default_factory=list, max_length=1000)
    approvals: dict[str, ApprovalDecision] = Field(default_factory=dict)


class ProveRequest(ConfigRequest):
    """``budget`` (examples per context) wins over ``profile`` (dev, ci or demo)."""

    budget: int | None = Field(default=None, ge=1, le=MAX_BUDGET)
    seed: int | None = Field(default=None, ge=0, le=2**63 - 1)
    profile: str | None = None
    haunt: bool = False  # demo: prove a deliberately broken candidate (necro.haunt); prove only
    # name of a built-in sample: its golden flows from samples/golden-flows run first
    sample: str | None = Field(default=None, max_length=64, pattern=r"^[a-z0-9][a-z0-9.-]*$")


class GateRequest(ProveRequest):
    """Gates and the report. ``budget`` and ``profile`` default to the ``ci`` budget, because a
    GO verdict needs it. ``sidecar`` carries waivers, accepted risks, ledger decisions and the
    change record; the hosted demo does not store it. ``golden`` is golden-flow TOML text and
    beats the golden flows of ``sample``."""

    sidecar: Sidecar | None = None
    # the remediations to build and judge a tightened artifact from, as for resurrect. The
    # baseline verdict is the same with or without it (governance R1)
    tightening: TighteningSelection | None = None
    golden: str | None = Field(default=None, max_length=MAX_GOLDEN_CHARS)
    name: str | None = Field(default=None, max_length=120)  # label of the input in the report

    @field_validator("haunt")
    @classmethod
    def _refuse_haunt(cls, value: bool) -> bool:
        """A verdict or report never rests on a deliberately broken candidate."""
        if value:
            raise ValueError("haunt is only available for prove, never for gates or the report")
        return value


class ResurrectRequest(ConfigRequest):
    """Resurrect, optionally with a tightening selection (requirement 5.1).

    Without ``tightening`` the answer holds the baseline and the remediation proposals. With it,
    the answer also holds a separate tightened artifact, proved on its own. ``budget``, ``seed``
    and ``profile`` size that proof. ``sample`` names a built-in sample whose golden flows run."""

    tightening: TighteningSelection | None = None
    budget: int | None = Field(default=None, ge=1, le=MAX_BUDGET)
    seed: int | None = Field(default=None, ge=0, le=2**63 - 1)
    profile: str | None = None
    sample: str | None = Field(default=None, max_length=64, pattern=r"^[a-z0-9][a-z0-9.-]*$")


class ErrorBody(BaseModel):
    """The structured error of requirement 7.5."""

    code: str
    message: str
    line_no: int | None = None


class LineIssue(BaseModel):
    """A source line that was not migrated (redacted text)."""

    line_no: int
    text: str
    reason: str
    security_relevant: bool
    waived: bool = False


class InterfaceSummary(BaseModel):
    nameif: str
    hw_name: str
    security_level: int
    address: str


class AclSummary(BaseModel):
    name: str
    rules: int
    classification: str = ""  # IOS: policy, management-plane, non-policy or unused


class CoverageSummary(BaseModel):
    total_lines: int
    counts: dict[str, int]
    security_relevant: int
    handled: int
    waived: int
    blocking: int
    ratio: float


class ExhumeResult(BaseModel):
    api_version: str = API_VERSION
    dialect: str
    os_version: str
    mode: str
    address_space: str
    detection_confidence: float
    input_sha256: str
    interfaces: list[InterfaceSummary]
    acls: list[AclSummary]
    bindings: int
    nat_rules: int
    coverage: CoverageSummary
    unparsed: list[LineIssue]


class AutopsyResult(BaseModel):
    api_version: str = API_VERSION
    dialect: str
    findings: list[Finding]
    by_severity: dict[str, int]
    by_type: dict[str, int]


class Proposal(BaseModel):
    """One remediation offered for one autopsy finding (requirement 5.1)."""

    finding_id: str
    finding_type: str
    severity: str
    kind: RemediationKind
    rule_ref: str
    summary: str
    needs_networks: bool  # narrow-any: the user must confirm the networks (an object group)


class TightenedResult(BaseModel):
    """The tightened PAN-OS candidate: a separate artifact with its own ledger and proof.

    ``ledger`` holds the tightening entries and the emitter's like-for-like entries for this
    config. ``proof`` is None when the candidate cannot be compared (see ``proof_error``)."""

    config: str
    config_lines: int
    ledger: list[LedgerEntry]
    applied: list[str]
    skipped: list[Skipped]
    notes: list[str]
    validation_errors: list[str]
    proof: ProofResult | None
    proof_error: str = ""
    passed: bool  # True only when the proof ran and passed


class ResurrectResult(BaseModel):
    """The baseline (like for like) is never changed by a tightening selection."""

    api_version: str = API_VERSION
    dialect: str
    config: str
    config_lines: int
    ledger: list[LedgerEntry]
    unsupported: list[str]
    notes: list[str]
    blocking: list[LineIssue]
    proposals: list[Proposal] = Field(default_factory=list)
    tightened: TightenedResult | None = None


class ProveResult(BaseModel):
    api_version: str = API_VERSION
    dialect: str
    passed: bool
    proof: ProofResult
    ledger_entries: int
    blocking_lines: int
    haunted: bool = False  # True: the proof ran on a deliberately broken candidate (necro.haunt)


class TightenedGate(BaseModel):
    """The verdict on the tightened artifact: a separate change judged on its own evidence.

    G4 reads the tightened artifact's own proof, G6 the findings of the tightened policy.
    ``ledger`` holds its entries with the sidecar's decisions applied. ``accepted`` counts the
    remediations a person accepted."""

    verdict: Verdict
    proof_passed: bool | None
    golden_total: int
    golden_passed: int
    applied: list[str]
    accepted: int
    ledger: list[LedgerEntry]


class GateResponse(BaseModel):
    """Gates G1 to G6 and the readiness verdict, with the audit header on the verdict.

    ``verdict`` is the baseline (like for like). ``tightened`` is present only when a tightening
    selection was sent, and never changes ``verdict``."""

    api_version: str = API_VERSION
    dialect: str
    verdict: Verdict
    coverage: CoverageSummary
    proof_passed: bool | None  # None when the proof could not run
    examples_per_context: int
    seed: int
    profile: str
    golden_total: int
    golden_passed: int
    ledger: list[LedgerEntry] = Field(default_factory=list)  # baseline, decisions applied
    tightened: TightenedGate | None = None


class GrimoireResponse(GateResponse):
    """The verdict plus the Grimoire report as Markdown and as HTML (redacted text only).

    ``body_sha256`` is the SHA-256 of the Markdown body with the generated time masked: it is
    equal for equal input, options and seed (requirement 3.2).
    """

    markdown: str
    html: str
    body_sha256: str
