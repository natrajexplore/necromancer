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

API_VERSION = "v1"
MAX_BUDGET = 20_000  # security steering: oracle capped at 20,000 examples per request
MAX_GOLDEN_CHARS = 512 * 1024  # golden flows are small; the request body is capped anyway

DialectName = Literal["pix", "asa", "ios"]


class ConfigRequest(BaseModel):
    """A config to work on. ``dialect`` overrides detection."""

    config: str
    dialect: DialectName | None = None


class ProveRequest(ConfigRequest):
    """``budget`` (examples per context) wins over ``profile`` (dev, ci or demo)."""

    budget: int | None = Field(default=None, ge=1, le=MAX_BUDGET)
    seed: int | None = Field(default=None, ge=0, le=2**63 - 1)
    profile: str | None = None
    haunt: bool = False  # demo: prove a deliberately broken candidate (necro.haunt); prove only


class GateRequest(ProveRequest):
    """Gates and the report. ``budget`` and ``profile`` default to the ``ci`` budget, because a
    GO verdict needs it. ``sidecar`` carries waivers, accepted risks, ledger decisions and the
    change record; the hosted demo does not store it. ``golden`` is golden-flow TOML text."""

    sidecar: Sidecar | None = None
    golden: str | None = Field(default=None, max_length=MAX_GOLDEN_CHARS)
    name: str | None = Field(default=None, max_length=120)  # label of the input in the report

    @field_validator("haunt")
    @classmethod
    def _refuse_haunt(cls, value: bool) -> bool:
        """A verdict or report never rests on a deliberately broken candidate."""
        if value:
            raise ValueError("haunt is only available for prove, never for gates or the report")
        return value


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


class ResurrectResult(BaseModel):
    api_version: str = API_VERSION
    dialect: str
    config: str
    config_lines: int
    ledger: list[LedgerEntry]
    unsupported: list[str]
    notes: list[str]
    blocking: list[LineIssue]


class ProveResult(BaseModel):
    api_version: str = API_VERSION
    dialect: str
    passed: bool
    proof: ProofResult
    ledger_entries: int
    blocking_lines: int
    haunted: bool = False  # True: the proof ran on a deliberately broken candidate (necro.haunt)


class GateResponse(BaseModel):
    """Gates G1 to G6 and the readiness verdict, with the audit header on the verdict."""

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


class GrimoireResponse(GateResponse):
    """The verdict plus the Grimoire report as Markdown and as HTML (redacted text only).

    ``body_sha256`` is the SHA-256 of the Markdown body with the generated time masked: it is
    equal for equal input, options and seed (requirement 3.2).
    """

    markdown: str
    html: str
    body_sha256: str
