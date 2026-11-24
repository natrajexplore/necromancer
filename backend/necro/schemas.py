"""Versioned (v1) request and response schemas shared by the API, the MCP server and the CLI.

Responses carry redacted text only: line texts come from the parser's line records, which are
built from the redacted source (security steering, "Secret redaction on ingest").
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from necro.findings import Finding
from necro.ledger import LedgerEntry
from necro.proof_types import ProofResult

API_VERSION = "v1"
MAX_BUDGET = 20_000  # security steering: oracle capped at 20,000 examples per request

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
