"""Models of the migration-governance layer (requirements 2.2, 2.3, 3.1, 6.2).

The engine produces evidence; these models carry the human side of an approval: waivers,
accepted risks, ledger decisions and change metadata (the *sidecar*), and the results of the
gates and the verdict. Everything a human supplies is validated strictly. An unknown key in a
sidecar is an error, because a misspelled ``waivers`` would otherwise drop every waiver silently.
"""

from __future__ import annotations

import json
import re
import tomllib
from datetime import date, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from necro.tighten import ApprovalDecision

GateId = Literal["G1", "G2", "G3", "G4", "G5", "G6"]
GATE_IDS: tuple[GateId, ...] = ("G1", "G2", "G3", "G4", "G5", "G6")

# ``line:57`` (a source line), ``finding:AUT-0012`` (an autopsy finding), ``ledger:LED-0003``
_TARGET = re.compile(r"^(line:[1-9][0-9]*|finding:[A-Za-z0-9_.-]+|ledger:[A-Za-z0-9_.-]+)$")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Waiver(_Strict):
    """A named human's decision to accept something that would otherwise block the verdict.

    It is valid up to and including ``expires_on``. An expired waiver counts as missing.
    """

    target: str
    reason: str
    approver: str
    expires_on: date

    @field_validator("target")
    @classmethod
    def _known_target(cls, value: str) -> str:
        if not _TARGET.match(value):
            raise ValueError("target must be line:<n>, finding:<id> or ledger:<id>")
        return value

    @field_validator("reason", "approver")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty")
        return value.strip()

    @property
    def kind(self) -> str:
        return self.target.split(":", 1)[0]

    @property
    def subject(self) -> str:
        return self.target.split(":", 1)[1]

    def valid_on(self, today: date) -> bool:
        return today <= self.expires_on


class ChangeMeta(_Strict):
    """The change record the verdict belongs to (governance phase P5)."""

    change_id: str | None = None
    requested_by: str | None = None
    peer_reviewer: str | None = None
    cab_reference: str | None = None
    window_start: datetime | None = None
    window_end: datetime | None = None

    @model_validator(mode="after")
    def _window_in_order(self) -> ChangeMeta:
        if self.window_start and self.window_end and self.window_end <= self.window_start:
            raise ValueError("window_end must be after window_start")
        return self


class RunbookOverrides(_Strict):
    """Changes to the runbook defaults (requirement 5.4): rollback triggers, the time the change
    owner has to decide on a rollback, and the hypercare period. ``None`` keeps the default."""

    rollback_triggers: list[str] | None = None
    decision_time_limit_minutes: int | None = Field(default=None, ge=1, le=1440)
    hypercare_business_days: int | None = Field(default=None, ge=1, le=90)

    @field_validator("rollback_triggers")
    @classmethod
    def _triggers_not_blank(cls, value: list[str] | None) -> list[str] | None:
        if value is not None:
            if not value or any(not item.strip() for item in value):
                raise ValueError("rollback triggers must be a non-empty list of non-blank text")
            return [item.strip() for item in value]
        return value


class Sidecar(_Strict):
    """Waivers, accepted risks, ledger decisions and change metadata, from a JSON or TOML file.

    ``ledger_decisions`` maps a ledger entry id to a decision by a named human. A bare
    ``"accepted"`` is refused: governance requires an approver and a date for every decision.
    """

    waivers: list[Waiver] = Field(default_factory=list)
    accepted_risks: list[Waiver] = Field(default_factory=list)
    ledger_decisions: dict[str, ApprovalDecision] = Field(default_factory=dict)
    change: ChangeMeta = Field(default_factory=ChangeMeta)
    runbook: RunbookOverrides = Field(default_factory=RunbookOverrides)

    @field_validator("ledger_decisions", mode="before")
    @classmethod
    def _decisions_need_a_person(cls, value: object) -> object:
        if isinstance(value, dict):
            for key, decision in value.items():
                if isinstance(decision, str):
                    raise ValueError(
                        f"ledger decision for {key} needs approval, approver and decided_at, "
                        f"not just {decision!r}"
                    )
        return value

    @field_validator("accepted_risks")
    @classmethod
    def _risks_are_findings(cls, value: list[Waiver]) -> list[Waiver]:
        for risk in value:
            if risk.kind != "finding":
                raise ValueError(f"an accepted risk targets a finding, not {risk.target}")
        return value


def parse_sidecar(text: str, fmt: Literal["json", "toml"]) -> Sidecar:
    """A sidecar from JSON or TOML text. Raises ``ValueError`` on bad syntax or content."""
    try:
        data = json.loads(text) if fmt == "json" else tomllib.loads(text)
    except (json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"the sidecar is not valid {fmt.upper()}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("the sidecar must be a table / object at the top level")
    return Sidecar.model_validate(data)


def load_sidecar(path: Path) -> Sidecar:
    """A sidecar from a ``.json`` or ``.toml`` file."""
    suffix = path.suffix.lower()
    if suffix not in (".json", ".toml"):
        raise ValueError(f"a sidecar is a .json or .toml file, not {path.name}")
    fmt: Literal["json", "toml"] = "json" if suffix == ".json" else "toml"
    return parse_sidecar(path.read_text(encoding="utf-8"), fmt)


# -- results ------------------------------------------------------------------------------------


class Check(_Strict):
    """One thing a gate checked. ``ok`` is False for a problem; ``waiver`` covers it if valid."""

    id: str
    ok: bool
    severity: Literal["error", "warning"]
    detail: str
    waiver: Waiver | None = None


class GateResult(_Strict):
    """``fail`` when an error is not waived; ``waived`` when every error is; else ``pass``."""

    gate: GateId
    status: Literal["pass", "fail", "waived"]
    checks: list[Check]
    blocking_reasons: list[str]


class AuditHeader(_Strict):
    """What a reader needs to reproduce or trust a result (requirement 3.1).

    ``generated_at`` is the only value that changes between two identical runs.
    """

    tool_version: str
    git_commit: str
    inputs: dict[str, str]  # input name -> SHA-256
    dialect: str
    os_version: str
    options: dict[str, str] = Field(default_factory=dict)
    seed: int | None = None
    budget: int | None = None
    profile: str | None = None
    generated_at: datetime
    outputs: dict[str, str] = Field(default_factory=dict)  # artifact name -> SHA-256


class Verdict(_Strict):
    """GO, CONDITIONAL or NO-GO, with every reason in gate order (requirement 2.1)."""

    value: Literal["GO", "CONDITIONAL", "NO-GO"]
    gates: list[GateResult]
    blocking_reasons: list[str]  # why NO-GO, in gate order
    conditions: list[str]  # why CONDITIONAL rather than GO
    waivers_used: list[Waiver]
    notes: list[str] = Field(default_factory=list)  # worth reading, changes nothing
    audit: AuditHeader | None = None
