"""Finding model shared by the autopsy modules."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel

from necro import autopsy_text as text


class Severity(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


SEVERITY_RANK = {Severity.critical: 3, Severity.high: 2, Severity.medium: 1, Severity.low: 0}


class FindingType(StrEnum):
    shadowed = "shadowed"
    redundant = "redundant"
    overly_broad = "overly-broad"
    insecure_service = "insecure-service"
    unused_object = "unused-object"
    unused_acl = "unused-acl"
    insecure_management = "insecure-management"
    unfiltered_interface = "unfiltered-interface"
    return_traffic = "return-traffic"
    no_remark = "no-remark"


class Finding(BaseModel):
    """One autopsy finding. ``rule_ref`` is a rule id (``ACL#3``) or a subject such as
    ``interface:inside``; ``source_line`` is the line in the redacted source it points at."""

    id: str = ""
    type: FindingType
    severity: Severity
    rule_ref: str
    related: list[str] = []
    source_line: int = 0
    zone: str = ""
    explanation: str
    recommendation: str
    label: str
    verified: bool = False  # confirmed with decide() on a witness flow


def make_finding(
    kind: FindingType,
    severity: Severity,
    rule_ref: str,
    *,
    related: list[str] | None = None,
    source_line: int = 0,
    zone: str = "",
    verified: bool = False,
    **details: str,
) -> Finding:
    """Build a finding with the standard wording for ``kind``."""
    label, explanation, recommendation = text.render(
        kind.value, rule_ref=rule_ref, zone=zone or "an unknown zone", **details
    )
    return Finding(
        type=kind,
        severity=severity,
        rule_ref=rule_ref,
        related=related or [],
        source_line=source_line,
        zone=zone,
        explanation=explanation,
        recommendation=recommendation,
        label=label,
        verified=verified,
    )
