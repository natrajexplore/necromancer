"""Line accounting and coverage (requirement 1.9, property P14).

Every input line is classified exactly once as ``migrated``, ``not-policy``, ``management-plane``,
``out-of-scope`` or ``unparsed``. Coverage is the share of security-relevant lines that were
migrated or handled by the management plane; anything else blocks the verdict until a named human
waives it (the waiver itself lives in the governance layer and arrives here as ``waiver_id``).
"""

from __future__ import annotations

from dataclasses import dataclass

from necro.ir import LineRecord, Policy, UnparsedLine
from necro.parsers.cisco_common import split_lines

CLASSES = ("migrated", "not-policy", "management-plane", "out-of-scope", "unparsed")
_HANDLED = ("migrated", "management-plane")
_NOT_MIGRATED = ("out-of-scope", "unparsed")


class AccountingError(Exception):
    """The line records don't account for every input line exactly once."""


@dataclass(frozen=True)
class Coverage:
    """Counts over the line records of one parsed config."""

    total_lines: int
    counts: dict[str, int]  # classification -> number of lines; sums to total_lines
    security_relevant: int
    handled: int  # relevant lines that were migrated or are management-plane
    waived: int  # relevant, not handled, but carrying a waiver id
    blocking: int  # relevant, not handled, no waiver: these block the verdict
    ratio: float  # handled / security_relevant, or 1.0 when nothing is relevant


def compute_coverage(policy: Policy) -> Coverage:
    """Summarise ``policy.line_records``."""
    counts = dict.fromkeys(CLASSES, 0)
    relevant = handled = waived = blocking = 0
    for rec in policy.line_records:
        counts[rec.classification] += 1
        if not rec.security_relevant:
            continue
        relevant += 1
        if rec.classification in _HANDLED:
            handled += 1
        elif rec.waiver_id:
            waived += 1
        else:
            blocking += 1
    ratio = handled / relevant if relevant else 1.0
    return Coverage(
        total_lines=len(policy.line_records),
        counts=counts,
        security_relevant=relevant,
        handled=handled,
        waived=waived,
        blocking=blocking,
        ratio=ratio,
    )


def blocking_lines(policy: Policy) -> list[UnparsedLine]:
    """Security-relevant lines that were not migrated and have no waiver."""
    waived = {r.line_no for r in policy.line_records if r.waiver_id}
    return [u for u in policy.unparsed if u.security_relevant and u.line_no not in waived]


def verify_accounting(policy: Policy, text: str) -> Coverage:
    """Check that every line of ``text`` is classified exactly once. Raises AccountingError.

    ``text`` must be the text the parser saw (the redacted text). Returns the Coverage on success.
    """
    line_count = len(split_lines(text))
    records: list[LineRecord] = policy.line_records
    if [r.line_no for r in records] != list(range(1, line_count + 1)):
        raise AccountingError(
            f"expected line records 1..{line_count}, got {len(records)} records "
            f"(line numbers must be unique, contiguous and in order)"
        )
    bad = [r.line_no for r in records if r.classification not in CLASSES]
    if bad:
        raise AccountingError(f"unknown classification on lines {bad}")
    unparsed_lines = {r.line_no for r in records if r.classification in _NOT_MIGRATED}
    listed = [u.line_no for u in policy.unparsed]
    if sorted(listed) != sorted(unparsed_lines) or len(listed) != len(set(listed)):
        raise AccountingError("unparsed lines and line records disagree")
    relevance = {r.line_no: r.security_relevant for r in records}
    for u in policy.unparsed:
        if relevance[u.line_no] != u.security_relevant:
            raise AccountingError(f"line {u.line_no}: relevance differs between record and entry")
    cov = compute_coverage(policy)
    if sum(cov.counts.values()) != line_count:
        raise AccountingError("classification counts don't sum to the line count")
    return cov
