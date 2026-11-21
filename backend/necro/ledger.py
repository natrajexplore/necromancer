"""Exorcism ledger entries (policy-semantics section 7, requirements 4.3 and 5.2).

An entry records one place where the resurrected policy does not behave like the source, or where
the behaviour is only equivalent by a separate argument (to-the-box traffic, time ranges). Every
entry names the flows it covers (``regions``) and the decision the resurrected policy gives them
(``new_action``). The oracle compares a flow covered by an entry against that declared action,
not against the source decision (policy-semantics section 7).

Entries start ``pending``. A pending entry blocks a GO verdict (governance gate G5) until a named
human accepts or rejects it. An ``informational`` entry (old and new decision agree) documents a
mapping without changing any decision.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import AliasChoices, BaseModel, ConfigDict, Field

from necro.boxes import Box
from necro.ir import Action, Flow, LedgerClass


class Approval(StrEnum):
    pending = "pending"
    accepted = "accepted"
    rejected = "rejected"


class LedgerEntry(BaseModel):
    """One divergence (or one explained mapping) between the source and the resurrected policy."""

    model_config = ConfigDict(arbitrary_types_allowed=True, populate_by_name=True)

    id: str = ""
    entry_class: LedgerClass = Field(
        validation_alias=AliasChoices("class", "entry_class"), serialization_alias="class"
    )
    reason: str
    affected: str  # human-readable description of the flows covered
    context: str  # ingress context name (``outside:in``), or ``any``
    old_action: Action
    new_action: Action
    finding_ref: str = ""
    approval: Approval = Approval.pending
    approver: str = ""
    decided_at: str = ""
    informational: bool = False
    regions: list[Box] = Field(default_factory=list, exclude=True)

    def covers(self, context: str, flow: Flow) -> bool:
        """Whether ``flow`` entering on ``context`` lies in this entry's region."""
        if self.context not in ("any", context):
            return False
        return any(region.contains(flow) for region in self.regions)


def describe_regions(regions: list[Box], limit: int = 3) -> str:
    """``tcp any -> 10.0.0.0/8 dport 80; ...``: the first few regions, then a count."""
    shown = "; ".join(r.describe() for r in regions[:limit])
    more = len(regions) - limit
    return shown if more <= 0 else f"{shown}; and {more} more"


def make_entry(
    entry_class: LedgerClass,
    reason: str,
    context: str,
    old_action: Action,
    new_action: Action,
    regions: list[Box],
    *,
    informational: bool = False,
    finding_ref: str = "",
) -> LedgerEntry:
    return LedgerEntry(
        entry_class=entry_class,
        reason=reason,
        affected=describe_regions(regions),
        context=context,
        old_action=old_action,
        new_action=new_action,
        informational=informational,
        finding_ref=finding_ref,
        regions=regions,
    )


def number_entries(entries: list[LedgerEntry]) -> list[LedgerEntry]:
    """Give entries stable ids ``LED-0001...`` in list order (the list order is deterministic)."""
    return [e.model_copy(update={"id": f"LED-{i:04d}"}) for i, e in enumerate(entries, start=1)]


def covering(entries: list[LedgerEntry], context: str, flow: Flow) -> list[LedgerEntry]:
    """Every entry whose region contains the flow."""
    return [e for e in entries if e.covers(context, flow)]
