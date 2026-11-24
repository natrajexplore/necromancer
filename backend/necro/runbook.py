"""The cutover runbook: pre-checks, rollback, post-checks and hypercare (requirement 5).

It follows governance phases P6 to P9 and P11. The verification commands are built in
``runbook_commands`` (golden flows plus a deterministic sample of oracle flows, each with its
expected result). This module adds the checklists around them: what to check before the window,
the cutover steps, the rollback triggers and steps, and the post-cutover and hypercare list with
the rules and ledger entries to watch.

Rollback triggers, the decision time limit and the hypercare period have defaults that the
sidecar can override (requirement 5.4).
"""

from __future__ import annotations

from collections.abc import Sequence

from pydantic import BaseModel

from necro.emitters.panos import PanosEmission
from necro.gate_models import Sidecar
from necro.ir import Policy
from necro.ledger import LedgerEntry
from necro.proof_types import ProofResult
from necro.runbook_commands import (
    MAX_COMMANDS,
    Commands,
    ManualCheck,
    Verification,
    build_commands,
    packet_tracer_supported,
)

__all__ = [
    "DEFAULT_DECISION_MINUTES",
    "DEFAULT_HYPERCARE_DAYS",
    "DEFAULT_ROLLBACK_TRIGGERS",
    "MAX_COMMANDS",
    "Commands",
    "ManualCheck",
    "Runbook",
    "Step",
    "Verification",
    "WatchItem",
    "build_commands",
    "build_runbook",
    "packet_tracer_supported",
]

DEFAULT_DECISION_MINUTES = 30
DEFAULT_HYPERCARE_DAYS = 10
DEFAULT_ROLLBACK_TRIGGERS = (
    "A verification command gives a result that differs from its expected result.",
    "A P1 or P2 incident that is attributed to the change.",
    "An application owner asks for a rollback and the change owner agrees.",
)


class Step(BaseModel):
    """One item of a checklist."""

    id: str
    text: str


class WatchItem(BaseModel):
    subject: str
    reason: str


class Runbook(BaseModel):
    prechecks: list[Step]
    cutover: list[Step]
    commands: Commands
    rollback_triggers: list[str]
    decision_minutes: int
    rollback_steps: list[Step]
    postchecks: list[Step]
    hypercare_days: int
    watch: list[WatchItem]


# -- checklists --------------------------------------------------------------------------------


def _zone_steps(policy: Policy, emission: PanosEmission) -> list[Step]:
    steps: list[Step] = []
    for index, iface in enumerate(i for i in policy.interfaces if i.nameif):
        zone = emission.zones.by_nameif[iface.nameif]
        address = str(iface.ip_address) if iface.ip_address else "no address"
        steps.append(
            Step(
                id=f"PRE-ZONE-{index + 1:02d}",
                text=(
                    f"Zone {zone}: replace the placeholder port {emission.zones.ethernet[zone]} "
                    f"with the real port for source interface {iface.hw_name or iface.nameif} "
                    f"(nameif {iface.nameif}, {address})."
                ),
            )
        )
    return steps


def _prechecks(policy: Policy, emission: PanosEmission, sidecar: Sidecar) -> list[Step]:
    recorded = sidecar.change.cab_reference or "not recorded"
    static_routes = sum(1 for r in policy.routes if r.interface)
    return [
        Step(
            id="PRE-01",
            text="Back up the running configuration of the source and of the target. Record the "
            "file names and SHA-256 values with the change record.",
        ),
        Step(
            id="PRE-02",
            text="Load the candidate on the target in configure mode, run validate full, and do "
            "not commit. Attach the output.",
        ),
        *_zone_steps(policy, emission),
        Step(
            id="PRE-03",
            text=f"Compare the {static_routes} static routes of the candidate with show route on "
            "the source. Dynamic routing is not migrated; configure and review it separately.",
        ),
        Step(
            id="PRE-04",
            text=f"Review NAT: the candidate carries {len(policy.nat_rules)} translations from "
            "the source. Dynamic NAT, PAT and other forms are configured and reviewed separately.",
        ),
        Step(id="PRE-05", text="Confirm HA pairing and configuration sync on the target."),
        Step(
            id="PRE-06",
            text="Confirm that log forwarding to the SIEM works on the target: deny and "
            "end-of-session logs must arrive.",
        ),
        Step(
            id="PRE-07",
            text="Confirm the baseline capture is less than 7 days old at the cutover, or "
            "capture it again and re-run this report.",
        ),
        Step(
            id="PRE-08",
            text=f"Confirm the CAB approval reference is recorded on the change (now: {recorded}) "
            "and that a peer reviewer who did not do the translation has signed off.",
        ),
        Step(
            id="PRE-09", text="Walk through the rollback section with the team before the window."
        ),
    ]


def _cutover(commands: Commands) -> list[Step]:
    steps = [
        Step(id="CUT-01", text="Start the change freeze on the source: no rule changes."),
        Step(id="CUT-02", text="Apply the candidate on the target and commit."),
        Step(
            id="CUT-03",
            text=f"Run the {len(commands.target)} target verification commands and record each "
            "result next to its expected result.",
        ),
    ]
    if commands.source:
        steps.append(
            Step(
                id="CUT-04",
                text=f"Run the {len(commands.source)} source packet-tracer commands and record "
                "each result.",
            )
        )
    if commands.manual:
        steps.append(
            Step(
                id="CUT-05",
                text=f"Test the {len(commands.manual)} manual checks by another method and "
                "record the result.",
            )
        )
    steps.append(
        Step(
            id="CUT-06",
            text="Compare every result with its expected decision. A mismatch is a rollback "
            "trigger.",
        )
    )
    steps.append(Step(id="CUT-07", text="Move traffic to the target as the change plan says."))
    return steps


def _rollback_steps() -> list[Step]:
    return [
        Step(id="RB-01", text="Stop further changes on the target and note the time and trigger."),
        Step(
            id="RB-02",
            text="Re-cable or re-route traffic back to the source. Keep the source configured "
            "and powered until the end of hypercare.",
        ),
        Step(
            id="RB-03",
            text="If the target must be reverted, restore its configuration backup from PRE-01 "
            "and commit.",
        ),
        Step(id="RB-04", text="Repeat the source checks to confirm it behaves as before."),
        Step(id="RB-05", text="Record the outcome on the change record and inform the CAB."),
    ]


def _postchecks(days: int, secret_total: int) -> list[Step]:
    return [
        Step(
            id="POST-01",
            text=f"Watch deny logs on the target for {days} business days and investigate each "
            "unexpected deny.",
        ),
        Step(id="POST-02", text="Review rule hit counts for the rules in the watch list."),
        Step(
            id="POST-03",
            text="Collect sign-off from the application owner of each zone pair in the matrix.",
        ),
        Step(id="POST-04", text="Confirm that no unexplained denies remain after hypercare."),
        Step(
            id="POST-05",
            text="Decommission the source: remove it from production, archive its configuration "
            "per the retention policy, update the CMDB and IPAM, and record the decommission.",
        ),
        Step(
            id="POST-06",
            text=f"Rotate every shared secret that was on the source ({secret_total} redacted "
            "in this report). Consider them exposed.",
        ),
    ]


def _watch(
    ledger: Sequence[LedgerEntry],
    tightened_ledger: Sequence[LedgerEntry],
    proof: ProofResult | None,
) -> list[WatchItem]:
    items = [
        WatchItem(
            subject=f"ledger {e.id} ({e.entry_class.value})",
            reason=f"{e.reason}. Affected: {e.affected}",
        )
        for e in ledger
    ]
    items += [
        WatchItem(
            subject=f"tightened {e.id} ({e.entry_class.value})",
            reason=f"{e.reason}. Affected: {e.affected}. A separate change with its own proof",
        )
        for e in tightened_ledger
    ]
    if proof is None:
        items.append(WatchItem(subject="all rules", reason="no equivalence proof was run"))
        return items
    for context in proof.contexts:
        for side, cover in (("source", context.original), ("candidate", context.resurrected)):
            items += [
                WatchItem(
                    subject=f"{side} rule {rule}",
                    reason=f"not exercised by the proof in context {context.context} "
                    f"({cover.percent:g}% of active rules hit)",
                )
                for rule in cover.unhit
            ]
    return items


def build_runbook(
    policy: Policy,
    emission: PanosEmission,
    commands: Commands,
    ledger: Sequence[LedgerEntry],
    proof: ProofResult | None,
    sidecar: Sidecar,
    *,
    secret_total: int,
    tightened_ledger: Sequence[LedgerEntry] = (),
) -> Runbook:
    """The runbook for a candidate. ``commands`` come from ``build_commands`` (computed once)."""
    overrides = sidecar.runbook
    days = overrides.hypercare_business_days or DEFAULT_HYPERCARE_DAYS
    return Runbook(
        prechecks=_prechecks(policy, emission, sidecar),
        cutover=_cutover(commands),
        commands=commands,
        rollback_triggers=overrides.rollback_triggers or list(DEFAULT_ROLLBACK_TRIGGERS),
        decision_minutes=overrides.decision_time_limit_minutes or DEFAULT_DECISION_MINUTES,
        rollback_steps=_rollback_steps(),
        postchecks=_postchecks(days, secret_total),
        hypercare_days=days,
        watch=_watch(ledger, tightened_ledger, proof),
    )
