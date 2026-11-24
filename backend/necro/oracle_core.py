"""One flow, both policies: the equivalence check of policy-semantics 7.

For a flow ``f`` entering context ``c`` in the source config's address space::

    orig = decide(original, c, f)
    f'   = to_panos_space(original, c, f)
    res  = decide(read_panos(emitted), zone(c), f')

``orig.action == res.action`` and ``orig.to_zone == zone(res)`` unless the flow lies in an exorcism
ledger entry. Then ``res.action`` must equal the entry's declared action. The egress zone is
still compared for those flows, except where a ``zone-any`` entry says the zone is not resolved.
Flows addressed to the device itself (``to_zone == "self"``) are answered by the emitted
interface-management profile, which ``decide`` evaluates for the PAN-OS side.

The PAN-OS side is always the IR re-read from the emitted text, never the emitter's own model, so
an emitter bug cannot hide behind itself (requirement 6.1).
"""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from necro.contexts import build_contexts
from necro.emitters.panos_network import ZoneMap
from necro.evaluate import decide
from necro.ir import Action, Context, Decision, Flow, LedgerClass, Policy
from necro.ledger import LedgerEntry
from necro.nat import to_panos_space, to_source_space
from necro.parsers.panos_reader import read_panos
from necro.proof_types import Counterexample


class ProofInputError(ValueError):
    """The emitted config cannot be compared with the original (for example, a zone is missing)."""


@dataclass(frozen=True)
class Verdict:
    """Both decisions for one flow and what the comparison concluded."""

    flow: Flow  # in the source's address space: what ``decide(original)`` was asked
    original: Decision
    resurrected: Decision
    panos_flow: Flow
    entries: tuple[LedgerEntry, ...]
    expected_action: Action
    original_zone: str
    problem: str  # empty when the two policies agree


class Sides:
    """The original policy, the policy re-read from the emitted text, and the ledger."""

    def __init__(self, original: Policy, emitted_text: str, ledger: Sequence[LedgerEntry]) -> None:
        self.original = original
        self.resurrected = read_panos(emitted_text)
        self.zones = ZoneMap.build(original)
        self.ledger = list(ledger)
        self.contexts = build_contexts(original)
        self._by_name = {c.name: c for c in self.contexts}
        self._resurrected_ctx: dict[str, Context] = {}
        self._entries: dict[str, list[LedgerEntry]] = {}
        resurrected_names = {c.name: c for c in build_contexts(self.resurrected)}
        for ctx in self.contexts:
            zone = self.zones.of_context(original, ctx)
            target = resurrected_names.get(f"{zone}:in")
            if target is None:
                raise ProofInputError(f"the emitted config has no zone {zone} for {ctx.name}")
            self._resurrected_ctx[ctx.name] = target
            self._entries[ctx.name] = [e for e in self.ledger if e.context in ("any", ctx.name)]

    def context(self, name: str) -> Context:
        try:
            return self._by_name[name]
        except KeyError:
            raise ProofInputError(f"the original config has no context {name}") from None

    def zone_name(self, nameif: str) -> str:
        return self.zones.of_nameif(nameif)

    def check(
        self, ctx: Context, flow: Flow, panos_dst: ipaddress.IPv4Address | None = None
    ) -> Verdict:
        """Evaluate ``flow`` on both sides. ``panos_dst`` overrides the address mapping
        (a golden vector states the destination a PAN-OS rule must match)."""
        flow = to_source_space(self.original, ctx, flow)
        original = decide(self.original, ctx, flow)
        if panos_dst is None:
            panos_flow = to_panos_space(self.original, ctx, flow)
        else:
            panos_flow = flow.model_copy(update={"dst": panos_dst})
        resurrected = decide(self.resurrected, self._resurrected_ctx[ctx.name], panos_flow)
        entries = tuple(e for e in self._entries[ctx.name] if e.covers(ctx.name, flow))
        declared = {e.new_action for e in entries}
        expected = next(iter(declared)) if len(declared) == 1 else original.action
        original_zone = self.zone_name(original.to_zone)
        return Verdict(
            flow,
            original,
            resurrected,
            panos_flow,
            entries,
            expected,
            original_zone,
            _problem(resurrected, entries, declared, expected, original_zone),
        )

    def counterexample(
        self,
        source: Literal["golden", "search"],
        ctx: Context,
        verdict: Verdict,
        reason: str,
        vector_id: str = "",
    ) -> Counterexample:
        return Counterexample(
            source=source,
            context=ctx.name,
            flow=verdict.flow,
            panos_flow=verdict.panos_flow,
            original=verdict.original,
            resurrected=verdict.resurrected,
            original_zone=verdict.original_zone,
            expected_action=verdict.expected_action,
            ledger_ids=[e.id for e in verdict.entries],
            reason=reason,
            vector_id=vector_id,
        )


def _problem(
    resurrected: Decision,
    entries: tuple[LedgerEntry, ...],
    declared: set[Action],
    expected: Action,
    original_zone: str,
) -> str:
    """Why the two sides disagree, or an empty string when they do not."""
    if len(declared) > 1:
        ids = ", ".join(e.id for e in entries)
        return f"ledger entries {ids} declare different actions for the same flow"
    if resurrected.action != expected:
        basis = f"ledger entry {entries[0].id}" if entries else "the source decision"
        return (
            f"the resurrected policy gives {resurrected.action.value}, "
            f"{basis} requires {expected.value}"
        )
    zone_any = any(e.entry_class == LedgerClass.zone_any for e in entries)
    if not zone_any and resurrected.to_zone != original_zone:
        return (
            f"the egress zone is {resurrected.to_zone} on PAN-OS, but {original_zone} in the source"
        )
    return ""
