"""Ledger entries for constructs the PAN-OS candidate cannot reproduce exactly (requirement 4.3).

Each helper receives the rules of one context in evaluation order (``chain``) plus the flows that
reach each rule (``effective``: its boxes minus every earlier rule). Regions are therefore
disjoint across rules, so an entry's declared decision is never contradicted by another entry.

Flows addressed to the device itself are excluded from every region here: they are governed by
the interface management profile and covered by the ``to-the-box`` entries instead.
"""

from __future__ import annotations

from necro.boxes import Box, boxes_of, effective_regions, subtract_all
from necro.ir import Action, LedgerClass, Rule
from necro.ledger import LedgerEntry, make_entry
from necro.sets import AddrSet

_ADDR = 1  # index of the destination dimension in every box kind


def without_addresses(boxes: list[Box], excluded: AddrSet) -> list[Box]:
    """Boxes with ``excluded`` removed from the destination dimension."""
    result: list[Box] = []
    for box in boxes:
        dst = box.dims[_ADDR]
        assert isinstance(dst, AddrSet)
        left = box.restrict(_ADDR, dst.subtract(excluded))
        if left is not None:
            result.append(left)
    return result


def _outcome_of_remaining_rules(region: list[Box], later: list[Rule]) -> dict[Action, list[Box]]:
    """What the rules in ``later`` (then the implicit deny) decide for each part of ``region``."""
    decided: dict[Action, list[Box]] = {Action.permit: [], Action.deny: []}
    remaining = region
    for rule in later:
        mine = boxes_of(rule.match)
        for piece in remaining:
            decided[rule.action] += [hit for box in mine if (hit := piece.intersect(box))]
        remaining = subtract_all(remaining, mine)
        if not remaining:
            break
    decided[Action.deny] += remaining
    return decided


def established_entries(
    context: str,
    chain: list[Rule],
    effective: dict[str, list[Box]],
    device: AddrSet,
) -> list[LedgerEntry]:
    """``stateful-established``: the ACE is omitted, so later rules (or the final deny) decide.

    PAN-OS is stateful and has no flag-based match: return traffic is permitted by session state
    and unsolicited ACK/RST segments are dropped, which is a tightening (policy-semantics 3).
    The entry declares what the stateless model of the candidate does with the flows the ACE used
    to decide. Only the parts whose decision changes are recorded.
    """
    entries: list[LedgerEntry] = []
    for index, rule in enumerate(chain):
        if rule.inactive or not rule.match.established:
            continue
        region = without_addresses(effective.get(rule.id, []), device)
        later = [r for r in chain[index + 1 :] if not r.inactive and not r.match.established]
        outcome = _outcome_of_remaining_rules(region, later)
        for action, parts in outcome.items():
            if parts and action != rule.action:
                reason = (
                    f"{rule.id} matches only TCP segments with ACK or RST set. PAN-OS has no "
                    "equivalent, so the rule is omitted and the flows it decided fall to the "
                    f"rules after it ({action.value} for these)."
                )
                entries.append(
                    make_entry(
                        LedgerClass.stateful_established,
                        reason,
                        context,
                        rule.action,
                        action,
                        parts,
                    )
                )
    return entries


def time_range_entry(
    context: str, rule: Rule, effective: dict[str, list[Box]], device: AddrSet
) -> LedgerEntry | None:
    """``time-range``: the schedule is not modelled; the candidate treats the rule as always on."""
    region = without_addresses(effective.get(rule.id, []), device)
    if not region:
        return None
    reason = (
        f"{rule.id} is limited by time-range {rule.time_range}. The candidate applies it at all "
        "times (a superset); the equivalence proof cannot model time."
    )
    return make_entry(LedgerClass.time_range, reason, context, rule.action, rule.action, region)


def zone_any_entry(
    context: str,
    rule: Rule,
    effective: dict[str, list[Box]],
    unrouted: AddrSet,
    device: AddrSet,
) -> LedgerEntry | None:
    """``zone-any``: no known route covers part of the destination, so the rule says ``to any``."""
    parts: list[Box] = []
    for box in effective.get(rule.id, []):
        dst = box.dims[_ADDR]
        assert isinstance(dst, AddrSet)
        restricted = box.restrict(_ADDR, dst.intersect(unrouted))
        if restricted is not None:
            parts.append(restricted)
    parts = without_addresses(parts, device)
    if not parts:
        return None
    reason = (
        f"No static or connected route covers part of the destination of {rule.id}, so its "
        "egress zone is not known offline (a dynamic route may exist). The rule keeps "
        "'to any'. Resolve it with a route table capture."
    )
    return make_entry(LedgerClass.zone_any, reason, context, rule.action, rule.action, parts)


def ip_protocol_entry(
    context: str, rule: Rule, effective: dict[str, list[Box]], app: str, device: AddrSet
) -> LedgerEntry | None:
    """``app-id-protocol``: an IP protocol with no port is matched by a custom application."""
    region = without_addresses(effective.get(rule.id, []), device)
    if not region:
        return None
    reason = (
        f"{rule.id} matches IP protocol {rule.match.proto}, which a service object cannot "
        f"express. The candidate uses the custom application {app} (identified by protocol "
        "number), which matches exactly the same packets."
    )
    return make_entry(
        LedgerClass.app_id_protocol,
        reason,
        context,
        rule.action,
        rule.action,
        region,
        informational=True,
    )


def outbound_entries(
    context: str,
    chain: list[Rule],
    effective: dict[str, list[Box]],
    egress: dict[str, list[Rule]],
    zone_space: dict[str, AddrSet],
    device: AddrSet,
) -> list[LedgerEntry]:
    """``outbound-acl``: the candidate does not apply an outbound ACL, so it permits what it denied.

    ``egress`` maps an egress interface to its outbound ACL, ``zone_space`` to the destinations
    routed out of it. For each interface the entry covers the flows the ingress rules permit but
    that ACL denies (first match deny, or no match). Intersecting the two rule sets is possible
    but multiplies rules, so the candidate stays readable and the widening is put on record.
    """
    entries: list[LedgerEntry] = []
    for nameif, acl_rules in egress.items():
        space = zone_space.get(nameif)
        if space is None:
            continue
        egress_permits = [
            box
            for rule, boxes in effective_regions(acl_rules)
            if rule.action == Action.permit
            for box in boxes
        ]
        denied: list[Box] = []
        for rule in chain:
            if rule.inactive or rule.match.established or rule.action != Action.permit:
                continue
            routed = [
                part
                for box in without_addresses(effective.get(rule.id, []), device)
                if (part := box.restrict(_ADDR, _dst(box).intersect(space))) is not None
            ]
            denied += subtract_all(routed, egress_permits)
        if denied:
            reason = (
                f"Interface {nameif} has an outbound ACL. The candidate has no per-interface "
                "outbound policy, so flows the ingress rules permit and that ACL denied are now "
                "permitted. Tighten the rulebase or accept the widening."
            )
            entries.append(
                make_entry(
                    LedgerClass.outbound_acl, reason, context, Action.deny, Action.permit, denied
                )
            )
    return entries


def _dst(box: Box) -> AddrSet:
    dst = box.dims[_ADDR]
    assert isinstance(dst, AddrSet)
    return dst
