"""Exact permit regions per context, used to prove that a tightening step is monotone (P6).

A context permits a flow when its ACL chain does: the interface ACL decides first, and a flow
that matches no active rule there falls through to the global ACL (ASA 8.3+). Contexts with no
ACL bound fall back to implicit behaviour that tightening never touches, so they are ignored.
The regions are boxes (``necro.boxes``), so the comparison of "before" and "after" is exact.
"""

from __future__ import annotations

from necro.boxes import Box, boxes_of, effective_regions, subtract_all
from necro.ir import Action, Context, Match, Policy, Rule


def _permitted(rules: list[Rule]) -> list[Box]:
    return [
        box
        for rule, region in effective_regions(rules)
        if rule.action == Action.permit
        for box in region
    ]


def _matched(rules: list[Rule]) -> list[Box]:
    return [b for rule in rules if not rule.inactive for b in boxes_of(rule.match)]


def _intersect(left: list[Box], right: list[Box]) -> list[Box]:
    return [i for a in left for b in right if (i := a.intersect(b)) is not None]


def permit_region(policy: Policy, ctx: Context) -> list[Box]:
    """Flows the ACL chain of ``ctx`` permits; empty when the context has no ACL."""
    interface = policy.acls.get(ctx.acl_name, []) if ctx.acl_name else None
    chain = policy.acls.get(ctx.global_acl_name, []) if ctx.global_acl_name else None
    if interface is None and chain is None:
        return []
    if interface is None:
        return _permitted(chain or [])
    region = _permitted(interface)
    if chain is not None:
        fall_through = subtract_all(boxes_of(Match()), _matched(interface))
        region += _intersect(fall_through, _permitted(chain))
    return region


def affected_contexts(contexts: list[Context], acl: str) -> list[Context]:
    """Contexts whose decision can depend on ``acl``."""
    return [c for c in contexts if acl in (c.acl_name, c.global_acl_name)]


def narrowed(before: list[Box], after: list[Box]) -> list[Box]:
    """Flows permitted before and not after."""
    return subtract_all(list(before), after)


def widened(before: list[Box], after: list[Box]) -> list[Box]:
    """Flows permitted after and not before (must be empty for a tightening step)."""
    return subtract_all(list(after), before)
