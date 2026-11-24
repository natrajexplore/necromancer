"""Autopsy: ghost-rule findings (requirement 3).

Detection is exact set algebra over symbolic boxes (``necro.boxes``); every finding is then
confirmed with ``decide()``, the single source of truth for semantics:

* **shadowed**: an earlier rule covers every flow the rule matches, so it never fires. Confirmed
  when ``decide()`` never returns the rule's id for flows inside its own box.
* **redundant**: the flows that reach the rule are all matched, with the same action, by later
  rules. Confirmed when ``decide()`` gives the same action and egress zone with the rule removed.

Rules that are not active (``inactive``) take no part in evaluation and are left alone.
The other finding types live in ``necro.autopsy_checks``; ``analyze`` runs them all.
"""

from __future__ import annotations

from collections.abc import Iterable
from itertools import groupby

from necro.autopsy_checks import (
    AclView,
    acl_contexts,
    acl_findings,
    interface_findings,
    management_findings,
    object_findings,
    remark_findings,
    rule_findings,
    scoped_policy,
)
from necro.boxes import Box, covered, overlaps, subtract_all
from necro.evaluate import decide
from necro.findings import Finding, FindingType, Severity, make_finding
from necro.ir import Action, Context, Flow, Policy, Rule

__all__ = ["Finding", "FindingType", "Severity", "analyze", "without_rule"]


def without_rule(policy: Policy, acl: str, rule: Rule) -> Policy:
    kept = [r for r in policy.acls[acl] if r is not rule]
    return policy.model_copy(update={"acls": {**policy.acls, acl: kept}})


def _flows(pieces: list[Box], limit: int = 3) -> list[Flow]:
    return [f for piece in pieces[:limit] for f in piece.witnesses()]


def _ids(rules: Iterable[Rule]) -> list[str]:
    seen: list[str] = []
    for r in rules:
        if r.id not in seen:
            seen.append(r.id)
    return seen


# ---------------------------------------------------------------------------
# Shadowed and redundant (requirements 3.1, 3.2)
# ---------------------------------------------------------------------------


def hygiene_findings(policy: Policy, acl: str, rules: list[Rule]) -> list[Finding]:
    """Shadowed and redundant findings for one ACL, in rule order."""
    contexts = acl_contexts(policy, acl)
    view = AclView(rules)
    findings: list[Finding] = []
    for i, rule in enumerate(view.active):
        mine = view.boxes[i]
        earlier = view.index.overlapping(mine, before=i)
        earlier_boxes = [box for _, box in earlier]
        if covered(mine, earlier_boxes):
            related = _ids(view.active[position] for position, _ in earlier)
            # every rule the shadowed rule's flows can match: the earlier overlaps and itself
            known = [view.active[p] for p in dict.fromkeys(p for p, _ in earlier)] + [rule]
            ok, verified = _confirm_shadowed(policy, acl, contexts, rule, mine, view, known)
            if ok:
                findings.append(_shadowed(rule, related, verified))
            continue
        if not view.index.overlapping(mine, after=i):
            continue  # no later rule overlaps it, so none can take its flows over
        region = subtract_all(list(mine), earlier_boxes)
        covering = _covering_later_rules(rule, region, view, i)
        if covering:
            ok, verified = _confirm_redundant(policy, acl, contexts, rule, region, view)
            if ok:
                findings.append(_redundant(rule, covering, verified))
    return findings


def _covering_later_rules(rule: Rule, region: list[Box], view: AclView, position: int) -> list[str]:
    """Ids of later rules that take over every flow reaching ``rule``, all with its action.

    Empty when some flow would instead hit an opposite-action rule, or fall off the end of the
    ACL (implicit deny, or the global ACL, which may decide differently).
    """
    remaining = region
    covering: list[Rule] = []
    later = view.index.overlapping(region, after=position)
    for later_position, group in groupby(later, key=lambda hit: hit[0]):
        other = view.active[later_position]
        boxes = [box for _, box in group]
        if not overlaps(remaining, boxes):
            continue
        if other.action != rule.action:
            return []
        covering.append(other)
        remaining = subtract_all(remaining, boxes)
        if not remaining:
            return [i for i in _ids(covering) if i != rule.id]
    return []


def _confirm_shadowed(
    policy: Policy,
    acl: str,
    contexts: list[Context],
    rule: Rule,
    mine: list[Box],
    view: AclView,
    known: list[Rule],
) -> tuple[bool, bool]:
    """(consistent, verified): decide() must never answer with the shadowed rule's id."""
    if not contexts:
        return True, False
    scoped = scoped_policy(policy, acl, view, mine[:3], known)
    for flow in _flows(mine):
        for ctx in contexts:
            if decide(scoped, ctx, flow).rule_id == rule.id:
                return False, True
    return True, True


def _confirm_redundant(
    policy: Policy,
    acl: str,
    contexts: list[Context],
    rule: Rule,
    region: list[Box],
    view: AclView,
) -> tuple[bool, bool]:
    """(consistent, verified): removing the rule must not change action or egress zone."""
    if not contexts:
        return True, False
    scoped = scoped_policy(policy, acl, view, region[:3])
    reduced = without_rule(scoped, acl, rule)
    for flow in _flows(region):
        for ctx in contexts:
            before, after = decide(scoped, ctx, flow), decide(reduced, ctx, flow)
            if (before.action, before.to_zone) != (after.action, after.to_zone):
                return False, True
    return True, True


def _shadowed(rule: Rule, related: list[str], verified: bool) -> Finding:
    return make_finding(
        FindingType.shadowed,
        Severity.medium,
        rule.id,
        related=related,
        source_line=rule.source_line,
        verified=verified,
        by=", ".join(related) or "earlier rules",
    )


def _redundant(rule: Rule, covering: list[str], verified: bool) -> Finding:
    return make_finding(
        FindingType.redundant,
        Severity.medium,
        rule.id,
        related=covering,
        source_line=rule.source_line,
        verified=verified,
        by=", ".join(covering),
        verb="permitted" if rule.action == Action.permit else "denied",
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def analyze(policy: Policy) -> list[Finding]:
    """All findings for ``policy``, in source order, with stable ids (``AUT-0001`` ...)."""
    findings: list[Finding] = []
    for acl, rules in policy.acls.items():
        findings += hygiene_findings(policy, acl, rules)
        findings += rule_findings(policy, acl, rules)
    findings += remark_findings(policy)
    findings += object_findings(policy)
    findings += acl_findings(policy)
    findings += management_findings(policy)
    findings += interface_findings(policy)
    unique: dict[tuple[str, str], Finding] = {}
    for f in findings:
        unique.setdefault((f.type.value, f.rule_ref), f)
    ordered = sorted(unique.values(), key=lambda f: (f.source_line, f.type.value, f.rule_ref))
    return [f.model_copy(update={"id": f"AUT-{n:04d}"}) for n, f in enumerate(ordered, 1)]
