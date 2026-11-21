"""Security rules for the PAN-OS candidate config: one block per ingress context, in source order.

Each context's rules are emitted exactly as the source evaluates them: the interface ACL, then the
global ACL (ASA 8.3+), then, where the source relied on an implicit permit, explicit allow rules
tagged ``necro:implicit`` that reproduce it. A final deny from any zone to any zone closes
the rulebase.

A rule whose destination spans several egress zones is split into one rule per zone, in place, so
first-match order is preserved (the pieces are disjoint). The zone comes from the source device's
routing table (``RouteTable.partition``), the same lookup ``decide()`` uses.
"""

from __future__ import annotations

from dataclasses import dataclass

from necro.emitters.panos_network import ZoneMap
from necro.ir import Action, Context, Dialect, Policy, Rule
from necro.sets import AddrSet, PortSet
from necro.zones import RouteTable

TAG_IMPLICIT = "necro:implicit"
TAG_FINAL_DENY = "necro:final-deny"
FINAL_DENY_KEY = "necro-final-deny"
ANY_ZONE = "any"
_DESCRIPTION_MAX = 1023


@dataclass(frozen=True)
class RuleSpec:
    """One PAN-OS security rule, before names are allocated and objects are created."""

    key: str  # unique per rule: drives the PAN-OS rule name
    source: str  # source rule id (``acl#seq``) or an implicit rule id
    from_zone: str
    to_zone: str
    src: AddrSet
    dst: AddrSet
    proto: int | None
    sport: PortSet
    dport: PortSet
    icmp_types: frozenset[int] | None
    action: Action
    disabled: bool = False
    remark: str = ""
    tags: tuple[str, ...] = ()
    log_start: bool = False


@dataclass
class BuildEnv:
    """What rule building needs: the source policy, zone names, routes, and a list of gaps."""

    policy: Policy
    zones: ZoneMap
    routes: RouteTable
    unsupported: list[str]  # constructs not expressed exactly (blocks the verdict until resolved)


def _seq(rule: Rule) -> int:
    return int(rule.id.rsplit("#", 1)[1])


def zone_pieces(env: BuildEnv, dst: AddrSet) -> list[tuple[str, AddrSet]]:
    """Split a destination set by egress zone, in interface order, unrouted space last.

    A destination of ``any`` spans every zone, so it stays one piece with the zone ``any``.
    """
    if dst == AddrSet.any():
        return [(ANY_ZONE, dst)]
    order = {zone: index for index, zone in enumerate(env.zones.order)}
    pieces = [(env.zones.of_nameif(nameif), part) for nameif, part in env.routes.partition(dst)]
    return sorted(pieces, key=lambda piece: order.get(piece[0], len(order)))


def acl_rule_specs(env: BuildEnv, acl: str, from_zone: str) -> list[RuleSpec]:
    """Rules of one ACL, in order. Inactive rules stay in place and are emitted disabled."""
    specs: list[RuleSpec] = []
    for rule in env.policy.acls.get(acl, []):
        m = rule.match
        if m.proto not in (None, 6, 17):
            env.unsupported.append(f"{rule.id}: ip protocol {m.proto} needs a custom application")
            continue
        if m.established:
            env.unsupported.append(f"{rule.id}: 'established' has no PAN-OS equivalent")
            continue
        base = f"{acl}-{_seq(rule)}"
        pieces = zone_pieces(env, m.dst)
        for index, (to_zone, dst) in enumerate(pieces, start=1):
            specs.append(
                RuleSpec(
                    key=base if len(pieces) == 1 else f"{base}-z{index}",
                    source=rule.id,
                    from_zone=from_zone,
                    to_zone=to_zone,
                    src=m.src,
                    dst=dst,
                    proto=m.proto,
                    sport=m.src_ports,
                    dport=m.dst_ports,
                    icmp_types=m.icmp_types,
                    action=rule.action,
                    disabled=rule.inactive,
                    remark=rule.remark[:_DESCRIPTION_MAX],
                    tags=(f"src-acl:{acl}",),
                )
            )
    return specs


def _implicit(key: str, source: str, from_zone: str, to_zone: str) -> RuleSpec:
    return RuleSpec(
        key=key,
        source=source,
        from_zone=from_zone,
        to_zone=to_zone,
        src=AddrSet.any(),
        dst=AddrSet.any(),
        proto=None,
        sport=PortSet.any(),
        dport=PortSet.any(),
        icmp_types=None,
        action=Action.permit,
        tags=(TAG_IMPLICIT,),
    )


def security_level_specs(env: BuildEnv, from_zone: str, ctx: Context) -> list[RuleSpec]:
    """Allow rules for the implicit security-level permits of an interface with no ACL.

    ``_security_level_decision`` in ``evaluate.py`` is the source of truth: higher to lower level,
    equal level only with ``same-security-traffic permit inter-interface``, and back out of the same
    interface only with ``permit intra-interface``. Flows with no route (zone ``any``) count as
    level 0.
    """
    policy = env.policy
    levels = {i.nameif: i.security_level for i in policy.interfaces if i.nameif}
    src_level = levels.get(ctx.interface, 0)
    specs: list[RuleSpec] = []
    targets = [(nameif, env.zones.by_nameif[nameif]) for nameif in levels] + [(ANY_ZONE, ANY_ZONE)]
    for nameif, zone in targets:
        if nameif == ctx.interface:
            allowed = policy.same_security_intra
        else:
            dst_level = levels.get(nameif, 0)
            allowed = src_level > dst_level or (
                src_level == dst_level and policy.same_security_inter
            )
        if allowed:
            key = f"implicit-{from_zone}-to-{zone}"
            specs.append(_implicit(key, "implicit-security-level", from_zone, zone))
    return specs


def context_specs(env: BuildEnv, ctx: Context) -> list[RuleSpec]:
    """Every rule for packets entering on ``ctx``, in evaluation order."""
    policy = env.policy
    from_zone = env.zones.of_context(policy, ctx)
    if policy.dialect == Dialect.ios:
        if not ctx.acl_name:
            key = f"implicit-{from_zone}-to-any"
            return [_implicit(key, "implicit-permit-no-acl", from_zone, ANY_ZONE)]
        return acl_rule_specs(env, ctx.acl_name, from_zone)
    specs: list[RuleSpec] = []
    if ctx.acl_name:
        specs += acl_rule_specs(env, ctx.acl_name, from_zone)
    if ctx.global_acl_name:
        specs += acl_rule_specs(env, ctx.global_acl_name, from_zone)
    if not ctx.acl_name and not ctx.global_acl_name:
        specs += security_level_specs(env, from_zone, ctx)
    return specs


def final_deny_spec() -> RuleSpec:
    """The explicit final deny, so behaviour never depends on PAN-OS default rules."""
    return RuleSpec(
        key=FINAL_DENY_KEY,
        source="implicit-deny",
        from_zone=ANY_ZONE,
        to_zone=ANY_ZONE,
        src=AddrSet.any(),
        dst=AddrSet.any(),
        proto=None,
        sport=PortSet.any(),
        dport=PortSet.any(),
        icmp_types=None,
        action=Action.deny,
        tags=(TAG_FINAL_DENY,),
        log_start=True,
    )
