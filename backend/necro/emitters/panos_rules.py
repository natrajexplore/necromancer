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

from dataclasses import replace

from necro.boxes import Box, effective_regions
from necro.emitters.panos_env import ANY_ZONE, BuildEnv, RuleSpec
from necro.emitters.panos_ledger import (
    established_entries,
    ip_protocol_entry,
    outbound_entries,
    time_range_entry,
    zone_any_entry,
)
from necro.emitters.panos_objects import ip_protocol_app_name
from necro.emitters.panos_space import (
    restrict_translated,
    translated_pieces,
    unrouted_space,
    zone_pieces,
    zone_space,
)
from necro.ir import Action, Context, Dialect, Policy, Rule
from necro.ledger import LedgerEntry
from necro.sets import AddrSet, PortSet

TAG_IMPLICIT = "necro:implicit"
TAG_FINAL_DENY = "necro:final-deny"
FINAL_DENY_KEY = "necro-final-deny"
_DESCRIPTION_MAX = 1023
ICMP_PROTOCOL = 1


def _seq(rule: Rule) -> int:
    return int(rule.id.rsplit("#", 1)[1])


def _chain(policy: Policy, ctx: Context) -> list[tuple[str, Rule]]:
    """Every ACE a packet entering on ``ctx`` is matched against, in order, with its ACL name."""
    acls = [ctx.acl_name] if ctx.acl_name else []
    if policy.dialect != Dialect.ios and ctx.global_acl_name:
        acls.append(ctx.global_acl_name)
    # An ACL repeated in one chain (bound per interface and globally) can never be the first match
    # the second time, so only its first occurrence matters.
    chain: list[tuple[str, Rule]] = []
    seen: set[str] = set()
    for acl in acls:
        for rule in policy.acls.get(acl, []):
            if rule.id not in seen:
                seen.add(rule.id)
                chain.append((acl, rule))
    return chain


def _rule_specs(
    env: BuildEnv,
    ctx: Context,
    acl: str,
    rule: Rule,
    from_zone: str,
    effective: dict[str, list[Box]],
) -> list[RuleSpec]:
    """The PAN-OS rules for one ACE, plus ledger entries for whatever the rules cannot express."""
    m = rule.match
    if m.established:
        return []  # omitted; ``established_entries`` records what that changes
    if m.proto == ICMP_PROTOCOL and m.icmp_types is not None and not m.icmp_types:
        return []  # an ICMP rule with no types matches nothing
    if m.proto is not None and m.proto not in (1, 6, 17) and not rule.inactive:
        entry = ip_protocol_entry(
            ctx.name, rule, effective, ip_protocol_app_name(m.proto), env.device
        )
        if entry is not None:
            env.ledger.append(entry)
    if rule.time_range and not rule.inactive:
        entry = time_range_entry(ctx.name, rule, effective, env.device)
        if entry is not None:
            env.ledger.append(entry)
    ingress = env.ingress(ctx)
    base = f"{acl}-{_seq(rule)}"
    narrowed = (
        translated_pieces(env, ingress, m.src, m.dst)
        if rule.action == Action.permit
        else [(m.src, m.dst)]
    )
    if not narrowed:
        env.notes.append(
            f"{rule.id}: every flow it permits lacks a translation, so nat-control already "
            "denied them; no PAN-OS rule is needed"
        )
    specs: list[RuleSpec] = []
    unrouted = AddrSet()
    for part, (src, wanted) in enumerate(narrowed, start=1):
        pieces = zone_pieces(env, wanted, ingress)
        for index, (to_zone, dst) in enumerate(pieces, start=1):
            if to_zone == ANY_ZONE and wanted != AddrSet.any():
                unrouted = unrouted.union(dst)
            key = base + (f"-n{part}" if len(narrowed) > 1 else "")
            key += f"-z{index}" if len(pieces) > 1 else ""
            specs.append(
                RuleSpec(
                    key=key,
                    source=rule.id,
                    from_zone=from_zone,
                    to_zone=to_zone,
                    src=src,
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
    if not unrouted.is_empty() and not rule.inactive:
        entry = zone_any_entry(ctx.name, rule, effective, unrouted, env.device)
        if entry is not None:
            env.ledger.append(entry)
    return specs


def chain_specs(env: BuildEnv, ctx: Context, from_zone: str) -> list[RuleSpec]:
    """ACL rules of a context in order; omitted ACEs become ledger entries."""
    chain = _chain(env.policy, ctx)
    rules = [rule for _, rule in chain]
    effective = {rule.id: boxes for rule, boxes in effective_regions(rules)}
    for rule in rules:
        if rule.action == Action.permit and rule.id in effective:
            effective[rule.id] = restrict_translated(env, env.ingress(ctx), effective[rule.id])
    specs: list[RuleSpec] = []
    for acl, rule in chain:
        specs += _rule_specs(env, ctx, acl, rule, from_zone, effective)
    env.ledger += established_entries(ctx.name, rules, effective, env.device)
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
        if not allowed:
            continue
        base = _implicit(
            f"implicit-{from_zone}-to-{zone}", "implicit-security-level", from_zone, zone
        )
        # ``to any`` would also match every real zone, so it is limited to unrouted destinations
        wanted = unrouted_space(env, ctx.interface) if zone == ANY_ZONE else AddrSet.any()
        parts = translated_pieces(env, ctx.interface, AddrSet.any(), wanted)
        for part, (src, dst) in enumerate(parts, start=1):
            suffix = f"-n{part}" if len(parts) > 1 else ""
            specs.append(replace(base, key=base.key + suffix, src=src, dst=dst))
    return specs


def _outbound(env: BuildEnv, ctx: Context, specs: list[RuleSpec]) -> list[LedgerEntry]:
    """``outbound-acl`` entries for the rules emitted on ``ctx``."""
    policy = env.policy
    egress = {
        env.zones.of_nameif(nameif): policy.acls.get(acl, [])
        for nameif, acl in policy.egress_acls.items()
    }
    space = zone_space(env, env.ingress(ctx))
    return outbound_entries(ctx.name, specs, egress, space, env.device)


def context_specs(env: BuildEnv, ctx: Context) -> list[RuleSpec]:
    """Every rule for packets entering on ``ctx``, in evaluation order."""
    policy = env.policy
    from_zone = env.zones.of_context(policy, ctx)
    if policy.dialect == Dialect.ios and not ctx.acl_name:
        key = f"implicit-{from_zone}-to-any"
        specs = [_implicit(key, "implicit-permit-no-acl", from_zone, ANY_ZONE)]
    else:
        specs = chain_specs(env, ctx, from_zone)
        if policy.dialect != Dialect.ios and not ctx.acl_name and not ctx.global_acl_name:
            specs += security_level_specs(env, from_zone, ctx)
    env.ledger += _outbound(env, ctx, specs)
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
