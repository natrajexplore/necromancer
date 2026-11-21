"""Interface management profiles for traffic addressed to the device (requirement 4.10).

Policy-semantics 1.3: to-the-box access is never a security rule. It maps to one PAN-OS interface
management profile per receiving interface: the enabled services plus a single ``permitted-ip``
list. A profile cannot give two services different source lists, so the list is the union, and the
widening it causes is recorded as a ``to-the-box`` ledger entry.

Inputs are the source's management commands (ASA ``telnet``/``ssh``/``http``/``icmp``/
``snmp-server host``; IOS ``vty``, SNMP and HTTP lines) and, on IOS only, permit rules whose
destination is entirely the router's own addresses (``permit tcp any host <router> eq 23``).
ASA and PIX ACLs never filter traffic to the box, so they contribute nothing.
"""

from __future__ import annotations

import ipaddress

from necro.boxes import Box, boxes_of, effective_regions, subtract_all
from necro.contexts import build_contexts
from necro.emitters.panos_env import BuildEnv
from necro.emitters.panos_names import NameRegistry
from necro.emitters.panos_network import device_addresses
from necro.emitters.panos_objects import name_list
from necro.ir import Action, Context, Dialect, LedgerClass, Match, Policy
from necro.ledger import LedgerEntry, make_entry
from necro.mgmt import SERVICE_NAMES, access_services, service_box
from necro.sets import AddrSet

Access = dict[str, dict[str, AddrSet]]  # zone -> management service -> permitted sources
Addresses = dict[str, ipaddress.IPv4Address]  # zone -> the interface address that receives traffic


class MgmtPlan:
    """What each interface's management profile enables."""

    def __init__(self, access: Access, addresses: Addresses) -> None:
        self.access = access
        self.addresses = addresses

    def enabled(self, zone: str) -> list[str]:
        have = self.access.get(zone, {})
        return [s for s in SERVICE_NAMES if s in have]

    def permitted(self, zone: str) -> AddrSet:
        """The single permitted-ip list of the zone's profile: every service's sources merged."""
        merged = AddrSet()
        for sources in self.access.get(zone, {}).values():
            merged = merged.union(sources)
        return merged


def _interface_addresses(env: BuildEnv) -> Addresses:
    return {
        env.zones.by_nameif[i.nameif]: i.ip_address.ip
        for i in env.policy.interfaces
        if i.nameif and i.ip_address is not None
    }


def _add(access: Access, zone: str, service: str, sources: AddrSet) -> None:
    by_service = access.setdefault(zone, {})
    by_service[service] = by_service.get(service, AddrSet()).union(sources)


def _router_rule_access(env: BuildEnv, access: Access, addresses: Addresses) -> None:
    """IOS permit rules that address only the router itself become profile services."""
    policy = env.policy
    device = device_addresses(policy)
    for ctx in build_contexts(policy):
        rules = policy.acls.get(ctx.acl_name, []) if ctx.acl_name else []
        for rule, boxes in effective_regions(rules):
            if rule.action != Action.permit or not device.covers(rule.match.dst):
                continue
            for zone, address in addresses.items():
                host = AddrSet.from_host(address)
                for service in SERVICE_NAMES:
                    probe = service_box(service, AddrSet.any(), host)
                    for box in boxes:
                        hit = box.intersect(probe)
                        if hit is not None:
                            sources = hit.dims[0]
                            assert isinstance(sources, AddrSet)
                            _add(access, zone, service, sources)


def plan_management(env: BuildEnv) -> MgmtPlan:
    """Collect the services and sources each interface's profile needs."""
    policy = env.policy
    addresses = _interface_addresses(env)
    access: Access = {}
    for entry in policy.mgmt_access:
        services = access_services(policy.dialect, entry.proto)
        if not services:
            env.unsupported.append(
                f"line {entry.source_line}: management access '{entry.proto}' has no PAN-OS "
                "interface-management service"
            )
            continue
        zones = [env.zones.of_nameif(entry.interface)] if entry.interface else list(addresses)
        for zone in zones:
            if zone in addresses:
                for service in services:
                    _add(access, zone, service, entry.src_addr)
    if policy.dialect == Dialect.ios:
        _router_rule_access(env, access, addresses)
    return MgmtPlan(access, addresses)


def profile_lines(env: BuildEnv, plan: MgmtPlan) -> list[str]:
    """Profile definitions, then the commands that attach each one to its interface."""
    names = NameRegistry()
    definitions: list[str] = []
    attachments: list[str] = []
    for zone in env.zones.order:
        enabled = plan.enabled(zone)
        if not enabled:
            continue
        name = names.name(zone, f"necro-mgmt-{zone}")
        head = f"set network profiles interface-management-profile {name}"
        definitions += [f"{head} {service} yes" for service in enabled]
        permitted = plan.permitted(zone)
        if permitted != AddrSet.any():
            networks = name_list([str(n) for n in permitted.to_networks()])
            definitions.append(f"{head} permitted-ip {networks}")
        port = env.zones.ethernet[zone]
        attachments.append(
            f"set network interface ethernet {port} layer3 interface-management-profile {name}"
        )
    return definitions + attachments


def _old_regions(policy: Policy, ctx: Context, whole: list[Box]) -> dict[Action, list[Box]]:
    """What the source decides for flows to the device's addresses, per ingress context."""
    if policy.dialect != Dialect.ios or not ctx.acl_name:
        # decide(): ACLs never filter to-the-box traffic on PIX/ASA, and an IOS interface with
        # no ACL permits everything.
        return {Action.permit: list(whole), Action.deny: []}
    rules = policy.acls.get(ctx.acl_name, [])
    decided: dict[Action, list[Box]] = {Action.permit: [], Action.deny: []}
    effective = effective_regions(rules)
    for rule, boxes in effective:
        for box in boxes:
            decided[rule.action] += [hit for w in whole if (hit := box.intersect(w))]
    covered = [b for rule, _ in effective for b in boxes_of(rule.match)]
    decided[Action.deny] += subtract_all(list(whole), covered)
    return decided


_PREFIX = "Traffic to the device's own addresses is governed by the interface management profile. "
_REASONS = {
    (Action.permit, Action.permit): _PREFIX
    + "The source permits these flows and the profile admits them.",
    (Action.permit, Action.deny): _PREFIX
    + "The source model permits these flows but no management service of the emitted profile "
    "admits them, so PAN-OS denies them.",
    (Action.deny, Action.deny): _PREFIX
    + "The source denies these flows and the profile does not admit them.",
    (Action.deny, Action.permit): _PREFIX
    + "A profile has one permitted-ip list for all its services, so it admits flows the source "
    "denied (a service from a source that only another service allowed).",
}


def to_the_box_entries(env: BuildEnv, plan: MgmtPlan) -> list[LedgerEntry]:
    """One entry per (context, old decision, new decision) covering every flow to the device."""
    policy = env.policy
    device = device_addresses(policy)
    if device.is_empty():
        return []
    whole = boxes_of(Match(dst=device))
    admitted: list[Box] = []
    for zone, host in plan.addresses.items():
        permitted = plan.permitted(zone)
        admitted += [
            service_box(service, permitted, AddrSet.from_host(host))
            for service in plan.enabled(zone)
        ]
    entries: list[LedgerEntry] = []
    for ctx in build_contexts(policy):
        groups: dict[tuple[Action, Action], list[Box]] = {}
        for old, pieces in _old_regions(policy, ctx, whole).items():
            for piece in pieces:
                for box in admitted:
                    hit = piece.intersect(box)
                    if hit is not None:
                        groups.setdefault((old, Action.permit), []).append(hit)
                for rest in subtract_all([piece], admitted):
                    groups.setdefault((old, Action.deny), []).append(rest)
        for (old, new), regions in groups.items():
            entries.append(
                make_entry(
                    LedgerClass.to_the_box,
                    _REASONS[(old, new)],
                    ctx.name,
                    old,
                    new,
                    regions,
                    informational=old == new,
                )
            )
    return entries
