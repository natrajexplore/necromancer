"""Zones, placeholder interfaces and static routes for the PAN-OS candidate config.

PAN-OS derives a rule's destination zone from the firewall's routing table, so the candidate carries
the source device's connected networks and static routes. The ``ethernet1/N`` names are placeholders
in source interface order: mapping them to the real ports is a pre-cutover task for a human.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from necro.emitters.panos_names import ZONE_MAX_LEN, NameRegistry
from necro.ir import Context, Dialect, Policy
from necro.sets import AddrSet


@dataclass
class ZoneMap:
    """Source interface -> PAN-OS zone name and placeholder ethernet port."""

    by_nameif: dict[str, str] = field(default_factory=dict)
    by_hw: dict[str, str] = field(default_factory=dict)
    ethernet: dict[str, str] = field(default_factory=dict)  # zone name -> ethernet1/N
    order: list[str] = field(default_factory=list)  # zone names in source interface order

    @classmethod
    def build(cls, policy: Policy) -> ZoneMap:
        registry = NameRegistry(ZONE_MAX_LEN)
        zones = cls()
        for index, iface in enumerate(i for i in policy.interfaces if i.nameif):
            key = iface.nameif
            zone = registry.name(f"{iface.hw_name}|{key}", key)
            zones.by_nameif[key] = zone
            zones.by_hw[iface.hw_name] = zone
            zones.ethernet[zone] = f"ethernet1/{index + 1}"
            zones.order.append(zone)
        return zones

    def of_nameif(self, nameif: str) -> str:
        """The zone for an egress/ingress nameif; ``any`` stays ``any``."""
        return self.by_nameif.get(nameif, nameif)

    def of_context(self, policy: Policy, ctx: Context) -> str:
        """The zone of a context's ingress interface (IOS contexts are keyed by hardware name)."""
        if policy.dialect == Dialect.ios:
            return self.by_hw[ctx.interface]
        return self.by_nameif[ctx.interface]


def device_addresses(policy: Policy) -> AddrSet:
    """Every address the device owns (its interface addresses)."""
    owned = AddrSet()
    for iface in policy.interfaces:
        if iface.ip_address is not None:
            owned = owned.union(AddrSet.from_host(iface.ip_address.ip))
    return owned


def network_lines(policy: Policy, zones: ZoneMap) -> list[str]:
    """``set`` commands for interfaces, zones, the virtual router and static routes."""
    lines: list[str] = []
    ifaces = [i for i in policy.interfaces if i.nameif]
    for iface in ifaces:
        zone = zones.by_nameif[iface.nameif]
        port = zones.ethernet[zone]
        if iface.ip_address is not None:
            lines.append(
                f"set network interface ethernet {port} layer3 ip {iface.ip_address.with_prefixlen}"
            )
        else:
            lines.append(f"set network interface ethernet {port} layer3")
    for iface in ifaces:
        zone = zones.by_nameif[iface.nameif]
        lines.append(f"set zone {zone} network layer3 {zones.ethernet[zone]}")
    if ifaces:
        ports = " ".join(zones.ethernet[zones.by_nameif[i.nameif]] for i in ifaces)
        lines.append(f"set network virtual-router default interface [ {ports} ]")
    routes = NameRegistry()
    for route in policy.routes:
        route_zone = zones.by_nameif.get(route.interface)
        if route_zone is None:
            continue
        route_key = f"{route.network}|{route.next_hop}|{route_zone}"
        name = routes.name(route_key, f"r-{route.network}")
        hop = f" nexthop ip-address {route.next_hop}" if route.next_hop else ""
        lines.append(
            f"set network virtual-router default routing-table ip static-route {name} "
            f"destination {route.network} interface {zones.ethernet[route_zone]}{hop}"
        )
    return lines
