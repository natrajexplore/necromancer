"""Route table + longest-prefix match -> to_zone derivation.

Build a route table from the parsed Policy (connected interface networks +
static routes), then resolve a destination IP to the outgoing interface nameif.

Special cases:
  - An IP equal to one of the device's own interface addresses -> "self".
  - No matching route -> "any" (caller emits a zone-any ledger entry).

Dynamic routes (OSPF/EIGRP/BGP) cannot be resolved offline and are not modelled;
traffic reachable only via dynamic routes falls through to "any".
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from necro.ir import Policy
from necro.sets import AddrSet


@dataclass
class _RouteEntry:
    network: ipaddress.IPv4Network
    interface: str  # nameif
    is_connected: bool = False


class RouteTable:
    """A longest-prefix-match route table built from a parsed Policy."""

    def __init__(self, policy: Policy) -> None:
        self._entries: list[_RouteEntry] = []
        self._device_ips: set[int] = set()

        # Collect device interface IPs for "self" detection
        for iface in policy.interfaces:
            if iface.ip_address is not None:
                self._device_ips.add(int(iface.ip_address.ip))

        # Connected routes: each interface subnet is reachable via that nameif
        for iface in policy.interfaces:
            if iface.nameif and iface.ip_address is not None:
                net = iface.ip_address.network
                self._entries.append(
                    _RouteEntry(network=net, interface=iface.nameif, is_connected=True)
                )

        # Static routes
        for route in policy.routes:
            if route.interface:
                self._entries.append(
                    _RouteEntry(
                        network=route.network,
                        interface=route.interface,
                        is_connected=False,
                    )
                )

        # Longest-prefix-match: sort descending by prefix length
        self._entries.sort(key=lambda e: e.network.prefixlen, reverse=True)

    def to_zone(self, dst: ipaddress.IPv4Address) -> str:
        """Return the egress nameif for dst.

        Returns "self" when dst matches a device interface IP.
        Returns "any" when no route covers dst.
        """
        dst_int = int(dst)

        if dst_int in self._device_ips:
            return "self"

        for entry in self._entries:
            lo = int(entry.network.network_address)
            hi = int(entry.network.broadcast_address)
            if lo <= dst_int <= hi:
                return entry.interface

        return "any"

    def partition(self, addresses: AddrSet) -> list[tuple[str, AddrSet]]:
        """Split ``addresses`` by egress interface: ``to_zone`` applied to every address at once.

        Longest prefix wins, exactly as in ``to_zone``. Addresses no route covers come last, under
        ``"any"``. Device addresses stay with the interface whose network holds them (``to_zone``
        reports them as ``"self"``; a rule's destination zone is still that interface's zone).
        """
        remaining = addresses
        parts: dict[str, AddrSet] = {}
        for entry in self._entries:
            if remaining.is_empty():
                break
            hit = remaining.intersect(AddrSet.from_network(entry.network))
            if hit.is_empty():
                continue
            known = parts.get(entry.interface)
            parts[entry.interface] = hit if known is None else known.union(hit)
            remaining = remaining.subtract(hit)
        result = list(parts.items())
        if not remaining.is_empty():
            result.append(("any", remaining))
        return result

    def interface_for_ip(self, ip: ipaddress.IPv4Address) -> str:
        """Return the nameif of the connected subnet that contains ip, or ""."""
        ip_int = int(ip)
        for entry in self._entries:
            if not entry.is_connected:
                continue
            lo = int(entry.network.network_address)
            hi = int(entry.network.broadcast_address)
            if lo <= ip_int <= hi:
                return entry.interface
        return ""


def build_route_table(policy: Policy) -> RouteTable:
    """Build a RouteTable from a parsed Policy."""
    return RouteTable(policy)
