"""Tests for zones.py (task 3.1).

All IP addresses are RFC 5737 (192.0.2.x, 198.51.100.x, 203.0.113.x) or RFC 1918 (10.x.x.x).
"""

from __future__ import annotations

import ipaddress

from necro.ir import Dialect, Interface, Policy, Route
from necro.zones import RouteTable, build_route_table


def _make_policy(
    interfaces: list[Interface],
    routes: list[Route] | None = None,
) -> Policy:
    return Policy(dialect=Dialect.asa, interfaces=interfaces, routes=routes or [])


def test_to_zone_connected_route() -> None:
    iface = Interface(
        nameif="inside",
        security_level=100,
        ip_address=ipaddress.IPv4Interface("192.0.2.1/24"),
    )
    rt = build_route_table(_make_policy([iface]))
    assert rt.to_zone(ipaddress.IPv4Address("192.0.2.50")) == "inside"


def test_to_zone_self_for_device_ip() -> None:
    iface = Interface(
        nameif="inside",
        security_level=100,
        ip_address=ipaddress.IPv4Interface("192.0.2.1/24"),
    )
    rt = build_route_table(_make_policy([iface]))
    assert rt.to_zone(ipaddress.IPv4Address("192.0.2.1")) == "self"


def test_to_zone_no_route_returns_any() -> None:
    iface = Interface(
        nameif="inside",
        security_level=100,
        ip_address=ipaddress.IPv4Interface("192.0.2.1/24"),
    )
    rt = build_route_table(_make_policy([iface]))
    assert rt.to_zone(ipaddress.IPv4Address("198.51.100.1")) == "any"


def test_to_zone_static_route() -> None:
    iface = Interface(
        nameif="outside",
        security_level=0,
        ip_address=ipaddress.IPv4Interface("203.0.113.1/24"),
    )
    route = Route(
        network=ipaddress.IPv4Network("198.51.100.0/24"),
        interface="outside",
    )
    rt = build_route_table(_make_policy([iface], routes=[route]))
    assert rt.to_zone(ipaddress.IPv4Address("198.51.100.50")) == "outside"


def test_to_zone_longest_prefix_match() -> None:
    """The /24 (dmz) beats the /8 (inside) for 10.1.1.x traffic."""
    iface_inside = Interface(
        nameif="inside",
        security_level=100,
        ip_address=ipaddress.IPv4Interface("10.0.0.1/8"),
    )
    iface_dmz = Interface(
        nameif="dmz",
        security_level=50,
        ip_address=ipaddress.IPv4Interface("10.1.1.1/24"),
    )
    rt = build_route_table(_make_policy([iface_inside, iface_dmz]))
    assert rt.to_zone(ipaddress.IPv4Address("10.1.1.50")) == "dmz"
    assert rt.to_zone(ipaddress.IPv4Address("10.2.0.1")) == "inside"


def test_interface_for_ip_hit() -> None:
    iface = Interface(
        nameif="inside",
        security_level=100,
        ip_address=ipaddress.IPv4Interface("192.0.2.1/24"),
    )
    rt = RouteTable(_make_policy([iface]))
    assert rt.interface_for_ip(ipaddress.IPv4Address("192.0.2.50")) == "inside"


def test_interface_for_ip_miss() -> None:
    iface = Interface(
        nameif="inside",
        security_level=100,
        ip_address=ipaddress.IPv4Interface("192.0.2.1/24"),
    )
    rt = RouteTable(_make_policy([iface]))
    assert rt.interface_for_ip(ipaddress.IPv4Address("198.51.100.1")) == ""


def test_multiple_interfaces_routing() -> None:
    inside = Interface(
        nameif="inside",
        security_level=100,
        ip_address=ipaddress.IPv4Interface("10.0.1.1/24"),
    )
    outside = Interface(
        nameif="outside",
        security_level=0,
        ip_address=ipaddress.IPv4Interface("192.0.2.1/30"),
    )
    rt = build_route_table(_make_policy([inside, outside]))
    assert rt.to_zone(ipaddress.IPv4Address("10.0.1.5")) == "inside"
    assert rt.to_zone(ipaddress.IPv4Address("192.0.2.2")) == "outside"
    assert rt.to_zone(ipaddress.IPv4Address("10.0.1.1")) == "self"
    assert rt.to_zone(ipaddress.IPv4Address("192.0.2.1")) == "self"
