"""Tests for nat.py (task 3.3).

All IP addresses use RFC 5737 (192.0.2.x, 198.51.100.x) or RFC 1918 (10.x.x.x).
No real credentials or company names.
"""

from __future__ import annotations

import ipaddress

from necro.ir import Dialect, Flow, NatRule, NatType, Policy
from necro.nat import NatModel
from necro.sets import AddrSet


def _flow(src: str, dst: str, proto: int = 6, dst_port: int = 80) -> Flow:
    return Flow(
        src=ipaddress.IPv4Address(src),
        dst=ipaddress.IPv4Address(dst),
        proto=proto,
        src_port=1024,
        dst_port=dst_port,
    )


def _policy(nat_rules: list[NatRule]) -> Policy:
    return Policy(dialect=Dialect.asa, nat_rules=nat_rules)


# ---------------------------------------------------------------------------
# Static NAT: mapped-side translation
# ---------------------------------------------------------------------------


def test_static_nat_translates_mapped_dst() -> None:
    """Flow to the mapped address on the mapped interface counts as translated."""
    # Pre-8.3 static: outside mapped 192.0.2.10 -> inside real 10.0.0.10
    nat = NatRule(
        nat_type=NatType.static,
        real_interface="inside",
        mapped_interface="outside",
        real_addr=AddrSet.from_host("10.0.0.10"),
        mapped_addr=AddrSet.from_host("192.0.2.10"),
    )
    model = NatModel(_policy([nat]))
    flow = _flow("198.51.100.5", "192.0.2.10")
    assert model.translates("outside", flow)


def test_static_nat_does_not_translate_unmatched_dst() -> None:
    nat = NatRule(
        nat_type=NatType.static,
        real_interface="inside",
        mapped_interface="outside",
        real_addr=AddrSet.from_host("10.0.0.10"),
        mapped_addr=AddrSet.from_host("192.0.2.10"),
    )
    model = NatModel(_policy([nat]))
    flow = _flow("198.51.100.5", "192.0.2.11")  # different destination
    assert not model.translates("outside", flow)


# ---------------------------------------------------------------------------
# Dynamic NAT/PAT: source-side translation
# ---------------------------------------------------------------------------


def test_dynamic_nat_translates_matching_source() -> None:
    nat = NatRule(
        nat_type=NatType.dynamic,
        real_interface="inside",
        mapped_interface="outside",
        real_addr=AddrSet.from_network(ipaddress.IPv4Network("10.0.0.0/24")),
    )
    model = NatModel(_policy([nat]))
    flow = _flow("10.0.0.50", "192.0.2.1")
    assert model.translates("inside", flow)


def test_dynamic_nat_does_not_translate_out_of_range_source() -> None:
    nat = NatRule(
        nat_type=NatType.dynamic,
        real_interface="inside",
        mapped_interface="outside",
        real_addr=AddrSet.from_network(ipaddress.IPv4Network("10.0.0.0/24")),
    )
    model = NatModel(_policy([nat]))
    flow = _flow("10.1.0.50", "192.0.2.1")  # source outside the NAT range
    assert not model.translates("inside", flow)


# ---------------------------------------------------------------------------
# nat0 (exemption)
# ---------------------------------------------------------------------------


def test_nat0_exemption_counts_as_translated() -> None:
    nat = NatRule(
        nat_type=NatType.nat0,
        real_interface="inside",
        real_addr=AddrSet.from_network(ipaddress.IPv4Network("10.0.0.0/24")),
    )
    model = NatModel(_policy([nat]))
    flow = _flow("10.0.0.50", "192.0.2.1")
    assert model.translates("inside", flow)


def test_nat0_exemption_wrong_interface() -> None:
    nat = NatRule(
        nat_type=NatType.nat0,
        real_interface="inside",
        real_addr=AddrSet.from_network(ipaddress.IPv4Network("10.0.0.0/24")),
    )
    model = NatModel(_policy([nat]))
    flow = _flow("10.0.0.50", "192.0.2.1")
    assert not model.translates("outside", flow)  # ingress is "outside", not "inside"


# ---------------------------------------------------------------------------
# No NAT rules
# ---------------------------------------------------------------------------


def test_no_nat_rules_translates_false() -> None:
    model = NatModel(_policy([]))
    flow = _flow("10.0.0.5", "192.0.2.1")
    assert not model.translates("inside", flow)


# ---------------------------------------------------------------------------
# map_destination
# ---------------------------------------------------------------------------


def test_map_destination_returns_real_address() -> None:
    nat = NatRule(
        nat_type=NatType.static,
        real_interface="inside",
        mapped_interface="outside",
        real_addr=AddrSet.from_host("10.0.0.10"),
        mapped_addr=AddrSet.from_host("192.0.2.10"),
    )
    model = NatModel(_policy([nat]))
    result = model.map_destination("outside", ipaddress.IPv4Address("192.0.2.10"))
    assert result == ipaddress.IPv4Address("10.0.0.10")


def test_map_destination_no_match_returns_original() -> None:
    nat = NatRule(
        nat_type=NatType.static,
        real_interface="inside",
        mapped_interface="outside",
        real_addr=AddrSet.from_host("10.0.0.10"),
        mapped_addr=AddrSet.from_host("192.0.2.10"),
    )
    model = NatModel(_policy([nat]))
    dst = ipaddress.IPv4Address("192.0.2.11")  # not in mapped_addr
    assert model.map_destination("outside", dst) == dst
