"""Task 6.2: each rule's to-zone comes from route derivation; spanning rules are split in place."""

from __future__ import annotations

import ipaddress

import pytest
from hypothesis import given
from hypothesis import strategies as st

from necro.emitters import emit_panos
from necro.ir import Dialect, Interface, Policy, Route
from necro.parsers.pix_asa import parse_pix_asa
from necro.sets import AddrSet
from necro.zones import build_route_table
from tests.panos_helpers import address_set, policy_of, rules_of, union_of

BASE = """
interface E0
 nameif outside
 security-level 0
 ip address 192.0.2.1 255.255.255.0
interface E1
 nameif inside
 security-level 100
 ip address 10.1.0.1 255.255.255.0
interface E2
 nameif dmz
 security-level 50
 ip address 10.2.0.1 255.255.255.0
"""
DEFAULT_ROUTE = "route outside 0.0.0.0 0.0.0.0 192.0.2.254 1\n"


def asa(acl_lines: str, routes: str = DEFAULT_ROUTE) -> Policy:
    text = BASE + acl_lines + "access-group A in interface outside\n" + routes
    return parse_pix_asa(text, dialect=Dialect.asa, os_version="8.2(5)")


def net(cidr: str) -> AddrSet:
    return AddrSet.from_network(ipaddress.IPv4Network(cidr))


# -- RouteTable.partition ---------------------------------------------------------------------


def _policy(*routes: tuple[str, str]) -> Policy:
    interfaces = [
        Interface(nameif="outside", ip_address=ipaddress.IPv4Interface("192.0.2.1/24")),
        Interface(nameif="inside", ip_address=ipaddress.IPv4Interface("10.1.0.1/24")),
    ]
    return Policy(
        interfaces=interfaces,
        routes=[Route(network=ipaddress.IPv4Network(n), interface=i) for n, i in routes],
    )


def test_partition_uses_longest_prefix_and_puts_unrouted_space_last() -> None:
    table = build_route_table(_policy(("10.0.0.0/8", "outside")))
    whole = net("10.0.0.0/8").union(net("172.16.0.0/16"))
    parts = dict(table.partition(whole))
    assert list(parts) == ["inside", "outside", "any"]
    assert parts["inside"] == net("10.1.0.0/24")
    assert parts["any"] == net("172.16.0.0/16")
    assert parts["outside"] == net("10.0.0.0/8").subtract(parts["inside"])


def test_partition_of_an_empty_set_is_empty() -> None:
    assert build_route_table(_policy()).partition(AddrSet()) == []


def test_device_addresses_stay_with_the_interface_that_owns_the_network() -> None:
    table = build_route_table(_policy())
    host = AddrSet.from_host("10.1.0.1")
    assert table.to_zone(ipaddress.IPv4Address("10.1.0.1")) == "self"
    assert table.partition(host) == [("inside", host)]


_NETS = st.builds(
    lambda base, bits: ipaddress.IPv4Network((base, bits), strict=False),
    st.integers(min_value=0, max_value=2**32 - 1),
    st.integers(min_value=8, max_value=30),
)


@pytest.mark.pbt
@given(
    routes=st.lists(st.tuples(_NETS, st.sampled_from(["outside", "inside", "dmz"])), max_size=5),
    dst=st.lists(_NETS, min_size=1, max_size=4),
    probes=st.lists(st.integers(min_value=0, max_value=2**32 - 1), min_size=1, max_size=20),
)
def test_partition_agrees_with_to_zone_for_every_address(
    routes: list[tuple[ipaddress.IPv4Network, str]],
    dst: list[ipaddress.IPv4Network],
    probes: list[int],
) -> None:
    policy = Policy(
        interfaces=[
            Interface(nameif="outside", ip_address=ipaddress.IPv4Interface("192.0.2.1/24")),
            Interface(nameif="dmz", ip_address=ipaddress.IPv4Interface("10.2.0.1/24")),
        ],
        routes=[Route(network=n, interface=i) for n, i in routes],
    )
    table = build_route_table(policy)
    wanted = AddrSet.from_cidr_list(dst)
    parts = table.partition(wanted)
    union = AddrSet()
    for _, part in parts:
        assert union.intersect(part).is_empty()  # the parts are disjoint
        union = union.union(part)
    assert union == wanted  # and cover exactly the requested addresses
    edges = [int(n.network_address) for n in dst] + [int(n.broadcast_address) for n in dst]
    for value in [*probes, *edges]:
        addr = ipaddress.IPv4Address(value)
        if not wanted.contains(addr):
            continue
        owner = next(zone for zone, part in parts if part.contains(addr))
        expected = table.to_zone(addr)
        assert owner == (table.interface_for_ip(addr) if expected == "self" else expected)


# -- the emitter ------------------------------------------------------------------------------


def test_a_destination_spanning_three_zones_is_split_in_place_in_interface_order() -> None:
    policy = asa(
        "access-list A extended permit tcp any 10.0.0.0 255.0.0.0 eq 80\n"
        "access-list A extended deny ip any any\n"
    )
    emission = emit_panos(policy)
    rules = rules_of(emission.lines)
    names = list(rules)
    pieces = [n for n in names if n.startswith("A-1-z")]
    assert pieces == ["A-1-z1", "A-1-z2", "A-1-z3"]
    assert [rules[n]["to"] for n in pieces] == ["outside", "inside", "dmz"]
    # adjacent, before the next rule, and all traced to the same source rule
    assert names[names.index("A-1-z1") : names.index("A-1-z3") + 1] == pieces
    assert names.index("A-1-z3") + 1 == names.index("A-2")
    assert {emission.rule_sources[n] for n in pieces} == {"A#1"}
    dsts = [address_set(emission.lines, rules[n]["destination"]) for n in pieces]
    assert union_of(dsts) == net("10.0.0.0/8")
    assert all(a.intersect(b).is_empty() for i, a in enumerate(dsts) for b in dsts[i + 1 :])
    assert dsts[1] == net("10.1.0.0/24")


def test_a_destination_inside_one_zone_stays_one_rule() -> None:
    emission = emit_panos(asa("access-list A extended permit tcp any host 10.1.0.5 eq 80\n"))
    rules = rules_of(emission.lines)
    assert [n for n in rules if n.startswith("A-1")] == ["A-1"]
    assert rules["A-1"]["to"] == "inside"


def test_any_destination_spans_every_zone_and_stays_one_rule_to_any() -> None:
    emission = emit_panos(asa("access-list A extended permit tcp any any eq 80\n"))
    rules = rules_of(emission.lines)
    assert [n for n in rules if n.startswith("A-1")] == ["A-1"]
    assert (rules["A-1"]["to"], rules["A-1"]["destination"]) == ("any", "any")


def test_space_no_route_covers_goes_to_zone_any() -> None:
    acl = "access-list A extended permit tcp any 172.16.0.0 255.255.0.0 eq 80\n"
    rules = rules_of(emit_panos(asa(acl, routes="")).lines)
    assert rules["A-1"]["to"] == "any"


def test_every_acl_rule_in_the_samples_has_a_zone_from_the_route_table() -> None:
    for config in ("pix-2006-hq.cfg", "asa-8.2-branch.cfg", "ios-12-edge.cfg"):
        policy = policy_of(config)
        zones = {i.nameif for i in policy.interfaces} | {"any"}
        for name, attrs in rules_of(emit_panos(policy).lines).items():
            assert attrs["to"] in zones, (config, name)


def test_split_rules_keep_every_other_attribute() -> None:
    acl = (
        "access-list A remark open web\n"
        "access-list A extended permit tcp any 10.0.0.0 255.0.0.0 eq 80 inactive\n"
    )
    rules = rules_of(emit_panos(asa(acl)).lines)
    for name in ("A-1-z1", "A-1-z2", "A-1-z3"):
        assert rules[name]["disabled"] == "yes"
        assert rules[name]["description"] == '"open web"'
        assert rules[name]["service"] == rules["A-1-z1"]["service"]
