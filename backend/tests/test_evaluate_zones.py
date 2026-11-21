"""Egress zone on every decision, pre-8.3 destination mapping and IOS outbound ACLs.

These pin down the evaluator changes made while wiring up the golden flows (task 4.6):
policy-semantics section 7 compares ``to_zone`` for every flow (denies included), section 1.5
derives the zone from the real address, and section 3 applies outbound ACLs to forwarded IOS
traffic.
"""

from __future__ import annotations

import ipaddress

from necro.contexts import find_context
from necro.evaluate import decide
from necro.ir import Action, Flow
from necro.nat import NatModel
from necro.parsers.ios_acl import parse_ios
from necro.parsers.pix_asa import parse_pix_asa

ASA = """
interface Ethernet0/0
 nameif outside
 security-level 0
 ip address 192.0.2.2 255.255.255.0
interface Ethernet0/1
 nameif inside
 security-level 100
 ip address 10.0.0.1 255.255.255.0
route inside 172.16.0.0 255.255.0.0 10.0.0.254
access-list OUT_IN extended permit tcp any host 192.0.2.50 eq 80
access-list OUT_IN extended permit tcp any host 192.0.2.60 eq 8080
access-list OUT_IN extended permit tcp any host 192.0.2.70 eq 22
access-group OUT_IN in interface outside
static (inside,outside) 192.0.2.50 172.16.1.50 netmask 255.255.255.255
static (inside,outside) tcp 192.0.2.60 8080 172.16.1.60 80 netmask 255.255.255.255
"""


def _flow(dst: str, dport: int, proto: int = 6) -> Flow:
    return Flow(
        src=ipaddress.IPv4Address("203.0.113.9"),
        dst=ipaddress.IPv4Address(dst),
        proto=proto,
        src_port=40000,
        dst_port=dport,
    )


def test_denied_flows_report_the_egress_zone() -> None:
    policy = parse_pix_asa(ASA)
    ctx = find_context(policy, "outside:in")
    d = decide(policy, ctx, _flow("172.16.1.50", 25))  # real address, no ACE matches
    assert (d.action, d.rule_id, d.to_zone) == (Action.deny, "implicit-deny", "inside")


def test_pre_8_3_zone_comes_from_the_real_address_of_a_static() -> None:
    policy = parse_pix_asa(ASA)
    ctx = find_context(policy, "outside:in")
    # 192.0.2.50 is the mapped address; connected route says outside, the static says inside.
    d = decide(policy, ctx, _flow("192.0.2.50", 80))
    assert (d.action, d.rule_id, d.to_zone) == (Action.permit, "OUT_IN#1", "inside")


def test_port_static_only_maps_its_own_protocol_and_port() -> None:
    policy = parse_pix_asa(ASA)
    ctx = find_context(policy, "outside:in")
    assert decide(policy, ctx, _flow("192.0.2.60", 8080)).to_zone == "inside"
    assert decide(policy, ctx, _flow("192.0.2.60", 9999)).to_zone == "outside"
    assert decide(policy, ctx, _flow("192.0.2.60", 8080, proto=17)).to_zone == "outside"


def test_unmapped_destination_keeps_the_route_lookup_zone() -> None:
    policy = parse_pix_asa(ASA)
    ctx = find_context(policy, "outside:in")
    assert decide(policy, ctx, _flow("192.0.2.70", 22)).to_zone == "outside"


def test_mapped_destinations_are_not_translated_for_asa_8_3_plus() -> None:
    policy = parse_pix_asa(ASA, os_version="9.8(4)")
    ctx = find_context(policy, "outside:in")
    # In real-address space the flow already carries the real destination.
    assert decide(policy, ctx, _flow("192.0.2.50", 80)).to_zone == "outside"


def test_map_destination_without_a_flow_ignores_ports() -> None:
    policy = parse_pix_asa(ASA)
    model = NatModel(policy)
    mapped = ipaddress.IPv4Address("192.0.2.60")
    assert str(model.map_destination("outside", mapped)) == "172.16.1.60"
    assert str(model.map_destination("inside", mapped)) == "192.0.2.60"  # wrong ingress interface


IOS = """
interface FastEthernet0/0
 description WAN
 ip address 192.0.2.2 255.255.255.0
 ip access-group IN_ANY in
interface FastEthernet0/1
 description LAN
 ip address 10.0.0.1 255.255.255.0
 ip access-group LAN_EGRESS out
interface FastEthernet0/2
 description MGMT
 ip address 10.9.0.1 255.255.255.0
 ip access-group MGMT_EGRESS out
ip access-list extended IN_ANY
 permit ip any any
ip access-list extended LAN_EGRESS
 permit tcp any any eq 443
ip access-list extended MGMT_EGRESS
 permit ip any any
"""


def test_ios_outbound_acl_filters_forwarded_traffic() -> None:
    policy = parse_ios(IOS)
    ctx = find_context(policy, "FastEthernet0/0:in")
    ok = decide(policy, ctx, _flow("10.0.0.5", 443))
    assert (ok.action, ok.rule_id, ok.to_zone) == (Action.permit, "IN_ANY#1", "LAN")
    blocked = decide(policy, ctx, _flow("10.0.0.5", 80))
    assert (blocked.action, blocked.rule_id) == (Action.deny, "implicit-deny")
    assert blocked.to_zone == "LAN" and blocked.reason == "egress ACL implicit deny"
    other = decide(policy, ctx, _flow("10.9.0.5", 80))
    assert (other.action, other.to_zone) == (Action.permit, "MGMT")


def test_ios_outbound_acl_applies_when_ingress_has_no_acl() -> None:
    policy = parse_ios(IOS)
    ctx = find_context(policy, "FastEthernet0/1:in")  # no inbound ACL
    to_wan = decide(policy, ctx, _flow("192.0.2.77", 80))
    assert (to_wan.action, to_wan.rule_id, to_wan.to_zone) == (
        Action.permit,
        "implicit-permit-no-acl",
        "WAN",
    )
    to_mgmt = decide(policy, ctx, _flow("10.9.0.7", 80))
    assert to_mgmt.action == Action.permit
    denied = decide(policy, find_context(policy, "FastEthernet0/2:in"), _flow("10.0.0.5", 25))
    assert (denied.action, denied.to_zone) == (Action.deny, "LAN")


def test_ios_traffic_to_the_router_is_not_filtered_by_outbound_acls() -> None:
    policy = parse_ios(IOS)
    ctx = find_context(policy, "FastEthernet0/0:in")
    d = decide(policy, ctx, _flow("10.0.0.1", 80))  # the router's own LAN address
    assert (d.action, d.to_zone) == (Action.permit, "self")
