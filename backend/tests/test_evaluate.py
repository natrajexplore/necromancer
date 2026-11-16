"""Tests for evaluate.py (task 3.2) — includes PBT P8.

All IP addresses use RFC 5737 (192.0.2.x, 198.51.100.x, 203.0.113.x) or RFC 1918 (10.x.x.x).
No real credentials or company names.
"""

from __future__ import annotations

import ipaddress

import pytest
from hypothesis import given
from hypothesis import strategies as st

from necro.evaluate import decide
from necro.ir import (
    Action,
    AddressSpace,
    Context,
    Dialect,
    Flow,
    Interface,
    Match,
    Policy,
    Rule,
)
from necro.sets import AddrSet, PortSet

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _iface(nameif: str, level: int, cidr: str) -> Interface:
    return Interface(
        nameif=nameif,
        security_level=level,
        ip_address=ipaddress.IPv4Interface(cidr),
    )


def _flow(
    src: str,
    dst: str,
    proto: int = 6,
    dst_port: int = 80,
    src_port: int = 1024,
    icmp_type: int | None = None,
    established: bool = False,
) -> Flow:
    return Flow(
        src=ipaddress.IPv4Address(src),
        dst=ipaddress.IPv4Address(dst),
        proto=proto,
        dst_port=dst_port,
        src_port=src_port,
        icmp_type=icmp_type,
        established=established,
    )


def _rule(
    acl_name: str,
    seq: int,
    action: Action,
    src_net: str = "0.0.0.0/0",
    dst_net: str = "0.0.0.0/0",
    proto: int | None = None,
    dst_ports: PortSet | None = None,
    inactive: bool = False,
) -> Rule:
    src = AddrSet.from_network(ipaddress.IPv4Network(src_net))
    dst = AddrSet.from_network(ipaddress.IPv4Network(dst_net))
    match = Match(
        src=src,
        dst=dst,
        proto=proto,
        dst_ports=dst_ports or PortSet.any(),
    )
    return Rule(id=f"{acl_name}#{seq}", action=action, match=match, inactive=inactive)


def _context(
    nameif: str,
    acl_name: str = "",
    global_acl: str = "",
    egress_acl: str = "",
    address_space: AddressSpace = AddressSpace.as_is,
) -> Context:
    return Context(
        name=f"{nameif}:in",
        interface=nameif,
        acl_name=acl_name,
        global_acl_name=global_acl,
        egress_acl_name=egress_acl,
        address_space=address_space,
    )


# ---------------------------------------------------------------------------
# IOS: stateless, implicit-permit-no-acl
# ---------------------------------------------------------------------------


def test_ios_no_acl_permits() -> None:
    policy = Policy(
        dialect=Dialect.ios,
        interfaces=[_iface("eth0", 0, "192.0.2.1/24")],
    )
    ctx = _context("eth0")
    flow = _flow("198.51.100.1", "192.0.2.50")
    d = decide(policy, ctx, flow)
    assert d.action == Action.permit
    assert d.rule_id == "implicit-permit-no-acl"


def test_ios_acl_first_match_permit() -> None:
    rule = _rule("ACL100", 1, Action.permit, dst_ports=PortSet.single(80), proto=6)
    policy = Policy(
        dialect=Dialect.ios,
        interfaces=[
            _iface("eth0", 0, "192.0.2.1/24"),
            _iface("eth1", 0, "198.51.100.1/24"),
        ],
        acls={"ACL100": [rule]},
    )
    ctx = _context("eth0", acl_name="ACL100")
    flow = _flow("10.0.0.1", "198.51.100.5", proto=6, dst_port=80)
    d = decide(policy, ctx, flow)
    assert d.action == Action.permit
    assert d.rule_id == "ACL100#1"
    assert d.to_zone == "eth1"


def test_ios_acl_implicit_deny() -> None:
    rule = _rule("ACL100", 1, Action.permit, proto=6, dst_ports=PortSet.single(443))
    policy = Policy(
        dialect=Dialect.ios,
        interfaces=[_iface("eth0", 0, "192.0.2.1/24")],
        acls={"ACL100": [rule]},
    )
    ctx = _context("eth0", acl_name="ACL100")
    flow = _flow("10.0.0.1", "192.0.2.50", proto=6, dst_port=80)
    d = decide(policy, ctx, flow)
    assert d.action == Action.deny
    assert d.rule_id == "implicit-deny"


def test_ios_inactive_rule_skipped() -> None:
    inactive_rule = _rule("ACL", 1, Action.permit, proto=6, inactive=True)
    deny_rule = _rule("ACL", 2, Action.deny)
    policy = Policy(
        dialect=Dialect.ios,
        interfaces=[_iface("eth0", 0, "192.0.2.1/24")],
        acls={"ACL": [inactive_rule, deny_rule]},
    )
    ctx = _context("eth0", acl_name="ACL")
    flow = _flow("10.0.0.1", "192.0.2.5", proto=6, dst_port=80)
    d = decide(policy, ctx, flow)
    assert d.action == Action.deny
    assert d.rule_id == "ACL#2"


# ---------------------------------------------------------------------------
# ASA: security levels
# ---------------------------------------------------------------------------


def test_asa_high_to_low_permits() -> None:
    """inside (100) to outside (0): permitted by security level."""
    inside = _iface("inside", 100, "10.0.0.1/24")
    outside = _iface("outside", 0, "192.0.2.1/24")
    policy = Policy(dialect=Dialect.asa, interfaces=[inside, outside])
    ctx = _context("inside")
    flow = _flow("10.0.0.5", "192.0.2.50")
    d = decide(policy, ctx, flow)
    assert d.action == Action.permit
    assert d.rule_id == "implicit-security-level"
    assert d.to_zone == "outside"


def test_asa_low_to_high_denies() -> None:
    """outside (0) to inside (100): denied by security level."""
    inside = _iface("inside", 100, "10.0.0.1/24")
    outside = _iface("outside", 0, "192.0.2.1/24")
    policy = Policy(dialect=Dialect.asa, interfaces=[inside, outside])
    ctx = _context("outside")
    flow = _flow("192.0.2.5", "10.0.0.50")
    d = decide(policy, ctx, flow)
    assert d.action == Action.deny


def test_asa_same_level_denies_without_flag() -> None:
    dmz1 = _iface("dmz1", 50, "198.51.100.1/24")
    dmz2 = _iface("dmz2", 50, "10.1.0.1/24")
    policy = Policy(dialect=Dialect.asa, interfaces=[dmz1, dmz2])
    ctx = _context("dmz1")
    flow = _flow("198.51.100.5", "10.1.0.5")
    d = decide(policy, ctx, flow)
    assert d.action == Action.deny
    assert d.rule_id == "same-security-deny"


def test_asa_same_level_permits_with_inter_flag() -> None:
    dmz1 = _iface("dmz1", 50, "198.51.100.1/24")
    dmz2 = _iface("dmz2", 50, "10.1.0.1/24")
    policy = Policy(
        dialect=Dialect.asa,
        interfaces=[dmz1, dmz2],
        same_security_inter=True,
    )
    ctx = _context("dmz1")
    flow = _flow("198.51.100.5", "10.1.0.5")
    d = decide(policy, ctx, flow)
    assert d.action == Action.permit


def test_asa_acl_bound_overrides_level() -> None:
    """When an ACL is bound, security levels no longer grant permits."""
    inside = _iface("inside", 100, "10.0.0.1/24")
    outside = _iface("outside", 0, "192.0.2.1/24")
    deny_all = _rule("ACL_IN", 1, Action.deny)
    policy = Policy(
        dialect=Dialect.asa,
        interfaces=[inside, outside],
        acls={"ACL_IN": [deny_all]},
    )
    ctx = _context("inside", acl_name="ACL_IN")
    flow = _flow("10.0.0.5", "192.0.2.50")
    d = decide(policy, ctx, flow)
    assert d.action == Action.deny


def test_asa_to_the_box_bypasses_acl() -> None:
    """On PIX/ASA, traffic destined to the device IP bypasses security ACLs."""
    inside = _iface("inside", 100, "10.0.0.1/24")
    deny_all = _rule("ACL_IN", 1, Action.deny)
    policy = Policy(
        dialect=Dialect.asa,
        interfaces=[inside],
        acls={"ACL_IN": [deny_all]},
    )
    ctx = _context("inside", acl_name="ACL_IN")
    flow = _flow("10.0.0.5", "10.0.0.1")  # destination is device's own IP
    d = decide(policy, ctx, flow)
    assert d.action == Action.permit
    assert d.to_zone == "self"


# ---------------------------------------------------------------------------
# ASA: global ACL (8.3+ behaviour)
# ---------------------------------------------------------------------------


def test_asa_global_acl_applied_when_no_interface_acl() -> None:
    inside = _iface("inside", 100, "10.0.0.1/24")
    outside = _iface("outside", 0, "192.0.2.1/24")
    # Spec §2: interface ACL -> global ACL -> implicit deny.
    # Once a global ACL exists, security-level implicit permits are gone.
    # Only explicitly permitted flows in the global ACL are allowed.
    deny_telnet = _rule("GLOBAL_ACL", 1, Action.deny, proto=6, dst_ports=PortSet.single(23))
    permit_http = _rule("GLOBAL_ACL", 2, Action.permit, proto=6, dst_ports=PortSet.single(80))
    policy = Policy(
        dialect=Dialect.asa,
        interfaces=[inside, outside],
        acls={"GLOBAL_ACL": [deny_telnet, permit_http]},
    )
    ctx = _context("inside", global_acl="GLOBAL_ACL")
    d_telnet = decide(policy, ctx, _flow("10.0.0.5", "192.0.2.50", proto=6, dst_port=23))
    d_http = decide(policy, ctx, _flow("10.0.0.5", "192.0.2.50", proto=6, dst_port=80))
    assert d_telnet.action == Action.deny
    assert d_http.action == Action.permit


def test_asa_global_acl_eliminates_security_level_permit() -> None:
    """When a global ACL exists, security-level implicit permits are gone."""
    inside = _iface("inside", 100, "10.0.0.1/24")
    outside = _iface("outside", 0, "192.0.2.1/24")
    global_permit_80 = _rule("GLOBAL_ACL", 1, Action.permit, proto=6, dst_ports=PortSet.single(80))
    policy = Policy(
        dialect=Dialect.asa,
        interfaces=[inside, outside],
        acls={"GLOBAL_ACL": [global_permit_80]},
    )
    ctx = _context("inside", global_acl="GLOBAL_ACL")
    # Port 443: not in global ACL, so implicit deny (not security-level permit)
    d = decide(policy, ctx, _flow("10.0.0.5", "192.0.2.50", proto=6, dst_port=443))
    assert d.action == Action.deny
    assert d.rule_id == "implicit-deny"


# ---------------------------------------------------------------------------
# Egress/outbound ACL
# ---------------------------------------------------------------------------


def test_egress_acl_denies_after_ingress_permit() -> None:
    inside = _iface("inside", 100, "10.0.0.1/24")
    outside = _iface("outside", 0, "192.0.2.1/24")
    ingress_permit = _rule("IN_ACL", 1, Action.permit)
    egress_deny_smtp = _rule("OUT_ACL", 1, Action.deny, proto=6, dst_ports=PortSet.single(25))
    policy = Policy(
        dialect=Dialect.asa,
        interfaces=[inside, outside],
        acls={"IN_ACL": [ingress_permit], "OUT_ACL": [egress_deny_smtp]},
    )
    ctx = _context("inside", acl_name="IN_ACL", egress_acl="OUT_ACL")
    flow = _flow("10.0.0.5", "192.0.2.50", proto=6, dst_port=25)
    d = decide(policy, ctx, flow)
    assert d.action == Action.deny
    assert "egress" in d.reason


# ---------------------------------------------------------------------------
# PBT P8: evaluator never raises on any well-formed flow (total function)
# ---------------------------------------------------------------------------

_ip_st = st.integers(min_value=0, max_value=0xFFFFFFFF).map(lambda n: str(ipaddress.IPv4Address(n)))
_proto_st = st.sampled_from([1, 6, 17, 47, 50, 89])
_port_st = st.integers(0, 65535)
_icmp_st: st.SearchStrategy[int | None] = st.one_of(st.none(), st.integers(0, 32))


@pytest.mark.pbt
@given(
    src=_ip_st,
    dst=_ip_st,
    proto=_proto_st,
    src_port=_port_st,
    dst_port=_port_st,
    icmp_type=_icmp_st,
    established=st.booleans(),
)
def test_pbt_evaluator_never_raises(
    src: str,
    dst: str,
    proto: int,
    src_port: int,
    dst_port: int,
    icmp_type: int | None,
    established: bool,
) -> None:
    """decide() is a total function: never raises for any well-formed flow."""
    inside = _iface("inside", 100, "10.0.0.1/24")
    outside = _iface("outside", 0, "192.0.2.1/24")
    rule = _rule("ACL", 1, Action.permit)
    policy = Policy(
        dialect=Dialect.asa,
        interfaces=[inside, outside],
        acls={"ACL": [rule]},
    )
    ctx = _context("inside", acl_name="ACL")
    flow = Flow(
        src=ipaddress.IPv4Address(src),
        dst=ipaddress.IPv4Address(dst),
        proto=proto,
        src_port=src_port,
        dst_port=dst_port,
        icmp_type=icmp_type,
        established=established,
    )
    d = decide(policy, ctx, flow)
    assert d.action in (Action.permit, Action.deny)
    assert isinstance(d.rule_id, str) and len(d.rule_id) > 0


# ---------------------------------------------------------------------------
# Additional coverage tests
# ---------------------------------------------------------------------------


def test_rule_match_src_address_miss() -> None:
    """Rule with src restriction: flow from outside range is denied."""
    restricted_rule = _rule("ACL", 1, Action.permit, src_net="10.0.0.0/24", proto=6)
    policy = Policy(
        dialect=Dialect.ios,
        interfaces=[_iface("eth0", 0, "192.0.2.1/24")],
        acls={"ACL": [restricted_rule]},
    )
    ctx = _context("eth0", acl_name="ACL")
    flow = _flow("10.1.0.5", "192.0.2.50", proto=6, dst_port=80)
    d = decide(policy, ctx, flow)
    assert d.action == Action.deny


def test_rule_match_dst_address_miss() -> None:
    """Rule with dst restriction: flow to outside range is denied."""
    restricted_rule = _rule("ACL", 1, Action.permit, dst_net="192.0.2.0/24", proto=6)
    policy = Policy(
        dialect=Dialect.ios,
        interfaces=[_iface("eth0", 0, "192.0.2.1/24")],
        acls={"ACL": [restricted_rule]},
    )
    ctx = _context("eth0", acl_name="ACL")
    flow = _flow("10.0.0.5", "198.51.100.50", proto=6, dst_port=80)
    d = decide(policy, ctx, flow)
    assert d.action == Action.deny


def test_rule_match_src_port_miss() -> None:
    """Rule matches only specific source port; miss -> falls through."""
    rule = Rule(
        id="ACL#1",
        action=Action.permit,
        match=Match(
            proto=6,
            src_ports=PortSet.single(1024),
            dst_ports=PortSet.any(),
        ),
    )
    deny_all = _rule("ACL", 2, Action.deny)
    policy = Policy(
        dialect=Dialect.ios,
        interfaces=[_iface("eth0", 0, "192.0.2.1/24")],
        acls={"ACL": [rule, deny_all]},
    )
    ctx = _context("eth0", acl_name="ACL")
    flow = _flow("10.0.0.5", "192.0.2.50", proto=6, src_port=2048, dst_port=80)
    d = decide(policy, ctx, flow)
    assert d.action == Action.deny


def test_rule_match_established_flag() -> None:
    """established=True in rule requires established=True in flow."""
    est_rule = Rule(
        id="ACL#1",
        action=Action.permit,
        match=Match(proto=6, established=True),
    )
    deny_all = _rule("ACL", 2, Action.deny)
    policy = Policy(
        dialect=Dialect.ios,
        interfaces=[_iface("eth0", 0, "192.0.2.1/24")],
        acls={"ACL": [est_rule, deny_all]},
    )
    ctx = _context("eth0", acl_name="ACL")
    flow_new = _flow("10.0.0.5", "192.0.2.50", proto=6, established=False)
    assert decide(policy, ctx, flow_new).action == Action.deny
    flow_est = _flow("10.0.0.5", "192.0.2.50", proto=6, established=True)
    assert decide(policy, ctx, flow_est).action == Action.permit


def test_rule_match_icmp_type_filtering() -> None:
    """Rule restricts to specific ICMP types; other types are denied."""
    icmp_rule = Rule(
        id="ACL#1",
        action=Action.permit,
        match=Match(proto=1, icmp_types=frozenset([8])),
    )
    deny_all = _rule("ACL", 2, Action.deny)
    policy = Policy(
        dialect=Dialect.ios,
        interfaces=[_iface("eth0", 0, "192.0.2.1/24")],
        acls={"ACL": [icmp_rule, deny_all]},
    )
    ctx = _context("eth0", acl_name="ACL")
    flow_echo = _flow("10.0.0.5", "192.0.2.50", proto=1, icmp_type=8)
    assert decide(policy, ctx, flow_echo).action == Action.permit
    flow_reply = _flow("10.0.0.5", "192.0.2.50", proto=1, icmp_type=0)
    assert decide(policy, ctx, flow_reply).action == Action.deny


def test_asa_intrazone_permit_with_intra_flag() -> None:
    """Hairpin traffic is permitted with same-security-traffic intra-interface."""
    inside = _iface("inside", 100, "10.0.0.1/24")
    policy = Policy(dialect=Dialect.asa, interfaces=[inside], same_security_intra=True)
    ctx = _context("inside")
    flow = _flow("10.0.0.5", "10.0.0.6")
    d = decide(policy, ctx, flow)
    assert d.action == Action.permit
    assert d.rule_id == "implicit-security-level"


def test_pix_nat_control_no_translation_denies() -> None:
    """PIX always enforces nat-control; flow without a translation is denied."""
    inside = _iface("inside", 100, "10.0.0.1/24")
    outside = _iface("outside", 0, "192.0.2.1/24")
    permit_all = _rule("ACL", 1, Action.permit)
    policy = Policy(
        dialect=Dialect.pix,
        interfaces=[inside, outside],
        acls={"ACL": [permit_all]},
        nat_rules=[],
    )
    ctx = _context("inside", acl_name="ACL")
    flow = _flow("10.0.0.5", "192.0.2.50")
    d = decide(policy, ctx, flow)
    assert d.action == Action.deny
    assert "no-translation" in d.reason


def test_egress_acl_permits_pass_through() -> None:
    """Egress ACL permit: ingress decision stands."""
    inside = _iface("inside", 100, "10.0.0.1/24")
    outside = _iface("outside", 0, "192.0.2.1/24")
    ingress_permit = _rule("IN_ACL", 1, Action.permit)
    egress_permit = _rule("OUT_ACL", 1, Action.permit)
    policy = Policy(
        dialect=Dialect.asa,
        interfaces=[inside, outside],
        acls={"IN_ACL": [ingress_permit], "OUT_ACL": [egress_permit]},
    )
    ctx = _context("inside", acl_name="IN_ACL", egress_acl="OUT_ACL")
    flow = _flow("10.0.0.5", "192.0.2.50")
    d = decide(policy, ctx, flow)
    assert d.action == Action.permit
