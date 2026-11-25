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
    MgmtAccess,
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
    address_space: AddressSpace = AddressSpace.as_is,
) -> Context:
    return Context(
        name=f"{nameif}:in",
        interface=nameif,
        acl_name=acl_name,
        global_acl_name=global_acl,
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


def test_asa_to_the_box_ignores_the_acl_and_follows_the_management_commands() -> None:
    """On PIX/ASA, an ACL neither blocks nor admits traffic to the device (policy-semantics 1.3)."""
    inside = _iface("inside", 100, "10.0.0.1/24")
    deny_all = _rule("ACL_IN", 1, Action.deny)
    policy = Policy(
        dialect=Dialect.asa,
        interfaces=[inside],
        acls={"ACL_IN": [deny_all]},
        mgmt_access=[MgmtAccess(proto="telnet", src_addr=AddrSet.any(), interface="inside")],
    )
    ctx = _context("inside", acl_name="ACL_IN")
    telnet = _flow("10.0.0.5", "10.0.0.1", dst_port=23)
    assert decide(policy, ctx, telnet).action == Action.permit  # the deny-all ACL is not consulted
    d = decide(policy, ctx, _flow("10.0.0.5", "10.0.0.1"))  # tcp without a management command
    assert (d.action, d.rule_id, d.to_zone) == (Action.deny, "implicit-deny", "self")


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
        egress_acls={"outside": "OUT_ACL"},
    )
    ctx = _context("inside", acl_name="IN_ACL")
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
        egress_acls={"outside": "OUT_ACL"},
    )
    ctx = _context("inside", acl_name="IN_ACL")
    flow = _flow("10.0.0.5", "192.0.2.50")
    d = decide(policy, ctx, flow)
    assert d.action == Action.permit


# ---------------------------------------------------------------------------
# Outbound ACLs belong to the egress interface (policy-semantics 1.4)
# ---------------------------------------------------------------------------


def _three_zone_policy(egress_acls: dict[str, str], dmz_out: list[Rule]) -> Policy:
    inside = _iface("inside", 100, "10.0.0.1/24")
    dmz = _iface("dmz", 50, "198.51.100.1/24")
    outside = _iface("outside", 0, "192.0.2.1/24")
    return Policy(
        dialect=Dialect.asa,
        interfaces=[inside, dmz, outside],
        acls={
            "OUTSIDE_IN": [_rule("OUTSIDE_IN", 1, Action.permit)],
            "DMZ_OUT": dmz_out,
            "OUTSIDE_OUT": [_rule("OUTSIDE_OUT", 1, Action.deny)],
            "INSIDE_OUT": [_rule("INSIDE_OUT", 1, Action.deny)],
        },
        egress_acls=egress_acls,
    )


# outside -> dmz, the egress interface is dmz
_OUTSIDE_TO_DMZ = _flow("203.0.113.9", "198.51.100.10", proto=6, dst_port=80)


def test_egress_acl_is_looked_up_by_egress_interface_permit() -> None:
    policy = _three_zone_policy(
        {"dmz": "DMZ_OUT"},
        [_rule("DMZ_OUT", 1, Action.permit, proto=6, dst_ports=PortSet.single(80))],
    )
    d = decide(policy, _context("outside", acl_name="OUTSIDE_IN"), _OUTSIDE_TO_DMZ)
    assert d.action == Action.permit
    assert d.rule_id == "OUTSIDE_IN#1"
    assert d.to_zone == "dmz"


def test_egress_acl_explicit_deny_reports_egress_rule() -> None:
    policy = _three_zone_policy(
        {"dmz": "DMZ_OUT"},
        [_rule("DMZ_OUT", 1, Action.deny, proto=6, dst_ports=PortSet.single(80))],
    )
    d = decide(policy, _context("outside", acl_name="OUTSIDE_IN"), _OUTSIDE_TO_DMZ)
    assert d.action == Action.deny
    assert d.rule_id == "DMZ_OUT#1"
    assert d.reason == "denied by egress ACL"


def test_egress_acl_no_match_is_implicit_deny() -> None:
    policy = _three_zone_policy(
        {"dmz": "DMZ_OUT"},
        [_rule("DMZ_OUT", 1, Action.permit, proto=6, dst_ports=PortSet.single(443))],
    )
    d = decide(policy, _context("outside", acl_name="OUTSIDE_IN"), _OUTSIDE_TO_DMZ)
    assert d.action == Action.deny
    assert d.rule_id == "implicit-deny"
    assert d.reason == "egress ACL implicit deny"


def test_egress_acl_empty_or_undefined_is_implicit_deny() -> None:
    empty = _three_zone_policy({"dmz": "DMZ_OUT"}, [])
    undefined = _three_zone_policy({"dmz": "MISSING_ACL"}, [])
    for policy in (empty, undefined):
        d = decide(policy, _context("outside", acl_name="OUTSIDE_IN"), _OUTSIDE_TO_DMZ)
        assert d.action == Action.deny
        assert d.rule_id == "implicit-deny"
        assert d.reason == "egress ACL implicit deny"


def test_egress_acl_applies_with_security_level_permit_and_global_acl() -> None:
    """The egress check also runs after the implicit security-level permit and the global ACL."""
    deny_all_dmz = [_rule("DMZ_OUT", 1, Action.deny)]
    policy = _three_zone_policy({"dmz": "DMZ_OUT"}, deny_all_dmz)
    inside_to_dmz = _flow("10.0.0.5", "198.51.100.10")
    d = decide(policy, _context("inside"), inside_to_dmz)  # 100 -> 50 implicit permit
    assert d.action == Action.deny
    assert d.rule_id == "DMZ_OUT#1"

    policy.acls["GLOBAL"] = [_rule("GLOBAL", 1, Action.permit)]
    d = decide(policy, _context("inside", global_acl="GLOBAL"), inside_to_dmz)
    assert d.action == Action.deny
    assert d.rule_id == "DMZ_OUT#1"


def test_out_acl_on_other_interfaces_is_unaffected() -> None:
    """Out-ACLs on the ingress interface or an unrelated interface don't filter outside -> dmz."""
    policy = _three_zone_policy(
        {"outside": "OUTSIDE_OUT", "inside": "INSIDE_OUT"},
        [_rule("DMZ_OUT", 1, Action.deny)],
    )
    d = decide(policy, _context("outside", acl_name="OUTSIDE_IN"), _OUTSIDE_TO_DMZ)
    assert d.action == Action.permit
    assert d.rule_id == "OUTSIDE_IN#1"
    assert d.to_zone == "dmz"


def test_egress_acl_does_not_filter_ingress_denies() -> None:
    """An ingress deny stays the ingress deny; the egress ACL is never consulted."""
    policy = _three_zone_policy({"dmz": "DMZ_OUT"}, [_rule("DMZ_OUT", 1, Action.permit)])
    policy.acls["OUTSIDE_IN"] = [_rule("OUTSIDE_IN", 1, Action.deny)]
    d = decide(policy, _context("outside", acl_name="OUTSIDE_IN"), _OUTSIDE_TO_DMZ)
    assert d.action == Action.deny
    assert d.rule_id == "OUTSIDE_IN#1"


# ---------------------------------------------------------------------------
# PBT P8, broader: all dialects, NAT-control, global ACL and egress ACLs.
# decide() no longer swallows exceptions, so a raise here is a real failure.
# ---------------------------------------------------------------------------


@pytest.mark.pbt
@given(
    src=_ip_st,
    dst=_ip_st,
    proto=_proto_st,
    src_port=_port_st,
    dst_port=_port_st,
    icmp_type=_icmp_st,
    established=st.booleans(),
    dialect=st.sampled_from(list(Dialect)),
    ingress=st.sampled_from(["inside", "dmz", "outside"]),
    bind_ingress=st.booleans(),
    bind_global=st.booleans(),
    egress_names=st.lists(st.sampled_from(["inside", "dmz", "outside", "nowhere"]), max_size=4),
    nat_control=st.booleans(),
)
def test_pbt_evaluator_never_raises_broad(
    src: str,
    dst: str,
    proto: int,
    src_port: int,
    dst_port: int,
    icmp_type: int | None,
    established: bool,
    dialect: Dialect,
    ingress: str,
    bind_ingress: bool,
    bind_global: bool,
    egress_names: list[str],
    nat_control: bool,
) -> None:
    policy = _three_zone_policy(
        {name: "DMZ_OUT" for name in egress_names},
        [_rule("DMZ_OUT", 1, Action.permit, proto=6, dst_ports=PortSet.single(80))],
    )
    policy.dialect = dialect
    policy.nat_control = nat_control
    policy.acls["GLOBAL"] = [_rule("GLOBAL", 1, Action.permit, proto=6)]
    ctx = _context(
        ingress,
        acl_name="OUTSIDE_IN" if bind_ingress else "",
        global_acl="GLOBAL" if bind_global else "",
    )
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
    assert d.rule_id
