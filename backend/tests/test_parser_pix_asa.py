"""Task 4.1: PIX 6.x / ASA 7.x-8.2 parser (requirements 1.1, 1.4, 1.5, 1.7, 1.12)."""

from __future__ import annotations

import ipaddress
from pathlib import Path

import pytest

from necro.ir import Action, AddressSpace, Dialect, ParseError, Policy, PolicyMode
from necro.parsers.pix_asa import parse_pix_asa
from necro.redact import redact
from necro.sets import AddrSet, PortSet

SAMPLES = Path(__file__).resolve().parents[2] / "samples"


def _sample(folder: str, name: str, dialect: Dialect) -> Policy:
    text = redact((SAMPLES / folder / name).read_text(encoding="utf-8"))
    return parse_pix_asa(text, dialect=dialect)


def _asa(text: str) -> Policy:
    return parse_pix_asa(text.strip("\n") + "\n", dialect=Dialect.asa)


def _reasons(policy: Policy) -> list[str]:
    return [u.reason for u in policy.unparsed]


# ---------------------------------------------------------------------------
# Sample: pix-2006-hq.cfg
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def pix() -> Policy:
    return _sample("dead-configs", "pix-2006-hq.cfg", Dialect.pix)


def test_pix_header_and_interfaces(pix: Policy) -> None:
    assert pix.dialect == Dialect.pix
    assert pix.os_version == "6.3(5)"
    assert pix.address_space == AddressSpace.mapped
    got = {i.nameif: (i.security_level, str(i.ip_address)) for i in pix.interfaces}
    assert got == {
        "outside": (0, "198.51.100.1/28"),
        "inside": (100, "10.10.0.1/16"),
        "dmz": (50, "192.168.50.1/24"),
    }


def test_pix_nothing_unparsed(pix: Policy) -> None:
    assert pix.unparsed == []
    assert all(r.classification != "unparsed" for r in pix.line_records)


def test_pix_acl_ordinals_and_groups(pix: Policy) -> None:
    assert [r.id for r in pix.acls["outside_in"]] == [f"outside_in#{i}" for i in range(1, 8)]
    first = pix.acls["outside_in"][0]
    expected = AddrSet.from_host("192.168.50.10").union(AddrSet.from_host("192.168.50.11"))
    assert first.match.dst == expected
    assert first.match.dst_ports == PortSet([(80, 80), (443, 443)])
    assert first.match.proto == 6
    telnet = pix.acls["outside_in"][4]
    assert telnet.match.src == AddrSet.from_network(ipaddress.IPv4Network("203.0.113.0/24"))
    assert telnet.match.dst_ports == PortSet.single(23)
    echo_reply = pix.acls["outside_in"][5]
    assert echo_reply.match.proto == 1
    assert echo_reply.match.icmp_types == frozenset({0})
    last = pix.acls["outside_in"][6]
    assert last.action == Action.deny and last.match.proto is None


def test_pix_names_nat_routes_and_mgmt(pix: Policy) -> None:
    assert pix.name_aliases["web-srv"] == "192.168.50.10"
    kinds = [(n.nat_type.value, n.real_interface, n.mapped_interface) for n in pix.nat_rules]
    assert ("static", "dmz", "outside") in kinds
    assert ("dynamic", "inside", "") in kinds
    assert ("pat", "", "outside") in kinds
    assert [(str(r.network), r.interface, str(r.next_hop)) for r in pix.routes] == [
        ("0.0.0.0/0", "outside", "198.51.100.14")
    ]
    assert [(m.proto, m.interface) for m in pix.mgmt_access] == [("telnet", "inside")]
    assert [(b.acl_name, b.interface, b.direction) for b in pix.bindings] == [
        ("outside_in", "outside", "in"),
        ("dmz_in", "dmz", "in"),
    ]
    assert pix.egress_acls == {}


# ---------------------------------------------------------------------------
# Sample: asa-8.2-branch.cfg
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def asa82() -> Policy:
    return _sample("dead-configs", "asa-8.2-branch.cfg", Dialect.asa)


def test_asa82_interfaces_and_space(asa82: Policy) -> None:
    assert asa82.os_version == "8.2(5)"
    assert asa82.address_space == AddressSpace.mapped
    assert [(i.hw_name, i.nameif, i.security_level) for i in asa82.interfaces] == [
        ("Ethernet0/0", "outside", 0),
        ("Ethernet0/1", "inside", 100),
    ]
    assert asa82.nat_control is False


def test_asa82_only_vpn_line_is_out_of_scope_and_not_security_relevant(asa82: Policy) -> None:
    assert [(u.line_no, u.reason, u.security_relevant) for u in asa82.unparsed] == [
        (59, "vpn-not-migrated", False)
    ]
    record = asa82.line_records[58]
    assert record.classification == "out-of-scope"
    assert "<redacted>" in record.text  # the key was redacted before parsing


def test_asa82_rules(asa82: Policy) -> None:
    rules = asa82.acls["OUTSIDE_IN"]
    assert [r.id for r in rules] == [f"OUTSIDE_IN#{i}" for i in range(1, 10)]
    assert rules[0].remark == "Partner app tier"
    assert rules[1].remark == ""
    # object-group service APP_PORTS tcp: range 8080-8090 and eq 8443
    assert rules[0].match.dst_ports == PortSet([(8080, 8090), (8443, 8443)])
    # nested ALL_SERVERS = APP_SERVERS (172.16.20.0/24) + db-primary (172.16.30.5)
    assert rules[3].match.dst.contains(ipaddress.IPv4Address("172.16.30.5"))
    assert rules[3].match.dst.contains(ipaddress.IPv4Address("172.16.20.99"))
    # tcp-udp group used in a udp ACE yields the udp ports
    assert rules[4].match.proto == 17
    assert rules[4].match.dst_ports == PortSet([(69, 69), (161, 161)])
    # neq 22
    assert rules[5].match.dst_ports == PortSet.from_neq(22)
    assert rules[7].inactive is True
    assert rules[8].log is True and rules[8].action == Action.deny
    assert not any(r.inactive for r in rules[:7])


def test_asa82_static_nat_and_routes(asa82: Policy) -> None:
    (nat,) = asa82.nat_rules
    assert nat.mapped_interface == "outside" and nat.real_interface == "inside"
    assert nat.mapped_addr == AddrSet.from_host("198.51.100.5")
    assert nat.real_addr == AddrSet.from_host("172.16.30.5")
    assert [(str(r.network), r.interface) for r in asa82.routes] == [
        ("0.0.0.0/0", "outside"),
        ("172.16.0.0/16", "inside"),
    ]


def test_every_line_is_classified_once(pix: Policy, asa82: Policy) -> None:
    for policy, name in ((pix, "pix-2006-hq.cfg"), (asa82, "asa-8.2-branch.cfg")):
        count = len((SAMPLES / "dead-configs" / name).read_text(encoding="utf-8").splitlines())
        assert [r.line_no for r in policy.line_records] == list(range(1, count + 1))


# ---------------------------------------------------------------------------
# Negative fixtures
# ---------------------------------------------------------------------------


def test_group_cycle_names_the_path() -> None:
    text = redact((SAMPLES / "broken-configs" / "asa-group-cycle.cfg").read_text(encoding="utf-8"))
    with pytest.raises(ParseError) as err:
        parse_pix_asa(text)
    assert err.value.code == "group-cycle"
    assert "A_GROUP -> B_GROUP -> A_GROUP" in str(err.value)


def test_undefined_group_is_a_parse_error_with_line() -> None:
    path = SAMPLES / "broken-configs" / "asa-undefined-group.cfg"
    with pytest.raises(ParseError) as err:
        parse_pix_asa(redact(path.read_text(encoding="utf-8")))
    assert err.value.code == "undefined-group"
    assert err.value.message == "undefined object-group WEB_MISSING"
    assert err.value.line_no == 6


def test_transparent_mode_is_detected_and_blocks() -> None:
    path = SAMPLES / "broken-configs" / "asa-out-of-scope-mode.cfg"
    policy = parse_pix_asa(redact(path.read_text(encoding="utf-8")))
    assert policy.mode == PolicyMode.transparent
    assert ("transparent-firewall-mode", True) in [
        (u.reason, u.security_relevant) for u in policy.unparsed
    ]
    # access-group on an interface that doesn't exist is flagged, never dropped silently
    assert "access-group-unknown-interface" in _reasons(policy)


# ---------------------------------------------------------------------------
# Statement-level behaviour
# ---------------------------------------------------------------------------

BASE = """
interface Ethernet0/0
 nameif outside
 security-level 0
 ip address 192.0.2.2 255.255.255.0
interface Ethernet0/1
 nameif inside
 security-level 100
 ip address 10.0.0.1 255.255.255.0
"""


def test_unknown_port_name_is_security_relevant_unparsed() -> None:
    p = _asa(BASE + "access-list A extended permit tcp any any eq frobnicate\n")
    assert p.acls["A"] == []
    assert [(u.reason, u.security_relevant) for u in p.unparsed] == [("unknown-port-name", True)]


def test_protocol_keyed_port_names() -> None:
    p = _asa(
        BASE
        + "access-list A extended permit tcp any any eq cmd\n"
        + "access-list A extended permit udp any any eq syslog\n"
        + "access-list A extended permit udp any any eq radius\n"
    )
    ports = [r.match.dst_ports for r in p.acls["A"]]
    assert ports == [PortSet.single(514), PortSet.single(514), PortSet.single(1645)]
    q = _asa(BASE + "access-list A extended permit tcp any any eq syslog\n")
    assert _reasons(q) == ["unknown-port-name"]


def test_unsupported_ace_keeps_the_ordinal() -> None:
    p = _asa(
        BASE
        + "access-list A extended permit tcp any any eq 80\n"
        + "access-list A extended permit ip any6 any6\n"
        + "access-list A extended deny ip any any\n"
    )
    assert [r.id for r in p.acls["A"]] == ["A#1", "A#3"]
    assert _reasons(p) == ["ipv6"]


def test_port_operators_and_source_ports() -> None:
    p = _asa(
        BASE
        + "access-list A extended permit tcp any lt 1024 any gt 1023\n"
        + "access-list A extended permit udp any range 1000 2000 any neq 53\n"
    )
    r1, r2 = p.acls["A"]
    assert r1.match.src_ports == PortSet.from_lt(1024)
    assert r1.match.dst_ports == PortSet.from_gt(1023)
    assert r2.match.src_ports == PortSet.from_range(1000, 2000)
    assert r2.match.dst_ports == PortSet.from_neq(53)


def test_log_attributes_and_time_range() -> None:
    p = _asa(
        BASE
        + "access-list A extended permit ip any any log informational interval 600\n"
        + "access-list A extended permit ip any any log disable\n"
        + "access-list A extended permit ip any any log 4 time-range WORKDAYS\n"
    )
    r1, r2, r3 = p.acls["A"]
    assert (r1.log, r1.log_level) == (True, "informational")
    assert r2.log is False
    assert (r3.log, r3.log_level, r3.time_range) == (True, "4", "WORKDAYS")


def test_remark_attaches_to_next_ace_only_and_is_not_counted() -> None:
    p = _asa(
        BASE
        + "access-list A remark first\n"
        + "access-list A remark second\n"
        + "access-list A extended permit ip any any\n"
        + "access-list A extended deny ip any any\n"
    )
    r1, r2 = p.acls["A"]
    assert (r1.id, r1.remark) == ("A#1", "first second")
    assert (r2.id, r2.remark) == ("A#2", "")


def test_protocol_group_and_service_group_expand_with_one_ordinal() -> None:
    p = _asa(
        BASE
        + "object-group protocol PROTOS\n"
        + " protocol-object tcp\n"
        + " protocol-object 47\n"
        + "object-group service SVCS\n"
        + " service-object tcp destination eq www\n"
        + " service-object icmp echo\n"
        + "access-list A extended permit object-group PROTOS any any\n"
        + "access-list A extended permit object-group SVCS any any\n"
    )
    rules = p.acls["A"]
    assert [r.id for r in rules] == ["A#1", "A#1", "A#2", "A#2"]
    assert [r.match.proto for r in rules] == [6, 47, 6, 1]
    assert rules[2].match.dst_ports == PortSet.single(80)
    assert rules[3].match.icmp_types == frozenset({8})


def test_icmp_type_group_and_code_keyword() -> None:
    p = _asa(
        BASE
        + "object-group icmp-type PINGS\n"
        + " icmp-object echo\n"
        + " icmp-object 0\n"
        + "access-list A extended permit icmp any any object-group PINGS\n"
        + "access-list A extended permit icmp any any port-unreachable\n"
        + "access-list A extended permit icmp any any echo-reply\n"
    )
    assert [r.match.icmp_types for r in p.acls["A"]] == [frozenset({0, 8}), frozenset({0})]
    assert _reasons(p) == ["icmp-code-keyword"]


def test_service_group_protocol_mismatch_is_unparsed() -> None:
    p = _asa(
        BASE
        + "object-group service UDP_ONLY udp\n"
        + " port-object eq 53\n"
        + "access-list A extended permit tcp any any object-group UDP_ONLY\n"
    )
    assert _reasons(p) == ["service-group-protocol-mismatch"]


def test_8_3_constructs_are_never_skipped() -> None:
    p = _asa(
        BASE
        + "object network WEB\n"
        + " host 192.0.2.10\n"
        + " nat (inside,outside) static 198.51.100.10\n"
        + "access-list A extended permit tcp any object WEB eq 80\n"
        + "access-list A extended permit ip any interface inside\n"
        + "access-list A extended permit ip user DOMAIN\\bob any\n"
    )
    assert _reasons(p) == [
        "asa-8.3-object",
        "asa-8.3-object",
        "asa-8.3-object",
        "asa-8.3-object-operand",
        "asa-8.3-interface-operand",
        "identity-firewall",
    ]
    assert all(u.security_relevant for u in p.unparsed)


def test_out_of_scope_legacy_and_modes() -> None:
    p = _asa(
        BASE
        + "conduit permit tcp host 192.0.2.5 eq 80 any\n"
        + "outbound 10 permit 10.0.0.0 255.255.255.0 80 tcp\n"
        + "mode multiple\n"
        + "access-list E ethertype permit bpdu\n"
        + "access-list W webtype permit url any\n"
        + "ipv6 access-list V permit ip any any\n"
    )
    assert p.mode == PolicyMode.multiple
    assert _reasons(p) == [
        "pix-legacy-conduit",
        "pix-legacy-outbound",
        "multiple-context-mode",
        "ethertype-acl",
        "webtype-acl",
        "ipv6",
    ]


def test_bindings_in_out_global_and_control_plane() -> None:
    p = _asa(
        BASE
        + "access-list IN extended permit ip any any\n"
        + "access-list OUT extended permit ip any any\n"
        + "access-list GL extended deny ip any any\n"
        + "access-list CP extended permit tcp any any eq 22\n"
        + "access-group IN in interface outside\n"
        + "access-group OUT out interface inside\n"
        + "access-group GL global\n"
        + "access-group CP in interface outside control-plane\n"
        + "access-group IN in interface outside\n"
        + "access-group NOPE in interface inside\n"
        + "access-group IN in interface nowhere\n"
    )
    assert [(b.acl_name, b.interface, b.direction, b.global_acl) for b in p.bindings] == [
        ("IN", "outside", "in", False),
        ("OUT", "inside", "out", False),
        ("GL", "", "in", True),
    ]
    assert p.egress_acls == {"inside": "OUT"}
    assert _reasons(p) == [
        "duplicate-access-group",
        "access-group-undefined-acl",
        "access-group-unknown-interface",
    ]
    cp = [r for r in p.line_records if r.text.endswith("control-plane")]
    assert cp[0].classification == "management-plane"


def test_same_security_nat_control_and_no_forms() -> None:
    p = _asa(
        BASE
        + "same-security-traffic permit inter-interface\n"
        + "same-security-traffic permit intra-interface\n"
        + "nat-control\n"
    )
    assert (p.same_security_inter, p.same_security_intra, p.nat_control) == (True, True, True)
    q = _asa(
        BASE
        + "nat-control\nno nat-control\n"
        + "same-security-traffic permit inter-interface\n"
        + "no same-security-traffic permit inter-interface\n"
        + "no asdm history enable\n"
        + "no conduit\n"
        + "same-security-traffic permit bogus\n"
    )
    assert (q.nat_control, q.same_security_inter) == (False, False)
    assert _reasons(q) == ["pix-legacy-conduit", "bad-same-security-traffic"]


def test_nat_forms() -> None:
    p = _asa(
        BASE
        + "nat (inside) 1 10.0.0.0 255.255.255.0 0 0\n"
        + "nat (inside) 0 10.0.1.0 255.255.255.0\n"
        + "global (outside) 1 192.0.2.10-192.0.2.20 netmask 255.255.255.0\n"
        + "global (outside) 2 192.0.2.30\n"
        + "static (inside,outside) tcp 192.0.2.40 www 10.0.0.40 8080 netmask 255.255.255.255\n"
        + "static (inside,outside) 192.0.2.64 10.0.0.64 netmask 255.255.255.192\n"
        + "nat (inside) 3 access-list POLICY\n"
        + "nat (inside,outside) source dynamic any interface\n"
        + "static (inside,outside) 192.0.2.50 access-list POLICY\n"
        + "static (inside,outside) interface 10.0.0.50\n"
        + "nat (inside) 4 10.0.2.0 255.255.255.0 outside\n"
        + "global (outside) 5 192.0.2.99-192.0.2.1\n"
    )
    types = [(n.nat_type.value, n.nat_id, n.is_pat) for n in p.nat_rules]
    assert types == [
        ("dynamic", 1, False),
        ("nat0", 0, False),
        ("dynamic", 1, False),
        ("pat", 2, True),
        ("static", None, False),
        ("static", None, False),
    ]
    port_static = p.nat_rules[4]
    assert (port_static.proto, port_static.mapped_ports, port_static.real_ports) == (
        6,
        PortSet.single(80),
        PortSet.single(8080),
    )
    assert _reasons(p) == [
        "policy-nat-access-list",
        "twice-nat-unsupported",
        "policy-nat-access-list",
        "static-interface-mapping",
        "outside-nat",
        "inverted-global-range",
    ]


def test_management_commands() -> None:
    p = _asa(
        BASE
        + "telnet 10.0.0.0 255.255.255.0 inside\n"
        + "ssh 0 0 outside\n"
        + "http 10.0.0.9 255.255.255.255 inside\n"
        + "telnet timeout 5\nssh version 2\nhttp server enable\n"
        + "icmp permit any outside\n"
        + "icmp permit host 192.0.2.7 outside\n"
        + "icmp permit 10.0.0.0 255.255.255.0 inside\n"
        + "icmp deny any outside\n"
        + "icmp permit any echo outside\n"
        + "icmp unreachable rate-limit 1 burst-size 1\n"
        + "snmp-server host inside 10.0.0.77 poll version 2c\n"
        + "snmp-server location lab\n"
    )
    assert [(m.proto, m.interface) for m in p.mgmt_access] == [
        ("telnet", "inside"),
        ("ssh", "outside"),
        ("http", "inside"),
        ("icmp", "outside"),
        ("icmp", "outside"),
        ("icmp", "inside"),
        ("snmp", "inside"),
    ]
    assert p.mgmt_access[1].src_addr == AddrSet.any()
    assert p.mgmt_access[-1].version == "2c"
    assert _reasons(p) == ["icmp-deny-to-the-box", "icmp-type-to-the-box"]


def test_inspection_vpn_and_block_children_are_accounted() -> None:
    p = _asa(
        BASE
        + "policy-map global_policy\n"
        + " class inspection_default\n"
        + "  inspect ftp\n"
        + "crypto map M 10 match address VPN\n"
        + "tunnel-group X type ipsec-l2l\n"
        + " ipsec-attributes\n"
        + "frobnicate something\n"
        + " child of an unknown command\n"
        + " orphan\n"
        + "!\n"
        + " orphan after bang\n"
        + "hostname fw\n"
        + " child of a not-policy command\n"
        + "route outside 0.0.0.0 0.0.0.0 192.0.2.1 5\n"
        + "route nowhere 10.9.0.0 255.255.0.0 192.0.2.1\n"
        + "route outside 10.8.0.0 255.255.0.0 192.0.2.1 tunneled\n"
        + "route outside 10.7.0.0 255.255.0.0 192.0.2.1 track 1\n"
    )
    by_line = {r.line_no: r for r in p.line_records}
    n0 = len(BASE.strip("\n").splitlines())
    assert by_line[n0 + 1].classification == "out-of-scope"
    assert by_line[n0 + 3].classification == "out-of-scope"
    assert by_line[n0 + 3].reason == "inspection-engine-not-modelled"
    assert by_line[n0 + 7].reason == "unrecognized-command"
    assert by_line[n0 + 8].classification == "unparsed" and by_line[n0 + 8].security_relevant
    assert by_line[n0 + 9].reason == "unrecognized-command"
    assert by_line[n0 + 11].reason == "orphan-indented-line"
    assert by_line[n0 + 13].classification == "not-policy"
    assert [r.metric for r in p.routes] == [5]
    assert _reasons(p).count("route-unknown-interface") == 1
    assert "tunneled-route" in _reasons(p) and "route-option-unsupported" in _reasons(p)


def test_interface_edge_cases() -> None:
    p = _asa(
        """
interface Ethernet0/0
 nameif outside
 ip address 192.0.2.2 255.255.255.0 standby 192.0.2.3
 description uplink
 no shutdown
 speed 100
 ip address dhcp setroute
 frobnicate
interface Ethernet0/1
 nameif dmz
 security-level 500
 ip address 10.0.0.1 255.255.0.255
interface Ethernet0/2
 shutdown
interface ethernet3 auto
interface weird a b c
ip address ghost 10.1.1.1 255.255.255.0
ip address
ip bogus
name 10.9.9.9 dup
name 10.9.9.8 dup
name not-an-ip x
"""
    )
    (out,) = [i for i in p.interfaces if i.nameif == "outside"]
    assert out.description == "uplink" and str(out.ip_address) == "192.0.2.2/24"
    reasons = _reasons(p)
    assert reasons.count("dynamic-interface-address") == 1
    assert "unknown-interface-command" in reasons
    assert "security-level-out-of-range" in reasons
    assert "non-contiguous-mask" in reasons
    assert "missing-security-level" in reasons  # outside has no security-level, dmz was rejected
    assert "ip-address-unknown-interface" in reasons
    assert "unrecognized-interface-command" in reasons
    assert "bad-ip-address" in reasons
    assert "unrecognized-command" in reasons
    assert "bad-name-alias" in reasons


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ("access-list X\n", "malformed-access-list"),
        ("access-list X line 1 extended permit ip any any\n", "acl-line-insertion"),
        ("access-list X extended permit\n", "missing-protocol"),
        ("access-list X extended allow ip any any\n", "unknown-acl-action"),
        ("access-list X extended permit bogus any any\n", "unknown-protocol-name"),
        ("access-list X extended permit 300 any any\n", "protocol-out-of-range"),
        ("access-list X extended permit ip 192.0.2.1 any\n", "missing-mask"),
        ("access-list X extended permit ip 192.0.2.1 255.0.255.0 any\n", "non-contiguous-mask"),
        ("access-list X extended permit ip host nonesuch any\n", "undefined-name"),
        ("access-list X extended permit ip any eq 80 any\n", "port-operator-on-non-tcp-udp"),
        ("access-list X extended permit tcp any any eq 99999\n", "port-out-of-range"),
        ("access-list X extended permit tcp any any range 9 1\n", "inverted-port-range"),
        ("access-list X extended permit tcp any any range 9\n", "truncated-port-range"),
        ("access-list X extended permit tcp any any eq\n", "truncated-port-operator"),
        ("access-list X extended permit tcp any any eq 80 bogus\n", "unexpected-token"),
        ("access-list X extended permit icmp any any 3 1\n", "icmp-code-keyword"),
        ("access-list X extended permit icmp any any nonsense\n", "unknown-icmp-name"),
        ("access-list X extended permit icmp any any 300\n", "icmp-type-out-of-range"),
        ("access-list X extended permit ip any any time-range\n", "missing-time-range"),
        ("object-group network G\n network-object host 2001:db8::1\n", "ipv6"),
        ("object-group network G\n bogus-member 1\n", "unknown-group-member"),
        ("object-group network G\n network-object 192.0.2.0\n", "bad-network-object"),
        ("object-group network G\n network-object object OBJ\n", "asa-8.3-object-reference"),
        ("object-group service G tcp\n port-object eq 80 90\n", "trailing-tokens"),
        ("object-group service G\n service-object tcp source eq 1 bogus\n", "bad-service-object"),
        ("object-group service G\n service-object icmp 1 2\n", "bad-service-object"),
        ("object-group service G\n service-object 50 extra\n", "bad-service-object"),
        ("object-group protocol G\n protocol-object bogus\n", "unknown-protocol-name"),
        ("object-group protocol G\n protocol-object\n", "bad-protocol-object"),
        ("object-group icmp-type G\n icmp-object\n", "bad-icmp-object"),
        ("object-group network G\n group-object\n", "bad-group-object"),
        ("object-group\n", "bad-object-group"),
        ("object-group bogus G\n", "unknown-object-group-type"),
        ("object-group user G\n", "identity-firewall"),
        ("object-group security G\n", "trustsec-security-group"),
        ("object-group network G\nobject-group protocol G\n", "object-group-kind-redefined"),
    ],
)
def test_statement_failures_are_recorded_not_raised(text: str, reason: str) -> None:
    p = _asa(BASE + text)
    assert reason in _reasons(p)
    assert all(u.security_relevant for u in p.unparsed if u.reason == reason)


def test_object_group_edge_members() -> None:
    p = _asa(
        BASE
        + "object-group network G\n"
        + " description a group\n"
        + " network-object 10.0.0.0 255.255.255.0\n"
        + "object-group network G\n"
        + " network-object host 10.1.1.1\n"
        + "object-group service SVC tcp-udp\n"
        + " port-object eq 53\n"
        + "object-group service SVC2 tcp-udp\n"
        + " group-object SVC\n"
        + "object-group service UDPG udp\n"
        + " port-object eq 69\n"
        + "access-list A extended permit udp any any object-group SVC\n"
        + "access-list A extended permit tcp any object-group G\n"
        + "access-list A extended permit tcp any any object-group SVC2\n"
        + "access-list A extended permit tcp any any object-group UDPG\n"
    )
    r1, r2, r3 = p.acls["A"]
    assert r1.match.dst_ports == PortSet.single(53)
    expected = AddrSet.from_network(ipaddress.IPv4Network("10.0.0.0/24")).union(
        AddrSet.from_host("10.1.1.1")
    )
    assert r2.match.dst == expected
    assert r2.match.src_ports == PortSet.any()
    assert r3.match.dst_ports == PortSet.single(53)
    assert _reasons(p) == ["service-group-protocol-mismatch"]


def test_group_kind_mismatch_in_nesting_is_parse_error() -> None:
    with pytest.raises(ParseError) as err:
        _asa(
            BASE
            + "object-group network N\n group-object S\n"
            + "object-group service S tcp\n port-object eq 80\n"
        )
    assert err.value.code == "group-kind-mismatch"
    with pytest.raises(ParseError) as err2:
        _asa(
            BASE
            + "object-group service A tcp\n group-object B\n"
            + "object-group service B udp\n port-object eq 80\n"
        )
    assert err2.value.code == "group-kind-mismatch"
    with pytest.raises(ParseError) as err3:
        _asa(BASE + "object-group network N\n group-object MISSING\n")
    assert err3.value.message == "undefined object-group MISSING"
    assert err3.value.line_no == len(BASE.strip("\n").splitlines()) + 2


def test_group_used_with_wrong_kind_is_unparsed_not_fatal() -> None:
    p = _asa(
        BASE
        + "object-group service S tcp\n port-object eq 80\n"
        + "access-list A extended permit tcp object-group S any\n"
    )
    assert _reasons(p) == ["group-kind-mismatch"]


def test_parse_error_str_includes_line() -> None:
    err = ParseError("x", "boom", 7)
    assert str(err) == "x: boom (line 7)"
    assert str(ParseError("x", "boom")) == "x: boom"


def test_asa_9x_global_acl_binding_and_address_space() -> None:
    p = parse_pix_asa(
        BASE + "access-list G extended permit ip any any\naccess-group G global\n",
        dialect=Dialect.asa,
        os_version="9.8(4)",
    )
    assert p.address_space == AddressSpace.real
    assert p.bindings[0].global_acl is True


def test_context_and_firewall_variants() -> None:
    p = _asa("context admin\n config-url disk0:/admin.cfg\nfirewall bogus\nmode single\n")
    assert p.mode == PolicyMode.multiple
    assert _reasons(p) == [
        "multiple-context-mode",
        "multiple-context-mode",
        "unrecognized-command",
        "unrecognized-command",
    ]
    assert _asa("ASA Version\n").unparsed[0].reason == "unrecognized-command"


def test_pix_nameif_errors_and_hardware_lines() -> None:
    p = parse_pix_asa(
        "nameif ethernet0 outside security0\n"
        "nameif ethernet1 inside security999\n"
        "nameif ethernet2 dmz sec50\n"
        "interface ethernet0 auto\n",
        dialect=Dialect.pix,
    )
    assert [i.nameif for i in p.interfaces] == ["outside"]
    assert _reasons(p) == ["bad-nameif", "bad-nameif"]
