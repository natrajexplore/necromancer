"""Task 4.2: IOS 12.x ACL parser (requirements 1.2, 1.11, 1.12)."""

from __future__ import annotations

import ipaddress
from pathlib import Path

import pytest

from necro.ir import Action, AddressSpace, Dialect, Policy
from necro.parsers.ios_acl import parse_ios
from necro.redact import redact
from necro.sets import AddrSet, PortSet

SAMPLES = Path(__file__).resolve().parents[2] / "samples"


def _ios(text: str) -> Policy:
    return parse_ios(text.strip("\n") + "\n")


def _reasons(policy: Policy) -> list[str]:
    return [u.reason for u in policy.unparsed]


def _net(cidr: str) -> AddrSet:
    return AddrSet.from_network(ipaddress.IPv4Network(cidr))


@pytest.fixture(scope="module")
def edge() -> Policy:
    text = redact((SAMPLES / "dead-configs" / "ios-12-edge.cfg").read_text(encoding="utf-8"))
    return parse_ios(text)


# ---------------------------------------------------------------------------
# Sample: ios-12-edge.cfg
# ---------------------------------------------------------------------------


def test_edge_header_interfaces_and_zones(edge: Policy) -> None:
    assert edge.dialect == Dialect.ios
    assert edge.os_version == "12.4"
    assert edge.address_space == AddressSpace.as_is
    got = [(i.hw_name, i.nameif, str(i.ip_address)) for i in edge.interfaces]
    assert got == [
        ("FastEthernet0/0", "WAN", "192.0.2.2/30"),
        ("FastEthernet0/1", "LAN", "10.20.0.1/16"),
        ("FastEthernet0/2", "MGMT", "10.99.0.1/24"),
    ]


def test_edge_nothing_unparsed(edge: Policy) -> None:
    assert edge.unparsed == []


def test_edge_acl_ordinals_and_established(edge: Policy) -> None:
    acl110 = edge.acls["110"]
    assert [r.id for r in acl110] == [f"110#{i}" for i in range(1, 8)]
    first = acl110[0]
    assert first.match.proto == 6 and first.match.established is True
    assert first.match.dst == _net("10.20.0.0/16")
    assert acl110[1].match.dst_ports == PortSet.single(443)
    assert acl110[4].match.icmp_types == frozenset({0})
    assert acl110[5].match.icmp_types == frozenset({11})
    assert acl110[6].action == Action.deny and acl110[6].log is True
    lan = edge.acls["LAN_OUT"]
    assert [r.id for r in lan] == [f"LAN_OUT#{i}" for i in range(1, 7)]
    assert lan[0].remark == "Web, DNS and the legacy X11 range"
    assert lan[3].match.dst_ports == PortSet.single(443)
    assert lan[4].match.dst_ports == PortSet.from_range(6000, 6010)
    assert lan[3].match.src == _net("10.20.5.0/24")


def test_edge_acl_classification_by_reference(edge: Policy) -> None:
    assert edge.acl_classes == {"10": "management-plane", "110": "policy", "LAN_OUT": "policy"}
    by_line = {r.line_no: r for r in edge.line_records}
    assert by_line[25].classification == "management-plane" and by_line[25].security_relevant
    assert by_line[27].classification == "migrated"


def test_edge_route_bindings_and_mgmt(edge: Policy) -> None:
    assert [(str(r.network), r.interface, str(r.next_hop)) for r in edge.routes] == [
        ("0.0.0.0/0", "WAN", "192.0.2.1")
    ]
    assert [(b.acl_name, b.interface, b.direction) for b in edge.bindings] == [
        ("110", "WAN", "in"),
        ("LAN_OUT", "LAN", "in"),
    ]
    mgmt = {(m.proto, m.src_addr == _net("10.99.0.0/24")) for m in edge.mgmt_access}
    assert mgmt == {("telnet", True), ("ssh", True), ("snmp", True)}


def test_edge_every_line_classified_once(edge: Policy) -> None:
    n = len((SAMPLES / "dead-configs" / "ios-12-edge.cfg").read_text(encoding="utf-8").splitlines())
    assert [r.line_no for r in edge.line_records] == list(range(1, n + 1))


# ---------------------------------------------------------------------------
# Negative fixture: every EXPECT-UNPARSED reason matches
# ---------------------------------------------------------------------------


def test_every_expect_unparsed_annotation_matches() -> None:
    path = SAMPLES / "broken-configs" / "ios-unsupported-constructs.cfg"
    lines = path.read_text(encoding="utf-8").splitlines()
    policy = parse_ios(redact(path.read_text(encoding="utf-8")))
    expected = {
        i + 2: line.split("EXPECT-UNPARSED:")[1].strip()
        for i, line in enumerate(lines)
        if line.startswith("! EXPECT-UNPARSED:")
    }
    assert len(expected) == 6
    got = {u.line_no: u for u in policy.unparsed}
    assert {n: got[n].reason for n in expected} == expected
    assert all(got[n].security_relevant for n in expected)
    assert set(got) == set(expected)  # nothing else is unparsed
    # unsupported ACEs keep their ordinals, so the final deny is 120#6
    assert [r.id for r in policy.acls["120"]] == ["120#6"]


# ---------------------------------------------------------------------------
# ACE and ACL forms
# ---------------------------------------------------------------------------

BASE = """
interface FastEthernet0/0
 ip address 192.0.2.2 255.255.255.0
interface FastEthernet0/1
 description LAN
 ip address 10.0.0.1 255.255.255.0
"""


def test_standard_acls_numbered_and_named() -> None:
    p = _ios(
        BASE
        + "access-list 10 permit 10.1.1.0 0.0.0.255\n"
        + "access-list 10 deny host 10.1.2.3\n"
        + "access-list 10 permit 10.1.3.4\n"
        + "access-list 10 permit any log\n"
        + "ip access-list standard STD\n"
        + " permit 10.9.0.0 0.0.255.255\n"
    )
    r = p.acls["10"]
    assert r[0].match.src == _net("10.1.1.0/24")
    assert r[1].match.src == AddrSet.from_host("10.1.2.3") and r[1].action == Action.deny
    assert r[2].match.src == AddrSet.from_host("10.1.3.4")
    assert r[3].match.src == AddrSet.any() and r[3].log is True
    assert p.acls["STD"][0].match.src == _net("10.9.0.0/16")
    assert all(x.match.proto is None and x.match.dst == AddrSet.any() for x in r)


def test_named_acl_with_sequence_numbers_and_remarks() -> None:
    p = _ios(
        BASE
        + "ip access-list extended NAMED\n"
        + " remark first\n"
        + " 10 permit tcp any any eq 80\n"
        + " 20 remark ignored seq on remark\n"
        + " 30 deny udp any any eq 53 log-input\n"
        + " 25 permit ip any any\n"
        + " permit ip any any time-range WORK\n"
    )
    rules = p.acls["NAMED"]
    got = [(r.id, r.vendor_seq) for r in rules]
    assert got == [("NAMED#1", 10), ("NAMED#2", 30), ("NAMED#4", None)]
    assert rules[0].remark == "first"
    assert rules[1].log is True
    assert rules[2].time_range == "WORK"
    assert "acl-sequence-out-of-order" in _reasons(p)


def test_extended_protocols_ports_and_icmp() -> None:
    p = _ios(
        BASE
        + "access-list 101 permit tcp 10.0.0.0 0.0.0.255 gt 1023 host 192.0.2.9 range 80 90\n"
        + "access-list 101 permit udp any neq 53 any lt 1024\n"
        + "access-list 101 permit 47 any any\n"
        + "access-list 101 permit gre any any\n"
        + "access-list 101 permit icmp any any\n"
        + "access-list 101 permit icmp any any echo\n"
        + "access-list 101 permit ospf any any log\n"
        + "access-list 101 permit tcp any any eq cmd\n"
        + "access-list 101 permit udp any any eq syslog\n"
    )
    r = p.acls["101"]
    assert r[0].match.src_ports == PortSet.from_gt(1023)
    assert r[0].match.dst_ports == PortSet.from_range(80, 90)
    assert r[1].match.src_ports == PortSet.from_neq(53)
    assert r[1].match.dst_ports == PortSet.from_lt(1024)
    assert [x.match.proto for x in r[2:7]] == [47, 47, 1, 1, 89]
    assert r[4].match.icmp_types is None and r[5].match.icmp_types == frozenset({8})
    assert [x.match.dst_ports for x in r[7:]] == [PortSet.single(514)] * 2


def test_ios_acl_numbers() -> None:
    p = _ios(
        "access-list 1350 permit any\n"
        + "access-list 2000 permit ip any any\n"
        + "access-list 700 permit 0000.0000.0000 ffff.ffff.ffff\n"
        + "access-list 300 permit any\n"
        + "access-list foo permit any\n"
        + "access-list 10\n"
        + "access-list 150 dynamic TEST timeout 10 permit ip any any\n"
    )
    assert set(p.acls) == {"1350", "2000", "150"}
    assert _reasons(p) == [
        "unsupported-acl-number",
        "unsupported-acl-number",
        "unsupported-acl-number",
        "unsupported-acl-number",
        "lock-and-key",
    ]


@pytest.mark.parametrize(
    ("entry", "reason"),
    [
        ("permit", "missing-protocol"),
        ("allow ip any any", "unknown-acl-action"),
        ("permit bogus any any", "unknown-protocol-name"),
        ("permit 999 any any", "protocol-out-of-range"),
        ("permit object-group X any any", "ios-object-group"),
        ("permit ip object-group X any", "ios-object-group"),
        ("permit ip 10.0.0.0 any", "missing-wildcard"),
        ("permit ip host nonsense any", "bad-address"),
        ("permit ip 10.0.0.0 0.0.0.999 any", "bad-wildcard"),
        ("permit ip 2001:db8::1 any", "ipv6"),
        ("permit ip any", "missing-address"),
        ("permit ip any eq 80 any", "port-operator-on-non-tcp-udp"),
        ("permit icmp any any eq 80", "port-operator-on-non-tcp-udp"),
        ("permit tcp any any eq frobnicate", "unknown-port-name"),
        ("permit tcp any any eq 80 ack", "tcp-flag-keyword"),
        ("permit tcp any any eq 80 precedence critical", "qos-match-keyword"),
        ("permit tcp any any eq 80 tos 4", "qos-match-keyword"),
        ("permit ip any any option any-options", "option-keyword"),
        ("permit ip any any ttl eq 1", "ttl-keyword"),
        ("permit ip any any evaluate X", "reflexive-acl"),
        ("permit udp any any established", "established-on-non-tcp"),
        ("permit icmp any any 3 1", "icmp-code-keyword"),
        ("permit icmp any any host-unreachable", "icmp-code-keyword"),
        ("permit icmp any any nonsense", "unknown-icmp-name"),
        ("permit ip any any time-range", "missing-time-range"),
        ("permit ip any any bogus-keyword", "unexpected-token"),
        ("evaluate MIRROR", "reflexive-acl"),
        ("dynamic X permit ip any any", "lock-and-key"),
    ],
)
def test_ace_failures_keep_ordinals_and_are_security_relevant(entry: str, reason: str) -> None:
    bind = "interface FastEthernet0/3\n ip access-group X in\n"
    p = _ios(BASE + bind + f"ip access-list extended X\n {entry}\n deny ip any any\n")
    assert reason in _reasons(p)
    assert [r.id for r in p.acls["X"]] == ["X#2"]
    assert all(u.security_relevant for u in p.unparsed if u.reason == reason)


def test_named_acl_entry_with_only_a_sequence_number() -> None:
    p = _ios(BASE + "ip access-list extended X\n 42\n")
    assert _reasons(p) == ["bad-acl-entry"]


# ---------------------------------------------------------------------------
# ACL classification by reference
# ---------------------------------------------------------------------------


def test_acl_classes_for_every_reference_kind() -> None:
    p = _ios(
        BASE
        + "interface FastEthernet0/3\n ip access-group 101 in\n"
        + "access-list 101 permit ip any any\n"
        + "access-list 11 permit 10.0.0.0 0.0.0.255\n"
        + "access-list 12 permit 10.0.1.0 0.0.0.255\n"
        + "access-list 13 permit 10.0.2.0 0.0.0.255\n"
        + "access-list 14 permit 10.0.3.0 0.0.0.255\n"
        + "access-list 15 permit 10.0.4.0 0.0.0.255\n"
        + "access-list 16 permit 10.0.5.0 0.0.0.255\n"
        + "access-list 17 permit 10.0.6.0 0.0.0.255\n"
        + "access-list 18 permit 10.0.7.0 0.0.0.255\n"
        + "access-list 19 permit 10.0.8.0 0.0.0.255\n"
        + "access-list 20 remark nobody uses me\n"
        + "access-list 20 permit 10.0.9.0 0.0.0.255\n"
        + "ntp access-group peer 11\n"
        + "snmp-server community <redacted> RO 12\n"
        + "ip http access-class 13\n"
        + "ip nat inside source list 14 interface FastEthernet0/0 overload\n"
        + "route-map RM permit 10\n"
        + " match ip address 15\n"
        + "crypto map CM 10 ipsec-isakmp\n"
        + " match address 16\n"
        + "class-map match-any CMAP\n"
        + " match access-group 17\n"
        + "class-map match-any CMAP2\n"
        + " match access-group name 18\n"
        + "router ospf 1\n"
        + " distribute-list 19 in\n"
    )
    assert p.acl_classes == {
        "101": "policy",
        "11": "management-plane",
        "12": "management-plane",
        "13": "management-plane",
        "14": "non-policy",
        "15": "non-policy",
        "16": "non-policy",
        "17": "non-policy",
        "18": "non-policy",
        "19": "non-policy",
        "20": "unused",
    }
    by_text = {r.text: r for r in p.line_records}
    unused = by_text["access-list 20 permit 10.0.9.0 0.0.0.255"]
    assert unused.classification == "not-policy" and unused.reason == "unused-acl"
    assert not unused.security_relevant
    assert by_text["access-list 14 permit 10.0.3.0 0.0.0.255"].reason == "non-policy-acl"
    assert by_text["access-list 11 permit 10.0.0.0 0.0.0.255"].classification == "management-plane"
    assert by_text["router ospf 1"].classification == "out-of-scope"
    assert not by_text["router ospf 1"].security_relevant


def test_unused_acl_with_unsupported_ace_is_not_security_relevant_but_still_listed() -> None:
    p = _ios(BASE + "access-list 150 permit tcp any any eq 80 dscp ef\n")
    assert p.acl_classes["150"] == "unused"
    (u,) = p.unparsed
    assert (u.reason, u.security_relevant) == ("qos-match-keyword", False)


def test_bound_acl_with_unsupported_ace_stays_security_relevant() -> None:
    bind = "interface FastEthernet0/3\n ip access-group 101 in\n"
    p = _ios(BASE + bind + "access-list 101 permit tcp any any eq 80 dscp ef\n")
    (u,) = p.unparsed
    assert u.security_relevant is True


# ---------------------------------------------------------------------------
# Interfaces, routes, bindings
# ---------------------------------------------------------------------------


def test_zone_naming_collisions_and_invalid_descriptions() -> None:
    p = _ios(
        "interface Gi0/0\n description LAN\n"
        "interface Gi0/1\n description LAN\n"
        "interface Gi0/2\n description has spaces\n"
        "interface Gi0/3\n"
        "interface Gi0/4\n description Gi0-3\n"
        "interface Gi0-3\n"
    )
    # Gi0/4 asks for "Gi0-3", already taken by the slug of Gi0/3, so it uses its own slug.
    assert [i.nameif for i in p.interfaces] == [
        "LAN",
        "Gi0-1",
        "Gi0-2",
        "Gi0-3",
        "Gi0-4",
        "Gi0-3-2",
    ]


def test_interface_children() -> None:
    p = _ios(
        """
interface Gi0/0
 description WAN
 ip address 192.0.2.2 255.255.255.252
 ip address 192.0.2.5 255.255.255.252 secondary
 ip address dhcp
 ip address 192.0.2.9
 ip nat outside
 ip helper-address 10.0.0.9
 ip verify unicast reverse-path
 ip inspect OUT out
 ip policy route-map PBR
 ip unnumbered Gi0/1
 ip access-group 5 sideways
 ipv6 address 2001:db8::1/64
 ipv6 traffic-filter V6 in
 zone-member security inside
 crypto map CM
 service-policy output QOS
 duplex auto
 shutdown
 mystery-command
interface Gi0/9 point-to-point
interface Gi0/1 weird extra
"""
    )
    assert _reasons(p) == [
        "secondary-address",
        "dynamic-interface-address",
        "bad-ip-address",
        "unicast-rpf",
        "cbac-inspect",
        "policy-based-routing",
        "unrecognized-interface-command",  # ip unnumbered
        "bad-access-group",
        "ipv6",
        "ipv6",
        "zone-based-firewall",
        "vpn-not-migrated",
        "qos-not-modelled",
        "unrecognized-interface-command",  # mystery-command
        "unrecognized-interface-command",  # interface with extra tokens
    ]
    relevant = {u.reason: u.security_relevant for u in p.unparsed}
    assert relevant["vpn-not-migrated"] is False and relevant["qos-not-modelled"] is False
    assert [i.hw_name for i in p.interfaces] == ["Gi0/0", "Gi0/9"]


def test_routes_next_hop_interface_and_null() -> None:
    p = _ios(
        BASE
        + "ip route 0.0.0.0 0.0.0.0 192.0.2.1\n"
        + "ip route 10.5.0.0 255.255.0.0 FastEthernet0/1 10.0.0.2 200 name foo tag 5 permanent\n"
        + "ip route 10.6.0.0 255.255.0.0 Null0\n"
        + "ip route 10.7.0.0 255.255.0.0 172.31.0.1\n"
        + "ip route 10.8.0.0 255.255.0.0 Missing0/0\n"
        + "ip route 10.9.0.0 255.255.0.0 192.0.2.1 track 3\n"
        + "ip route vrf X 10.1.0.0 255.255.0.0 192.0.2.1\n"
        + "ip route 10.2.0.0 255.255.0.0\n"
        + "ip route 10.3.0.0 255.0.255.0 192.0.2.1\n"
        + "ip route 10.4.0.0 255.255.0.0 192.0.2.1 bogus extra\n"
        + "ip route 10.1.1.0 255.255.255.0 192.0.2.1 global\n"
        + "ip route 10.1.2.0 255.255.255.0 192.0.2.1 FastEthernet0/1 zzz\n"
    )
    assert [(str(r.network), r.interface, r.metric) for r in p.routes] == [
        ("0.0.0.0/0", "FastEthernet0-0", 1),
        ("10.5.0.0/16", "LAN", 200),
        ("10.6.0.0/16", "", 1),
    ]
    assert _reasons(p) == [
        "route-next-hop-unresolved",
        "route-unknown-interface",
        "route-track",
        "vrf-route",
        "bad-route",
        "non-contiguous-mask",
        "route-option-unsupported",
        "vrf-route",
        "route-option-unsupported",
    ]


def test_bindings_in_out_duplicate_and_undefined() -> None:
    p = _ios(
        """
interface Gi0/0
 ip access-group A in
 ip access-group B out
 ip access-group C in
 ip access-group MISSING out
access-list 1 permit any
ip access-list extended A
 permit ip any any
ip access-list extended B
 deny ip any any
ip access-list extended C
 permit ip any any
"""
    )
    assert [(b.acl_name, b.direction) for b in p.bindings] == [("A", "in"), ("B", "out")]
    assert p.egress_acls == {"Gi0-0": "B"}
    assert _reasons(p) == ["duplicate-access-group", "binding-to-undefined-acl"]
    assert p.acl_classes["C"] == "unused"


# ---------------------------------------------------------------------------
# Management plane
# ---------------------------------------------------------------------------


def test_vty_snmp_and_ntp_forms() -> None:
    p = _ios(
        BASE
        + "access-list 21 permit 10.0.0.0 0.0.0.255\n"
        + "access-list 21 deny any\n"
        + "ip access-list extended WIDE\n"
        + " permit tcp any any\n"
        + "line con 0\n"
        + " password <redacted>\n"
        + "line vty 0 4\n"
        + " access-class 21 in\n"
        + " transport input telnet\n"
        + "line vty 5 15\n"
        + " transport input all\n"
        + " transport input none\n"
        + " exec-timeout 5 0\n"
        + "line vty 16 20\n"
        + " access-class 21 out\n"
        + " ipv6 access-class V6 in\n"
        + "line vty 21 25\n"
        + " access-class WIDE in\n"
        + "line vty 26 30\n"
        + " access-class GONE in\n"
        + "snmp-server community <redacted> RO\n"
        + "snmp-server community <redacted> RW 21\n"
        + "snmp-server community <redacted> RO ipv6 V6\n"
        + "snmp-server community <redacted> RO WIDE\n"
        + "snmp-server location lab\n"
        + "ntp access-group peer 21\n"
        + "ntp server 192.0.2.77\n"
        + "ip http server\n"
    )
    mgmt = [(m.proto, m.src_addr) for m in p.mgmt_access]
    allowed = _net("10.0.0.0/24")
    assert mgmt == [
        ("telnet", allowed),
        ("telnet", AddrSet.any()),
        ("ssh", AddrSet.any()),
        ("vty", AddrSet.any()),
        ("snmp", AddrSet.any()),
        ("snmp", allowed),
        ("snmp", AddrSet.any()),
    ]
    assert _reasons(p) == [
        "vty-access-class-direction",
        "ipv6",
        "access-class-acl-not-source-only",
        "access-class-undefined-acl",
        "access-class-acl-not-source-only",
    ]


def test_banner_blocks_are_not_parsed_as_config() -> None:
    p = _ios(
        "banner motd ^CKeep out^C\n"
        "banner login ^C\n"
        "access-list 1 permit any\n"
        "still banner text\n"
        "^C\n"
        "hostname r1\n"
        "banner exec\n"
    )
    assert "1" not in p.acls
    assert p.unparsed == []
    assert [r.classification for r in p.line_records] == ["not-policy"] * 7


def test_top_level_classification() -> None:
    p = _ios(
        """
version 12.4
version
hostname r1
no ip domain-lookup
ip cef
ip domain-name lab.example
ip http server
ip http access-class 3
ip verify unicast source reachable-via rx
ip bogus
ip access-list resequence A 10 10
ip access-list bogus X
ip access-list extended
crypto map CM 10 ipsec-isakmp
 set peer 192.0.2.99
route-map RM permit 10
 set ip next-hop 192.0.2.1
class-map type inspect match-any CM
policy-map type inspect PM
policy-map QOS
 class CM
object-group network OG
 host 10.0.0.1
control-plane
 service-policy input CP
router eigrp 1
 network 10.0.0.0
zone security inside
ipv6 unicast-routing
zone-pair security A source inside destination outside
mystery
 child
distribute-list 7 in
"""
    )
    assert _reasons(p) == [
        "unrecognized-command",  # bare "version"
        "unicast-rpf",
        "unrecognized-command",  # ip bogus
        "unrecognized-command",  # ip access-list bogus
        "unrecognized-command",  # ip access-list extended (no name)
        "vpn-not-migrated",
        "vpn-not-migrated",
        "zone-based-firewall",  # class-map type inspect
        "zone-based-firewall",  # policy-map type inspect
        "qos-not-modelled",
        "qos-not-modelled",
        "ios-object-group",
        "ios-object-group",
        "dynamic-routing",
        "dynamic-routing",
        "zone-based-firewall",
        "ipv6",
        "zone-based-firewall",
        "unrecognized-command",
        "unrecognized-command",
    ]
    by_text = {r.text: r for r in p.line_records}
    assert by_text["ip http access-class 3"].classification == "management-plane"
    assert by_text[" set ip next-hop 192.0.2.1"].reason == "route-map"
    assert by_text["distribute-list 7 in"].classification == "not-policy"


def test_orphan_indented_line_and_comment_inside_acl_block() -> None:
    text = " lonely\nip access-list extended X\n! a comment inside the block\n permit ip any any\n"
    p = _ios(text)
    assert _reasons(p) == ["orphan-indented-line"]
    assert [r.id for r in p.acls["X"]] == ["X#1"]
