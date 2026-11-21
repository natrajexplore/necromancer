"""Task 5.2: overly broad, insecure service, unused, management, unfiltered, return-traffic and
no-remark findings, with severity from zone trust (requirements 3.3 to 3.6, 3.8 to 3.10, 3.13)."""

from __future__ import annotations

from pathlib import Path

import pytest
from hypothesis import given

from necro.autopsy import Finding, FindingType, Severity, analyze
from necro.autopsy_checks import Trust, management_ranges, zone_trust
from necro.ir import Policy
from necro.parsers import parse_config
from necro.parsers.ios_acl import parse_ios
from necro.parsers.pix_asa import parse_pix_asa
from tests.ir_strategies import ios_policies, pix_asa_policies

SAMPLES = Path(__file__).resolve().parents[2] / "samples" / "dead-configs"

BASE = """
interface Ethernet0/0
 nameif outside
 security-level 0
 ip address 198.51.100.1 255.255.255.0
interface Ethernet0/1
 nameif dmz
 security-level 50
 ip address 192.168.50.1 255.255.255.0
interface Ethernet0/2
 nameif inside
 security-level 100
 ip address 10.0.0.1 255.255.255.0
interface Ethernet0/3
 nameif mgmt
 security-level 100
 ip address 10.9.0.1 255.255.255.0
"""


def asa(body: str, bind: str = "outside", extra: str = "") -> Policy:
    return parse_pix_asa(BASE + extra + body + f"access-group A in interface {bind}\n")


def found(policy: Policy, kind: FindingType) -> dict[str, Finding]:
    return {f.rule_ref: f for f in analyze(policy) if f.type == kind}


def rule(text: str) -> str:
    return f"access-list A extended {text}\n"


# ---------------------------------------------------------------------------
# Zone trust
# ---------------------------------------------------------------------------


def test_zone_trust_uses_security_level_and_names() -> None:
    policy = asa("")
    assert zone_trust(policy, "outside") == Trust.untrusted
    assert zone_trust(policy, "dmz") == Trust.dmz
    assert zone_trust(policy, "inside") == Trust.internal
    ios = parse_ios("interface Gi0/0\n description WAN\ninterface Gi0/1\n description LAN\n")
    assert zone_trust(ios, "WAN") == Trust.untrusted  # IOS has no levels: the name decides
    assert zone_trust(ios, "LAN") == Trust.internal
    partner = parse_pix_asa(BASE.replace("nameif dmz", "nameif partner"))
    assert zone_trust(partner, "partner") == Trust.untrusted  # named partner, level 50


def test_management_ranges_are_the_networks_of_mgmt_interfaces() -> None:
    assert management_ranges(asa("")).to_networks()[0].with_prefixlen == "10.9.0.0/24"


# ---------------------------------------------------------------------------
# Overly broad (3.3)
# ---------------------------------------------------------------------------


def test_any_any_from_an_untrusted_zone_is_critical_and_from_dmz_high() -> None:
    outside = found(asa(rule("permit ip any any")), FindingType.overly_broad)
    assert outside["A#1"].severity == Severity.critical and outside["A#1"].verified
    assert outside["A#1"].zone == "outside"
    dmz = found(asa(rule("permit ip any any"), bind="dmz"), FindingType.overly_broad)
    assert dmz["A#1"].severity == Severity.high and dmz["A#1"].zone == "dmz"


@pytest.mark.parametrize(
    ("ace", "broad"),
    [
        ("permit tcp any any", True),
        ("permit 47 any any", True),
        ("permit ip 10.0.0.0 255.255.255.0 any", True),  # IP with any destination
        ("permit ip any host 192.168.50.10", False),
        ("permit icmp any any echo-reply", False),  # service-limited any/any
        ("permit tcp any any eq 80", False),
        ("permit tcp any eq 53 any", False),
        ("deny ip any any", False),
    ],
)
def test_overly_broad_definition(ace: str, broad: bool) -> None:
    assert bool(found(asa(rule(ace)), FindingType.overly_broad)) is broad


def test_a_shadowed_permit_is_not_exposure() -> None:
    policy = asa(rule("deny ip any any") + rule("permit ip any any"))
    assert found(policy, FindingType.overly_broad) == {}
    assert "A#2" in found(policy, FindingType.shadowed)


def test_rules_that_decide_never_selects_are_not_reported() -> None:
    ace = rule("permit tcp any host 192.168.50.10 eq 23")
    blocked = asa(ace, extra="nat-control\n")
    assert found(blocked, FindingType.insecure_service) == {}  # decide(): no-translation deny
    static = "static (dmz,outside) 192.168.50.10 192.168.50.10 netmask 255.255.255.255\n"
    translated = asa(ace, extra="nat-control\n" + static)
    assert "A#1" in found(translated, FindingType.insecure_service)


def test_exposure_checks_skip_acls_that_do_not_forward_traffic() -> None:
    unbound = parse_pix_asa(BASE + rule("permit ip any any"))
    assert found(unbound, FindingType.overly_broad) == {}
    assert "acl:A" in found(unbound, FindingType.unused_acl)


def test_an_outbound_only_acl_is_reported_but_unverified() -> None:
    policy = parse_pix_asa(
        BASE + rule("permit ip any any") + "access-group A out interface inside\n"
    )
    finding = found(policy, FindingType.overly_broad)["A#1"]
    assert finding.verified is False and finding.severity == Severity.high


# ---------------------------------------------------------------------------
# Insecure services (3.4)
# ---------------------------------------------------------------------------


def test_telnet_severity_follows_the_source_zone() -> None:
    ace = rule("permit tcp any host 10.0.0.5 eq 23")
    assert found(asa(ace), FindingType.insecure_service)["A#1"].severity == Severity.critical
    dmz = found(asa(ace, bind="dmz"), FindingType.insecure_service)
    assert dmz["A#1"].severity == Severity.high


def test_ftp_is_high_from_untrusted_and_medium_from_internal() -> None:
    ace = rule("permit tcp any host 192.168.50.10 eq 21")
    assert found(asa(ace), FindingType.insecure_service)["A#1"].severity == Severity.high
    inside = found(asa(ace, bind="inside"), FindingType.insecure_service)
    assert inside["A#1"].severity == Severity.medium


def test_services_that_matter_only_from_untrusted_zones() -> None:
    for port, proto in ((445, "tcp"), (139, "tcp"), (137, "udp"), (389, "tcp"), (110, "tcp")):
        ace = rule(f"permit {proto} any host 192.168.50.10 eq {port}")
        assert found(asa(ace), FindingType.insecure_service), port
        assert found(asa(ace, bind="inside"), FindingType.insecure_service) == {}, port


def test_rdp_is_critical_from_untrusted_and_high_to_a_management_range() -> None:
    from_outside = rule("permit tcp any host 192.168.50.10 eq 3389")
    got = found(asa(from_outside), FindingType.insecure_service)
    assert got["A#1"].severity == Severity.critical
    to_mgmt = rule("permit tcp 10.0.0.0 255.255.255.0 10.9.0.0 255.255.255.0 eq 3389")
    got = found(asa(to_mgmt, bind="inside"), FindingType.insecure_service)
    assert got["A#1"].severity == Severity.high
    web = rule("permit tcp 10.0.0.0 255.255.255.0 10.9.0.0 255.255.255.0 eq 80")
    got = found(asa(web, bind="inside"), FindingType.insecure_service)
    assert "management range" in got["A#1"].explanation
    wide = rule("permit tcp 10.0.0.0 255.255.255.0 any eq 80")
    assert found(asa(wide, bind="inside"), FindingType.insecure_service) == {}


def test_one_finding_per_rule_lists_every_insecure_service() -> None:
    ace = rule("permit udp any host 10.0.0.5 range 161 162")
    finding = found(asa(ace), FindingType.insecure_service)["A#1"]
    assert "snmp" in finding.explanation and finding.severity == Severity.critical
    both = rule("permit tcp any host 10.0.0.5 range 21 23")
    text = found(asa(both), FindingType.insecure_service)["A#1"].explanation
    assert "telnet" in text and "ftp" in text


def test_a_wide_port_range_is_not_a_service() -> None:
    wide = asa(rule("permit tcp any host 10.0.0.5 neq 22"))
    assert found(wide, FindingType.insecure_service) == {}
    assert found(asa(rule("permit tcp any host 10.0.0.5")), FindingType.insecure_service) == {}


# ---------------------------------------------------------------------------
# Return traffic (3.10) and no remark (3.13)
# ---------------------------------------------------------------------------

IOS_EDGE = """
interface FastEthernet0/0
 description WAN
 ip address 192.0.2.2 255.255.255.0
 ip access-group 101 in
interface FastEthernet0/1
 description LAN
 ip address 10.0.0.1 255.255.255.0
"""


def test_return_traffic_rules_on_ios() -> None:
    policy = parse_ios(
        IOS_EDGE
        + "access-list 101 permit tcp any 10.0.0.0 0.0.0.255 established\n"
        + "access-list 101 permit udp any eq 53 any\n"
        + "access-list 101 permit udp any any eq 53\n"
        + "access-list 101 deny ip any any\n"
    )
    got = found(policy, FindingType.return_traffic)
    assert set(got) == {"101#1", "101#2"}
    assert all(f.severity == Severity.medium and f.verified for f in got.values())
    assert "established" in got["101#1"].explanation
    assert "source port" in got["101#2"].explanation


def test_return_traffic_is_an_ios_finding_only() -> None:
    assert found(asa(rule("permit udp any eq 53 any")), FindingType.return_traffic) == {}


def test_no_remark_findings_are_low_and_remarked_rules_are_clean() -> None:
    body = "access-list A remark business reason\n"
    policy = asa(body + rule("permit tcp any any eq 80") + rule("deny ip any any"))
    got = found(policy, FindingType.no_remark)
    assert set(got) == {"A#2"} and got["A#2"].severity == Severity.low


# ---------------------------------------------------------------------------
# Unused objects and ACLs (3.5)
# ---------------------------------------------------------------------------


def test_unused_object_groups_include_nested_groups_only_when_the_parent_is_unused() -> None:
    policy = asa(
        "object-group network INNER\n network-object host 10.0.0.1\n"
        "object-group network OUTER\n group-object INNER\n"
        "object-group network LONELY\n network-object host 10.0.0.2\n"
        "object-group network CHILD\n network-object host 10.0.0.3\n"
        "object-group network PARENT\n group-object CHILD\n"
        + rule("permit ip object-group PARENT any")
        + rule("permit ip object-group OUTER any")
    )
    got = found(policy, FindingType.unused_object)
    assert set(got) == {"object-group:LONELY"}
    assert got["object-group:LONELY"].severity == Severity.low
    assert got["object-group:LONELY"].source_line > 0


def test_an_unused_parent_group_leaves_its_child_unused_too() -> None:
    policy = asa(
        "object-group network INNER\n network-object host 10.0.0.1\n"
        "object-group network OUTER\n group-object INNER\n" + rule("permit ip any any")
    )
    assert set(found(policy, FindingType.unused_object)) == {
        "object-group:INNER",
        "object-group:OUTER",
    }


def test_unused_acl_on_asa_checks_bindings_and_other_lines() -> None:
    policy = parse_pix_asa(
        BASE
        + "access-list A extended permit ip any any\n"
        + "access-list U extended permit ip any any\n"
        + "access-list V extended permit ip any any\n"
        + "access-list W extended permit ip any any\n"
        + "access-group A in interface outside\n"
        + "access-group W out interface inside\n"
        + "crypto map M 10 match address V\n"
    )
    assert set(found(policy, FindingType.unused_acl)) == {"acl:U"}


def test_unused_acl_on_ios_uses_the_reference_classification() -> None:
    policy = parse_ios(
        IOS_EDGE
        + "access-list 101 deny ip any any\n"
        + "access-list 150 permit ip any any\n"
        + "access-list 10 permit 10.0.0.0 0.0.0.255\n"
        + "line vty 0 4\n access-class 10 in\n"
    )
    assert set(found(policy, FindingType.unused_acl)) == {"acl:150"}


# ---------------------------------------------------------------------------
# Insecure management (3.8)
# ---------------------------------------------------------------------------


def test_telnet_management_severity_follows_the_interface_zone() -> None:
    policy = parse_pix_asa(
        BASE
        + "telnet 10.0.0.0 255.255.255.0 inside\n"
        + "telnet 0 0 outside\n"
        + "ssh 10.0.0.0 255.255.255.0 inside\n"
    )
    got = {f.zone: f for f in found(policy, FindingType.insecure_management).values()}
    assert got["inside"].severity == Severity.high
    assert got["outside"].severity == Severity.critical
    assert len(got) == 2  # ssh is fine
    assert "any address" in got["outside"].explanation


def test_snmp_v1_v2c_is_flagged_and_v3_is_not() -> None:
    policy = parse_pix_asa(
        BASE
        + "snmp-server host inside 10.0.0.77 poll version 2c\n"
        + "snmp-server host inside 10.0.0.78 poll version 3\n"
        + "snmp-server host outside 198.51.100.77 poll\n"
        + "snmp-server community <redacted>\n"
    )
    got = found(policy, FindingType.insecure_management)
    severities = sorted(f.severity.value for f in got.values())
    assert severities == ["critical", "medium", "medium"]
    assert "<redacted>" not in " ".join(f.explanation for f in got.values())


def test_plain_http_management_is_an_ios_finding_but_asa_http_is_tls() -> None:
    ios = parse_ios(IOS_EDGE + "ip http server\nip http secure-server\n")
    (finding,) = found(ios, FindingType.insecure_management).values()
    assert finding.severity == Severity.high and "without TLS" in finding.explanation
    assdm = parse_pix_asa(BASE + "http server enable\nhttp 10.0.0.0 255.255.255.0 inside\n")
    assert found(assdm, FindingType.insecure_management) == {}


def test_vty_telnet_on_ios_is_flagged() -> None:
    policy = parse_ios(
        IOS_EDGE
        + "line vty 0 4\n transport input telnet ssh\n"
        + "line vty 5 15\n transport input ssh\n"
    )
    got = found(policy, FindingType.insecure_management)
    assert len(got) == 1 and next(iter(got.values())).zone == "the vty lines"


# ---------------------------------------------------------------------------
# Unfiltered interfaces (3.9)
# ---------------------------------------------------------------------------


def test_unfiltered_asa_interface_names_the_implicit_behaviour_from_decide() -> None:
    policy = parse_pix_asa(BASE)
    got = found(policy, FindingType.unfiltered_interface)
    assert set(got) == {f"interface:{n}" for n in ("outside", "dmz", "inside", "mgmt")}
    inside = got["interface:inside"]
    assert inside.verified and inside.severity == Severity.high
    assert "permitted towards outside, dmz" in inside.explanation
    assert "denied towards mgmt" in inside.explanation  # equal security level
    outside = got["interface:outside"]
    assert outside.severity == Severity.critical
    assert "permitted towards no interface" in outside.explanation


def test_an_interface_with_an_inbound_acl_or_a_global_acl_is_filtered() -> None:
    bound = asa(rule("deny ip any any"))
    assert "interface:outside" not in found(bound, FindingType.unfiltered_interface)
    glob = parse_pix_asa(
        BASE + "access-list G extended deny ip any any\naccess-group G global\n",
        os_version="9.8(4)",
    )
    assert found(glob, FindingType.unfiltered_interface) == {}


def test_unfiltered_ios_interface_permits_everything() -> None:
    policy = parse_ios(IOS_EDGE + "access-list 101 deny ip any any\n")
    got = found(policy, FindingType.unfiltered_interface)
    assert "interface:LAN" in got and "interface:WAN" not in got
    assert "implicit-permit-no-acl" in got["interface:LAN"].explanation


def test_an_interface_with_no_other_addressed_interface_is_still_reported() -> None:
    policy = parse_pix_asa("interface E0\n nameif only\n security-level 10\n")
    (finding,) = found(policy, FindingType.unfiltered_interface).values()
    assert finding.verified is False and "no interface" in finding.explanation


# ---------------------------------------------------------------------------
# The finding record (3.6) and robustness
# ---------------------------------------------------------------------------


def _assert_complete(findings: list[Finding]) -> None:
    ids = [f.id for f in findings]
    assert len(ids) == len(set(ids))
    for f in findings:
        assert f.id.startswith("AUT-") and f.rule_ref and f.label
        assert f.explanation.strip() and f.recommendation.strip()
        assert "{" not in f.explanation and "{" not in f.recommendation  # no unfilled templates
        assert isinstance(f.related, list) and f.severity in Severity


@pytest.mark.parametrize("name", ["pix-2006-hq.cfg", "asa-8.2-branch.cfg", "ios-12-edge.cfg"])
def test_sample_findings_are_complete_and_deterministic(name: str) -> None:
    raw = (SAMPLES / name).read_text(encoding="utf-8")
    first, second = analyze(parse_config(raw)), analyze(parse_config(raw))
    assert first == second
    _assert_complete(first)
    assert [f.source_line for f in first] == sorted(f.source_line for f in first)


@pytest.mark.pbt
@given(pix_asa_policies() | ios_policies())
def test_analyze_is_total_and_complete_on_generated_policies(policy: Policy) -> None:
    _assert_complete(analyze(policy))
