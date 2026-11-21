"""Task 6.3: ICMP-type and IP-protocol custom applications; established omission (4.7, 4.9)."""

from __future__ import annotations

import ipaddress

import pytest

from necro.contexts import find_context
from necro.emitters import emit_panos
from necro.evaluate import decide
from necro.ir import Action, Dialect, Flow, LedgerClass, Policy
from necro.ledger import covering
from necro.parsers.ios_acl import parse_ios
from necro.parsers.pix_asa import parse_pix_asa
from tests.panos_helpers import policy_of, rules_of

ASA_BASE = """
interface E0
 nameif outside
 security-level 0
 ip address 192.0.2.1 255.255.255.0
interface E1
 nameif inside
 security-level 100
 ip address 10.1.0.1 255.255.255.0
"""
ASA_TAIL = "access-group A in interface outside\nroute outside 0.0.0.0 0.0.0.0 192.0.2.254 1\n"
IOS_BASE = """
interface FastEthernet0/0
 description WAN
 ip address 192.0.2.2 255.255.255.0
 ip access-group 101 in
interface FastEthernet0/1
 description LAN
 ip address 10.0.0.1 255.255.255.0
"""
WAN_IN = "FastEthernet0/0:in"


def asa(acl: str) -> Policy:
    return parse_pix_asa(ASA_BASE + acl + ASA_TAIL, dialect=Dialect.asa, os_version="8.2(5)")


def flow(
    src: str, dst: str, proto: int, sport: int = 0, dport: int = 0, established: bool = False
) -> Flow:
    return Flow(
        src=ipaddress.IPv4Address(src),
        dst=ipaddress.IPv4Address(dst),
        proto=proto,
        src_port=sport,
        dst_port=dport,
        established=established,
    )


def app_definitions(lines: list[str]) -> dict[str, str]:
    """Custom application name -> its ``default ...`` clause."""
    out: dict[str, str] = {}
    for line in lines:
        if line.startswith("set application "):
            words = line.split()
            out[words[2]] = " ".join(words[words.index("default") + 1 :])
    return out


# -- ICMP types -------------------------------------------------------------------------------


def test_icmp_echo_reply_uses_a_custom_application_for_that_exact_type() -> None:
    emission = emit_panos(policy_of("pix-2006-hq.cfg"))
    rule = rules_of(emission.lines)["outside_in-6"]
    assert rule["application"] == "necro-icmp-0"
    assert rule["service"] == "any"
    assert app_definitions(emission.lines)["necro-icmp-0"] == "ident-by-icmp-type type 0"


def test_the_ping_and_icmp_app_ids_are_never_used() -> None:
    for config in ("pix-2006-hq.cfg", "asa-8.2-branch.cfg", "ios-12-edge.cfg"):
        for name, attrs in rules_of(emit_panos(policy_of(config)).lines).items():
            apps = attrs["application"].replace("[", " ").replace("]", " ").split()
            assert not {"ping", "icmp", "icmp6"} & set(apps), (config, name)


def test_several_icmp_types_become_one_application_each_in_numeric_order() -> None:
    policy = asa(
        "object-group icmp-type T\n icmp-object echo-reply\n icmp-object unreachable\n"
        " icmp-object time-exceeded\naccess-list A extended permit icmp any any object-group T\n"
    )
    emission = emit_panos(policy)
    assert rules_of(emission.lines)["A-1"]["application"] == (
        "[ necro-icmp-0 necro-icmp-3 necro-icmp-11 ]"
    )
    assert set(app_definitions(emission.lines)) == {"necro-icmp-0", "necro-icmp-3", "necro-icmp-11"}


def test_icmp_of_every_type_is_matched_by_the_protocol_number() -> None:
    emission = emit_panos(asa("access-list A extended permit icmp any any\n"))
    assert rules_of(emission.lines)["A-1"]["application"] == "necro-ipproto-1"
    assert app_definitions(emission.lines)["necro-ipproto-1"] == "ident-by-ip-protocol 1"


# -- other IP protocols -----------------------------------------------------------------------


def test_gre_is_a_custom_application_and_is_recorded_in_the_ledger() -> None:
    emission = emit_panos(asa("access-list A extended permit gre any any\n"))
    rule = rules_of(emission.lines)["A-1"]
    assert (rule["application"], rule["service"]) == ("necro-ipproto-47", "any")
    assert app_definitions(emission.lines)["necro-ipproto-47"] == "ident-by-ip-protocol 47"
    (entry,) = [e for e in emission.ledger if e.entry_class == LedgerClass.app_id_protocol]
    assert entry.informational and entry.old_action == entry.new_action == Action.permit
    assert entry.covers("outside:in", flow("198.51.100.7", "10.1.0.9", 47))
    assert not entry.covers("outside:in", flow("198.51.100.7", "10.1.0.9", 50))
    assert not entry.covers("inside:in", flow("198.51.100.7", "10.1.0.9", 47))


# -- established ------------------------------------------------------------------------------


def test_the_ios_established_rule_is_omitted_and_ledgered_with_its_replacement_decision() -> None:
    policy = policy_of("ios-12-edge.cfg")
    emission = emit_panos(policy)
    assert "110-1" not in rules_of(emission.lines)
    assert emission.rule_sources["110-2"] == "110#2"
    golden = flow("198.51.100.5", "10.20.3.4", 6, sport=443, dport=51000, established=True)
    entries = [
        e
        for e in covering(emission.ledger, WAN_IN, golden)
        if e.entry_class == LedgerClass.stateful_established
    ]
    assert [(e.old_action, e.new_action, e.informational) for e in entries] == [
        (Action.permit, Action.deny, False)
    ]
    assert decide(policy, find_context(policy, WAN_IN), golden).action == Action.permit


def test_established_flows_a_later_rule_still_permits_need_no_entry() -> None:
    policy = parse_ios(
        IOS_BASE
        + "access-list 101 permit tcp any any established\n"
        + "access-list 101 permit tcp any any eq 80\n"
        + "access-list 101 deny ip any any\n"
    )
    est = [
        e for e in emit_panos(policy).ledger if e.entry_class == LedgerClass.stateful_established
    ]
    assert len(est) == 1 and (est[0].old_action, est[0].new_action) == (Action.permit, Action.deny)
    entry = est[0]
    assert entry.covers(WAN_IN, flow("198.51.100.7", "10.0.0.9", 6, dport=81, established=True))
    assert not entry.covers(WAN_IN, flow("198.51.100.7", "10.0.0.9", 6, dport=80, established=True))
    assert not entry.covers(WAN_IN, flow("198.51.100.7", "10.0.0.9", 6, dport=81))
    # traffic to the router itself is the to-the-box entries' business
    assert not entry.covers(WAN_IN, flow("198.51.100.7", "10.0.0.1", 6, dport=81, established=True))


def test_a_denying_established_rule_that_is_omitted_widens_and_says_so() -> None:
    policy = parse_ios(
        IOS_BASE
        + "access-list 101 deny tcp any any established\n"
        + "access-list 101 permit ip any any\n"
    )
    est = [
        e for e in emit_panos(policy).ledger if e.entry_class == LedgerClass.stateful_established
    ]
    assert [(e.old_action, e.new_action) for e in est] == [(Action.deny, Action.permit)]


def test_an_inactive_established_rule_changes_nothing_and_has_no_entry() -> None:
    policy = parse_ios(
        IOS_BASE
        + "access-list 101 permit tcp any any established\naccess-list 101 deny ip any any\n"
    )
    policy.acls["101"][0].inactive = True
    emission = emit_panos(policy)
    assert [e for e in emission.ledger if e.entry_class == LedgerClass.stateful_established] == []


@pytest.mark.parametrize("config", ["pix-2006-hq.cfg", "asa-8.2-branch.cfg", "ios-12-edge.cfg"])
def test_nothing_the_emitter_could_not_express_is_left_unsupported(config: str) -> None:
    assert emit_panos(policy_of(config)).unsupported == []
