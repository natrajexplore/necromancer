"""Task 5.1: shadowed and redundant detection, and property P3 (requirements 3.1, 3.2, 3.7).

P3: removing a rule the autopsy flags as shadowed or redundant changes no decision. "Decision" is
what ``decide()`` returns: for a redundant rule the action and egress zone must stay the same (the
rule id naturally changes); for a shadowed rule the whole decision must stay the same, because the
rule never fired.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

import pytest
from hypothesis import event, given
from hypothesis import strategies as st

from necro.autopsy import FindingType, Severity, analyze, without_rule
from necro.contexts import build_contexts
from necro.evaluate import decide
from necro.ir import Action, Binding, Dialect, Flow, Interface, Policy, Rule
from necro.ir import Match as IrMatch
from necro.parsers import parse_config
from necro.parsers.pix_asa import parse_pix_asa
from necro.sets import AddrSet, PortSet
from tests.ir_strategies import flows_near, ios_policies, pix_asa_policies

SAMPLES = Path(__file__).resolve().parents[2] / "samples" / "dead-configs"
HYGIENE = {FindingType.shadowed, FindingType.redundant}

BASE = """
interface Ethernet0/0
 nameif outside
 security-level 0
 ip address 198.51.100.1 255.255.255.0
interface Ethernet0/1
 nameif inside
 security-level 100
 ip address 10.0.0.1 255.255.255.0
"""


def _hygiene(text: str) -> dict[tuple[str, str], list[str]]:
    policy = parse_pix_asa(BASE + text + "access-group A in interface outside\n")
    return {(f.type.value, f.rule_ref): f.related for f in analyze(policy) if f.type in HYGIENE}


# ---------------------------------------------------------------------------
# Samples
# ---------------------------------------------------------------------------


def test_pix_sample_shadowed_and_redundant() -> None:
    found = {
        (f.type.value, f.rule_ref): f.related
        for f in analyze(parse_config((SAMPLES / "pix-2006-hq.cfg").read_text(encoding="utf-8")))
        if f.type in HYGIENE
    }
    assert found == {
        ("shadowed", "outside_in#4"): ["outside_in#1"],
        ("shadowed", "dmz_in#4"): ["dmz_in#3"],
        ("redundant", "dmz_in#1"): ["dmz_in#3"],
        ("redundant", "dmz_in#2"): ["dmz_in#3"],
    }


def test_asa_sample_redundant_rules_name_the_covering_rule() -> None:
    findings = analyze(parse_config((SAMPLES / "asa-8.2-branch.cfg").read_text(encoding="utf-8")))
    found = {f.rule_ref: f.related for f in findings if f.type == FindingType.redundant}
    assert found["OUTSIDE_IN#3"] == ["OUTSIDE_IN#4"]  # the seeded ghost
    assert found["INSIDE_OUT#1"] == ["INSIDE_OUT#4"]
    assert not [f for f in findings if f.type == FindingType.shadowed]


def test_ios_sample_shadowed_rule() -> None:
    findings = analyze(parse_config((SAMPLES / "ios-12-edge.cfg").read_text(encoding="utf-8")))
    shadowed = [f for f in findings if f.type == FindingType.shadowed]
    assert [(f.rule_ref, f.related, f.source_line) for f in shadowed] == [
        ("LAN_OUT#4", ["LAN_OUT#2"], 42)
    ]


def test_findings_are_confirmed_with_decide_and_carry_the_full_record() -> None:
    findings = analyze(parse_config((SAMPLES / "pix-2006-hq.cfg").read_text(encoding="utf-8")))
    hygiene = [f for f in findings if f.type in HYGIENE]
    assert hygiene and all(f.verified for f in hygiene)
    for f in hygiene:
        assert f.severity == Severity.medium
        assert f.id.startswith("AUT-") and f.source_line > 0
        assert f.rule_ref in f.explanation and f.rule_ref in f.recommendation
        assert f.label and f.related


# ---------------------------------------------------------------------------
# Detection rules
# ---------------------------------------------------------------------------


def test_opposite_action_in_between_prevents_redundancy() -> None:
    found = _hygiene(
        "access-list A extended permit tcp any host 192.0.2.10 eq 80\n"
        "access-list A extended deny tcp host 203.0.113.9 any eq 80\n"
        "access-list A extended permit tcp any any eq 80\n"
    )
    assert found == {}


def test_a_covered_rule_after_an_opposite_one_is_shadowed_not_redundant() -> None:
    found = _hygiene(
        "access-list A extended permit tcp any host 192.0.2.10 eq 80\n"
        "access-list A extended deny tcp host 203.0.113.9 host 192.0.2.10 eq 80\n"
    )
    assert found == {("shadowed", "A#2"): ["A#1"]}


def test_falling_through_to_the_implicit_deny_is_not_redundancy() -> None:
    assert _hygiene("access-list A extended deny tcp any host 192.0.2.10 eq 80\n") == {}
    found = _hygiene(
        "access-list A extended deny tcp any host 192.0.2.10 eq 80\n"
        "access-list A extended deny ip any any\n"
    )
    assert found == {("redundant", "A#1"): ["A#2"]}


def test_a_union_of_later_rules_can_cover() -> None:
    found = _hygiene(
        "access-list A extended permit tcp any host 192.0.2.10 range 1 100\n"
        "access-list A extended permit tcp any host 192.0.2.10 range 1 60\n"
        "access-list A extended permit tcp any host 192.0.2.10 range 40 200\n"
        "access-list A extended deny ip any any\n"
    )
    assert found == {("shadowed", "A#2"): ["A#1"], ("redundant", "A#1"): ["A#2", "A#3"]}


def test_shadowed_by_a_union_names_every_overlapping_earlier_rule() -> None:
    found = _hygiene(
        "access-list A extended permit tcp any host 192.0.2.10 range 1 50\n"
        "access-list A extended deny tcp any host 192.0.2.10 range 51 100\n"
        "access-list A extended permit tcp any host 192.0.2.10 range 20 80\n"
    )
    assert found == {("shadowed", "A#3"): ["A#1", "A#2"]}


def test_inactive_rules_neither_shadow_nor_get_flagged() -> None:
    found = _hygiene(
        "access-list A extended permit ip any any inactive\n"
        "access-list A extended permit tcp any host 192.0.2.10 eq 80\n"
        "access-list A extended permit tcp any host 192.0.2.10 eq 80 inactive\n"
    )
    assert found == {}


def test_icmp_types_and_other_ip_protocols_are_distinct_kinds() -> None:
    found = _hygiene(
        "access-list A extended permit icmp any any\n"
        "access-list A extended permit icmp any any echo\n"
        "access-list A extended permit 47 any any\n"
        "access-list A extended permit ip any any\n"
    )
    assert found == {
        ("shadowed", "A#2"): ["A#1"],
        ("redundant", "A#1"): ["A#2", "A#4"],
        ("redundant", "A#3"): ["A#4"],
    }


def test_a_rule_whose_flows_fall_to_the_global_acl_is_not_redundant() -> None:
    policy = parse_pix_asa(
        BASE
        + "access-list A extended permit tcp any host 192.0.2.10 eq 80\n"
        + "access-list G extended deny ip any any\n"
        + "access-group A in interface outside\n"
        + "access-group G global\n",
        os_version="9.8(4)",
    )
    assert [f for f in analyze(policy) if f.type in HYGIENE] == []


def test_unbound_acl_is_analysed_but_cannot_be_verified() -> None:
    policy = parse_pix_asa(
        BASE
        + "access-list U extended permit ip any any\n"
        + "access-list U extended permit tcp any any eq 80\n"
    )
    (finding,) = [f for f in analyze(policy) if f.type in HYGIENE]
    assert (finding.type, finding.rule_ref, finding.verified) == (
        FindingType.shadowed,
        "U#2",
        False,
    )


def test_without_rule_removes_only_that_rule() -> None:
    policy = parse_pix_asa(
        BASE + "access-list A extended permit ip any any\naccess-list A extended deny ip any any\n"
    )
    reduced = without_rule(policy, "A", policy.acls["A"][0])
    assert [r.id for r in reduced.acls["A"]] == ["A#2"]
    assert [r.id for r in policy.acls["A"]] == ["A#1", "A#2"]


# ---------------------------------------------------------------------------
# P3
# ---------------------------------------------------------------------------


def _rule_by_ref(policy: Policy, ref: str) -> tuple[str, Rule]:
    for acl, rules in policy.acls.items():
        for rule in rules:
            if rule.id == ref:
                return acl, rule
    raise AssertionError(ref)


def check_removal_changes_nothing(policy: Policy, flows: list[Flow]) -> int:
    """P3 on one policy. Returns how many hygiene findings were checked."""
    contexts = build_contexts(policy)
    checked = 0
    for finding in analyze(policy):
        if finding.type not in HYGIENE:
            continue
        acl, rule = _rule_by_ref(policy, finding.rule_ref)
        reduced = without_rule(policy, acl, rule)
        checked += 1
        for ctx in contexts:
            for flow in flows:
                before, after = decide(policy, ctx, flow), decide(reduced, ctx, flow)
                assert (before.action, before.to_zone) == (after.action, after.to_zone), (
                    finding.rule_ref,
                    flow,
                )
                if finding.type == FindingType.shadowed:
                    assert before == after, (finding.rule_ref, flow)
    return checked


_SRC = [
    AddrSet.any(),
    AddrSet.from_network(ipaddress.IPv4Network("10.1.0.0/16")),
    AddrSet.from_network(ipaddress.IPv4Network("10.1.1.0/24")),
    AddrSet.from_host("10.1.1.5"),
]
_DST = [
    AddrSet.any(),
    AddrSet.from_network(ipaddress.IPv4Network("192.0.2.0/24")),
    AddrSet.from_host("192.0.2.10"),
]
_PORTS = [PortSet.any(), PortSet.single(80), PortSet.from_range(80, 90), PortSet.single(443)]


@st.composite
def _small_rule(draw: st.DrawFn, acl: str, ordinal: int) -> Rule:
    proto = draw(st.sampled_from([None, 6, 17, 1]))
    ports = draw(st.sampled_from(_PORTS)) if proto in (6, 17) else PortSet.any()
    icmp = draw(st.sampled_from([None, frozenset({8}), frozenset({0, 8})])) if proto == 1 else None
    match = IrMatch(
        src=draw(st.sampled_from(_SRC)),
        dst=draw(st.sampled_from(_DST)),
        proto=proto,
        dst_ports=ports,
        icmp_types=icmp,
    )
    return Rule(
        id=f"{acl}#{ordinal}",
        action=draw(st.sampled_from(list(Action))),
        match=match,
        inactive=draw(st.sampled_from([False] * 7 + [True])),
    )


@st.composite
def small_policies(draw: st.DrawFn) -> Policy:
    """Few distinct addresses and ports, so shadowing and redundancy are common."""
    acls = {
        name: [draw(_small_rule(name, i + 1)) for i in range(draw(st.integers(1, 7)))]
        for name in ("A", "G")
    }
    bindings = [Binding(acl_name="A", interface="outside", direction="in")]
    if draw(st.booleans()):
        bindings.append(Binding(acl_name="G", interface="", direction="in", global_acl=True))
    return Policy(
        dialect=Dialect.asa,
        os_version=draw(st.sampled_from(["8.2(5)", "9.8(4)"])),
        interfaces=[
            Interface(
                hw_name="e0",
                nameif="outside",
                security_level=0,
                ip_address=ipaddress.IPv4Interface("198.51.100.1/24"),
            ),
            Interface(
                hw_name="e1",
                nameif="inside",
                security_level=100,
                ip_address=ipaddress.IPv4Interface("10.0.0.1/24"),
            ),
        ],
        bindings=bindings,
        acls=acls,
    )


@pytest.mark.pbt
@given(st.data())
def test_p3_removing_a_flagged_rule_changes_no_decision_small(data: st.DataObject) -> None:
    policy = data.draw(small_policies())
    matches = [r.match for rules in policy.acls.values() for r in rules]
    flows = data.draw(st.lists(flows_near(matches), min_size=15, max_size=40))
    checked = check_removal_changes_nothing(policy, flows)
    event(f"hygiene findings checked: {min(checked, 3)}")


@pytest.mark.pbt
@given(st.data())
def test_p3_removing_a_flagged_rule_changes_no_decision_generated(data: st.DataObject) -> None:
    policy = data.draw(pix_asa_policies() | ios_policies())
    matches = [r.match for rules in policy.acls.values() for r in rules]
    flows = data.draw(st.lists(flows_near(matches), min_size=10, max_size=25))
    check_removal_changes_nothing(policy, flows)


@pytest.mark.pbt
@pytest.mark.parametrize("name", ["pix-2006-hq.cfg", "asa-8.2-branch.cfg", "ios-12-edge.cfg"])
@given(st.data())
def test_p3_on_the_samples(name: str, data: st.DataObject) -> None:
    policy = parse_config((SAMPLES / name).read_text(encoding="utf-8"))
    matches = [r.match for rules in policy.acls.values() for r in rules]
    flows = data.draw(st.lists(flows_near(matches), min_size=20, max_size=40))
    assert check_removal_changes_nothing(policy, flows) >= 1


def test_p3_is_not_vacuous() -> None:
    """A crafted policy with a shadowed rule really is exercised."""
    policy = parse_pix_asa(
        BASE
        + "access-list A extended permit ip any any\n"
        + "access-list A extended permit tcp any any eq 80\n"
        + "access-group A in interface outside\n"
    )
    flow = Flow(
        src=ipaddress.IPv4Address("203.0.113.1"),
        dst=ipaddress.IPv4Address("10.0.0.50"),
        proto=6,
        dst_port=80,
    )
    assert check_removal_changes_nothing(policy, [flow]) == 1
