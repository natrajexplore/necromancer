"""PIX/ASA traffic to the device: only the management commands decide (policy-semantics 1.3, 7)."""

from __future__ import annotations

import ipaddress

import pytest
from hypothesis import given
from hypothesis import strategies as st

from necro.contexts import find_context
from necro.emitters import emit_panos
from necro.evaluate import decide
from necro.ir import Action, Dialect, Flow, Policy
from necro.mgmt import icmp_sources, source_boxes
from necro.oracle import prove
from necro.parsers.pix_asa import parse_pix_asa

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
 ip address 172.16.0.1 255.255.255.0
route outside 0.0.0.0 0.0.0.0 192.0.2.254 1
"""
OUTSIDE, INSIDE, DMZ = "192.0.2.1", "10.1.0.1", "172.16.0.1"


def asa(text: str = "") -> Policy:
    return parse_pix_asa(BASE + text, dialect=Dialect.asa, os_version="8.2(5)")


def flow(src: str, dst: str, proto: int = 6, dport: int = 0, icmp: int | None = None) -> Flow:
    return Flow(
        src=ipaddress.IPv4Address(src),
        dst=ipaddress.IPv4Address(dst),
        proto=proto,
        dst_port=dport,
        icmp_type=icmp,
    )


def verdict(policy: Policy, ctx: str, f: Flow) -> tuple[Action, str, str]:
    d = decide(policy, find_context(policy, ctx), f)
    return d.action, d.rule_id, d.to_zone


def test_telnet_is_admitted_from_the_listed_network_on_the_receiving_interface_only() -> None:
    p = asa("telnet 10.1.0.0 255.255.255.0 inside\n")
    assert verdict(p, "inside:in", flow("10.1.0.9", INSIDE, dport=23)) == (
        Action.permit,
        "mgmt:telnet",
        "self",
    )
    assert verdict(p, "inside:in", flow("10.2.0.9", INSIDE, dport=23))[0] == Action.deny
    assert verdict(p, "inside:in", flow("10.1.0.9", INSIDE, dport=22))[0] == Action.deny


def test_far_interface_access_is_denied() -> None:
    p = asa("telnet 0 0 inside\nssh 0 0 outside\n")
    # telnet is enabled on inside, but this flow arrives on outside (and targets inside's address)
    assert verdict(p, "outside:in", flow("203.0.113.9", INSIDE, dport=23))[0] == Action.deny
    # ssh is enabled on outside, but the flow targets the dmz address
    assert verdict(p, "outside:in", flow("203.0.113.9", DMZ, dport=22))[0] == Action.deny
    # same service, own address
    assert verdict(p, "outside:in", flow("203.0.113.9", OUTSIDE, dport=22))[0] == Action.permit


def test_https_needs_the_http_server_and_an_http_line() -> None:
    line = "http 10.1.0.0 255.255.255.0 inside\n"
    https = flow("10.1.0.9", INSIDE, dport=443)
    assert verdict(asa(line), "inside:in", https)[0] == Action.deny
    assert verdict(asa("http server enable\n"), "inside:in", https)[0] == Action.deny
    enabled = asa("http server enable\n" + line)
    assert verdict(enabled, "inside:in", https) == (Action.permit, "mgmt:https", "self")
    assert verdict(enabled, "inside:in", flow("10.1.0.9", INSIDE, dport=80))[0] == Action.deny


def test_snmp_is_admitted_for_the_snmp_server_host_only() -> None:
    p = asa("snmp-server host inside 10.1.0.77 poll\n")
    assert verdict(p, "inside:in", flow("10.1.0.77", INSIDE, 17, 161))[0] == Action.permit
    assert verdict(p, "inside:in", flow("10.1.0.78", INSIDE, 17, 161))[0] == Action.deny
    assert verdict(p, "inside:in", flow("10.1.0.77", INSIDE, 6, 161))[0] == Action.deny


def test_all_icmp_is_admitted_when_there_are_no_icmp_lines() -> None:
    p = asa()
    for icmp_type in (0, 3, 8, 30):
        got = verdict(p, "outside:in", flow("203.0.113.9", OUTSIDE, 1, icmp=icmp_type))
        assert got == (Action.permit, "mgmt:ping", "self")


def test_icmp_lists_are_first_match_with_an_implicit_deny() -> None:
    p = asa(
        "icmp deny host 10.1.0.66 inside\nicmp permit 10.1.0.0 255.255.255.0 inside\n"
        "icmp permit any dmz\n"
    )
    assert verdict(p, "inside:in", flow("10.1.0.66", INSIDE, 1, icmp=8))[0] == Action.deny
    assert verdict(p, "inside:in", flow("10.1.0.67", INSIDE, 1, icmp=8))[0] == Action.permit
    assert verdict(p, "inside:in", flow("10.9.0.1", INSIDE, 1, icmp=8))[0] == Action.deny
    # an interface without icmp lines still admits everything; dmz lists only a permit
    assert verdict(p, "outside:in", flow("203.0.113.9", OUTSIDE, 1, icmp=8))[0] == Action.permit
    assert verdict(p, "dmz:in", flow("203.0.113.9", DMZ, 1, icmp=0))[0] == Action.permit


def test_a_later_icmp_deny_does_not_override_an_earlier_permit() -> None:
    p = asa("icmp permit 10.1.0.0 255.255.255.0 inside\nicmp deny host 10.1.0.66 inside\n")
    assert icmp_sources(p, "inside").contains(ipaddress.IPv4Address("10.1.0.66"))


def test_an_acl_never_admits_traffic_to_the_box() -> None:
    p = asa(
        "access-list IN extended permit ip any any\naccess-group IN in interface outside\n"
        "telnet 10.1.0.0 255.255.255.0 inside\n"
    )
    assert verdict(p, "outside:in", flow("203.0.113.9", OUTSIDE, dport=22))[0] == Action.deny


def test_to_the_box_flows_are_denied_with_no_management_command_at_all() -> None:
    p = asa()
    for dport in (22, 23, 443):
        assert verdict(p, "inside:in", flow("10.1.0.9", INSIDE, dport=dport))[0] == Action.deny


MGMT = (
    "telnet 10.0.0.0 255.0.0.0 inside\nssh 0 0 outside\nhttp server enable\n"
    "http 10.1.0.0 255.255.255.0 inside\nsnmp-server host dmz 172.16.0.9\n"
    "icmp deny host 10.1.0.66 inside\nicmp permit 10.1.0.0 255.255.255.0 inside\n"
)


@given(
    src=st.integers(0, 2**32 - 1),
    proto=st.sampled_from([1, 6, 17, 47]),
    dport=st.sampled_from([22, 23, 80, 161, 443, 0]),
    icmp=st.sampled_from([0, 3, 8, 13, None]),
    target=st.sampled_from([OUTSIDE, INSIDE, DMZ]),
    ctx=st.sampled_from(["outside:in", "inside:in", "dmz:in"]),
)
@pytest.mark.pbt
def test_decide_agrees_with_the_admitted_boxes(
    src: int, proto: int, dport: int, icmp: int | None, target: str, ctx: str
) -> None:
    """decide() permits a flow to the box exactly when a box of its ingress interface holds it."""
    p = asa(MGMT)
    f = Flow(
        src=ipaddress.IPv4Address(src),
        dst=ipaddress.IPv4Address(target),
        proto=proto,
        dst_port=dport if proto in (6, 17) else 0,
        icmp_type=icmp if proto == 1 else None,
    )
    expected = any(box.contains(f) for box in source_boxes(p, ctx.split(":")[0]))
    assert (verdict(p, ctx, f)[0] == Action.permit) == expected


def test_a_config_with_management_lines_proves_equivalent_at_the_ci_budget() -> None:
    """The emitted profiles, the PAN-OS reader and decide() agree on every generated flow."""
    p = asa(MGMT)
    emission = emit_panos(p)
    result = prove(p, emission.text, emission.ledger, budget=2000, seed=11)
    assert result.passed, result.counterexample


def test_the_pix_sample_ledger_only_records_the_unavoidable_ping_widening() -> None:
    from tests.panos_helpers import policy_of

    emission = emit_panos(policy_of("pix-2006-hq.cfg"))
    changed = [
        (e.context, e.old_action, e.new_action)
        for e in emission.ledger
        if e.entry_class.value == "to-the-box" and not e.informational
    ]
    # inside admits telnet from 10.10.0.0/16 only. A profile has one permitted-ip list, so ping
    # (all sources, since the source has no icmp line) is left out instead of opening telnet.
    assert changed == [("inside:in", Action.permit, Action.deny)]


def test_the_emitter_follows_the_source_icmp_list_and_the_http_server_switch() -> None:
    p = asa(
        "icmp deny host 10.1.0.66 inside\nicmp permit 10.1.0.0 255.255.255.0 inside\n"
        "http 10.1.0.0 255.255.255.0 inside\n"
    )
    inside = [
        ln.split("necro-mgmt-inside ", 1)[1]
        for ln in emit_panos(p).lines
        if "necro-mgmt-inside " in ln and "ethernet" not in ln
    ]
    # no http server enable: no https. The ping list is 10.1.0.0/24 minus the denied host.
    assert inside[0] == "ping yes"
    assert "https yes" not in inside
    permitted = [i for i in inside if i.startswith("permitted-ip")][0]
    assert "10.1.0.66/32" not in permitted and "10.1.0.64/31" in permitted
