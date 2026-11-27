"""Task 6.3: management profiles, ledger entries and their consistency with decide() (4.3, 4.10)."""

from __future__ import annotations

import ipaddress

import pytest

from necro.contexts import build_contexts, find_context
from necro.emitters import emit_panos
from necro.evaluate import decide
from necro.ir import Action, Dialect, Flow, LedgerClass, MgmtAccess, Policy
from necro.ledger import Approval, LedgerEntry, covering, describe_regions, number_entries
from necro.mgmt import access_services, service_of_flow
from necro.parsers.pix_asa import parse_pix_asa
from necro.sets import AddrSet
from tests.panos_helpers import policy_of

CONFIGS = ["pix-2006-hq.cfg", "asa-8.2-branch.cfg", "ios-12-edge.cfg"]
BASE = """
interface E0
 nameif outside
 security-level 0
 ip address 192.0.2.1 255.255.255.0
interface E1
 nameif inside
 security-level 100
 ip address 10.1.0.1 255.255.255.0
"""
TAIL = "route outside 0.0.0.0 0.0.0.0 192.0.2.254 1\n"


def asa(text: str) -> Policy:
    return parse_pix_asa(BASE + text + TAIL, dialect=Dialect.asa, os_version="8.2(5)")


def flow(src: str, dst: str, proto: int, dport: int = 0, icmp_type: int | None = None) -> Flow:
    return Flow(
        src=ipaddress.IPv4Address(src),
        dst=ipaddress.IPv4Address(dst),
        proto=proto,
        dst_port=dport,
        icmp_type=icmp_type,
    )


def profile_lines(lines: list[str]) -> list[str]:
    return [ln for ln in lines if "interface-management-profile" in ln]


# -- ledger model -----------------------------------------------------------------------------


def test_entries_are_numbered_in_order_and_serialize_with_the_spec_field_names() -> None:
    emission = emit_panos(policy_of("ios-12-edge.cfg"))
    ids = [e.id for e in emission.ledger]
    assert ids == [f"LED-{i:04d}" for i in range(1, len(ids) + 1)]
    dumped = emission.ledger[0].model_dump(mode="json", by_alias=True)
    assert set(dumped) == {
        "id",
        "class",
        "reason",
        "affected",
        "context",
        "old_action",
        "new_action",
        "finding_ref",
        "decision_reason",
        "approval",
        "approver",
        "decided_at",
        "informational",
    }
    assert dumped["approval"] == "pending" and "regions" not in dumped


def test_every_entry_starts_pending_and_has_a_reason() -> None:
    for config in CONFIGS:
        for entry in emit_panos(policy_of(config)).ledger:
            assert entry.approval == Approval.pending and entry.approver == ""
            assert entry.reason and entry.affected and entry.regions


def test_number_entries_does_not_mutate_its_input_and_describe_truncates() -> None:
    entries = emit_panos(policy_of("ios-12-edge.cfg")).ledger
    renumbered = number_entries(list(reversed(entries)))
    assert renumbered[0].id == "LED-0001" and entries[0].id == "LED-0001"
    assert renumbered[0].reason == entries[-1].reason
    assert describe_regions(entries[0].regions, limit=1).endswith("more")


def test_a_context_scoped_entry_does_not_cover_another_context() -> None:
    emission = emit_panos(policy_of("ios-12-edge.cfg"))
    probe = flow("198.51.100.5", "10.20.0.1", 6, dport=23)
    wan = covering(emission.ledger, "FastEthernet0/0:in", probe)
    lan = covering(emission.ledger, "FastEthernet0/1:in", probe)
    assert wan and lan and {e.id for e in wan}.isdisjoint({e.id for e in lan})


@pytest.mark.parametrize("config", CONFIGS)
def test_ledger_claims_about_the_source_match_decide_and_regions_never_contradict(
    config: str,
) -> None:
    """Witness flows of every region: decide() agrees with ``old_action``; entries agree on new."""
    policy = policy_of(config)
    emission = emit_panos(policy)
    contexts = {c.name: c for c in build_contexts(policy)}
    for entry in emission.ledger:
        for region in entry.regions:
            for witness in region.witnesses():
                got = decide(policy, contexts[entry.context], witness)
                assert got.action == entry.old_action, (entry.id, witness)
                others = covering(emission.ledger, entry.context, witness)
                assert {e.new_action for e in others} == {entry.new_action}, (entry.id, witness)


# -- management profiles ----------------------------------------------------------------------


def test_asa_management_commands_become_one_profile_per_interface() -> None:
    policy = asa(
        "telnet 10.1.0.0 255.255.255.0 inside\nssh 10.1.0.0 255.255.255.0 inside\n"
        "http server enable\nhttp 10.1.0.0 255.255.255.0 inside\n"
    )
    emission = emit_panos(policy)
    head = "set network profiles interface-management-profile necro-mgmt-inside"
    outside = "set network profiles interface-management-profile necro-mgmt-outside"
    # no icmp line on outside: all ICMP is admitted. On inside the ping sources (any) are wider
    # than what the other services admit, so ping is enabled for the shared 10.1.0.0/24 only
    # rather than widening telnet to every source.
    assert profile_lines(emission.lines) == [
        f"{outside} ping yes",
        f"{head} telnet yes",
        f"{head} ssh yes",
        f"{head} https yes",  # ASA 'http' is the ASDM HTTPS server
        f"{head} ping yes",
        f'{head} permitted-ip "10.1.0.0/24"',
        "set network interface ethernet ethernet1/1 layer3 interface-management-profile "
        "necro-mgmt-outside",
        "set network interface ethernet ethernet1/2 layer3 interface-management-profile "
        "necro-mgmt-inside",
    ]
    assert emission.unsupported == []


def test_icmp_permit_maps_to_ping_and_any_source_leaves_permitted_ip_open() -> None:
    emission = emit_panos(asa("icmp permit any inside\n"))
    lines = [ln for ln in profile_lines(emission.lines) if "necro-mgmt-inside" in ln]
    assert lines[0].endswith("necro-mgmt-inside ping yes")
    assert not any("permitted-ip" in ln for ln in lines)


def test_traffic_to_the_box_is_compared_with_the_profile_not_the_acl() -> None:
    policy = asa("telnet 10.1.0.0 255.255.255.0 inside\n")
    emission = emit_panos(policy)
    ctx = "inside:in"
    allowed = flow("10.1.0.50", "10.1.0.1", 6, dport=23)
    wrong_port = flow("10.1.0.50", "10.1.0.1", 6, dport=25)
    wrong_source = flow("192.0.2.9", "10.1.0.1", 6, dport=23)
    # decided alike on both sides: no ledger entry, only a note
    for same in (allowed, wrong_port, wrong_source):
        assert covering(emission.ledger, ctx, same) == []
    assert any(n.startswith("inside:in: traffic to the device") and "permit on both" in n
               for n in emission.notes)  # fmt: skip
    assert any(n.startswith("inside:in: traffic to the device") and "deny on both" in n
               for n in emission.notes)  # fmt: skip
    # all ICMP is admitted by the source (no icmp line). Ping from the telnet sources still
    # matches; from any other source it would widen telnet, so it is denied and on the record.
    assert covering(emission.ledger, ctx, flow("10.1.0.50", "10.1.0.1", 1, icmp_type=8)) == []
    entries = covering(emission.ledger, ctx, flow("192.0.2.9", "10.1.0.1", 1, icmp_type=8))
    assert [(e.entry_class, e.old_action, e.new_action, e.informational) for e in entries] == [
        (LedgerClass.to_the_box, Action.permit, Action.deny, False)
    ]


def test_without_any_management_command_only_icmp_is_admitted_to_the_box() -> None:
    emission = emit_panos(asa(""))
    assert [ln.split("necro-mgmt-")[1] for ln in profile_lines(emission.lines)[:2]] == [
        "outside ping yes",
        "inside ping yes",
    ]
    # ssh is denied and ping permitted on both sides, so nothing differs and the ledger is empty
    assert emission.ledger == []
    outside = [n for n in emission.notes if n.startswith("outside:in: traffic to the device")]
    assert len(outside) == 2
    assert any("icmp any -> 192.0.2.1/32" in n and "permit on both" in n for n in outside)
    assert any("deny on both" in n for n in outside)


@pytest.mark.parametrize(
    "name", ["pix-2006-hq.cfg", "asa-8.2-branch.cfg", "asa-9.8-dc.cfg", "ios-12-edge.cfg"]
)
def test_the_ledger_holds_only_to_the_box_flows_whose_decision_changes(name: str) -> None:
    """Flows decided alike on both sides are notes; G5 must not block on them."""
    emission = emit_panos(policy_of(name))
    for entry in emission.ledger:
        if entry.entry_class == LedgerClass.to_the_box:
            assert entry.old_action != entry.new_action and not entry.informational, entry.id


def test_ios_vty_and_snmp_lines_apply_to_every_interface_address() -> None:
    emission = emit_panos(policy_of("ios-12-edge.cfg"))
    lines = profile_lines(emission.lines)
    wan = [ln.split("necro-mgmt-WAN ", 1)[1] for ln in lines if "necro-mgmt-WAN " in ln]
    assert wan == ["telnet yes", "ssh yes", "snmp yes", 'permitted-ip "10.99.0.0/24"']
    assert any(ln.endswith("necro-mgmt-MGMT ssh yes") for ln in lines)


def test_an_ios_rule_that_addresses_only_the_router_opens_its_service_for_that_interface() -> None:
    """110#4 permits telnet from anywhere to the LAN address, so LAN's profile admits any source.

    Only flows that arrive on LAN reach that profile. The WAN flow of 110#4 is no longer admitted
    (no far-interface access), and the ledger records that the source permitted it.
    """
    emission = emit_panos(policy_of("ios-12-edge.cfg"))
    lines = profile_lines(emission.lines)
    assert not any("necro-mgmt-LAN permitted-ip" in ln for ln in lines)
    assert any(ln.endswith("necro-mgmt-LAN telnet yes") for ln in lines)
    golden = flow("198.51.100.5", "10.20.0.1", 6, dport=23)
    entries = covering(emission.ledger, "FastEthernet0/0:in", golden)
    assert [(e.entry_class, e.old_action, e.new_action) for e in entries] == [
        (LedgerClass.to_the_box, Action.permit, Action.deny)
    ]


def test_one_permitted_ip_list_per_profile_widens_other_services_and_the_ledger_says_so() -> None:
    emission = emit_panos(policy_of("ios-12-edge.cfg"))
    # SSH to the LAN address arriving on LAN is denied by the source, but LAN's profile admits
    # ssh from any source because the same profile admits telnet from any source.
    widened = flow("198.51.100.5", "10.20.0.1", 6, dport=22)
    entries = covering(emission.ledger, "FastEthernet0/1:in", widened)
    assert [(e.old_action, e.new_action, e.informational) for e in entries] == [
        (Action.deny, Action.permit, False)
    ]


def test_a_management_service_with_no_profile_equivalent_blocks_the_verdict() -> None:
    policy = asa("")
    policy.mgmt_access.append(
        MgmtAccess(proto="ntp", src_addr=AddrSet.any(), interface="inside", source_line=7)
    )
    emission = emit_panos(policy)
    assert emission.unsupported == [
        "line 7: management access 'ntp' has no PAN-OS interface-management service"
    ]


def test_service_tables() -> None:
    assert access_services(Dialect.asa, "http") == ["https"]
    assert access_services(Dialect.ios, "http") == ["http"]
    assert access_services(Dialect.ios, "vty") == ["telnet", "ssh"]
    assert access_services(Dialect.asa, "icmp") == ["ping"]
    assert access_services(Dialect.asa, "tftp") == []
    assert service_of_flow(flow("10.0.0.1", "10.0.0.2", 6, dport=22)) == "ssh"
    assert service_of_flow(flow("10.0.0.1", "10.0.0.2", 17, dport=161)) == "snmp"
    assert service_of_flow(flow("10.0.0.1", "10.0.0.2", 1, icmp_type=8)) == "ping"
    assert service_of_flow(flow("10.0.0.1", "10.0.0.2", 1, icmp_type=0)) == "ping"
    assert service_of_flow(flow("10.0.0.1", "10.0.0.2", 1)) == "ping"
    assert service_of_flow(flow("10.0.0.1", "10.0.0.2", 47)) is None
    assert service_of_flow(flow("10.0.0.1", "10.0.0.2", 6, dport=25)) is None


# -- the other ledger classes -----------------------------------------------------------------


def test_outbound_acl_widening_is_ledgered_for_the_flows_it_used_to_deny() -> None:
    policy = asa(
        "access-list A extended permit ip any any\n"
        "access-list OUT extended permit tcp any any eq 80\n"
        "access-group A in interface outside\naccess-group OUT out interface inside\n"
    )
    emission = emit_panos(policy)
    ctx = find_context(policy, "outside:in")
    denied_by_out = flow("203.0.113.9", "10.1.0.9", 6, dport=22)
    allowed_by_out = flow("203.0.113.9", "10.1.0.9", 6, dport=80)
    elsewhere = flow("203.0.113.9", "198.51.100.9", 6, dport=22)
    assert decide(policy, ctx, denied_by_out).action == Action.deny
    entries = covering(emission.ledger, "outside:in", denied_by_out)
    assert [(e.entry_class, e.old_action, e.new_action) for e in entries] == [
        (LedgerClass.outbound_acl, Action.deny, Action.permit)
    ]
    assert covering(emission.ledger, "outside:in", allowed_by_out) == []
    assert covering(emission.ledger, "outside:in", elsewhere) == []


def test_destinations_no_route_covers_are_ledgered_as_zone_any() -> None:
    policy = parse_pix_asa(
        BASE + "access-list A extended permit tcp any 172.16.0.0 255.255.0.0 eq 81\n"
        "access-group A in interface outside\n",
        dialect=Dialect.asa,
        os_version="8.2(5)",
    )
    emission = emit_panos(policy)
    inside = flow("203.0.113.9", "172.16.4.4", 6, dport=81)
    (entry,) = covering(emission.ledger, "outside:in", inside)
    assert entry.entry_class == LedgerClass.zone_any and not entry.informational
    assert entry.old_action == entry.new_action == Action.permit


def test_a_time_range_rule_is_ledgered_because_the_schedule_is_not_modelled() -> None:
    policy = asa(
        "time-range BH\n periodic weekdays 8:00 to 18:00\n"
        "access-list A extended permit tcp any any eq 80 time-range BH\n"
        "access-group A in interface outside\n"
    )
    emission = emit_panos(policy)
    probe = flow("203.0.113.9", "10.1.0.9", 6, dport=80)
    (entry,) = [
        e
        for e in covering(emission.ledger, "outside:in", probe)
        if e.entry_class == LedgerClass.time_range
    ]
    assert not entry.informational and "BH" in entry.reason
    assert entry.old_action == entry.new_action == Action.permit


def test_entry_objects_can_be_built_from_the_spec_field_names() -> None:
    entry = LedgerEntry.model_validate(
        {
            "class": "tightening",
            "reason": "r",
            "affected": "a",
            "context": "any",
            "old_action": "permit",
            "new_action": "deny",
        }
    )
    assert entry.entry_class == LedgerClass.tightening
    assert entry.covers("anything", flow("10.0.0.1", "10.0.0.2", 6)) is False  # no regions
