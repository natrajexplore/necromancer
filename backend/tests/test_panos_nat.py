"""Task 6.4: pre-8.3 address space (zone from the real address, nat-control), requirement 4.11."""

from __future__ import annotations

import ipaddress

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from necro.contexts import build_contexts
from necro.emitters import emit_panos
from necro.evaluate import decide
from necro.ir import AddressSpace, Dialect, Flow, LedgerClass, NatRule, NatType, Policy
from necro.nat import NatModel
from necro.parsers.pix_asa import parse_pix_asa
from necro.sets import AddrSet
from tests.ir_strategies import ios_policies, pix_asa_policies
from tests.panos_helpers import address_set, policy_of, rules_of

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
 ip address 10.2.0.1 255.255.255.0
"""
ROUTE = "route outside 0.0.0.0 0.0.0.0 192.0.2.254 1\n"


def asa(text: str, version: str = "8.2(5)") -> Policy:
    return parse_pix_asa(BASE + text + ROUTE, dialect=Dialect.asa, os_version=version)


def net(cidr: str) -> AddrSet:
    return AddrSet.from_network(ipaddress.IPv4Network(cidr))


def host(address: str) -> AddrSet:
    return AddrSet.from_host(address)


def static(mapped: str, real: str, *, mapped_if: str = "outside", real_if: str = "inside") -> str:
    return f"static ({real_if},{mapped_if}) {mapped} {real} netmask 255.255.255.255\n"


def flow(src: str, dst: str, proto: int = 6) -> Flow:
    return Flow(src=ipaddress.IPv4Address(src), dst=ipaddress.IPv4Address(dst), proto=proto)


# -- the translation space and the mapped split -----------------------------------------------


def test_translation_space_is_what_translates_tests() -> None:
    policy = asa(
        "nat (inside) 1 10.1.0.0 255.255.255.0\nglobal (outside) 1 interface\n"
        "nat (dmz) 0 10.2.0.0 255.255.255.0\n" + static("192.0.2.50", "10.1.0.50")
    )
    model = NatModel(policy)
    sources, destinations = model.translation_space("inside")
    assert sources == net("10.1.0.0/24") and destinations == host("10.1.0.50")
    assert model.translation_space("outside") == (AddrSet(), host("192.0.2.50"))
    assert model.translation_space("dmz")[0] == net("10.2.0.0/24")
    assert model.translates("inside", flow("10.1.0.9", "203.0.113.9"))
    assert not model.translates("inside", flow("10.9.0.9", "203.0.113.9"))


def test_split_mapped_pairs_mapped_addresses_with_their_real_addresses() -> None:
    model = NatModel(asa(static("192.0.2.50", "10.1.0.50")))
    both = host("192.0.2.50").union(host("192.0.2.51"))
    split = model.split_mapped("outside", both)
    ((mapped, real, offset),) = split.translated
    assert mapped == host("192.0.2.50") and real == host("10.1.0.50")
    assert offset == int(ipaddress.IPv4Address("10.1.0.50")) - int(
        ipaddress.IPv4Address("192.0.2.50")
    )
    assert split.untouched == host("192.0.2.51") and split.port_dependent.is_empty()
    # a different ingress interface sees no translation
    assert model.split_mapped("dmz", both).untouched == both


def test_a_port_static_makes_the_real_address_depend_on_the_flow() -> None:
    port_static = NatRule(
        nat_type=NatType.static,
        real_interface="inside",
        mapped_interface="outside",
        real_addr=host("10.1.0.50"),
        mapped_addr=host("192.0.2.50"),
        proto=6,
    )
    split = NatModel(Policy(nat_rules=[port_static])).split_mapped("outside", host("192.0.2.50"))
    assert split.port_dependent == host("192.0.2.50") and split.translated == []


@pytest.mark.pbt
@settings(deadline=None)
@given(policy=pix_asa_policies(), probe=st.integers(0, 2**32 - 1))
def test_split_mapped_agrees_with_map_destination(policy: Policy, probe: int) -> None:
    """Where the split says a mapped address maps to X, ``map_destination`` says the same."""
    model = NatModel(policy)
    statics = [r.mapped_addr for r in policy.nat_rules if r.nat_type == NatType.static]
    probes = [probe, *(iv.lo for a in statics for iv in a.intervals)]
    for iface in policy.interfaces:
        for value in probes:
            addr = ipaddress.IPv4Address(value)
            split = model.split_mapped(iface.nameif, AddrSet.from_host(addr))
            # protocol 47 never matches a port static, so only plain statics can translate here
            probe_flow = Flow(src=addr, dst=addr, proto=47)
            mapped_to = model.map_destination(iface.nameif, addr, probe_flow)
            if split.translated:
                ((_, real, _),) = split.translated
                assert real.contains(mapped_to)
            elif split.port_dependent.is_empty():
                assert mapped_to == addr


# -- zones from real addresses ----------------------------------------------------------------


def test_the_asa_sample_keeps_the_mapped_address_and_takes_the_zone_from_the_real_one() -> None:
    emission = emit_panos(policy_of("asa-8.2-branch.cfg"))
    rule = rules_of(emission.lines)["OUTSIDE_IN-7"]  # permit tcp 203.0.113.128/25 host 198.51.100.5
    assert address_set(emission.lines, rule["destination"]) == host("198.51.100.5")
    assert rule["to"] == "inside"  # 198.51.100.5 is the mapped address of 172.16.30.5 (inside)


def test_the_static_becomes_a_destination_nat_rule_from_the_mapped_zone() -> None:
    emission = emit_panos(policy_of("asa-8.2-branch.cfg"))
    prefix = "set rulebase nat rules "
    nat = [ln.removeprefix(prefix) for ln in emission.lines if ln.startswith(prefix)]
    assert nat == [
        "necro-nat-198.51.100.5 from outside",
        "necro-nat-198.51.100.5 to outside",
        "necro-nat-198.51.100.5 source any",
        "necro-nat-198.51.100.5 destination h-198.51.100.5",
        "necro-nat-198.51.100.5 service any",
        "necro-nat-198.51.100.5 destination-translation translated-address 172.16.30.5",
    ]
    assert emission.unsupported == []


def test_identity_statics_need_no_nat_rule() -> None:
    emission = emit_panos(policy_of("pix-2006-hq.cfg"))
    assert not any(" nat rules " in ln for ln in emission.lines)
    assert emission.unsupported == []


def test_one_acl_destination_is_split_where_mapped_and_unmapped_addresses_differ() -> None:
    policy = asa(
        static("192.0.2.50", "10.1.0.50")
        + "access-list A extended permit tcp any 192.0.2.48 255.255.255.240 eq 80\n"
        "access-group A in interface outside\n"
    )
    emission = emit_panos(policy)
    rules = rules_of(emission.lines)
    zone_of = {n: r["to"] for n, r in rules.items() if n.startswith("A-1")}
    dst_of = {n: address_set(emission.lines, rules[n]["destination"]) for n in zone_of}
    assert zone_of == {"A-1-z1": "outside", "A-1-z2": "inside"}
    assert dst_of["A-1-z2"] == host("192.0.2.50")  # the mapped address is kept
    assert dst_of["A-1-z1"] == net("192.0.2.48/28").subtract(host("192.0.2.50"))


def test_a_port_static_blocks_the_verdict_and_leaves_the_zone_open() -> None:
    policy = asa(
        "static (inside,outside) tcp 192.0.2.50 80 10.1.0.50 8080 netmask 255.255.255.255\n"
        "access-list A extended permit tcp any host 192.0.2.50 eq 80\n"
        "access-group A in interface outside\n"
    )
    emission = emit_panos(policy)
    assert rules_of(emission.lines)["A-1"]["to"] == "any"
    assert [u for u in emission.unsupported if u.startswith("Static NAT with port")]


def test_a_subnet_static_with_different_addresses_blocks_the_verdict() -> None:
    policy = asa("static (inside,outside) 192.0.2.64 10.1.0.0 netmask 255.255.255.192\n")
    emission = emit_panos(policy)
    assert [u for u in emission.unsupported if u.startswith("Static NAT of a subnet")]
    assert not any(" nat rules " in ln for ln in emission.lines)


def test_asa_8_3_object_nat_is_flagged_as_phase_2_instead_of_emitted_wrongly() -> None:
    policy = asa(static("192.0.2.50", "10.1.0.50"))
    policy.address_space = AddressSpace.real
    emission = emit_panos(policy)
    assert len(emission.unsupported) == 1 and "8.3+" in emission.unsupported[0]
    assert not any(" nat rules " in ln for ln in emission.lines)
    policy.nat_rules[0].mapped_addr = policy.nat_rules[0].real_addr
    assert emit_panos(policy).unsupported == []


def test_source_nat_is_noted_but_not_emitted() -> None:
    nat = "nat (inside) 1 10.1.0.0 255.255.255.0\nglobal (outside) 1 interface\n"
    emission = emit_panos(asa(nat))
    assert any("source NAT" in n for n in emission.notes)
    assert emission.unsupported == []


# -- nat-control ------------------------------------------------------------------------------

NAT_CONTROL = (
    "nat-control\nnat (inside) 1 10.1.0.0 255.255.255.0\nglobal (outside) 1 interface\n"
    + static("192.0.2.50", "10.1.0.50")
)


def test_nat_control_narrows_permits_to_the_flows_the_source_translates() -> None:
    policy = asa(
        NAT_CONTROL + "access-list A extended permit tcp any any eq 80\n"
        "access-list B extended permit ip any any\n"
        "access-group A in interface outside\naccess-group B in interface inside\n"
    )
    assert policy.nat_control
    emission = emit_panos(policy)
    rules = rules_of(emission.lines)
    lines = emission.lines
    # outside translates only what arrives for the mapped address
    assert address_set(lines, rules["A-1"]["destination"]) == host("192.0.2.50")
    assert rules["A-1"]["to"] == "inside"
    # inside translates sources in 10.1.0.0/24, plus the reverse static for 10.1.0.50
    first, second = rules["B-1-n1"], rules["B-1-n2"]
    assert address_set(lines, first["source"]) == net("10.1.0.0/24")
    assert address_set(lines, first["destination"]) == AddrSet.any()
    assert address_set(lines, second["source"]) == AddrSet.any().subtract(net("10.1.0.0/24"))
    assert address_set(lines, second["destination"]) == host("10.1.0.50")


def test_without_nat_control_the_same_acl_is_emitted_as_written() -> None:
    policy = asa(
        NAT_CONTROL.replace("nat-control\n", "")
        + "access-list A extended permit tcp any any eq 80\naccess-group A in interface outside\n"
    )
    assert not policy.nat_control
    rules = rules_of(emit_panos(policy).lines)
    assert (rules["A-1"]["to"], rules["A-1"]["destination"]) == ("any", "any")


def test_deny_rules_are_never_narrowed() -> None:
    policy = asa(
        NAT_CONTROL + "access-list A extended deny tcp any any eq 23\n"
        "access-list A extended permit ip any any\naccess-group A in interface outside\n"
    )
    rules = rules_of(emit_panos(policy).lines)
    assert (rules["A-1"]["to"], rules["A-1"]["destination"]) == ("any", "any")
    assert rules["A-1"]["action"] == "deny"


def test_a_permit_nothing_can_translate_is_left_out_and_noted() -> None:
    policy = asa(
        "nat-control\naccess-list A extended permit tcp any any eq 80\n"
        "access-group A in interface outside\n"
    )
    emission = emit_panos(policy)
    assert not [n for n in rules_of(emission.lines) if n.startswith("A-1")]
    assert any(note.startswith("A#1") for note in emission.notes)


def test_pix_always_enforces_nat_control_and_the_icmp_rule_follows_the_static() -> None:
    emission = emit_panos(policy_of("pix-2006-hq.cfg"))
    rule = rules_of(emission.lines)["outside_in-6"]  # permit icmp any any echo-reply
    assert address_set(emission.lines, rule["destination"]) == net("192.168.50.0/24")
    assert rule["to"] == "dmz"


def test_implicit_permits_follow_nat_control_too() -> None:
    nat = "nat-control\nnat (inside) 1 10.1.0.0 255.255.255.0\nglobal (outside) 1 interface\n"
    emission = emit_panos(asa(nat))
    rule = rules_of(emission.lines)["implicit-inside-to-outside"]
    assert address_set(emission.lines, rule["source"]) == net("10.1.0.0/24")


def test_ledger_regions_under_nat_control_only_cover_flows_the_source_would_permit() -> None:
    """Entries claim old_action == decide(); untranslated flows decide() denies are not covered."""
    policy = asa(
        NAT_CONTROL
        + "time-range BH\n periodic weekdays 8:00 to 18:00\n"
        + "access-list A extended permit tcp any any eq 80 time-range BH\n"
        + "access-group A in interface outside\n"
    )
    emission = emit_panos(policy)
    contexts = {c.name: c for c in build_contexts(policy)}
    assert LedgerClass.time_range in {e.entry_class for e in emission.ledger}
    for entry in emission.ledger:
        for region in entry.regions:
            for witness in region.witnesses():
                assert decide(policy, contexts[entry.context], witness).action == entry.old_action
    untranslated = Flow(
        src=ipaddress.IPv4Address("203.0.113.9"),
        dst=ipaddress.IPv4Address("192.0.2.77"),
        proto=6,
        dst_port=80,
    )
    assert decide(policy, contexts["outside:in"], untranslated).action.value == "deny"
    assert not [e for e in emission.ledger if e.covers("outside:in", untranslated)]


# -- totality ---------------------------------------------------------------------------------


@pytest.mark.pbt
@settings(deadline=None)
@given(policy=st.one_of(pix_asa_policies(), ios_policies()))
def test_emission_never_raises_and_every_zone_it_names_exists(policy: Policy) -> None:
    emission = emit_panos(policy)
    zones = {ln.split()[2] for ln in emission.lines if ln.startswith("set zone ")} | {"any"}
    for name, attrs in rules_of(emission.lines).items():
        assert attrs["from"] in zones and attrs["to"] in zones, name
