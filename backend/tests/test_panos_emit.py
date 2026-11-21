"""Task 6.1: PAN-OS emitter output: zones, objects, rules in source order, explicit final deny.

These checks read the emitted ``set`` text directly. Behavioural equivalence is proven separately,
through ``panos_reader`` and ``evaluate.decide`` (tasks 6.5, 8.x).
"""

from __future__ import annotations

import ipaddress

import pytest

from necro.emitters import emit_panos
from necro.emitters.panos_names import ZONE_MAX_LEN, is_valid_name
from necro.emitters.panos_objects import ObjectTable, name_list, name_token, port_spec
from necro.parsers import parse_config
from necro.sets import AddrSet, PortSet
from tests.panos_helpers import RULE_PREFIX, address_set, policy_of, rules_of

CONFIGS = ["pix-2006-hq.cfg", "asa-8.2-branch.cfg", "ios-12-edge.cfg"]
_RULE_PREFIX = RULE_PREFIX


# -- objects ----------------------------------------------------------------------------------


def test_any_stays_any_and_hosts_reuse_the_config_alias() -> None:
    table = ObjectTable({"web-srv": "192.0.2.10"})
    assert table.address(AddrSet.any()) == "any"
    assert table.address(AddrSet.from_host("192.0.2.10")) == "web-srv"
    assert table.address(AddrSet.from_host("192.0.2.11")) == "h-192.0.2.11"
    assert table.address_lines() == [
        "set address h-192.0.2.11 ip-netmask 192.0.2.11/32",
        "set address web-srv ip-netmask 192.0.2.10/32",
    ]


def test_two_aliases_for_one_address_pick_the_alphabetically_first() -> None:
    table = ObjectTable({"zeta": "192.0.2.1", "alpha": "192.0.2.1"})
    assert table.address(AddrSet.from_host("192.0.2.1")) == "alpha"


def test_a_set_of_several_networks_becomes_an_address_group() -> None:
    table = ObjectTable()
    two = AddrSet.from_host("192.0.2.1").union(AddrSet.from_host("192.0.2.9"))
    name = table.address(two)
    assert name == table.address(two)  # content-addressed
    assert table.group_lines() == [
        f"set address-group {name} static [ h-192.0.2.1 h-192.0.2.9 ]",
    ]
    assert len(table.address_lines()) == 2


def test_service_objects_carry_destination_and_source_ports() -> None:
    table = ObjectTable()
    web = table.service(6, PortSet.any(), PortSet([(80, 80), (443, 443), (8080, 8090)]))
    dns = table.service(17, PortSet([(1024, 65535)]), PortSet.single(53))
    assert table.service(6, PortSet.any(), PortSet([(80, 80), (443, 443), (8080, 8090)])) == web
    assert table.service_lines() == sorted(
        [
            f"set service {web} protocol tcp port 80,443,8080-8090",
            f"set service {dns} protocol udp port 53 source-port 1024-65535",
        ],
        key=lambda line: line.split()[2],
    )


def test_a_very_long_port_list_gets_a_short_hashed_service_name() -> None:
    table = ObjectTable()
    ports = PortSet([(p, p) for p in range(1000, 1100, 2)])
    name = table.service(6, PortSet.any(), ports)
    assert is_valid_name(name) and len(name) <= 13


def test_neq_is_two_port_ranges() -> None:
    assert port_spec(PortSet.from_neq(22)) == "0-21,23-65535"
    assert port_spec(PortSet.from_lt(1024)) == "0-1023"


def test_names_with_unsafe_characters_are_quoted() -> None:
    assert name_token("outside_in-1") == "outside_in-1"
    assert name_token("src-acl:outside_in") == '"src-acl:outside_in"'
    assert name_token('a"b') == '"a\\"b"'
    assert name_list(["a"]) == "a"
    assert name_list(["a", "src-acl:b"]) == '[ a "src-acl:b" ]'


# -- the emitted candidate --------------------------------------------------------------------


@pytest.mark.parametrize("config", CONFIGS)
def test_zones_come_from_interfaces_with_placeholder_ports(config: str) -> None:
    policy = policy_of(config)
    emission = emit_panos(policy)
    nameifs = [i.nameif for i in policy.interfaces]
    zone_lines = [ln for ln in emission.lines if ln.startswith("set zone ")]
    assert [ln.split()[2] for ln in zone_lines] == nameifs
    assert all(len(ln.split()[2]) <= ZONE_MAX_LEN for ln in zone_lines)
    assert zone_lines[0].endswith("network layer3 ethernet1/1")
    assert any(
        "virtual-router default routing-table ip static-route" in ln for ln in emission.lines
    )


@pytest.mark.parametrize("config", CONFIGS)
def test_every_emitted_name_is_a_valid_identifier(config: str) -> None:
    emission = emit_panos(policy_of(config))
    for line in emission.lines:
        words = line.split()
        if line.startswith("set address ") or line.startswith("set service "):
            assert is_valid_name(words[2]), line
        if line.startswith(_RULE_PREFIX):
            assert is_valid_name(words[4]), line
    assert len(rules_of(emission.lines)) == len(set(rules_of(emission.lines)))


@pytest.mark.parametrize("config", CONFIGS)
def test_baseline_is_port_based_and_never_uses_application_default(config: str) -> None:
    emission = emit_panos(policy_of(config))
    assert "application-default" not in emission.text
    for name, attrs in rules_of(emission.lines).items():
        apps = attrs["application"].replace("[", " ").replace("]", " ").split()
        assert all(a == "any" or a.startswith("necro-") for a in apps), name


@pytest.mark.parametrize("config", CONFIGS)
def test_final_deny_is_last_and_logs(config: str) -> None:
    rules = rules_of(emit_panos(policy_of(config)).lines)
    name, attrs = list(rules.items())[-1]
    assert name == "necro-final-deny"
    assert (attrs["from"], attrs["to"], attrs["source"], attrs["destination"]) == ("any",) * 4
    assert (attrs["service"], attrs["action"]) == ("any", "deny")
    assert attrs["log-start"] == "yes" and attrs["log-end"] == "yes"
    assert attrs["tag"] == '"necro:final-deny"'


@pytest.mark.parametrize("config", CONFIGS)
def test_every_rule_is_tagged_and_every_allow_logs_at_session_end(config: str) -> None:
    for name, attrs in rules_of(emit_panos(policy_of(config)).lines).items():
        assert "tag" in attrs, name
        assert attrs["tag"].startswith(('"src-acl:', '"necro:')), name
        if attrs["action"] == "allow":
            assert attrs["log-end"] == "yes", name


def test_acl_rules_keep_their_source_order_and_blocks_follow_interface_order() -> None:
    policy = policy_of("pix-2006-hq.cfg")
    emission = emit_panos(policy)
    names = list(rules_of(emission.lines))
    outside = [n for n in names if n.startswith("outside_in-")]
    dmz = [n for n in names if n.startswith("dmz_in-")]
    assert outside == sorted(outside, key=lambda n: int(n.rsplit("-", 1)[1]))
    assert dmz == sorted(dmz, key=lambda n: int(n.rsplit("-", 1)[1]))
    assert names.index(outside[-1]) < names.index(dmz[0])  # outside, then inside, then dmz
    sources = emission.rule_sources
    assert sources["outside_in-1"] == "outside_in#1"
    assert sources["necro-final-deny"] == "implicit-deny"


def test_security_level_implicit_permits_become_tagged_allow_rules() -> None:
    rules = rules_of(emit_panos(policy_of("pix-2006-hq.cfg")).lines)
    implicit = {n: a for n, a in rules.items() if a["tag"] == '"necro:implicit"'}
    # inside (100) may reach outside (0) and dmz (50). The PIX has a default route, so no
    # destination is left without a zone and no ``to any`` rule is needed.
    assert {(a["from"], a["to"]) for a in implicit.values()} == {
        ("inside", "outside"),
        ("inside", "dmz"),
    }
    assert all(a["action"] == "allow" for a in implicit.values())


def test_equal_levels_need_same_security_traffic_and_hairpin_needs_intra() -> None:
    base = (
        "interface E0\n nameif a\n security-level 50\n ip address 10.1.0.1 255.255.255.0\n"
        "interface E1\n nameif b\n security-level 50\n ip address 10.2.0.1 255.255.255.0\n"
    )

    def implicit_pairs(text: str) -> set[tuple[str, str]]:
        rules = rules_of(emit_panos(parse_config(text)).lines)
        pairs = {(a["from"], a["to"]) for a in rules.values() if a.get("tag") == '"necro:implicit"'}
        # Destinations with no route count as level 0, so level 50 always reaches "any".
        return {(f, t) for f, t in pairs if t != "any"}

    assert implicit_pairs(base) == set()
    assert implicit_pairs(base + "same-security-traffic permit inter-interface\n") == {
        ("a", "b"),
        ("b", "a"),
    }
    both = base + "same-security-traffic permit inter-interface\n"
    both += "same-security-traffic permit intra-interface\n"
    assert ("a", "a") in implicit_pairs(both)


def test_ios_interface_without_an_acl_gets_an_allow_all_rule() -> None:
    rules = rules_of(emit_panos(policy_of("ios-12-edge.cfg")).lines)
    attrs = rules["implicit-MGMT-to-any"]
    assert (attrs["from"], attrs["to"], attrs["action"]) == ("MGMT", "any", "allow")
    assert attrs["tag"] == '"necro:implicit"'


def test_inactive_rules_are_disabled_and_remarks_become_descriptions() -> None:
    emission = emit_panos(policy_of("asa-8.2-branch.cfg"))
    rules = rules_of(emission.lines)
    disabled = [n for n, a in rules.items() if a.get("disabled") == "yes"]
    assert disabled == ["OUTSIDE_IN-8"]
    assert rules["OUTSIDE_IN-1"]["description"] == '"Partner app tier"'
    assert "description" not in rules["OUTSIDE_IN-2"]


def test_neq_rule_uses_two_port_ranges() -> None:
    emission = emit_panos(policy_of("asa-8.2-branch.cfg"))
    rule = rules_of(emission.lines)["OUTSIDE_IN-6"]
    prefix = f"set service {rule['service']} "
    service_line = next(ln for ln in emission.lines if ln.startswith(prefix))
    assert service_line.endswith("protocol tcp port 0-21,23-65535")


def test_emission_is_plain_set_commands() -> None:
    for config in CONFIGS:
        emission = emit_panos(policy_of(config))
        assert all(line.startswith("set ") for line in emission.lines)
        assert emission.text.endswith("\n") and not emission.text.endswith("\n\n")


def test_implicit_permit_to_unrouted_space_must_not_match_the_real_zones() -> None:
    """A ``to any`` rule matches every zone, so it only covers destinations no route gives."""
    text = (
        "interface E0\n nameif outside\n security-level 0\n ip address 192.0.2.1 255.255.255.0\n"
        "interface E1\n nameif inside\n security-level 100\n ip address 10.1.0.1 255.255.255.0\n"
    )
    emission = emit_panos(parse_config(text))
    rule = rules_of(emission.lines)["implicit-inside-to-any"]
    dst = address_set(emission.lines, rule["destination"])
    assert rule["to"] == "any" and dst != AddrSet.any()
    assert dst.contains(ipaddress.IPv4Address("172.16.0.9"))
    assert not dst.contains(ipaddress.IPv4Address("10.1.0.9"))  # inside: hairpin needs permission
    assert not dst.contains(ipaddress.IPv4Address("192.0.2.9"))
