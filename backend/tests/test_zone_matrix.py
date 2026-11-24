"""Task 7: the zone-to-zone matrix, before (source) and after (emitted PAN-OS), requirement 4.3."""

from __future__ import annotations

import pytest

from necro.emitters import emit_panos
from necro.ir import Dialect
from necro.parsers import parse_config
from necro.zone_matrix import UNRESOLVED, ZoneMatrix, matrix_after, matrix_before
from tests.gov_helpers import DIALECTS, NAMES, text_of

BASE = """ASA Version 8.2(5)
interface Ethernet0/0
 nameif outside
 security-level 0
 ip address 198.51.100.1 255.255.255.0
interface Ethernet0/1
 nameif inside
 security-level 100
 ip address 10.0.0.1 255.255.255.0
"""
DEFAULT_ROUTE = "route outside 0.0.0.0 0.0.0.0 198.51.100.254\n"
BIND_IN = "access-group IN in interface inside\n"


def matrices(acl_lines: str, *, route: bool = True) -> tuple[ZoneMatrix, ZoneMatrix]:
    policy = parse_config(BASE + acl_lines + (DEFAULT_ROUTE if route else ""), Dialect.asa)
    emission = emit_panos(policy)
    return matrix_before(policy, emission.zones), matrix_after(emission.text)


def rows(matrix: ZoneMatrix) -> list[tuple[str, str, list[str]]]:
    return [(r.from_zone, r.to_zone, r.services) for r in matrix.rows]


def test_services_are_merged_per_zone_pair_in_a_fixed_order() -> None:
    before, after = matrices(
        "access-list IN extended permit tcp 10.0.0.0 255.255.255.0 any eq 443\n"
        "access-list IN extended permit icmp any any echo\n"
        "access-list IN extended permit gre any any\n"
        "access-list IN extended permit udp any any eq 53\n" + BIND_IN
    )
    services = ["tcp/443", "udp/53", "icmp type 8", "ip protocol 47"]
    expected = [("inside", "outside", services), ("inside", "inside", services)]
    assert rows(before) == rows(after) == expected


def test_a_permit_that_an_earlier_rule_shadows_is_not_listed() -> None:
    before, after = matrices(
        "access-list IN extended deny tcp any any eq 443\n"
        "access-list IN extended permit tcp any any eq 443\n" + BIND_IN
    )
    assert rows(before) == rows(after) == []


def test_a_partly_shadowed_permit_keeps_the_part_that_is_reached() -> None:
    before, _ = matrices(
        "access-list IN extended deny tcp any any eq 443\n"
        "access-list IN extended permit tcp any any range 440 445\n" + BIND_IN
    )
    assert {r.services[0] for r in before.rows} == {"tcp/440-442,444-445"}


def test_permit_ip_any_any_is_any() -> None:
    before, after = matrices("access-list IN extended permit ip any any\n" + BIND_IN)
    expected = [("inside", "outside", ["any"]), ("inside", "inside", ["any"])]
    assert rows(before) == rows(after) == expected


def test_destinations_no_route_reaches_are_listed_before_and_become_any_zone_after() -> None:
    before, after = matrices(
        "access-list IN extended permit tcp any any eq 443\n" + BIND_IN, route=False
    )
    assert ("inside", UNRESOLVED, ["tcp/443"]) in rows(before)
    assert all(r.to_zone != UNRESOLVED for r in after.rows)


def test_an_interface_with_no_acl_follows_the_security_levels() -> None:
    policy = parse_config(BASE + DEFAULT_ROUTE, Dialect.asa)
    emission = emit_panos(policy)
    before = rows(matrix_before(policy, emission.zones))
    assert before == [("inside", "outside", ["any"])]  # 100 -> 0 is permitted, 0 -> 100 is not
    assert rows(matrix_after(emission.text)) == before


def test_a_pre_8_3_static_places_the_destination_in_its_real_zone() -> None:
    """The mapped address lies in the outside network; the real host is inside."""
    policy = parse_config(
        BASE + "static (inside,outside) 198.51.100.50 10.0.0.50 netmask 255.255.255.255\n"
        "access-list OUT extended permit tcp any host 198.51.100.50 eq 443\n"
        "access-group OUT in interface outside\n" + DEFAULT_ROUTE,
        Dialect.asa,
    )
    emission = emit_panos(policy)
    pairs = {(r.from_zone, r.to_zone) for r in matrix_before(policy, emission.zones).rows}
    assert ("outside", "inside") in pairs and ("outside", "outside") not in pairs


@pytest.mark.parametrize("name", NAMES)
def test_the_matrices_of_every_sample_agree_apart_from_ledger_covered_zones(name: str) -> None:
    policy = parse_config(text_of(name), Dialect(DIALECTS[name]))
    emission = emit_panos(policy)
    before, after = matrix_before(policy, emission.zones), matrix_after(emission.text)
    old = {(r.from_zone, r.to_zone): r.services for r in before.rows}
    new = {(r.from_zone, r.to_zone): r.services for r in after.rows}
    changed = {pair for pair in old.keys() | new.keys() if old.get(pair) != new.get(pair)}
    if name == "ios-12-edge":
        # the established ACE is omitted on PAN-OS: only WAN -> LAN differs, and the ledger says so
        assert changed == {("WAN", "LAN")}
        assert any(e.entry_class.value == "stateful-established" for e in emission.ledger)
    else:
        assert changed == set(), f"{name}: {sorted(changed)}"


def test_the_before_matrix_of_asa_8_2_has_no_outside_to_outside_row() -> None:
    policy = parse_config(text_of("asa-8.2-branch"), Dialect.asa)
    emission = emit_panos(policy)
    pairs = {(r.from_zone, r.to_zone) for r in matrix_before(policy, emission.zones).rows}
    assert ("outside", "outside") not in pairs and ("outside", "inside") in pairs


def test_notes_say_how_to_read_the_matrix() -> None:
    before, after = matrices("access-list IN extended permit ip any any\n" + BIND_IN)
    assert any("management profile" in n for n in before.notes)
    assert any("same-security-traffic" in n.lower() for n in before.notes)
    assert any("final deny" in n for n in after.notes)
