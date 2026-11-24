"""Task 8.4: ``BoxIndex`` finds exactly the boxes a full scan would, so autopsy can scale.

The index is an optimisation: it must never change an answer. Every check compares it with the
obvious quadratic code it replaced.
"""

from __future__ import annotations

import ipaddress

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from necro.boxes import Box, BoxIndex, boxes_of, effective_regions, subtract_all
from necro.ir import Action, Match, Policy, Rule
from necro.sets import AddrSet, PortSet
from tests.ir_strategies import ios_policies, pix_asa_policies

_QUICK = settings(
    max_examples=150,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)


def _net(cidr: str) -> AddrSet:
    return AddrSet.from_network(ipaddress.IPv4Network(cidr))


def _rule(name: int, match: Match, action: Action = Action.permit, inactive: bool = False) -> Rule:
    return Rule(id=f"A#{name}", action=action, match=match, inactive=inactive)


def _tcp(src: str, dst: str, port: int | None = None) -> Match:
    ports = PortSet.any() if port is None else PortSet.single(port)
    return Match(proto=6, src=_net(src), dst=_net(dst), dst_ports=ports)


def _scan(
    per_rule: list[list[Box]], query: list[Box], before: int | None, after: int | None
) -> list[tuple[int, Box]]:
    """The obvious answer: try every stored box."""
    out: list[tuple[int, Box]] = []
    for position, boxes in enumerate(per_rule):
        if before is not None and position >= before:
            continue
        if after is not None and position <= after:
            continue
        out += [(position, b) for b in boxes if any(q.intersect(b) is not None for q in query)]
    return out


def _same(a: list[tuple[int, Box]], b: list[tuple[int, Box]]) -> bool:
    return len(a) == len(b) and all(
        x[0] == y[0] and x[1] is y[1] for x, y in zip(a, b, strict=True)
    )


def _old_effective_regions(rules: list[Rule]) -> list[tuple[Rule, list[Box]]]:
    out: list[tuple[Rule, list[Box]]] = []
    earlier: list[Box] = []
    for rule in rules:
        if rule.inactive:
            continue
        mine = boxes_of(rule.match)
        out.append((rule, subtract_all(list(mine), earlier)))
        earlier += mine
    return out


# -- the index ----------------------------------------------------------------------------------


def test_it_finds_overlaps_in_every_protocol_kind_and_nothing_else() -> None:
    src, dst = "10.0.0.0/24", "192.0.2.0/24"
    rules = [
        _tcp(src, dst, 80),
        Match(proto=17, src=_net(src), dst=_net(dst), dst_ports=PortSet.single(80)),
        Match(proto=1, src=_net(src), dst=_net(dst), icmp_types=frozenset({8})),
        Match(proto=47, src=_net(src), dst=_net(dst)),
        _tcp(src, "198.51.100.0/24"),  # elsewhere
        _tcp(src, dst, 81),
    ]
    per_rule = [boxes_of(m) for m in rules]
    index = BoxIndex(per_rule)
    assert [p for p, _ in index.overlapping(boxes_of(rules[0]))] == [0]  # the tcp/80 rule only
    everything = boxes_of(Match(src=_net(src), dst=_net(dst)))
    assert [p for p, _ in index.overlapping(everything)] == [0, 1, 2, 3, 5]
    assert _same(index.overlapping(everything, before=2), _scan(per_rule, everything, 2, None))
    assert [p for p, _ in index.overlapping(everything, after=2)] == [3, 5]
    assert index.overlapping([]) == []


def test_boxes_spanning_many_buckets_and_queries_spanning_many_buckets_are_found() -> None:
    wide = Match(proto=6, src=AddrSet.any(), dst=_net("10.0.0.0/8"))  # spans 256 /16 buckets
    narrow = Match(proto=6, src=AddrSet.any(), dst=_net("10.77.1.0/24"))
    other = Match(proto=6, src=AddrSet.any(), dst=_net("172.16.0.0/16"))
    per_rule = [boxes_of(m) for m in (wide, narrow, other)]
    index = BoxIndex(per_rule)
    assert [p for p, _ in index.overlapping(boxes_of(narrow))] == [0, 1]  # via the wide list
    assert [p for p, _ in index.overlapping(boxes_of(wide))] == [0, 1]  # a query over many buckets
    anywhere = boxes_of(Match(proto=6))
    assert [p for p, _ in index.overlapping(anywhere)] == [0, 1, 2]
    # a box that starts several buckets before the query's first bucket is still found
    low = int(ipaddress.IPv4Address("10.0.0.0"))
    start = Match(proto=6, dst=AddrSet([(low, low + 5 * 2**16)]))
    index = BoxIndex([boxes_of(start)])
    probe = boxes_of(Match(proto=6, dst=_net("10.5.0.0/24")))
    assert [p for p, _ in index.overlapping(probe)] == [0]


def test_a_rule_with_several_boxes_is_reported_once_per_overlapping_box_in_stored_order() -> None:
    both = Match(src=_net("10.0.0.0/24"), dst=_net("192.0.2.0/24"))  # tcp, udp, icmp and other
    per_rule = [boxes_of(both)]
    found = BoxIndex(per_rule).overlapping(boxes_of(both))
    assert [b for _, b in found] == per_rule[0]


@pytest.mark.pbt
@settings(_QUICK)
@given(policy=st.one_of(pix_asa_policies(), ios_policies()), pick=st.data())
def test_the_index_answers_like_a_full_scan_on_generated_acls(
    policy: Policy, pick: st.DataObject
) -> None:
    for rules in policy.acls.values():
        active = [r for r in rules if not r.inactive]
        per_rule = [boxes_of(r.match) for r in active]
        index = BoxIndex(per_rule)
        queries = [boxes_of(r.match) for r in rules] + [boxes_of(Match())]
        for query in queries:
            before = pick.draw(st.one_of(st.none(), st.integers(0, len(active) + 1)))
            after = pick.draw(st.one_of(st.none(), st.integers(-1, len(active))))
            assert _same(
                index.overlapping(query, before=before, after=after),
                _scan(per_rule, query, before, after),
            )


@pytest.mark.pbt
@settings(_QUICK)
@given(policy=st.one_of(pix_asa_policies(), ios_policies()))
def test_effective_regions_equals_the_all_pairs_version_piece_for_piece(policy: Policy) -> None:
    for rules in policy.acls.values():
        old, new = _old_effective_regions(rules), effective_regions(rules)
        assert [r.id for r, _ in old] == [r.id for r, _ in new]
        for (_, a), (_, b) in zip(old, new, strict=True):
            assert a == b  # the same pieces in the same order, not just the same union


def test_inactive_rules_take_no_part_in_the_regions() -> None:
    match = Match(proto=6, dst=_net("192.0.2.0/24"))
    rules = [_rule(1, match, inactive=True), _rule(2, match), _rule(3, match)]
    regions = effective_regions(rules)
    assert [r.id for r, _ in regions] == ["A#2", "A#3"]
    assert regions[0][1] == boxes_of(match) and regions[1][1] == []
