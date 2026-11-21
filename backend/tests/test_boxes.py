"""Symbolic boxes agree with the evaluator, and subtraction is exact (supports task 5.1)."""

from __future__ import annotations

import ipaddress

import pytest
from hypothesis import given
from hypothesis import strategies as st

from necro.boxes import Box, boxes_of, overlaps, subtract_all
from necro.evaluate import _flow_matches_rule
from necro.ir import Action, Flow, Rule
from necro.ir import Match as IrMatch
from necro.sets import AddrSet, PortSet
from tests.ir_strategies import flows_near, rules


def _rule(match: IrMatch) -> Rule:
    return Rule(id="T#1", action=Action.permit, match=match)


@st.composite
def _pair_and_flows(draw: st.DrawFn) -> tuple[IrMatch, IrMatch, list[Flow]]:
    a = draw(rules("T", 1, ios=draw(st.booleans()))).match
    b = draw(rules("T", 2, ios=draw(st.booleans()))).match
    flows = draw(st.lists(flows_near([a, b]), min_size=10, max_size=25))
    return a, b, flows


@pytest.mark.pbt
@given(_pair_and_flows())
def test_boxes_describe_exactly_the_flows_the_evaluator_matches(
    case: tuple[IrMatch, IrMatch, list[Flow]],
) -> None:
    a, _, flows = case
    boxes = boxes_of(a)
    for flow in flows:
        assert any(b.contains(flow) for b in boxes) == _flow_matches_rule(flow, _rule(a))


@pytest.mark.pbt
@given(_pair_and_flows())
def test_subtraction_is_exact(case: tuple[IrMatch, IrMatch, list[Flow]]) -> None:
    a, b, flows = case
    rest = subtract_all(boxes_of(a), boxes_of(b))
    for flow in flows:
        in_rest = any(piece.contains(flow) for piece in rest)
        expected = _flow_matches_rule(flow, _rule(a)) and not _flow_matches_rule(flow, _rule(b))
        assert in_rest == expected


@pytest.mark.pbt
@given(_pair_and_flows())
def test_subtracted_pieces_are_disjoint(case: tuple[IrMatch, IrMatch, list[Flow]]) -> None:
    a, b, _ = case
    pieces = subtract_all(boxes_of(a), boxes_of(b))
    for i, p in enumerate(pieces):
        for q in pieces[i + 1 :]:
            assert p.intersect(q) is None


@pytest.mark.pbt
@given(rules("T", 1))
def test_witnesses_lie_inside_their_box_and_match_the_rule(rule: Rule) -> None:
    for box in boxes_of(rule.match):
        for flow in box.witnesses():
            assert box.contains(flow)
            assert _flow_matches_rule(flow, rule)


def test_protocol_specific_semantics() -> None:
    est = IrMatch(proto=6, established=True)
    plain = IrMatch(proto=6)
    assert subtract_all(boxes_of(est), boxes_of(plain)) == []
    assert subtract_all(boxes_of(plain), boxes_of(est)) != []  # non-established flows remain
    echo = IrMatch(proto=1, icmp_types=frozenset({8}))
    any_icmp = IrMatch(proto=1)
    assert subtract_all(boxes_of(echo), boxes_of(any_icmp)) == []
    assert subtract_all(boxes_of(any_icmp), boxes_of(echo)) != []
    # an ICMP flow with no type is only matched by a rule that doesn't name types
    typeless = Flow(
        src=ipaddress.IPv4Address("10.0.0.1"), dst=ipaddress.IPv4Address("10.0.0.2"), proto=1
    )
    assert any(b.contains(typeless) for b in boxes_of(any_icmp))
    assert not any(b.contains(typeless) for b in boxes_of(echo))


def test_ip_rule_splits_into_every_protocol_kind() -> None:
    kinds = {b.kind for b in boxes_of(IrMatch())}
    assert kinds == {"tcp", "udp", "icmp", "other"}
    assert {b.kind for b in boxes_of(IrMatch(proto=47))} == {"other"}
    assert boxes_of(IrMatch(src=AddrSet())) == []
    assert boxes_of(IrMatch(proto=6, dst_ports=PortSet([]))) == []


def test_overlap_restrict_and_empty_box_helpers() -> None:
    web = boxes_of(IrMatch(proto=6, dst_ports=PortSet.single(80)))
    ssh = boxes_of(IrMatch(proto=6, dst_ports=PortSet.single(22)))
    assert not overlaps(web, ssh)
    assert overlaps(web, boxes_of(IrMatch(proto=6)))
    assert web[0].restrict(3, PortSet.single(22)) is None
    assert web[0].restrict(3, PortSet.from_range(1, 100)) is not None
    udp = boxes_of(IrMatch(proto=17))[0]
    assert web[0].intersect(udp) is None and web[0].subtract(udp) == [web[0]]
    assert Box("tcp", web[0].dims).is_empty() is False
