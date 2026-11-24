"""Task 8.1: the boundary-biased flow strategy and the 8.3+ address mapping (requirement 6.1).

The strategy is what makes the oracle find off-by-one bugs, so these tests check the pools it draws
from, the shape of every flow it produces, and that it reaches boundary corners that uniform
random flows essentially never hit.
"""

from __future__ import annotations

import ipaddress
import random

import pytest
from hypothesis import HealthCheck, find, given, settings
from hypothesis import strategies as st

from necro.boxes import effective_regions
from necro.contexts import build_contexts, find_context
from necro.ir import (
    Action,
    AddressSpace,
    Context,
    Dialect,
    Flow,
    Interface,
    Match,
    NatRule,
    NatType,
    Policy,
    Rule,
)
from necro.names import all_icmp_types, all_named_ports
from necro.nat import to_panos_space
from necro.oracle_flows import FlowSpace, flow_space, flow_strategy, flows_for
from necro.sets import AddrSet, PortSet
from tests.panos_helpers import policy_of

SAMPLE_NAMES = ["pix-2006-hq.cfg", "asa-8.2-branch.cfg", "ios-12-edge.cfg"]
_QUICK = settings(
    max_examples=300, deadline=None, suppress_health_check=list(HealthCheck), database=None
)


def _space(name: str, ctx_name: str | None = None) -> tuple[Policy, Context, FlowSpace]:
    policy = policy_of(name)
    ctx = find_context(policy, ctx_name) if ctx_name else build_contexts(policy)[0]
    return policy, ctx, flow_space(policy, ctx)


def _addr(text: str | int) -> ipaddress.IPv4Address:
    return ipaddress.IPv4Address(text)


# -- the pools --------------------------------------------------------------------------------


@pytest.mark.parametrize("name", SAMPLE_NAMES)
def test_every_rule_boundary_is_in_the_pools(name: str) -> None:
    policy, _ctx, space = _space(name)
    addrs = {int(a) for a in space.addrs}
    for rules in policy.acls.values():
        for rule in rules:
            for dim in (rule.match.src, rule.match.dst):
                for iv in dim.intervals:
                    expected = {iv.lo - 1, iv.lo, iv.hi, iv.hi + 1}
                    assert {v for v in expected if 0 <= v <= 0xFFFFFFFF} <= addrs, rule.id
            for ports in (rule.match.src_ports, rule.match.dst_ports):
                for iv in ports.intervals:
                    expected = {iv.lo - 1, iv.lo, iv.hi, iv.hi + 1}
                    assert {v for v in expected if 0 <= v <= 65535} <= set(space.ports), rule.id


@pytest.mark.parametrize("name", SAMPLE_NAMES)
def test_device_nat_and_route_addresses_are_in_the_pools(name: str) -> None:
    policy, _ctx, space = _space(name)
    addrs = set(space.addrs)
    for iface in policy.interfaces:
        if iface.ip_address is not None:
            assert iface.ip_address.ip in addrs
            assert iface.ip_address.network.network_address in addrs
            assert iface.ip_address.network.broadcast_address in addrs
    for nat in policy.nat_rules:
        for side in (nat.real_addr, nat.mapped_addr):
            assert all(_addr(iv.lo) in addrs and _addr(iv.hi) in addrs for iv in side.intervals)
    for route in policy.routes:
        assert route.network.network_address in addrs
    assert _addr("0.0.0.0") in addrs and _addr("255.255.255.255") in addrs


@pytest.mark.parametrize("name", SAMPLE_NAMES)
def test_every_named_icmp_type_every_named_port_and_the_special_protocols_are_drawn(
    name: str,
) -> None:
    _policy, _ctx, space = _space(name)
    assert set(all_icmp_types()) <= set(space.icmp_types)
    assert None in space.icmp_types  # an ICMP flow with no type
    assert set(all_named_ports()) <= set(space.ports)
    assert {1, 6, 17, 47, 50, 88, 89} <= set(space.protocols)
    assert space.protocols[:3] == (6, 17, 1)  # shrinks toward tcp


def test_icmp_neighbours_of_a_rule_type_are_drawn() -> None:
    policy, ctx, _ = _space("ios-12-edge.cfg")
    space = flow_space(policy, ctx)
    rule_types = {
        t for rules in policy.acls.values() for r in rules for t in r.match.icmp_types or ()
    }
    assert rule_types
    for t in rule_types:
        assert {max(t - 1, 0), t, min(t + 1, 255)} <= set(space.icmp_types) - {None}


def test_the_established_flag_is_only_drawn_when_a_rule_uses_it() -> None:
    _, _, ios = _space("ios-12-edge.cfg", "FastEthernet0/0:in")
    _, _, pix = _space("pix-2006-hq.cfg")
    assert ios.uses_established and not pix.uses_established


def test_witnesses_lie_inside_the_region_that_reaches_each_rule() -> None:
    policy, ctx, space = _space("pix-2006-hq.cfg", "outside:in")
    reached = 0
    for rule, pieces in effective_regions(policy.acls[ctx.acl_name]):
        if not pieces:
            continue
        reached += 1
        assert any(any(box.contains(w) for box in pieces) for w in space.witnesses), rule.id
    assert reached >= 5


# -- the strategy -----------------------------------------------------------------------------


@pytest.mark.pbt
@settings(_QUICK)
@given(data=st.data())
def test_every_flow_is_well_formed(data: st.DataObject) -> None:
    name = data.draw(st.sampled_from(SAMPLE_NAMES))
    policy = policy_of(name)
    ctx = data.draw(st.sampled_from(build_contexts(policy)))
    space = flow_space(policy, ctx)
    flow = data.draw(flow_strategy(space))
    assert Flow.model_validate(flow.model_dump()) == flow  # a valid IR flow
    if flow.proto in (6, 17):
        assert flow.icmp_type is None
    elif flow.proto == 1:
        assert flow.src_port == flow.dst_port == 0 and flow.icmp_type in space.icmp_types
    else:
        assert flow.src_port == flow.dst_port == 0 and flow.icmp_type is None
    if flow.established:
        assert flow.proto == 6 and space.uses_established
    assert flow.proto in space.protocols or flow in space.witnesses


def test_most_flows_sit_on_a_boundary_unlike_uniform_random_flows() -> None:
    policy, ctx, space = _space("pix-2006-hq.cfg", "outside:in")
    drawn: list[Flow] = []

    @settings(_QUICK)
    @given(flow=flow_strategy(space))
    def collect(flow: Flow) -> None:
        drawn.append(flow)

    collect()
    biased = sum(space.score(f) >= 2 for f in drawn) / len(drawn)
    rnd = random.Random(0)
    uniform = [
        Flow(
            src=_addr(rnd.getrandbits(32)),
            dst=_addr(rnd.getrandbits(32)),
            proto=6,
            src_port=rnd.randrange(65536),
            dst_port=rnd.randrange(65536),
        )
        for _ in range(len(drawn))
    ]
    assert biased > 0.5
    assert sum(space.score(f) >= 1 for f in uniform) == 0
    assert policy.acls  # the sample really has rules to be biased toward


def test_the_search_steps_just_outside_a_rule_range_inside_its_region() -> None:
    """A destination port one above a rule's range, from an address the rule matches: the probe
    that exposes an off-by-one, which pool sampling alone reaches about once in 100,000 draws."""
    policy, ctx, space = _space("pix-2006-hq.cfg", "outside:in")
    rule = next(
        r for r in policy.acls[ctx.acl_name] if r.match.dst_ports != PortSet.any() and r.match.proto
    )
    port_edge = rule.match.dst_ports.intervals[-1].hi + 1
    found = find(
        flow_strategy(space),
        lambda f: (
            f.proto == rule.match.proto
            and f.dst_port == port_edge
            and rule.match.dst.contains(f.dst)
            and rule.match.src.contains(f.src)
        ),
        settings=settings(max_examples=3000, deadline=None, database=None),
    )
    assert found.dst_port == port_edge


def test_score_counts_boundary_fields() -> None:
    space = FlowSpace(
        addrs=(_addr("10.0.0.0"),),
        boundary_addrs=frozenset({int(_addr("10.0.0.0"))}),
        ports=(80,),
        boundary_ports=frozenset({80}),
        icmp_types=(None, 8),
        boundary_icmp=frozenset({8}),
        protocols=(6,),
        witnesses=(),
        uses_established=False,
    )
    on = Flow(src=_addr("10.0.0.0"), dst=_addr("10.0.0.0"), proto=6, src_port=80, dst_port=80)
    off = Flow(src=_addr("10.0.0.1"), dst=_addr("10.0.0.2"), proto=6, src_port=81, dst_port=82)
    echo = Flow(src=_addr("10.0.0.0"), dst=_addr("10.0.0.2"), proto=1, icmp_type=8)
    other = Flow(src=_addr("10.0.0.0"), dst=_addr("10.0.0.0"), proto=47)
    scores = (space.score(on), space.score(off), space.score(echo), space.score(other))
    assert scores == (4.0, 0.0, 2.0, 2.0)


def test_a_context_with_no_rules_has_no_witnesses_but_still_draws_flows() -> None:
    policy, ctx, space = _space("pix-2006-hq.cfg", "inside:in")
    assert ctx.acl_name == "" and space.witnesses == ()

    @settings(_QUICK)
    @given(flow=flows_for(policy, ctx))
    def draw(flow: Flow) -> None:
        assert flow.proto in space.protocols

    draw()


def test_the_witnesses_are_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("necro.oracle_flows._MAX_WITNESSES", 10)
    rules = [
        Rule(
            id=f"BIG#{i}",
            action=Action.permit,
            match=Match(dst=AddrSet.from_host(_addr(0x0A000000 + i))),
        )
        for i in range(1, 40)
    ]
    policy = Policy(
        dialect=Dialect.pix,
        interfaces=[Interface(nameif="outside", hw_name="e0")],
        acls={"BIG": rules},
    )
    ctx = Context(name="outside:in", interface="outside", acl_name="BIG")
    assert len(flow_space(policy, ctx).witnesses) == 10


# -- 8.3+ address space -----------------------------------------------------------------------


def _real_space_policy(port_static: bool = False) -> Policy:
    nat = NatRule(
        nat_type=NatType.static,
        real_interface="inside",
        mapped_interface="outside",
        real_addr=AddrSet.from_network(ipaddress.IPv4Network("10.0.0.0/30")),
        mapped_addr=AddrSet.from_network(ipaddress.IPv4Network("198.51.100.8/30")),
        proto=6 if port_static else None,
        real_ports=PortSet.single(80) if port_static else PortSet.any(),
    )
    return Policy(
        dialect=Dialect.asa,
        address_space=AddressSpace.real,
        interfaces=[Interface(nameif="outside"), Interface(nameif="inside")],
        nat_rules=[nat],
    )


def _flow(dst: str, proto: int = 6, dport: int = 80) -> Flow:
    return Flow(src=_addr("203.0.113.5"), dst=_addr(dst), proto=proto, dst_port=dport)


def test_8_3_real_destination_becomes_the_mapped_address_on_the_mapped_interface() -> None:
    policy = _real_space_policy()
    outside = Context(name="outside:in", interface="outside")
    inside = Context(name="inside:in", interface="inside")
    assert to_panos_space(policy, outside, _flow("10.0.0.2")).dst == _addr("198.51.100.10")
    assert to_panos_space(policy, inside, _flow("10.0.0.2")).dst == _addr("10.0.0.2")  # elsewhere
    assert to_panos_space(policy, outside, _flow("10.0.0.7")).dst == _addr("10.0.0.7")  # not real


def test_a_port_static_only_maps_its_protocol_and_port() -> None:
    policy = _real_space_policy(port_static=True)
    outside = Context(name="outside:in", interface="outside")
    assert to_panos_space(policy, outside, _flow("10.0.0.1")).dst == _addr("198.51.100.9")
    assert to_panos_space(policy, outside, _flow("10.0.0.1", dport=81)).dst == _addr("10.0.0.1")
    assert to_panos_space(policy, outside, _flow("10.0.0.1", proto=17)).dst == _addr("10.0.0.1")


def test_other_address_spaces_are_never_mapped() -> None:
    outside = Context(name="outside:in", interface="outside")
    flow = _flow("10.0.0.2")
    for space, dialect in (
        (AddressSpace.mapped, Dialect.pix),
        (AddressSpace.mapped, Dialect.asa),
        (AddressSpace.as_is, Dialect.ios),
        (AddressSpace.real, Dialect.ios),
    ):
        base = _real_space_policy()
        policy = base.model_copy(update={"address_space": space, "dialect": dialect})
        assert to_panos_space(policy, outside, flow) is flow


def test_a_static_without_networks_is_ignored() -> None:
    policy = _real_space_policy()
    policy.nat_rules[0].mapped_addr = AddrSet()
    outside = Context(name="outside:in", interface="outside")
    assert to_panos_space(policy, outside, _flow("10.0.0.2")).dst == _addr("10.0.0.2")
