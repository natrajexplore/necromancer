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
from necro.nat import to_panos_space, to_source_space
from necro.oracle_flows import FlowSpace, flow_space, flow_strategy, flows_for, shrink_flow
from necro.parsers.pix_asa import parse_pix_asa
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
        corners=(),
        probes=(),
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


def test_a_mapped_destination_is_un_translated_to_the_real_one_before_the_acl_sees_it() -> None:
    """An ASA 8.3+ un-NATs on the mapped interface, so its ACLs only ever see real addresses."""
    policy = _real_space_policy()
    outside = Context(name="outside:in", interface="outside")
    inside = Context(name="inside:in", interface="inside")
    assert to_source_space(policy, outside, _flow("198.51.100.10")).dst == _addr("10.0.0.2")
    assert to_source_space(policy, inside, _flow("198.51.100.10")).dst == _addr("198.51.100.10")
    real = _flow("10.0.0.2")
    assert to_source_space(policy, outside, real) is real  # already a real address
    # the two translations are inverses for the addresses of the static
    flow = _flow("10.0.0.3")
    assert to_source_space(policy, outside, to_panos_space(policy, outside, flow)) == flow


def test_a_port_static_is_only_un_translated_for_its_protocol_and_mapped_port() -> None:
    outside = Context(name="outside:in", interface="outside")
    policy = _real_space_policy(port_static=True)
    policy.nat_rules[0].mapped_ports = PortSet.single(8080)
    hit = _flow("198.51.100.9", dport=8080)
    assert to_source_space(policy, outside, hit).dst == _addr("10.0.0.1")
    for miss in (_flow("198.51.100.9", dport=80), _flow("198.51.100.9", proto=17, dport=8080)):
        assert to_source_space(policy, outside, miss) is miss


def test_pre_8_3_and_ios_flows_are_already_in_the_space_of_the_source() -> None:
    outside = Context(name="outside:in", interface="outside")
    flow = _flow("198.51.100.10")
    for space, dialect in (
        (AddressSpace.mapped, Dialect.pix),
        (AddressSpace.mapped, Dialect.asa),
        (AddressSpace.as_is, Dialect.ios),
        (AddressSpace.real, Dialect.ios),
    ):
        base = _real_space_policy()
        policy = base.model_copy(update={"address_space": space, "dialect": dialect})
        assert to_source_space(policy, outside, flow) is flow


# -- the probes: every corner moved by one -----------------------------------------------------

_RANGE_ACL = """
interface E0
 nameif outside
 security-level 0
 ip address 192.0.2.1 255.255.255.0
interface E1
 nameif inside
 security-level 100
 ip address 10.1.0.1 255.255.255.0
access-list IN extended permit tcp 10.20.30.0 255.255.255.0 10.1.0.0 255.255.255.0 range 8000 8100
access-list IN extended deny ip any any
access-group IN in interface outside
"""


def _range_space() -> tuple[Policy, Context, FlowSpace]:
    policy = parse_pix_asa(_RANGE_ACL, dialect=Dialect.asa, os_version="8.2(5)")
    ctx = find_context(policy, "outside:in")
    return policy, ctx, flow_space(policy, ctx)


def _fields(flow: Flow) -> tuple[int, ...]:
    return (int(flow.src), int(flow.dst), flow.src_port, flow.dst_port, flow.proto)


def _key(flow: Flow) -> tuple[object, ...]:
    """Everything that makes two flows different (``Flow`` is not hashable)."""
    return tuple(flow.__dict__.values())


def test_probes_step_just_inside_and_just_outside_every_edge_of_a_rule() -> None:
    _policy, _ctx, space = _range_space()
    tcp = [f for f in space.probes if f.proto == 6]
    assert {f.dst_port for f in tcp} >= {7999, 8001, 8099, 8101}  # both edges of 8000-8100
    assert {int(f.src) for f in tcp} >= {
        int(_addr("10.20.29.255")),  # one below the source /24
        int(_addr("10.20.30.1")),
        int(_addr("10.20.30.254")),
        int(_addr("10.20.31.0")),  # one above
    }
    assert {int(f.dst) for f in tcp} >= {int(_addr("10.1.1.0")), int(_addr("10.0.255.255"))}


def test_every_probe_moves_exactly_one_field_of_a_corner_by_exactly_one() -> None:
    for name in SAMPLE_NAMES:
        _policy, _ctx, space = _space(name)
        corners = {_fields(c): c for c in space.corners}
        for probe in space.probes:
            near = [
                c
                for c in corners.values()
                if c.proto == probe.proto
                and sum(a != b for a, b in zip(_fields(c), _fields(probe), strict=True)) == 1
                and sum(abs(a - b) for a, b in zip(_fields(c), _fields(probe), strict=True)) == 1
            ]
            icmp_neighbour = probe.proto == 1 and any(c.proto == 1 for c in corners.values())
            assert near or icmp_neighbour, (name, probe)
        assert space.probes and len(space.probes) == len({_key(p) for p in space.probes})


def test_probes_are_deterministic_and_never_a_corner_itself() -> None:
    _policy, _ctx, first = _range_space()
    _policy, _ctx, second = _range_space()
    assert first.probes == second.probes and first.corners == second.corners
    assert not {_key(c) for c in first.corners} & {_key(p) for p in first.probes}


def test_the_probes_are_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    import necro.oracle_flows as module

    monkeypatch.setattr(module, "_MAX_PROBES", 5)
    _policy, _ctx, space = _range_space()
    assert len(space.probes) == 5


def test_a_context_with_no_rules_has_no_corners_or_probes() -> None:
    _policy, ctx, space = _space("pix-2006-hq.cfg", "inside:in")
    assert ctx.acl_name == "" and space.corners == () and space.probes == ()


def test_random_nudges_start_from_the_corners_not_from_the_special_variants() -> None:
    _policy, _ctx, space = _range_space()
    assert {_key(c) for c in space.corners} <= {_key(w) for w in space.witnesses}
    assert len(space.corners) < len(space.witnesses)


# -- shrinking a flow the sweep found -----------------------------------------------------------


def _big_flow(**changes: object) -> Flow:
    base = Flow(
        src=_addr("203.0.113.77"),
        dst=_addr("10.1.0.200"),
        proto=6,
        src_port=51234,
        dst_port=8101,
        established=True,
    )
    return base.model_copy(update=changes)


def test_shrinking_resets_every_field_the_failure_does_not_need() -> None:
    _policy, _ctx, space = _range_space()
    shrunk = shrink_flow(space, _big_flow(), lambda f: f.dst_port == 8101 and f.proto == 6)
    assert shrunk == Flow(src=_addr("0.0.0.0"), dst=_addr("0.0.0.0"), proto=6, dst_port=8101)


def test_shrinking_keeps_what_the_failure_needs() -> None:
    _policy, _ctx, space = _range_space()

    def needs(f: Flow) -> bool:
        return f.established and int(f.src) >= int(_addr("203.0.113.0")) and f.dst_port >= 8100

    shrunk = shrink_flow(space, _big_flow(), needs)
    assert needs(shrunk) and shrunk.established
    assert int(shrunk.src) <= int(_addr("203.0.113.77")) and shrunk.dst_port <= 8101
    assert shrunk.src_port == 0 and shrunk.dst == _addr("0.0.0.0")


def test_shrinking_never_changes_the_protocol_and_lowers_an_icmp_type_only_if_it_may() -> None:
    _policy, _ctx, space = _range_space()
    echo = Flow(src=_addr("10.1.0.9"), dst=_addr("10.1.0.8"), proto=1, icmp_type=8)
    assert shrink_flow(space, echo, lambda f: f.icmp_type == 8).icmp_type == 8
    assert shrink_flow(space, echo, lambda f: f.proto == 1).icmp_type is None
    other = Flow(src=_addr("10.1.0.9"), dst=_addr("10.1.0.8"), proto=47)
    assert shrink_flow(space, other, lambda f: f.proto == 47).proto == 47


def test_a_flow_that_cannot_be_reduced_is_returned_as_it_is() -> None:
    _policy, _ctx, space = _range_space()
    flow = Flow(src=_addr("0.0.0.0"), dst=_addr("0.0.0.0"), proto=6)
    assert shrink_flow(space, flow, lambda f: True) == flow
    stuck = _big_flow()
    assert shrink_flow(space, stuck, lambda f: f == stuck) == stuck


@pytest.mark.pbt
@settings(_QUICK)
@given(
    src=st.integers(0, 2**32 - 1),
    dst=st.integers(0, 2**32 - 1),
    sport=st.integers(0, 65535),
    dport=st.integers(0, 65535),
    floor=st.integers(0, 65535),
    established=st.booleans(),
)
def test_shrinking_keeps_the_failure_and_never_makes_a_field_larger(
    src: int, dst: int, sport: int, dport: int, floor: int, established: bool
) -> None:
    _policy, _ctx, space = _range_space()
    flow = Flow(
        src=ipaddress.IPv4Address(src),
        dst=ipaddress.IPv4Address(dst),
        proto=6,
        src_port=sport,
        dst_port=dport,
        established=established,
    )

    def fails(f: Flow) -> bool:
        return f.dst_port >= floor and int(f.dst) >= dst // 2

    if not fails(flow):
        return
    shrunk = shrink_flow(space, flow, fails)
    assert fails(shrunk)
    assert int(shrunk.src) <= src and int(shrunk.dst) <= dst
    assert shrunk.src_port <= sport and shrunk.dst_port <= dport
    assert shrunk.established <= established and shrunk.proto == 6
    assert shrink_flow(space, shrunk, fails) == shrunk  # idempotent: nothing is left to reduce
