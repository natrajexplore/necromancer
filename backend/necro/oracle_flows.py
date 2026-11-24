"""Boundary-biased flows for the Proof of Life oracle (requirement 6.1, pbt-playbook "Strategies").

A bug in a translated policy lives at the edge of a range: ``range 20 25`` emitted as ``20-26``,
a ``/24`` emitted as a ``/8``, ``lt 80`` emitted as ``gt 80``. Uniform random flows almost never
land on those edges, so the flows are drawn from pools built from the policy itself:

* addresses: network, broadcast, and one below and above, of every rule, interface, route, NAT
  and management address, plus the device's own addresses;
* ports: ``lo-1, lo, hi, hi+1`` of every rule, plus every Cisco-named port;
* ICMP types: every named type plus the types in rules and their neighbours (so a widened
  ``echo-reply`` shows up as type 8);
* protocols: tcp, udp, icmp, every protocol in a rule, and 47, 50, 88, 89.

70% of the addresses and ports come from the pools and 30% are uniform. Two flows in ten are
*witnesses*: flows inside the region that actually reaches a rule, so every reachable rule gets
exercised. Three in ten are a witness with one field moved by one, which steps just across a
range edge or prefix boundary. ``FlowSpace.score`` counts how many fields of a flow sit on a
boundary. The oracle feeds it to ``hypothesis.target()`` so the search climbs toward corners
where several boundaries meet.

The pools are built once per context and every draw is an index into them, which keeps a flow to
about a dozen cheap draws. Pools are sorted, so Hypothesis shrinks toward the lowest values.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass

from hypothesis import strategies as st

from necro.boxes import effective_regions
from necro.ir import Context, Flow, Policy
from necro.names import all_icmp_types, all_named_ports
from necro.sets import AddrSet, PortSet

_MAX_ADDR = 0xFFFFFFFF
_MAX_WITNESSES = 2_000
_EXTRA_PROTOCOLS = (47, 50, 88, 89)
_FIXED_PORTS = (0, 1, 1023, 1024, 65535)
_WITNESS_SHARE = 2  # of 10 draws: a witness as it is
_NEAR_SHARE = 3  # of 10 draws: a witness with one field moved by one
_POOL_SHARE = 7  # of 10 address and port draws come from the pools


@dataclass(frozen=True)
class FlowSpace:
    """The pools one context's flows are drawn from."""

    addrs: tuple[ipaddress.IPv4Address, ...]
    boundary_addrs: frozenset[int]
    ports: tuple[int, ...]
    boundary_ports: frozenset[int]
    icmp_types: tuple[int | None, ...]  # ``None`` is an ICMP flow without a type
    boundary_icmp: frozenset[int]
    protocols: tuple[int, ...]
    witnesses: tuple[Flow, ...]
    uses_established: bool

    def score(self, flow: Flow) -> float:
        """How many fields of ``flow`` sit exactly on a boundary of the policy."""
        hits = int(int(flow.src) in self.boundary_addrs) + int(int(flow.dst) in self.boundary_addrs)
        if flow.proto in (6, 17):
            hits += int(flow.src_port in self.boundary_ports)
            hits += int(flow.dst_port in self.boundary_ports)
        elif flow.proto == 1 and flow.icmp_type in self.boundary_icmp:
            hits += 1
        return float(hits)


def _around(lo: int, hi: int, limit: int) -> Iterable[int]:
    """``lo-1, lo, hi, hi+1`` clamped to ``[0, limit]``."""
    return (v for v in (lo - 1, lo, hi, hi + 1) if 0 <= v <= limit)


def _addr_points(sets: Iterable[AddrSet]) -> set[int]:
    points: set[int] = {0, _MAX_ADDR}
    for addrs in sets:
        for iv in addrs.intervals:
            points.update(_around(iv.lo, iv.hi, _MAX_ADDR))
    return points


def _port_points(sets: Iterable[PortSet]) -> set[int]:
    points: set[int] = set()
    for ports in sets:
        for iv in ports.intervals:
            points.update(_around(iv.lo, iv.hi, 65535))
    return points


def _address_sets(policy: Policy) -> list[AddrSet]:
    """Every address set the policy mentions: rules, interfaces, routes, NAT and management."""
    sets: list[AddrSet] = []
    for rules in policy.acls.values():
        for rule in rules:
            sets += [rule.match.src, rule.match.dst]
    for iface in policy.interfaces:
        if iface.ip_address is not None:
            sets += [
                AddrSet.from_host(iface.ip_address.ip),
                AddrSet.from_network(iface.ip_address.network),
            ]
    sets += [AddrSet.from_network(route.network) for route in policy.routes]
    for nat in policy.nat_rules:
        sets += [nat.real_addr, nat.mapped_addr]
    sets += [access.src_addr for access in policy.mgmt_access]
    return sets


def _witnesses(policy: Policy, ctx: Context, uses_established: bool) -> tuple[Flow, ...]:
    """Flows that reach each rule of the context's ACLs, in rule order, without repeats (capped).

    The ``established`` flag only exists on IOS, so other policies get it cleared.
    """
    flows: dict[tuple[object, ...], Flow] = {}
    for name in (ctx.acl_name, ctx.global_acl_name):
        if not name:
            continue
        for _rule, pieces in effective_regions(policy.acls.get(name, [])):
            for piece in pieces[:2]:
                for flow in piece.witnesses():
                    if flow.established and (flow.proto != 6 or not uses_established):
                        flow = flow.model_copy(update={"established": False})
                    flows.setdefault(tuple(flow.__dict__.values()), flow)
        if len(flows) >= _MAX_WITNESSES:
            break
    return tuple(list(flows.values())[:_MAX_WITNESSES])


def flow_space(policy: Policy, ctx: Context) -> FlowSpace:
    """Build the pools for flows entering ``ctx`` (flows are in the source's address space)."""
    addr_points = _addr_points(_address_sets(policy))
    rule_matches = [r.match for rules in policy.acls.values() for r in rules]
    port_points = _port_points(
        [m.src_ports for m in rule_matches] + [m.dst_ports for m in rule_matches]
    )
    icmp_points = {t for m in rule_matches for t in (m.icmp_types or ())}
    boundary_icmp = {n for t in icmp_points for n in _around(t, t, 255)}
    named_ports = set(all_named_ports()) | set(_FIXED_PORTS)
    protocols = [6, 17, 1]
    for proto in sorted({m.proto for m in rule_matches if m.proto} | set(_EXTRA_PROTOCOLS)):
        if proto not in protocols:
            protocols.append(proto)
    icmp_pool = sorted(set(all_icmp_types()) | boundary_icmp)
    uses_established = any(m.established for m in rule_matches)
    return FlowSpace(
        addrs=tuple(ipaddress.IPv4Address(a) for a in sorted(addr_points)),
        boundary_addrs=frozenset(addr_points),
        ports=tuple(sorted(port_points | named_ports)),
        boundary_ports=frozenset(port_points),
        icmp_types=(None, *icmp_pool),
        boundary_icmp=frozenset(boundary_icmp),
        protocols=tuple(protocols),
        witnesses=_witnesses(policy, ctx, uses_established),
        uses_established=uses_established,
    )


def flow_strategy(space: FlowSpace) -> st.SearchStrategy[Flow]:
    """Hypothesis strategy over the pools of ``space`` (see the module docstring)."""
    share = st.integers(0, 9)
    any_addr = st.integers(0, _MAX_ADDR)
    any_port = st.integers(0, 65535)
    addr_index = st.integers(0, len(space.addrs) - 1)
    port_index = st.integers(0, len(space.ports) - 1)
    proto_index = st.integers(0, len(space.protocols) - 1)
    icmp_index = st.integers(0, len(space.icmp_types) - 1)
    witness_index = st.integers(0, max(len(space.witnesses) - 1, 0))
    field_index = st.integers(0, 3)
    flag = st.booleans()

    @st.composite
    def build(draw: st.DrawFn) -> Flow:
        if space.witnesses:
            mode = draw(share)
            if mode < _WITNESS_SHARE:
                return space.witnesses[draw(witness_index)]
            if mode < _WITNESS_SHARE + _NEAR_SHARE:
                return _nudged(space.witnesses[draw(witness_index)], draw(field_index), draw(flag))
        proto = space.protocols[draw(proto_index)]
        src = _pick_addr(draw, share, addr_index, any_addr, space)
        dst = _pick_addr(draw, share, addr_index, any_addr, space)
        src_port = dst_port = 0
        icmp_type: int | None = None
        established = False
        if proto in (6, 17):
            src_port = _pick_port(draw, share, port_index, any_port, space)
            dst_port = _pick_port(draw, share, port_index, any_port, space)
            established = proto == 6 and space.uses_established and draw(flag)
        elif proto == 1:
            icmp_type = space.icmp_types[draw(icmp_index)]
        return Flow.model_construct(
            src=src,
            dst=dst,
            proto=proto,
            src_port=src_port,
            dst_port=dst_port,
            icmp_type=icmp_type,
            established=established,
        )

    return build()


def _nudged(flow: Flow, field: int, up: bool) -> Flow:
    """``flow`` with one field moved by one: src, dst, source port or destination port.

    A witness sits on a corner of the region that reaches a rule (every field at its lowest or
    highest value), so moving one field by one steps just inside or just outside that region.
    That is exactly the probe that finds an off-by-one in a range or a prefix length. For ICMP
    the last two fields move the ICMP type, and for other protocols they move the destination.
    """
    step = 1 if up else -1
    if field < 2:
        name = "src" if field == 0 else "dst"
        value = int(getattr(flow, name)) + step
        if not 0 <= value <= _MAX_ADDR:
            return flow
        return flow.model_copy(update={name: ipaddress.IPv4Address(value)})
    if flow.proto in (6, 17):
        name = "src_port" if field == 2 else "dst_port"
        value = getattr(flow, name) + step
        return flow if not 0 <= value <= 65535 else flow.model_copy(update={name: value})
    if flow.proto == 1 and flow.icmp_type is not None:
        icmp_type = flow.icmp_type + step
        return (
            flow if not 0 <= icmp_type <= 255 else flow.model_copy(update={"icmp_type": icmp_type})
        )
    value = int(flow.dst) + step
    return flow if not 0 <= value <= _MAX_ADDR else flow.model_copy(update={"dst": _addr(value)})


def _addr(value: int) -> ipaddress.IPv4Address:
    return ipaddress.IPv4Address(value)


def _pick_addr(
    draw: st.DrawFn,
    share: st.SearchStrategy[int],
    index: st.SearchStrategy[int],
    uniform: st.SearchStrategy[int],
    space: FlowSpace,
) -> ipaddress.IPv4Address:
    if draw(share) < _POOL_SHARE:
        return space.addrs[draw(index)]
    return ipaddress.IPv4Address(draw(uniform))


def _pick_port(
    draw: st.DrawFn,
    share: st.SearchStrategy[int],
    index: st.SearchStrategy[int],
    uniform: st.SearchStrategy[int],
    space: FlowSpace,
) -> int:
    if draw(share) < _POOL_SHARE:
        return space.ports[draw(index)]
    return draw(uniform)


def flows_for(policy: Policy, ctx: Context) -> st.SearchStrategy[Flow]:
    """Boundary-biased flows entering ``ctx``, in the source config's address space."""
    return flow_strategy(flow_space(policy, ctx))
