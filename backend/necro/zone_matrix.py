"""The zone-to-zone matrix: which services each zone pair allows, before and after (req. 4.3).

"Before" reads the source policy and "after" reads the PAN-OS candidate as ``panos_reader`` sees
it, so the second matrix is what the emitted text says and not what the emitter intended.

A cell lists the services that the pair allows for *some* source and destination addresses. Both
matrices are computed the same way: the flows that reach each permit rule (its match minus every
earlier rule, exact, from ``boxes.effective_regions``) are split by egress zone and merged per
service. Addresses are left out on purpose, so a cell never claims more precision than it has.
The rule inventory and the equivalence proof carry the exact decisions.

Interfaces with no ACL bound have no rule to read. For those the cell asks ``evaluate.decide`` about
a probe flow, so the security-level and no-ACL behaviour comes from the one source of truth.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from pydantic import BaseModel

from necro.boxes import KIND_ICMP, KIND_OTHER, KIND_TCP, KIND_UDP, Box, effective_regions
from necro.contexts import build_contexts
from necro.emitters.panos_env import ANY_ZONE, BuildEnv
from necro.emitters.panos_network import ZoneMap, device_addresses
from necro.emitters.panos_space import restrict_translated, zone_space
from necro.evaluate import decide
from necro.ir import Action, Context, Dialect, Flow, Policy, Rule
from necro.nat import NatModel
from necro.parsers.panos_reader import RULEBASE, read_panos
from necro.sets import AddrSet, PortSet
from necro.zones import build_route_table

UNRESOLVED = "any (no route)"
PROBE_PORT = 80
_PORTS = PortSet([(0, 65535)])
_ICMP_TYPES = PortSet([(0, 255)])
_OTHER_PROTOCOLS = PortSet([(0, 255)]).subtract(PortSet([(1, 1), (6, 6), (17, 17)]))


class MatrixRow(BaseModel):
    from_zone: str
    to_zone: str
    services: list[str]


class ZoneMatrix(BaseModel):
    """Allowed services per zone pair, in the source order of the zones."""

    rows: list[MatrixRow]
    notes: list[str] = []


def _spec(ports: PortSet) -> str:
    return ",".join(str(iv.lo) if iv.lo == iv.hi else f"{iv.lo}-{iv.hi}" for iv in ports.intervals)


@dataclass
class _Cell:
    """The services one zone pair allows, merged across rules."""

    tcp: PortSet = field(default_factory=PortSet)
    udp: PortSet = field(default_factory=PortSet)
    icmp: PortSet = field(default_factory=PortSet)
    other: PortSet = field(default_factory=PortSet)
    notes: set[str] = field(default_factory=set)

    def add(self, box: Box) -> None:
        if box.kind in (KIND_TCP, KIND_UDP):
            ports = box.dims[3]
            assert isinstance(ports, PortSet)
            if box.kind == KIND_TCP:
                self.tcp = self.tcp.union(ports)
            else:
                self.udp = self.udp.union(ports)
            return
        values = box.dims[2]
        assert isinstance(values, PortSet)
        if box.kind == KIND_ICMP:
            self.icmp = self.icmp.union(values.intersect(_ICMP_TYPES))
        elif box.kind == KIND_OTHER:
            self.other = self.other.union(values)

    def add_everything(self) -> None:
        self.tcp, self.udp, self.icmp, self.other = _PORTS, _PORTS, _ICMP_TYPES, _OTHER_PROTOCOLS

    def services(self) -> list[str]:
        everything = (
            self.tcp.covers(_PORTS)
            and self.udp.covers(_PORTS)
            and self.icmp.covers(_ICMP_TYPES)
            and self.other.covers(_OTHER_PROTOCOLS)
        )
        if everything:
            return ["any"]
        out: list[str] = []
        for name, ports in (("tcp", self.tcp), ("udp", self.udp)):
            if not ports.is_empty():
                out.append(f"{name}/any" if ports.covers(_PORTS) else f"{name}/{_spec(ports)}")
        if not self.icmp.is_empty():
            covers_all = self.icmp.covers(_ICMP_TYPES)
            out.append("icmp (any type)" if covers_all else f"icmp type {_spec(self.icmp)}")
        if not self.other.is_empty():
            covers_all = self.other.covers(_OTHER_PROTOCOLS)
            out.append(
                "other IP protocols (all)" if covers_all else f"ip protocol {_spec(self.other)}"
            )
        return out + sorted(self.notes)


Cells = dict[tuple[str, str], _Cell]


def _cell(cells: Cells, source: str, target: str) -> _Cell:
    return cells.setdefault((source, target), _Cell())


def _ordered(cells: Cells, zone_order: list[str]) -> list[MatrixRow]:
    def rank(zone: str) -> int:
        return zone_order.index(zone) if zone in zone_order else len(zone_order)

    keys = sorted(cells, key=lambda k: (rank(k[0]), k[0], rank(k[1]), k[1]))
    rows = [MatrixRow(from_zone=k[0], to_zone=k[1], services=cells[k].services()) for k in keys]
    return [row for row in rows if row.services]


# -- before: the source policy -----------------------------------------------------------------


def _probe_destinations(policy: Policy) -> list[tuple[str, ipaddress.IPv4Address]]:
    """One host address per interface network that is not an address of the device."""
    owned = {i.ip_address.ip for i in policy.interfaces if i.ip_address is not None}
    found: list[tuple[str, ipaddress.IPv4Address]] = []
    for iface in policy.interfaces:
        if iface.ip_address is None or not iface.nameif:
            continue
        host = next((h for h in iface.ip_address.network.hosts() if h not in owned), None)
        if host is not None:
            found.append((iface.nameif, host))
    return found


def _probe_source(policy: Policy, ctx: Context) -> ipaddress.IPv4Address | None:
    """A host address in the network that the context's interface is attached to."""
    ios = policy.dialect == Dialect.ios
    for iface in policy.interfaces:
        if (iface.hw_name if ios else iface.nameif) == ctx.interface and iface.ip_address:
            owned = iface.ip_address.ip
            return next((h for h in iface.ip_address.network.hosts() if h != owned), None)
    return None


def _implicit(policy: Policy, ctx: Context, from_zone: str, zones: ZoneMap, cells: Cells) -> None:
    """A context with no ACL: ask ``decide`` about a probe flow to each interface network."""
    source = _probe_source(policy, ctx)
    if source is None:
        return
    for nameif, host in _probe_destinations(policy):
        flow = Flow(src=source, dst=host, proto=6, src_port=40000, dst_port=PROBE_PORT)
        decision = decide(policy, ctx, flow)
        if decision.action == Action.permit:
            _cell(cells, from_zone, zones.of_nameif(nameif)).add_everything()


def _acl_rules(policy: Policy, ctx: Context) -> list[Rule]:
    names = [n for n in (ctx.acl_name, ctx.global_acl_name) if n]
    return [rule for name in names for rule in policy.acls.get(name, [])]


def _before_notes(policy: Policy) -> list[str]:
    notes = ["Traffic to the device itself follows the management profile, not this matrix."]
    if policy.dialect in (Dialect.pix, Dialect.asa):
        notes.append(
            "Interfaces without an ACL show every service where the implicit rule permits a probe "
            "flow. Same-security-traffic is not applied to ACL rules here; the equivalence proof "
            "covers exact decisions."
        )
    return notes


def matrix_before(policy: Policy, zones: ZoneMap) -> ZoneMatrix:
    """The zone-to-zone matrix of the source policy (interface ACL, then global ACL).

    Destinations are placed in the zone of their real address (static NAT is followed for
    pre-8.3 sources), and flows that nat-control would drop are left out, as on the device.
    """
    env = BuildEnv(
        policy,
        zones,
        build_route_table(policy),
        device_addresses(policy),
        NatModel(policy),
        nat_control=policy.dialect == Dialect.pix or policy.nat_control,
    )
    cells: Cells = {}
    for ctx in build_contexts(policy):
        from_zone = zones.of_context(policy, ctx)
        if not ctx.acl_name and not ctx.global_acl_name:
            _implicit(policy, ctx, from_zone, zones, cells)
            continue
        ingress = env.ingress(ctx)
        space = zone_space(env, ingress)
        permits = effective_regions(
            _acl_rules(policy, ctx), only=lambda r: r.action == Action.permit
        )
        for _rule, regions in permits:
            for box in restrict_translated(env, ingress, regions):
                dst = box.dims[1]
                assert isinstance(dst, AddrSet)
                for zone, part in space.items():
                    if not dst.intersect(part).is_empty():
                        target = UNRESOLVED if zone == ANY_ZONE else zone
                        _cell(cells, from_zone, target).add(box)
    return ZoneMatrix(rows=_ordered(cells, zones.order), notes=_before_notes(policy))


# -- after: the emitted PAN-OS candidate -------------------------------------------------------


def matrix_after(emitted_text: str) -> ZoneMatrix:
    """The zone-to-zone matrix of an emitted PAN-OS candidate, read back from its text."""
    policy = read_panos(emitted_text)
    rules = policy.acls.get(RULEBASE, [])
    zone_order = [b.interface for b in policy.bindings]
    cells: Cells = {}
    for source in zone_order:
        for target in zone_order:
            applying = [
                r
                for r in rules
                if (not r.from_zones or source in r.from_zones)
                and (not r.to_zones or target in r.to_zones)
            ]
            permits = effective_regions(applying, only=lambda r: r.action == Action.permit)
            for _rule, regions in permits:
                for box in regions:
                    _cell(cells, source, target).add(box)
    return ZoneMatrix(
        rows=_ordered(cells, zone_order),
        notes=["Read back from the emitted set commands. The final deny is not listed."],
    )
