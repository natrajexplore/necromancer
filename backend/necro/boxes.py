"""Symbolic boxes over flow space, for exact coverage questions (shadowed, redundant, effective).

A rule's Match is a product of sets, but its meaning depends on the protocol: ports and the
``established`` flag only apply to TCP/UDP flows, ICMP types only to ICMP, and every other IP
protocol is matched by address alone (see ``necro.evaluate._flow_matches_rule``). So a Match is
split into at most four *kinds* of box, and each box is a product of ``AddrSet`` / ``PortSet``
dimensions. Subtracting boxes is exact: no sampling, no approximation.

Boxes answer "does anything reach this rule?". The autopsy then confirms the answer with
``decide()`` on a witness flow, because ``decide()`` is the single source of truth for semantics.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from necro.ir import Flow, Match, Rule
from necro.sets import AddrSet, PortSet

KIND_TCP = "tcp"
KIND_UDP = "udp"
KIND_ICMP = "icmp"
KIND_OTHER = "other"

_ICMP_NONE = 256  # stands for "ICMP flow without a type": only a type-less rule matches it
_Dim = AddrSet | PortSet


@dataclass(frozen=True)
class Box:
    """A product of sets for one protocol kind. Dimension order is fixed per kind:

    tcp / udp: src, dst, src port, dst port, established (0/1)
    icmp:      src, dst, ICMP type (0-255, 256 = no type)
    other:     src, dst, IP protocol number
    """

    kind: str
    dims: tuple[_Dim, ...]

    def is_empty(self) -> bool:
        return any(d.is_empty() for d in self.dims)

    def intersect(self, other: Box) -> Box | None:
        if self.kind != other.kind:
            return None
        dims = tuple(_intersect(a, b) for a, b in zip(self.dims, other.dims, strict=True))
        box = Box(self.kind, dims)
        return None if box.is_empty() else box

    def subtract(self, other: Box) -> list[Box]:
        """``self`` minus ``other`` as disjoint boxes (empty list when fully covered)."""
        if self.kind != other.kind or self.intersect(other) is None:
            return [self]
        pieces: list[Box] = []
        prefix: list[_Dim] = []
        for i, (a, b) in enumerate(zip(self.dims, other.dims, strict=True)):
            rest = _subtract(a, b)
            if not rest.is_empty():
                pieces.append(Box(self.kind, (*prefix, rest, *self.dims[i + 1 :])))
            prefix.append(_intersect(a, b))
        return pieces

    def restrict(self, index: int, dim: _Dim) -> Box | None:
        """Intersect one dimension with ``dim``; None when that leaves nothing."""
        dims = list(self.dims)
        dims[index] = _intersect(dims[index], dim)
        box = Box(self.kind, tuple(dims))
        return None if box.is_empty() else box

    def describe(self) -> str:
        """A short human-readable form for ledger entries and reports."""
        src, dst = _addr_text(self.dims[0]), _addr_text(self.dims[1])
        if self.kind in (KIND_TCP, KIND_UDP):
            sport, dport, est = self.dims[2:]
            parts = [f"{self.kind} {src} -> {dst}"]
            if sport != PortSet.any():
                parts.append(f"sport {_spec(sport)}")
            if dport != PortSet.any():
                parts.append(f"dport {_spec(dport)}")
            if est == PortSet([(1, 1)]):
                parts.append("established")
            return " ".join(parts)
        if self.kind == KIND_ICMP:
            types = self.dims[2]
            suffix = "" if types == PortSet([(0, _ICMP_NONE)]) else f" type {_spec(types)}"
            return f"icmp {src} -> {dst}{suffix}"
        return f"ip protocol {_spec(self.dims[2])} {src} -> {dst}"

    def contains(self, flow: Flow) -> bool:
        """Whether ``flow`` lies in this box (used to check boxes against ``decide()``)."""
        values: list[ipaddress.IPv4Address | int] = [flow.src, flow.dst]
        if flow.proto in (6, 17):
            kind = KIND_TCP if flow.proto == 6 else KIND_UDP
            values += [flow.src_port, flow.dst_port, int(flow.established)]
        elif flow.proto == 1:
            kind = KIND_ICMP
            values.append(_ICMP_NONE if flow.icmp_type is None else flow.icmp_type)
        else:
            kind = KIND_OTHER
            values.append(flow.proto)
        return self.kind == kind and all(_has(d, v) for d, v in zip(self.dims, values, strict=True))

    def witnesses(self) -> list[Flow]:
        """Two flows inside the box: every dimension at its lowest and at its highest value."""
        return [self._flow(lowest=True), self._flow(lowest=False)]

    def _flow(self, *, lowest: bool) -> Flow:
        src = ipaddress.IPv4Address(_pick(self.dims[0], lowest))
        dst = ipaddress.IPv4Address(_pick(self.dims[1], lowest))
        if self.kind in (KIND_TCP, KIND_UDP):
            sport, dport, est = (_pick(d, lowest) for d in self.dims[2:])
            return Flow(
                src=src,
                dst=dst,
                proto=6 if self.kind == KIND_TCP else 17,
                src_port=sport,
                dst_port=dport,
                established=bool(est),
            )
        value = _pick(self.dims[2], lowest)
        if self.kind == KIND_ICMP:
            icmp_type = None if value == _ICMP_NONE else value
            return Flow(src=src, dst=dst, proto=1, icmp_type=icmp_type)
        return Flow(src=src, dst=dst, proto=value)


def _spec(ports: _Dim) -> str:
    return ",".join(str(iv.lo) if iv.lo == iv.hi else f"{iv.lo}-{iv.hi}" for iv in ports.intervals)


def _addr_text(dim: _Dim) -> str:
    assert isinstance(dim, AddrSet)
    if dim == AddrSet.any():
        return "any"
    nets = dim.to_networks()
    return str(nets[0]) if len(nets) == 1 else f"{nets[0]} and {len(nets) - 1} more"


def _intersect(a: _Dim, b: _Dim) -> _Dim:
    if isinstance(a, AddrSet) and isinstance(b, AddrSet):
        return a.intersect(b)
    assert isinstance(a, PortSet) and isinstance(b, PortSet)
    return a.intersect(b)


def _subtract(a: _Dim, b: _Dim) -> _Dim:
    if isinstance(a, AddrSet) and isinstance(b, AddrSet):
        return a.subtract(b)
    assert isinstance(a, PortSet) and isinstance(b, PortSet)
    return a.subtract(b)


def _has(dim: _Dim, value: ipaddress.IPv4Address | int) -> bool:
    if isinstance(dim, AddrSet):
        return dim.contains(value)
    assert isinstance(value, int)
    return dim.contains(value)


def _pick(dim: _Dim, lowest: bool) -> int:
    ivs = dim.intervals
    return ivs[0].lo if lowest else ivs[-1].hi


def boxes_of(match: Match) -> list[Box]:
    """Split a Match into protocol-kind boxes (the exact set of flows it matches)."""
    out: list[Box] = []
    est = PortSet([(1, 1)]) if match.established else PortSet([(0, 1)])
    for proto, kind in ((6, KIND_TCP), (17, KIND_UDP)):
        if match.proto in (None, proto):
            out.append(Box(kind, (match.src, match.dst, match.src_ports, match.dst_ports, est)))
    if match.proto in (None, 1):
        types = (
            PortSet([(0, _ICMP_NONE)])
            if match.icmp_types is None
            else PortSet([(t, t) for t in match.icmp_types])
        )
        out.append(Box(KIND_ICMP, (match.src, match.dst, types)))
    if match.proto is None:
        others = PortSet([(0, 255)]).subtract(PortSet([(1, 1), (6, 6), (17, 17)]))
        out.append(Box(KIND_OTHER, (match.src, match.dst, others)))
    elif match.proto not in (1, 6, 17):
        out.append(Box(KIND_OTHER, (match.src, match.dst, PortSet.single(match.proto))))
    return [b for b in out if not b.is_empty()]


def subtract_all(pieces: list[Box], covers: list[Box]) -> list[Box]:
    """``pieces`` minus every box in ``covers``."""
    for cover in covers:
        pieces = [rest for p in pieces for rest in p.subtract(cover)]
        if not pieces:
            break
    return pieces


def effective_regions(rules: list[Rule]) -> list[tuple[Rule, list[Box]]]:
    """Each active rule with the flows that reach it (its boxes minus all earlier rules)."""
    out: list[tuple[Rule, list[Box]]] = []
    earlier: list[Box] = []
    for rule in rules:
        if rule.inactive:
            continue
        mine = boxes_of(rule.match)
        out.append((rule, subtract_all(list(mine), earlier)))
        earlier += mine
    return out


def overlaps(a: list[Box], b: list[Box]) -> bool:
    return any(x.intersect(y) is not None for x in a for y in b)
