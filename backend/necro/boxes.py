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
from collections.abc import Callable, Iterable, Sequence
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
    """``pieces`` minus every box in ``covers``.

    Subtraction splits a piece into up to one piece per dimension, so the pieces multiply. Most
    covers miss most pieces, though, and a piece a cover misses is kept as it is: a cheap envelope
    test settles that before ``subtract`` builds anything.
    """
    for cover in covers:
        envelope = _envelope(cover)
        kept: list[Box] = []
        for piece in pieces:
            if piece.kind != cover.kind or _apart(envelope, _envelope(piece)):
                kept.append(piece)
            else:
                kept += piece.subtract(cover)
        pieces = kept
        if not pieces:
            break
    return pieces


def _projections_covered(piece: Box, covers: list[Box]) -> bool:
    """A necessary condition for ``covers`` to cover ``piece``: in every dimension, the union of
    the covers' values must include the piece's. A catch-all rule at the end of an ACL fails it
    at once (no earlier rule reaches every source address), so it is never subtracted piecewise.
    """
    for index, dim in enumerate(piece.dims):
        reach = _union(cover.dims[index] for cover in covers)
        if reach is None or not _covers(reach, dim):
            return False
    return True


def _union(dims: Iterable[_Dim]) -> _Dim | None:
    """The union of many sets of one type, in one sort (pairwise unions would be quadratic)."""
    dims = list(dims)
    if not dims:
        return None
    ranges = [(iv.lo, iv.hi) for dim in dims for iv in dim.intervals]
    return AddrSet(ranges) if isinstance(dims[0], AddrSet) else PortSet(ranges)


def _covers(a: _Dim, b: _Dim) -> bool:
    if isinstance(a, AddrSet) and isinstance(b, AddrSet):
        return a.covers(b)
    assert isinstance(a, PortSet) and isinstance(b, PortSet)
    return a.covers(b)


def covered(pieces: list[Box], covers: list[Box]) -> bool:
    """Whether ``covers`` leave nothing of ``pieces`` (``subtract_all(...) == []``), cheaply.

    The pieces are taken one at a time, depth first, and the answer is ``False`` at the first
    fragment no cover touches. A region that survives (the usual case) is never built in full.
    """
    for piece in pieces:
        if not _projections_covered(piece, [c for c in covers if c.kind == piece.kind]):
            return False  # some dimension of the piece has values no cover reaches at all
    stack = [(piece, 0) for piece in reversed(pieces)]
    envelopes = [_envelope(cover) for cover in covers]
    while stack:
        piece, start = stack.pop()
        envelope = _envelope(piece)
        for at in range(start, len(covers)):
            cover = covers[at]
            touches = cover.kind == piece.kind and not _apart(envelope, envelopes[at])
            if touches and piece.intersect(cover) is not None:
                stack += [(rest, at + 1) for rest in reversed(piece.subtract(cover))]
                break
        else:
            return False
    return True


def effective_regions(
    rules: list[Rule], *, only: Callable[[Rule], bool] | None = None
) -> list[tuple[Rule, list[Box]]]:
    """Each active rule with the flows that reach it (its boxes minus all earlier rules).

    ``only`` limits the result to the rules a caller asks about. The others still count as
    earlier rules, but their own region is never computed, which matters for a catch-all rule
    at the end of a long ACL: its region is everything the ACL does not match, in many pieces.

    Only the earlier boxes that overlap a rule can change its region, so each rule is subtracted
    from just those, found through a ``BoxIndex``. The result is exactly what subtracting every
    earlier box would give, in the same order.
    """
    active = [rule for rule in rules if not rule.inactive]
    boxes = [boxes_of(rule.match) for rule in active]
    index = BoxIndex(boxes)
    return [
        (rule, subtract_all(list(mine), [box for _, box in index.overlapping(mine, before=i)]))
        for i, (rule, mine) in enumerate(zip(active, boxes, strict=True))
        if only is None or only(rule)
    ]


def overlaps(a: list[Box], b: list[Box]) -> bool:
    return any(x.intersect(y) is not None for x in a for y in b)


# -- finding the boxes that overlap a box without trying them all ------------------------------

# Addresses are bucketed by /24. Real ACLs crowd into a few private ranges, so /16 buckets put
# thousands of rules in one bucket; /24 spreads hosts and subnets out. A box spanning up to
# ``_MAX_SPAN`` buckets (a /20) is filed in its first bucket; a wider one is filed by its other
# address, or kept in the wide list.
_BUCKET_SHIFT = 8
_MAX_SPAN = 16
_Envelope = tuple[int, int, int, int, int, int]


def _envelope(box: Box) -> _Envelope:
    """Cheap integer bounds of a box: source, destination, and the dimension that tells rules of
    one protocol apart (destination port, ICMP type or IP protocol). A necessary condition for
    overlap: two boxes whose envelopes are apart cannot intersect."""
    last = box.dims[3] if box.kind in (KIND_TCP, KIND_UDP) else box.dims[2]
    src, dst, key = box.dims[0].intervals, box.dims[1].intervals, last.intervals
    return (src[0].lo, src[-1].hi, dst[0].lo, dst[-1].hi, key[0].lo, key[-1].hi)


def _apart(a: _Envelope, b: _Envelope) -> bool:
    return a[1] < b[0] or b[1] < a[0] or a[3] < b[2] or b[3] < a[2] or a[5] < b[4] or b[5] < a[4]


@dataclass(frozen=True)
class _Entry:
    position: int  # the rule's place in its list
    serial: int  # the box's place among all boxes, in insertion order
    box: Box
    envelope: _Envelope


class _KindIndex:
    """The boxes of one protocol kind, bucketed (by /24) by the address they are narrow in.

    A box narrow in its destination (spanning fewer than ``_MAX_SPAN`` buckets) is filed by
    where its destination starts; failing that, a box narrow in its source is filed by where its
    source starts; a box wide in both (``any`` to ``any``) is kept in ``wide``. A query collects
    from both bucket maps, so every box that can overlap it is found whichever way it was filed.
    """

    def __init__(self) -> None:
        self.by_dst: dict[int, list[_Entry]] = {}
        self.by_src: dict[int, list[_Entry]] = {}
        self.wide: list[_Entry] = []

    def add(self, entry: _Entry) -> None:
        e = entry.envelope
        dst_first, dst_last = e[2] >> _BUCKET_SHIFT, e[3] >> _BUCKET_SHIFT
        src_first, src_last = e[0] >> _BUCKET_SHIFT, e[1] >> _BUCKET_SHIFT
        if dst_last - dst_first < _MAX_SPAN:
            self.by_dst.setdefault(dst_first, []).append(entry)
        elif src_last - src_first < _MAX_SPAN:
            self.by_src.setdefault(src_first, []).append(entry)
        else:
            self.wide.append(entry)

    @staticmethod
    def _collect(buckets: dict[int, list[_Entry]], lo: int, hi: int) -> list[_Entry]:
        """Entries filed in ``buckets`` whose range may meet ``[lo, hi]``. A filed entry starts
        at most ``_MAX_SPAN - 1`` buckets below the first bucket it touches."""
        low = (lo >> _BUCKET_SHIFT) - (_MAX_SPAN - 1)
        high = hi >> _BUCKET_SHIFT
        if high - low + 1 > len(buckets):
            keys: Iterable[int] = [k for k in buckets if low <= k <= high]
        else:
            keys = range(low, high + 1)
        found: list[_Entry] = []
        for key in keys:
            found += buckets.get(key, ())
        return found

    def candidates(self, envelope: _Envelope) -> list[_Entry]:
        """Every entry that can overlap the envelope (each once)."""
        return [
            *self.wide,
            *self._collect(self.by_dst, envelope[2], envelope[3]),
            *self._collect(self.by_src, envelope[0], envelope[1]),
        ]


class BoxIndex:
    """The boxes of a rule list, to ask which of them overlap a box (exactly, not approximately).

    ``boxes[position]`` are the boxes of the rule at ``position``. ``overlapping`` returns the
    stored boxes that intersect any of the given boxes, ordered by position and then as stored,
    optionally only those of rules before or after a position. It tries a stored box only if
    its destination bucket and its envelope allow an overlap, then confirms with ``intersect``,
    so a list of thousands of rules costs roughly what the real overlaps cost.
    """

    def __init__(self, boxes: Sequence[Sequence[Box]]) -> None:
        self._kinds: dict[str, _KindIndex] = {}
        serial = 0
        for position, rule_boxes in enumerate(boxes):
            for box in rule_boxes:
                index = self._kinds.setdefault(box.kind, _KindIndex())
                index.add(_Entry(position, serial, box, _envelope(box)))
                serial += 1

    def overlapping(
        self, boxes: Iterable[Box], *, before: int | None = None, after: int | None = None
    ) -> list[tuple[int, Box]]:
        """``(position, box)`` for every stored box that intersects one of ``boxes``."""
        found: dict[int, _Entry] = {}
        for query in boxes:
            index = self._kinds.get(query.kind)
            if index is None:
                continue
            envelope = _envelope(query)
            for entry in index.candidates(envelope):
                if entry.serial in found:
                    continue
                if before is not None and entry.position >= before:
                    continue
                if after is not None and entry.position <= after:
                    continue
                if _apart(envelope, entry.envelope) or query.intersect(entry.box) is None:
                    continue
                found[entry.serial] = entry
        return [(e.position, e.box) for e in sorted(found.values(), key=lambda e: e.serial)]
