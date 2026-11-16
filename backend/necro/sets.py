"""PortSet and AddrSet: interval algebra over ports and IPv4 addresses.

Each type stores a canonical, sorted, merged list of non-overlapping intervals.
Operations: normalize, contains, intersect, subtract, covers, union.

PBT P9: set algebra laws are verified in tests/test_sets.py.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Internal interval type (ports)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, order=True)
class _Interval:
    lo: int
    hi: int  # inclusive

    def __post_init__(self) -> None:
        if self.lo > self.hi:
            raise ValueError(f"Invalid interval: lo={self.lo} > hi={self.hi}")


def _normalize(intervals: list[_Interval]) -> list[_Interval]:
    """Sort and merge overlapping/adjacent intervals into a canonical list."""
    if not intervals:
        return []
    sorted_ivs = sorted(intervals)
    merged: list[_Interval] = [sorted_ivs[0]]
    for iv in sorted_ivs[1:]:
        last = merged[-1]
        if iv.lo <= last.hi + 1:  # adjacent or overlapping
            if iv.hi > last.hi:
                merged[-1] = _Interval(last.lo, iv.hi)
        else:
            merged.append(iv)
    return merged


# ---------------------------------------------------------------------------
# PortSet
# ---------------------------------------------------------------------------

PORT_MIN = 0
PORT_MAX = 65535


class PortSet:
    """A normalized set of TCP/UDP port numbers in [0, 65535]."""

    __slots__ = ("_intervals",)

    def __init__(self, intervals: list[tuple[int, int]] | None = None) -> None:
        raw: list[_Interval] = []
        for lo, hi in intervals or []:
            clo = max(PORT_MIN, int(lo))
            chi = min(PORT_MAX, int(hi))
            if clo <= chi:
                raw.append(_Interval(clo, chi))
        self._intervals: tuple[_Interval, ...] = tuple(_normalize(raw))

    # ------------------------------------------------------------------
    # Convenience constructors
    # ------------------------------------------------------------------

    @classmethod
    def any(cls) -> PortSet:
        return cls([(PORT_MIN, PORT_MAX)])

    @classmethod
    def single(cls, port: int) -> PortSet:
        return cls([(port, port)])

    @classmethod
    def from_eq(cls, port: int) -> PortSet:
        return cls.single(port)

    @classmethod
    def from_neq(cls, port: int) -> PortSet:
        """neq p = [0, p-1] union [p+1, 65535]."""
        ivs: list[tuple[int, int]] = []
        if port > PORT_MIN:
            ivs.append((PORT_MIN, port - 1))
        if port < PORT_MAX:
            ivs.append((port + 1, PORT_MAX))
        return cls(ivs)

    @classmethod
    def from_lt(cls, port: int) -> PortSet:
        """lt p = [0, p-1] (strict less-than)."""
        if port <= PORT_MIN:
            return cls([])
        return cls([(PORT_MIN, port - 1)])

    @classmethod
    def from_gt(cls, port: int) -> PortSet:
        """gt p = [p+1, 65535] (strict greater-than)."""
        if port >= PORT_MAX:
            return cls([])
        return cls([(port + 1, PORT_MAX)])

    @classmethod
    def from_range(cls, lo: int, hi: int) -> PortSet:
        return cls([(lo, hi)])

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    def contains(self, port: int) -> bool:
        for iv in self._intervals:
            if iv.lo <= port <= iv.hi:
                return True
            if iv.lo > port:
                break
        return False

    def is_empty(self) -> bool:
        return len(self._intervals) == 0

    def union(self, other: PortSet) -> PortSet:
        ps = PortSet.__new__(PortSet)
        ps._intervals = tuple(_normalize(list(self._intervals) + list(other._intervals)))
        return ps

    def intersect(self, other: PortSet) -> PortSet:
        result: list[_Interval] = []
        j = 0
        ivs_b = list(other._intervals)
        for a in self._intervals:
            while j < len(ivs_b) and ivs_b[j].hi < a.lo:
                j += 1
            k = j
            while k < len(ivs_b) and ivs_b[k].lo <= a.hi:
                lo = max(a.lo, ivs_b[k].lo)
                hi = min(a.hi, ivs_b[k].hi)
                if lo <= hi:
                    result.append(_Interval(lo, hi))
                k += 1
        ps = PortSet.__new__(PortSet)
        ps._intervals = tuple(_normalize(result))
        return ps

    def subtract(self, other: PortSet) -> PortSet:
        """Return self minus other."""
        remaining: list[_Interval] = list(self._intervals)
        for sub in other._intervals:
            new_remaining: list[_Interval] = []
            for iv in remaining:
                if sub.hi < iv.lo or sub.lo > iv.hi:
                    new_remaining.append(iv)
                else:
                    if iv.lo < sub.lo:
                        new_remaining.append(_Interval(iv.lo, sub.lo - 1))
                    if iv.hi > sub.hi:
                        new_remaining.append(_Interval(sub.hi + 1, iv.hi))
            remaining = new_remaining
        ps = PortSet.__new__(PortSet)
        ps._intervals = tuple(_normalize(remaining))
        return ps

    def covers(self, other: PortSet) -> bool:
        """Return True if self is a superset of other."""
        return other.subtract(self).is_empty()

    # ------------------------------------------------------------------
    # Dunder helpers
    # ------------------------------------------------------------------

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PortSet):
            return NotImplemented
        return self._intervals == other._intervals

    def __hash__(self) -> int:
        return hash(self._intervals)

    def __repr__(self) -> str:
        return f"PortSet({list(self._intervals)!r})"

    def __bool__(self) -> bool:
        return not self.is_empty()

    @property
    def intervals(self) -> tuple[_Interval, ...]:
        return self._intervals


# ---------------------------------------------------------------------------
# Internal interval type (addresses)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, order=True)
class _AddrInterval:
    lo: int  # integer representation of IPv4 address
    hi: int  # inclusive

    def __post_init__(self) -> None:
        if self.lo > self.hi:
            raise ValueError(f"Invalid addr interval: lo={self.lo} > hi={self.hi}")


def _normalize_addr(intervals: list[_AddrInterval]) -> list[_AddrInterval]:
    if not intervals:
        return []
    sorted_ivs = sorted(intervals)
    merged: list[_AddrInterval] = [sorted_ivs[0]]
    for iv in sorted_ivs[1:]:
        last = merged[-1]
        if iv.lo <= last.hi + 1:
            if iv.hi > last.hi:
                merged[-1] = _AddrInterval(last.lo, iv.hi)
        else:
            merged.append(iv)
    return merged


ADDR_MIN = 0
ADDR_MAX = 0xFFFFFFFF


class AddrSet:
    """A normalized set of IPv4 addresses stored as integer intervals."""

    __slots__ = ("_intervals",)

    def __init__(self, intervals: list[tuple[int, int]] | None = None) -> None:
        raw: list[_AddrInterval] = []
        for lo, hi in intervals or []:
            clo = max(ADDR_MIN, int(lo))
            chi = min(ADDR_MAX, int(hi))
            if clo <= chi:
                raw.append(_AddrInterval(clo, chi))
        self._intervals: tuple[_AddrInterval, ...] = tuple(_normalize_addr(raw))

    # ------------------------------------------------------------------
    # Convenience constructors
    # ------------------------------------------------------------------

    @classmethod
    def any(cls) -> AddrSet:
        return cls([(ADDR_MIN, ADDR_MAX)])

    @classmethod
    def from_network(cls, network: ipaddress.IPv4Network) -> AddrSet:
        lo = int(network.network_address)
        hi = int(network.broadcast_address)
        return cls([(lo, hi)])

    @classmethod
    def from_host(cls, addr: ipaddress.IPv4Address | str) -> AddrSet:
        ip = int(ipaddress.IPv4Address(addr))
        return cls([(ip, ip)])

    @classmethod
    def from_range(
        cls,
        first: ipaddress.IPv4Address | str,
        last: ipaddress.IPv4Address | str,
    ) -> AddrSet:
        lo = int(ipaddress.IPv4Address(first))
        hi = int(ipaddress.IPv4Address(last))
        return cls([(lo, hi)])

    @classmethod
    def from_cidr_list(cls, networks: list[ipaddress.IPv4Network]) -> AddrSet:
        raw: list[tuple[int, int]] = []
        for net in networks:
            raw.append((int(net.network_address), int(net.broadcast_address)))
        return cls(raw)

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    def contains(self, addr: ipaddress.IPv4Address | int) -> bool:
        ip = int(addr) if isinstance(addr, ipaddress.IPv4Address) else int(addr)
        for iv in self._intervals:
            if iv.lo <= ip <= iv.hi:
                return True
            if iv.lo > ip:
                break
        return False

    def is_empty(self) -> bool:
        return len(self._intervals) == 0

    def union(self, other: AddrSet) -> AddrSet:
        s = AddrSet.__new__(AddrSet)
        s._intervals = tuple(_normalize_addr(list(self._intervals) + list(other._intervals)))
        return s

    def intersect(self, other: AddrSet) -> AddrSet:
        result: list[_AddrInterval] = []
        j = 0
        ivs_b = list(other._intervals)
        for a in self._intervals:
            while j < len(ivs_b) and ivs_b[j].hi < a.lo:
                j += 1
            k = j
            while k < len(ivs_b) and ivs_b[k].lo <= a.hi:
                lo = max(a.lo, ivs_b[k].lo)
                hi = min(a.hi, ivs_b[k].hi)
                if lo <= hi:
                    result.append(_AddrInterval(lo, hi))
                k += 1
        s = AddrSet.__new__(AddrSet)
        s._intervals = tuple(_normalize_addr(result))
        return s

    def subtract(self, other: AddrSet) -> AddrSet:
        """Return self minus other."""
        remaining: list[_AddrInterval] = list(self._intervals)
        for sub in other._intervals:
            new_remaining: list[_AddrInterval] = []
            for iv in remaining:
                if sub.hi < iv.lo or sub.lo > iv.hi:
                    new_remaining.append(iv)
                else:
                    if iv.lo < sub.lo:
                        new_remaining.append(_AddrInterval(iv.lo, sub.lo - 1))
                    if iv.hi > sub.hi:
                        new_remaining.append(_AddrInterval(sub.hi + 1, iv.hi))
            remaining = new_remaining
        s = AddrSet.__new__(AddrSet)
        s._intervals = tuple(_normalize_addr(remaining))
        return s

    def covers(self, other: AddrSet) -> bool:
        """Return True if self is a superset of other."""
        return other.subtract(self).is_empty()

    def to_networks(self) -> list[ipaddress.IPv4Network]:
        """Convert back to a list of IPv4Network objects."""
        result: list[ipaddress.IPv4Network] = []
        for iv in self._intervals:
            lo_addr = ipaddress.IPv4Address(iv.lo)
            hi_addr = ipaddress.IPv4Address(iv.hi)
            result.extend(ipaddress.summarize_address_range(lo_addr, hi_addr))
        return result

    # ------------------------------------------------------------------
    # Dunder helpers
    # ------------------------------------------------------------------

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AddrSet):
            return NotImplemented
        return self._intervals == other._intervals

    def __hash__(self) -> int:
        return hash(self._intervals)

    def __repr__(self) -> str:
        return f"AddrSet({list(self._intervals)!r})"

    def __bool__(self) -> bool:
        return not self.is_empty()

    @property
    def intervals(self) -> tuple[_AddrInterval, ...]:
        return self._intervals
