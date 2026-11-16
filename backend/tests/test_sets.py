"""Tests for PortSet and AddrSet (task 2.1) — includes PBT P9."""

from __future__ import annotations

import ipaddress

import pytest
from hypothesis import given
from hypothesis import strategies as st

from necro.sets import ADDR_MAX, ADDR_MIN, PORT_MAX, PORT_MIN, AddrSet, PortSet

# ---------------------------------------------------------------------------
# PortSet unit tests
# ---------------------------------------------------------------------------


def test_portset_empty() -> None:
    ps = PortSet()
    assert ps.is_empty()
    assert not ps.contains(0)
    assert not ps.contains(80)


def test_portset_single() -> None:
    ps = PortSet.single(80)
    assert ps.contains(80)
    assert not ps.contains(79)
    assert not ps.contains(81)


def test_portset_any() -> None:
    ps = PortSet.any()
    assert ps.contains(0)
    assert ps.contains(65535)
    assert ps.contains(443)


def test_portset_from_neq() -> None:
    ps = PortSet.from_neq(80)
    assert ps.contains(0)
    assert ps.contains(79)
    assert not ps.contains(80)
    assert ps.contains(81)
    assert ps.contains(65535)
    assert PortSet.from_neq(0).contains(1)
    assert not PortSet.from_neq(0).contains(0)
    assert PortSet.from_neq(65535).contains(65534)
    assert not PortSet.from_neq(65535).contains(65535)


def test_portset_from_lt() -> None:
    ps = PortSet.from_lt(80)
    assert ps.contains(79)
    assert not ps.contains(80)
    assert PortSet.from_lt(0).is_empty()


def test_portset_from_gt() -> None:
    ps = PortSet.from_gt(80)
    assert ps.contains(81)
    assert not ps.contains(80)
    assert PortSet.from_gt(65535).is_empty()


def test_portset_from_range() -> None:
    ps = PortSet.from_range(80, 90)
    assert ps.contains(80)
    assert ps.contains(90)
    assert not ps.contains(79)
    assert not ps.contains(91)


def test_portset_normalization_merges_adjacent() -> None:
    ps = PortSet([(10, 20), (21, 30)])
    assert len(ps.intervals) == 1
    assert ps.intervals[0].lo == 10
    assert ps.intervals[0].hi == 30


def test_portset_normalization_merges_overlapping() -> None:
    ps = PortSet([(10, 25), (20, 30)])
    assert len(ps.intervals) == 1
    assert ps.intervals[0].lo == 10
    assert ps.intervals[0].hi == 30


def test_portset_subtract() -> None:
    ps = PortSet.any().subtract(PortSet.single(80))
    assert not ps.contains(80)
    assert ps.contains(79)
    assert ps.contains(81)


def test_portset_intersect() -> None:
    a = PortSet.from_range(10, 100)
    b = PortSet.from_range(50, 200)
    result = a.intersect(b)
    assert result.contains(50)
    assert result.contains(100)
    assert not result.contains(49)
    assert not result.contains(101)


def test_portset_union() -> None:
    a = PortSet.single(80)
    b = PortSet.single(443)
    result = a.union(b)
    assert result.contains(80)
    assert result.contains(443)
    assert not result.contains(81)


def test_portset_covers() -> None:
    full = PortSet.any()
    partial = PortSet.from_range(80, 443)
    assert full.covers(partial)
    assert not partial.covers(full)
    assert partial.covers(partial)


def test_portset_equality() -> None:
    assert PortSet.from_range(10, 20) == PortSet([(10, 20)])
    assert PortSet.from_range(10, 20) != PortSet.from_range(10, 21)


# ---------------------------------------------------------------------------
# AddrSet unit tests  (use RFC 5737 and RFC 1918 addresses only)
# ---------------------------------------------------------------------------


def test_addrset_empty() -> None:
    s = AddrSet()
    assert s.is_empty()


def test_addrset_from_host() -> None:
    # RFC 5737 documentation range
    s = AddrSet.from_host("192.0.2.1")
    assert s.contains(ipaddress.IPv4Address("192.0.2.1"))
    assert not s.contains(ipaddress.IPv4Address("192.0.2.2"))


def test_addrset_from_network() -> None:
    net = ipaddress.IPv4Network("192.0.2.0/24")
    s = AddrSet.from_network(net)
    assert s.contains(ipaddress.IPv4Address("192.0.2.0"))
    assert s.contains(ipaddress.IPv4Address("192.0.2.255"))
    assert not s.contains(ipaddress.IPv4Address("192.0.3.0"))


def test_addrset_any() -> None:
    s = AddrSet.any()
    assert s.contains(ipaddress.IPv4Address("0.0.0.0"))
    assert s.contains(ipaddress.IPv4Address("255.255.255.255"))


def test_addrset_subtract() -> None:
    full = AddrSet.any()
    host = AddrSet.from_host("10.0.0.1")
    result = full.subtract(host)
    assert not result.contains(ipaddress.IPv4Address("10.0.0.1"))
    assert result.contains(ipaddress.IPv4Address("10.0.0.2"))


def test_addrset_intersect() -> None:
    a = AddrSet.from_network(ipaddress.IPv4Network("10.0.0.0/8"))
    b = AddrSet.from_network(ipaddress.IPv4Network("10.1.0.0/16"))
    result = a.intersect(b)
    assert result.contains(ipaddress.IPv4Address("10.1.0.1"))
    assert not result.contains(ipaddress.IPv4Address("10.2.0.1"))


def test_addrset_union_adjacent() -> None:
    a = AddrSet.from_host("10.0.0.1")
    b = AddrSet.from_host("10.0.0.2")
    result = a.union(b)
    assert len(result.intervals) == 1
    assert result.contains(ipaddress.IPv4Address("10.0.0.1"))
    assert result.contains(ipaddress.IPv4Address("10.0.0.2"))


def test_addrset_covers() -> None:
    full = AddrSet.any()
    partial = AddrSet.from_network(ipaddress.IPv4Network("10.0.0.0/8"))
    assert full.covers(partial)
    assert not partial.covers(full)


def test_addrset_to_networks() -> None:
    net = ipaddress.IPv4Network("192.0.2.0/24")
    s = AddrSet.from_network(net)
    nets = s.to_networks()
    assert len(nets) == 1
    assert nets[0] == net


# ---------------------------------------------------------------------------
# PBT P9: Set algebra laws
# ---------------------------------------------------------------------------

_port_intervals_st = st.lists(
    st.tuples(
        st.integers(min_value=PORT_MIN, max_value=PORT_MAX),
        st.integers(min_value=PORT_MIN, max_value=PORT_MAX),
    ).map(lambda t: (min(t), max(t))),
    min_size=0,
    max_size=5,
)

_port_st = st.integers(min_value=PORT_MIN, max_value=PORT_MAX)


@pytest.mark.pbt
@given(intervals=_port_intervals_st)
def test_pbt_portset_idempotent_union(intervals: list[tuple[int, int]]) -> None:
    """A union A = A (idempotence)."""
    a = PortSet(intervals)
    assert a.union(a) == a


@pytest.mark.pbt
@given(intervals=_port_intervals_st)
def test_pbt_portset_subtract_self_empty(intervals: list[tuple[int, int]]) -> None:
    """A subtract A = empty."""
    a = PortSet(intervals)
    assert a.subtract(a).is_empty()


@pytest.mark.pbt
@given(a_ivs=_port_intervals_st, b_ivs=_port_intervals_st)
def test_pbt_portset_subtract_intersect_disjoint(
    a_ivs: list[tuple[int, int]], b_ivs: list[tuple[int, int]]
) -> None:
    """(A subtract B) intersect B = empty."""
    a = PortSet(a_ivs)
    b = PortSet(b_ivs)
    diff = a.subtract(b)
    assert diff.intersect(b).is_empty()


@pytest.mark.pbt
@given(intervals=_port_intervals_st, port=_port_st)
def test_pbt_portset_contains_iff_intersect_nonempty(
    intervals: list[tuple[int, int]], port: int
) -> None:
    """contains(x) iff intersect({x}) is nonempty."""
    a = PortSet(intervals)
    singleton = PortSet.single(port)
    assert a.contains(port) == (not a.intersect(singleton).is_empty())


@pytest.mark.pbt
@given(intervals=_port_intervals_st)
def test_pbt_portset_normalization_canonical(intervals: list[tuple[int, int]]) -> None:
    """Normalization is canonical: normalize(normalize(x)) == normalize(x)."""
    a = PortSet(intervals)
    b = PortSet([(iv.lo, iv.hi) for iv in a.intervals])
    assert a == b


# AddrSet PBT algebra laws
# Build IPv4 network intervals manually using prefix_len + base_address
_addr_net_st = st.tuples(
    st.integers(min_value=8, max_value=28),
    st.integers(min_value=0, max_value=0xFFFFFFFF),
).map(
    lambda t: (
        int(
            ipaddress.IPv4Network(
                f"{ipaddress.IPv4Address(t[1])}/{t[0]}", strict=False
            ).network_address
        ),
        int(
            ipaddress.IPv4Network(
                f"{ipaddress.IPv4Address(t[1])}/{t[0]}", strict=False
            ).broadcast_address
        ),
    )
)

_addr_intervals_st = st.lists(_addr_net_st, min_size=0, max_size=4)

_addr_st = st.integers(min_value=ADDR_MIN, max_value=ADDR_MAX)


@pytest.mark.pbt
@given(intervals=_addr_intervals_st)
def test_pbt_addrset_idempotent_union(intervals: list[tuple[int, int]]) -> None:
    """A union A = A."""
    a = AddrSet(intervals)
    assert a.union(a) == a


@pytest.mark.pbt
@given(intervals=_addr_intervals_st)
def test_pbt_addrset_subtract_self_empty(intervals: list[tuple[int, int]]) -> None:
    """A subtract A = empty."""
    a = AddrSet(intervals)
    assert a.subtract(a).is_empty()


@pytest.mark.pbt
@given(a_ivs=_addr_intervals_st, b_ivs=_addr_intervals_st)
def test_pbt_addrset_subtract_intersect_disjoint(
    a_ivs: list[tuple[int, int]], b_ivs: list[tuple[int, int]]
) -> None:
    """(A subtract B) intersect B = empty."""
    a = AddrSet(a_ivs)
    b = AddrSet(b_ivs)
    diff = a.subtract(b)
    assert diff.intersect(b).is_empty()


@pytest.mark.pbt
@given(intervals=_addr_intervals_st, addr=_addr_st)
def test_pbt_addrset_contains_iff_intersect_nonempty(
    intervals: list[tuple[int, int]], addr: int
) -> None:
    """contains(x) iff intersect({x}) is nonempty."""
    a = AddrSet(intervals)
    singleton = AddrSet([(addr, addr)])
    assert a.contains(addr) == (not a.intersect(singleton).is_empty())
