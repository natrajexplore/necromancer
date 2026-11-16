"""Tests for masks.py (task 2.3) — includes PBT P7."""

from __future__ import annotations

import ipaddress

import pytest
from hypothesis import given
from hypothesis import strategies as st

from necro.masks import (
    NonContiguousMaskError,
    is_contiguous_wildcard,
    parse_addr_subnet,
    parse_addr_wildcard,
    prefix_len_to_subnet,
    prefix_len_to_wildcard,
    subnet_to_prefix_len,
    wildcard_to_prefix_len,
)

# ---------------------------------------------------------------------------
# Unit tests: subnet -> prefix_len
# ---------------------------------------------------------------------------


def test_subnet_to_prefix_len_host() -> None:
    assert subnet_to_prefix_len("255.255.255.255") == 32


def test_subnet_to_prefix_len_24() -> None:
    assert subnet_to_prefix_len("255.255.255.0") == 24


def test_subnet_to_prefix_len_16() -> None:
    assert subnet_to_prefix_len("255.255.0.0") == 16


def test_subnet_to_prefix_len_8() -> None:
    assert subnet_to_prefix_len("255.0.0.0") == 8


def test_subnet_to_prefix_len_any() -> None:
    assert subnet_to_prefix_len("0.0.0.0") == 0


def test_subnet_to_prefix_len_non_contiguous() -> None:
    with pytest.raises(NonContiguousMaskError):
        subnet_to_prefix_len("255.0.255.0")


# ---------------------------------------------------------------------------
# Unit tests: wildcard -> prefix_len
# ---------------------------------------------------------------------------


def test_wildcard_to_prefix_len_host() -> None:
    assert wildcard_to_prefix_len("0.0.0.0") == 32


def test_wildcard_to_prefix_len_24() -> None:
    assert wildcard_to_prefix_len("0.0.0.255") == 24


def test_wildcard_to_prefix_len_16() -> None:
    assert wildcard_to_prefix_len("0.0.255.255") == 16


def test_wildcard_to_prefix_len_any() -> None:
    assert wildcard_to_prefix_len("255.255.255.255") == 0


def test_wildcard_to_prefix_len_non_contiguous() -> None:
    with pytest.raises(NonContiguousMaskError):
        wildcard_to_prefix_len("0.255.0.255")


# ---------------------------------------------------------------------------
# Unit tests: prefix_len -> subnet/wildcard
# ---------------------------------------------------------------------------


def test_prefix_len_to_subnet_24() -> None:
    assert prefix_len_to_subnet(24) == "255.255.255.0"


def test_prefix_len_to_subnet_0() -> None:
    assert prefix_len_to_subnet(0) == "0.0.0.0"


def test_prefix_len_to_subnet_32() -> None:
    assert prefix_len_to_subnet(32) == "255.255.255.255"


def test_prefix_len_to_wildcard_24() -> None:
    assert prefix_len_to_wildcard(24) == "0.0.0.255"


def test_prefix_len_to_wildcard_0() -> None:
    assert prefix_len_to_wildcard(0) == "255.255.255.255"


def test_prefix_len_to_wildcard_32() -> None:
    assert prefix_len_to_wildcard(32) == "0.0.0.0"


def test_prefix_len_invalid() -> None:
    with pytest.raises(ValueError):
        prefix_len_to_subnet(33)
    with pytest.raises(ValueError):
        prefix_len_to_wildcard(-1)


# ---------------------------------------------------------------------------
# Unit tests: parse_addr_* helpers
# ---------------------------------------------------------------------------


def test_parse_addr_subnet() -> None:
    # RFC 5737 documentation range
    net = parse_addr_subnet("192.0.2.0", "255.255.255.0")
    assert net == ipaddress.IPv4Network("192.0.2.0/24")


def test_parse_addr_subnet_non_contiguous() -> None:
    with pytest.raises(NonContiguousMaskError):
        parse_addr_subnet("10.0.0.0", "255.0.255.0")


def test_parse_addr_wildcard() -> None:
    # RFC 1918 range, IOS wildcard style
    net = parse_addr_wildcard("10.0.0.0", "0.255.255.255")
    assert net == ipaddress.IPv4Network("10.0.0.0/8")


def test_parse_addr_wildcard_non_contiguous() -> None:
    with pytest.raises(NonContiguousMaskError):
        parse_addr_wildcard("10.0.0.0", "0.255.0.255")


def test_is_contiguous_wildcard_true() -> None:
    assert is_contiguous_wildcard("0.0.0.255")
    assert is_contiguous_wildcard("0.0.255.255")
    assert is_contiguous_wildcard("0.0.0.0")


def test_is_contiguous_wildcard_false() -> None:
    assert not is_contiguous_wildcard("0.255.0.255")
    assert not is_contiguous_wildcard("1.0.0.1")


# ---------------------------------------------------------------------------
# PBT P7: subnet <-> wildcard conversion is a bijection on contiguous masks;
#          non-contiguous masks are rejected.
# ---------------------------------------------------------------------------

_prefix_len_st = st.integers(min_value=0, max_value=32)


@pytest.mark.pbt
@given(prefix_len=_prefix_len_st)
def test_pbt_subnet_roundtrip(prefix_len: int) -> None:
    """prefix_len -> subnet -> prefix_len is identity for all valid prefix lengths."""
    subnet_str = prefix_len_to_subnet(prefix_len)
    result = subnet_to_prefix_len(subnet_str)
    assert result == prefix_len


@pytest.mark.pbt
@given(prefix_len=_prefix_len_st)
def test_pbt_wildcard_roundtrip(prefix_len: int) -> None:
    """prefix_len -> wildcard -> prefix_len is identity for all valid prefix lengths."""
    wildcard_str = prefix_len_to_wildcard(prefix_len)
    result = wildcard_to_prefix_len(wildcard_str)
    assert result == prefix_len


@pytest.mark.pbt
@given(prefix_len=_prefix_len_st)
def test_pbt_subnet_wildcard_complement(prefix_len: int) -> None:
    """Subnet and wildcard for the same prefix are bitwise complements."""
    subnet_int = int(ipaddress.IPv4Address(prefix_len_to_subnet(prefix_len)))
    wildcard_int = int(ipaddress.IPv4Address(prefix_len_to_wildcard(prefix_len)))
    assert (subnet_int ^ wildcard_int) == 0xFFFFFFFF


@pytest.mark.pbt
@given(
    octets=st.tuples(
        st.integers(0, 255),
        st.integers(0, 255),
        st.integers(0, 255),
        st.integers(0, 255),
    )
)
def test_pbt_non_contiguous_masks_rejected(octets: tuple[int, int, int, int]) -> None:
    """Non-contiguous wildcard masks are always rejected; contiguous ones always succeed."""
    wc_int = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
    subnet_int = wc_int ^ 0xFFFFFFFF

    bit_str = f"{subnet_int:032b}"
    stripped = bit_str.lstrip("1")
    expected_prefix = 32 - len(stripped)
    is_contiguous = "1" not in stripped

    wc_str = str(ipaddress.IPv4Address(wc_int))
    if is_contiguous:
        result = wildcard_to_prefix_len(wc_str)
        assert result == expected_prefix
    else:
        with pytest.raises(NonContiguousMaskError):
            wildcard_to_prefix_len(wc_str)
