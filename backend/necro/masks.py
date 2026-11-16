"""Subnet mask and wildcard mask conversions.

PIX/ASA use subnet masks (255.255.255.0).
IOS uses wildcard masks (0.0.0.255).

A contiguous mask (either style) can be unambiguously converted to a prefix length.
A non-contiguous wildcard is a security-relevant unparsed line in v1.

PBT P7: subnet <-> wildcard conversion is a bijection on contiguous masks;
         non-contiguous masks are rejected.
"""

from __future__ import annotations

import ipaddress


class NonContiguousMaskError(ValueError):
    """Raised when a wildcard mask is non-contiguous (cannot map to a prefix length)."""


def wildcard_to_prefix_len(wildcard: str) -> int:
    """Convert an IOS wildcard mask string to a prefix length.

    Example: "0.0.0.255" -> 24

    Raises NonContiguousMaskError for non-contiguous wildcards.
    Raises ValueError for addresses that are not valid IPv4.
    """
    wc = ipaddress.IPv4Address(wildcard)
    wc_int = int(wc)
    # Flip bits to get what would be a subnet mask
    subnet_int = wc_int ^ 0xFFFFFFFF
    return _subnet_int_to_prefix_len(subnet_int)


def subnet_to_prefix_len(subnet_mask: str) -> int:
    """Convert a subnet mask string to a prefix length.

    Example: "255.255.255.0" -> 24

    Raises NonContiguousMaskError for non-contiguous subnet masks.
    """
    mask = ipaddress.IPv4Address(subnet_mask)
    return _subnet_int_to_prefix_len(int(mask))


def _subnet_int_to_prefix_len(subnet_int: int) -> int:
    """Convert a 32-bit subnet mask integer to a prefix length.

    A valid subnet mask is a contiguous run of 1s followed by 0s.
    """
    if subnet_int == 0:
        return 0
    if subnet_int == 0xFFFFFFFF:
        return 32

    # Count the leading 1-bits
    prefix_len = bin(subnet_int).count("1")
    # Reconstruct the canonical mask and compare
    expected = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
    if expected != subnet_int:
        wc_str = str(ipaddress.IPv4Address(subnet_int ^ 0xFFFFFFFF))
        raise NonContiguousMaskError(
            f"Non-contiguous mask: {ipaddress.IPv4Address(subnet_int)} "
            f"(wildcard equivalent: {wc_str})"
        )
    return prefix_len


def prefix_len_to_subnet(prefix_len: int) -> str:
    """Convert a prefix length to a dotted-decimal subnet mask.

    Example: 24 -> "255.255.255.0"
    """
    if not (0 <= prefix_len <= 32):
        raise ValueError(f"Invalid prefix length: {prefix_len}")
    if prefix_len == 0:
        return "0.0.0.0"
    mask_int = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
    return str(ipaddress.IPv4Address(mask_int))


def prefix_len_to_wildcard(prefix_len: int) -> str:
    """Convert a prefix length to a dotted-decimal wildcard mask.

    Example: 24 -> "0.0.0.255"
    """
    if not (0 <= prefix_len <= 32):
        raise ValueError(f"Invalid prefix length: {prefix_len}")
    mask_int = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
    wc_int = mask_int ^ 0xFFFFFFFF
    return str(ipaddress.IPv4Address(wc_int))


def parse_addr_subnet(ip_str: str, mask_str: str) -> ipaddress.IPv4Network:
    """Parse an IP + subnet mask pair into an IPv4Network (PIX/ASA style).

    Raises NonContiguousMaskError, ValueError.
    """
    prefix_len = subnet_to_prefix_len(mask_str)
    return ipaddress.IPv4Network(f"{ip_str}/{prefix_len}", strict=False)


def parse_addr_wildcard(ip_str: str, wildcard_str: str) -> ipaddress.IPv4Network:
    """Parse an IP + wildcard mask pair into an IPv4Network (IOS style).

    Raises NonContiguousMaskError for non-contiguous wildcards.
    """
    prefix_len = wildcard_to_prefix_len(wildcard_str)
    return ipaddress.IPv4Network(f"{ip_str}/{prefix_len}", strict=False)


def is_contiguous_wildcard(wildcard_str: str) -> bool:
    """Return True if the wildcard mask corresponds to a contiguous prefix."""
    try:
        wildcard_to_prefix_len(wildcard_str)
        return True
    except (NonContiguousMaskError, ValueError):
        return False
