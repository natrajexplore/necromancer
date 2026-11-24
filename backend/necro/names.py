"""Protocol-keyed name tables for Cisco port and ICMP type resolution.

Port names differ by protocol: resolve with (protocol, name) key, never a flat map.
Traps from policy-semantics section 4:
  - 514/tcp = "cmd" / "rsh"  but  514/udp = "syslog"
  - 512/tcp = "exec"         but  512/udp = "biff"
  - radius  = 1645 (not 1812), radius-acct = 1646 (not 1813)

An unknown name must NOT be guessed; callers should raise a security-relevant unparsed error.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# TCP port names
# ---------------------------------------------------------------------------

_TCP_NAMES: dict[str, int] = {
    "ftp-data": 20,
    "ftp": 21,
    "ssh": 22,
    "telnet": 23,
    "smtp": 25,
    "domain": 53,
    "finger": 79,
    "www": 80,
    "http": 80,
    "pop2": 109,
    "pop3": 110,
    "sunrpc": 111,
    "ident": 113,
    "nntp": 119,
    "netbios-ssn": 139,
    "imap4": 143,
    "bgp": 179,
    "ldap": 389,
    "https": 443,
    "exec": 512,
    "login": 513,
    "cmd": 514,
    "rsh": 514,
    "lpd": 515,
    "talk": 517,
    "uucp": 540,
    "klogin": 543,
    "kshell": 544,
    "rtsp": 554,
    "ldaps": 636,
    "lotusnotes": 1352,
    "citrix-ica": 1494,
    "sqlnet": 1521,
    "h323": 1720,
    "pptp": 1723,
    "nfs": 2049,
    "ctiqbe": 2748,
    "cifs": 3020,
    "aol": 5190,
    "sip": 5060,
    "pcanywhere-data": 5631,
    "tacacs": 49,
    "kerberos": 88,
}

# ---------------------------------------------------------------------------
# UDP port names
# ---------------------------------------------------------------------------

_UDP_NAMES: dict[str, int] = {
    "echo": 7,
    "discard": 9,
    "time": 37,
    "nameserver": 42,
    "domain": 53,
    "bootps": 67,
    "bootpc": 68,
    "tftp": 69,
    "sunrpc": 111,
    "ntp": 123,
    "netbios-ns": 137,
    "netbios-dgm": 138,
    "snmp": 161,
    "snmptrap": 162,
    "xdmcp": 177,
    "isakmp": 500,
    "biff": 512,
    "who": 513,
    "syslog": 514,
    "talk": 517,
    "rip": 520,
    "radius": 1645,
    "radius-acct": 1646,
    "nfs": 2049,
    "sip": 5060,
    "tacacs": 49,
    "mobile-ip": 434,
    "secureid-udp": 5510,
    "kerberos": 88,
    "pcanywhere-status": 5632,
}

# ---------------------------------------------------------------------------
# ICMP type names
# ---------------------------------------------------------------------------

_ICMP_TYPES: dict[str, int] = {
    "echo-reply": 0,
    "unreachable": 3,
    "source-quench": 4,
    "redirect": 5,
    "alternate-address": 6,
    "echo": 8,
    "router-advertisement": 9,
    "router-solicitation": 10,
    "time-exceeded": 11,
    "parameter-problem": 12,
    "timestamp-request": 13,
    "timestamp-reply": 14,
    "information-request": 15,
    "information-reply": 16,
    "mask-request": 17,
    "mask-reply": 18,
    "traceroute": 30,
    "conversion-error": 31,
    "mobile-redirect": 32,
}

# ---------------------------------------------------------------------------
# IP protocol names
# ---------------------------------------------------------------------------

_IP_PROTOCOLS: dict[str, int] = {
    "icmp": 1,
    "igmp": 2,
    "ipinip": 4,
    "tcp": 6,
    "igrp": 9,
    "udp": 17,
    "gre": 47,
    "pptp": 47,
    "esp": 50,
    "ipsec": 50,
    "ah": 51,
    "icmp6": 58,
    "eigrp": 88,
    "ospf": 89,
    "nos": 94,
    "pim": 103,
    "pcp": 108,
    "snp": 109,
    # "ip" in Cisco ACLs means protocol=any (not a real proto number; callers use proto=None)
    "ip": 0,
}

# ---------------------------------------------------------------------------
# Public resolution API
# ---------------------------------------------------------------------------

_PORT_TABLES: dict[str, dict[str, int]] = {
    "tcp": _TCP_NAMES,
    "udp": _UDP_NAMES,
}


def resolve_port(proto_name: str, port_name: str) -> int | None:
    """Return the port number for (proto_name, port_name), or None if unknown.

    proto_name is "tcp" or "udp" (case-insensitive).
    port_name is a Cisco port keyword (case-insensitive).

    Returns None for an unknown name; callers must treat that as a
    security-relevant unparsed line and never guess.
    """
    table = _PORT_TABLES.get(proto_name.lower())
    if table is None:
        return None
    return table.get(port_name.lower())


def resolve_icmp_type(type_name: str) -> int | None:
    """Return the ICMP type number for a Cisco ICMP type name, or None if unknown."""
    return _ICMP_TYPES.get(type_name.lower())


def resolve_protocol(proto_name: str) -> int | None:
    """Return the IP protocol number for a Cisco protocol name, or None if unknown.

    Returns None for an unknown name; callers must treat that as a
    security-relevant unparsed line and never guess.

    Note: "ip" returns 0, which callers should interpret as proto=any (None in Match).
    """
    return _IP_PROTOCOLS.get(proto_name.lower())


def all_icmp_type_names() -> list[str]:
    """Return all known ICMP type names (for strategy generation in PBT)."""
    return list(_ICMP_TYPES.keys())


def all_icmp_types() -> list[int]:
    """Return all known ICMP type numbers (for strategy generation in PBT)."""
    return list(_ICMP_TYPES.values())


def all_named_ports() -> list[int]:
    """Every port number that has a Cisco name for TCP or UDP, sorted (for the oracle's flows)."""
    return sorted({port for table in _PORT_TABLES.values() for port in table.values()})
