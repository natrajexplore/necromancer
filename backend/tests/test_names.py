"""Tests for names.py (task 2.4).

Verifies the protocol-keyed name tables, with extra focus on the tricky traps:
  - 514/tcp = cmd/rsh  vs  514/udp = syslog
  - 512/tcp = exec     vs  512/udp = biff
  - radius  = 1645 (not 1812), radius-acct = 1646 (not 1813)
"""

from __future__ import annotations

from necro.names import (
    all_icmp_type_names,
    all_icmp_types,
    resolve_icmp_type,
    resolve_port,
    resolve_protocol,
)

# ---------------------------------------------------------------------------
# Port resolution traps (from policy-semantics section 4)
# ---------------------------------------------------------------------------


def test_514_tcp_is_cmd() -> None:
    assert resolve_port("tcp", "cmd") == 514


def test_514_tcp_rsh_alias() -> None:
    assert resolve_port("tcp", "rsh") == 514


def test_514_udp_is_syslog() -> None:
    assert resolve_port("udp", "syslog") == 514


def test_514_protocols_differ() -> None:
    # cmd/rsh and syslog both map to port 514, but via different protocol tables
    assert resolve_port("tcp", "cmd") == resolve_port("udp", "syslog")


def test_512_tcp_is_exec() -> None:
    assert resolve_port("tcp", "exec") == 512


def test_512_udp_is_biff() -> None:
    assert resolve_port("udp", "biff") == 512


def test_radius_is_1645() -> None:
    """Cisco radius = 1645, NOT 1812."""
    assert resolve_port("udp", "radius") == 1645


def test_radius_acct_is_1646() -> None:
    """Cisco radius-acct = 1646, NOT 1813."""
    assert resolve_port("udp", "radius-acct") == 1646


# ---------------------------------------------------------------------------
# Standard port resolution
# ---------------------------------------------------------------------------


def test_tcp_www() -> None:
    assert resolve_port("tcp", "www") == 80


def test_tcp_http() -> None:
    assert resolve_port("tcp", "http") == 80


def test_tcp_https() -> None:
    assert resolve_port("tcp", "https") == 443


def test_tcp_ssh() -> None:
    assert resolve_port("tcp", "ssh") == 22


def test_tcp_telnet() -> None:
    assert resolve_port("tcp", "telnet") == 23


def test_tcp_ftp() -> None:
    assert resolve_port("tcp", "ftp") == 21


def test_tcp_domain() -> None:
    assert resolve_port("tcp", "domain") == 53


def test_udp_domain() -> None:
    assert resolve_port("udp", "domain") == 53


def test_udp_snmp() -> None:
    assert resolve_port("udp", "snmp") == 161


def test_udp_ntp() -> None:
    assert resolve_port("udp", "ntp") == 123


def test_unknown_tcp_port() -> None:
    assert resolve_port("tcp", "not-a-real-service") is None


def test_unknown_udp_port() -> None:
    assert resolve_port("udp", "bogus") is None


def test_unknown_protocol() -> None:
    assert resolve_port("sctp", "domain") is None


def test_case_insensitive() -> None:
    assert resolve_port("TCP", "HTTP") == 80
    assert resolve_port("udp", "SYSLOG") == 514


# ---------------------------------------------------------------------------
# ICMP type resolution
# ---------------------------------------------------------------------------


def test_icmp_echo_reply() -> None:
    assert resolve_icmp_type("echo-reply") == 0


def test_icmp_echo() -> None:
    assert resolve_icmp_type("echo") == 8


def test_icmp_unreachable() -> None:
    assert resolve_icmp_type("unreachable") == 3


def test_icmp_time_exceeded() -> None:
    assert resolve_icmp_type("time-exceeded") == 11


def test_icmp_traceroute() -> None:
    assert resolve_icmp_type("traceroute") == 30


def test_icmp_unknown() -> None:
    assert resolve_icmp_type("not-an-icmp-type") is None


def test_icmp_case_insensitive() -> None:
    assert resolve_icmp_type("ECHO-REPLY") == 0


# ---------------------------------------------------------------------------
# IP protocol resolution
# ---------------------------------------------------------------------------


def test_protocol_tcp() -> None:
    assert resolve_protocol("tcp") == 6


def test_protocol_udp() -> None:
    assert resolve_protocol("udp") == 17


def test_protocol_icmp() -> None:
    assert resolve_protocol("icmp") == 1


def test_protocol_esp() -> None:
    assert resolve_protocol("esp") == 50


def test_protocol_gre() -> None:
    assert resolve_protocol("gre") == 47


def test_protocol_ospf() -> None:
    assert resolve_protocol("ospf") == 89


def test_protocol_ip_returns_zero() -> None:
    # "ip" in Cisco ACLs means any protocol; callers interpret 0 as proto=None
    assert resolve_protocol("ip") == 0


def test_protocol_unknown() -> None:
    assert resolve_protocol("not-a-protocol") is None


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def test_all_icmp_type_names_nonempty() -> None:
    names = all_icmp_type_names()
    assert len(names) > 0
    assert "echo" in names
    assert "echo-reply" in names


def test_all_icmp_types_nonempty() -> None:
    types = all_icmp_types()
    assert 0 in types  # echo-reply
    assert 8 in types  # echo
