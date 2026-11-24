"""Short readable text for a rule's match, used by the rule inventory of the Grimoire."""

from __future__ import annotations

from necro.ir import Flow, Match
from necro.sets import AddrSet, PortSet

_PROTOCOLS = {1: "icmp", 6: "tcp", 17: "udp"}
_LISTED_NETWORKS = 3


def addr_text(addresses: AddrSet) -> str:
    """``any``, or CIDR networks (the first few, then a count)."""
    if addresses == AddrSet.any():
        return "any"
    networks = addresses.to_networks()
    if not networks:
        return "none"
    shown = ", ".join(str(n) for n in networks[:_LISTED_NETWORKS])
    more = len(networks) - _LISTED_NETWORKS
    return shown if more <= 0 else f"{shown} and {more} more"


def port_text(ports: PortSet) -> str:
    """``80,443,8000-8010``."""
    return ",".join(str(iv.lo) if iv.lo == iv.hi else f"{iv.lo}-{iv.hi}" for iv in ports.intervals)


def service_text(match: Match) -> str:
    """The protocol and ports of a match: ``tcp dport 80,443``, ``icmp type 8``, ``ip``."""
    if match.proto is None:
        return "ip"
    parts = [_PROTOCOLS.get(match.proto, f"ip protocol {match.proto}")]
    if match.proto in (6, 17):
        if match.src_ports != PortSet.any():
            parts.append(f"sport {port_text(match.src_ports)}")
        if match.dst_ports != PortSet.any():
            parts.append(f"dport {port_text(match.dst_ports)}")
        if match.established:
            parts.append("established")
    elif match.proto == 1 and match.icmp_types is not None:
        parts.append("type " + ",".join(str(t) for t in sorted(match.icmp_types)))
    return " ".join(parts)


def match_text(match: Match) -> str:
    """``tcp dport 80 from 10.0.0.0/24 to any``."""
    return f"{service_text(match)} from {addr_text(match.src)} to {addr_text(match.dst)}"


def flow_text(flow: Flow) -> str:
    """One flow on one line: ``tcp 10.0.0.1:40000 -> 10.0.1.1:80``."""
    if flow.proto in (6, 17):
        proto = "tcp" if flow.proto == 6 else "udp"
        return f"{proto} {flow.src}:{flow.src_port} -> {flow.dst}:{flow.dst_port}"
    if flow.proto == 1:
        kind = "any type" if flow.icmp_type is None else f"type {flow.icmp_type}"
        return f"icmp {flow.src} -> {flow.dst} {kind}"
    return f"ip protocol {flow.proto} {flow.src} -> {flow.dst}"
