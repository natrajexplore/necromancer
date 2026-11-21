"""Render a Policy IR as Cisco IOS 12.x configuration text (requirement 1.8, property P1).

The inverse of ``necro.parsers.ios_acl`` for everything an IOS IR can hold. IOS has no object
groups, so every address operand must be ``any``, a host or one network (wildcard mask), and every
port operand one range. Management-plane entries (vty, SNMP) are rebuilt from ACL references by
the parser and are not rendered.
"""

from __future__ import annotations

import ipaddress

from necro.ir import Binding, Policy, Rule
from necro.masks import prefix_len_to_subnet, prefix_len_to_wildcard
from necro.renderers.cisco_pix_asa import UnrenderableError
from necro.sets import AddrSet, PortSet

_PROTO_NAMES = {None: "ip", 1: "icmp", 6: "tcp", 17: "udp"}


def _addr(addrs: AddrSet) -> str:
    if addrs.is_empty():
        raise UnrenderableError("empty address set matches nothing")
    if addrs == AddrSet.any():
        return "any"
    nets = addrs.to_networks()
    if len(nets) != 1:
        raise UnrenderableError("IOS ACEs take one network per operand")
    net = nets[0]
    if net.prefixlen == 32:
        return f"host {net.network_address}"
    return f"{net.network_address} {prefix_len_to_wildcard(net.prefixlen)}"


def _ports(ports: PortSet) -> str:
    if ports.is_empty():
        raise UnrenderableError("empty port set matches nothing")
    if ports == PortSet.any():
        return ""
    ivs = ports.intervals
    if len(ivs) != 1:
        raise UnrenderableError("IOS ACEs take one port range per operand")
    iv = ivs[0]
    return f" eq {iv.lo}" if iv.lo == iv.hi else f" range {iv.lo} {iv.hi}"


def _is_standard_shape(rule: Rule) -> bool:
    m = rule.match
    return (
        m.proto is None
        and m.dst == AddrSet.any()
        and m.src_ports == PortSet.any()
        and m.dst_ports == PortSet.any()
        and m.icmp_types is None
        and not m.established
        and not rule.time_range
    )


def _standard_entry(rule: Rule) -> str:
    if not _is_standard_shape(rule):
        raise UnrenderableError("a standard ACL entry matches the source address only")
    return f"{rule.action.value} {_addr(rule.match.src)}" + (" log" if rule.log else "")


def _extended_entry(rule: Rule) -> str:
    m = rule.match
    if rule.inactive:
        raise UnrenderableError("IOS has no 'inactive' ACEs")
    if m.icmp_types is not None and m.proto != 1:
        raise UnrenderableError("ICMP types on a non-ICMP rule")
    if m.established and m.proto != 6:
        raise UnrenderableError("'established' is TCP only")
    parts = [rule.action.value, _PROTO_NAMES.get(m.proto, str(m.proto)), _addr(m.src)]
    if m.proto in (6, 17):
        parts[-1] += _ports(m.src_ports)
    elif m.src_ports != PortSet.any() or m.dst_ports != PortSet.any():
        raise UnrenderableError("ports on a protocol that has none")
    parts.append(_addr(m.dst))
    if m.proto in (6, 17):
        parts[-1] += _ports(m.dst_ports)
    elif m.icmp_types is not None:
        if len(m.icmp_types) != 1:
            raise UnrenderableError("IOS ACEs take one ICMP type")
        parts.append(str(next(iter(m.icmp_types))))
    line = " ".join(parts)
    if m.established:
        line += " established"
    if rule.log:
        line += " log"
    if rule.time_range:
        line += f" time-range {rule.time_range}"
    return line


def _acl_lines(name: str, rules: list[Rule]) -> list[str]:
    number = int(name) if name.isdigit() else None
    if number is not None and (1 <= number <= 99 or 1300 <= number <= 1999):
        lines: list[str] = []
        for r in rules:
            if r.remark:
                lines.append(f"access-list {name} remark {r.remark}")
            lines.append(f"access-list {name} {_standard_entry(r)}")
        return lines
    if number is not None:
        if not (100 <= number <= 199 or 2000 <= number <= 2699):
            raise UnrenderableError(f"ACL number {number} is not supported")
        lines = []
        for r in rules:
            if r.remark:
                lines.append(f"access-list {name} remark {r.remark}")
            lines.append(f"access-list {name} {_extended_entry(r)}")
        return lines
    lines = [f"ip access-list extended {name}"]
    for r in rules:
        if r.remark:
            lines.append(f" remark {r.remark}")
        seq = f"{r.vendor_seq} " if r.vendor_seq is not None else ""
        lines.append(f" {seq}{_extended_entry(r)}")
    return lines


def _route_line(net: ipaddress.IPv4Network, target: str, metric: int) -> str:
    distance = f" {metric}" if metric != 1 else ""
    mask = prefix_len_to_subnet(net.prefixlen)
    return f"ip route {net.network_address} {mask} {target}{distance}"


def render_ios(policy: Policy) -> str:
    """Render ``policy`` as IOS configuration text."""
    lines: list[str] = []
    if policy.os_version:
        lines.append(f"version {policy.os_version}")
    hw_of = {i.nameif: i.hw_name for i in policy.interfaces}
    bindings: dict[str, list[Binding]] = {}
    for b in policy.bindings:
        bindings.setdefault(b.interface, []).append(b)
    for i in policy.interfaces:
        lines.append(f"interface {i.hw_name}")
        if i.description:
            lines.append(f" description {i.description}")
        if i.ip_address is not None:
            mask = prefix_len_to_subnet(i.ip_address.network.prefixlen)
            lines.append(f" ip address {i.ip_address.ip} {mask}")
        for b in bindings.get(i.nameif, []):
            lines.append(f" ip access-group {b.acl_name} {b.direction}")
    for r in policy.routes:
        if r.interface == "":
            lines.append(_route_line(r.network, "Null0", r.metric))
        elif r.next_hop is not None:
            lines.append(_route_line(r.network, str(r.next_hop), r.metric))
        else:
            lines.append(_route_line(r.network, hw_of[r.interface], r.metric))
    for name, rules in policy.acls.items():
        lines += _acl_lines(name, rules)
    return "\n".join(lines) + "\n"
