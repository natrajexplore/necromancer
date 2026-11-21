"""Render a Policy IR as PIX 6.x / ASA 7.x-8.2 configuration text (requirement 1.8, property P1).

This is the inverse of ``necro.parsers.pix_asa`` for everything the IR can hold:
``parse(render(ir))`` reproduces the IR. It exists to prove the parser round-trips and to
give tests readable fixtures. It is never used to produce a migration artifact.

Sets that don't fit one ACE operand (several networks, several port ranges, several ICMP types)
become ``object-group`` definitions, which the parser expands back to the same sets.
"""

from __future__ import annotations

import ipaddress

from necro.ir import (
    Dialect,
    Interface,
    MgmtAccess,
    NatRule,
    NatType,
    Policy,
    Rule,
)
from necro.masks import prefix_len_to_subnet
from necro.sets import AddrSet, PortSet


class UnrenderableError(ValueError):
    """The IR holds something this dialect can't express."""


_PROTO_NAMES = {None: "ip", 1: "icmp", 6: "tcp", 17: "udp"}


def _mask(net: ipaddress.IPv4Network) -> str:
    return prefix_len_to_subnet(net.prefixlen)


class _Groups:
    """Deduplicated object-group definitions, emitted before the ACLs that use them."""

    def __init__(self) -> None:
        self.names: dict[tuple[str, str], str] = {}
        self.lines: list[str] = []

    def network(self, addrs: AddrSet) -> str:
        key = ("network", repr(addrs))
        if key not in self.names:
            name = f"NECRO_N{len(self.names)}"
            self.names[key] = name
            self.lines.append(f"object-group network {name}")
            for net in addrs.to_networks():
                if net.prefixlen == 32:
                    self.lines.append(f" network-object host {net.network_address}")
                else:
                    self.lines.append(f" network-object {net.network_address} {_mask(net)}")
        return self.names[key]

    def ports(self, ports: PortSet, proto: str) -> str:
        key = (f"service-{proto}", repr(ports))
        if key not in self.names:
            name = f"NECRO_P{len(self.names)}"
            self.names[key] = name
            self.lines.append(f"object-group service {name} {proto}")
            for iv in ports.intervals:
                if iv.lo == iv.hi:
                    self.lines.append(f" port-object eq {iv.lo}")
                else:
                    self.lines.append(f" port-object range {iv.lo} {iv.hi}")
        return self.names[key]

    def icmp(self, types: frozenset[int]) -> str:
        key = ("icmp", repr(sorted(types)))
        if key not in self.names:
            name = f"NECRO_I{len(self.names)}"
            self.names[key] = name
            self.lines.append(f"object-group icmp-type {name}")
            for t in sorted(types):
                self.lines.append(f" icmp-object {t}")
        return self.names[key]


def _addr(addrs: AddrSet, groups: _Groups) -> str:
    if addrs.is_empty():
        raise UnrenderableError("empty address set matches nothing")
    if addrs == AddrSet.any():
        return "any"
    nets = addrs.to_networks()
    if len(nets) == 1:
        net = nets[0]
        if net.prefixlen == 32:
            return f"host {net.network_address}"
        return f"{net.network_address} {_mask(net)}"
    return f"object-group {groups.network(addrs)}"


def _ports(ports: PortSet, proto: int, groups: _Groups) -> str:
    if ports.is_empty():
        raise UnrenderableError("empty port set matches nothing")
    if ports == PortSet.any():
        return ""
    ivs = ports.intervals
    if len(ivs) == 1:
        iv = ivs[0]
        return f" eq {iv.lo}" if iv.lo == iv.hi else f" range {iv.lo} {iv.hi}"
    return f" object-group {groups.ports(ports, 'tcp' if proto == 6 else 'udp')}"


def _rule_line(acl: str, rule: Rule, groups: _Groups) -> str:
    m = rule.match
    if m.established:
        raise UnrenderableError("'established' is an IOS construct")
    if m.icmp_types is not None and m.proto != 1:
        raise UnrenderableError("ICMP types on a non-ICMP rule")
    proto = _PROTO_NAMES.get(m.proto, str(m.proto))
    parts = [f"access-list {acl} extended {rule.action.value} {proto}", _addr(m.src, groups)]
    if m.proto in (6, 17):
        parts[-1] += _ports(m.src_ports, m.proto, groups)
    elif m.src_ports != PortSet.any():
        raise UnrenderableError("ports on a protocol that has none")
    parts.append(_addr(m.dst, groups))
    if m.proto in (6, 17):
        parts[-1] += _ports(m.dst_ports, m.proto, groups)
    elif m.dst_ports != PortSet.any():
        raise UnrenderableError("ports on a protocol that has none")
    elif m.icmp_types is not None:
        types = sorted(m.icmp_types)
        if not types:
            raise UnrenderableError("empty ICMP type set matches nothing")
        single = len(types) == 1
        parts.append(str(types[0]) if single else f"object-group {groups.icmp(m.icmp_types)}")
    line = " ".join(parts)
    if rule.log:
        line += " log" + (f" {rule.log_level}" if rule.log_level else "")
    if rule.time_range:
        line += f" time-range {rule.time_range}"
    if rule.inactive:
        line += " inactive"
    return line


def _ip_mask(i: Interface) -> str:
    assert i.ip_address is not None
    return f"{i.ip_address.ip} {prefix_len_to_subnet(i.ip_address.network.prefixlen)}"


def _interface_lines(policy: Policy) -> list[str]:
    lines: list[str] = []
    pix = policy.dialect == Dialect.pix
    for i in policy.interfaces:
        if pix:
            lines.append(f"nameif {i.hw_name} {i.nameif} security{i.security_level}")
        else:
            lines += [f"interface {i.hw_name}", f" nameif {i.nameif}"]
            lines.append(f" security-level {i.security_level}")
            if i.description:
                lines.append(f" description {i.description}")
            if i.ip_address is not None:
                lines.append(f" ip address {_ip_mask(i)}")
    if pix:
        lines += [f"ip address {i.nameif} {_ip_mask(i)}" for i in policy.interfaces if i.ip_address]
    return lines


def _nat_line(n: NatRule) -> str:
    if n.nat_type == NatType.static:
        proto = {6: "tcp ", 17: "udp "}.get(n.proto or 0, "")
        real = n.real_addr.to_networks()
        mapped = n.mapped_addr.to_networks()
        if len(real) != 1 or len(mapped) != 1:
            raise UnrenderableError("static NAT needs one network on each side")
        mport = rport = ""
        if proto:
            mp, rp = n.mapped_ports.intervals, n.real_ports.intervals
            if len(mp) != 1 or len(rp) != 1 or mp[0].lo != mp[0].hi or rp[0].lo != rp[0].hi:
                raise UnrenderableError("port static NAT needs one port on each side")
            mport, rport = f" {mp[0].lo}", f" {rp[0].lo}"
        return (
            f"static ({n.real_interface},{n.mapped_interface}) {proto}"
            f"{mapped[0].network_address}{mport} {real[0].network_address}{rport} "
            f"netmask {_mask(real[0])}"
        )
    if n.real_interface:
        nets = n.real_addr.to_networks()
        if len(nets) != 1:
            raise UnrenderableError("nat needs one real network")
        return f"nat ({n.real_interface}) {n.nat_id} {nets[0].network_address} {_mask(nets[0])}"
    if n.is_pat and n.mapped_addr.is_empty():
        pool = "interface"
    else:
        ivs = n.mapped_addr.intervals
        if len(ivs) != 1:
            raise UnrenderableError("global needs one address or one range")
        lo, hi = ipaddress.IPv4Address(ivs[0].lo), ipaddress.IPv4Address(ivs[0].hi)
        pool = str(lo) if lo == hi else f"{lo}-{hi}"
    return f"global ({n.mapped_interface}) {n.nat_id} {pool}"


def _mgmt_line(m: MgmtAccess) -> str:
    nets = m.src_addr.to_networks()
    if m.proto == "snmp":
        if len(nets) != 1 or nets[0].prefixlen != 32:
            raise UnrenderableError("snmp-server host needs one host address")
        version = f" version {m.version}" if m.version else ""
        return f"snmp-server host {m.interface} {nets[0].network_address}{version}"
    if len(nets) != 1:
        raise UnrenderableError("management access needs one source network")
    net = nets[0]
    if m.proto == "icmp":
        if net.prefixlen == 0:
            return f"icmp permit any {m.interface}"
        if net.prefixlen == 32:
            return f"icmp permit host {net.network_address} {m.interface}"
        return f"icmp permit {net.network_address} {_mask(net)} {m.interface}"
    return f"{m.proto} {net.network_address} {_mask(net)} {m.interface}"


def render_pix_asa(policy: Policy) -> str:
    """Render ``policy`` as PIX/ASA configuration text.

    Raises UnrenderableError for IR this dialect can't hold (e.g. an ``established`` rule).
    """
    header = "PIX" if policy.dialect == Dialect.pix else "ASA"
    lines: list[str] = []
    if policy.os_version:
        lines.append(f"{header} Version {policy.os_version}")
    if policy.name_aliases:
        lines.append("names")
        lines += [f"name {ip} {label}" for label, ip in policy.name_aliases.items()]
    lines += _interface_lines(policy)
    groups = _Groups()
    acl_lines: list[str] = []
    for acl, rules in policy.acls.items():
        for rule in rules:
            if rule.remark:
                acl_lines.append(f"access-list {acl} remark {rule.remark}")
            acl_lines.append(_rule_line(acl, rule, groups))
    lines += groups.lines + acl_lines
    for b in policy.bindings:
        if b.global_acl:
            lines.append(f"access-group {b.acl_name} global")
        else:
            lines.append(f"access-group {b.acl_name} {b.direction} interface {b.interface}")
    if policy.same_security_inter:
        lines.append("same-security-traffic permit inter-interface")
    if policy.same_security_intra:
        lines.append("same-security-traffic permit intra-interface")
    if policy.nat_control:
        lines.append("nat-control")
    for r in policy.routes:
        if r.next_hop is None:
            raise UnrenderableError("PIX/ASA routes need a gateway")
        lines.append(
            f"route {r.interface} {r.network.network_address} {_mask(r.network)} "
            f"{r.next_hop} {r.metric}"
        )
    lines += [_nat_line(n) for n in policy.nat_rules]
    lines += [_mgmt_line(m) for m in policy.mgmt_access]
    return "\n".join(lines) + "\n"
