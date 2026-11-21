"""Hypothesis strategies that generate valid, renderable Policy IR (used by P1 and later tasks).

Everything is built from RFC 1918 and RFC 5737 space. "Valid" means the IR is something the parser
could have produced from a config in that dialect, so ``parse(render(ir)) == ir`` is meaningful.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable

from hypothesis import strategies as st

from necro.ir import (
    Action,
    AddressSpace,
    Binding,
    Dialect,
    Flow,
    Interface,
    MgmtAccess,
    NatRule,
    NatType,
    Policy,
    Route,
    Rule,
)
from necro.ir import Match as IrMatch
from necro.parsers.ios_finish import IosIface, assign_zones
from necro.sets import AddrSet, PortSet

_BASES = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("192.0.2.0/24"),
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
]
_NAMEIFS = ["outside", "inside", "dmz", "partner", "mgmt"]
_LOG_LEVELS = ["0", "3", "6", "informational", "debugging"]
_WORD = st.from_regex(r"[a-z][a-z0-9]{0,6}", fullmatch=True)
_TEXT = st.lists(_WORD, min_size=1, max_size=4).map(" ".join)
_POOL_LO = int(ipaddress.IPv4Address("192.0.2.0"))
_POOL_HI = int(ipaddress.IPv4Address("192.0.2.200"))


@st.composite
def networks(draw: st.DrawFn, min_prefix: int = 8, max_prefix: int = 32) -> ipaddress.IPv4Network:
    base = draw(st.sampled_from(_BASES))
    prefix = draw(st.integers(max(base.prefixlen, min_prefix), max_prefix))
    addr = int(base.network_address) + draw(st.integers(0, base.num_addresses - 1))
    return ipaddress.IPv4Network((addr, prefix), strict=False)


@st.composite
def addr_sets(draw: st.DrawFn, *, single_only: bool = False) -> AddrSet:
    kind = draw(st.sampled_from(["any", "host", "net", "multi"]))
    if kind == "any":
        return AddrSet.any()
    if kind == "host":
        return AddrSet.from_network(draw(networks(min_prefix=32)))
    if kind == "net" or single_only:
        return AddrSet.from_network(draw(networks()))
    parts = draw(st.lists(networks(), min_size=2, max_size=3))
    return AddrSet.from_cidr_list(parts)


@st.composite
def port_sets(draw: st.DrawFn, *, single_only: bool = False) -> PortSet:
    kind = draw(st.sampled_from(["any", "eq", "range", "multi"]))
    if kind == "any":
        return PortSet.any()
    lo = draw(st.integers(0, 65535))
    if kind == "eq":
        return PortSet.single(lo)
    hi = draw(st.integers(lo, 65535))
    if kind == "range" or single_only:
        return PortSet.from_range(lo, hi)
    lo2 = draw(st.integers(0, 65535))
    hi2 = draw(st.integers(lo2, 65535))
    return PortSet([(lo, hi), (lo2, hi2)])


@st.composite
def rules(
    draw: st.DrawFn, acl: str, ordinal: int, *, ios: bool = False, standard: bool = False
) -> Rule:
    action = draw(st.sampled_from(list(Action)))
    log = draw(st.booleans())
    remark = draw(st.one_of(st.just(""), _TEXT))
    rule_id = f"{acl}#{ordinal}"
    if standard:
        match = IrMatch(src=draw(addr_sets(single_only=True)))
        return Rule(id=rule_id, action=action, match=match, remark=remark, log=log)
    proto = draw(st.sampled_from([None, 1, 6, 17, 47, 89]))
    src = draw(addr_sets(single_only=ios))
    dst = draw(addr_sets(single_only=ios))
    sport = dport = PortSet.any()
    icmp: frozenset[int] | None = None
    established = False
    if proto in (6, 17):
        sport = draw(port_sets(single_only=ios))
        dport = draw(port_sets(single_only=ios))
        established = ios and proto == 6 and draw(st.booleans())
    elif proto == 1:
        types = draw(st.lists(st.integers(0, 255), min_size=1, max_size=1 if ios else 3))
        icmp = draw(st.one_of(st.none(), st.just(frozenset(types))))
    match = IrMatch(
        src=src,
        dst=dst,
        proto=proto,
        src_ports=sport,
        dst_ports=dport,
        icmp_types=icmp,
        established=established,
    )
    rule = Rule(id=rule_id, action=action, match=match, remark=remark, log=log)
    if not ios:
        rule.inactive = draw(st.booleans())
        rule.time_range = draw(st.sampled_from(["", "", "WORKHOURS"]))
        rule.log_level = draw(st.sampled_from(_LOG_LEVELS)) if log else ""
    return rule


def _acl_rules(
    draw: st.DrawFn, acl: str, *, ios: bool = False, standard: bool = False
) -> list[Rule]:
    n = draw(st.integers(1, 5))
    return [draw(rules(acl, i + 1, ios=ios, standard=standard)) for i in range(n)]


# ---------------------------------------------------------------------------
# PIX / ASA
# ---------------------------------------------------------------------------


@st.composite
def _nat_rules(draw: st.DrawFn, nameifs: list[str]) -> NatRule:
    iface = st.sampled_from(nameifs)
    kind = draw(st.sampled_from(["static", "port-static", "nat", "nat0", "global"]))
    if kind in ("static", "port-static"):
        prefix = 32 if kind == "port-static" else draw(st.integers(24, 32))
        rule = NatRule(
            nat_type=NatType.static,
            real_interface=draw(iface),
            mapped_interface=draw(iface),
            real_addr=AddrSet.from_network(draw(networks(min_prefix=prefix, max_prefix=prefix))),
            mapped_addr=AddrSet.from_network(draw(networks(min_prefix=prefix, max_prefix=prefix))),
        )
        if kind == "port-static":
            rule.proto = draw(st.sampled_from([6, 17]))
            rule.real_ports = PortSet.single(draw(st.integers(0, 65535)))
            rule.mapped_ports = PortSet.single(draw(st.integers(0, 65535)))
        return rule
    if kind in ("nat", "nat0"):
        return NatRule(
            nat_type=NatType.nat0 if kind == "nat0" else NatType.dynamic,
            real_interface=draw(iface),
            real_addr=AddrSet.from_network(draw(networks())),
            nat_id=0 if kind == "nat0" else draw(st.integers(1, 5)),
        )
    nat_id = draw(st.integers(1, 5))
    pool = draw(st.sampled_from(["interface", "range", "single"]))
    if pool == "interface":
        return NatRule(
            nat_type=NatType.pat, mapped_interface=draw(iface), nat_id=nat_id, is_pat=True
        )
    lo = draw(st.integers(_POOL_LO, _POOL_HI))
    if pool == "single":
        return NatRule(
            nat_type=NatType.pat,
            mapped_interface=draw(iface),
            nat_id=nat_id,
            mapped_addr=AddrSet([(lo, lo)]),
            is_pat=True,
        )
    return NatRule(
        nat_type=NatType.dynamic,
        mapped_interface=draw(iface),
        nat_id=nat_id,
        mapped_addr=AddrSet([(lo, lo + draw(st.integers(1, 50)))]),
    )


@st.composite
def _mgmt(draw: st.DrawFn, nameifs: list[str]) -> MgmtAccess:
    proto = draw(st.sampled_from(["telnet", "ssh", "http", "icmp", "snmp"]))
    iface = draw(st.sampled_from(nameifs))
    if proto == "snmp":
        host = AddrSet.from_network(draw(networks(min_prefix=32)))
        version = draw(st.sampled_from(["", "2c"]))
        return MgmtAccess(proto=proto, src_addr=host, interface=iface, version=version)
    kind = draw(st.sampled_from(["any", "host", "net"]) if proto == "icmp" else st.just("net"))
    if kind == "any":
        src = AddrSet.any()
    elif kind == "host":
        src = AddrSet.from_network(draw(networks(min_prefix=32)))
    else:
        src = AddrSet.from_network(draw(networks(min_prefix=8, max_prefix=31)))
    return MgmtAccess(proto=proto, src_addr=src, interface=iface)


@st.composite
def pix_asa_policies(draw: st.DrawFn) -> Policy:
    dialect = draw(st.sampled_from([Dialect.pix, Dialect.asa]))
    pix = dialect == Dialect.pix
    count = draw(st.integers(2, 4))
    nameifs = draw(st.permutations(_NAMEIFS))[:count]
    interfaces = [
        Interface(
            hw_name=f"ethernet{i}" if pix else f"Ethernet0/{i}",
            nameif=name,
            security_level=draw(st.integers(0, 100)),
            ip_address=draw(
                st.one_of(st.none(), st.just(ipaddress.IPv4Interface(f"10.{i + 1}.0.1/24")))
            ),
            description="" if pix else draw(st.one_of(st.just(""), _TEXT)),
        )
        for i, name in enumerate(nameifs)
    ]
    labels = draw(st.lists(_WORD.map(lambda w: f"h-{w}"), unique=True, max_size=3))
    aliases = {label: str(draw(networks(min_prefix=32)).network_address) for label in labels}
    acl_names = draw(
        st.lists(st.sampled_from(["ACL_A", "ACL_B", "ACL_C"]), unique=True, max_size=3)
    )
    acls = {name: _acl_rules(draw, name) for name in acl_names}
    bindings: list[Binding] = []
    egress: dict[str, str] = {}
    if acl_names:
        for nameif in nameifs:
            for direction in ("in", "out"):
                if draw(st.booleans()):
                    acl = draw(st.sampled_from(acl_names))
                    bindings.append(Binding(acl_name=acl, interface=nameif, direction=direction))  # type: ignore[arg-type]
                    if direction == "out":
                        egress[nameif] = acl
        if not pix and draw(st.booleans()):
            acl = draw(st.sampled_from(acl_names))
            bindings.append(Binding(acl_name=acl, interface="", direction="in", global_acl=True))
    routes = [
        Route(
            network=draw(networks()),
            next_hop=draw(networks(min_prefix=32)).network_address,
            interface=draw(st.sampled_from(nameifs)),
            metric=draw(st.integers(1, 255)),
        )
        for _ in range(draw(st.integers(0, 3)))
    ]
    return Policy(
        dialect=dialect,
        os_version="6.3(5)" if pix else draw(st.sampled_from(["7.2(4)", "8.0(4)", "8.2(5)"])),
        address_space=AddressSpace.mapped,
        name_aliases=aliases,
        interfaces=interfaces,
        routes=routes,
        bindings=bindings,
        acls=acls,
        egress_acls=egress,
        nat_rules=draw(st.lists(_nat_rules(nameifs), max_size=4)),
        nat_control=draw(st.booleans()),
        mgmt_access=draw(st.lists(_mgmt(nameifs), max_size=3)),
        same_security_inter=draw(st.booleans()),
        same_security_intra=draw(st.booleans()),
    )


# ---------------------------------------------------------------------------
# IOS
# ---------------------------------------------------------------------------


@st.composite
def ios_policies(draw: st.DrawFn) -> Policy:
    count = draw(st.integers(1, 4))
    descriptions = draw(
        st.lists(
            st.one_of(st.just(""), st.sampled_from(["WAN", "LAN", "DMZ", "MGMT"])),
            min_size=count,
            max_size=count,
        )
    )
    states = [
        IosIface(
            hw=f"FastEthernet0/{i}",
            line=0,
            description=descriptions[i],
            ip=draw(st.one_of(st.none(), st.just(ipaddress.IPv4Interface(f"10.{i + 1}.0.1/24")))),
        )
        for i in range(count)
    ]
    interfaces = assign_zones(states)
    nameifs = [i.nameif for i in interfaces]
    names = draw(
        st.lists(
            st.sampled_from(["10", "1350", "101", "2001", "EDGE_IN", "LAN_OUT"]),
            unique=True,
            max_size=4,
        )
    )
    acls: dict[str, list[Rule]] = {}
    for name in names:
        standard = name.isdigit() and (1 <= int(name) <= 99 or 1300 <= int(name) <= 1999)
        rule_list = _acl_rules(draw, name, ios=True, standard=standard)
        if not name.isdigit() and draw(st.booleans()):
            rule_list = [
                r.model_copy(update={"vendor_seq": 10 * (i + 1)}) for i, r in enumerate(rule_list)
            ]
        acls[name] = rule_list
    bindings: list[Binding] = []
    egress: dict[str, str] = {}
    if names:
        for nameif in nameifs:
            for direction in ("in", "out"):
                if draw(st.booleans()):
                    acl = draw(st.sampled_from(names))
                    bindings.append(Binding(acl_name=acl, interface=nameif, direction=direction))  # type: ignore[arg-type]
                    if direction == "out":
                        egress[nameif] = acl
    routes: list[Route] = []
    for _ in range(draw(st.integers(0, 3))):
        form = draw(st.sampled_from(["interface", "next-hop", "null"]))
        net = draw(networks())
        metric = draw(st.integers(1, 255))
        idx = draw(st.integers(0, count - 1))
        if form == "null":
            routes.append(Route(network=net, interface="", metric=metric))
        elif form == "interface":
            routes.append(Route(network=net, interface=nameifs[idx], metric=metric))
        elif states[idx].ip is not None:
            hop = ipaddress.IPv4Address(f"10.{idx + 1}.0.254")
            routes.append(Route(network=net, next_hop=hop, interface=nameifs[idx], metric=metric))
    return Policy(
        dialect=Dialect.ios,
        os_version="12.4",
        address_space=AddressSpace.as_is,
        interfaces=interfaces,
        routes=routes,
        bindings=bindings,
        acls=acls,
        egress_acls=egress,
    )


# ---------------------------------------------------------------------------
# Flows biased toward rule boundaries
# ---------------------------------------------------------------------------


def _edges(values: Iterable[tuple[int, int]], limit: int) -> list[int]:
    """lo-1, lo, hi, hi+1 of every interval, clamped to [0, limit]."""
    out = {0, limit}
    for lo, hi in values:
        out.update(v for v in (lo - 1, lo, hi, hi + 1) if 0 <= v <= limit)
    return sorted(out)


def flows_near(matches: Iterable[IrMatch]) -> st.SearchStrategy[Flow]:
    """Flows whose fields sit on or next to the boundaries of the given matches (70%), or are
    uniform (30%), mirroring the oracle strategy in the PBT playbook."""
    addr_iv: list[tuple[int, int]] = []
    port_iv: list[tuple[int, int]] = []
    icmp_types: set[int] = set()
    for m in matches:
        addr_iv += [(iv.lo, iv.hi) for iv in m.src.intervals + m.dst.intervals]
        port_iv += [(iv.lo, iv.hi) for iv in m.src_ports.intervals + m.dst_ports.intervals]
        icmp_types |= set(m.icmp_types or ())
    addrs = _edges(addr_iv, 0xFFFFFFFF)
    ports = _edges(port_iv, 65535)
    addr = st.one_of(
        st.sampled_from(addrs).map(ipaddress.IPv4Address),
        st.integers(0, 0xFFFFFFFF).map(ipaddress.IPv4Address),
    )
    port = st.one_of(st.sampled_from(ports), st.integers(0, 65535))
    icmp = st.one_of(st.none(), st.integers(0, 255), st.sampled_from(sorted(icmp_types or {8})))
    return st.builds(
        Flow,
        src=addr,
        dst=addr,
        proto=st.sampled_from([1, 6, 17, 47, 50, 88, 89]),
        src_port=port,
        dst_port=port,
        icmp_type=icmp,
        established=st.booleans(),
    )
