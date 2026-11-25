"""Single-line PIX/ASA statements: static/nat/global, route, telnet/ssh/http/icmp/snmp-server host.

Each function takes the statement tokens and the ``name`` alias table and returns IR objects, or
raises ``Unsupported(reason)`` so the caller records a security-relevant unparsed line.
Pre-8.3 forms only (policy-semantics section 1.5). Policy NAT with ACLs is unsupported in v1.
"""

from __future__ import annotations

import ipaddress

from necro.ir import Action, MgmtAccess, NatRule, NatType, Route
from necro.parsers.cisco_common import (
    Unsupported,
    looks_like_ipv4,
    parse_interface_pair,
    parse_ipv4,
    parse_port_value,
    parse_subnet_mask,
)
from necro.sets import AddrSet, PortSet

_NAT_TAIL_WORDS = frozenset({"dns", "norandomseq", "nailed"})
_MGMT_NON_ACCESS = frozenset({"timeout", "version", "server", "scopy", "key-exchange", "redirect"})


def _addr_or_zero(token: str, names: dict[str, str]) -> ipaddress.IPv4Address:
    """The PIX shorthand ``0`` stands for 0.0.0.0."""
    if token == "0":
        return ipaddress.IPv4Address(0)
    return parse_ipv4(token, names)


def _mask_or_zero(token: str) -> int:
    return 0 if token == "0" else parse_subnet_mask(token)


def _network(addr: ipaddress.IPv4Address, prefix: int, *, strict: bool) -> ipaddress.IPv4Network:
    try:
        return ipaddress.IPv4Network(f"{addr}/{prefix}", strict=strict)
    except ValueError:
        raise Unsupported("host-bits-set") from None


def _check_tail(tokens: list[str], i: int) -> None:
    """Accept connection limits and harmless keywords after nat/static. Reject the rest."""
    for tok in tokens[i:]:
        if tok.isdigit() or tok in _NAT_TAIL_WORDS:
            continue
        if tok == "outside":
            raise Unsupported("outside-nat")
        raise Unsupported("nat-option-unsupported")


# ---------------------------------------------------------------------------
# NAT
# ---------------------------------------------------------------------------


def parse_static(tokens: list[str], names: dict[str, str]) -> NatRule:
    """``static (real_if,mapped_if) [tcp|udp] mapped [port] real [port] [netmask M]``."""
    if len(tokens) < 4:
        raise Unsupported("truncated-static")
    pair = parse_interface_pair(tokens[1])
    if len(pair) != 2:
        raise Unsupported("bad-interface-pair")
    i = 2
    proto: int | None = None
    proto_name = ""
    if tokens[i] in ("tcp", "udp"):
        proto_name = tokens[i]
        proto = 6 if proto_name == "tcp" else 17
        i += 1

    def take_addr() -> ipaddress.IPv4Address:
        nonlocal i
        if i >= len(tokens):
            raise Unsupported("truncated-static")
        tok = tokens[i]
        if tok == "access-list":
            raise Unsupported("policy-nat-access-list")
        if tok == "interface":
            raise Unsupported("static-interface-mapping")
        i += 1
        return _addr_or_zero(tok, names)

    def take_port() -> PortSet:
        nonlocal i
        if proto is None:
            return PortSet()
        if i >= len(tokens):
            raise Unsupported("truncated-static")
        port = parse_port_value(proto_name, tokens[i])
        i += 1
        return PortSet.single(port)

    mapped = take_addr()
    mapped_ports = take_port()
    real = take_addr()
    real_ports = take_port()
    prefix = 32
    if i < len(tokens) and tokens[i] == "netmask":
        if i + 1 >= len(tokens):
            raise Unsupported("truncated-static")
        prefix = _mask_or_zero(tokens[i + 1])
        i += 2
    _check_tail(tokens, i)
    if proto is not None and prefix != 32:
        raise Unsupported("port-static-with-subnet")
    return NatRule(
        nat_type=NatType.static,
        real_interface=pair[0],
        mapped_interface=pair[1],
        real_addr=AddrSet.from_network(_network(real, prefix, strict=True)),
        mapped_addr=AddrSet.from_network(_network(mapped, prefix, strict=True)),
        real_ports=real_ports,
        mapped_ports=mapped_ports,
        proto=proto,
    )


def parse_nat(tokens: list[str], names: dict[str, str]) -> NatRule:
    """``nat (real_if) <id> <addr> <mask> [max_conns [emb_limit]] [norandomseq]``."""
    if len(tokens) < 3:
        raise Unsupported("truncated-nat")
    pair = parse_interface_pair(tokens[1])
    if len(pair) != 1:
        raise Unsupported("twice-nat-unsupported")
    if not tokens[2].isdigit():
        raise Unsupported("bad-nat-id")
    nat_id = int(tokens[2])
    if len(tokens) > 3 and tokens[3] == "access-list":
        raise Unsupported("policy-nat-access-list")
    if len(tokens) < 5:
        raise Unsupported("truncated-nat")
    addr = _addr_or_zero(tokens[3], names)
    prefix = _mask_or_zero(tokens[4])
    _check_tail(tokens, 5)
    return NatRule(
        nat_type=NatType.nat0 if nat_id == 0 else NatType.dynamic,
        real_interface=pair[0],
        real_addr=AddrSet.from_network(_network(addr, prefix, strict=False)),
        nat_id=nat_id,
    )


def parse_global(tokens: list[str], names: dict[str, str]) -> NatRule:
    """``global (mapped_if) <id> interface | <lo>-<hi> | <addr> [netmask M]``."""
    if len(tokens) < 4:
        raise Unsupported("truncated-global")
    pair = parse_interface_pair(tokens[1])
    if len(pair) != 1 or not tokens[2].isdigit():
        raise Unsupported("bad-global")
    nat_id = int(tokens[2])
    pool = tokens[3]
    if pool == "interface":
        if len(tokens) != 4:
            raise Unsupported("bad-global")
        return NatRule(
            nat_type=NatType.pat,
            mapped_interface=pair[0],
            nat_id=nat_id,
            is_pat=True,
        )
    if len(tokens) not in (4, 6) or (len(tokens) == 6 and tokens[4] != "netmask"):
        raise Unsupported("bad-global")
    if "-" in pool:
        lo_tok, hi_tok = pool.split("-", 1)
        lo = parse_ipv4(lo_tok, names)
        hi = parse_ipv4(hi_tok, names)
        if int(lo) > int(hi):
            raise Unsupported("inverted-global-range")
        return NatRule(
            nat_type=NatType.dynamic,
            mapped_interface=pair[0],
            nat_id=nat_id,
            mapped_addr=AddrSet.from_range(lo, hi),
        )
    return NatRule(
        nat_type=NatType.pat,
        mapped_interface=pair[0],
        nat_id=nat_id,
        mapped_addr=AddrSet.from_host(parse_ipv4(pool, names)),
        is_pat=True,
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


def parse_route(tokens: list[str], names: dict[str, str]) -> Route:
    """``route <nameif> <net> <mask> <gateway> [metric]``."""
    if len(tokens) < 5:
        raise Unsupported("truncated-route")
    net = _addr_or_zero(tokens[2], names)
    prefix = _mask_or_zero(tokens[3])
    gateway = parse_ipv4(tokens[4], names)
    metric = 1
    for tok in tokens[5:]:
        if tok.isdigit():
            metric = int(tok)
        elif tok == "tunneled":
            raise Unsupported("tunneled-route")
        else:
            raise Unsupported("route-option-unsupported")
    return Route(
        network=_network(net, prefix, strict=False),
        next_hop=gateway,
        interface=tokens[1],
        metric=metric,
    )


# ---------------------------------------------------------------------------
# Management plane
# ---------------------------------------------------------------------------


def parse_mgmt(tokens: list[str], names: dict[str, str]) -> MgmtAccess | None:
    """``telnet|ssh|http <addr> <mask> <nameif>``. Returns None for non-access sub-commands."""
    if len(tokens) >= 2 and tokens[1] in _MGMT_NON_ACCESS:
        return None
    if len(tokens) != 4:
        raise Unsupported("bad-management-command")
    addr = _addr_or_zero(tokens[1], names)
    prefix = _mask_or_zero(tokens[2])
    return MgmtAccess(
        proto=tokens[0].lower(),
        src_addr=AddrSet.from_network(_network(addr, prefix, strict=False)),
        interface=tokens[3],
    )


def parse_icmp_mgmt(tokens: list[str], names: dict[str, str]) -> MgmtAccess | None:
    """``icmp permit|deny <any|host H|A M> <nameif>``. ICMP types are unsupported in v1."""
    if len(tokens) >= 2 and tokens[1] == "unreachable":
        return None
    if len(tokens) < 4 or tokens[1] not in ("permit", "deny"):
        raise Unsupported("bad-icmp-command")
    action = Action.deny if tokens[1] == "deny" else Action.permit
    rest = tokens[2:]
    if rest[0] == "any" and len(rest) == 2:
        src = AddrSet.any()
    elif rest[0] == "host" and len(rest) == 3:
        src = AddrSet.from_host(parse_ipv4(rest[1], names))
    elif len(rest) == 3 and looks_like_ipv4(rest[1]):
        prefix = _mask_or_zero(rest[1])
        src = AddrSet.from_network(_network(parse_ipv4(rest[0], names), prefix, strict=False))
    else:
        raise Unsupported("icmp-type-to-the-box")
    return MgmtAccess(proto="icmp", src_addr=src, interface=rest[-1], action=action)


def parse_snmp_host(tokens: list[str], names: dict[str, str]) -> MgmtAccess:
    """``snmp-server host <nameif> <ip> [trap|poll] [version v] ...``."""
    if len(tokens) < 4:
        raise Unsupported("bad-snmp-host")
    version = ""
    if "version" in tokens[4:]:
        idx = tokens.index("version", 4)
        if idx + 1 < len(tokens):
            version = tokens[idx + 1]
    return MgmtAccess(
        proto="snmp",
        src_addr=AddrSet.from_host(parse_ipv4(tokens[3], names)),
        interface=tokens[2],
        version=version,
    )
