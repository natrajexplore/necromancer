"""Extended ACE parsing for PIX 6.x / ASA 7.x-8.2 (policy-semantics sections 1.1, 1.6, 1.7).

``parse_ace`` turns the tokens after ``access-list NAME [extended]`` into one or more matches
(several only when a protocol-position object-group expands to several protocols). Anything the
v1 model can't represent raises ``Unsupported`` with a specific reason; undefined object-groups
raise ``ParseError``.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from necro.ir import Action, Match
from necro.names import resolve_protocol
from necro.parsers.cisco_common import (
    Unsupported,
    is_port_operator,
    looks_like_ipv4,
    parse_icmp_type,
    parse_ipv4,
    parse_port_operator,
    parse_subnet_mask,
)
from necro.parsers.cisco_groups import (
    KIND_ICMP,
    KIND_NETWORK,
    KIND_PROTOCOL,
    KIND_SERVICE,
    KIND_SERVICE_MULTI,
    GroupTable,
)
from necro.sets import AddrSet, PortSet

_LOG_LEVELS = frozenset(
    {
        "emergencies",
        "alerts",
        "critical",
        "errors",
        "warnings",
        "notifications",
        "informational",
        "debugging",
    }
)
_UNSUPPORTED_OPERANDS = {
    "object": "asa-8.3-object-operand",
    "interface": "asa-8.3-interface-operand",
    "any6": "ipv6",
    "user": "identity-firewall",
    "user-group": "identity-firewall",
    "object-group-user": "identity-firewall",
    "security-group": "trustsec-security-group",
    "object-group-security": "trustsec-security-group",
}
_PROTO_LABEL = {6: "tcp", 17: "udp"}

# (protocol, own source ports, own destination ports, own ICMP types) for one ACE element
_ProtoSpec = tuple[int | None, PortSet | None, PortSet | None, frozenset[int] | None]


@dataclass
class AceAttrs:
    log: bool = False
    log_level: str = ""
    time_range: str = ""
    inactive: bool = False


@dataclass
class ParsedAce:
    action: Action
    matches: list[Match]
    attrs: AceAttrs


def parse_ace(
    tokens: list[str], names: dict[str, str], groups: GroupTable, line_no: int
) -> ParsedAce:
    """Parse ``permit|deny <proto> <src> [ports] <dst> [ports|icmp] [attributes]``."""
    if not tokens or tokens[0] not in ("permit", "deny"):
        raise Unsupported("unknown-acl-action")
    action = Action.permit if tokens[0] == "permit" else Action.deny
    p = _Parser(tokens, names, groups, line_no)
    return ParsedAce(action, p.parse(), p.attrs)


class _Parser:
    def __init__(
        self, tokens: list[str], names: dict[str, str], groups: GroupTable, line_no: int
    ) -> None:
        self.t = tokens
        self.i = 1
        self.names = names
        self.groups = groups
        self.line_no = line_no
        self.attrs = AceAttrs()

    # ------------------------------------------------------------------

    def parse(self) -> list[Match]:
        protos = self._protocol()
        src = self._address()
        results: list[Match] = []
        start = self.i  # a protocol-position group re-reads the rest of the ACE for each element
        for proto, spec_sport, spec_dport, spec_icmp in protos:
            self.i = start
            sport = self._ports(proto) if proto in (6, 17) else self._no_ports()
            dst = self._address()
            dport = PortSet.any()
            icmp: frozenset[int] | None = None
            if proto in (6, 17):
                dport = self._ports(proto)
            elif proto == 1:
                icmp = self._icmp()
            else:
                self._no_ports()
            self._trailer()
            if spec_sport is not None:  # a service-object element carries its own ports
                sport = sport.intersect(spec_sport)
            if spec_dport is not None:
                dport = dport.intersect(spec_dport)
            if spec_icmp is not None:
                icmp = spec_icmp
            results.append(
                Match(
                    src=src,
                    dst=dst,
                    proto=proto,
                    src_ports=sport,
                    dst_ports=dport,
                    icmp_types=icmp,
                )
            )
        return results

    # ------------------------------------------------------------------
    # Protocol position
    # ------------------------------------------------------------------

    def _protocol(self) -> list[_ProtoSpec]:
        tok = self._take("missing-protocol")
        if tok == "object":
            raise Unsupported("asa-8.3-object-operand")
        if tok == "object-group":
            name = self._take("missing-group-name")
            group = self.groups.lookup(name, (KIND_PROTOCOL, KIND_SERVICE_MULTI), self.line_no)
            if group.kind == KIND_PROTOCOL:
                return [(p, None, None, None) for p in sorted(group.protos, key=_proto_key)]
            return [(s.proto, s.sport, s.dport, s.icmp_types) for s in group.services]
        if tok.isdigit():
            number = int(tok)
            if number > 255:
                raise Unsupported("protocol-out-of-range")
            return [(None if number == 0 else number, None, None, None)]
        resolved = resolve_protocol(tok)
        if resolved is None:
            raise Unsupported("unknown-protocol-name")
        return [(None if resolved == 0 else resolved, None, None, None)]

    # ------------------------------------------------------------------
    # Address position
    # ------------------------------------------------------------------

    def _address(self) -> AddrSet:
        tok = self._take("missing-address")
        if tok in ("any", "any4"):
            return AddrSet.any()
        if tok in _UNSUPPORTED_OPERANDS:
            raise Unsupported(_UNSUPPORTED_OPERANDS[tok])
        if tok == "host":
            return AddrSet.from_host(parse_ipv4(self._take("missing-host"), self.names))
        if tok == "object-group":
            name = self._take("missing-group-name")
            group = self.groups.lookup(name, (KIND_NETWORK,), self.line_no)
            return group.addr
        addr = parse_ipv4(tok, self.names)
        mask_tok = self._take("missing-mask")
        if not looks_like_ipv4(mask_tok):
            raise Unsupported("missing-mask")
        prefix = parse_subnet_mask(mask_tok)
        return AddrSet.from_network(ipaddress.IPv4Network(f"{addr}/{prefix}", strict=False))

    # ------------------------------------------------------------------
    # Port / ICMP positions
    # ------------------------------------------------------------------

    def _ports(self, proto: int) -> PortSet:
        """Optional port operator or service group at the current position."""
        if self.i >= len(self.t):
            return PortSet.any()
        tok = self.t[self.i]
        if is_port_operator(tok):
            ps, self.i = parse_port_operator(self.t, self.i, _PROTO_LABEL[proto])
            return ps
        if tok == "object-group" and self.i + 1 < len(self.t):
            name = self.t[self.i + 1]
            if self.groups.kind_of(name) == KIND_SERVICE:
                group = self.groups.lookup(name, (KIND_SERVICE,), self.line_no)
                self.i += 2
                if proto not in group.ports:
                    raise Unsupported("service-group-protocol-mismatch")
                return group.ports[proto]
        return PortSet.any()

    def _no_ports(self) -> PortSet:
        if self.i < len(self.t) and is_port_operator(self.t[self.i]):
            raise Unsupported("port-operator-on-non-tcp-udp")
        return PortSet.any()

    def _icmp(self) -> frozenset[int] | None:
        if self.i >= len(self.t) or self.t[self.i] in ("log", "time-range", "inactive"):
            return None
        tok = self.t[self.i]
        if tok == "object-group":
            name = self._peek(1, "missing-group-name")
            group = self.groups.lookup(name, (KIND_ICMP,), self.line_no)
            self.i += 2
            return frozenset(group.icmp)
        if is_port_operator(tok):
            raise Unsupported("port-operator-on-non-tcp-udp")
        self.i += 1
        icmp_type = parse_icmp_type(tok)
        if self.i < len(self.t) and self.t[self.i].isdigit():
            raise Unsupported("icmp-code-keyword")
        return frozenset({icmp_type})

    # ------------------------------------------------------------------
    # Trailing attributes
    # ------------------------------------------------------------------

    def _trailer(self) -> None:
        attrs = AceAttrs()
        while self.i < len(self.t):
            tok = self.t[self.i]
            self.i += 1
            if tok == "log":
                attrs.log = True
                self._log_options(attrs)
            elif tok == "time-range":
                attrs.time_range = self._take("missing-time-range")
            elif tok == "inactive":
                attrs.inactive = True
            else:
                raise Unsupported("unexpected-token")
        self.attrs = attrs

    def _log_options(self, attrs: AceAttrs) -> None:
        if self.i < len(self.t):
            tok = self.t[self.i]
            if tok == "disable":
                attrs.log = False
                self.i += 1
                return
            if (tok.isdigit() and len(tok) == 1 and int(tok) <= 7) or tok in _LOG_LEVELS:
                attrs.log_level = tok
                self.i += 1
        if (
            self.i + 1 < len(self.t)
            and self.t[self.i] == "interval"
            and self.t[self.i + 1].isdigit()
        ):
            self.i += 2  # the interval is an attribute only and is not kept in the IR

    # ------------------------------------------------------------------

    def _take(self, reason: str) -> str:
        if self.i >= len(self.t):
            raise Unsupported(reason)
        tok = self.t[self.i]
        self.i += 1
        return tok

    def _peek(self, offset: int, reason: str) -> str:
        if self.i + offset >= len(self.t):
            raise Unsupported(reason)
        return self.t[self.i + offset]


def _proto_key(p: int | None) -> int:
    return -1 if p is None else p
