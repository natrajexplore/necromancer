"""object-group collection, expansion, cycle and undefined-reference detection (PIX/ASA).

Groups are collected while the file is walked, then resolved together once every ``name`` alias
is known. Expansion is recursive over ``group-object``. A cycle raises ``ParseError`` naming the
path (``A_GROUP -> B_GROUP -> A_GROUP``); an undefined reference raises ``ParseError`` with the
line number of the reference (requirement 1.5, policy-semantics section 1.6).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from necro.ir import ObjectGroupInfo, ParseError
from necro.names import resolve_protocol
from necro.parsers.cisco_common import (
    LineLedger,
    Unsupported,
    parse_icmp_type,
    parse_ipv4,
    parse_port_operator,
    parse_subnet_mask,
)
from necro.sets import AddrSet, PortSet

KIND_NETWORK = "network"
KIND_SERVICE = "service"  # object-group service NAME tcp|udp|tcp-udp (port position)
KIND_SERVICE_MULTI = "service-multi"  # object-group service NAME (protocol position)
KIND_PROTOCOL = "protocol"
KIND_ICMP = "icmp-type"

_PORT_PROTOS: dict[str, tuple[int, ...]] = {"tcp": (6,), "udp": (17,), "tcp-udp": (6, 17)}
_PROTO_NAME = {6: "tcp", 17: "udp"}


@dataclass(frozen=True)
class SvcSpec:
    """One element of a protocol-position group: a protocol with optional ports or ICMP types."""

    proto: int | None
    sport: PortSet
    dport: PortSet
    icmp_types: frozenset[int] | None = None


@dataclass
class Group:
    name: str
    kind: str
    port_proto: str  # "", "tcp", "udp" or "tcp-udp" (service groups only)
    line: int
    members: list[tuple[int, list[str]]] = field(default_factory=list)
    refs: list[tuple[str, int]] = field(default_factory=list)
    # direct contributions
    addr: AddrSet = field(default_factory=AddrSet)
    ports: dict[int, PortSet] = field(default_factory=dict)
    protos: set[int | None] = field(default_factory=set)
    icmp: set[int] = field(default_factory=set)
    services: list[SvcSpec] = field(default_factory=list)
    expanded: bool = False


class GroupTable:
    """Collects groups, resolves their members and expands nesting."""

    def __init__(self) -> None:
        self.groups: dict[str, Group] = {}
        self.used: set[str] = set()  # groups an ACE refers to

    def define(self, name: str, kind: str, port_proto: str, line: int) -> bool:
        """Open (or re-open) a group. Returns False when a re-open changes its kind."""
        existing = self.groups.get(name)
        if existing is None:
            self.groups[name] = Group(name=name, kind=kind, port_proto=port_proto, line=line)
            return True
        return existing.kind == kind and existing.port_proto == port_proto

    def add_member(self, name: str, line_no: int, tokens: list[str]) -> None:
        self.groups[name].members.append((line_no, tokens))

    # ------------------------------------------------------------------
    # Resolution
    # ------------------------------------------------------------------

    def resolve(self, names: dict[str, str], ledger: LineLedger) -> None:
        """Parse every member line, then expand nesting. Raises ParseError on cycle/undefined."""
        for group in self.groups.values():
            for line_no, tokens in group.members:
                self._resolve_member(group, line_no, tokens, names, ledger)
        for group in self.groups.values():
            self._expand(group.name, [])

    def _resolve_member(
        self,
        group: Group,
        line_no: int,
        tokens: list[str],
        names: dict[str, str],
        ledger: LineLedger,
    ) -> None:
        keyword = tokens[0].lower()
        if keyword == "description":
            ledger.mark(line_no, "migrated", relevant=False)
            return
        try:
            if keyword == "group-object":
                if len(tokens) != 2:
                    raise Unsupported("bad-group-object")
                group.refs.append((tokens[1], line_no))
            elif group.kind == KIND_NETWORK and keyword == "network-object":
                group.addr = group.addr.union(_network_object(tokens, names))
            elif group.kind == KIND_SERVICE and keyword == "port-object":
                self._port_object(group, tokens)
            elif group.kind == KIND_SERVICE_MULTI and keyword == "service-object":
                group.services.append(_service_object(tokens))
            elif group.kind == KIND_PROTOCOL and keyword == "protocol-object":
                group.protos.add(_protocol_number(tokens))
            elif group.kind == KIND_ICMP and keyword == "icmp-object":
                if len(tokens) != 2:
                    raise Unsupported("bad-icmp-object")
                group.icmp.add(parse_icmp_type(tokens[1]))
            else:
                raise Unsupported("unknown-group-member")
        except Unsupported as exc:
            ledger.unparsed(line_no, exc.reason)
            return
        ledger.mark(line_no, "migrated", relevant=True)

    @staticmethod
    def _port_object(group: Group, tokens: list[str]) -> None:
        for proto in _PORT_PROTOS[group.port_proto]:
            ps, end = parse_port_operator(tokens, 1, _PROTO_NAME[proto])
            if end != len(tokens):
                raise Unsupported("trailing-tokens")
            group.ports[proto] = group.ports.get(proto, PortSet()).union(ps)

    # ------------------------------------------------------------------
    # Expansion
    # ------------------------------------------------------------------

    def _expand(self, name: str, stack: list[str]) -> Group:
        group = self.groups[name]
        if group.expanded:
            return group
        stack = [*stack, name]
        for ref, line_no in group.refs:
            if ref in stack:
                path = [*stack[stack.index(ref) :], ref]
                raise ParseError("group-cycle", "object-group cycle: " + " -> ".join(path), line_no)
            child = self.groups.get(ref)
            if child is None:
                raise ParseError("undefined-group", f"undefined object-group {ref}", line_no)
            if child.kind != group.kind or not _proto_compatible(group, child):
                raise ParseError(
                    "group-kind-mismatch",
                    f"object-group {ref} ({child.kind}) cannot nest in {name} ({group.kind})",
                    line_no,
                )
            self._expand(ref, stack)
            _merge(group, child)
        group.expanded = True
        return group

    def lookup(self, name: str, kinds: tuple[str, ...], line_no: int) -> Group:
        """Fetch an expanded group for an ACE. Undefined is a ParseError at ``line_no``."""
        group = self.groups.get(name)
        if group is None:
            raise ParseError("undefined-group", f"undefined object-group {name}", line_no)
        self.used.add(name)
        if group.kind not in kinds:
            raise Unsupported("group-kind-mismatch")
        return group

    def info(self) -> list[ObjectGroupInfo]:
        """Every group with its usage: used by an ACE, or nested in a group that is."""
        used: set[str] = set()
        stack = [n for n in self.used if n in self.groups]
        while stack:
            name = stack.pop()
            if name in used:
                continue
            used.add(name)
            stack.extend(ref for ref, _ in self.groups[name].refs if ref in self.groups)
        groups = sorted(self.groups.values(), key=lambda g: (g.line, g.name))
        return [
            ObjectGroupInfo(name=g.name, kind=g.kind, line=g.line, used=g.name in used)
            for g in groups
        ]

    def kind_of(self, name: str) -> str | None:
        group = self.groups.get(name)
        return None if group is None else group.kind


def _proto_compatible(parent: Group, child: Group) -> bool:
    if parent.kind != KIND_SERVICE:
        return True
    return set(_PORT_PROTOS[child.port_proto]) <= set(_PORT_PROTOS[parent.port_proto])


def _merge(parent: Group, child: Group) -> None:
    parent.addr = parent.addr.union(child.addr)
    for proto, ps in child.ports.items():
        parent.ports[proto] = parent.ports.get(proto, PortSet()).union(ps)
    parent.protos |= child.protos
    parent.icmp |= child.icmp
    parent.services.extend(s for s in child.services if s not in parent.services)


# ---------------------------------------------------------------------------
# Member parsers
# ---------------------------------------------------------------------------


def _network_object(tokens: list[str], names: dict[str, str]) -> AddrSet:
    if len(tokens) >= 2 and tokens[1] == "object":
        raise Unsupported("asa-8.3-object-reference")
    if len(tokens) == 3 and tokens[1] == "host":
        return AddrSet.from_host(parse_ipv4(tokens[2], names))
    if len(tokens) == 3:
        addr = parse_ipv4(tokens[1], names)
        prefix = parse_subnet_mask(tokens[2])
        return AddrSet.from_network(ipaddress.IPv4Network(f"{addr}/{prefix}", strict=False))
    raise Unsupported("bad-network-object")


def _protocol_number(tokens: list[str]) -> int | None:
    if len(tokens) != 2:
        raise Unsupported("bad-protocol-object")
    token = tokens[1].lower()
    if token.isdigit() and int(token) <= 255:
        return int(token)
    number = resolve_protocol(token)
    if number is None:
        raise Unsupported("unknown-protocol-name")
    return None if number == 0 else number  # "ip" means any protocol


def _service_object(tokens: list[str]) -> SvcSpec:
    if len(tokens) < 2:
        raise Unsupported("bad-service-object")
    if tokens[1] == "object":
        raise Unsupported("asa-8.3-object-reference")
    proto = _protocol_number(tokens[:2])
    if proto in (6, 17):
        proto_name = "tcp" if proto == 6 else "udp"
        sport = PortSet.any()
        dport = PortSet.any()
        i = 2
        while i < len(tokens):
            if tokens[i] == "source":
                sport, i = parse_port_operator(tokens, i + 1, proto_name)
            elif tokens[i] == "destination":
                dport, i = parse_port_operator(tokens, i + 1, proto_name)
            else:
                raise Unsupported("bad-service-object")
        return SvcSpec(proto, sport, dport)
    if proto == 1:
        if len(tokens) == 2:
            return SvcSpec(1, PortSet.any(), PortSet.any(), None)
        if len(tokens) == 3:
            return SvcSpec(1, PortSet.any(), PortSet.any(), frozenset({parse_icmp_type(tokens[2])}))
        raise Unsupported("bad-service-object")
    if len(tokens) != 2:
        raise Unsupported("bad-service-object")
    return SvcSpec(proto, PortSet.any(), PortSet.any(), None)
