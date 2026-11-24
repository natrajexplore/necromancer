"""Read emitted PAN-OS ``set`` commands back into the IR (requirement 6.1).

The oracle compares the original policy with the IR read from the *emitted text*, not with the
IR the emitter started from. That is what makes the proof meaningful: an emitter bug shows up
as a different decision here. For the same reason the reader is strict: a command it does not
understand raises ``ParseError`` naming the line, so nothing in the candidate goes unread.

The result has ``dialect == panos``. Zones become interface names, the whole rulebase is one ACL
(``rulebase``) bound inbound to every zone, each rule carries its ``from``/``to`` zones, and the
interface management profiles become ``MgmtAccess`` entries. ``decide`` evaluates it with the
PAN-OS rules (``evaluate_panos``). Addresses are the pre-NAT addresses the rules match, so the
address space is ``mapped`` and static destination NAT rules are read as static ``NatRule``s.
"""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass, field

from necro.ir import (
    Action,
    AddressSpace,
    Binding,
    Dialect,
    Interface,
    Match,
    MgmtAccess,
    NatRule,
    NatType,
    ParseError,
    Policy,
    Route,
    Rule,
)
from necro.mgmt import SERVICE_NAMES
from necro.sets import AddrSet, PortSet
from necro.zones import RouteTable

RULEBASE = "rulebase"
_ANY = "any"
_PROTOCOLS = {"tcp": 6, "udp": 17}
_DENY_ACTIONS = ("deny", "drop", "reset-client", "reset-server", "reset-both")
# Predefined App-IDs for ICMP. They are broader than one ICMP type, so a rule that uses one is a
# widening of an exact type match (policy-semantics 6). They are read as the broad matches they
# are: ``ping`` is echo reply and echo request, ``icmp`` is every ICMP type (None).
_PREDEFINED_ICMP_APPS: dict[str, frozenset[int] | None] = {
    "ping": frozenset({0, 8}),
    "icmp": None,
}

Token = str | list[str]


def _tokenize(line: str, line_no: int) -> list[Token]:
    """Words, with ``"quoted text"`` kept whole and ``[ a b ]`` read as one list token."""
    tokens: list[Token] = []
    current: list[str] | None = None
    i, n = 0, len(line)
    while i < n:
        if line[i].isspace():
            i += 1
        elif line[i] == '"':
            chars: list[str] = []
            i += 1
            while i < n and line[i] != '"':
                if line[i] == "\\" and i + 1 < n:
                    i += 1
                chars.append(line[i])
                i += 1
            if i >= n:
                raise ParseError("unterminated-quote", "unterminated quoted text", line_no)
            i += 1
            (tokens if current is None else current).append("".join(chars))
        else:
            start = i
            while i < n and not line[i].isspace():
                i += 1
            word = line[start:i]
            if word == "[":
                current = []
            elif word == "]":
                if current is None:
                    raise ParseError("unbalanced-list", "']' without '['", line_no)
                tokens.append(current)
                current = None
            else:
                (tokens if current is None else current).append(word)
    if current is not None:
        raise ParseError("unbalanced-list", "'[' without ']'", line_no)
    return tokens


def _words(token: Token) -> list[str]:
    return [token] if isinstance(token, str) else token


def _starts(tokens: list[Token], *prefix: str) -> bool:
    return len(tokens) >= len(prefix) and all(t == p for t, p in zip(tokens, prefix, strict=False))


def _port_set(spec: str, line_no: int) -> PortSet:
    ranges: list[tuple[int, int]] = []
    try:
        for part in spec.split(","):
            lo, _, hi = part.partition("-")
            ranges.append((int(lo), int(hi or lo)))
    except ValueError as exc:
        raise ParseError("bad-port-list", f"bad port list {spec!r}", line_no) from exc
    return PortSet(ranges)


@dataclass
class _Service:
    proto: int
    sport: PortSet
    dport: PortSet


@dataclass
class _Reader:
    ports: dict[str, ipaddress.IPv4Interface | None] = field(default_factory=dict)
    port_profile: dict[str, str] = field(default_factory=dict)
    zones: dict[str, list[str]] = field(default_factory=dict)
    static_routes: list[tuple[ipaddress.IPv4Network, str, ipaddress.IPv4Address | None]] = field(
        default_factory=list
    )
    profiles: dict[str, dict[str, list[str] | bool]] = field(default_factory=dict)
    addresses: dict[str, ipaddress.IPv4Network] = field(default_factory=dict)
    groups: dict[str, list[str]] = field(default_factory=dict)
    services: dict[str, _Service] = field(default_factory=dict)
    apps: dict[str, tuple[str, int]] = field(default_factory=dict)  # name -> (kind, number)
    rules: dict[str, dict[str, Token]] = field(default_factory=dict)
    rule_lines: dict[str, int] = field(default_factory=dict)
    nat: dict[str, dict[str, Token]] = field(default_factory=dict)

    # -- statements -------------------------------------------------------------------------

    def feed(self, line_no: int, tokens: list[Token]) -> None:
        if not _starts(tokens, "set") or len(tokens) < 3:
            raise ParseError("unknown-panos-command", "not a 'set' command", line_no)
        rest = tokens[1:]
        if _starts(rest, "network", "interface", "ethernet"):
            self._interface(line_no, rest[3:])
        elif _starts(rest, "zone") and len(rest) == 5 and _starts(rest[2:], "network", "layer3"):
            self.zones.setdefault(str(rest[1]), []).extend(_words(rest[4]))
        elif _starts(rest, "network", "virtual-router") and len(rest) > 3:
            self._virtual_router(line_no, rest[3:])
        elif _starts(rest, "network", "profiles", "interface-management-profile"):
            self._profile(line_no, rest[3:])
        elif _starts(rest, "tag"):
            pass  # tag definitions are labels; a rule's own tags are read with the rule
        elif _starts(rest, "address") and len(rest) == 4 and rest[2] == "ip-netmask":
            self._address(line_no, str(rest[1]), str(rest[3]))
        elif _starts(rest, "address-group") and len(rest) == 4 and rest[2] == "static":
            self.groups[str(rest[1])] = _words(rest[3])
        elif _starts(rest, "service"):
            self._service(line_no, [str(t) for t in rest[1:]])
        elif _starts(rest, "application"):
            self._application(line_no, [str(t) for t in rest[1:]])
        elif _starts(rest, "rulebase", "security", "rules") and len(rest) == 6:
            self._attribute(self.rules, rest[3:])
            self.rule_lines.setdefault(str(rest[3]), line_no)
        elif _starts(rest, "rulebase", "nat", "rules") and len(rest) >= 6:
            self._attribute(self.nat, rest[3:])
        else:
            raise ParseError("unknown-panos-command", f"unrecognised command: {rest[:3]}", line_no)

    def _interface(self, line_no: int, rest: list[Token]) -> None:
        if len(rest) < 2 or rest[1] != "layer3":
            raise ParseError("unknown-panos-command", "unsupported interface command", line_no)
        port = str(rest[0])
        self.ports.setdefault(port, None)
        if len(rest) == 4 and rest[2] == "ip":
            try:
                self.ports[port] = ipaddress.IPv4Interface(str(rest[3]))
            except ValueError as exc:
                raise ParseError("bad-address", f"bad address {rest[3]!r}", line_no) from exc
        elif len(rest) == 4 and rest[2] == "interface-management-profile":
            self.port_profile[port] = str(rest[3])
        elif len(rest) != 2:
            raise ParseError("unknown-panos-command", "unsupported interface command", line_no)

    def _virtual_router(self, line_no: int, rest: list[Token]) -> None:
        if _starts(rest, "interface"):
            return  # which ports the virtual router owns carries no policy
        if not _starts(rest, "routing-table", "ip", "static-route") or len(rest) not in (8, 11):
            raise ParseError("unknown-panos-command", "unsupported routing command", line_no)
        body = rest[4:]
        shape = body[0] == "destination" and body[2] == "interface"
        if shape and len(body) == 7:
            shape = _starts(body[4:], "nexthop", "ip-address")
        if not shape:
            raise ParseError("bad-route", "cannot read static route", line_no)
        try:
            network = ipaddress.IPv4Network(str(body[1]))
            hop = ipaddress.IPv4Address(str(body[6])) if len(body) == 7 else None
        except ValueError as exc:
            raise ParseError("bad-route", "cannot read static route", line_no) from exc
        self.static_routes.append((network, str(body[3]), hop))

    def _profile(self, line_no: int, rest: list[Token]) -> None:
        if len(rest) != 3:
            raise ParseError("bad-profile", "unsupported management profile command", line_no)
        name, key, value = str(rest[0]), str(rest[1]), rest[2]
        entry = self.profiles.setdefault(name, {})
        if key in SERVICE_NAMES and value in ("yes", "no"):
            entry[key] = value == "yes"
        elif key == "permitted-ip":
            entry[key] = _words(value)
        else:
            raise ParseError("bad-profile", f"unsupported profile setting {key!r}", line_no)

    def _address(self, line_no: int, name: str, cidr: str) -> None:
        try:
            self.addresses[name] = ipaddress.IPv4Network(cidr, strict=False)
        except ValueError as exc:
            raise ParseError("bad-address", f"bad address {cidr!r}", line_no) from exc

    def _service(self, line_no: int, words: list[str]) -> None:
        shape = len(words) in (5, 7) and words[1] == "protocol" and words[3] == "port"
        if len(words) == 7:
            shape = shape and words[5] == "source-port"
        if not shape or words[2] not in _PROTOCOLS:
            raise ParseError("bad-service", "unsupported service definition", line_no)
        sport = _port_set(words[6], line_no) if len(words) == 7 else PortSet.any()
        self.services[words[0]] = _Service(
            _PROTOCOLS[words[2]], sport, _port_set(words[4], line_no)
        )

    def _application(self, line_no: int, words: list[str]) -> None:
        try:
            tail = words[words.index("default") + 1 :]
            if tail[0] == "ident-by-icmp-type" and tail[1] == "type":
                self.apps[words[0]] = ("icmp", int(tail[2]))
            elif tail[0] == "ident-by-ip-protocol":
                self.apps[words[0]] = ("ip", int(tail[1]))
            else:
                raise ParseError("bad-application", "unsupported identification", line_no)
        except (ValueError, IndexError) as exc:
            raise ParseError("bad-application", "cannot read application", line_no) from exc

    @staticmethod
    def _attribute(table: dict[str, dict[str, Token]], rest: list[Token]) -> None:
        value: Token = rest[2] if len(rest) == 3 else [str(t) for t in rest[2:]]
        table.setdefault(str(rest[0]), {})[str(rest[1])] = value

    # -- assembly ---------------------------------------------------------------------------

    def _address_set(self, name: str, seen: tuple[str, ...] = ()) -> AddrSet:
        if name == _ANY:
            return AddrSet.any()
        if name in self.addresses:
            return AddrSet.from_network(self.addresses[name])
        if name in self.groups and name not in seen:
            result = AddrSet()
            for member in self.groups[name]:
                result = result.union(self._address_set(member, (*seen, name)))
            return result
        raise ParseError("undefined-address", f"address object {name!r} is not defined (or loops)")

    def _addresses(self, token: Token | None) -> AddrSet:
        result = AddrSet()
        for name in _words(_ANY if token is None else token):
            result = result.union(self._address_set(name))
        return result

    def _matches(self, name: str, attrs: dict[str, Token]) -> list[Match]:
        src, dst = self._addresses(attrs.get("source")), self._addresses(attrs.get("destination"))
        apps = _words(attrs.get("application", _ANY))
        services = _words(attrs.get("service", _ANY))
        if _ANY in apps:
            found: list[_Service | None] = [None] if _ANY in services else []
            for service in (s for s in services if s != _ANY):
                if service not in self.services:
                    raise ParseError("undefined-service", f"service {service!r} in {name}")
                found.append(self.services[service])
            return [
                Match(
                    src=src,
                    dst=dst,
                    proto=s.proto if s else None,
                    src_ports=s.sport if s else PortSet.any(),
                    dst_ports=s.dport if s else PortSet.any(),
                )
                for s in found
            ]
        if services != [_ANY]:
            raise ParseError("unsupported-combination", f"{name} mixes applications and services")
        icmp_types: set[int] = set()
        icmp_any = False
        protocols: list[int] = []
        for app in apps:
            if app in _PREDEFINED_ICMP_APPS:
                types = _PREDEFINED_ICMP_APPS[app]
                if types is None:
                    icmp_any = True
                else:
                    icmp_types |= types
                continue
            if app not in self.apps:
                raise ParseError("undefined-application", f"application {app!r} in {name}")
            kind, number = self.apps[app]
            if kind == "icmp":
                icmp_types.add(number)
            elif number not in protocols:
                protocols.append(number)
        matches: list[Match] = []
        if icmp_any and 1 not in protocols:
            matches.append(Match(src=src, dst=dst, proto=1))
        elif icmp_types and 1 not in protocols:
            matches.append(Match(src=src, dst=dst, proto=1, icmp_types=frozenset(icmp_types)))
        matches += [Match(src=src, dst=dst, proto=n) for n in protocols]
        return matches

    def _rules(self, name: str, attrs: dict[str, Token]) -> list[Rule]:
        line_no = self.rule_lines.get(name, 0)
        action = attrs.get("action")
        if action != "allow" and action not in _DENY_ACTIONS:
            raise ParseError("bad-rule", f"rule {name} has no valid action", line_no)
        from_zones = tuple(z for z in _words(attrs.get("from", _ANY)) if z != _ANY)
        to_zones = tuple(z for z in _words(attrs.get("to", _ANY)) if z != _ANY)
        description = attrs.get("description", "")
        matches = self._matches(name, attrs)
        return [
            Rule(
                id=name if len(matches) == 1 else f"{name}/{index}",
                action=Action.permit if action == "allow" else Action.deny,
                match=match,
                inactive=attrs.get("disabled") == "yes",
                remark=description if isinstance(description, str) else "",
                source_line=line_no,
                from_zones=from_zones,
                to_zones=to_zones,
            )
            for index, match in enumerate(matches, start=1)
        ]

    def _mgmt(self, zone_of_port: dict[str, str]) -> list[MgmtAccess]:
        access: list[MgmtAccess] = []
        for port, profile_name in self.port_profile.items():
            profile = self.profiles.get(profile_name)
            if profile is None:
                raise ParseError("undefined-profile", f"management profile {profile_name!r}")
            listed = profile.get("permitted-ip")
            permitted = AddrSet.any()
            if isinstance(listed, list):
                permitted = AddrSet.from_cidr_list(
                    [ipaddress.IPv4Network(item, strict=False) for item in listed]
                )
            access += [
                MgmtAccess(proto=service, src_addr=permitted, interface=zone_of_port.get(port, ""))
                for service in SERVICE_NAMES
                if profile.get(service) is True
            ]
        return access

    def _nat_rules(self, policy: Policy) -> list[NatRule]:
        table = RouteTable(policy)
        rules: list[NatRule] = []
        for name, attrs in self.nat.items():
            translated = attrs.get("destination-translation")
            static_dnat = (
                attrs.get("source") == _ANY
                and attrs.get("service") == _ANY
                and isinstance(translated, list)
                and len(translated) == 2
                and translated[0] == "translated-address"
            )
            if not static_dnat or not isinstance(translated, list):
                raise ParseError("unsupported-nat-rule", f"NAT rule {name} is not a static DNAT")
            real = ipaddress.IPv4Address(translated[1])
            owner = table.to_zone(real)
            rules.append(
                NatRule(
                    nat_type=NatType.static,
                    real_interface="" if owner in ("self", "any") else owner,
                    mapped_interface=_words(attrs.get("from", ""))[0],
                    real_addr=AddrSet.from_host(real),
                    mapped_addr=self._addresses(attrs.get("destination")),
                )
            )
        return rules

    def build(self, text: str) -> Policy:
        zone_of_port = {p: z for z, ports in self.zones.items() for p in ports}
        interfaces = [
            Interface(hw_name=port, nameif=zone, ip_address=self.ports.get(port))
            for zone, ports in self.zones.items()
            for port in ports
        ]
        interfaces += [
            Interface(hw_name=port, nameif="", ip_address=ip)
            for port, ip in self.ports.items()
            if port not in zone_of_port
        ]
        policy = Policy(
            dialect=Dialect.panos,
            address_space=AddressSpace.mapped,
            interfaces=interfaces,
            routes=[
                Route(network=n, next_hop=hop, interface=zone_of_port.get(port, ""))
                for n, port, hop in self.static_routes
            ],
            acls={RULEBASE: [r for name, a in self.rules.items() for r in self._rules(name, a)]},
            bindings=[
                Binding(acl_name=RULEBASE, interface=zone, direction="in") for zone in self.zones
            ],
            mgmt_access=self._mgmt(zone_of_port),
            input_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        )
        policy.nat_rules = self._nat_rules(policy)
        return policy


def read_panos(text: str) -> Policy:
    """Parse emitted PAN-OS ``set`` commands into a ``Policy`` with ``dialect == panos``."""
    reader = _Reader()
    for line_no, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if line:
            reader.feed(line_no, _tokenize(line, line_no))
    return reader.build(text)
