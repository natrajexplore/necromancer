"""IOS 12.x ACE parsing: standard and extended entries (policy-semantics section 3).

IOS uses wildcard masks, never subnet masks. Constructs the v1 model can't represent (reflexive
ACLs, QoS match keywords, ``fragments``, ICMP codes, non-contiguous wildcards, ...) raise
``Unsupported`` with the reason code the negative fixtures expect.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from necro.ir import Action, Match
from necro.masks import NonContiguousMaskError, wildcard_to_prefix_len
from necro.names import resolve_protocol
from necro.parsers.cisco_common import (
    Unsupported,
    is_port_operator,
    looks_like_ipv4,
    parse_icmp_type,
    parse_port_operator,
)
from necro.sets import AddrSet, PortSet

_UNSUPPORTED_KEYWORDS = {
    "fragments": "fragments-keyword",
    "dscp": "qos-match-keyword",
    "precedence": "qos-match-keyword",
    "tos": "qos-match-keyword",
    "reflect": "reflexive-acl",
    "evaluate": "reflexive-acl",
    "option": "option-keyword",
    "ttl": "ttl-keyword",
    "ack": "tcp-flag-keyword",
    "rst": "tcp-flag-keyword",
    "syn": "tcp-flag-keyword",
    "fin": "tcp-flag-keyword",
    "psh": "tcp-flag-keyword",
    "urg": "tcp-flag-keyword",
    "match-any": "tcp-flag-keyword",
    "match-all": "tcp-flag-keyword",
}
_PROTO_LABEL = {6: "tcp", 17: "udp"}


@dataclass
class IosAce:
    action: Action
    match: Match
    log: bool = False
    time_range: str = ""


def parse_ios_ace(tokens: list[str], *, standard: bool) -> IosAce:
    """Parse ``permit|deny ...`` (tokens start at the action)."""
    if not tokens or tokens[0] not in ("permit", "deny"):
        raise Unsupported("unknown-acl-action")
    action = Action.permit if tokens[0] == "permit" else Action.deny
    p = _Parser(tokens)
    match = p.standard() if standard else p.extended()
    return IosAce(action, match, p.log, p.time_range)


class _Parser:
    def __init__(self, tokens: list[str]) -> None:
        self.t = tokens
        self.i = 1
        self.log = False
        self.time_range = ""

    # ------------------------------------------------------------------

    def standard(self) -> Match:
        src = self._address(allow_bare_host=True)
        self._trailer(proto=None)
        return Match(src=src)

    def extended(self) -> Match:
        proto = self._protocol()
        src = self._address()
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
        established = self._trailer(proto)
        return Match(
            src=src,
            dst=dst,
            proto=proto,
            src_ports=sport,
            dst_ports=dport,
            icmp_types=icmp,
            established=established,
        )

    # ------------------------------------------------------------------

    def _take(self, reason: str) -> str:
        if self.i >= len(self.t):
            raise Unsupported(reason)
        tok = self.t[self.i]
        self.i += 1
        return tok

    def _protocol(self) -> int | None:
        tok = self._take("missing-protocol").lower()
        if tok == "object-group":
            raise Unsupported("ios-object-group")
        if tok.isdigit():
            number = int(tok)
            if number > 255:
                raise Unsupported("protocol-out-of-range")
            return None if number == 0 else number
        resolved = resolve_protocol(tok)
        if resolved is None:
            raise Unsupported("unknown-protocol-name")
        return None if resolved == 0 else resolved

    def _address(self, *, allow_bare_host: bool = False) -> AddrSet:
        tok = self._take("missing-address")
        if tok == "any":
            return AddrSet.any()
        if tok == "object-group":
            raise Unsupported("ios-object-group")
        if ":" in tok:
            raise Unsupported("ipv6")
        if tok == "host":
            return AddrSet.from_host(_ipv4(self._take("missing-host")))
        addr = _ipv4(tok)
        if self.i < len(self.t) and looks_like_ipv4(self.t[self.i]):
            wildcard = self.t[self.i]
            self.i += 1
            try:
                prefix = wildcard_to_prefix_len(wildcard)
            except NonContiguousMaskError:
                raise Unsupported("non-contiguous-wildcard") from None
            except ValueError:
                raise Unsupported("bad-wildcard") from None
            return AddrSet.from_network(ipaddress.IPv4Network(f"{addr}/{prefix}", strict=False))
        if allow_bare_host:
            return AddrSet.from_host(addr)  # standard ACL: a bare address means host
        raise Unsupported("missing-wildcard")

    def _ports(self, proto: int) -> PortSet:
        if self.i < len(self.t) and is_port_operator(self.t[self.i]):
            ps, self.i = parse_port_operator(self.t, self.i, _PROTO_LABEL[proto])
            return ps
        return PortSet.any()

    def _no_ports(self) -> PortSet:
        if self.i < len(self.t) and is_port_operator(self.t[self.i]):
            raise Unsupported("port-operator-on-non-tcp-udp")
        return PortSet.any()

    def _icmp(self) -> frozenset[int] | None:
        if self.i >= len(self.t):
            return None
        tok = self.t[self.i]
        if tok in ("log", "log-input", "time-range") or tok in _UNSUPPORTED_KEYWORDS:
            return None
        if is_port_operator(tok):
            raise Unsupported("port-operator-on-non-tcp-udp")
        self.i += 1
        icmp_type = parse_icmp_type(tok)
        if self.i < len(self.t) and self.t[self.i].isdigit():
            raise Unsupported("icmp-code-keyword")
        return frozenset({icmp_type})

    def _trailer(self, proto: int | None) -> bool:
        established = False
        while self.i < len(self.t):
            tok = self.t[self.i]
            self.i += 1
            if tok == "established":
                if proto != 6:
                    raise Unsupported("established-on-non-tcp")
                established = True
            elif tok in ("log", "log-input"):
                self.log = True
            elif tok == "time-range":
                self.time_range = self._take("missing-time-range")
            elif tok in _UNSUPPORTED_KEYWORDS:
                raise Unsupported(_UNSUPPORTED_KEYWORDS[tok])
            else:
                raise Unsupported("unexpected-token")
        return established


def _ipv4(token: str) -> ipaddress.IPv4Address:
    try:
        return ipaddress.IPv4Address(token)
    except ValueError:
        raise Unsupported("bad-address") from None
