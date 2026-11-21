"""Shared tokenizer helpers, operand parsing and line ledger for the Cisco parsers.

Parsers see already-redacted text only (see necro.redact). Everything here is linear-time:
lines are split on whitespace, no backtracking regexes.

Two kinds of failure are used throughout the parsers:
  - ``Unsupported(reason)``: one statement can't be migrated. The parser records an
    ``UnparsedLine`` for it and carries on (requirement 1.4).
  - ``necro.ir.ParseError``: a structural problem that makes the whole parse meaningless
    (group cycle, undefined group).
"""

from __future__ import annotations

import ipaddress
import re
from typing import Literal

from necro.ir import LineRecord, UnparsedLine
from necro.masks import NonContiguousMaskError, subnet_to_prefix_len
from necro.names import resolve_icmp_type, resolve_port
from necro.sets import PortSet

Classification = Literal["migrated", "not-policy", "management-plane", "out-of-scope", "unparsed"]

# ICMP keywords that name a type *and code* (IOS/ASA). They are not in the type table and are not
# modelled in v1 (policy-semantics section 3), so they must never be guessed as a type.
ICMP_CODE_KEYWORDS: frozenset[str] = frozenset(
    {
        "administratively-prohibited",
        "dod-host-prohibited",
        "dod-net-prohibited",
        "fragments-needed",
        "general-parameter-problem",
        "host-isolated",
        "host-precedence-unreachable",
        "host-redirect",
        "host-tos-redirect",
        "host-tos-unreachable",
        "host-unknown",
        "host-unreachable",
        "net-redirect",
        "net-tos-redirect",
        "net-tos-unreachable",
        "net-unreachable",
        "network-unknown",
        "no-room-for-option",
        "option-missing",
        "packet-too-big",
        "parameter-problem-code",
        "port-unreachable",
        "precedence-unreachable",
        "protocol-unreachable",
        "reassembly-timeout",
        "redirect-code",
        "router-advertisement-code",
        "source-route-failed",
        "time-exceeded-code",
        "ttl-exceeded",
    }
)

_PORT_OPERATORS = frozenset({"eq", "neq", "lt", "gt", "range"})


class Unsupported(Exception):
    """A single statement can't be migrated; ``reason`` is the machine-readable code."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# ---------------------------------------------------------------------------
# Line handling
# ---------------------------------------------------------------------------


def split_lines(text: str) -> list[str]:
    """Split config text into lines on \\n, \\r\\n or \\r. A final newline adds no extra line."""
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def is_indented(line: str) -> bool:
    return bool(line) and line[0] in " \t"


def is_comment_or_blank(line: str) -> bool:
    stripped = line.strip()
    return stripped == "" or stripped[0] in "!:"


# ---------------------------------------------------------------------------
# Line ledger: every line is classified exactly once (requirement 1.9, property P14)
# ---------------------------------------------------------------------------


class LineLedger:
    """Collects one ``LineRecord`` per input line and the matching ``UnparsedLine`` entries."""

    def __init__(self, lines: list[str]) -> None:
        self._lines = lines
        self._records: dict[int, LineRecord] = {}
        self._unparsed: dict[int, UnparsedLine] = {}

    def is_marked(self, line_no: int) -> bool:
        return line_no in self._records

    def record(self, line_no: int) -> LineRecord | None:
        """The current classification of a line, or None if it has not been classified yet."""
        return self._records.get(line_no)

    def mark(
        self,
        line_no: int,
        classification: Classification,
        *,
        relevant: bool = False,
        reason: str = "",
    ) -> None:
        """Classify a line. Marking a line twice is a parser bug and raises."""
        if line_no in self._records:
            raise ValueError(f"line {line_no} classified twice")
        self._set(line_no, classification, relevant, reason)

    def reclassify(
        self,
        line_no: int,
        classification: Classification,
        *,
        relevant: bool = False,
        reason: str = "",
    ) -> None:
        """Replace an earlier classification (used when a later pass learns more)."""
        self._unparsed.pop(line_no, None)
        self._set(line_no, classification, relevant, reason)

    def unparsed(
        self,
        line_no: int,
        reason: str,
        *,
        relevant: bool = True,
        classification: Literal["unparsed", "out-of-scope"] = "unparsed",
        replace: bool = False,
    ) -> None:
        """Record a line that was not migrated. Never silent: it also gets an UnparsedLine."""
        if replace:
            self.reclassify(line_no, classification, relevant=relevant, reason=reason)
        else:
            self.mark(line_no, classification, relevant=relevant, reason=reason)

    def _set(
        self, line_no: int, classification: Classification, relevant: bool, reason: str
    ) -> None:
        text = self._lines[line_no - 1].rstrip()
        self._records[line_no] = LineRecord(
            line_no=line_no,
            text=text,
            classification=classification,
            security_relevant=relevant,
            reason=reason,
        )
        if classification in ("unparsed", "out-of-scope"):
            self._unparsed[line_no] = UnparsedLine(
                line_no=line_no, text=text, reason=reason, security_relevant=relevant
            )

    def finalize(self) -> tuple[list[LineRecord], list[UnparsedLine]]:
        """Return records for lines 1..N in order. A line nobody classified is flagged, not lost."""
        for line_no in range(1, len(self._lines) + 1):
            if line_no not in self._records:
                self._set(line_no, "unparsed", True, "unclassified")
        records = [self._records[n] for n in range(1, len(self._lines) + 1)]
        unparsed = [self._unparsed[n] for n in sorted(self._unparsed)]
        return records, unparsed


# ---------------------------------------------------------------------------
# Operand parsing
# ---------------------------------------------------------------------------


def parse_ipv4(token: str, names: dict[str, str] | None = None) -> ipaddress.IPv4Address:
    """Parse a dotted-quad or a ``name`` alias. IPv6 and unknown labels are Unsupported."""
    if ":" in token:
        raise Unsupported("ipv6")
    try:
        return ipaddress.IPv4Address(token)
    except ValueError:
        pass
    if names is not None and token in names:
        return ipaddress.IPv4Address(names[token])
    raise Unsupported("undefined-name")


def looks_like_ipv4(token: str) -> bool:
    parts = token.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


def parse_subnet_mask(token: str) -> int:
    """Prefix length of a PIX/ASA subnet mask (255.255.255.0). Wildcards are not accepted."""
    try:
        return subnet_to_prefix_len(token)
    except NonContiguousMaskError:
        raise Unsupported("non-contiguous-mask") from None
    except ValueError:
        raise Unsupported("bad-mask") from None


def parse_port_value(proto_name: str, token: str) -> int:
    """A port number or a protocol-keyed Cisco port name. An unknown name is never guessed."""
    if token.isdigit():
        value = int(token)
        if value > 65535:
            raise Unsupported("port-out-of-range")
        return value
    port = resolve_port(proto_name, token)
    if port is None:
        raise Unsupported("unknown-port-name")
    return port


def parse_port_operator(tokens: list[str], i: int, proto_name: str) -> tuple[PortSet, int]:
    """Parse ``eq|neq|lt|gt|range`` at tokens[i]. Returns the PortSet and the next index."""
    if i >= len(tokens) or tokens[i] not in _PORT_OPERATORS:
        raise Unsupported("expected-port-operator")
    op = tokens[i]
    if op == "range":
        if i + 2 >= len(tokens):
            raise Unsupported("truncated-port-range")
        lo = parse_port_value(proto_name, tokens[i + 1])
        hi = parse_port_value(proto_name, tokens[i + 2])
        if lo > hi:
            raise Unsupported("inverted-port-range")
        return PortSet.from_range(lo, hi), i + 3
    if i + 1 >= len(tokens):
        raise Unsupported("truncated-port-operator")
    port = parse_port_value(proto_name, tokens[i + 1])
    if op == "eq":
        return PortSet.from_eq(port), i + 2
    if op == "neq":
        return PortSet.from_neq(port), i + 2
    if op == "lt":
        return PortSet.from_lt(port), i + 2
    return PortSet.from_gt(port), i + 2


def is_port_operator(token: str) -> bool:
    return token in _PORT_OPERATORS


def parse_icmp_type(token: str) -> int:
    """An ICMP type number or Cisco type name. Code keywords are unsupported in v1."""
    if token.isdigit():
        value = int(token)
        if value > 255:
            raise Unsupported("icmp-type-out-of-range")
        return value
    if token in ICMP_CODE_KEYWORDS:
        raise Unsupported("icmp-code-keyword")
    number = resolve_icmp_type(token)
    if number is None:
        raise Unsupported("unknown-icmp-name")
    return number


_VERSION_RE = re.compile(r"^(\d+)\.(\d+)")


def version_at_least(os_version: str, major: int, minor: int) -> bool:
    """True when ``os_version`` (e.g. ``8.2(5)``) is >= major.minor. Unknown versions are False."""
    m = _VERSION_RE.match(os_version)
    if m is None:
        return False
    return (int(m.group(1)), int(m.group(2))) >= (major, minor)


def parse_interface_pair(token: str) -> tuple[str, ...]:
    """Parse ``(inside)`` or ``(inside,outside)`` into its interface names."""
    if len(token) < 3 or token[0] != "(" or token[-1] != ")":
        raise Unsupported("bad-interface-pair")
    parts = tuple(p.strip() for p in token[1:-1].split(","))
    if not all(parts):
        raise Unsupported("bad-interface-pair")
    return parts
