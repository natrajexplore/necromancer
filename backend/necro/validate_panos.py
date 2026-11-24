"""Static checks of an emitted PAN-OS candidate config: gate G3 (requirement 1.4).

The checks read the ``set`` lines themselves, not the IR from ``panos_reader``: the reader stops at
the first undefined reference, while a reviewer needs every problem at once. Both share one
tokenizer, so quoting and ``[ ... ]`` lists are read the same way.

Errors block the verdict; warnings are listed and do not. "any to any" means an allow rule from
any zone to any zone with any source, destination, application and service: it needs a ledger
entry, referenced by the rule's ``necro:<entry id>`` tag. A broad allow between two named zones
(how an implicit security-level permit is reproduced) is a warning.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Literal

from pydantic import BaseModel

from necro.emitters.panos_names import ZONE_MAX_LEN
from necro.gate_models import Check
from necro.ir import ParseError
from necro.ledger import LedgerEntry
from necro.parsers.panos_reader import Token, tokenize

ANY = "any"
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
PORT = re.compile(r"^ethernet[0-9]+/[0-9]+(\.[0-9]+)?$")  # a port name, not a user-chosen name
TAG_MAX_LEN = 127
DENY_ACTIONS = frozenset({"deny", "drop", "reset-client", "reset-server", "reset-both"})
RULE_FIELDS = ("from", "to", "source", "destination", "application", "service", "action")
BROAD_APPS = frozenset({"ping", "icmp"})  # predefined App-IDs broader than one ICMP type

# Namespaces whose members PAN-OS keeps in one name space.
_SHARED = {"address": "address", "address-group": "address", "service": "service",
           "service-group": "service", "application": "application"}  # fmt: skip

CHECK_IDS = (
    "g3-syntax",
    "g3-name-valid",
    "g3-name-unique",
    "g3-reference",
    "g3-empty-group",
    "g3-rule-fields",
    "g3-final-deny",
    "g3-any-any",
    "g3-baseline-service",
    "g3-broad-allow",
    "g3-predefined-app",
    "g3-logging",
)
_WARNINGS = frozenset({"g3-broad-allow", "g3-predefined-app", "g3-logging"})
_TITLES = {
    "g3-syntax": "every line is a readable set command",
    "g3-name-valid": "every name is a valid PAN-OS identifier",
    "g3-name-unique": "names are unique and each rule is defined once",
    "g3-reference": "every reference resolves",
    "g3-empty-group": "no empty or circular groups",
    "g3-rule-fields": "every rule has zones, addresses, application, service and action",
    "g3-final-deny": "the rulebase ends with an explicit deny from any to any",
    "g3-any-any": "no allow from any to any without a ledger entry",
    "g3-baseline-service": "the like-for-like baseline does not use application-default",
    "g3-broad-allow": "allow rules with any source, destination and service are listed",
    "g3-predefined-app": "predefined App-IDs are listed",
    "g3-logging": "allow rules log at session end, the final deny logs",
}


class Validation(BaseModel):
    """The G3 checks: one failing ``Check`` per problem, and one passing ``Check`` per check id
    that found nothing, so a report can show what was checked."""

    checks: list[Check]

    @property
    def errors(self) -> list[Check]:
        return [c for c in self.checks if not c.ok and c.severity == "error"]

    @property
    def warnings(self) -> list[Check]:
        return [c for c in self.checks if not c.ok and c.severity == "warning"]

    @property
    def passed(self) -> bool:
        return not self.errors


@dataclass
class _Rule:
    name: str
    line_no: int
    attrs: dict[str, Token] = field(default_factory=dict)


@dataclass
class _Index:
    """What the lines define and what they reference, with line numbers."""

    defined: dict[str, dict[str, int]] = field(default_factory=dict)  # namespace -> name -> line
    groups: dict[str, list[str]] = field(default_factory=dict)
    rules: dict[str, _Rule] = field(default_factory=dict)  # security rules, in order
    nat: dict[str, _Rule] = field(default_factory=dict)
    refs: list[tuple[int, str, str, str]] = field(default_factory=list)  # line, kind, name, by
    problems: list[Check] = field(default_factory=list)

    def define(self, namespace: str, name: str, line_no: int) -> None:
        self.defined.setdefault(namespace, {}).setdefault(name, line_no)

    def has(self, namespace: str, name: str) -> bool:
        return name in self.defined.get(namespace, {})

    def problem(self, check_id: str, detail: str) -> None:
        severity: Literal["error", "warning"] = "warning" if check_id in _WARNINGS else "error"
        self.problems.append(Check(id=check_id, ok=False, severity=severity, detail=detail))


def _words(token: Token) -> list[str]:
    return [token] if isinstance(token, str) else list(token)


def _is_literal_address(text: str) -> bool:
    """An IP, a CIDR or an ``a-b`` range written into a rule instead of an object name."""
    try:
        if "-" in text and "/" not in text:
            low, high = text.split("-", 1)
            ipaddress.IPv4Address(low)
            ipaddress.IPv4Address(high)
        else:
            ipaddress.IPv4Network(text, strict=False)
    except ValueError:
        return False
    return True


# -- reading the lines -------------------------------------------------------------------------


def _attribute(table: dict[str, _Rule], index: _Index, line_no: int, rest: list[Token]) -> None:
    """One ``<rule> <attribute> <value...>`` line. A second, different value for the same
    attribute means two rules share a name (set commands would silently merge them)."""
    name, attr = str(rest[0]), str(rest[1])
    value: Token = rest[2] if len(rest) == 3 else [w for t in rest[2:] for w in _words(t)]
    rule = table.setdefault(name, _Rule(name, line_no))
    known = rule.attrs.get(attr)
    if known is not None and _words(known) != _words(value):
        index.problem(
            "g3-name-unique",
            f"line {line_no}: rule {name} sets {attr} again with a different value; "
            "two rules share this name",
        )
    rule.attrs[attr] = value


def _router_ports(index: _Index, line_no: int, words: list[str], rest: list[Token]) -> list[str]:
    """Ports a virtual-router line names: its interface list, or a static route's interface."""
    if rest[3] == "interface" and len(rest) == 5:
        return _words(rest[4])
    if "static-route" not in words or len(rest) < 7:
        return []
    index.define("static-route", str(rest[6]), line_no)
    texts = [str(t) for t in rest]
    at = texts.index("interface") if "interface" in texts else -1
    return [texts[at + 1]] if 0 <= at < len(texts) - 1 else []


def _read_line(index: _Index, line_no: int, tokens: list[Token]) -> None:
    words = [t if isinstance(t, str) else "" for t in tokens]
    if len(tokens) < 3 or words[0] != "set":
        index.problem("g3-syntax", f"line {line_no}: not a set command")
        return
    head, rest = words[1:4], tokens[1:]
    if head[:3] == ["network", "interface", "ethernet"] and len(rest) >= 5:
        index.define("interface", str(rest[3]), line_no)
        if len(rest) == 7 and rest[5] == "interface-management-profile":
            index.refs.append((line_no, "profile", str(rest[6]), f"interface {rest[3]}"))
    elif head[0] == "zone" and len(rest) == 5:
        index.define("zone", str(rest[1]), line_no)
        for port in _words(rest[4]):
            index.refs.append((line_no, "interface", port, f"zone {rest[1]}"))
    elif head[:2] == ["network", "virtual-router"] and len(rest) >= 4:
        for port in _router_ports(index, line_no, words, rest):
            index.refs.append((line_no, "interface", port, f"virtual router {rest[2]}"))
    elif head[:3] == ["network", "profiles", "interface-management-profile"] and len(rest) > 3:
        index.define("profile", str(rest[3]), line_no)
    elif head[0] in ("tag", "address", "service", "application", "schedule") and len(rest) >= 3:
        index.define(head[0], str(rest[1]), line_no)
    elif head[0] in ("address-group", "service-group") and len(rest) == 4:
        name = str(rest[1])
        index.define(head[0], name, line_no)
        members = _words(rest[3])
        index.groups[f"{head[0]}:{name}"] = members
        kind = "address" if head[0] == "address-group" else "service"
        for member in members:
            index.refs.append((line_no, kind, member, f"{head[0]} {name}"))
    elif head[:3] == ["rulebase", "security", "rules"] and len(rest) >= 6:
        _attribute(index.rules, index, line_no, rest[3:])
    elif head[:3] == ["rulebase", "nat", "rules"] and len(rest) >= 6:
        _attribute(index.nat, index, line_no, rest[3:])
    else:
        index.problem("g3-syntax", f"line {line_no}: unrecognised command {' '.join(head)}")


def _read(text: str) -> _Index:
    index = _Index()
    for line_no, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        try:
            tokens = tokenize(line, line_no)
        except ParseError as exc:
            index.problem("g3-syntax", f"line {line_no}: {exc.message}")
            continue
        _read_line(index, line_no, tokens)
    return index


# -- the checks ---------------------------------------------------------------------------------


def _check_names(index: _Index) -> None:
    named = [(ns, name) for ns, names in index.defined.items() for name in names]
    named += [("rule", name) for name in index.rules] + [("nat rule", name) for name in index.nat]
    for namespace, name in named:
        if namespace == "interface":
            if not PORT.match(name):
                index.problem("g3-name-valid", f"interface {name!r} is not an ethernet port name")
            continue
        if namespace == "tag":
            if not 0 < len(name) <= TAG_MAX_LEN or not name.isprintable():
                index.problem("g3-name-valid", f"tag {name!r} is not a valid tag name")
            continue
        if name == ANY:
            index.problem("g3-name-valid", f"{namespace} {name!r} uses a reserved name")
        elif not NAME.match(name):
            index.problem("g3-name-valid", f"{namespace} {name!r} is not a valid PAN-OS name")
        elif namespace == "zone" and len(name) > ZONE_MAX_LEN:
            index.problem("g3-name-valid", f"zone {name!r} is longer than {ZONE_MAX_LEN}")


def _check_unique(index: _Index) -> None:
    owners: dict[tuple[str, str], str] = {}
    for namespace, names in index.defined.items():
        shared = _SHARED.get(namespace)
        if shared is None:
            continue
        for name in names:
            other = owners.setdefault((shared, name), namespace)
            if other != namespace:
                index.problem(
                    "g3-name-unique", f"{name} is defined as both {other} and {namespace}"
                )


def _check_groups(index: _Index) -> None:
    for key, members in index.groups.items():
        if not members:
            index.problem("g3-empty-group", f"{key.replace(':', ' ')} has no members")

    def loops(key: str, path: tuple[str, ...]) -> bool:
        kind = key.split(":", 1)[0]
        for member in index.groups.get(key, []):
            nested = f"{kind}:{member}"
            if nested in path or (nested in index.groups and loops(nested, (*path, nested))):
                return True
        return False

    for key in index.groups:
        if loops(key, (key,)):
            index.problem("g3-empty-group", f"{key.replace(':', ' ')} contains itself")


def _resolves(index: _Index, kind: str, name: str) -> bool:
    if kind == "address":
        return (
            name == ANY
            or index.has("address", name)
            or index.has("address-group", name)
            or _is_literal_address(name)
        )
    if kind == "service":
        return name in (ANY, "application-default") or any(
            index.has(ns, name) for ns in ("service", "service-group")
        )
    if kind == "zone":
        return name == ANY or index.has("zone", name)
    return index.has(kind, name)


def _rule_refs(index: _Index) -> None:
    for table, label in ((index.rules, "rule"), (index.nat, "nat rule")):
        for rule in table.values():
            by = f"{label} {rule.name}"
            fields = [("from", "zone"), ("to", "zone"), ("source", "address")]
            fields += [("destination", "address"), ("service", "service"), ("tag", "tag")]
            for attr, kind in fields:
                for name in _words(rule.attrs.get(attr, [])):
                    index.refs.append((rule.line_no, kind, name, by))


def _check_refs(index: _Index) -> None:
    _rule_refs(index)
    for line_no, kind, name, by in index.refs:
        if not _resolves(index, kind, name):
            index.problem(
                "g3-reference", f"line {line_no}: {by} refers to {kind} {name}, undefined"
            )


def _is_any(rule: _Rule, attr: str) -> bool:
    return _words(rule.attrs.get(attr, [])) == [ANY]


def _check_rule(index: _Index, rule: _Rule, ledger_ids: set[str]) -> None:
    missing = [attr for attr in RULE_FIELDS if attr not in rule.attrs]
    if missing:
        index.problem("g3-rule-fields", f"rule {rule.name} has no {', '.join(missing)}")
    action = str(rule.attrs.get("action", ""))
    if action and action != "allow" and action not in DENY_ACTIONS:
        index.problem("g3-rule-fields", f"rule {rule.name} has an unknown action {action}")
    if "application-default" in _words(rule.attrs.get("service", [])):
        index.problem(
            "g3-baseline-service",
            f"rule {rule.name} uses service application-default, which changes the allowed ports",
        )
    for app in _words(rule.attrs.get("application", [])):
        if app != ANY and not index.has("application", app):
            broad = " (broader than one ICMP type)" if app in BROAD_APPS else ""
            index.problem("g3-predefined-app", f"rule {rule.name} uses App-ID {app}{broad}")
    if action != "allow":
        return
    if str(rule.attrs.get("log-end", "")) != "yes":
        index.problem("g3-logging", f"allow rule {rule.name} does not log at session end")
    wide = all(_is_any(rule, a) for a in ("source", "destination", "application", "service"))
    if not wide or rule.attrs.get("disabled") == "yes":
        return
    if _is_any(rule, "from") and _is_any(rule, "to"):
        tags = {t.removeprefix("necro:") for t in _words(rule.attrs.get("tag", []))}
        if not tags & ledger_ids:
            index.problem(
                "g3-any-any",
                f"rule {rule.name} allows everything from any zone to any zone "
                "and no ledger entry references it",
            )
    else:
        zones = f"{' '.join(_words(rule.attrs['from']))} to {' '.join(_words(rule.attrs['to']))}"
        index.problem("g3-broad-allow", f"rule {rule.name} allows everything from {zones}")


def _check_final_deny(index: _Index) -> None:
    if not index.rules:
        index.problem("g3-final-deny", "the rulebase has no rules, so no explicit final deny")
        return
    last = list(index.rules.values())[-1]
    open_fields = ("from", "to", "source", "destination", "application", "service")
    if (
        str(last.attrs.get("action", "")) not in DENY_ACTIONS
        or not all(_is_any(last, attr) for attr in open_fields)
        or last.attrs.get("disabled") == "yes"
    ):
        index.problem(
            "g3-final-deny",
            f"the last rule ({last.name}) is not an enabled deny of any to any",
        )
    elif (
        str(last.attrs.get("log-start", "")) != "yes"
        and str(last.attrs.get("log-end", "")) != "yes"
    ):
        index.problem("g3-logging", f"the final deny {last.name} does not log")


def validate_panos(text: str, ledger: Sequence[LedgerEntry] = ()) -> Validation:
    """Gate G3 on the emitted ``set`` text. ``ledger`` is the candidate's exorcism ledger."""
    index = _read(text)
    _check_names(index)
    _check_unique(index)
    _check_groups(index)
    _check_refs(index)
    ledger_ids = {entry.id for entry in ledger if entry.id}
    for rule in index.rules.values():
        _check_rule(index, rule, ledger_ids)
    _check_final_deny(index)
    failed = {c.id for c in index.problems}
    passed = [
        Check(
            id=check_id,
            ok=True,
            severity="warning" if check_id in _WARNINGS else "error",
            detail=_TITLES[check_id],
        )
        for check_id in CHECK_IDS
        if check_id not in failed
    ]
    order = {check_id: i for i, check_id in enumerate(CHECK_IDS)}
    problems = sorted(index.problems, key=lambda c: order[c.id])  # stable: line order within
    return Validation(checks=[*problems, *passed])
