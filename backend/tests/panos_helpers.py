"""Helpers for reading emitted PAN-OS ``set`` text in tests (the real reader is panos_reader)."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from functools import cache
from pathlib import Path

from necro.ir import Policy
from necro.parsers import parse_config
from necro.sets import AddrSet

SAMPLES = Path(__file__).resolve().parents[2] / "samples" / "dead-configs"
RULE_PREFIX = "set rulebase security rules "


@cache
def policy_of(name: str) -> Policy:
    """A sample dead config, parsed once."""
    return parse_config((SAMPLES / name).read_text(encoding="utf-8"))


def rules_of(lines: list[str]) -> dict[str, dict[str, str]]:
    """Rule name -> {attribute: value text}, in rulebase order."""
    rules: dict[str, dict[str, str]] = {}
    for line in lines:
        if line.startswith(RULE_PREFIX):
            name, attr, *value = line.removeprefix(RULE_PREFIX).split(" ", 2)
            rules.setdefault(name, {})[attr] = " ".join(value)
    return rules


def union_of(sets: Iterable[AddrSet]) -> AddrSet:
    result = AddrSet()
    for item in sets:
        result = result.union(item)
    return result


def address_set(lines: list[str], name: str) -> AddrSet:
    """Resolve an emitted address object or group name back to the addresses it matches."""
    if name == "any":
        return AddrSet.any()
    for line in lines:
        words = line.split()
        if line.startswith(f"set address {name} "):
            return AddrSet.from_network(ipaddress.IPv4Network(words[4]))
        if line.startswith(f"set address-group {name} static "):
            members = [w for w in words[4:] if w not in ("[", "]")]
            return union_of(address_set(lines, m) for m in members)
    raise AssertionError(f"no address object {name}")
