"""The mutation sanity suite's mutants (pbt-playbook, requirement 6.7).

A mutant is a deliberately broken candidate: the text a broken emitter would have written. The
oracle must refuse every one with a shrunk counterexample. A mutant is only meaningful when the
unbroken candidate for the same fixture proves equivalent, so every fixture carries the correct
text and ``tests/test_oracle_mutants.py`` proves that first.

The playbook lists ten mutants. Nine are text rewrites of an emitted config: each changes one
construct and nothing else. The tenth, an 8.3+ real destination left untranslated, is the
emitter's own output for a real-address ACL, since translating it to the mapped address is a
Phase 2 feature (requirement 4.12): the correct candidate is the emission of the same policy
written in mapped addresses.

Everything here uses RFC 5737 and RFC 1918 addresses.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from dataclasses import dataclass
from functools import cache

from necro.emitters import emit_panos
from necro.ir import AddressSpace, Dialect, Policy
from necro.ledger import LedgerEntry
from necro.parsers.pix_asa import parse_pix_asa

_TWO_ZONES = """
interface Ethernet0/0
 nameif outside
 security-level 0
 ip address 192.0.2.1 255.255.255.0
interface Ethernet0/1
 nameif inside
 security-level 100
 ip address 10.1.0.1 255.255.255.0
route outside 0.0.0.0 0.0.0.0 192.0.2.254 1
"""

_THREE_ZONES = """
interface Ethernet0/0
 nameif outside
 security-level 0
 ip address 192.0.2.1 255.255.255.0
interface Ethernet0/1
 nameif inside
 security-level 100
 ip address 10.1.0.1 255.255.255.0
interface Ethernet0/2
 nameif dmz
 security-level 50
 ip address 10.2.0.1 255.255.255.0
route outside 0.0.0.0 0.0.0.0 192.0.2.254 1
"""

_NAT_83 = _TWO_ZONES + (
    "static (inside,outside) 192.0.2.50 10.1.0.50 netmask 255.255.255.255\n"
    "access-list OUT_IN extended permit tcp any host 192.0.2.50 eq 80\n"
    "access-list OUT_IN extended deny ip any any\n"
    "access-group OUT_IN in interface outside\n"
)

# name -> ASA 8.2 config text. Each ACL is bound inbound on ``outside``.
CONFIGS: dict[str, str] = {
    # lt, gt, range, neq and a /24 source: the constructs the port and mask mutants break
    "ports": _TWO_ZONES + "access-list IN extended permit tcp any 10.1.0.0 255.255.255.0 lt 1024\n"
    "access-list IN extended permit tcp any 10.1.0.0 255.255.255.0 gt 49151\n"
    "access-list IN extended permit tcp any 10.1.0.0 255.255.255.0 range 8000 8100\n"
    "access-list IN extended permit udp any 10.1.0.0 255.255.255.0 neq 53\n"
    "access-list IN extended permit tcp 10.20.30.0 255.255.255.0 host 10.1.0.7 eq 3389\n"
    "access-list IN extended deny ip any any\n"
    "access-group IN in interface outside\n",
    # a host denied before the rule that would permit it
    "order": _TWO_ZONES
    + "access-list IN extended deny tcp host 203.0.113.9 10.1.0.0 255.255.255.0 eq 22\n"
    "access-list IN extended permit tcp any 10.1.0.0 255.255.255.0 eq 22\n"
    "access-list IN extended deny ip any any\n"
    "access-group IN in interface outside\n",
    # an inactive rule that must stay disabled
    "inactive": _TWO_ZONES
    + "access-list IN extended permit tcp any host 10.1.0.9 eq 3389 inactive\n"
    "access-list IN extended permit tcp any host 10.1.0.9 eq 80\n"
    "access-list IN extended deny ip any any\n"
    "access-group IN in interface outside\n",
    # echo-reply only: the ping App-ID would also let echo requests through
    "icmp": _TWO_ZONES
    + "access-list IN extended permit icmp any 10.1.0.0 255.255.255.0 echo-reply\n"
    "access-list IN extended deny ip any any\n"
    "access-group IN in interface outside\n",
    # three security levels and two interfaces with no ACL: implicit permits per target zone
    "zones": _THREE_ZONES
    + "access-list OUT_IN extended permit tcp any 10.2.0.0 255.255.255.0 eq 80\n"
    "access-group OUT_IN in interface outside\n",
    # a static NAT: the mapped address and the real one differ (pre-8.3 form; see ``nat83``)
    "nat83": _NAT_83,
}


@dataclass(frozen=True)
class Fixture:
    """A policy, the candidate that is equivalent to it, and that candidate's ledger."""

    name: str
    original: Policy
    correct: str
    ledger: tuple[LedgerEntry, ...]


@dataclass(frozen=True)
class Candidate:
    """What a mutant hands to the oracle."""

    text: str
    ledger: tuple[LedgerEntry, ...]


@dataclass(frozen=True)
class Mutant:
    """One playbook mutant: ``build`` turns a fixture into the broken candidate."""

    name: str  # the playbook's wording
    fixture: str
    build: Callable[[Fixture], Candidate]


def _policy(text: str, *, version: str = "8.2(5)") -> Policy:
    return parse_pix_asa(text, dialect=Dialect.asa, os_version=version)


def _real_address_policy(mapped: Policy) -> Policy:
    """The same policy as an ASA 9.x config would state it: ACLs name the real destination."""
    real = mapped.model_copy(deep=True)
    real.address_space = AddressSpace.real
    real.os_version = "9.8(4)"
    static = real.nat_rules[0]
    for rules in real.acls.values():
        for rule in rules:
            if static.mapped_addr.covers(rule.match.dst) and not rule.match.dst.is_empty():
                rule.match.dst = static.real_addr
    return real


@cache
def fixture(name: str) -> Fixture:
    policy = _policy(CONFIGS[name])
    emission = emit_panos(policy)
    original = _real_address_policy(policy) if name == "nat83" else policy
    return Fixture(name, original, emission.text, tuple(emission.ledger))


# -- text rewriting ---------------------------------------------------------------------------

_SERVICE = "set service "
_ADDRESS = "set address "
_RULE = "set rulebase security rules "
_FULL = 65535


def _ranges(spec: str) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for part in spec.split(","):
        lo, _, hi = part.partition("-")
        out.append((int(lo), int(hi or lo)))
    return out


def _rewrite_services(text: str, change: Callable[[list[tuple[int, int]]], str | None]) -> str:
    """Apply ``change`` to the port list of every service object; ``None`` keeps the line."""
    lines: list[str] = []
    for line in text.splitlines():
        words = line.split()
        if line.startswith(_SERVICE) and len(words) >= 7 and words[5] == "port":
            replaced = change(_ranges(words[6]))
            if replaced is not None:
                words[6] = replaced
                line = " ".join(words)
        lines.append(line)
    return "\n".join(lines) + "\n"


def _swap_lt_and_gt(ranges: list[tuple[int, int]]) -> str | None:
    """``lt p`` becomes ``gt p`` and ``gt p`` becomes ``lt p``."""
    if len(ranges) != 1:
        return None
    lo, hi = ranges[0]
    if lo == 0 and hi < _FULL:  # lt (hi + 1)
        return f"{hi + 2}-{_FULL}"
    if hi == _FULL and lo > 0:  # gt (lo - 1)
        return f"0-{lo - 2}"
    return None


def _range_upper_bound_off_by_one(ranges: list[tuple[int, int]]) -> str | None:
    if len(ranges) == 1 and 0 < ranges[0][0] < ranges[0][1] < _FULL:
        return f"{ranges[0][0]}-{ranges[0][1] + 1}"
    return None


def _neq_as_eq(ranges: list[tuple[int, int]]) -> str | None:
    """``neq p`` is ``0-(p-1),(p+1)-65535``: write ``p`` instead."""
    if len(ranges) != 2:
        return None
    (first_lo, first_hi), (second_lo, second_hi) = ranges
    if first_lo == 0 and second_hi == _FULL and second_lo == first_hi + 2:
        return str(first_hi + 1)
    return None


def _mask_as_wildcard(text: str) -> str:
    """Read the prefix length of every network object as its wildcard (``/24`` becomes ``/8``)."""
    lines: list[str] = []
    for line in text.splitlines():
        words = line.split()
        if line.startswith(_ADDRESS) and len(words) == 5 and words[3] == "ip-netmask":
            address, _, prefix = words[4].partition("/")
            if 1 <= int(prefix) <= 31:
                network = ipaddress.ip_network(f"{address}/{32 - int(prefix)}", strict=False)
                line = f"{_ADDRESS}{words[2]} ip-netmask {network}"
        lines.append(line)
    return "\n".join(lines) + "\n"


def _block(lines: list[str], rule: str) -> list[int]:
    head = f"{_RULE}{rule} "
    return [i for i, line in enumerate(lines) if line.startswith(head)]


def _swap_adjacent_rules(text: str, first: str, second: str) -> str:
    lines = text.splitlines()
    one, two = _block(lines, first), _block(lines, second)
    assert one and two and one[-1] + 1 == two[0], "the two rules must be adjacent, in this order"
    swapped = [*lines[: one[0]], *(lines[i] for i in two), *(lines[i] for i in one)]
    return "\n".join([*swapped, *lines[two[-1] + 1 :]]) + "\n"


def _drop_final_deny(text: str) -> str:
    lines = [ln for ln in text.splitlines() if not ln.startswith(f"{_RULE}necro-final-deny ")]
    return "\n".join(lines) + "\n"


def _enable_inactive_rules(text: str) -> str:
    lines = [ln for ln in text.splitlines() if not ln.endswith(" disabled yes")]
    return "\n".join(lines) + "\n"


def _icmp_type_as_ping_app_id(text: str) -> str:
    lines: list[str] = []
    for line in text.splitlines():
        words = line.split()
        is_application = line.startswith(_RULE) and len(words) == 7 and words[5] == "application"
        if is_application and words[6].startswith("necro-icmp-"):
            line = " ".join([*words[:6], "ping"])
        lines.append(line)
    return "\n".join(lines) + "\n"


def _force_to_zone_any(text: str) -> str:
    lines: list[str] = []
    for line in text.splitlines():
        words = line.split()
        if line.startswith(_RULE) and len(words) == 7 and words[5] == "to":
            line = " ".join([*words[:6], "any"])
        lines.append(line)
    return "\n".join(lines) + "\n"


def _rewrite(change: Callable[[str], str]) -> Callable[[Fixture], Candidate]:
    return lambda fx: Candidate(change(fx.correct), fx.ledger)


def _untranslated_real_destination(fx: Fixture) -> Candidate:
    """The emitter's output for an ACL written with the real destination (policy-semantics 1.5)."""
    emission = emit_panos(fx.original)
    return Candidate(emission.text, tuple(emission.ledger))


MUTANTS: tuple[Mutant, ...] = (
    Mutant("lt and gt swapped", "ports", _rewrite(lambda t: _rewrite_services(t, _swap_lt_and_gt))),
    Mutant(
        "range upper bound off by one",
        "ports",
        _rewrite(lambda t: _rewrite_services(t, _range_upper_bound_off_by_one)),
    ),
    Mutant("neq emitted as eq", "ports", _rewrite(lambda t: _rewrite_services(t, _neq_as_eq))),
    Mutant("subnet mask emitted as wildcard", "ports", _rewrite(_mask_as_wildcard)),
    Mutant(
        "rule order reversed for two overlapping rules",
        "order",
        _rewrite(lambda t: _swap_adjacent_rules(t, "IN-1", "IN-2")),
    ),
    Mutant("final deny dropped", "zones", _rewrite(_drop_final_deny)),
    Mutant("inactive rule emitted as enabled", "inactive", _rewrite(_enable_inactive_rules)),
    Mutant(
        "ICMP echo-reply widened to the ping App-ID", "icmp", _rewrite(_icmp_type_as_ping_app_id)
    ),
    Mutant("8.3+ real destination left untranslated", "nat83", _untranslated_real_destination),
    Mutant("to-zone forced to any", "zones", _rewrite(_force_to_zone_any)),
)

# The playbook's list, so a mutant cannot be dropped by accident.
PLAYBOOK = (
    "lt and gt swapped",
    "range upper bound off by one",
    "neq emitted as eq",
    "subnet mask emitted as wildcard",
    "rule order reversed for two overlapping rules",
    "final deny dropped",
    "inactive rule emitted as enabled",
    "ICMP echo-reply widened to the ping App-ID",
    "8.3+ real destination left untranslated",
    "to-zone forced to any",
)
