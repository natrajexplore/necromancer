"""Task 5.2 / requirement 3.14: seeded-ghost recall on samples/dead-configs is 100%.

Every ``! GHOST: <type> (...)`` comment marks the line below it. A finding of that type must point
at that line. Findings that are not seeded are extras: they are printed (run with ``-s``) with a
justification per type, and every type that can appear as an extra must have one.
ASA 9.8 is Phase 2 (object NAT, global ACL, any4), so its ghosts are not checked here.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest

from necro.autopsy import Finding, FindingType, analyze
from necro.parsers import parse_config

DEAD = Path(__file__).resolve().parents[2] / "samples" / "dead-configs"
SUPPORTED = ["pix-2006-hq.cfg", "asa-8.2-branch.cfg", "ios-12-edge.cfg"]
GHOST_TYPES = {t.value for t in FindingType}

# Why each kind of unseeded finding is correct to report (requirement 3.14).
JUSTIFICATIONS = {
    "no-remark": "the sample ACLs carry few remarks; each rule without one is a finding (3.13)",
    "redundant": "a later rule with the same action already takes every flow",
    "shadowed": "an earlier rule already takes every flow",
    "overly-broad": "an any/any (or IP-to-any) permit that decide() confirms is reachable",
    "insecure-service": "a clear-text or abused service permit that decide() confirms",
    "insecure-management": "SNMP v1/v2c communities and telnet/HTTP management are insecure",
    "unfiltered-interface": "no inbound ACL: the implicit behaviour is read from decide()",
    "return-traffic": "an IOS established or source-port-only permit (3.10)",
    "unused-object": "an object-group that no rule reaches",
    "unused-acl": "an ACL that nothing binds or references",
}


def _ghosts(path: Path) -> list[tuple[str, int]]:
    """(type, line below the annotation) for every seeded ghost in a config."""
    found = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        parts = line.split()
        if line.startswith("! GHOST: ") and len(parts) > 2 and parts[2] in GHOST_TYPES:
            found.append((parts[2], number + 1))
    return found


def _findings(name: str) -> list[Finding]:
    return analyze(parse_config((DEAD / name).read_text(encoding="utf-8")))


@pytest.mark.parametrize("name", SUPPORTED)
def test_every_seeded_ghost_is_found(name: str) -> None:
    ghosts = _ghosts(DEAD / name)
    assert ghosts, "the fixture must seed ghosts"
    found = {(f.type.value, f.source_line) for f in _findings(name)}
    missed = [g for g in ghosts if g not in found]
    recall = (len(ghosts) - len(missed)) / len(ghosts)
    assert recall == 1.0, f"{name}: missed {missed}"


def test_the_seeded_types_cover_every_kind_of_ghost_the_samples_promise() -> None:
    seeded = {t for name in SUPPORTED for t, _ in _ghosts(DEAD / name)}
    assert seeded == {
        "shadowed",
        "redundant",
        "overly-broad",
        "insecure-service",
        "unused-object",
        "insecure-management",
        "unfiltered-interface",
        "return-traffic",
    }


def test_extras_are_listed_and_justified() -> None:
    lines = ["", "Autopsy extras (findings beyond the seeded ghosts):"]
    unjustified = []
    for name in SUPPORTED:
        seeded = set(_ghosts(DEAD / name))
        extras = [f for f in _findings(name) if (f.type.value, f.source_line) not in seeded]
        by_type = Counter(f.type.value for f in extras)
        lines.append(f"  {name}: {sum(by_type.values())} extra")
        for kind, count in sorted(by_type.items()):
            why = JUSTIFICATIONS.get(kind)
            if why is None:
                unjustified.append(kind)
            lines.append(f"    {count:3d} x {kind:<20} {why}")
        for f in extras:
            if f.type != FindingType.no_remark:
                lines.append(f"        {f.rule_ref} (line {f.source_line}) {f.severity.value}")
    print("\n".join(lines))
    assert not unjustified, f"no justification for extra finding types: {unjustified}"


def test_asa_9_8_ghosts_are_phase_2() -> None:
    """The 9.8 sample parses (its 8.3+ constructs are reported as unparsed lines, never skipped),
    but its ghosts need object NAT and the global ACL, which arrive with Phase 2."""
    policy = parse_config((DEAD / "asa-9.8-dc.cfg").read_text(encoding="utf-8"))
    assert [u for u in policy.unparsed if u.security_relevant]
    analyze(policy)  # must not raise on a partly parsed config
