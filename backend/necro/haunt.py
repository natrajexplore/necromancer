"""Haunt it: a deliberately broken candidate, for showing a failed proof on stage.

The demo switch of requirement 4.3 of graveyard-ui. ``haunt_candidate`` rewrites the emitted
PAN-OS text in one fixed way: the first enabled allow rule becomes a deny. Every flow that rule
admitted is then denied by the candidate and permitted by the source, so the oracle refuses the
candidate with a shrunk counterexample. The other mutants of the mutation suite
(``tests/mutants.py``) each need a construct that only some configs have, such as a /24 network
object or an inactive rule, so none of them fails on every sample. This one needs only an
allow rule.

The rewrite feeds the proof and nothing else. It never changes the emitted config, the ledger,
the gates, the verdict or the Grimoire (see ``service.prove``).
"""

from __future__ import annotations

HAUNT_MUTANT = "first enabled allow rule emitted as deny"

_RULE = "set rulebase security rules "
_ALLOW = " action allow"
_DENY = " action deny"


class HauntError(ValueError):
    """The candidate has no enabled allow rule to break."""


def _rule_name(line: str) -> str | None:
    words = line.split()
    return words[4] if line.startswith(_RULE) and len(words) > 4 else None


def haunt_candidate(text: str) -> str:
    """The emitted PAN-OS ``set`` commands with their first enabled allow rule flipped to deny."""
    lines = text.splitlines()
    disabled = {_rule_name(line) for line in lines if line.endswith(" disabled yes")}
    target = next(
        (
            name
            for line in lines
            if line.endswith(_ALLOW) and (name := _rule_name(line)) and name not in disabled
        ),
        None,
    )
    if target is None:
        raise HauntError("the candidate has no enabled allow rule to haunt")
    head = f"{_RULE}{target}{_ALLOW}"
    haunted = [f"{_RULE}{target}{_DENY}" if line == head else line for line in lines]
    return "\n".join(haunted) + "\n"
