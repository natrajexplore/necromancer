"""Deterministic, collision-free PAN-OS identifiers (requirement 4.4, property P12).

A valid name is 1-``max_len`` characters from ``[A-Za-z0-9_.-]`` and starts with an alphanumeric.
``NameRegistry`` maps source keys to such names: the same key always gets the same name, and two
different keys never share one. A key whose slug is already taken gets ``-<hex of sha1(key)>``.
"""

from __future__ import annotations

import hashlib

MAX_LEN = 63
ZONE_MAX_LEN = 31  # PAN-OS zone names are shorter than other object names
_SUFFIX_RESERVE = 5  # "-" plus four hex digits, the collision suffix

_ALLOWED_PUNCT = "_.-"


def _is_name_char(ch: str) -> bool:
    return ch.isascii() and (ch.isalnum() or ch in _ALLOWED_PUNCT)


def is_valid_name(name: str, max_len: int = MAX_LEN) -> bool:
    """Whether ``name`` is a valid PAN-OS identifier."""
    return (
        0 < len(name) <= max_len
        and name[0].isascii()
        and name[0].isalnum()
        and all(_is_name_char(c) for c in name)
    )


def slug(text: str, max_len: int = MAX_LEN) -> str:
    """Turn arbitrary text into a valid identifier of at most ``max_len`` characters."""
    cleaned = "".join(c if _is_name_char(c) else "-" for c in text)
    start = next((i for i, c in enumerate(cleaned) if c.isalnum()), len(cleaned))
    cleaned = cleaned[start:][:max_len]
    return cleaned or "x"


def _digest(key: str) -> str:
    return hashlib.sha1(key.encode("utf-8"), usedforsecurity=False).hexdigest()


class NameRegistry:
    """One namespace of PAN-OS names (zones, addresses, rules, ...)."""

    def __init__(self, max_len: int = MAX_LEN) -> None:
        if max_len < _SUFFIX_RESERVE + 1:
            raise ValueError("max_len too small for a collision suffix")
        self._max_len = max_len
        self._by_key: dict[str, str] = {}
        self._used: set[str] = set()

    def __contains__(self, key: str) -> bool:
        return key in self._by_key

    def __len__(self) -> int:
        return len(self._by_key)

    def names(self) -> list[str]:
        return sorted(self._used)

    def name(self, key: str, preferred: str | None = None) -> str:
        """The name for ``key``, allocating one on first use.

        ``preferred`` is the text to slug (it defaults to ``key``). The key, not the preferred
        text, drives the collision suffix, so equal preferred text never merges two keys.
        """
        known = self._by_key.get(key)
        if known is not None:
            return known
        base = slug(key if preferred is None else preferred, self._max_len - _SUFFIX_RESERVE)
        chosen = base if base not in self._used else self._disambiguate(key, base)
        self._by_key[key] = chosen
        self._used.add(chosen)
        return chosen

    def _disambiguate(self, key: str, base: str) -> str:
        digest = _digest(key)
        for width in range(4, min(len(digest), self._max_len - 2) + 1, 2):
            candidate = f"{base[: self._max_len - 1 - width]}-{digest[:width]}"
            if candidate not in self._used:
                return candidate
        counter = 1
        while True:  # unreachable in practice; keeps the function total
            tail = f"-{counter}"
            candidate = f"{base[: self._max_len - len(tail)]}{tail}"
            if candidate not in self._used:
                return candidate
            counter += 1
