"""Task 6.1 / property P12: emitted PAN-OS names are valid, short enough, unique and stable."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from necro.emitters.panos_names import (
    MAX_LEN,
    ZONE_MAX_LEN,
    NameRegistry,
    is_valid_name,
    slug,
)

# Small alphabets force collisions after slugging ("a b" and "a-b", "A:1" and "A-1", ...).
_COLLIDING = st.text(alphabet="ab -_.:/é", min_size=0, max_size=12)
_ARBITRARY = st.text(max_size=120)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("outside_in", "outside_in"),
        ("-leading", "leading"),
        ("a b:c/d", "a-b-c-d"),
        ("", "x"),
        ("---", "x"),
        ("é", "x"),
    ],
)
def test_slug_examples(text: str, expected: str) -> None:
    assert slug(text) == expected


def test_slug_truncates() -> None:
    assert len(slug("a" * 200)) == MAX_LEN
    assert len(slug("a" * 200, 10)) == 10


@pytest.mark.parametrize(
    ("name", "ok"),
    [
        ("web-srv", True),
        ("a", True),
        ("1abc", True),
        ("", False),
        ("-a", False),
        ("_a", False),
        ("a b", False),
        ("a:b", False),
        ("é", False),
        ("a" * 63, True),
        ("a" * 64, False),
    ],
)
def test_is_valid_name(name: str, ok: bool) -> None:
    assert is_valid_name(name) is ok


def test_same_key_gets_the_same_name() -> None:
    reg = NameRegistry()
    first = reg.name("outside_in-1")
    assert reg.name("outside_in-1") == first
    assert "outside_in-1" in reg
    assert len(reg) == 1


def test_collisions_get_a_hash_suffix_and_the_first_keeps_the_plain_name() -> None:
    reg = NameRegistry()
    plain = reg.name("a b")
    other = reg.name("a-b")
    assert plain == "a-b"
    assert other != plain and other.startswith("a-b-") and len(other) == len("a-b") + 5
    assert is_valid_name(other)
    assert reg.names() == sorted([plain, other])


def test_preferred_text_drives_the_slug_but_not_the_identity() -> None:
    reg = NameRegistry()
    assert reg.name("net:10.0.0.0/8", "n-10.0.0.0-8") == "n-10.0.0.0-8"
    assert reg.name("other", "n-10.0.0.0-8") != "n-10.0.0.0-8"


def test_long_names_stay_within_the_limit_after_disambiguation() -> None:
    reg = NameRegistry()
    names = [reg.name(f"key{i}", "x" * 100) for i in range(5)]
    assert len(set(names)) == 5
    assert all(is_valid_name(n) and len(n) <= MAX_LEN for n in names)


def test_exhausting_every_hash_width_falls_back_to_a_counter() -> None:
    reg = NameRegistry(max_len=6)  # one base character, so hash prefixes collide quickly
    names = [reg.name(f"k{i}", "a") for i in range(3000)]
    assert len(set(names)) == 3000
    assert all(is_valid_name(n, 6) for n in names)


def test_registry_rejects_a_limit_with_no_room_for_a_suffix() -> None:
    with pytest.raises(ValueError, match="too small"):
        NameRegistry(max_len=3)


@pytest.mark.pbt
@given(
    keys=st.lists(_COLLIDING, min_size=0, max_size=60),
    limit=st.sampled_from([MAX_LEN, ZONE_MAX_LEN, 12]),
)
def test_p12_names_are_valid_and_unique_under_collisions(keys: list[str], limit: int) -> None:
    reg = NameRegistry(limit)
    assigned = {k: reg.name(k) for k in keys}
    assert all(is_valid_name(n, limit) for n in assigned.values())
    assert len(set(assigned.values())) == len(assigned)  # distinct keys never share a name


@pytest.mark.pbt
@given(keys=st.lists(_ARBITRARY, max_size=25), limit=st.sampled_from([MAX_LEN, ZONE_MAX_LEN]))
def test_p12_arbitrary_text_and_determinism(keys: list[str], limit: int) -> None:
    first, second = NameRegistry(limit), NameRegistry(limit)
    out_a = [first.name(k) for k in keys]
    out_b = [second.name(k) for k in keys]
    assert out_a == out_b  # same input sequence, same names
    assert [first.name(k) for k in keys] == out_a  # asking again never renames
    assert all(is_valid_name(n, limit) for n in out_a)
    assert len(set(out_a)) == len(set(keys))


@pytest.mark.pbt
@given(text=_ARBITRARY, limit=st.integers(min_value=1, max_value=MAX_LEN))
def test_p12_slug_is_always_a_valid_name(text: str, limit: int) -> None:
    assert is_valid_name(slug(text, limit), limit)
