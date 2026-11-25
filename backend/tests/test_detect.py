"""Task 4.3: dialect, OS version and mode detection with confidence (requirement 1.3)."""

from __future__ import annotations

from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from necro.ir import Dialect, ParseError, PolicyMode
from necro.parsers import detect, parse_config
from necro.redact import redact

SAMPLES = Path(__file__).resolve().parents[2] / "samples"


def _read(folder: str, name: str) -> str:
    return (SAMPLES / folder / name).read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("folder", "name", "dialect", "version"),
    [
        ("dead-configs", "pix-2006-hq.cfg", Dialect.pix, "6.3(5)"),
        ("dead-configs", "asa-8.2-branch.cfg", Dialect.asa, "8.2(5)"),
        ("dead-configs", "asa-9.8-dc.cfg", Dialect.asa, "9.8(4)"),
        ("dead-configs", "ios-12-edge.cfg", Dialect.ios, "12.4"),
    ],
)
def test_samples_are_detected_with_high_confidence(
    folder: str, name: str, dialect: Dialect, version: str
) -> None:
    d = detect(redact(_read(folder, name)))
    assert (d.dialect, d.os_version, d.mode) == (dialect, version, PolicyMode.routed)
    assert d.confidence >= 0.95  # a banner that agrees with the syntax
    assert d.signals


def test_modes_are_detected() -> None:
    transparent = detect(_read("broken-configs", "asa-out-of-scope-mode.cfg"))
    assert transparent.dialect == Dialect.asa
    assert transparent.mode == PolicyMode.transparent
    assert detect("mode multiple\nASA Version 9.8(4)\n").mode == PolicyMode.multiple
    assert detect("context admin\n").mode == PolicyMode.multiple


def test_pix_7_and_later_use_asa_syntax() -> None:
    d = detect("PIX Version 7.2(4)\n")
    assert (d.dialect, d.os_version) == (Dialect.asa, "7.2(4)")


def test_asa_software_banner() -> None:
    d = detect(": Cisco Adaptive Security Appliance Software Version 9.1(2)\n")
    assert d.dialect == Dialect.asa and 0 < d.confidence < 0.98


def test_headerless_configs_get_lower_confidence_than_banners() -> None:
    asa = detect(
        "interface Ethernet0/0\n nameif outside\n security-level 0\n"
        "access-list A extended permit ip any any\n"
        "access-group A in interface outside\n"
    )
    ios = detect(
        "interface FastEthernet0/0\n ip access-group 101 in\n"
        "ip access-list extended X\nline vty 0 4\nip route 0.0.0.0 0.0.0.0 192.0.2.1\n"
    )
    pix = detect(
        "nameif ethernet0 outside security0\nfixup protocol ftp 21\nconduit permit ip any any\n"
    )
    assert (asa.dialect, ios.dialect, pix.dialect) == (Dialect.asa, Dialect.ios, Dialect.pix)
    for d in (asa, ios, pix):
        assert 0.4 < d.confidence < 0.9
        assert d.os_version == ""


def test_no_evidence_means_no_dialect() -> None:
    d = detect("hostname lonely\n! nothing to see\n")
    assert (d.dialect, d.confidence, d.mode) == (None, 0.0, PolicyMode.routed)
    assert detect("").dialect is None


def test_conflicting_evidence_lowers_confidence() -> None:
    clean = detect("ASA Version 8.2(5)\n")
    mixed = detect(
        "ASA Version 8.2(5)\nip access-list extended X\nline vty 0 4\nservice timestamps\n"
    )
    assert mixed.dialect == Dialect.asa
    assert mixed.confidence < clean.confidence


@given(st.lists(st.text(max_size=40), max_size=20).map("\n".join))
def test_pbt_detection_confidence_is_always_in_unit_interval(text: str) -> None:
    d = detect(text)
    assert 0.0 <= d.confidence <= 1.0
    assert (d.dialect is None) == (d.confidence == 0.0)


# ---------------------------------------------------------------------------
# parse_config: redact first, then detect, then parse
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("folder", "name", "dialect"),
    [
        ("dead-configs", "pix-2006-hq.cfg", Dialect.pix),
        ("dead-configs", "asa-8.2-branch.cfg", Dialect.asa),
        ("dead-configs", "ios-12-edge.cfg", Dialect.ios),
    ],
)
def test_parse_config_autodetects_and_never_leaks_secrets(
    folder: str, name: str, dialect: Dialect
) -> None:
    raw = _read(folder, name)
    policy = parse_config(raw)
    assert policy.dialect == dialect
    assert 0.75 <= policy.detection_confidence <= 1.0
    # Every token the redactor removed from a line must be absent from what parse_config returns.
    redacted = redact(raw)
    secrets: set[str] = set()
    for before, after in zip(raw.splitlines(), redacted.splitlines(), strict=True):
        if before != after:
            secrets |= set(before.split()) - set(after.split())
    assert secrets  # the samples do contain (fake) secrets
    dumped = repr(policy)
    assert not [s for s in secrets if s in dumped]


def test_explicit_dialect_overrides_detection() -> None:
    policy = parse_config(_read("dead-configs", "pix-2006-hq.cfg"), dialect=Dialect.pix)
    assert policy.detection_confidence == 1.0


def test_unknown_dialect_is_a_parse_error() -> None:
    with pytest.raises(ParseError) as err:
        parse_config("hostname lonely\n")
    assert err.value.code == "unknown-dialect"


def test_parse_config_surfaces_group_cycles() -> None:
    with pytest.raises(ParseError) as err:
        parse_config(_read("broken-configs", "asa-group-cycle.cfg"))
    assert err.value.code == "group-cycle"


_ACCESS_GROUP = "access-group A in interface outside\n"
_AGREEING = {
    "PIX Version 6.3(5)": "nameif ethernet0 outside security0\n" + _ACCESS_GROUP,
    "PIX Version 7.2(4)": "interface E0\n nameif outside\n" + _ACCESS_GROUP,
    "ASA Version 9.8(4)": (
        "interface E0\n nameif outside\naccess-list A extended permit ip any any\n"
    ),
    "version 12.4": "ip access-list extended A\nline vty 0 4\nip route 0.0.0.0 0.0.0.0 192.0.2.1\n",
}


@pytest.mark.parametrize("banner", list(_AGREEING))
def test_a_banner_that_agrees_with_the_syntax_gives_at_least_0_95(banner: str) -> None:
    d = detect(banner + "\n" + _AGREEING[banner])
    assert d.dialect is not None and d.confidence >= 0.95


def test_a_banner_that_the_syntax_contradicts_stays_below_the_floor() -> None:
    """An ASA banner over IOS-only syntax is not consistent evidence."""
    ios_only = (
        "ip access-list extended A\nline vty 0 4\nip route 0.0.0.0 0.0.0.0 1.1.1.1\n"
        "ip access-list standard B\nservice timestamps debug\n"
    )
    assert detect("ASA Version 9.8(4)\n" + ios_only).confidence < 0.95


@given(st.text(alphabet="abcdef \n!-.", max_size=200))
def test_pbt_a_lone_banner_with_noise_never_drops_below_the_floor(noise: str) -> None:
    """Text that gives no dialect any evidence cannot dilute a banner."""
    d = detect("ASA Version 9.8(4)\n" + "\n".join(f"! {line}" for line in noise.splitlines()))
    assert d.dialect == Dialect.asa and d.confidence >= 0.95
