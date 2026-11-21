"""Task 4.4: line accounting and coverage (requirement 1.9, property P14)."""

from __future__ import annotations

from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from necro.coverage import (
    CLASSES,
    AccountingError,
    blocking_lines,
    compute_coverage,
    verify_accounting,
)
from necro.ir import Dialect, ParseError, Policy
from necro.parsers import parse_config
from necro.parsers.cisco_common import split_lines
from necro.parsers.ios_acl import parse_ios
from necro.parsers.pix_asa import parse_pix_asa
from necro.redact import redact

SAMPLES = Path(__file__).resolve().parents[2] / "samples"


def _parse(folder: str, name: str) -> tuple[Policy, str]:
    raw = (SAMPLES / folder / name).read_text(encoding="utf-8")
    return parse_config(raw), redact(raw)


# ---------------------------------------------------------------------------
# Samples
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["pix-2006-hq.cfg", "asa-8.2-branch.cfg", "ios-12-edge.cfg"])
def test_supported_samples_are_fully_covered(name: str) -> None:
    policy, text = _parse("dead-configs", name)
    cov = verify_accounting(policy, text)
    assert cov.blocking == 0 and cov.waived == 0
    assert cov.ratio == 1.0
    assert cov.handled == cov.security_relevant > 0
    assert cov.total_lines == len(split_lines(text)) == sum(cov.counts.values())
    assert blocking_lines(policy) == []


def test_negative_fixture_blocks_coverage_until_waived() -> None:
    policy, text = _parse("broken-configs", "ios-unsupported-constructs.cfg")
    cov = verify_accounting(policy, text)
    assert cov.blocking == 6 and cov.waived == 0
    assert cov.ratio == pytest.approx(cov.handled / cov.security_relevant)
    assert cov.ratio < 1.0
    assert len(blocking_lines(policy)) == 6
    # a waiver removes the line from "blocking" but never counts it as migrated
    waived_no = blocking_lines(policy)[0].line_no
    records = [
        r.model_copy(update={"waiver_id": "W-1"}) if r.line_no == waived_no else r
        for r in policy.line_records
    ]
    waived = policy.model_copy(update={"line_records": records})
    cov2 = compute_coverage(waived)
    assert (cov2.blocking, cov2.waived, cov2.handled) == (5, 1, cov.handled)
    assert waived_no not in {u.line_no for u in blocking_lines(waived)}


def test_transparent_mode_blocks_coverage() -> None:
    policy, text = _parse("broken-configs", "asa-out-of-scope-mode.cfg")
    cov = verify_accounting(policy, text)
    assert cov.blocking >= 1
    assert "transparent-firewall-mode" in [u.reason for u in blocking_lines(policy)]


def _annotated(path: Path, marker: str) -> list[tuple[int, str]]:
    """(line number of the NEXT line, annotation text) for every ``! <marker>:`` comment."""
    lines = path.read_text(encoding="utf-8").splitlines()
    return [
        (i + 2, line.split(f"{marker}:", 1)[1].strip())
        for i, line in enumerate(lines)
        if line.startswith(f"! {marker}:")
    ]


_ALL_FIXTURES = sorted((SAMPLES / "dead-configs").glob("*.cfg")) + sorted(
    (SAMPLES / "broken-configs").glob("*.cfg")
)


_ANNOTATED_FIXTURES = [
    p for p in _ALL_FIXTURES if _annotated(p, "UNSUPPORTED") or _annotated(p, "EXPECT-UNPARSED")
]


@pytest.mark.parametrize("path", _ANNOTATED_FIXTURES, ids=lambda p: p.name)
def test_every_unsupported_annotation_becomes_a_security_relevant_unparsed_line(
    path: Path,
) -> None:
    expected = _annotated(path, "UNSUPPORTED") + _annotated(path, "EXPECT-UNPARSED")
    policy = parse_config(path.read_text(encoding="utf-8"))
    got = {u.line_no: u for u in policy.unparsed}
    for line_no, reason in expected:
        assert line_no in got, f"{path.name}:{line_no} ({reason}) was not reported"
        assert got[line_no].security_relevant


def test_no_sample_line_falls_through_to_the_unclassified_safety_net() -> None:
    parsed = 0
    for path in _ALL_FIXTURES:
        try:
            policy = parse_config(path.read_text(encoding="utf-8"))
        except ParseError:
            continue  # the cycle / undefined-group fixtures fail by design
        parsed += 1
        assert "unclassified" not in {r.reason for r in policy.line_records}, path.name
    assert parsed >= 6


# ---------------------------------------------------------------------------
# verify_accounting rejects broken accounting
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def pix() -> tuple[Policy, str]:
    return _parse("dead-configs", "pix-2006-hq.cfg")


def test_missing_duplicate_and_reordered_records_are_rejected(pix: tuple[Policy, str]) -> None:
    policy, text = pix
    recs = policy.line_records
    for broken in (recs[:-1], [*recs, recs[0]], [recs[1], recs[0], *recs[2:]]):
        with pytest.raises(AccountingError):
            verify_accounting(policy.model_copy(update={"line_records": broken}), text)


def test_unknown_classification_is_rejected(pix: tuple[Policy, str]) -> None:
    policy, text = pix
    bad = policy.line_records[0].model_construct(
        line_no=1, text="x", classification="bogus", security_relevant=False
    )
    broken = policy.model_copy(update={"line_records": [bad, *policy.line_records[1:]]})
    with pytest.raises(AccountingError, match="unknown classification"):
        verify_accounting(broken, text)


def test_unparsed_entries_must_mirror_the_records() -> None:
    policy, text = _parse("broken-configs", "ios-unsupported-constructs.cfg")
    with pytest.raises(AccountingError, match="disagree"):
        verify_accounting(policy.model_copy(update={"unparsed": policy.unparsed[1:]}), text)
    flipped = [policy.unparsed[0].model_copy(update={"security_relevant": False})]
    mismatched = policy.model_copy(update={"unparsed": [*flipped, *policy.unparsed[1:]]})
    with pytest.raises(AccountingError, match="relevance"):
        verify_accounting(mismatched, text)


def test_empty_config_has_full_coverage() -> None:
    policy = parse_pix_asa("")
    cov = verify_accounting(policy, "")
    assert (cov.total_lines, cov.security_relevant, cov.ratio) == (0, 0, 1.0)


# ---------------------------------------------------------------------------
# P14: every input line is classified exactly once, whatever the input
# ---------------------------------------------------------------------------

ASA_POOL = [
    "ASA Version 8.2(5)", ": Saved", "!", "", "hostname fw", "names", "name 10.0.0.5 srv",
    "interface Ethernet0/0", " nameif outside", " security-level 0", " shutdown", " frobnicate",
    " ip address 192.0.2.2 255.255.255.0", "interface Ethernet0/1", " nameif inside",
    " security-level 100", " ip address 10.0.0.1 255.255.255.0",
    "object-group network G1", " network-object host 10.0.0.1", " group-object G2",
    " network-object 10.1.0.0 255.255.0.0", "object-group network G2", " description d",
    "object-group service S1 tcp", " port-object eq www", " port-object range 1 2",
    "object-group icmp-type I1", " icmp-object echo",
    "access-list A extended permit tcp any object-group G1 eq 80",
    "access-list A extended permit tcp any object-group MISSING eq 80",
    "access-list A remark hello", "access-list A extended deny ip any any log",
    "access-list A extended permit tcp any any eq bogusname",
    "access-list A extended permit ip any6 any6", "access-list B extended permit icmp any any I1",
    "access-list A extended permit tcp any any object-group S1 inactive",
    "access-group A in interface outside", "access-group B out interface inside",
    "route outside 0.0.0.0 0.0.0.0 192.0.2.1", "nat (inside) 1 10.0.0.0 255.0.0.0",
    "global (outside) 1 interface", "nat-control", "no nat-control", "conduit permit ip any any",
    "static (inside,outside) 192.0.2.9 10.0.0.9 netmask 255.255.255.255",
    "telnet 10.0.0.0 255.0.0.0 inside", "snmp-server community <redacted>",
    "crypto isakmp key <redacted> address 192.0.2.9", "policy-map global_policy",
    " class inspection_default", "firewall transparent", "mystery command", "mode multiple",
    "same-security-traffic permit inter-interface", "object network X", " host 10.0.0.9",
]  # fmt: skip

IOS_POOL = [
    "version 12.4", "hostname r1", "!", "", "no ip domain-lookup", "banner motd ^Chi^C",
    "interface FastEthernet0/0", " description WAN", " ip address 192.0.2.2 255.255.255.252",
    " ip access-group 101 in", " ip access-group 10 out", " shutdown", " mystery",
    "interface FastEthernet0/1", " ip address 10.0.0.1 255.255.255.0", " ip access-group X in",
    "access-list 101 permit tcp any any established", "access-list 101 deny ip any any log",
    "access-list 101 permit tcp any any eq frobnicate", "access-list 101 remark r",
    "access-list 101 permit ip 10.0.0.0 0.255.0.255 any",
    "access-list 10 permit 10.0.0.0 0.0.0.255",
    "access-list 10 deny any", "access-list 99 permit any", "access-list 700 permit any",
    "ip access-list extended X", " remark about X", " 10 permit tcp any any eq 22",
    " permit icmp any any echo", " deny ip any any", " permit ip any any fragments",
    "ip route 0.0.0.0 0.0.0.0 192.0.2.1", "ip route 10.9.0.0 255.255.0.0 Null0",
    "ip route 10.8.0.0 255.255.0.0 172.31.0.1", "line vty 0 4", " access-class 10 in",
    " transport input telnet ssh", " password <redacted>", "snmp-server community <redacted> RO 10",
    "route-map RM permit 10", " match ip address 99", "router ospf 1", " network 10.0.0.0",
    "zone-pair security A source b destination c", "ipv6 unicast-routing", "mystery command",
]  # fmt: skip

_JOINERS = st.sampled_from(["\n", "\r\n"])


def _text(pool: list[str]) -> st.SearchStrategy[str]:
    return st.builds(
        lambda lines, nl, trailing: nl.join(lines) + (nl if trailing else ""),
        st.lists(st.sampled_from(pool), max_size=40),
        _JOINERS,
        st.booleans(),
    )


def _check(policy: Policy, text: str) -> None:
    cov = verify_accounting(policy, text)
    assert cov.total_lines == len(split_lines(text))
    assert sum(cov.counts.values()) == cov.total_lines
    assert set(cov.counts) == set(CLASSES)
    assert [r.line_no for r in policy.line_records] == list(range(1, cov.total_lines + 1))
    assert "unclassified" not in {r.reason for r in policy.line_records}


@pytest.mark.pbt
@given(_text(ASA_POOL), st.sampled_from([Dialect.asa, Dialect.pix]))
def test_p14_pix_asa_every_line_classified_exactly_once(text: str, dialect: Dialect) -> None:
    try:
        policy = parse_pix_asa(text, dialect=dialect)
    except ParseError as err:
        assert err.code in {"undefined-group", "group-cycle", "group-kind-mismatch"}
        return
    _check(policy, text)


@pytest.mark.pbt
@given(_text(IOS_POOL))
def test_p14_ios_every_line_classified_exactly_once(text: str) -> None:
    _check(parse_ios(text), text)


@pytest.mark.pbt
@given(_text(ASA_POOL + IOS_POOL))
def test_p14_through_parse_config_after_redaction(text: str) -> None:
    try:
        policy = parse_config(text)
    except ParseError:
        return
    _check(policy, redact(text))
