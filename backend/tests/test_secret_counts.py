"""Secret counts for the report's rotation advice (migration-governance requirement 4.6).

The values below are synthetic placeholders made for these tests; they are not credentials.
"""

from __future__ import annotations

import pytest

from necro.parsers import parse_config
from necro.redact import redact
from necro.secret_counts import OTHER, classify, count_secrets
from tests.panos_helpers import SAMPLES

# (config line as written, the type the redacted line must be counted as)
LINES = [
    ("enable password synthetic-enable-1", "device enable password"),
    ("enable secret 5 $1$abcd$abcdefghijklmnopqrstuv", "device enable password"),
    ("passwd synthetic-passwd", "device password"),
    ("username ops password synthetic-user-1", "local user password"),
    ("snmp-server community synthetic-community RO", "SNMP community or credential"),
    ("snmp-server host inside 10.0.0.9 community synthetic-trap", "SNMP community or credential"),
    ("crypto isakmp key synthetic-psk address 198.51.100.9", "VPN pre-shared key"),
    ("tacacs-server key synthetic-tacacs", "AAA shared key"),
    ("radius-server key synthetic-radius", "AAA shared key"),
    ("ntp authentication-key 1 md5 synthetic-ntp", "NTP authentication key"),
    ("ldap-login-password synthetic-ldap", "LDAP login password"),
    ("ip ospf authentication-key synthetic-ospf", "routing authentication key"),
    ("neighbor 10.0.0.2 password synthetic-bgp", "routing authentication key"),
    ("failover key synthetic-failover", "failover key"),
    (" password synthetic-vty", "line or device password"),
]


@pytest.mark.parametrize(("line", "expected"), LINES)
def test_every_redacted_line_is_counted_under_its_type(line: str, expected: str) -> None:
    redacted = redact(line)
    assert "synthetic" not in redacted
    assert count_secrets(redacted.splitlines()) == {expected: 1}


def test_counts_are_by_type_sorted_and_one_per_line() -> None:
    lines = [
        "enable password <redacted>",
        "snmp-server community <redacted> RO",
        "snmp-server host inside 10.0.0.9 community <redacted> version 2c",
        "hostname lab",
        "! a comment with no placeholder",
    ]
    counts = count_secrets(lines)
    assert counts == {"SNMP community or credential": 2, "device enable password": 1}
    assert list(counts) == sorted(counts)


def test_a_certificate_block_is_one_secret_and_unknown_lines_are_not_dropped() -> None:
    counts = count_secrets(["<redacted certificate>", "something <redacted> odd"])
    assert counts == {"certificate block": 1, OTHER: 1}
    assert classify("  Enable Secret <redacted>  ") == "device enable password"


def test_no_secret_value_is_in_the_counts_of_the_samples() -> None:
    for sample in sorted(SAMPLES.glob("*.cfg")):
        policy = parse_config(sample.read_text(encoding="utf-8"))
        counts = count_secrets(r.text for r in policy.line_records)
        assert all(isinstance(k, str) and v > 0 for k, v in counts.items())
        assert OTHER not in counts, f"{sample.name}: a secret has no type"
