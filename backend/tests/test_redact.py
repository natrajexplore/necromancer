"""Tests for redact.py (task 2.5) — includes PBT P10.

The test strings like "SomeSekret", "hunter2", etc. are synthetic placeholders
used exclusively to verify that the redaction engine removes them. They are
test inputs, not real credentials.
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from necro.redact import redact, redact_lines

REDACTED = "<redacted>"


def r(text: str) -> str:
    """Redact a single-line string and strip trailing newline."""
    return redact(text).rstrip("\n")


# ---------------------------------------------------------------------------
# Unit tests: each redaction pattern
# ---------------------------------------------------------------------------


def test_enable_password() -> None:
    out = r("enable password SomeSekret")
    assert REDACTED in out
    assert "SomeSekret" not in out


def test_enable_secret() -> None:
    out = r("enable secret MySecret123")
    assert REDACTED in out
    assert "MySecret123" not in out


def test_enable_secret_type5() -> None:
    # Synthetic type-5 hash (not a real credential)
    line = "enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0"
    out = r(line)
    assert "enable secret" in out
    assert "$1$" not in out


def test_passwd() -> None:
    out = r("passwd ClearText")
    assert REDACTED in out
    assert "ClearText" not in out


def test_username_password() -> None:
    out = r("username admin password 0 hunter2")
    assert REDACTED in out
    assert "hunter2" not in out


def test_username_secret() -> None:
    out = r("username ops secret MyPass")
    assert REDACTED in out
    assert "MyPass" not in out


def test_password_line_stanza() -> None:
    out = r("password cisco123")
    assert REDACTED in out
    assert "cisco123" not in out


def test_snmp_community() -> None:
    out = r("snmp-server community public RO")
    assert REDACTED in out
    assert "public" not in out


def test_snmp_host_community() -> None:
    # RFC 5737 address
    out = r("snmp-server host 192.0.2.10 version 2c mycommunity")
    assert REDACTED in out
    assert "mycommunity" not in out


def test_snmp_user_auth() -> None:
    out = r("snmp-server user v3user grp1 v3 auth sha AuthPass1 priv aes 128 PrivPass2")
    assert REDACTED in out
    assert "AuthPass1" not in out


def test_crypto_isakmp_key() -> None:
    # RFC 5737 address
    out = r("crypto isakmp key MySuperKey address 192.0.2.1")
    assert REDACTED in out
    assert "MySuperKey" not in out


def test_pre_shared_key() -> None:
    out = r(" pre-shared-key MyPSK")
    assert REDACTED in out
    assert "MyPSK" not in out


def test_ikev2_pre_shared_key() -> None:
    out = r(" ikev2 local-authentication pre-shared-key mykey")
    assert REDACTED in out
    assert "mykey" not in out


def test_key_string() -> None:
    out = r("key-string MyKeyStr")
    assert REDACTED in out
    assert "MyKeyStr" not in out


def test_tacacs_server_key() -> None:
    out = r("tacacs-server key TacacsSecret")
    assert REDACTED in out
    assert "TacacsSecret" not in out


def test_radius_server_key() -> None:
    out = r("radius-server key RadiusSecret")
    assert REDACTED in out
    assert "RadiusSecret" not in out


def test_aaa_server_key() -> None:
    # RFC 5737 address
    out = r("aaa-server TACACS+ (inside) host 192.0.2.5 TacacsKey")
    assert REDACTED in out
    assert "TacacsKey" not in out


def test_key_block() -> None:
    out = r(" key MyKey")
    assert REDACTED in out
    assert "MyKey" not in out


def test_ntp_authentication_key() -> None:
    out = r("ntp authentication-key 1 md5 ntpkey")
    assert REDACTED in out
    assert "ntpkey" not in out


def test_ldap_login_password() -> None:
    out = r("ldap-login-password myldappass")
    assert REDACTED in out
    assert "myldappass" not in out


def test_ospf_message_digest_key() -> None:
    out = r("ospf message-digest-key 1 md5 ospfkey")
    assert REDACTED in out
    assert "ospfkey" not in out


def test_ip_ospf_auth_key() -> None:
    out = r("ip ospf authentication-key ospfsecret")
    assert REDACTED in out
    assert "ospfsecret" not in out


def test_neighbor_password() -> None:
    # RFC 5737 address
    out = r("neighbor 192.0.2.1 password bgpsecret")
    assert REDACTED in out
    assert "bgpsecret" not in out


def test_failover_key() -> None:
    out = r("failover key failsecret")
    assert REDACTED in out
    assert "failsecret" not in out


# ---------------------------------------------------------------------------
# Certificate block
# ---------------------------------------------------------------------------


def test_cert_block_collapsed() -> None:
    cfg = "\n".join(
        [
            "crypto ca certificate chain ROOTCA",
            "certificate 01",
            "  AABBCCDD",
            "  EEFF0011",
            "quit",
            "hostname router",
        ]
    )
    out = redact(cfg)
    assert "<redacted certificate>" in out
    assert "AABBCCDD" not in out
    assert "hostname router" in out


# ---------------------------------------------------------------------------
# Type-7 inline hash redaction
# ---------------------------------------------------------------------------


def test_type7_inline() -> None:
    out = r("username admin password 7 03174E0D1A0D")
    assert "03174E0D1A0D" not in out
    assert REDACTED in out


# ---------------------------------------------------------------------------
# Non-secret lines are preserved; line structure is maintained
# ---------------------------------------------------------------------------


def test_non_secret_lines_unchanged() -> None:
    # RFC 5737 address
    cfg = "hostname router\ninterface GigabitEthernet0/0\n ip address 192.0.2.1 255.255.255.0\n"
    out = redact(cfg)
    assert "hostname router" in out
    assert "192.0.2.1" in out


def test_line_count_preserved() -> None:
    cfg = "hostname router\nenable password secret123\ninterface Gi0/0\n"
    assert len(redact(cfg).splitlines()) == len(cfg.splitlines())


def test_redact_lines_function() -> None:
    lines = ["enable password abc", "hostname fw"]
    out = redact_lines(lines)
    assert "abc" not in out[0]
    assert "hostname fw" in out[1]


# ---------------------------------------------------------------------------
# PBT P10: no generated secret appears verbatim in redacted output
# ---------------------------------------------------------------------------

_secret_st = st.text(
    alphabet=st.characters(
        whitelist_categories=("Lu", "Ll", "Nd"),
        whitelist_characters="_-",
    ),
    min_size=4,
    max_size=20,
)


@pytest.mark.pbt
@given(secret=_secret_st)
def test_pbt_enable_password_redacted(secret: str) -> None:
    """enable password <secret>: generated secret never appears in redacted output."""
    line = f"enable password {secret}"
    out = redact(line)
    if secret != REDACTED:
        assert secret not in out


@pytest.mark.pbt
@given(secret=_secret_st)
def test_pbt_snmp_community_redacted(secret: str) -> None:
    """snmp-server community <secret>: generated secret never appears in redacted output."""
    line = f"snmp-server community {secret} RO"
    out = redact(line)
    if secret != REDACTED:
        assert secret not in out


@pytest.mark.pbt
@given(secret=_secret_st)
def test_pbt_pre_shared_key_redacted(secret: str) -> None:
    """pre-shared-key <secret>: generated secret never appears in redacted output."""
    line = f"pre-shared-key {secret}"
    out = redact(line)
    if secret != REDACTED:
        assert secret not in out


@pytest.mark.pbt
@given(secret=_secret_st)
def test_pbt_tacacs_key_redacted(secret: str) -> None:
    """tacacs-server key <secret>: generated secret never appears in redacted output."""
    line = f"tacacs-server key {secret}"
    out = redact(line)
    if secret != REDACTED:
        assert secret not in out
