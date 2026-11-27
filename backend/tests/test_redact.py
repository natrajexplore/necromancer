"""Tests for redact.py (task 2.5) -- includes PBT P10.

The test strings like "SomeSekret", "hunter2", etc. are synthetic placeholders
used exclusively to verify that the redaction engine removes them. They are
test inputs, not real credentials.
"""

from __future__ import annotations

import pytest
from hypothesis import example, given
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
# PBT P10: redacted output has the value position replaced with exactly
# <redacted>, not merely "secret not in output".
#
# The old oracle (assert secret not in out) was wrong for secrets that are
# substrings of a keyword prefix.  Example: secret="taca" is a substring of
# "tacacs-server", so the correct redacted line "tacacs-server key <redacted>"
# still contains "taca" -- that is correct behaviour, not a leak.
#
# The fix: reconstruct the exact expected line and assert equality.  This is
# stricter than the old check: it verifies both that the value was replaced
# and that nothing else on the line changed.
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
    """enable password <secret>: value position is exactly <redacted>."""
    line = f"enable password {secret}"
    out = redact(line).rstrip("\n")
    assert out == f"enable password {REDACTED}"


@pytest.mark.pbt
@given(secret=_secret_st)
def test_pbt_snmp_community_redacted(secret: str) -> None:
    """snmp-server community <secret> RO: value position is exactly <redacted>."""
    line = f"snmp-server community {secret} RO"
    out = redact(line).rstrip("\n")
    assert out == f"snmp-server community {REDACTED} RO"


@pytest.mark.pbt
@given(secret=_secret_st)
def test_pbt_pre_shared_key_redacted(secret: str) -> None:
    """pre-shared-key <secret>: value position is exactly <redacted>."""
    line = f"pre-shared-key {secret}"
    out = redact(line).rstrip("\n")
    assert out == f"pre-shared-key {REDACTED}"


@pytest.mark.pbt
@example(secret="taca")
@given(secret=_secret_st)
def test_pbt_tacacs_key_redacted(secret: str) -> None:
    """tacacs-server key <secret>: value position is exactly <redacted>.

    The old oracle (assert secret not in out) failed for secrets that are
    substrings of the keyword prefix -- e.g. secret="taca" appears in
    "tacacs-server" even after correct redaction.  The fix is to assert the
    full reconstructed line, which is both stricter and correct.
    """
    line = f"tacacs-server key {secret}"
    out = redact(line).rstrip("\n")
    assert out == f"tacacs-server key {REDACTED}"


def test_snmp_host_community_asa_form() -> None:
    # ASA/PIX form: the community follows the literal keyword; the address must stay.
    out = r("snmp-server host inside 192.0.2.10 poll community mycommunity version 2c")
    assert out == "snmp-server host inside 192.0.2.10 poll community <redacted> version 2c"
    assert r("snmp-server host inside 192.0.2.10 community trapcomm").endswith(
        "community <redacted>"
    )
    # No community keyword: the IOS pattern still applies.
    assert "mycommunity" not in r("snmp-server host 192.0.2.10 mycommunity")


@pytest.mark.pbt
@given(secret=_secret_st)
def test_pbt_asa_snmp_host_community_redacted(secret: str) -> None:
    line = f"snmp-server host inside 192.0.2.10 community {secret} version 2c"
    assert r(line) == "snmp-server host inside 192.0.2.10 community <redacted> version 2c"


# ---------------------------------------------------------------------------
# Regression tests for confirmed leaks (one per leaking form). Each asserts the exact line:
# the encryption-type digit stays, the secret and nothing else is replaced.
# ---------------------------------------------------------------------------


def test_leak_tacacs_server_key_with_type_digit() -> None:
    assert r("tacacs-server key 7 S3cretTacacs") == "tacacs-server key 7 <redacted>"


def test_leak_radius_server_key_with_type_digit() -> None:
    assert r("radius-server key 7 S3cretRadius") == "radius-server key 7 <redacted>"
    assert r("radius-server key S3cretRadius") == "radius-server key <redacted>"


def test_leak_server_host_key_with_type_digit() -> None:
    out = r("tacacs-server host 192.0.2.7 key 7 S3cretHost")
    assert out == "tacacs-server host 192.0.2.7 key 7 <redacted>"


def test_leak_aaa_server_host_with_key_keyword() -> None:
    assert (
        r("aaa-server T host 10.10.1.5 key S3cretAaa")
        == "aaa-server T host 10.10.1.5 key <redacted>"
    )
    assert (
        r("aaa-server T (inside) host 10.10.1.5 key S3cretAaa timeout 5")
        == "aaa-server T (inside) host 10.10.1.5 key <redacted> timeout 5"
    )
    # Without the keyword the value is the word after the address.
    assert r("aaa-server T host 10.10.1.5 S3cretAaa") == "aaa-server T host 10.10.1.5 <redacted>"


def test_leak_username_attributes_before_secret() -> None:
    out = r("username a privilege 15 secret 5 S3cretUser")
    assert out == "username a privilege 15 secret 5 <redacted>"
    assert r("username a privilege 15 password S3cretUser") == (
        "username a privilege 15 password <redacted>"
    )
    assert r("username a password S3cretUser privilege 15") == (
        "username a password <redacted> privilege 15"
    )


def test_leak_pix_isakmp_key_without_crypto() -> None:
    out = r("isakmp key S3cretPsk address 192.0.2.9 netmask 255.255.255.255")
    assert out == "isakmp key <redacted> address 192.0.2.9 netmask 255.255.255.255"
    assert r("crypto isakmp key 6 S3cretPsk address 192.0.2.9") == (
        "crypto isakmp key 6 <redacted> address 192.0.2.9"
    )


def test_leak_ftp_server_password() -> None:
    assert r("ftp-server password S3cretFtp") == "ftp-server password <redacted>"
    assert r("ip ftp password 7 S3cretFtp") == "ip ftp password 7 <redacted>"


def test_leak_ppp_chap_password() -> None:
    assert r("ppp chap password S3cretPpp") == "ppp chap password <redacted>"
    assert r("ppp pap sent-username u password S3cretPpp") == (
        "ppp pap sent-username u password <redacted>"
    )


def test_leak_ikev1_pre_shared_key_in_tunnel_group() -> None:
    assert r(" ikev1 pre-shared-key S3cretPsk") == " ikev1 pre-shared-key <redacted>"


def test_leak_enable_password_with_level() -> None:
    assert r("enable password level 5 S3cretLvl") == "enable password level 5 <redacted>"


def test_leak_snmp_user_priv_password() -> None:
    out = r("snmp-server user u g v3 auth sha AuthPw1234 priv aes 128 PrivPw1234")
    assert out == "snmp-server user u g v3 auth sha <redacted> priv aes 128 <redacted>"


@pytest.mark.parametrize("enc", ["0", "5", "7", "md5", "sha"])
def test_encryption_type_word_is_kept_and_the_secret_replaced(enc: str) -> None:
    for head in (
        "tacacs-server key",
        "radius-server key",
        "aaa-server T host 10.10.1.5 key",
        "isakmp key",
        "ftp-server password",
        "ppp chap password",
        "ntp-future passphrase",
    ):
        assert r(f"{head} {enc} S3cretValue") == f"{head} {enc} <redacted>", head


# ---- generic fallback ----


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("future-cmd password S3cret", "future-cmd password <redacted>"),
        ("future-cmd secret 5 S3cret extra", "future-cmd secret 5 <redacted> extra"),
        ("future-cmd community S3cret", "future-cmd community <redacted>"),
        ("future-cmd pre-shared-key S3cret", "future-cmd pre-shared-key <redacted>"),
        ("future-cmd key-string 7 S3cret", "future-cmd key-string 7 <redacted>"),
        ("future-cmd passphrase md5 S3cret", "future-cmd passphrase md5 <redacted>"),
        (
            "future-cmd authentication-key sha256 S3cret",
            "future-cmd authentication-key sha256 <redacted>",
        ),
        ("  future-cmd key S3cret", "  future-cmd key <redacted>"),
    ],
)
def test_generic_fallback_redacts_the_word_after_the_keyword(line: str, expected: str) -> None:
    assert r(line) == expected


@pytest.mark.parametrize(
    "line",
    [
        "access-list password extended permit tcp any any eq 22",
        "access-list OUT extended permit tcp any object-group key eq 22",
        "access-list secret remark key community",
        "ip access-list extended password",
        " permit tcp any host 192.0.2.1 object-group key",
        "10 deny ip any any log secret",
        "object-group network password",
        "object-group service key tcp",
        "object network secret",
        " network-object object key",
        "name 192.0.2.1 key description password",
        "names",
        "nameif password",
        " nameif key",
        "description the key community password",
        "crypto key generate rsa modulus 2048",
        "key chain CHAIN1",
        "service password-encryption",
        "hostname key",
    ],
)
def test_generic_fallback_leaves_names_alone(line: str) -> None:
    assert r(line) == line


def test_the_generic_fallback_skips_lines_already_redacted() -> None:
    assert r("enable password S3cret") == "enable password <redacted>"
    assert r("snmp-server host inside 192.0.2.10 community S3cret version 2c").count(REDACTED) == 1


def test_a_very_long_line_is_redacted_in_linear_time() -> None:
    line = "future-cmd " + "password " * 50_000 + "S3cret"
    assert "S3cret" not in redact(line)
