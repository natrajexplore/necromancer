"""Secret redaction: runs before any other module sees config text.

Replaces secret values with <redacted> while preserving line numbers and structure
so parsers can still classify every line correctly.

Patterns from security steering (all case-insensitive):
  - enable password / enable secret
  - passwd (standalone), username ... password|secret
  - password under line stanzas
  - snmp-server community, snmp-server host ... community, snmp-server user ... auth|priv
  - crypto isakmp key, pre-shared-key, ikev1|ikev2 ... pre-shared-key, key-string
  - tacacs-server key, radius-server key, aaa-server ... key
  - key <k> under tacacs-server host / radius-server host
  - ntp authentication-key, ldap-login-password
  - ospf message-digest-key, ip ospf authentication-key, neighbor ... password
  - failover key
  - Type 5/7/8/9 hashes (dollar-sign patterns)
  - crypto ca certificate blocks (certificate ... quit) collapsed to one line

PBT P10: no known secret token from generated configs appears in any output.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Compiled patterns — anchored, one small non-backtracking regex per statement type.
# Groups: (1) prefix to keep, (2) value to redact, (3) suffix to keep.
# ---------------------------------------------------------------------------

# Inline type-5 MD5 hash: $1$<salt>$<hash>
_TYPE5_RE = re.compile(r"\$1\$[^\s$]{1,8}\$[A-Za-z0-9./]{22}")

# Inline type-8 (PBKDF2-SHA256): $8$<salt>$<hash>
_TYPE8_RE = re.compile(r"\$8\$[A-Za-z0-9./+]{14}\$[A-Za-z0-9./+]{43}")

# Inline type-9 (scrypt): $9$<salt>$<hash>
_TYPE9_RE = re.compile(r"\$9\$[A-Za-z0-9./+]{14}\$[A-Za-z0-9./+]{43}")

# Type-7 reversible hash: "7 <hex>" token
_TYPE7_RE = re.compile(r"\b7\s+([0-9A-Fa-f]{2,50})\b")

# enable password|secret [<enc-type>] <secret>
_ENABLE_RE = re.compile(
    r"^(\s*enable\s+(?:password|secret)\s+(?:[0-9]\s+)?)(\S+)(.*)",
    re.IGNORECASE,
)

# passwd <secret>
_PASSWD_RE = re.compile(r"^(\s*passwd\s+)(\S+)(.*)", re.IGNORECASE)

# username <name> password|secret [<enc-type>] <secret>
_USERNAME_RE = re.compile(
    r"^(\s*username\s+\S+\s+(?:password|secret)\s+(?:[0-9]\s+)?)(\S+)(.*)",
    re.IGNORECASE,
)

# password [<enc-type>] <secret>  (line stanza or generic)
_PASSWORD_LINE_RE = re.compile(r"^(\s*password\s+(?:[0-9]\s+)?)(\S+)(.*)", re.IGNORECASE)

# snmp-server community <community> [...]
_SNMP_COMMUNITY_RE = re.compile(r"^(\s*snmp-server\s+community\s+)(\S+)(.*)", re.IGNORECASE)

# snmp-server host <ip> [traps|informs] [version <v>] <community> [...]
_SNMP_HOST_RE = re.compile(
    r"^(\s*snmp-server\s+host\s+\S+(?:\s+(?:traps|informs))?(?:\s+version\s+\S+)?\s+)(\S+)(.*)",
    re.IGNORECASE,
)

# snmp-server user <name> <group> [v3] auth <alg> <authpass> [...]
_SNMP_USER_AUTH_RE = re.compile(
    r"^(\s*snmp-server\s+user\s+\S+\s+\S+(?:\s+v3)?\s+auth\s+\S+\s+)(\S+)(.*)",
    re.IGNORECASE,
)

# crypto isakmp key <key> address <addr>
_ISAKMP_KEY_RE = re.compile(r"^(\s*crypto\s+isakmp\s+key\s+)(\S+)(.*)", re.IGNORECASE)

# pre-shared-key / ikev1|ikev2 ... pre-shared-key [local|remote] <key>
_PSK_RE = re.compile(
    r"^(\s*(?:ikev[12]\s+(?:local|remote)-authentication\s+)?pre-shared-key"
    r"\s+(?:local\s+|remote\s+)?)(\S+)(.*)",
    re.IGNORECASE,
)

# key-string <key>
_KEY_STRING_RE = re.compile(r"^(\s*key-string\s+)(\S+)(.*)", re.IGNORECASE)

# tacacs-server key <key>
_TACACS_KEY_RE = re.compile(r"^(\s*tacacs-server\s+key\s+)(\S+)(.*)", re.IGNORECASE)

# radius-server key <key>
_RADIUS_KEY_RE = re.compile(r"^(\s*radius-server\s+key\s+)(\S+)(.*)", re.IGNORECASE)

# aaa-server <grp> [(<iface>)] host <ip> <key>
_AAA_KEY_RE = re.compile(
    r"^(\s*aaa-server\s+\S+(?:\s+\(\S+\))?\s+host\s+\S+\s+)(\S+)(.*)",
    re.IGNORECASE,
)

# key <k>  (inside tacacs-server host / radius-server host block)
_KEY_RE = re.compile(r"^(\s*key\s+)(\S+)(.*)", re.IGNORECASE)

# ntp authentication-key <id> <alg> <key>
_NTP_AUTH_KEY_RE = re.compile(
    r"^(\s*ntp\s+authentication-key\s+\d+\s+\S+\s+)(\S+)(.*)", re.IGNORECASE
)

# ldap-login-password <password>
_LDAP_LOGIN_RE = re.compile(r"^(\s*ldap-login-password\s+)(\S+)(.*)", re.IGNORECASE)

# ospf message-digest-key <id> md5 <key>  /  ip ospf authentication-key <key>
_OSPF_MD5_RE = re.compile(
    r"^(\s*(?:ip\s+)?ospf\s+(?:message-digest-key\s+\d+\s+md5\s+|authentication-key\s+))(\S+)(.*)",
    re.IGNORECASE,
)

# neighbor <ip> password [<enc-type>] <key>  (BGP)
_BGP_NEIGHBOR_PW_RE = re.compile(
    r"^(\s*neighbor\s+\S+\s+password\s+(?:[0-9]\s+)?)(\S+)(.*)", re.IGNORECASE
)

# failover key <key>
_FAILOVER_KEY_RE = re.compile(r"^(\s*failover\s+key\s+)(\S+)(.*)", re.IGNORECASE)

# ssl trust-point <tp> <passphrase>  (passphrase is the third token)
_SSL_TRUST_RE = re.compile(r"^(\s*ssl\s+trust-point\s+\S+\s+)(\S+)(.*)", re.IGNORECASE)

# Ordered list — first match wins per line.
_LINE_PATTERNS: list[re.Pattern[str]] = [
    _ENABLE_RE,
    _PASSWD_RE,
    _USERNAME_RE,
    _PASSWORD_LINE_RE,
    _SNMP_COMMUNITY_RE,
    _SNMP_HOST_RE,
    _SNMP_USER_AUTH_RE,
    _ISAKMP_KEY_RE,
    _PSK_RE,
    _KEY_STRING_RE,
    _TACACS_KEY_RE,
    _RADIUS_KEY_RE,
    _AAA_KEY_RE,
    _KEY_RE,
    _NTP_AUTH_KEY_RE,
    _LDAP_LOGIN_RE,
    _OSPF_MD5_RE,
    _BGP_NEIGHBOR_PW_RE,
    _FAILOVER_KEY_RE,
    _SSL_TRUST_RE,
]

# Certificate block delimiters
_CERT_BEGIN_RE = re.compile(r"^\s*certificate\s+", re.IGNORECASE)
_CERT_END_RE = re.compile(r"^\s*quit\s*$", re.IGNORECASE)

# Inline hash patterns applied after line-level patterns
_INLINE_HASH_PATTERNS: list[re.Pattern[str]] = [
    _TYPE5_RE,
    _TYPE8_RE,
    _TYPE9_RE,
]

_REDACTED = "<redacted>"
_REDACTED_CERT = "<redacted certificate>"


def _redact_inline_hashes(line: str) -> str:
    for pattern in _INLINE_HASH_PATTERNS:
        line = pattern.sub(_REDACTED, line)
    line = _TYPE7_RE.sub(r"7 <redacted>", line)
    return line


def _redact_asa_snmp_host(line: str) -> str | None:
    """ASA form: ``snmp-server host <if> <ip> ... community <c> ...``.

    The community follows the literal keyword, so the IOS pattern (which assumes the community is
    the first free token after the address) would redact the address and leak the community.
    Returns None when the line is not in this form. Linear scan, no regex.
    """
    spans: list[tuple[int, int]] = []
    start = -1
    for i, ch in enumerate(line + " "):
        if ch.isspace():
            if start >= 0:
                spans.append((start, i))
                start = -1
        elif start < 0:
            start = i
    words = [line[a:b] for a, b in spans]
    if len(words) < 5 or words[0].lower() != "snmp-server" or words[1].lower() != "host":
        return None
    for idx in range(3, len(words) - 1):
        if words[idx].lower() == "community":
            a, b = spans[idx + 1]
            return line[:a] + _REDACTED + line[b:]
    return None


def redact(text: str) -> str:
    """Redact all secrets from a firewall config text.

    Replaces secret values with <redacted>, preserving line structure.
    Certificate blocks (certificate ... quit) are collapsed to one placeholder line.

    Returns the redacted text. Line count is preserved where possible.
    """
    lines = text.splitlines(keepends=True)
    result: list[str] = []
    in_cert_block = False

    for line in lines:
        stripped = line.rstrip("\r\n")

        if _CERT_BEGIN_RE.match(stripped):
            in_cert_block = True
            result.append(_REDACTED_CERT + "\n")
            continue

        if in_cert_block:
            if _CERT_END_RE.match(stripped):
                in_cert_block = False
            result.append("")
            continue

        redacted_line = stripped
        asa_snmp = _redact_asa_snmp_host(redacted_line)
        if asa_snmp is not None:
            redacted_line = asa_snmp
        else:
            for pattern in _LINE_PATTERNS:
                m = pattern.match(redacted_line)
                if m:
                    redacted_line = m.group(1) + _REDACTED + m.group(3)
                    break

        redacted_line = _redact_inline_hashes(redacted_line)

        ending = line[len(stripped) :]
        result.append(redacted_line + ending)

    return "".join(result)


def redact_lines(lines: list[str]) -> list[str]:
    """Redact a list of bare lines (no line endings). Returns a new list."""
    return redact("\n".join(lines)).splitlines()
