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
from collections.abc import Iterable

# ---------------------------------------------------------------------------
# Compiled patterns — anchored, one small non-backtracking regex per statement type.
# Groups: (1) prefix to keep, (2) value to redact, (3) suffix to keep.
# ---------------------------------------------------------------------------

# Optional encryption-type token before a secret: one digit (0/5/6/7/8/9) or md5/sha/sha256.
_ENC = r"(?:(?:[0-9]|md5|sha256|sha)\s+)?"

# Inline type-5 MD5 hash: $1$<salt>$<hash>
_TYPE5_RE = re.compile(r"\$1\$[^\s$]{1,8}\$[A-Za-z0-9./]{22}")

# Inline type-8 (PBKDF2-SHA256): $8$<salt>$<hash>
_TYPE8_RE = re.compile(r"\$8\$[A-Za-z0-9./+]{14}\$[A-Za-z0-9./+]{43}")

# Inline type-9 (scrypt): $9$<salt>$<hash>
_TYPE9_RE = re.compile(r"\$9\$[A-Za-z0-9./+]{14}\$[A-Za-z0-9./+]{43}")

# Type-7 reversible hash: "7 <hex>" token
_TYPE7_RE = re.compile(r"\b7\s+([0-9A-Fa-f]{2,50})\b")

# enable password|secret [level <n>] [<enc-type>] <secret>
_ENABLE_RE = re.compile(
    r"^(\s*enable\s+(?:password|secret)\s+(?:level\s+\d+\s+)?" + _ENC + r")(\S+)(.*)",
    re.IGNORECASE,
)

# passwd <secret>
_PASSWD_RE = re.compile(r"^(\s*passwd\s+)(\S+)(.*)", re.IGNORECASE)

# username <name> [attributes...] password|secret [<enc-type>] <secret>: see _redact_username.

# password [<enc-type>] <secret>  (line stanza or generic)
_PASSWORD_LINE_RE = re.compile(r"^(\s*password\s+" + _ENC + r")(\S+)(.*)", re.IGNORECASE)

# ftp-server password / ip ftp password [<enc-type>] <secret>
_FTP_PASSWORD_RE = re.compile(
    r"^(\s*(?:ip\s+ftp|ftp-server)\s+password\s+" + _ENC + r")(\S+)(.*)", re.IGNORECASE
)

# ppp chap|pap password [<enc-type>] <secret>
_PPP_PASSWORD_RE = re.compile(
    r"^(\s*ppp\s+(?:chap|pap)\s+password\s+" + _ENC + r")(\S+)(.*)", re.IGNORECASE
)

# snmp-server community <community> [...]
_SNMP_COMMUNITY_RE = re.compile(r"^(\s*snmp-server\s+community\s+)(\S+)(.*)", re.IGNORECASE)

# snmp-server host <ip> [traps|informs] [version <v>] <community> [...]
_SNMP_HOST_RE = re.compile(
    r"^(\s*snmp-server\s+host\s+\S+(?:\s+(?:traps|informs))?(?:\s+version\s+\S+)?\s+)(\S+)(.*)",
    re.IGNORECASE,
)

# snmp-server user <name> <group> [v3] auth <alg> <authpass> [priv <alg> [bits] <privpass>]:
# see _redact_snmp_user.

# [crypto] isakmp key [<enc-type>] <key> address <addr>   (the PIX form has no "crypto")
_ISAKMP_KEY_RE = re.compile(
    r"^(\s*(?:crypto\s+)?isakmp\s+key\s+" + _ENC + r")(\S+)(.*)", re.IGNORECASE
)

# pre-shared-key / ikev1|ikev2 ... pre-shared-key [local|remote] <key>
_PSK_RE = re.compile(
    r"^(\s*(?:ikev[12]\s+(?:(?:local|remote)-authentication\s+)?)?pre-shared-key"
    r"\s+(?:local\s+|remote\s+)?" + _ENC + r")(\S+)(.*)",
    re.IGNORECASE,
)

# key-string <key>
_KEY_STRING_RE = re.compile(r"^(\s*key-string\s+" + _ENC + r")(\S+)(.*)", re.IGNORECASE)

# tacacs-server key <key>
_TACACS_KEY_RE = re.compile(
    r"^(\s*tacacs-server\s+(?:host\s+\S+\s+)?key\s+" + _ENC + r")(\S+)(.*)",
    re.IGNORECASE,
)

# radius-server key <key>
_RADIUS_KEY_RE = re.compile(
    r"^(\s*radius-server\s+(?:host\s+\S+\s+)?key\s+" + _ENC + r")(\S+)(.*)",
    re.IGNORECASE,
)

# aaa-server <grp> [(<iface>)] host <ip> [key] [<enc-type>] <key>
_AAA_KEY_RE = re.compile(
    r"^(\s*aaa-server\s+\S+(?:\s+\(\S+\))?\s+host\s+\S+\s+(?:key\s+)?" + _ENC + r")(\S+)(.*)",
    re.IGNORECASE,
)

# key <k>  (inside tacacs-server host / radius-server host block)
_KEY_RE = re.compile(r"^(\s*key\s+(?!chain\b)" + _ENC + r")(\S+)(.*)", re.IGNORECASE)

# ntp authentication-key <id> <alg> <key>
_NTP_AUTH_KEY_RE = re.compile(
    r"^(\s*ntp\s+authentication-key\s+\d+\s+\S+\s+)(\S+)(.*)", re.IGNORECASE
)

# ldap-login-password <password>
_LDAP_LOGIN_RE = re.compile(r"^(\s*ldap-login-password\s+" + _ENC + r")(\S+)(.*)", re.IGNORECASE)

# ospf message-digest-key <id> md5 <key>  /  ip ospf authentication-key <key>
_OSPF_MD5_RE = re.compile(
    r"^(\s*(?:ip\s+)?ospf\s+(?:message-digest-key\s+\d+\s+md5\s+|authentication-key\s+)"
    + _ENC
    + r")(\S+)(.*)",
    re.IGNORECASE,
)

# neighbor <ip> password [<enc-type>] <key>  (BGP)
_BGP_NEIGHBOR_PW_RE = re.compile(
    r"^(\s*neighbor\s+\S+\s+password\s+" + _ENC + r")(\S+)(.*)", re.IGNORECASE
)

# failover key <key>
_FAILOVER_KEY_RE = re.compile(
    r"^(\s*failover\s+(?:ipsec\s+)?key\s+" + _ENC + r")(\S+)(.*)", re.IGNORECASE
)

# ssl trust-point <tp> <passphrase>  (passphrase is the third token)
_SSL_TRUST_RE = re.compile(r"^(\s*ssl\s+trust-point\s+\S+\s+)(\S+)(.*)", re.IGNORECASE)

# Ordered list — first match wins per line.
_LINE_PATTERNS: list[re.Pattern[str]] = [
    _ENABLE_RE,
    _PASSWD_RE,
    _PASSWORD_LINE_RE,
    _FTP_PASSWORD_RE,
    _PPP_PASSWORD_RE,
    _SNMP_COMMUNITY_RE,
    _SNMP_HOST_RE,
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
_ENC_WORDS = frozenset({"md5", "sha", "sha256"})

# Words after which the next word is a secret, for lines no specific pattern matched.
_GENERIC_KEYWORDS = frozenset(
    {
        "password",
        "secret",
        "key",
        "community",
        "pre-shared-key",
        "key-string",
        "passphrase",
        "authentication-key",
    }
)

# Statements where those words are names or free text, never secrets.
_NAME_LINES = frozenset(
    {
        "access-list",
        "access-group",
        "access-class",
        "ipv6",
        "object",
        "object-group",
        "group-object",
        "network-object",
        "service-object",
        "protocol-object",
        "port-object",
        "icmp-object",
        "name",
        "names",
        "nameif",
        "description",
        "remark",
        "permit",
        "deny",
        "inactive",
        "hostname",
        "domain-name",
        "interface",
        "route-map",
        "class-map",
        "policy-map",
    }
)

# Words after "key" that are subcommands, not values.
_STRUCTURAL_NEXT = frozenset({"chain", "generate", "zeroize", "exchange"})
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


def _words(line: str) -> list[tuple[int, int]]:
    """Start and end offsets of the whitespace-separated words of a line (linear scan)."""
    spans: list[tuple[int, int]] = []
    start = -1
    for i, ch in enumerate(line + " "):
        if ch.isspace():
            if start >= 0:
                spans.append((start, i))
                start = -1
        elif start < 0:
            start = i
    return spans


def _is_enc_type(word: str) -> bool:
    lowered = word.lower()
    return lowered in _ENC_WORDS or (len(lowered) == 1 and lowered.isdigit())


def _secret_index(line: str, spans: list[tuple[int, int]], keyword_at: int) -> int | None:
    """Index of the word holding the secret after the keyword at ``keyword_at``.

    Skips one encryption-type word, but only when another word follows it, so a bare
    ``key 7`` still treats the 7 as the secret.
    """
    idx = keyword_at + 1
    if idx >= len(spans):
        return None
    if _is_enc_type(line[spans[idx][0] : spans[idx][1]]) and idx + 1 < len(spans):
        idx += 1
    return idx


def _replace_words(line: str, spans: list[tuple[int, int]], indices: Iterable[int]) -> str:
    """Replace the words at ``indices`` with the placeholder in one pass (linear)."""
    out: list[str] = []
    pos = 0
    for at in sorted(set(indices)):
        a, b = spans[at]
        out.append(line[pos:a])
        out.append(_REDACTED)
        pos = b
    out.append(line[pos:])
    return "".join(out)


def _redact_username(line: str) -> str | None:
    """``username <name> [attributes...] password|secret [<enc-type>] <secret> ...``."""
    spans = _words(line)
    if len(spans) < 4 or line[spans[0][0] : spans[0][1]].lower() != "username":
        return None
    for i in range(2, len(spans) - 1):
        if line[spans[i][0] : spans[i][1]].lower() in ("password", "secret"):
            at = _secret_index(line, spans, i)
            return None if at is None else _replace_words(line, spans, [at])
    return None


def _redact_snmp_user(line: str) -> str | None:
    """``snmp-server user <n> <g> [v3] auth <alg> <pw> [priv <alg> [bits] <pw>]``."""
    spans = _words(line)
    words = [line[a:b].lower() for a, b in spans]
    if len(words) < 7 or words[0] != "snmp-server" or words[1] != "user":
        return None
    hits: list[int] = []
    for i in range(3, len(words) - 2):
        if words[i] == "auth":
            hits.append(i + 2)
        elif words[i] == "priv":
            at = i + 2
            if words[i + 1].startswith("aes") and at < len(words) and words[at].isdigit():
                at += 1
            hits.append(at)
    hits = [h for h in hits if h < len(spans)]
    if not hits:
        return None
    return _replace_words(line, spans, hits)


def _redact_generic(line: str) -> str:
    """Fallback for a line no specific pattern redacted.

    The word after ``password|secret|key|community|pre-shared-key|key-string|passphrase|
    authentication-key`` (past one encryption-type word) becomes ``<redacted>``. Lines where
    those words are names (ACLs, objects, name tables) are left alone.
    """
    spans = _words(line)
    if not spans:
        return line
    words = [line[a:b].lower() for a, b in spans]
    first = words[0]
    if first.isdigit() and len(words) > 1:
        first = words[1]
    if first in _NAME_LINES:
        return line
    hits: list[int] = []
    for i, word in enumerate(words):
        if word in _GENERIC_KEYWORDS:
            if i + 1 < len(words) and words[i + 1] in _STRUCTURAL_NEXT:
                continue
            at = _secret_index(line, spans, i)
            if at is not None:
                hits.append(at)
    return _replace_words(line, spans, hits)


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
        special = (
            _redact_asa_snmp_host(redacted_line)
            or _redact_username(redacted_line)
            or _redact_snmp_user(redacted_line)
        )
        if special is not None:
            redacted_line = special
        else:
            for pattern in _LINE_PATTERNS:
                m = pattern.match(redacted_line)
                if m:
                    redacted_line = m.group(1) + _REDACTED + m.group(3)
                    break
        if _REDACTED not in redacted_line:
            redacted_line = _redact_generic(redacted_line)

        redacted_line = _redact_inline_hashes(redacted_line)

        ending = line[len(stripped) :]
        result.append(redacted_line + ending)

    return "".join(result)


def redact_lines(lines: list[str]) -> list[str]:
    """Redact a list of bare lines (no line endings). Returns a new list."""
    return redact("\n".join(lines)).splitlines()
