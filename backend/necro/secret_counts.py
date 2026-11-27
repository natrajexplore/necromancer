"""How many secrets the redactor removed, by type (migration-governance requirement 4.6).

The report recommends rotating every shared secret that was on the source device, because the
secrets are considered exposed once the device is decommissioned (governance rule R7). It states
how many of each type there were and never shows one: the input here is the *redacted* text, and a
line counts when it carries a placeholder.

Types are decided by plain string tests on the line, in order, first match wins. A line with a
placeholder that matches no type counts as ``other secret``, so nothing the redactor touched is
left out of the total.
"""

from __future__ import annotations

from collections.abc import Iterable

PLACEHOLDER = "<redacted>"
CERTIFICATE_PLACEHOLDER = "<redacted certificate>"
OTHER = "other secret"

# (type name, words that must all appear in the lower-cased line, in this order)
_TYPES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("device enable password", ("enable", "password")),
    ("device enable password", ("enable", "secret")),
    ("local user password", ("username",)),
    ("FTP server password", ("ftp", "password")),
    ("PPP authentication password", ("ppp",)),
    ("SNMP community or credential", ("snmp-server",)),
    ("VPN pre-shared key", ("isakmp", "key")),
    ("VPN pre-shared key", ("pre-shared-key",)),
    ("routing authentication key", ("key-string",)),
    ("AAA shared key", ("tacacs",)),
    ("AAA shared key", ("radius",)),
    ("AAA shared key", ("aaa-server",)),
    ("NTP authentication key", ("ntp", "authentication-key")),
    ("LDAP login password", ("ldap-login-password",)),
    ("routing authentication key", ("ospf",)),
    ("routing authentication key", ("neighbor", "password")),
    ("routing authentication key", ("authentication-key",)),
    ("failover key", ("failover", "key")),
    ("trust-point passphrase", ("ssl", "trust-point")),
    ("passphrase", ("passphrase",)),
    ("device password", ("passwd",)),
    ("line or device password", ("password",)),
    ("AAA shared key", ("key",)),
)


def _in_order(line: str, words: tuple[str, ...]) -> bool:
    at = 0
    for word in words:
        found = line.find(word, at)
        if found < 0:
            return False
        at = found + len(word)
    return True


def classify(line: str) -> str:
    """The secret type of one redacted line that carries a placeholder."""
    lowered = line.strip().lower()
    for name, words in _TYPES:
        if _in_order(lowered, words):
            return name
    return OTHER


def count_secrets(lines: Iterable[str]) -> dict[str, int]:
    """Redacted secrets by type, sorted by type name. One line counts once."""
    counts: dict[str, int] = {}
    for line in lines:
        if CERTIFICATE_PLACEHOLDER in line:
            name = "certificate block"
        elif PLACEHOLDER in line:
            name = classify(line)
        else:
            continue
        counts[name] = counts.get(name, 0) + 1
    return dict(sorted(counts.items()))
