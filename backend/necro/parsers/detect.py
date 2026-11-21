"""Dialect, OS version and mode detection with a confidence value (requirement 1.3).

Detection is evidence-based: an explicit version banner is strong evidence, command shapes that
only one platform uses are weak evidence. The confidence is in [0, 1] and shrinks when another
dialect also has evidence. Nothing here guesses silently; a config with no evidence gets
``dialect=None`` and confidence 0.
"""

from __future__ import annotations

from dataclasses import dataclass

from necro.ir import Dialect, PolicyMode
from necro.parsers.cisco_common import is_indented, split_lines

_STRONG = 10
_BANNER = 8
_IOS_VERSION = 6
_IOS_ACL_WORDS = ("extended", "standard")


@dataclass(frozen=True)
class Detection:
    """What detect() concluded. ``signals`` lists the evidence, for the report."""

    dialect: Dialect | None
    os_version: str
    mode: PolicyMode
    confidence: float
    signals: tuple[str, ...] = ()


def _major(version: str) -> int:
    head = version.split(".", 1)[0]
    return int(head) if head.isdigit() else -1


class _Scores:
    def __init__(self) -> None:
        self.points = {Dialect.pix: 0, Dialect.asa: 0, Dialect.ios: 0}
        self.signals: list[str] = []
        self.version = ""
        self.banner = False

    def add(self, dialect: Dialect, weight: int, signal: str) -> None:
        self.points[dialect] += weight
        self.signals.append(f"{signal} -> {dialect.value} (+{weight})")


def detect(text: str) -> Detection:
    """Detect dialect, OS version and mode from (already redacted) config text."""
    scores = _Scores()
    mode = PolicyMode.routed
    for line in split_lines(text):
        tokens = line.split()
        if not tokens:
            continue
        head = [t.lower() for t in tokens[:4]]
        if is_indented(line):
            _indented_signals(scores, head)
        elif not _banner_signal(scores, tokens, head):
            mode = _command_signal(scores, head) or mode
    return _conclude(scores, mode)


def _banner_signal(scores: _Scores, tokens: list[str], head: list[str]) -> bool:
    """Record a version banner. Returns True when the line was a banner."""
    if len(tokens) >= 3 and head[:2] == ["pix", "version"]:
        dialect = Dialect.pix if 0 <= _major(tokens[2]) < 7 else Dialect.asa
        scores.add(dialect, _STRONG, "PIX Version banner")
        scores.version, scores.banner = tokens[2], True
    elif len(tokens) >= 3 and head[:2] == ["asa", "version"]:
        scores.add(Dialect.asa, _STRONG, "ASA Version banner")
        scores.version, scores.banner = tokens[2], True
    elif len(tokens) == 2 and head[0] == "version" and _major(tokens[1]) > 0:
        scores.add(Dialect.ios, _IOS_VERSION, "version banner")
        scores.version = scores.version or tokens[1]
    elif "adaptive" in head and "security" in head:
        scores.add(Dialect.asa, _BANNER, "Adaptive Security Appliance banner")
    else:
        return False
    return True


def _command_signal(scores: _Scores, head: list[str]) -> PolicyMode | None:
    """Weak evidence from command shapes. Returns a mode when the command sets one."""
    kw = head[0]
    if kw == "firewall" and head[1:2] == ["transparent"]:
        scores.signals.append("firewall transparent -> mode transparent")
        return PolicyMode.transparent
    if kw == "mode" and head[1:2] == ["multiple"]:
        scores.signals.append("mode multiple -> mode multiple")
        return PolicyMode.multiple
    if kw == "context":
        scores.signals.append("context block -> mode multiple")
        return PolicyMode.multiple
    if kw == "nameif" and len(head) >= 3:
        scores.add(Dialect.pix, 3, "top-level nameif")
    elif kw == "access-group" and "interface" in head:
        scores.add(Dialect.asa, 1, "access-group ... interface")
        scores.add(Dialect.pix, 1, "access-group ... interface")
    elif kw == "access-list" and "extended" in head:
        scores.add(Dialect.asa, 2, "access-list extended")
    elif kw == "ip" and head[1:2] == ["access-list"] and head[2:3] and head[2] in _IOS_ACL_WORDS:
        scores.add(Dialect.ios, 3, "ip access-list")
    elif kw == "ip" and head[1:2] == ["route"]:
        scores.add(Dialect.ios, 2, "ip route")
    elif kw == "line" and head[1:2] == ["vty"]:
        scores.add(Dialect.ios, 3, "line vty")
    elif kw == "service" and head[1:2] in (["timestamps"], ["password-encryption"]):
        scores.add(Dialect.ios, 2, "service timestamps")
    elif kw in ("fixup", "conduit", "outbound", "apply"):
        scores.add(Dialect.pix, 3, f"legacy PIX command {kw}")
    return None


def _indented_signals(scores: _Scores, head: list[str]) -> None:
    kw = head[0]
    if kw == "nameif":
        scores.add(Dialect.asa, 3, "interface nameif")
    elif kw == "security-level":
        scores.add(Dialect.asa, 3, "interface security-level")
    elif kw == "ip" and head[1:2] == ["access-group"]:
        scores.add(Dialect.ios, 2, "interface ip access-group")


def _conclude(scores: _Scores, mode: PolicyMode) -> Detection:
    ranked = sorted(scores.points.items(), key=lambda kv: (-kv[1], kv[0].value))
    (best, top), (_, second) = ranked[0], ranked[1]
    if top == 0:
        return Detection(None, "", mode, 0.0, tuple(scores.signals))
    base = 0.98 if scores.banner else min(0.85, 0.3 + 0.1 * top)
    confidence = round(max(0.0, min(1.0, base * top / (top + second))), 3)
    return Detection(best, scores.version, mode, confidence, tuple(scores.signals))
