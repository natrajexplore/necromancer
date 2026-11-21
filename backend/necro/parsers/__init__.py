"""Config parsers. Each returns the vendor-neutral IR and never emits vendor config.

``parse_config`` is the single entry point for raw text: it redacts secrets first (nothing else
ever sees unredacted text), detects the dialect when none is given, and dispatches to a parser.
"""

from __future__ import annotations

from necro.ir import Dialect, ParseError, Policy
from necro.parsers.detect import Detection, detect
from necro.parsers.ios_acl import parse_ios
from necro.parsers.pix_asa import parse_pix_asa
from necro.redact import redact

__all__ = ["Detection", "detect", "parse_config"]


def parse_config(text: str, dialect: Dialect | None = None) -> Policy:
    """Redact, detect (unless ``dialect`` is given) and parse a firewall/router config.

    Raises ``ParseError`` when the dialect can't be detected, or on object-group cycles and
    undefined groups. ``Policy.detection_confidence`` is 1.0 for an explicit dialect.
    """
    redacted = redact(text)
    detection = detect(redacted)
    chosen = dialect or detection.dialect
    if chosen is None:
        raise ParseError("unknown-dialect", "no PIX, ASA or IOS evidence found in the config")
    if chosen == Dialect.ios:
        policy = parse_ios(redacted, os_version=detection.os_version)
    else:
        policy = parse_pix_asa(redacted, dialect=chosen, os_version=detection.os_version)
    policy.detection_confidence = 1.0 if dialect is not None else detection.confidence
    return policy
