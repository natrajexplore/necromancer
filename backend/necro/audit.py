"""The audit header of every report and API result (migration-governance requirement 3.1).

It records what a reader needs to reproduce or trust a result: the tool version and git commit,
the SHA-256 of every input, the dialect and OS version, the options, the seed, the example budget,
the profile, the UTC time and the SHA-256 of every output artifact.

Everything except ``generated_at`` is a function of the input, the options and the seed, so two
runs with the same arguments produce the same header apart from that one value (requirement 3.2).
Only hashes of the input are recorded. The redacted text is the only text an artifact contains
(requirement 3.3).
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from datetime import UTC, datetime

from necro.gate_models import AuditHeader
from necro.ir import Policy
from necro.version import __version__, git_commit

DEFAULT_INPUT_NAME = "config"


def sha256_text(text: str) -> str:
    """SHA-256 of ``text`` encoded as UTF-8, as lowercase hex."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def utc_now() -> datetime:
    """The current UTC time to the second (a header value needs no more)."""
    return datetime.now(UTC).replace(microsecond=0)


def build_audit(
    policy: Policy,
    *,
    original_sha256: str,
    outputs: Mapping[str, str],
    options: Mapping[str, str],
    seed: int,
    budget: int,
    profile: str,
    generated_at: datetime,
    input_name: str = DEFAULT_INPUT_NAME,
) -> AuditHeader:
    """The header for one run.

    ``original_sha256`` is the hash of the text as supplied, so that it matches the file an
    auditor holds. ``policy.input_sha256`` is the hash of the redacted text the engine worked on.
    Both are recorded, and neither reveals a secret.
    """
    return AuditHeader(
        tool_version=__version__,
        git_commit=git_commit(),
        inputs={
            input_name: original_sha256,
            f"{input_name} (redacted)": policy.input_sha256,
        },
        dialect=policy.dialect.value,
        os_version=policy.os_version or "unknown",
        options=dict(options),
        seed=seed,
        budget=budget,
        profile=profile,
        generated_at=generated_at,
        outputs=dict(outputs),
    )
