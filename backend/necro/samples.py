"""Locate the bundled synthetic samples (``samples/dead-configs`` and ``samples/golden-flows``).

A request that names a built-in sample gets that sample's hand-verified golden flows without
sending them. The directory is the repository's ``samples`` folder, or ``$NECRO_SAMPLES_DIR``.
Names are matched against the files that exist, so a request can never read another path.
"""

from __future__ import annotations

import os
from pathlib import Path

SAMPLES_ENV = "NECRO_SAMPLES_DIR"


def samples_root() -> Path:
    override = os.environ.get(SAMPLES_ENV)
    return Path(override) if override else Path(__file__).resolve().parents[2] / "samples"


def sample_names() -> list[str]:
    """Names of the samples that have golden flows, sorted."""
    folder = samples_root() / "golden-flows"
    return sorted(p.stem for p in folder.glob("*.toml")) if folder.is_dir() else []


def golden_path(name: str) -> Path | None:
    """The golden-flow file of a built-in sample, or None when ``name`` is not one."""
    if name not in sample_names():
        return None
    return samples_root() / "golden-flows" / f"{name}.toml"


def sample_of_config(path: Path) -> str | None:
    """The sample name when ``path`` is one of the bundled configs, else None."""
    try:
        resolved = path.resolve()
    except OSError:
        return None
    for name in sample_names():
        candidate = samples_root() / "dead-configs" / f"{name}.cfg"
        if candidate.is_file() and candidate.resolve() == resolved:
            return name
    return None
