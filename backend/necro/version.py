"""Version and git commit, printed by ``necro --version``, ``/healthz`` and every report."""

from __future__ import annotations

import os
import subprocess
from functools import cache
from pathlib import Path

from necro import __version__

__all__ = ["__version__", "git_commit", "version_string"]


@cache
def git_commit() -> str:
    """Commit hash: ``NECRO_GIT_COMMIT`` (set at build time), else ``git``, else ``unknown``."""
    env = os.environ.get("NECRO_GIT_COMMIT", "").strip()
    if env:
        return env[:40]
    try:
        done = subprocess.run(  # fixed arguments, no user input
            ["git", "rev-parse", "--short=12", "HEAD"],
            cwd=Path(__file__).resolve().parent,
            stdin=subprocess.DEVNULL,  # never the caller's stdin: under MCP it is the protocol pipe
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    commit = done.stdout.strip()
    return commit if done.returncode == 0 and commit else "unknown"


def version_string() -> str:
    return f"necromancer {__version__} (commit {git_commit()})"
