"""Renderers turn the IR back into source-dialect text (used for round-trip proofs and fixtures).

They are not emitters: nothing here produces a migration artifact, and nothing here reads raw
config. Emitters for the target platform live in ``necro.emitters``.
"""

from __future__ import annotations

from necro.ir import Dialect, Policy
from necro.renderers.cisco_ios import render_ios
from necro.renderers.cisco_pix_asa import UnrenderableError, render_pix_asa

__all__ = ["UnrenderableError", "render", "render_ios", "render_pix_asa"]


def render(policy: Policy) -> str:
    """Render ``policy`` in its own dialect."""
    if policy.dialect == Dialect.ios:
        return render_ios(policy)
    return render_pix_asa(policy)
