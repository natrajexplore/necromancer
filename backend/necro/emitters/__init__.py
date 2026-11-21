"""Emitters turn the IR into a target platform's configuration. They never read raw config."""

from __future__ import annotations

from necro.emitters.panos import PanosEmission, emit_panos

__all__ = ["PanosEmission", "emit_panos"]
