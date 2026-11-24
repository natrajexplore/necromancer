"""The five MCP tools as plain functions returning JSON-ready dicts.

``backend/mcp_server.py`` registers them with FastMCP (stdio). A refused request returns
``{"error": {code, message, line_no?}}`` instead of raising, so the client sees the same
structured error as the HTTP API. Tools take config text, never file paths, and make no network
calls.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from pydantic import BaseModel

from necro import service
from necro.gate_models import Sidecar
from necro.service import NecroError
from necro.version import __version__, git_commit


def _dump(model: BaseModel) -> dict[str, Any]:
    return model.model_dump(mode="json", by_alias=True)


def _guarded(call: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    try:
        return call()
    except NecroError as exc:
        return {"error": exc.body()}


def exhume(config: str, dialect: str | None = None) -> dict[str, Any]:
    """Parse a dead PIX/ASA/IOS config: dialect, interfaces, ACLs, line coverage, unparsed lines."""
    return _guarded(lambda: _dump(service.exhume(config, dialect)))


def autopsy(config: str, dialect: str | None = None) -> dict[str, Any]:
    """Find ghost rules: shadowed, redundant, overly broad, insecure services, unused objects."""
    return _guarded(lambda: _dump(service.autopsy(config, dialect)))


def resurrect(config: str, dialect: str | None = None) -> dict[str, Any]:
    """Emit the like-for-like PAN-OS candidate config (set commands) with its exorcism ledger."""
    return _guarded(lambda: _dump(service.resurrect(config, dialect)))


def prove(
    config: str,
    dialect: str | None = None,
    budget: int | None = None,
    seed: int | None = None,
    profile: str | None = None,
) -> dict[str, Any]:
    """Proof of Life: compare original and resurrected behaviour over generated flows."""
    return _guarded(
        lambda: _dump(service.prove(config, dialect, budget=budget, seed=seed, profile=profile))
    )


def _sidecar(data: dict[str, Any] | None) -> Sidecar | None:
    if not data:
        return None
    try:
        return Sidecar.model_validate(data)
    except ValueError as exc:
        raise NecroError("invalid-sidecar", f"the sidecar is not valid: {exc}") from exc


def gate(
    config: str,
    dialect: str | None = None,
    budget: int | None = None,
    seed: int | None = None,
    profile: str | None = None,
    sidecar: dict[str, Any] | None = None,
    golden: str | None = None,
) -> dict[str, Any]:
    """Readiness gates G1-G6 and the GO / CONDITIONAL / NO-GO verdict with blocking reasons.

    Defaults to the ci budget (5,000 examples per context), which a GO verdict needs. ``sidecar``
    holds waivers, accepted_risks, ledger_decisions, change and runbook overrides. ``golden`` is
    golden-flow TOML text."""
    return _guarded(
        lambda: _dump(
            service.gate(
                config,
                dialect,
                sidecar=_sidecar(sidecar),
                budget=budget,
                seed=seed,
                profile=profile,
                golden=service.parse_golden_text(golden),
            )
        )
    )


def server_info() -> dict[str, str]:
    return {"name": "necromancer", "version": __version__, "commit": git_commit()}


TOOLS: tuple[Callable[..., dict[str, Any]], ...] = (exhume, autopsy, resurrect, prove, gate)
