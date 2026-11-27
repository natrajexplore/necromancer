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
from necro.schemas import TighteningSelection
from necro.service import NecroError
from necro.version import __version__, git_commit


def _dump(model: BaseModel) -> dict[str, Any]:
    return model.model_dump(mode="json", by_alias=True)


def _guarded(call: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    try:
        return call()
    except NecroError as exc:
        return {"error": exc.body()}


def _selection(data: dict[str, Any] | None) -> TighteningSelection | None:
    if data is None:
        return None
    try:
        return TighteningSelection.model_validate(data)
    except ValueError as exc:
        raise NecroError(
            "invalid-tightening", f"the tightening selection is not valid: {exc}"
        ) from exc


def exhume(config: str, dialect: str | None = None) -> dict[str, Any]:
    """Parse a dead PIX/ASA/IOS config: dialect, interfaces, ACLs, line coverage, unparsed lines."""
    return _guarded(lambda: _dump(service.exhume(config, dialect)))


def autopsy(config: str, dialect: str | None = None) -> dict[str, Any]:
    """Find ghost rules: shadowed, redundant, overly broad, insecure services, unused objects."""
    return _guarded(lambda: _dump(service.autopsy(config, dialect)))


def resurrect(
    config: str,
    dialect: str | None = None,
    tightening: dict[str, Any] | None = None,
    budget: int | None = None,
    seed: int | None = None,
    profile: str | None = None,
    sample: str | None = None,
) -> dict[str, Any]:
    """Emit the like-for-like PAN-OS candidate (set commands) with its exorcism ledger.

    The answer always lists remediation ``proposals`` (remove shadowed or redundant rules,
    replace insecure services, narrow any, SNMP v3 notes). Pass ``tightening`` as
    ``{"choices": [{"finding_id": ..., "networks": [...]}], "approvals": {...}}`` to also get a
    separate ``tightened`` artifact with its own ledger and proof. The baseline never changes.
    ``budget``, ``seed``, ``profile`` and ``sample`` apply to that proof."""
    return _guarded(
        lambda: _dump(
            service.resurrect(
                config,
                dialect,
                tightening=_selection(tightening),
                budget=budget,
                seed=seed,
                profile=profile,
                golden=service.golden_for(sample),
            )
        )
    )


def prove(
    config: str,
    dialect: str | None = None,
    budget: int | None = None,
    seed: int | None = None,
    profile: str | None = None,
    haunt: bool = False,
    sample: str | None = None,
) -> dict[str, Any]:
    """Proof of Life: compare original and resurrected behaviour over generated flows.

    ``haunt`` is a demo switch: it proves a deliberately broken candidate and answers
    ``haunted: true``. Never use a haunted result for a migration. ``sample`` names a built-in
    sample (for example ``pix-2006-hq``) whose golden flows run first.
    """
    return _guarded(
        lambda: _dump(
            service.prove(
                config,
                dialect,
                budget=budget,
                seed=seed,
                profile=profile,
                golden=service.golden_for(sample),
                haunt=haunt,
            )
        )
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
    sample: str | None = None,
    tightening: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Readiness gates G1-G6 and the GO / CONDITIONAL / NO-GO verdict with blocking reasons.

    Defaults to the ci budget (5,000 examples per context), which a GO verdict needs. ``sidecar``
    holds waivers, accepted_risks, ledger_decisions, change and runbook overrides. ``golden`` is
    golden-flow TOML text. ``sample`` names a built-in sample whose golden flows run when
    ``golden`` is empty. ``tightening`` is the same selection as for resurrect: it adds a separate
    ``tightened`` verdict (own proof and ledger, G6 on the tightened policy). The baseline
    ``verdict`` does not change."""
    return _guarded(
        lambda: _dump(
            service.gate(
                config,
                dialect,
                sidecar=_sidecar(sidecar),
                budget=budget,
                seed=seed,
                profile=profile,
                golden=service.golden_for(sample, golden),
                tightening=_selection(tightening),
            )
        )
    )


def server_info() -> dict[str, str]:
    return {"name": "necromancer", "version": __version__, "commit": git_commit()}


TOOLS: tuple[Callable[..., dict[str, Any]], ...] = (exhume, autopsy, resurrect, prove, gate)
