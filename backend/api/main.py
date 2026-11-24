"""FastAPI app: ``/v1`` endpoints and ``/healthz``, with a mangum handler for AWS Lambda.

Run locally with ``uv run python -m uvicorn api.main:app`` from ``backend/``. Configs are
processed in memory and never persisted. Limits: 2 MB upload, 10 s parse timeout, 20,000 oracle
examples, 10 POSTs a minute per client (security steering "Runtime").
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from mangum import Mangum

from api.errors import install_error_handlers
from api.middleware import GuardMiddleware, RateLimiter
from necro import service
from necro.schemas import (
    AutopsyResult,
    ConfigRequest,
    ExhumeResult,
    ProveRequest,
    ProveResult,
    ResurrectResult,
)
from necro.version import __version__, git_commit

DEFAULT_UI_ORIGIN = "http://localhost:5173"
RATE_PER_MINUTE = 10


def _counts(request: Request, **counts: int) -> None:
    request.state.counts = counts  # sizes and counts only, never config lines


def build_v1() -> APIRouter:
    router = APIRouter(prefix="/v1")

    @router.post("/exhume")
    def exhume(body: ConfigRequest, request: Request) -> ExhumeResult:
        result = service.exhume(body.config, body.dialect)
        _counts(
            request,
            chars=len(body.config),
            acls=len(result.acls),
            blocking=result.coverage.blocking,
        )
        return result

    @router.post("/autopsy")
    def autopsy(body: ConfigRequest, request: Request) -> AutopsyResult:
        result = service.autopsy(body.config, body.dialect)
        _counts(request, chars=len(body.config), findings=len(result.findings))
        return result

    @router.post("/resurrect")
    def resurrect(body: ConfigRequest, request: Request) -> ResurrectResult:
        result = service.resurrect(body.config, body.dialect)
        _counts(
            request,
            chars=len(body.config),
            lines=result.config_lines,
            ledger=len(result.ledger),
            blocking=len(result.blocking),
        )
        return result

    @router.post("/prove")
    def prove(body: ProveRequest, request: Request) -> ProveResult:
        result = service.prove(
            body.config,
            body.dialect,
            budget=body.budget,
            seed=body.seed,
            profile=body.profile,
        )
        _counts(
            request,
            chars=len(body.config),
            examples=result.proof.examples,
            passed=int(result.passed),
        )
        return result

    @router.post("/gate")
    def gate(body: ConfigRequest) -> None:
        service.gate(body.config, body.dialect)

    @router.post("/grimoire")
    def grimoire(body: ConfigRequest) -> None:
        service.grimoire(body.config, body.dialect)

    return router


def create_app(*, rate_per_minute: int = RATE_PER_MINUTE, ui_origin: str | None = None) -> FastAPI:
    app = FastAPI(
        title="NECROMANCER",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url="/v1/openapi.json",
    )
    install_error_handlers(app)
    app.include_router(build_v1())

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        return {"status": "ok", "version": __version__, "commit": git_commit()}

    # Middleware added later is outermost. The guard is last, so that every response, including
    # CORS preflights and rate-limit refusals, carries the security headers and a request id.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[ui_origin or os.environ.get("NECRO_UI_ORIGIN", DEFAULT_UI_ORIGIN)],
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
        expose_headers=["X-Request-ID", "Retry-After"],
    )
    app.add_middleware(GuardMiddleware, limiter=RateLimiter(rate_per_minute))
    return app


app = create_app()
handler = Mangum(app, lifespan="off")
