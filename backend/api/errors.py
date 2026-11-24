"""Structured errors: every failure is ``{code, message, line_no?}`` (requirement 7.5)."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from necro.service import ErrorKind, NecroError

# 422 for input errors (parse errors carry line_no), 413 over the size limit,
# 504 when the parse timeout fires, 501 for features that arrive with later specs.
STATUS: dict[ErrorKind, int] = {
    "input": 422,
    "too-large": 413,
    "timeout": 504,
    "not-implemented": 501,
}


def error_response(
    status: int, code: str, message: str, line_no: int = 0, headers: dict[str, str] | None = None
) -> JSONResponse:
    body: dict[str, object] = {"code": code, "message": message}
    if line_no:
        body["line_no"] = line_no
    return JSONResponse(body, status_code=status, headers=headers)


async def _necro(_: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, NecroError)
    return JSONResponse(exc.body(), status_code=STATUS[exc.kind])


async def _validation(_: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, RequestValidationError)
    first = exc.errors()[0] if exc.errors() else {}
    where = ".".join(str(p) for p in first.get("loc", ()) if p != "body")
    reason = str(first.get("msg", "invalid request"))
    return error_response(422, "invalid-request", f"{where}: {reason}" if where else reason)


async def _http(_: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, StarletteHTTPException)
    codes = {404: "not-found", 405: "method-not-allowed"}
    return error_response(
        exc.status_code, codes.get(exc.status_code, "http-error"), str(exc.detail)
    )


def install_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(NecroError, _necro)
    app.add_exception_handler(RequestValidationError, _validation)
    app.add_exception_handler(StarletteHTTPException, _http)
