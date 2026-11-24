"""Request middleware: security headers, request ids, body limit, rate limit, structured logs.

Logs carry request ids, sizes, timings and counts. They never carry config lines (security
steering "Runtime"). The rate limiter is per process: on Lambda the API Gateway throttle is the
shared limit, and this one is a second line of defence for a single warm instance.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from collections import deque
from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from api.errors import error_response
from necro.service import MAX_UPLOAD_BYTES

log = logging.getLogger("necro.api")

# JSON escaping and the envelope make a request body larger than the config text it carries.
MAX_BODY_BYTES = MAX_UPLOAD_BYTES * 2 + 4096
RATE_WINDOW_S = 60.0
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


class RateLimiter:
    """Sliding window: at most ``limit`` requests per ``RATE_WINDOW_S`` for each client."""

    def __init__(self, limit: int, clock: Callable[[], float] = time.monotonic) -> None:
        self.limit = limit
        self._clock = clock
        self._hits: dict[str, deque[float]] = {}

    def retry_after(self, client: str) -> int:
        """0 when the request is allowed (and counted), else seconds until a slot frees up."""
        now = self._clock()
        hits = self._hits.setdefault(client, deque())
        while hits and now - hits[0] >= RATE_WINDOW_S:
            hits.popleft()
        if len(hits) >= self.limit:
            return max(1, int(RATE_WINDOW_S - (now - hits[0])) + 1)
        hits.append(now)
        if len(self._hits) > 10_000:  # bound memory: forget clients with no recent hits
            self._hits = {k: v for k, v in self._hits.items() if v and now - v[-1] < RATE_WINDOW_S}
        return 0


def _with_headers(response: Response, request_id: str) -> Response:
    for name, value in SECURITY_HEADERS.items():
        response.headers[name] = value
    response.headers["X-Request-ID"] = request_id
    return response


class GuardMiddleware(BaseHTTPMiddleware):
    """Applies the limits, stamps the headers and writes one log line per request."""

    def __init__(self, app: ASGIApp, limiter: RateLimiter) -> None:
        super().__init__(app)
        self.limiter = limiter

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request_id = uuid.uuid4().hex
        started = time.perf_counter()
        declared = request.headers.get("content-length", "")
        size = int(declared) if declared.isdigit() else 0
        request.state.counts = {}
        response = self._refuse(request, size)
        if response is None:
            try:
                response = await call_next(request)
            except Exception:  # never leak internals; the log has the type, not the content
                log.exception("unhandled error", extra={"request_id": request_id})
                response = error_response(500, "internal-error", "internal error")
        _with_headers(response, request_id)
        log.info(
            json.dumps(
                {
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "status": response.status_code,
                    "bytes_in": size,
                    "ms": round((time.perf_counter() - started) * 1000, 1),
                    "counts": request.state.counts,
                },
                sort_keys=True,
            )
        )
        return response

    def _refuse(self, request: Request, size: int) -> Response | None:
        if size > MAX_BODY_BYTES:
            return error_response(413, "too-large", "request body is too large")
        if request.method == "POST":
            client = request.client.host if request.client else "unknown"
            wait = self.limiter.retry_after(client)
            if wait:
                return error_response(
                    429,
                    "rate-limited",
                    "too many requests: the demo allows 10 requests per minute",
                    headers={"Retry-After": str(wait)},
                )
        return None
