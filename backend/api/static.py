"""Serve the built UI from the API when there is no CDN (``NECRO_STATIC_DIR``).

Used by the no-CloudFront deployment (``deploy.ps1 -NoCdn``). The files are served from the 404
path, so every real route (``/v1/*``, ``/healthz``) is matched first and keeps its own 404 and 405
answers. Unknown GET paths get ``index.html`` (SPA fallback), except ``/assets/*``, ``/v1/*`` and
``/healthz``, which stay JSON 404s.
"""

from __future__ import annotations

import inspect
from pathlib import Path

from fastapi import FastAPI, Request
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import FileResponse, Response

# Same policy as the CloudFront UI headers policy in template.yaml.
UI_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; "
    "img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; "
    "frame-ancestors 'none'"
)
IMMUTABLE = "public, max-age=31536000, immutable"  # Vite hashes the file names under assets/
# Explicit types: mimetypes reads the Windows registry, and nosniff would block a text/plain script.
CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript",
    ".mjs": "text/javascript",
    ".css": "text/css",
    ".json": "application/json",
    ".svg": "image/svg+xml",
    ".woff2": "font/woff2",
    ".woff": "font/woff",
    ".txt": "text/plain; charset=utf-8",
    ".ico": "image/x-icon",
    ".png": "image/png",
    ".map": "application/json",
}
API_PREFIXES = ("v1", "healthz")


def _is_api_path(path: str) -> bool:
    first = path.strip("/").split("/", 1)[0]
    return first in API_PREFIXES


def _file(path: Path, cache_control: str) -> FileResponse:
    response = FileResponse(
        path,
        media_type=CONTENT_TYPES.get(path.suffix.lower(), "application/octet-stream"),
    )
    response.headers["Cache-Control"] = cache_control
    response.headers["Content-Security-Policy"] = UI_CSP
    return response


def _lookup(root: Path, url_path: str) -> Response | None:
    relative = url_path.strip("/")
    if relative:
        candidate = (root / relative).resolve()
        if candidate.is_relative_to(root) and candidate.is_file():
            immutable = relative.startswith("assets/")
            return _file(candidate, IMMUTABLE if immutable else "no-cache")
    if relative.startswith("assets/") or relative == "assets":
        return None  # a missing hashed asset is a 404, not index.html
    index = root / "index.html"
    return _file(index, "no-cache") if index.is_file() else None


def install_static(app: FastAPI, directory: str | Path) -> bool:
    """Serve ``directory`` for unmatched GET/HEAD paths. Returns False when it does not exist."""
    root = Path(directory).resolve()
    if not root.is_dir():
        return False
    previous = app.exception_handlers[StarletteHTTPException]

    async def handler(request: Request, exc: Exception) -> Response:
        if (
            isinstance(exc, StarletteHTTPException)
            and exc.status_code == 404
            and request.method in ("GET", "HEAD")
            and not _is_api_path(request.url.path)
        ):
            found = _lookup(root, request.url.path)
            if found is not None:
                return found
        result = previous(request, exc)
        return await result if inspect.isawaitable(result) else result

    app.add_exception_handler(StarletteHTTPException, handler)
    return True
