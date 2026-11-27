"""No-CDN deployment: the API serves the built UI (NECRO_STATIC_DIR) after its own routes."""

from __future__ import annotations

import socket
from collections.abc import Generator
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from api.main import create_app
from api.static import UI_CSP, install_static

INDEX = "<!doctype html><title>necro-ui</title>"


@pytest.fixture(autouse=True)
def block_network() -> Generator[None, None, None]:
    """Replaces the conftest guard (asyncio needs a loopback socketpair); lookups stay blocked."""

    def _guard(*args: object, **kwargs: object) -> None:
        raise RuntimeError("Network call attempted during test suite")

    with (
        patch.object(socket, "getaddrinfo", side_effect=_guard),
        patch.object(socket, "create_connection", side_effect=_guard),
    ):
        yield


@pytest.fixture
def ui_dir(tmp_path: Path) -> Path:
    root = tmp_path / "static"
    (root / "assets").mkdir(parents=True)
    (root / "index.html").write_text(INDEX, encoding="utf-8")
    (root / "assets" / "app-abc123.js").write_text("console.log(1)", encoding="utf-8")
    (root / "assets" / "app-abc123.css").write_text("body{}", encoding="utf-8")
    (root / "favicon.svg").write_text("<svg/>", encoding="utf-8")
    (tmp_path / "secret.txt").write_text("outside", encoding="utf-8")
    return root


@pytest.fixture
def client(ui_dir: Path) -> TestClient:
    return TestClient(create_app(rate_per_minute=1000, static_dir=str(ui_dir)))


def test_root_and_index_serve_the_ui(client: TestClient) -> None:
    for path in ("/", "/index.html"):
        response = client.get(path)
        assert response.status_code == 200 and response.text == INDEX
        assert response.headers["content-type"] == "text/html; charset=utf-8"
        assert response.headers["cache-control"] == "no-cache"


def test_assets_have_explicit_types_and_immutable_caching(client: TestClient) -> None:
    js = client.get("/assets/app-abc123.js")
    assert js.status_code == 200 and js.headers["content-type"].startswith("text/javascript")
    assert "immutable" in js.headers["cache-control"]
    assert client.get("/assets/app-abc123.css").headers["content-type"].startswith("text/css")
    assert client.get("/favicon.svg").headers["content-type"] == "image/svg+xml"


def test_unknown_paths_fall_back_to_index(client: TestClient) -> None:
    for path in ("/graveyard", "/a/b/c", "/report/42"):
        response = client.get(path)
        assert response.status_code == 200 and response.text == INDEX


def test_head_is_served_and_other_methods_are_not(client: TestClient) -> None:
    assert client.head("/graveyard").status_code == 200
    refused = client.post("/graveyard")
    assert refused.status_code in (404, 405)
    assert refused.headers["content-type"].startswith("application/json")


def test_missing_asset_is_a_json_404(client: TestClient) -> None:
    response = client.get("/assets/missing-000.js")
    assert response.status_code == 404 and response.json()["code"] == "not-found"


def test_v1_and_healthz_still_win(client: TestClient) -> None:
    health = client.get("/healthz")
    assert health.status_code == 200 and health.json()["status"] == "ok"
    exhume = client.post("/v1/exhume", json={"config": "hostname r1\n"})
    assert exhume.headers["content-type"].startswith("application/json")
    assert exhume.status_code != 404 and exhume.text != INDEX
    assert client.get("/v1/openapi.json").status_code == 200


def test_unknown_api_paths_are_json_errors_not_the_ui(client: TestClient) -> None:
    unknown = client.get("/v1/nope")
    assert unknown.status_code == 404 and unknown.json()["code"] == "not-found"
    assert client.get("/healthz/extra").status_code == 404
    wrong_method = client.get("/v1/exhume")
    assert wrong_method.status_code == 405 and wrong_method.json()["code"] == "method-not-allowed"


@pytest.mark.parametrize(
    "path", ["/../secret.txt", "/%2e%2e/secret.txt", "/assets/../../secret.txt"]
)
def test_path_traversal_never_leaves_the_directory(client: TestClient, path: str) -> None:
    response = client.get(path)
    assert "outside" not in response.text


def test_security_headers_on_every_response(client: TestClient) -> None:
    responses = [
        client.get("/"),
        client.get("/graveyard"),
        client.get("/assets/app-abc123.js"),
        client.get("/assets/missing.js"),
        client.get("/healthz"),
        client.get("/v1/nope"),
        client.post("/v1/exhume"),
    ]
    for response in responses:
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["referrer-policy"] == "no-referrer"
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["strict-transport-security"] == "max-age=31536000"
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
        assert len(response.headers["x-request-id"]) == 32


def test_ui_gets_the_ui_csp_and_the_api_keeps_the_strict_one(client: TestClient) -> None:
    assert client.get("/").headers["content-security-policy"] == UI_CSP
    assert client.get("/assets/app-abc123.js").headers["content-security-policy"] == UI_CSP
    assert (
        client.get("/healthz").headers["content-security-policy"]
        == "default-src 'none'; frame-ancestors 'none'"
    )


def test_without_a_static_dir_nothing_is_served(tmp_path: Path) -> None:
    plain = TestClient(create_app(rate_per_minute=1000, static_dir=str(tmp_path / "absent")))
    assert plain.get("/").status_code == 404
    assert plain.get("/healthz").status_code == 200
    assert install_static(create_app(), tmp_path / "absent") is False


def test_env_variable_enables_static_serving(ui_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NECRO_STATIC_DIR", str(ui_dir))
    assert TestClient(create_app(rate_per_minute=1000)).get("/anything").text == INDEX
    monkeypatch.delenv("NECRO_STATIC_DIR")
    assert TestClient(create_app(rate_per_minute=1000)).get("/anything").status_code == 404
