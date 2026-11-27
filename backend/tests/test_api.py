"""Task 9.2: FastAPI ``/v1`` endpoints, ``/healthz``, limits, headers and structured errors.

The secret-looking strings are the synthetic placeholders already in samples/dead-configs
(see test_redact.py); they are test inputs, not credentials.
"""

from __future__ import annotations

import json
import re
import socket
from collections.abc import Generator
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from api.main import create_app, handler
from api.middleware import RATE_WINDOW_S, RateLimiter
from necro import __version__
from tests.gov_helpers import GO_CONFIG, GOLDEN, core_for, full_sidecar
from tests.panos_helpers import SAMPLES

CONFIG = (SAMPLES / "pix-2006-hq.cfg").read_text(encoding="utf-8")
BROKEN = SAMPLES.parent / "broken-configs"
SAMPLE_SECRETS = ("8Ry2YjIyt7RRXU24", "2KFQnbNIdI.2KYOU", "n0t-a-real-community")
HEADERS = {
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
}


@pytest.fixture(autouse=True)
def block_network() -> Generator[None, None, None]:
    """Replaces the conftest guard: asyncio needs a loopback socketpair for its event loop.

    Name resolution and outbound connections stay blocked, which is what the engine must not do.
    """

    def _guard(*args: object, **kwargs: object) -> None:
        raise RuntimeError("Network call attempted during test suite")

    with (
        patch.object(socket, "getaddrinfo", side_effect=_guard),
        patch.object(socket, "create_connection", side_effect=_guard),
    ):
        yield


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app(rate_per_minute=1000))


def _post(client: TestClient, path: str, **body: object) -> object:
    return client.post(f"/v1/{path}", json={"config": CONFIG, **body})


def test_healthz_reports_version_and_commit(client: TestClient) -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok" and body["version"] == __version__ and body["commit"]


def test_every_response_carries_the_security_headers_and_a_request_id(client: TestClient) -> None:
    for response in (client.get("/healthz"), client.get("/nope"), client.post("/v1/exhume")):
        for name, value in HEADERS.items():
            assert response.headers[name] == value
        assert len(response.headers["x-request-id"]) == 32


def test_exhume_autopsy_resurrect(client: TestClient) -> None:
    exhumed = _post(client, "exhume").json()  # type: ignore[attr-defined]
    assert exhumed["dialect"] == "pix" and exhumed["interfaces"] and exhumed["acls"]
    assert exhumed["coverage"]["total_lines"] == len(CONFIG.splitlines())
    autopsied = _post(client, "autopsy").json()  # type: ignore[attr-defined]
    assert autopsied["findings"] and autopsied["findings"][0]["id"] == "AUT-0001"
    raised = _post(client, "resurrect").json()  # type: ignore[attr-defined]
    assert raised["config"].startswith("set ") and raised["config_lines"] > 10
    assert all("class" in entry for entry in raised["ledger"])


def test_prove_passes_on_a_sample_and_is_reproducible(client: TestClient) -> None:
    first = _post(client, "prove", budget=50, seed=7).json()  # type: ignore[attr-defined]
    second = _post(client, "prove", budget=50, seed=7).json()  # type: ignore[attr-defined]
    assert first["passed"] is True and first == second
    assert first["proof"]["seed"] == 7 and first["proof"]["budget"] == 50


def test_prove_uses_a_profile_when_no_budget_is_given(client: TestClient) -> None:
    response = _post(client, "prove", profile="dev")
    assert response.status_code == 200  # type: ignore[attr-defined]
    assert response.json()["proof"]["budget"] == 500  # type: ignore[attr-defined]


def test_budget_over_the_cap_is_a_structured_422(client: TestClient) -> None:
    response = _post(client, "prove", budget=20_001)
    assert response.status_code == 422  # type: ignore[attr-defined]
    body = response.json()  # type: ignore[attr-defined]
    assert body["code"] == "invalid-request" and "budget" in body["message"]


def test_unknown_profile_is_a_structured_422(client: TestClient) -> None:
    response = _post(client, "prove", profile="huge")
    assert response.status_code == 422  # type: ignore[attr-defined]
    assert response.json()["code"] == "invalid-profile"  # type: ignore[attr-defined]


def test_parse_error_is_422_with_a_line_number(client: TestClient) -> None:
    text = (BROKEN / "asa-group-cycle.cfg").read_text(encoding="utf-8")
    response = client.post("/v1/exhume", json={"config": text})
    assert response.status_code == 422
    body = response.json()
    assert body["code"] == "group-cycle" and body["line_no"] > 0
    assert set(body) == {"code", "message", "line_no"}


def test_undetectable_config_is_a_422_without_a_line_number(client: TestClient) -> None:
    response = client.post("/v1/exhume", json={"config": "hello\nworld\n"})
    assert response.status_code == 422
    assert response.json()["code"] == "unknown-dialect" and "line_no" not in response.json()


def test_missing_or_malformed_body_is_a_structured_422(client: TestClient) -> None:
    for payload in ({}, {"config": 5}, {"config": "x", "dialect": "junos"}):
        response = client.post("/v1/exhume", json=payload)
        assert response.status_code == 422 and response.json()["code"] == "invalid-request"


def test_upload_over_2_mb_is_413(client: TestClient) -> None:
    big = "! padding\n" * 230_000  # about 2.3 MB of text, under the envelope allowance
    response = client.post("/v1/exhume", json={"config": big})
    assert response.status_code == 413 and response.json()["code"] == "too-large"
    huge = client.post("/v1/exhume", content=b"{" + b" " * (5 * 1024 * 1024) + b"}")
    assert huge.status_code == 413 and huge.json()["code"] == "too-large"


GATES = ["G1", "G2", "G3", "G4", "G5", "G6"]


def test_gate_returns_the_verdict_with_gates_and_the_audit_header(client: TestClient) -> None:
    response = _post(client, "gate", dialect="pix", budget=60, seed=5)
    body = response.json()  # type: ignore[attr-defined]
    assert response.status_code == 200 and body["api_version"] == "v1"  # type: ignore[attr-defined]
    verdict = body["verdict"]
    assert verdict["value"] == "NO-GO" and [g["gate"] for g in verdict["gates"]] == GATES
    assert verdict["blocking_reasons"] and verdict["blocking_reasons"][0].startswith("G")
    audit = verdict["audit"]
    assert audit["tool_version"] == __version__ and audit["git_commit"]
    assert audit["seed"] == 5 and audit["budget"] == 60 and audit["generated_at"]
    assert len(audit["inputs"]) == 2 and set(audit["outputs"]) == {
        "panos-baseline.set",
        "source-redacted.cfg",
    }
    assert body["examples_per_context"] == 60 and body["profile"] == "custom"
    assert body["proof_passed"] is True and body["coverage"]["total_lines"] > 0


def test_gate_defaults_to_the_ci_budget_and_a_profile_can_lower_it(client: TestClient) -> None:
    default = _post(client, "gate", dialect="pix").json()  # type: ignore[attr-defined]
    assert default["examples_per_context"] == 5000 and default["profile"] == "ci"
    assert not any("below the ci budget" in r for r in default["verdict"]["blocking_reasons"])
    dev = _post(client, "gate", dialect="pix", profile="dev").json()  # type: ignore[attr-defined]
    assert dev["examples_per_context"] == 500 and dev["profile"] == "dev"
    assert any("below the ci budget" in r for r in dev["verdict"]["blocking_reasons"])


def test_gate_reaches_go_with_a_complete_sidecar_in_the_request_body(client: TestClient) -> None:
    sidecar = full_sidecar(core_for(GO_CONFIG, "asa"))
    body = {"config": GO_CONFIG, "dialect": "asa", "sidecar": sidecar.model_dump(mode="json")}
    response = client.post("/v1/gate", json=body)
    assert response.status_code == 200
    verdict = response.json()["verdict"]
    assert verdict["value"] == "GO" and verdict["blocking_reasons"] == []
    refused = client.post("/v1/gate", json={"config": GO_CONFIG, "dialect": "asa"})
    assert refused.json()["verdict"]["value"] == "NO-GO"  # the sidecar is not stored


def test_a_sidecar_with_an_unknown_key_or_a_bare_decision_is_a_structured_422(
    client: TestClient,
) -> None:
    for sidecar in ({"waivres": []}, {"ledger_decisions": {"LED-0001": "accepted"}}):
        response = _post(client, "gate", sidecar=sidecar)
        assert response.status_code == 422  # type: ignore[attr-defined]
        assert response.json()["code"] == "invalid-request"  # type: ignore[attr-defined]


def test_gate_runs_golden_flows_given_as_toml_text(client: TestClient) -> None:
    golden = (GOLDEN / "pix-2006-hq.toml").read_text(encoding="utf-8")
    body = _post(client, "gate", dialect="pix", budget=40, golden=golden).json()  # type: ignore[attr-defined]
    assert body["golden_total"] == 16 and body["golden_passed"] == 16
    for bad in ("[[flow]]\nid = 'X'\n", "not toml ["):
        response = _post(client, "gate", dialect="pix", budget=20, golden=bad)
        assert response.status_code == 422  # type: ignore[attr-defined]
        assert response.json()["code"] == "invalid-golden"  # type: ignore[attr-defined]


def test_grimoire_returns_markdown_html_and_a_body_hash(client: TestClient) -> None:
    first = _post(client, "grimoire", dialect="pix", budget=40, name="hq-firewall.cfg").json()  # type: ignore[attr-defined]
    second = _post(client, "grimoire", dialect="pix", budget=40, name="hq-firewall.cfg").json()  # type: ignore[attr-defined]
    assert first["markdown"].startswith(
        "# Grimoire: migration evidence report: hq-firewall.cfg (baseline artifact)\n"
    )
    assert first["html"].startswith("<!DOCTYPE html>") and "<h2>10. Appendix</h2>" in first["html"]
    assert re.findall(r"^## (\d+)\. ", first["markdown"], flags=re.MULTILINE) == [
        str(n) for n in range(1, 11)
    ]
    assert first["verdict"]["value"] in ("GO", "CONDITIONAL", "NO-GO")
    assert first["body_sha256"] == second["body_sha256"] and len(first["body_sha256"]) == 64


def test_grimoire_escapes_the_input_name(client: TestClient) -> None:
    body = _post(
        client, "grimoire", dialect="pix", budget=20, name="<script>alert(1)</script>"
    ).json()  # type: ignore[attr-defined]
    assert "<script>" not in body["html"] and "&lt;script&gt;" in body["html"]
    assert body["markdown"].splitlines()[0].startswith("# Grimoire")


def test_gate_and_grimoire_refuse_what_the_other_endpoints_refuse(client: TestClient) -> None:
    for path in ("gate", "grimoire"):
        assert _post(client, path, budget=20_001).status_code == 422  # type: ignore[attr-defined]
        assert _post(client, path, profile="huge").json()["code"] == "invalid-profile"  # type: ignore[attr-defined]
        cycle = (BROKEN / "asa-group-cycle.cfg").read_text(encoding="utf-8")
        response = client.post(f"/v1/{path}", json={"config": cycle})
        assert response.status_code == 422 and response.json()["line_no"] > 0
        too_big = client.post(f"/v1/{path}", json={"config": "! padding\n" * 230_000})
        assert too_big.status_code == 413 and too_big.json()["code"] == "too-large"


def test_gate_and_grimoire_logs_hold_counts_only(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level("INFO", logger="necro.api"):
        _post(client, "gate", dialect="pix", budget=20)
        _post(client, "grimoire", dialect="pix", budget=20)
    entries = [json.loads(r.getMessage()) for r in caplog.records if r.name == "necro.api"]
    assert [e["status"] for e in entries] == [200, 200]
    assert entries[0]["counts"]["blocking"] > 0 and entries[1]["counts"]["report_chars"] > 0
    for token in (*SAMPLE_SECRETS, "access-list", "telnet", "Grimoire"):
        assert token not in caplog.text


def test_unknown_route_and_wrong_method_are_structured(client: TestClient) -> None:
    missing = client.get("/v1/exhume")
    assert missing.status_code == 405 and missing.json()["code"] == "method-not-allowed"
    assert client.get("/nope").json()["code"] == "not-found"


def test_rate_limit_is_ten_posts_a_minute_per_client() -> None:
    limited = TestClient(create_app())
    codes = [limited.post("/v1/exhume", json={"config": CONFIG}).status_code for _ in range(12)]
    assert codes[:10] == [200] * 10 and codes[10:] == [429, 429]
    refused = limited.post("/v1/exhume", json={"config": CONFIG})
    assert refused.json()["code"] == "rate-limited" and int(refused.headers["retry-after"]) >= 1
    assert limited.get("/healthz").status_code == 200  # GET is not limited


def test_rate_limiter_window_slides() -> None:
    now = [0.0]
    limiter = RateLimiter(2, clock=lambda: now[0])
    assert limiter.retry_after("a") == 0 and limiter.retry_after("a") == 0
    assert limiter.retry_after("a") > 0 and limiter.retry_after("b") == 0
    now[0] = RATE_WINDOW_S + 1
    assert limiter.retry_after("a") == 0


def test_cors_allows_only_the_ui_origin() -> None:
    cors = TestClient(create_app(rate_per_minute=1000, ui_origin="https://ui.example.com"))
    ok = cors.get("/healthz", headers={"Origin": "https://ui.example.com"})
    assert ok.headers["access-control-allow-origin"] == "https://ui.example.com"
    other = cors.get("/healthz", headers={"Origin": "https://elsewhere.example.net"})
    assert "access-control-allow-origin" not in other.headers


def test_logs_have_ids_and_counts_but_never_config_lines(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level("INFO", logger="necro.api"):
        client.post("/v1/exhume", json={"config": CONFIG})
    entries = [json.loads(r.getMessage()) for r in caplog.records if r.name == "necro.api"]
    assert len(entries) == 1 and entries[0]["status"] == 200 and entries[0]["bytes_in"] > 0
    assert entries[0]["counts"]["acls"] >= 1 and entries[0]["request_id"]
    for token in (*SAMPLE_SECRETS, "access-list", "telnet"):
        assert token not in caplog.text


def test_sample_secrets_never_reach_a_response(client: TestClient) -> None:
    assert all(token in CONFIG for token in SAMPLE_SECRETS)
    for path in ("exhume", "autopsy", "resurrect", "prove", "gate", "grimoire"):
        body = client.post(f"/v1/{path}", json={"config": CONFIG, "budget": 20}).text
        assert not [t for t in SAMPLE_SECRETS if t in body], path


def test_an_unexpected_error_is_a_500_with_no_details() -> None:
    app = create_app(rate_per_minute=1000)

    @app.get("/boom")
    def boom() -> None:
        raise RuntimeError("internal detail that must not leak")

    response = TestClient(app, raise_server_exceptions=False).get("/boom")
    assert response.status_code == 500 and response.json()["code"] == "internal-error"
    assert "internal detail" not in response.text and response.headers["x-content-type-options"]


def test_the_lambda_handler_serves_http_api_events() -> None:
    event = {
        "version": "2.0",
        "routeKey": "GET /healthz",
        "rawPath": "/healthz",
        "rawQueryString": "",
        "headers": {"host": "api.example.com"},
        "requestContext": {
            "http": {
                "method": "GET",
                "path": "/healthz",
                "protocol": "HTTP/1.1",
                "sourceIp": "203.0.113.9",
            },
            "stage": "$default",
        },
        "isBase64Encoded": False,
    }
    result = handler(event, None)
    assert result["statusCode"] == 200 and json.loads(result["body"])["status"] == "ok"
