"""A request that names a built-in sample runs that sample's golden flows without sending them."""

from __future__ import annotations

import json
import socket
from collections.abc import Generator
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from api.main import create_app
from necro import cli, mcp_tools, samples, service
from tests.panos_helpers import SAMPLES

PIX = SAMPLES / "pix-2006-hq.cfg"
CONFIG = PIX.read_text(encoding="utf-8")
GOLDEN = SAMPLES.parent / "golden-flows"


@pytest.fixture(autouse=True)
def block_network() -> Generator[None, None, None]:
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


def test_the_sample_names_are_the_golden_files() -> None:
    assert samples.sample_names() == sorted(p.stem for p in GOLDEN.glob("*.toml"))
    assert samples.golden_path("pix-2006-hq") == GOLDEN / "pix-2006-hq.toml"
    assert samples.golden_path("../dead-configs/pix-2006-hq") is None
    assert samples.sample_of_config(PIX) == "pix-2006-hq"
    assert samples.sample_of_config(SAMPLES / "no-such.cfg") is None


def test_the_samples_folder_can_be_moved_with_an_environment_variable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(samples.SAMPLES_ENV, str(tmp_path))
    assert samples.sample_names() == []
    with pytest.raises(service.NecroError) as err:
        service.golden_for("pix-2006-hq")
    assert err.value.code == "unknown-sample" and "none found" in err.value.message


def test_api_prove_with_a_sample_runs_all_sixteen_golden_flows(client: TestClient) -> None:
    named = client.post(
        "/v1/prove", json={"config": CONFIG, "sample": "pix-2006-hq", "budget": 40, "seed": 3}
    ).json()
    assert named["passed"] is True
    assert (named["proof"]["golden"]["total"], named["proof"]["golden"]["passed"]) == (16, 16)
    anonymous = client.post("/v1/prove", json={"config": CONFIG, "budget": 40, "seed": 3}).json()
    assert anonymous["proof"]["golden"]["total"] == 0


def test_api_gate_and_grimoire_with_a_sample_report_sixteen_of_sixteen(
    client: TestClient,
) -> None:
    for path in ("gate", "grimoire"):
        body = client.post(
            f"/v1/{path}", json={"config": CONFIG, "sample": "pix-2006-hq", "budget": 40}
        ).json()
        assert (body["golden_total"], body["golden_passed"]) == (16, 16)


def test_api_explicit_golden_text_beats_the_sample(client: TestClient) -> None:
    text = (GOLDEN / "asa-8.2-branch.toml").read_text(encoding="utf-8")
    body = client.post(
        "/v1/gate", json={"config": CONFIG, "sample": "pix-2006-hq", "golden": text, "budget": 20}
    ).json()
    assert body["golden_total"] != 16  # the asa vectors ran instead, and fail on this config


@pytest.mark.parametrize("sample", ["no-such-sample", "../etc/passwd", "PIX"])
def test_api_refuses_an_unknown_or_malformed_sample(client: TestClient, sample: str) -> None:
    response = client.post("/v1/prove", json={"config": CONFIG, "sample": sample, "budget": 5})
    assert response.status_code == 422
    assert response.json()["code"] in {"unknown-sample", "invalid-request"}


def _run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str]:
    code = cli.main(list(argv))
    return code, capsys.readouterr().out


def test_cli_detects_a_bundled_sample_config(capsys: pytest.CaptureFixture[str]) -> None:
    code, out = _run(capsys, "prove", str(PIX), "--budget", "30", "--format", "json")
    assert code == 0
    assert json.loads(out)["proof"]["golden"]["total"] == 16


def test_cli_sample_flag_names_the_sample_for_a_copied_config(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    copy = tmp_path / "my-firewall.cfg"
    copy.write_text(CONFIG, encoding="utf-8")
    _, plain = _run(capsys, "prove", str(copy), "--budget", "30", "--format", "json")
    assert json.loads(plain)["proof"]["golden"]["total"] == 0
    _, named = _run(
        capsys, "prove", str(copy), "--budget", "30", "--format", "json", "--sample", "pix-2006-hq"
    )
    assert json.loads(named)["proof"]["golden"]["passed"] == 16


def test_cli_golden_file_beats_the_sample(capsys: pytest.CaptureFixture[str]) -> None:
    only = GOLDEN / "pix-2006-hq.toml"
    code, out = _run(
        capsys, "prove", str(PIX), "--budget", "20", "--format", "json", "--golden", str(only)
    )
    assert code == 0 and json.loads(out)["proof"]["golden"]["total"] == 16


def test_cli_unknown_sample_exits_with_an_input_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli.main(["prove", str(PIX), "--sample", "nope"]) == 2
    assert "unknown-sample" in capsys.readouterr().err


def test_mcp_tools_accept_a_sample() -> None:
    proved = mcp_tools.prove(CONFIG, "pix", budget=20, sample="pix-2006-hq")
    assert proved["proof"]["golden"]["passed"] == 16
    gated = mcp_tools.gate(CONFIG, "pix", budget=20, sample="pix-2006-hq")
    assert (gated["golden_total"], gated["golden_passed"]) == (16, 16)
    assert mcp_tools.prove(CONFIG, "pix", budget=5, sample="nope")["error"]["code"] == (
        "unknown-sample"
    )
