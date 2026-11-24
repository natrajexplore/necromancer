"""Task 9.4: the ``necro`` CLI: formats, seed, profile, golden flows and exit codes."""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from necro import __version__
from necro.cli import main
from necro.service import NecroError, check_size, resolve_budget, run_limited
from tests.panos_helpers import SAMPLES

PIX = str(SAMPLES / "pix-2006-hq.cfg")
GOLDEN = SAMPLES.parent / "golden-flows"
BACKEND = Path(__file__).resolve().parents[1]


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


@pytest.mark.parametrize("command", ["exhume", "autopsy", "resurrect"])
@pytest.mark.parametrize("fmt", ["json", "md", "text"])
def test_read_only_commands_exit_zero_in_every_format(
    capsys: pytest.CaptureFixture[str], command: str, fmt: str
) -> None:
    code, out, _ = run(capsys, command, PIX, "--format", fmt)
    assert code == 0 and out.strip()
    if fmt == "json":
        assert json.loads(out)["api_version"] == "v1"
    elif fmt == "md":
        assert out.startswith("# ")


def test_resurrect_text_is_only_the_candidate_config(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, err = run(capsys, "resurrect", PIX)
    assert code == 0 and all(line.startswith("set ") for line in out.splitlines())
    assert "ledger entries" in err


def test_json_ledger_uses_the_class_key(capsys: pytest.CaptureFixture[str]) -> None:
    _, out, _ = run(capsys, "resurrect", PIX, "--format", "json")
    assert all("class" in e for e in json.loads(out)["ledger"])


def test_prove_passes_with_golden_flows_and_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(
        capsys, "prove", PIX, "--budget", "60", "--golden", str(GOLDEN / "pix-2006-hq.toml")
    )
    assert code == 0 and "PASS" in out and "16 of 16 passed" in out


def test_prove_is_deterministic_for_a_seed_and_reports_it(
    capsys: pytest.CaptureFixture[str],
) -> None:
    args = ("prove", PIX, "--budget", "40", "--seed", "99", "--format", "json")
    first = run(capsys, *args)[1]
    assert run(capsys, *args)[1] == first and json.loads(first)["proof"]["seed"] == 99


def test_profile_sets_the_budget_and_budget_beats_it(capsys: pytest.CaptureFixture[str]) -> None:
    _, out, _ = run(capsys, "prove", PIX, "--profile", "dev", "--format", "json")
    assert json.loads(out)["proof"]["budget"] == 500
    _, out, _ = run(capsys, "prove", PIX, "--profile", "demo", "--budget", "30", "--format", "json")
    assert json.loads(out)["proof"]["budget"] == 30


def test_a_divergence_exits_one_with_the_counterexample(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """A golden vector the config cannot satisfy is a divergence, found before any search."""
    wrong = tmp_path / "wrong.toml"
    text = (GOLDEN / "pix-2006-hq.toml").read_text(encoding="utf-8")
    assert 'expect_action = "permit"' in text
    wrong.write_text(text.replace('expect_action = "permit"', 'expect_action = "deny"', 1))
    code, out, _ = run(capsys, "prove", PIX, "--budget", "10", "--golden", str(wrong))
    assert code == 1 and "FAIL" in out and "counterexample" in out


@pytest.mark.parametrize(
    "argv",
    [
        ["exhume", "no-such-file.cfg"],
        ["exhume", str(SAMPLES.parent / "broken-configs" / "asa-group-cycle.cfg")],
        ["prove", PIX, "--profile", "huge"],
        ["prove", PIX, "--budget", "0"],
        ["prove", PIX, "--budget", "20001"],
        ["prove", PIX, "--golden", "no-such.toml"],
        ["gate", PIX],
        ["grimoire", PIX],
    ],
)
def test_input_errors_exit_two_with_a_message_on_stderr(
    capsys: pytest.CaptureFixture[str], argv: list[str]
) -> None:
    code, out, err = run(capsys, *argv)
    assert code == 2 and not out and err.startswith("necro: error: ")


def test_parse_errors_name_the_line(capsys: pytest.CaptureFixture[str]) -> None:
    cycle = str(SAMPLES.parent / "broken-configs" / "asa-group-cycle.cfg")
    _, _, err = run(capsys, "exhume", cycle)
    assert "group-cycle" in err and "(line " in err


def test_empty_and_oversized_files_are_input_errors(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    empty = tmp_path / "empty.cfg"
    empty.write_text("")
    assert run(capsys, "exhume", str(empty))[0] == 2
    big = tmp_path / "big.cfg"
    big.write_bytes(b"!" * (2 * 1024 * 1024 + 1))
    code, _, err = run(capsys, "exhume", str(big))
    assert code == 2 and "larger than 2 MB" in err


def test_usage_errors_exit_two(capsys: pytest.CaptureFixture[str]) -> None:
    for argv in (["bogus", PIX], ["exhume"], ["exhume", PIX, "--format", "xml"]):
        with pytest.raises(SystemExit) as exc:
            main(argv)
        assert exc.value.code == 2
    capsys.readouterr()


def test_version_prints_version_and_commit(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    out = capsys.readouterr().out
    assert exc.value.code == 0 and __version__ in out and "commit" in out


def test_python_dash_m_necro_propagates_exit_codes() -> None:
    """The real entry point: ``python -m necro`` (Smart App Control blocks the .exe launchers)."""
    ok = subprocess.run(
        [sys.executable, "-m", "necro", "exhume", PIX, "--format", "json"],
        cwd=BACKEND,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert ok.returncode == 0 and json.loads(ok.stdout)["dialect"] == "pix"
    bad = subprocess.run(
        [sys.executable, "-m", "necro", "exhume", "missing.cfg"],
        cwd=BACKEND,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert bad.returncode == 2 and "necro: error" in bad.stderr


# -- service limits ---------------------------------------------------------------------------


def test_run_limited_times_out_and_passes_results_and_errors() -> None:
    assert run_limited(lambda: 41 + 1, timeout=5) == 42
    with pytest.raises(ValueError, match="boom"):
        run_limited(lambda: (_ for _ in ()).throw(ValueError("boom")), timeout=5)
    started = time.monotonic()
    with pytest.raises(NecroError) as exc:
        run_limited(lambda: time.sleep(1.0), timeout=0.05)
    assert exc.value.kind == "timeout" and exc.value.code == "timeout"
    assert time.monotonic() - started < 0.9


def test_size_check_counts_bytes_not_characters() -> None:
    check_size("a" * (2 * 1024 * 1024))
    with pytest.raises(NecroError) as exc:
        check_size("é" * (1024 * 1024 + 1))  # 2 bytes each in UTF-8
    assert exc.value.kind == "too-large"


def test_resolve_budget_rules() -> None:
    assert resolve_budget(5, "demo") == 5 and resolve_budget(None, "ci") == 5_000
    for bad in (0, 20_001):
        with pytest.raises(NecroError, match="between 1 and 20000"):
            resolve_budget(bad, None)
    with pytest.raises(NecroError) as exc:
        resolve_budget(None, "huge")
    assert exc.value.code == "invalid-profile"
