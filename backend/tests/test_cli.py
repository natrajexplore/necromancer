"""Task 9.4: the ``necro`` CLI: formats, seed, profile, golden flows and exit codes."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest

from necro import __version__
from necro.cli import main
from necro.service import NecroError, check_size, resolve_budget, run_limited
from tests.gov_helpers import GO_CONFIG, core_for, full_sidecar, sidecar_json
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
        ["gate", "no-such-file.cfg"],
        ["grimoire", "no-such-file.cfg"],
        ["gate", PIX, "--sidecar", "no-such-sidecar.json"],
        ["gate", PIX, "--format", "html"],
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


# -- gate and grimoire (migration-governance task 9) ------------------------------------------

FAST = ("--dialect", "pix", "--budget", "40")
LEDGER_DECISION = 'approval = "accepted"\napprover = "Dana Approver"\ndecided_at = "2026-11-23"\n'


def test_gate_exits_one_for_no_go_and_says_why(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "gate", PIX, *FAST)
    assert code == 1
    assert "verdict" in out and "NO-GO" in out and "Blocking reasons" in out
    assert re.search(r"^G5\s+fail", out, flags=re.MULTILINE)


def test_gate_json_has_the_verdict_gates_and_the_audit_header(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code, out, _ = run(capsys, "gate", PIX, *FAST, "--format", "json", "--seed", "9")
    body = json.loads(out)
    assert code == 1 and body["verdict"]["value"] == "NO-GO" and body["seed"] == 9
    assert [g["gate"] for g in body["verdict"]["gates"]] == ["G1", "G2", "G3", "G4", "G5", "G6"]
    audit = body["verdict"]["audit"]
    assert audit["tool_version"] == __version__ and audit["budget"] == 40
    assert audit["inputs"]["pix-2006-hq.cfg"] == hashlib.sha256(Path(PIX).read_bytes()).hexdigest()


def test_gate_md_format_is_a_markdown_document(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "gate", PIX, *FAST, "--format", "md")
    assert code == 1 and out.startswith("# Readiness gates\n")
    assert "## Gates" in out and re.search(r"^\| G1 \| pass \| 0 \|$", out, flags=re.MULTILINE)


def test_gate_exits_zero_for_go_and_for_conditional(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    config = tmp_path / "lab.cfg"
    config.write_text(GO_CONFIG, encoding="utf-8")
    core = core_for(GO_CONFIG, "asa")
    side = tmp_path / "side.json"
    side.write_text(sidecar_json(full_sidecar(core)), encoding="utf-8")
    code, out, _ = run(capsys, "gate", str(config), "--dialect", "asa", "--sidecar", str(side))
    assert code == 0 and "GO" in out and "(ci)" in out  # the default is the ci budget
    four_eyes = tmp_path / "four-eyes.json"
    four_eyes.write_text(
        sidecar_json(full_sidecar(core, peer_reviewer="Alex Engineer")), encoding="utf-8"
    )
    code, out, _ = run(capsys, "gate", str(config), "--dialect", "asa", "--sidecar", str(four_eyes))
    assert code == 0 and "CONDITIONAL" in out and "four-eyes" in out


def test_a_toml_sidecar_works_too(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    config = tmp_path / "lab.cfg"
    config.write_text(GO_CONFIG, encoding="utf-8")
    ids = [e.id for e in core_for(GO_CONFIG, "asa").emission.ledger]
    toml = (
        '[change]\nchange_id = "CHG-7"\nrequested_by = "Alex Engineer"\n'
        'peer_reviewer = "Robin Reviewer"\ncab_reference = "CAB-1"\n'
        + "".join(f"[ledger_decisions.{i}]\n{LEDGER_DECISION}" for i in ids)
    )
    side = tmp_path / "side.toml"
    side.write_text(toml, encoding="utf-8")
    code, out, _ = run(capsys, "gate", str(config), "--dialect", "asa", "--sidecar", str(side))
    assert code == 0 and "GO" in out


def test_gate_and_grimoire_default_to_the_ci_budget_whatever_hypothesis_profile_is_set(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HYPOTHESIS_PROFILE", "dev")
    _, out, _ = run(capsys, "gate", PIX, "--dialect", "pix", "--format", "json")
    assert json.loads(out)["examples_per_context"] == 5000
    _, out, _ = run(capsys, "gate", PIX, "--dialect", "pix", "--profile", "dev", "--format", "json")
    assert json.loads(out)["examples_per_context"] == 500


def test_grimoire_prints_the_report_and_exits_zero_even_for_no_go(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code, out, _ = run(capsys, "grimoire", PIX, *FAST)
    assert code == 0 and out.startswith("# Grimoire: migration evidence report: pix-2006-hq.cfg")
    assert "Readiness verdict: NO-GO." in out
    assert re.findall(r"^## (\d+)\. ", out, flags=re.MULTILINE) == [str(n) for n in range(1, 11)]
    code, html_out, _ = run(capsys, "grimoire", PIX, *FAST, "--format", "html")
    assert (
        code == 0 and html_out.startswith("<!DOCTYPE html>") and "<h2>1. Verdict</h2>" in html_out
    )
    code, as_json, _ = run(capsys, "grimoire", PIX, *FAST, "--format", "json")
    body = json.loads(as_json)
    assert (
        code == 0 and body["markdown"].startswith("# Grimoire") and len(body["body_sha256"]) == 64
    )


def test_the_report_body_hash_is_the_same_on_every_run(capsys: pytest.CaptureFixture[str]) -> None:
    hashes = {
        json.loads(run(capsys, "grimoire", PIX, *FAST, "--seed", "3", "--format", "json")[1])[
            "body_sha256"
        ]
        for _ in range(2)
    }
    assert len(hashes) == 1


def test_the_input_hash_is_that_of_the_file_bytes_even_with_crlf_line_endings(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    config = tmp_path / "crlf.cfg"
    config.write_bytes(Path(PIX).read_bytes().replace(b"\n", b"\r\n"))
    _, out, _ = run(capsys, "gate", str(config), *FAST, "--format", "json")
    audit = json.loads(out)["verdict"]["audit"]
    assert audit["inputs"]["crlf.cfg"] == hashlib.sha256(config.read_bytes()).hexdigest()
    assert audit["inputs"]["crlf.cfg"] != hashlib.sha256(Path(PIX).read_bytes()).hexdigest()


@pytest.mark.parametrize(
    ("name", "content", "needle"),
    [
        ("bad.json", "{not json", "not valid JSON"),
        ("bad.toml", "waivers = [", "not valid TOML"),
        ("typo.json", '{"waivres": []}', "waivres"),
        ("bare.json", '{"ledger_decisions": {"LED-0001": "accepted"}}', "needs approval"),
        ("notes.txt", "{}", "a .json or .toml file"),
    ],
)
def test_a_bad_sidecar_is_an_input_error(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, name: str, content: str, needle: str
) -> None:
    side = tmp_path / name
    side.write_text(content, encoding="utf-8")
    code, out, err = run(capsys, "gate", PIX, *FAST, "--sidecar", str(side))
    assert code == 2 and not out and "invalid-sidecar" in err and needle in err


def test_python_dash_m_necro_gate_propagates_the_no_go_exit_code() -> None:
    done = subprocess.run(
        [sys.executable, "-m", "necro", "gate", PIX, *FAST, "--format", "json"],
        cwd=BACKEND,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert done.returncode == 1 and json.loads(done.stdout)["verdict"]["value"] == "NO-GO"


def test_gate_output_never_holds_a_secret(capsys: pytest.CaptureFixture[str]) -> None:
    secrets = ("8Ry2YjIyt7RRXU24", "2KFQnbNIdI.2KYOU", "n0t-a-real-community")
    for command in ("gate", "grimoire"):
        for fmt in ("json", "md") if command == "gate" else ("json", "md", "html"):
            _, out, err = run(capsys, command, PIX, *FAST, "--format", fmt)
            assert not [s for s in secrets if s in out + err], (command, fmt)


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
