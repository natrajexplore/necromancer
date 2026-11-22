"""Task 6.6 / property P11: the same input gives byte-identical output (requirement 4.14).

The emitted config and the ledger are the deterministic parts that exist so far; the report body
(task 9.1) joins the property there. Two things can break determinism: state shared between runs
(caches, counters) and iteration order that depends on Python's per-process hash seed. The first
is tested in process, the second by running the emitter under several ``PYTHONHASHSEED`` values.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from necro.emitters import PanosEmission, emit_panos
from necro.ir import Policy
from necro.parsers import parse_config
from tests.ir_strategies import ios_policies, pix_asa_policies
from tests.panos_helpers import SAMPLES

CONFIGS = ["pix-2006-hq.cfg", "asa-8.2-branch.cfg", "ios-12-edge.cfg"]
BACKEND = Path(__file__).resolve().parents[1]


def fingerprint(emission: PanosEmission) -> str:
    """One hash over everything the emitter returns (text, ledger, notes, rule mapping)."""
    parts = [
        emission.text,
        "\n".join(e.model_dump_json(by_alias=True) for e in emission.ledger),
        "\n".join(emission.notes),
        "\n".join(emission.unsupported),
        "\n".join(f"{name}={source}" for name, source in emission.rule_sources.items()),
    ]
    return hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()


@pytest.mark.parametrize("config", CONFIGS)
def test_emitting_the_same_text_twice_is_byte_identical(config: str) -> None:
    text = (SAMPLES / config).read_text(encoding="utf-8")
    first, second = emit_panos(parse_config(text)), emit_panos(parse_config(text))
    assert first.text.encode("utf-8") == second.text.encode("utf-8")
    assert fingerprint(first) == fingerprint(second)


@pytest.mark.parametrize("config", CONFIGS)
def test_emission_has_no_run_dependent_content(config: str) -> None:
    text = emit_panos(parse_config((SAMPLES / config).read_text(encoding="utf-8"))).text
    assert "\r" not in text and "\t" not in text
    assert all(line == line.rstrip() for line in text.splitlines())
    assert text.endswith("\n") and not text.endswith("\n\n")


@pytest.mark.pbt
@settings(deadline=None)
@given(policy=st.one_of(pix_asa_policies(), ios_policies()))
def test_p11_generated_policies_emit_identically_every_time(policy: Policy) -> None:
    first = emit_panos(policy)
    again = emit_panos(policy)
    copied = emit_panos(policy.model_copy(deep=True))
    assert first.text.encode("utf-8") == again.text.encode("utf-8")
    assert fingerprint(first) == fingerprint(again) == fingerprint(copied)


_CHILD = """
import hashlib, sys
from pathlib import Path
from necro.emitters import emit_panos
from necro.parsers import parse_config
from tests.test_panos_determinism import fingerprint

digest = hashlib.sha256()
for name in sys.argv[2:]:
    text = (Path(sys.argv[1]) / name).read_text(encoding="utf-8")
    digest.update(fingerprint(emit_panos(parse_config(text))).encode())
print(digest.hexdigest())
"""


def _fingerprint_under_hash_seed(seed: str) -> str:
    env = {**os.environ, "PYTHONHASHSEED": seed, "PYTHONPATH": str(BACKEND)}
    done = subprocess.run(  # noqa: S603 - fixed argv, no user input
        [sys.executable, "-c", _CHILD, str(SAMPLES), *CONFIGS],
        capture_output=True,
        text=True,
        check=True,
        cwd=BACKEND,
        env=env,
        timeout=120,
    )
    return done.stdout.strip()


def test_p11_output_does_not_depend_on_the_python_hash_seed() -> None:
    results = {seed: _fingerprint_under_hash_seed(seed) for seed in ("0", "1", "4242", "random")}
    assert len(set(results.values())) == 1, results
    assert len(next(iter(results.values()))) == 64
