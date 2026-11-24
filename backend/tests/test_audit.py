"""Task 6: the audit header (migration-governance requirements 3.1 to 3.3)."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from necro import __version__
from necro.assessment import BASELINE_OUTPUT, SOURCE_OUTPUT, assemble, redacted_source
from necro.audit import build_audit, sha256_text, utc_now
from necro.gate_models import Sidecar
from necro.redact import redact
from necro.version import git_commit
from tests.gov_helpers import (
    NAMES,
    NOW,
    TODAY,
    assessment_of,
    core_of,
    full_sidecar,
    secret_tokens,
    text_of,
)


@pytest.mark.parametrize("name", NAMES)
def test_the_header_records_what_the_governance_steering_requires(name: str) -> None:
    a = assessment_of(name)
    audit, core = a.audit, a.core
    assert audit.tool_version == __version__
    assert audit.git_commit == git_commit() and audit.git_commit
    assert audit.inputs == {
        f"{name}.cfg": sha256_text(text_of(name)),
        f"{name}.cfg (redacted)": core.policy.input_sha256,
    }
    assert audit.dialect == core.policy.dialect.value
    assert audit.os_version == core.policy.os_version
    assert audit.options == {"dialect": f"{core.policy.dialect.value} (stated)"}
    assert (audit.seed, audit.budget, audit.profile) == (7, 60, "custom")
    assert audit.generated_at == NOW and audit.generated_at.utcoffset() == timedelta(0)
    assert a.verdict.audit == audit


@pytest.mark.parametrize("name", NAMES)
def test_every_output_artifact_has_its_sha256(name: str) -> None:
    core = core_of(name)
    audit = assessment_of(name).audit
    assert audit.outputs == {
        BASELINE_OUTPUT: sha256_text(core.emission.text),
        SOURCE_OUTPUT: sha256_text(core.redacted_source),
    }
    assert all(len(h) == 64 and set(h) <= set("0123456789abcdef") for h in audit.outputs.values())


@pytest.mark.parametrize("name", NAMES)
def test_the_redacted_source_is_what_the_redactor_makes_and_holds_no_secret(name: str) -> None:
    text = text_of(name)
    core = core_of(name)
    assert redacted_source(core.policy).splitlines() == redact(text).splitlines()
    assert core.redacted_source == redacted_source(core.policy)
    for token in secret_tokens(text):
        assert token not in core.redacted_source
        assert token not in core.emission.text


def test_the_original_hash_matches_the_text_and_differs_from_the_redacted_hash() -> None:
    audit = assessment_of("pix-2006-hq").audit
    original, redacted = audit.inputs.values()
    assert original != redacted  # the sample has secrets, so the two texts differ
    assert redacted == sha256_text(redact(text_of("pix-2006-hq")))


def test_two_runs_give_the_same_header_apart_from_the_time() -> None:
    core = core_of("ios-12-edge")
    first = assemble(core, Sidecar(), TODAY, NOW)
    later = assemble(core, Sidecar(), TODAY, NOW + timedelta(hours=5, minutes=3))
    one, two = first.audit.model_dump(), later.audit.model_dump()
    assert one.pop("generated_at") != two.pop("generated_at")
    assert one == two


def test_a_different_seed_changes_only_the_seed_and_a_different_input_changes_the_hashes() -> None:
    base = assessment_of("pix-2006-hq").audit
    other_seed = assemble(core_of("pix-2006-hq", 60, 8), Sidecar(), TODAY, NOW).audit
    assert other_seed.seed == 8 and base.seed == 7
    assert other_seed.inputs == base.inputs and other_seed.outputs == base.outputs
    other_input = assessment_of("asa-8.2-branch").audit
    assert other_input.inputs != base.inputs and other_input.outputs != base.outputs


def test_build_audit_takes_the_names_and_values_it_is_given() -> None:
    policy = core_of("pix-2006-hq").policy
    audit = build_audit(
        policy,
        original_sha256="a" * 64,
        outputs={"x": "b" * 64},
        options={"k": "v"},
        seed=1,
        budget=2,
        profile="ci",
        generated_at=NOW,
        input_name="fw.cfg",
    )
    assert audit.inputs == {"fw.cfg": "a" * 64, "fw.cfg (redacted)": policy.input_sha256}
    assert audit.options == {"k": "v"} and audit.outputs == {"x": "b" * 64}


def test_the_clock_helper_is_utc_to_the_second() -> None:
    now = utc_now()
    assert now.tzinfo == UTC and now.microsecond == 0


# Property P11 on the evidence itself: for a fixed input, options and seed, everything that is
# assembled from the human sidecar and the clock depends on them alone, and the generated time is
# the only header value the clock touches. The body-level form is in test_report_determinism.py.

clock = st.datetimes(min_value=datetime(2026, 1, 1), max_value=datetime(2030, 1, 1)).map(
    lambda d: d.replace(tzinfo=UTC)
)
days = st.dates(min_value=date(2026, 1, 1), max_value=date(2028, 12, 31))
CORE = core_of("asa-8.2-branch")


@pytest.mark.pbt
@given(today=days, first=clock, second=clock, approve=st.booleans())
def test_p11_verdict_runbook_and_header_do_not_depend_on_the_clock(
    today: date, first: datetime, second: datetime, approve: bool
) -> None:
    sidecar = full_sidecar(CORE) if approve else Sidecar()
    one = assemble(CORE, sidecar, today, first)
    two = assemble(CORE, sidecar, today, second)
    head_one, head_two = one.audit.model_dump(), two.audit.model_dump()
    assert head_one.pop("generated_at") == first and head_two.pop("generated_at") == second
    assert head_one == head_two
    assert one.verdict.model_copy(update={"audit": None}) == two.verdict.model_copy(
        update={"audit": None}
    )
    assert one.runbook == two.runbook and one.ledger == two.ledger
