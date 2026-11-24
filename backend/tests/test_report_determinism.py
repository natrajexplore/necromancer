"""Tasks 6 and 7: the report body is deterministic (property P11, requirement 3.2).

The same input, options and seed give a byte-identical body. Only the generated time in the audit
header may differ. Two kinds of test:

* end to end: two independent runs of the whole pipeline (parse, emit, prove, assemble);
* property P11: the human-supplied part (waivers, accepted risks, ledger decisions, change record,
  runbook overrides) and the clock are generated, and the body must not depend on the clock and
  must be the same for equal inputs. The expensive proof is done once per sample, as it is a
  function of the input and the seed alone.
"""

from __future__ import annotations

import html
import re
from datetime import UTC, date, datetime, timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from necro import report
from necro.assessment import Core, assemble
from necro.controls import SECTION_TITLES
from necro.gate_models import ChangeMeta, RunbookOverrides, Sidecar, Waiver
from necro.ledger import Approval
from necro.tighten import ApprovalDecision
from tests.gov_helpers import (
    DIALECTS,
    FAR,
    FORBIDDEN,
    NAMES,
    NOW,
    TODAY,
    assessment_of,
    core_for,
    core_of,
    full_sidecar,
    golden_of,
    text_of,
)
from tests.test_report import headings


def fresh_core(name: str, seed: int) -> Core:
    """A core computed from scratch: nothing is shared with another run."""
    return core_for(
        text_of(name),
        DIALECTS[name],
        name=f"{name}.cfg",
        budget=40,
        seed=seed,
        golden=tuple(golden_of(name)),
    )


@pytest.mark.parametrize("name", NAMES)
def test_two_independent_runs_give_byte_identical_report_bodies(name: str) -> None:
    first = assemble(fresh_core(name, 11), Sidecar(), TODAY, NOW)
    second = assemble(fresh_core(name, 11), Sidecar(), TODAY, NOW + timedelta(minutes=17))
    assert report.render_md(first, mask_time=True) == report.render_md(second, mask_time=True)
    assert report.render_html(first, mask_time=True) == report.render_html(second, mask_time=True)
    assert report.body_sha256(first) == report.body_sha256(second)
    assert first.core.emission.text == second.core.emission.text
    assert first.core.proof == second.core.proof
    assert first.audit.outputs == second.audit.outputs


def test_unmasked_reports_differ_only_in_the_generated_time_line() -> None:
    core = core_of("asa-8.2-branch")
    later = NOW + timedelta(days=2, minutes=3)
    one = report.render_md(assemble(core, Sidecar(), TODAY, NOW)).splitlines()
    two = report.render_md(assemble(core, Sidecar(), TODAY, later)).splitlines()
    assert len(one) == len(two)
    differing = [(a, b) for a, b in zip(one, two, strict=True) if a != b]
    assert len(differing) == 1 and differing[0][0].startswith("| Generated (UTC) |")


def test_the_masked_body_has_no_time_and_a_different_seed_changes_the_body() -> None:
    a = assessment_of("pix-2006-hq")
    masked = report.render_md(a, mask_time=True)
    assert NOW.isoformat() not in masked and "(not part of the report body)" in masked
    other = assemble(core_of("pix-2006-hq", 60, 8), Sidecar(), TODAY, NOW)
    assert report.body_sha256(other) != report.body_sha256(a)


def test_the_date_waivers_are_judged_on_is_part_of_the_body() -> None:
    """Expiry changes the verdict, so the date used is recorded in the audit header."""
    core = core_of("pix-2006-hq")
    sidecar = full_sidecar(core)
    valid = assemble(core, sidecar, TODAY, NOW)
    expired = assemble(core, sidecar, FAR + timedelta(days=1), NOW)
    assert valid.verdict != expired.verdict
    assert report.body_sha256(valid) != report.body_sha256(expired)
    assert "| Waivers evaluated on | 2028-01-01 |" in report.render_md(expired)


# -- property P11 -------------------------------------------------------------------------------

text_values = st.text(
    alphabet=st.characters(exclude_categories=("Cs",), max_codepoint=0x2FFF),
    min_size=1,
    max_size=30,
).filter(lambda s: s.strip() != "")
optional_text = st.none() | text_values
dates = st.dates(min_value=date(2026, 1, 1), max_value=date(2028, 12, 31))
stamps = st.datetimes(min_value=datetime(2026, 1, 1), max_value=datetime(2030, 1, 1)).map(
    lambda d: d.replace(tzinfo=UTC)
)


def sidecars(core: Core) -> st.SearchStrategy[Sidecar]:
    """Sidecars that name things the core really has, plus free text for every field."""
    findings = st.sampled_from([f"finding:{f.id}" for f in core.findings])
    ledger_ids = [e.id for e in core.emission.ledger]
    targets = st.one_of(
        st.integers(1, 80).map(lambda n: f"line:{n}"),
        findings,
        st.sampled_from([f"ledger:{i}" for i in ledger_ids]),
    )

    def waiver(target: st.SearchStrategy[str]) -> st.SearchStrategy[Waiver]:
        return st.builds(
            Waiver, target=target, reason=text_values, approver=text_values, expires_on=dates
        )

    decision = st.builds(
        ApprovalDecision,
        approval=st.sampled_from([Approval.accepted, Approval.rejected]),
        approver=text_values,
        decided_at=text_values,
    )
    change = st.builds(
        ChangeMeta,
        change_id=optional_text,
        requested_by=optional_text,
        peer_reviewer=optional_text,
        cab_reference=optional_text,
    )
    overrides = st.builds(
        RunbookOverrides,
        rollback_triggers=st.none() | st.lists(text_values, min_size=1, max_size=3),
        decision_time_limit_minutes=st.none() | st.integers(1, 1440),
        hypercare_business_days=st.none() | st.integers(1, 90),
    )
    return st.builds(
        Sidecar,
        waivers=st.lists(waiver(targets), max_size=4),
        accepted_risks=st.lists(waiver(findings), max_size=3),
        ledger_decisions=st.dictionaries(st.sampled_from(ledger_ids), decision, max_size=4),
        change=change,
        runbook=overrides,
    )


IOS_CORE = core_of("ios-12-edge")
PIX_CORE = core_of("pix-2006-hq")


@pytest.mark.pbt
@given(sidecar=sidecars(IOS_CORE), today=dates, first=stamps, second=stamps)
def test_p11_the_report_body_depends_on_the_inputs_and_not_on_the_clock(
    sidecar: Sidecar, today: date, first: datetime, second: datetime
) -> None:
    one = assemble(IOS_CORE, sidecar, today, first)
    again = Sidecar.model_validate(sidecar.model_dump(mode="json"))  # an equal, separate object
    two = assemble(IOS_CORE, again, today, second)
    body = report.render_md(one, mask_time=True)
    assert body == report.render_md(two, mask_time=True)
    assert report.body_sha256(one) == report.body_sha256(two)
    assert headings(body) == list(enumerate(SECTION_TITLES, start=1))
    assert not FORBIDDEN.search(body)
    if first != second:
        assert report.render_md(one) != report.render_md(two)  # the time is in the header only


@pytest.mark.pbt
@given(sidecar=sidecars(PIX_CORE), today=dates, stamp=stamps)
def test_p11_html_is_deterministic_and_escapes_every_value(
    sidecar: Sidecar, today: date, stamp: datetime
) -> None:
    one = report.render_html(assemble(PIX_CORE, sidecar, today, stamp), mask_time=True)
    two = report.render_html(assemble(PIX_CORE, sidecar, today, stamp), mask_time=True)
    assert one == two
    change = sidecar.change
    for value in (change.change_id, change.requested_by, change.peer_reviewer):
        if value:
            assert f"<td>{html.escape(value, quote=True)}</td>" in one
    assert not re.search(r"<script|<img|<iframe", one)


@pytest.mark.pbt
@given(sidecar=sidecars(PIX_CORE), today=dates)
def test_p11_input_text_never_creates_a_heading(sidecar: Sidecar, today: date) -> None:
    plain_md = report.render_md(assemble(PIX_CORE, Sidecar(), today, NOW))
    md = report.render_md(assemble(PIX_CORE, sidecar, today, NOW))
    assert headings(md) == headings(plain_md)
    stray = [
        line
        for line in md.splitlines()
        if line.startswith("#") and not line.startswith(("# ", "## ", "### "))
    ]
    assert stray == []
