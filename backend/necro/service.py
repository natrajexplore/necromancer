"""The engine operations behind every interface: exhume, autopsy, resurrect, prove, gate.

The API, the MCP server and the CLI all call these functions, so limits and error handling are
the same everywhere (security steering "Runtime": 2 MB upload, 10 s parse timeout, 20,000
examples per request). Nothing here reads files, opens sockets or logs config lines.
"""

from __future__ import annotations

import threading
from collections import Counter
from collections.abc import Callable, Sequence
from typing import Literal, NoReturn

from necro.autopsy import analyze
from necro.coverage import compute_coverage
from necro.emitters import emit_panos
from necro.golden import GoldenVector
from necro.ir import Dialect, ParseError, Policy
from necro.oracle import (
    DEFAULT_SEED,
    MAX_BUDGET,
    ProofInputError,
    budget_for_profile,
)
from necro.oracle import prove as run_prove
from necro.parsers import parse_config
from necro.schemas import (
    AclSummary,
    AutopsyResult,
    CoverageSummary,
    ExhumeResult,
    InterfaceSummary,
    LineIssue,
    ProveResult,
    ResurrectResult,
)

MAX_UPLOAD_BYTES = 2 * 1024 * 1024
PARSE_TIMEOUT_S = 10.0

ErrorKind = Literal["input", "too-large", "timeout", "not-implemented"]


class NecroError(Exception):
    """A request the engine refuses or cannot complete: ``{code, message, line_no?}``."""

    def __init__(
        self, code: str, message: str, line_no: int = 0, kind: ErrorKind = "input"
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.line_no = line_no
        self.kind: ErrorKind = kind

    def body(self) -> dict[str, object]:
        out: dict[str, object] = {"code": self.code, "message": self.message}
        if self.line_no:
            out["line_no"] = self.line_no
        return out


def run_limited[T](fn: Callable[[], T], timeout: float = PARSE_TIMEOUT_S) -> T:
    """Run ``fn`` and give up after ``timeout`` seconds.

    A thread cannot be killed, so a runaway parse keeps its thread until it ends. The caller gets
    its answer on time, and the thread is a daemon so it never blocks process exit.
    """
    values: list[T] = []
    errors: list[BaseException] = []

    def target() -> None:
        try:
            values.append(fn())
        except BaseException as exc:  # re-raised in the caller
            errors.append(exc)

    worker = threading.Thread(target=target, daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        raise NecroError("timeout", f"parsing took longer than {timeout:g} s", kind="timeout")
    if errors:
        raise errors[0]
    return values[0]


def check_size(text: str) -> None:
    if len(text) > MAX_UPLOAD_BYTES or len(text.encode("utf-8")) > MAX_UPLOAD_BYTES:
        raise NecroError(
            "too-large",
            f"config is larger than {MAX_UPLOAD_BYTES // (1024 * 1024)} MB",
            kind="too-large",
        )


def load(text: str, dialect: str | None = None) -> Policy:
    """Check the size, then redact and parse within the parse timeout."""
    check_size(text)
    chosen = Dialect(dialect) if dialect else None
    try:
        return run_limited(lambda: parse_config(text, chosen))
    except ParseError as exc:
        raise NecroError(exc.code, exc.message, exc.line_no) from exc


def _issues(policy: Policy) -> list[LineIssue]:
    waived = {r.line_no for r in policy.line_records if r.waiver_id}
    return [
        LineIssue(
            line_no=u.line_no,
            text=u.text,
            reason=u.reason,
            security_relevant=u.security_relevant,
            waived=u.line_no in waived,
        )
        for u in policy.unparsed
    ]


def _blocking(policy: Policy) -> list[LineIssue]:
    return [i for i in _issues(policy) if i.security_relevant and not i.waived]


def exhume(text: str, dialect: str | None = None) -> ExhumeResult:
    policy = load(text, dialect)
    cov = compute_coverage(policy)
    return ExhumeResult(
        dialect=policy.dialect.value,
        os_version=policy.os_version,
        mode=policy.mode.value,
        address_space=policy.address_space.value,
        detection_confidence=policy.detection_confidence,
        input_sha256=policy.input_sha256,
        interfaces=[
            InterfaceSummary(
                nameif=i.nameif or i.hw_name,
                hw_name=i.hw_name,
                security_level=i.security_level,
                address=str(i.ip_address) if i.ip_address else "",
            )
            for i in policy.interfaces
        ],
        acls=[
            AclSummary(name=name, rules=len(rules), classification=policy.acl_classes.get(name, ""))
            for name, rules in policy.acls.items()
        ],
        bindings=len(policy.bindings),
        nat_rules=len(policy.nat_rules),
        coverage=CoverageSummary(
            total_lines=cov.total_lines,
            counts=cov.counts,
            security_relevant=cov.security_relevant,
            handled=cov.handled,
            waived=cov.waived,
            blocking=cov.blocking,
            ratio=cov.ratio,
        ),
        unparsed=_issues(policy),
    )


def autopsy(text: str, dialect: str | None = None) -> AutopsyResult:
    policy = load(text, dialect)
    findings = analyze(policy)
    return AutopsyResult(
        dialect=policy.dialect.value,
        findings=findings,
        by_severity=dict(Counter(f.severity.value for f in findings)),
        by_type=dict(Counter(f.type.value for f in findings)),
    )


def resurrect(text: str, dialect: str | None = None) -> ResurrectResult:
    policy = load(text, dialect)
    emission = emit_panos(policy)
    return ResurrectResult(
        dialect=policy.dialect.value,
        config=emission.text,
        config_lines=len(emission.lines),
        ledger=emission.ledger,
        unsupported=emission.unsupported,
        notes=emission.notes,
        blocking=_blocking(policy),
    )


def resolve_budget(budget: int | None, profile: str | None) -> int:
    """An explicit ``budget`` wins; otherwise the profile (or ``HYPOTHESIS_PROFILE``, or dev)."""
    if budget is not None:
        if not 1 <= budget <= MAX_BUDGET:
            raise NecroError("invalid-budget", f"budget must be between 1 and {MAX_BUDGET}")
        return budget
    try:
        return budget_for_profile(profile)
    except ValueError as exc:
        raise NecroError("invalid-profile", str(exc)) from exc


def prove(
    text: str,
    dialect: str | None = None,
    *,
    budget: int | None = None,
    seed: int | None = None,
    profile: str | None = None,
    golden: Sequence[GoldenVector] = (),
) -> ProveResult:
    """Resurrect, then prove the candidate behaves like the source (Proof of Life)."""
    examples = resolve_budget(budget, profile)
    policy = load(text, dialect)
    emission = emit_panos(policy)
    try:
        proof = run_prove(
            policy,
            emission.text,
            emission.ledger,
            budget=examples,
            seed=DEFAULT_SEED if seed is None else seed,
            golden=golden,
        )
    except (ProofInputError, ParseError) as exc:
        raise NecroError("proof-input", str(exc)) from exc
    return ProveResult(
        dialect=policy.dialect.value,
        passed=proof.passed,
        proof=proof,
        ledger_entries=len(emission.ledger),
        blocking_lines=len(_blocking(policy)),
    )


def gate(text: str, dialect: str | None = None) -> NoReturn:
    """Gates G1-G6 arrive with the migration-governance spec (task 9)."""
    raise NecroError(
        "not-implemented",
        "gate is not implemented yet: gates G1-G6 arrive with migration-governance task 9",
        kind="not-implemented",
    )


def grimoire(text: str, dialect: str | None = None) -> NoReturn:
    """The Grimoire report arrives with the migration-governance spec (task 9.1)."""
    raise NecroError(
        "not-implemented",
        "grimoire is not implemented yet: the report arrives with migration-governance task 9",
        kind="not-implemented",
    )
