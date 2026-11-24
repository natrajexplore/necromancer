"""Plain text and Markdown renderings of the engine results (CLI ``--format text|md``).

Each result becomes a ``Doc`` (facts, tables, optional code block), which renders the same way
in both formats. The output is plain and professional: no theming, no claims of compliance.
Line texts are the redacted ones from the result models.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from necro.proof_types import Counterexample
from necro.schemas import (
    AutopsyResult,
    ExhumeResult,
    GateResponse,
    ProveResult,
    ResurrectResult,
)


@dataclass
class Table:
    heading: str
    headers: list[str]
    rows: list[list[str]]


@dataclass
class Doc:
    title: str
    facts: list[tuple[str, str]] = field(default_factory=list)
    tables: list[Table] = field(default_factory=list)
    code: str = ""


def _cell(value: object) -> str:
    return str(value).replace("\n", " ")


def exhume_doc(r: ExhumeResult) -> Doc:
    c = r.coverage
    return Doc(
        "Exhume",
        [
            ("dialect", f"{r.dialect} {r.os_version}".strip()),
            ("detection confidence", f"{r.detection_confidence:.2f}"),
            ("mode / address space", f"{r.mode} / {r.address_space}"),
            ("lines", str(c.total_lines)),
            ("security-relevant lines", f"{c.security_relevant} ({c.handled} handled)"),
            ("blocking lines", str(c.blocking)),
            ("sha256", r.input_sha256),
        ],
        [
            Table(
                "Interfaces",
                ["name", "level", "address"],
                [[i.nameif, str(i.security_level), i.address] for i in r.interfaces],
            ),
            Table(
                "ACLs",
                ["name", "rules", "class"],
                [[a.name, str(a.rules), a.classification] for a in r.acls],
            ),
            Table(
                "Lines not migrated",
                ["line", "relevant", "reason", "text"],
                [
                    [str(u.line_no), "yes" if u.security_relevant else "no", u.reason, u.text]
                    for u in r.unparsed
                ],
            ),
        ],
    )


def autopsy_doc(r: AutopsyResult) -> Doc:
    severities = ", ".join(f"{k} {v}" for k, v in sorted(r.by_severity.items())) or "none"
    return Doc(
        "Autopsy",
        [("dialect", r.dialect), ("findings", f"{len(r.findings)} ({severities})")],
        [
            Table(
                "Findings",
                ["id", "severity", "type", "rule", "line", "finding"],
                [
                    [
                        f.id,
                        f.severity.value,
                        f.type.value,
                        f.rule_ref,
                        str(f.source_line),
                        f.label,
                    ]
                    for f in r.findings
                ],
            )
        ],
    )


def resurrect_doc(r: ResurrectResult) -> Doc:
    return Doc(
        "Resurrect",
        [
            ("dialect", r.dialect),
            ("candidate config lines", str(r.config_lines)),
            ("ledger entries", str(len(r.ledger))),
            ("not expressed", str(len(r.unsupported))),
            ("blocking source lines", str(len(r.blocking))),
        ],
        [
            Table(
                "Exorcism ledger",
                ["id", "class", "approval", "context", "reason"],
                [
                    [e.id, e.entry_class.value, e.approval.value, e.context, e.reason]
                    for e in r.ledger
                ],
            ),
            Table("Not expressed", ["item"], [[u] for u in r.unsupported]),
            Table("Notes", ["note"], [[n] for n in r.notes]),
            Table(
                "Blocking source lines",
                ["line", "reason", "text"],
                [[str(b.line_no), b.reason, b.text] for b in r.blocking],
            ),
        ],
        code=r.config,
    )


def _counterexample_facts(cx: Counterexample) -> list[tuple[str, str]]:
    f = cx.flow
    icmp = f" icmp-type {f.icmp_type}" if f.icmp_type is not None else ""
    was, now = cx.original, cx.resurrected
    return [
        ("counterexample", cx.reason),
        ("context", cx.context),
        ("flow", f"{f.src}:{f.src_port} -> {f.dst}:{f.dst_port} proto {f.proto}{icmp}"),
        ("original", f"{was.action.value} by {was.rule_id} to {cx.original_zone}"),
        ("resurrected", f"{now.action.value} by {now.rule_id} to {now.to_zone}"),
    ]


def prove_doc(r: ProveResult) -> Doc:
    p = r.proof
    facts = [
        ("result", "PASS: supports evidence for equivalence" if r.passed else "FAIL: divergence"),
        ("seed", str(p.seed)),
        ("examples per context", str(p.budget)),
        ("examples checked", str(p.examples)),
        ("golden flows", f"{p.golden.passed} of {p.golden.total} passed"),
        ("ledger entries", str(r.ledger_entries)),
        ("blocking source lines", str(r.blocking_lines)),
    ]
    if p.counterexample is not None:
        facts += _counterexample_facts(p.counterexample)
    rows = [
        [
            c.context,
            "implicit" if c.implicit else "acl",
            str(c.examples),
            "pass" if c.passed else "FAIL",
            f"{c.original.percent:g}%",
            f"{c.resurrected.percent:g}%",
        ]
        for c in p.contexts
    ]
    headers = ["context", "kind", "examples", "result", "source rules hit", "candidate rules hit"]
    return Doc("Proof of Life", facts, [Table("Contexts", headers, rows)])


def gate_doc(r: GateResponse) -> Doc:
    """The verdict first, then the gates, the blocking reasons and the conditions."""
    v = r.verdict
    facts = [
        ("verdict", v.value),
        ("dialect", r.dialect),
        ("coverage", f"{r.coverage.ratio * 100:.1f}% of {r.coverage.security_relevant} lines"),
        ("proof", "not run" if r.proof_passed is None else ("pass" if r.proof_passed else "FAIL")),
        ("examples per context", f"{r.examples_per_context} ({r.profile})"),
        ("seed", str(r.seed)),
        ("golden flows", f"{r.golden_passed} of {r.golden_total} passed"),
    ]
    return Doc(
        "Readiness gates",
        facts,
        [
            Table(
                "Gates",
                ["gate", "status", "blocking reasons"],
                [[g.gate, g.status, str(len(g.blocking_reasons))] for g in v.gates],
            ),
            Table("Blocking reasons", ["reason"], [[b] for b in v.blocking_reasons]),
            Table("Conditions", ["condition"], [[c] for c in v.conditions]),
            Table("Notes", ["note"], [[n] for n in v.notes]),
        ],
    )


def render_text(doc: Doc) -> str:
    lines = [doc.title, "=" * len(doc.title)]
    width = max((len(k) for k, _ in doc.facts), default=0)
    lines += [f"{k.ljust(width)}  {v}" for k, v in doc.facts]
    for table in doc.tables:
        if not table.rows:
            continue
        cells = [table.headers, *[[_cell(c) for c in row] for row in table.rows]]
        widths = [max(len(row[i]) for row in cells) for i in range(len(table.headers))]
        lines += ["", table.heading]
        for n, row in enumerate(cells):
            lines.append("  ".join(c.ljust(w) for c, w in zip(row, widths, strict=True)).rstrip())
            if n == 0:
                lines.append("  ".join("-" * w for w in widths))
    if doc.code:
        lines += ["", doc.code.rstrip("\n")]
    return "\n".join(lines) + "\n"


def render_md(doc: Doc) -> str:
    lines = [f"# {doc.title}", ""]
    lines += [f"- **{k}:** {v}" for k, v in doc.facts]
    for table in doc.tables:
        if not table.rows:
            continue
        lines += ["", f"## {table.heading}", "", "| " + " | ".join(table.headers) + " |"]
        lines.append("|" + "---|" * len(table.headers))
        for row in table.rows:
            lines.append("| " + " | ".join(_cell(c).replace("|", "\\|") for c in row) + " |")
    if doc.code:
        lines += ["", "## Candidate PAN-OS configuration", "", "```", doc.code.rstrip("\n"), "```"]
    return "\n".join(lines) + "\n"
