"""A small document model, rendered to Markdown and to print-friendly HTML.

The report builds one list of ``Section`` objects and both renderers walk it, so the Markdown and
the HTML always carry the same content in the same order. There is no template engine: values are
escaped here, once, so a waiver reason, a rule remark or a finding text from the input cannot add
markup or fake a heading (migration-governance design, "Report").

Markdown: text from the input is collapsed to one line, ``|`` is escaped inside tables, and ``<``
is escaped so that placeholders such as ``<redacted>`` stay visible. HTML: everything goes through
``html.escape``. The HTML has no scripts, no external assets and a Content-Security-Policy that
allows nothing but its own inline style.
"""

from __future__ import annotations

import html
from dataclasses import dataclass


@dataclass(frozen=True)
class Heading:
    """A level-3 heading inside a section."""

    text: str


@dataclass(frozen=True)
class Para:
    text: str


@dataclass(frozen=True)
class Bullets:
    items: tuple[str, ...]


@dataclass(frozen=True)
class Table:
    headers: tuple[str, ...]
    rows: tuple[tuple[str, ...], ...]
    empty: str = "None."  # shown instead of a table with no rows


@dataclass(frozen=True)
class Code:
    """Text shown verbatim (a config)."""

    text: str


Block = Heading | Para | Bullets | Table | Code


@dataclass(frozen=True)
class Section:
    number: int
    title: str
    blocks: tuple[Block, ...]


def one_line(text: str) -> str:
    """``text`` on one line with single spaces: input text can't start a new Markdown block."""
    return " ".join(text.split())


def md_text(text: str) -> str:
    """Text for a Markdown paragraph, bullet or table cell."""
    return one_line(text).replace("<", "\\<")


def md_cell(text: str) -> str:
    return md_text(text).replace("|", "\\|")


def _fence(text: str) -> str:
    """A code fence longer than any run of backticks in ``text``."""
    longest = run = 0
    for char in text:
        run = run + 1 if char == "`" else 0
        longest = max(longest, run)
    return "`" * max(3, longest + 1)


def _md_block(block: Block) -> list[str]:
    if isinstance(block, Heading):
        return [f"### {md_text(block.text)}", ""]
    if isinstance(block, Para):
        return [md_text(block.text), ""]
    if isinstance(block, Bullets):
        return [*(f"- {md_text(item)}" for item in block.items), ""]
    if isinstance(block, Table):
        if not block.rows:
            return [md_text(block.empty), ""]
        head = "| " + " | ".join(md_cell(h) for h in block.headers) + " |"
        rule = "|" + "|".join("---" for _ in block.headers) + "|"
        rows = ["| " + " | ".join(md_cell(c) for c in row) + " |" for row in block.rows]
        return [head, rule, *rows, ""]
    fence = _fence(block.text)
    return [fence, block.text.rstrip("\n"), fence, ""]


def render_md(title: str, sections: list[Section]) -> str:
    """The sections as Markdown, ending with one newline."""
    lines = [f"# {md_text(title)}", ""]
    for section in sections:
        lines += [f"## {section.number}. {md_text(section.title)}", ""]
        for block in section.blocks:
            lines += _md_block(block)
    return "\n".join(lines).rstrip("\n") + "\n"


# -- HTML --------------------------------------------------------------------------------------

_CSS = """
body { font: 11pt/1.4 Arial, Helvetica, sans-serif; color: #111; margin: 2rem auto;
  max-width: 60rem; padding: 0 1rem; }
h1 { font-size: 1.6rem; border-bottom: 2px solid #111; padding-bottom: .3rem; }
h2 { font-size: 1.25rem; margin-top: 2rem; border-bottom: 1px solid #888; }
h3 { font-size: 1.05rem; margin-top: 1.2rem; }
table { border-collapse: collapse; width: 100%; margin: .5rem 0 1rem; font-size: 9.5pt; }
th, td { border: 1px solid #888; padding: .25rem .4rem; text-align: left; vertical-align: top;
  overflow-wrap: anywhere; }
th { background: #eee; }
pre { background: #f6f6f6; border: 1px solid #ccc; padding: .6rem; font-size: 8.5pt;
  white-space: pre-wrap; overflow-wrap: anywhere; }
@media print {
  body { margin: 0; max-width: none; }
  h2 { break-after: avoid; }
  tr { break-inside: avoid; }
  #s2, #s10 { break-before: page; }
}
""".strip()

_CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"


def _e(text: str) -> str:
    return html.escape(text, quote=True)


def _html_block(block: Block) -> list[str]:
    if isinstance(block, Heading):
        return [f"<h3>{_e(block.text)}</h3>"]
    if isinstance(block, Para):
        return [f"<p>{_e(block.text)}</p>"]
    if isinstance(block, Bullets):
        return ["<ul>", *(f"<li>{_e(item)}</li>" for item in block.items), "</ul>"]
    if isinstance(block, Table):
        if not block.rows:
            return [f"<p>{_e(block.empty)}</p>"]
        head = "".join(f"<th>{_e(h)}</th>" for h in block.headers)
        rows = ["<tr>" + "".join(f"<td>{_e(c)}</td>" for c in row) + "</tr>" for row in block.rows]
        return ["<table>", f"<tr>{head}</tr>", *rows, "</table>"]
    return [f"<pre>{_e(block.text)}</pre>"]


def render_html(title: str, sections: list[Section]) -> str:
    """The sections as one self-contained HTML document (no scripts, no external assets)."""
    lines = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        f'<meta http-equiv="Content-Security-Policy" content="{_CSP}">',
        '<meta name="referrer" content="no-referrer">',
        f"<title>{_e(title)}</title>",
        f"<style>{_CSS}</style>",
        "</head>",
        "<body>",
        f"<h1>{_e(title)}</h1>",
    ]
    for section in sections:
        lines.append(f'<section id="s{section.number}">')
        lines.append(f"<h2>{section.number}. {_e(section.title)}</h2>")
        for block in section.blocks:
            lines += _html_block(block)
        lines.append("</section>")
    lines += ["</body>", "</html>"]
    return "\n".join(lines) + "\n"
