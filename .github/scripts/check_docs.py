"""Documentation hygiene for tracked text files. Run: python -I .github/scripts/check_docs.py

Checks every tracked .md, .yaml, .yml, .toml, .json, .txt and .ps1 file for a UTF-8 byte order mark,
invalid UTF-8, mojibake (UTF-8 text decoded as Windows-1252 and saved again) and e-mail addresses.
For every tracked .md file outside .kiro/agents it also checks that relative links and #anchors
resolve, that there is exactly one H1 and that heading levels do not skip. Template files that
are pasted into GitHub forms (.github/pull_request_template.md) are not checked for headings.
Repo tooling, not application code. Exit code 1 when anything is found.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TEXT = ("*.md", "*.yaml", "*.yml", "*.toml", "*.json", "*.txt", "*.ps1")
# a lead byte read as Latin-1 / Windows-1252 followed by a character that cannot start a word
MOJIBAKE = re.compile(
    "[\u00c3\u00c2\u00e2\u00f0][\u0080-\u00bf\u0152\u0153\u0160\u0161\u0178\u017d\u017e\u0192"
    "\u02c6\u02dc\u2013\u2014\u2018\u2019\u201a\u201c\u201d\u201e\u2020\u2021\u2022\u2026\u2030"
    "\u2039\u203a\u20ac\u2122]|\ufffd"
)
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
problems: list[str] = []


def tracked(*patterns: str) -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", *patterns], cwd=ROOT, capture_output=True, text=True, check=True
    )
    return out.stdout.split()


def slug(heading: str) -> str:
    text = re.sub(r"`", "", heading.strip().lower())
    text = re.sub(r"[^\w\s-]", "", text, flags=re.UNICODE)
    return re.sub(r"\s", "-", text)


def headings(text: str) -> list[tuple[int, int, str]]:
    found, fenced = [], False
    for number, line in enumerate(text.splitlines(), 1):
        if line.startswith("```"):
            fenced = not fenced
        match = None if fenced else re.match(r"^(#{1,6})\s+(.*)$", line)
        if match:
            found.append((number, len(match.group(1)), match.group(2)))
    return found


def check_encoding(path: str) -> str | None:
    with open(os.path.join(ROOT, path), "rb") as handle:
        data = handle.read()
    if data.startswith(b"\xef\xbb\xbf"):
        problems.append(f"{path}: has a UTF-8 byte order mark")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        problems.append(f"{path}: not valid UTF-8 ({exc})")
        return None
    if MOJIBAKE.search(text):
        problems.append(f"{path}: mojibake (UTF-8 saved through another encoding)")
    for address in sorted(set(EMAIL.findall(text))):
        problems.append(f"{path}: e-mail address {address}")
    return text


def check_markdown(path: str, text: str) -> None:
    levels = headings(text)
    if sum(1 for _, level, _ in levels if level == 1) != 1:
        problems.append(f"{path}: needs exactly one H1")
    previous = 0
    for number, level, _ in levels:
        if previous and level > previous + 1:
            problems.append(f"{path}:{number}: heading jumps from H{previous} to H{level}")
        previous = level
    body = re.sub(r"```.*?```", "", text, flags=re.S)
    for url in LINK.findall(body):
        if re.match(r"^(https?:|mailto:)", url):
            continue
        target, _, fragment = url.partition("#")
        full = os.path.normpath(os.path.join(os.path.dirname(path), target)) if target else path
        if target and not os.path.exists(os.path.join(ROOT, full)):
            problems.append(f"{path}: broken link {url}")
        elif fragment and full.endswith(".md"):
            with open(os.path.join(ROOT, full), encoding="utf-8") as handle:
                known = {slug(title) for _, _, title in headings(handle.read())}
            if fragment not in known:
                problems.append(f"{path}: broken anchor {url}")


def main() -> int:
    files = tracked(*TEXT)
    for path in files:
        text = check_encoding(path)
        skipped = path.startswith(".kiro/agents/") or path == ".github/pull_request_template.md"
        if text is not None and path.endswith(".md") and not skipped:
            check_markdown(path, text)
    for line in problems:
        print(line)
    print(f"check_docs: {len(files)} files, {len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
