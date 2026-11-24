"""``necro`` command line (requirement 7.4).

    necro exhume|autopsy|resurrect|prove|gate|grimoire <file>
          [--format json|md|text] [--dialect pix|asa|ios]
          [--seed N] [--profile dev|ci|demo] [--budget N] [--golden FILE.toml]

Exit codes: 0 = GO / pass, 1 = NO-GO / divergence, 2 = input error. ``exhume``, ``autopsy`` and
``resurrect`` exit 0 when they complete. ``gate`` and ``grimoire`` exit 2 with "not implemented
yet" until the migration-governance spec lands. Runnable as ``uv run python -m necro ...``.
The CLI reads the one file it is given and makes no network calls.
"""

from __future__ import annotations

import argparse
import contextlib
import sys
import tomllib
from collections.abc import Sequence
from pathlib import Path

from pydantic import BaseModel

from necro import cli_format, service
from necro.golden import GoldenVector, load_golden
from necro.service import MAX_UPLOAD_BYTES, NecroError
from necro.version import version_string

COMMANDS = ("exhume", "autopsy", "resurrect", "prove", "gate", "grimoire")
EXIT_OK, EXIT_DIVERGENCE, EXIT_INPUT = 0, 1, 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="necro",
        description="Raise dead firewall configs as zero-trust policy, and prove they came back "
        "the same. Exit codes: 0 GO/pass, 1 NO-GO/divergence, 2 input error.",
    )
    parser.add_argument("--version", action="version", version=version_string())
    parser.add_argument("command", choices=COMMANDS)
    parser.add_argument("file", type=Path, help="a PIX, ASA or IOS config")
    parser.add_argument("--format", choices=("json", "md", "text"), default="text")
    parser.add_argument("--dialect", choices=("pix", "asa", "ios"), help="skip detection")
    parser.add_argument("--seed", type=int, help="oracle seed (default: the fixed report seed)")
    parser.add_argument(
        "--profile", help="oracle budget: dev, ci or demo (default: $HYPOTHESIS_PROFILE, else dev)"
    )
    parser.add_argument(
        "--budget", type=int, help="examples per context, 1 to 20000 (beats --profile)"
    )
    parser.add_argument("--golden", type=Path, help="hand-verified flows (TOML) to run first")
    return parser


def _read(path: Path) -> str:
    try:
        if path.stat().st_size > MAX_UPLOAD_BYTES:
            raise NecroError("too-large", f"{path} is larger than 2 MB", kind="too-large")
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise NecroError("unreadable", f"cannot read {path}: {exc.strerror or exc}") from exc


def _golden(path: Path | None) -> list[GoldenVector]:
    if path is None:
        return []
    try:
        return load_golden(path)
    except (OSError, ValueError, KeyError, tomllib.TOMLDecodeError) as exc:
        raise NecroError("invalid-golden", f"cannot load golden flows {path}: {exc}") from exc


def _emit(result: BaseModel, doc: cli_format.Doc, fmt: str, *, config_only: str = "") -> None:
    if fmt == "json":
        print(result.model_dump_json(by_alias=True, indent=2))
    elif fmt == "md":
        print(cli_format.render_md(doc), end="")
    elif config_only:
        print(config_only, end="")
    else:
        print(cli_format.render_text(doc), end="")


def _run(args: argparse.Namespace) -> int:
    text = _read(args.file)
    fmt: str = args.format
    if args.command == "exhume":
        exhumed = service.exhume(text, args.dialect)
        _emit(exhumed, cli_format.exhume_doc(exhumed), fmt)
    elif args.command == "autopsy":
        autopsied = service.autopsy(text, args.dialect)
        _emit(autopsied, cli_format.autopsy_doc(autopsied), fmt)
    elif args.command == "resurrect":
        raised = service.resurrect(text, args.dialect)
        _emit(raised, cli_format.resurrect_doc(raised), fmt, config_only=raised.config)
        if fmt == "text" and (raised.ledger or raised.unsupported or raised.blocking):
            print(
                f"necro: {len(raised.ledger)} ledger entries, {len(raised.unsupported)} not "
                f"expressed, {len(raised.blocking)} blocking source lines; "
                "use --format md or json for the details",
                file=sys.stderr,
            )
    elif args.command == "prove":
        proved = service.prove(
            text,
            args.dialect,
            budget=args.budget,
            seed=args.seed,
            profile=args.profile,
            golden=_golden(args.golden),
        )
        _emit(proved, cli_format.prove_doc(proved), fmt)
        return EXIT_OK if proved.passed else EXIT_DIVERGENCE
    elif args.command == "gate":
        service.gate(text, args.dialect)
    else:
        service.grimoire(text, args.dialect)
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point of the ``necro`` script and ``python -m necro``. Returns the exit code."""
    with contextlib.suppress(AttributeError, ValueError):
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    args = _parser().parse_args(argv)  # argparse exits with 2 on a usage error
    try:
        return _run(args)
    except NecroError as exc:
        where = f" (line {exc.line_no})" if exc.line_no else ""
        print(f"necro: error: {exc.code}: {exc.message}{where}", file=sys.stderr)
        return EXIT_INPUT
