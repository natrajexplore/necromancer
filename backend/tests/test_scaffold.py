"""Smoke tests for the task-1 scaffold (version, CLI entry point, socket guard)."""

from __future__ import annotations

import pytest


def test_version_string() -> None:
    from necro import __version__

    assert __version__ == "0.1.0"


def test_cli_main_runs(capsys: pytest.CaptureFixture[str]) -> None:
    """main() should print the stub message and exit cleanly."""
    from necro.cli import main

    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "necromancer" in captured.out


def test_socket_guard_active() -> None:
    """The autouse block_network fixture should block socket creation."""
    import socket

    with pytest.raises((RuntimeError, OSError)):
        socket.socket(socket.AF_INET, socket.SOCK_STREAM)
