"""pytest configuration: Hypothesis profiles, pbt marker, socket-blocking fixture."""

from __future__ import annotations

import os
import socket
from collections.abc import Generator
from unittest.mock import patch

import pytest
from hypothesis import HealthCheck, settings

# ---------------------------------------------------------------------------
# Hypothesis profiles
# ---------------------------------------------------------------------------
settings.register_profile(
    "dev",
    max_examples=500,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.register_profile(
    "ci",
    max_examples=5_000,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.register_profile(
    "demo",
    max_examples=10_000,
    suppress_health_check=[HealthCheck.too_slow],
)

_profile = os.environ.get("HYPOTHESIS_PROFILE", "dev")
settings.load_profile(_profile)

# ---------------------------------------------------------------------------
# Custom markers
# ---------------------------------------------------------------------------


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "pbt: property-based tests (run with HYPOTHESIS_PROFILE=ci for the full budget)",
    )


# ---------------------------------------------------------------------------
# Socket-blocking fixture (requirement 8.3: engine makes no network calls)
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def block_network() -> Generator[None, None, None]:
    """Raise if any test opens a real network socket."""

    def _guard(*args: object, **kwargs: object) -> None:
        raise RuntimeError(
            "Network call attempted during test suite — the engine must make no network calls"
        )

    with patch.object(socket, "socket", side_effect=_guard):
        yield
