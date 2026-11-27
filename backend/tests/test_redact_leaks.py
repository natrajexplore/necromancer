"""P10, end to end: an injected secret appears in no output of the engine.

Every known secret form is appended to a sample config with a random secret, and the config goes
through every API endpoint (the Grimoire in Markdown and HTML) and every CLI command and format.
The secrets are random test inputs, not credentials.
"""

from __future__ import annotations

import contextlib
import io
import socket
import tempfile
from collections.abc import Generator
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from hypothesis import HealthCheck, example, given, settings
from hypothesis import strategies as st

from api.main import create_app
from necro.cli import main
from necro.redact import redact
from tests.panos_helpers import SAMPLES

SAMPLE_FILES = sorted(SAMPLES.glob("*.cfg"))

# One template per known secret form; {s} is the secret. Forms that parse as ordinary
# statements are included too, so a regression in an old pattern fails here as well.
FORMS = (
    "enable password {s}",
    "enable password level 5 {s}",
    "enable secret 5 {s}",
    "passwd {s}",
    "username a password 0 {s}",
    "username a privilege 15 secret 5 {s}",
    "username b privilege 1 password {s} mschap",
    "snmp-server community {s} RO",
    "snmp-server host inside 192.0.2.10 community {s} version 2c",
    "snmp-server user u g v3 auth sha {s} priv aes 128 {p}",
    "crypto isakmp key {s} address 192.0.2.1",
    "crypto isakmp key 6 {s} address 192.0.2.1",
    "isakmp key {s} address 192.0.2.9 netmask 255.255.255.255",
    " pre-shared-key {s}",
    " ikev1 pre-shared-key {s}",
    " ikev2 local-authentication pre-shared-key {s}",
    " key-string 7 {s}",
    "tacacs-server key {s}",
    "tacacs-server key 7 {s}",
    "radius-server key 7 {s}",
    "radius-server key {s}",
    "aaa-server T host 10.10.1.5 key {s}",
    "aaa-server T (inside) host 10.10.1.5 {s}",
    " key 7 {s}",
    "ntp authentication-key 1 md5 {s}",
    "ldap-login-password {s}",
    "ip ospf message-digest-key 1 md5 {s}",
    "ip ospf authentication-key {s}",
    "neighbor 192.0.2.1 password 7 {s}",
    "failover key {s}",
    "ftp-server password {s}",
    "ppp chap password {s}",
    "future-command passphrase md5 {s}",
    "future-command authentication-key sha256 {s}",
)

# Secrets: a unique prefix keeps them from being substrings of keywords or of each other.
_body = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", min_size=8
)
secrets_st = st.lists(_body, min_size=2 * len(FORMS), max_size=2 * len(FORMS)).map(
    lambda bodies: [f"Zq{i}x{b}" for i, b in enumerate(bodies)]
)
FIXED = [f"Zq{i}xFixedValue{i:03d}" for i in range(2 * len(FORMS))]


@pytest.fixture(autouse=True)
def block_network() -> Generator[None, None, None]:
    """Same guard as test_api: asyncio needs a loopback socketpair, name lookups stay blocked."""

    def _guard(*args: object, **kwargs: object) -> None:
        raise RuntimeError("Network call attempted during test suite")

    with (
        patch.object(socket, "getaddrinfo", side_effect=_guard),
        patch.object(socket, "create_connection", side_effect=_guard),
    ):
        yield


def _line(i: int, secrets: list[str]) -> str:
    return FORMS[i].format(s=secrets[2 * i], p=secrets[2 * i + 1])


def inject(config: str, secrets: list[str]) -> str:
    lines = [_line(i, secrets) for i in range(len(FORMS))]
    return config.rstrip("\n") + "\n" + "\n".join(lines) + "\n"


def cli_outputs(path: Path) -> list[str]:
    runs = [
        (cmd, fmt)
        for cmd in ("exhume", "autopsy", "resurrect", "prove", "gate")
        for fmt in ("text", "md", "json")
    ] + [("grimoire", f) for f in ("md", "html", "json")]
    outputs: list[str] = []
    for cmd, fmt in runs:
        argv = [cmd, str(path), "--format", fmt]
        if cmd in ("prove", "gate", "grimoire"):
            argv += ["--budget", "5"]
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            main(argv)
        outputs.append(out.getvalue() + err.getvalue())
    return outputs


def api_outputs(config: str) -> list[str]:
    client = TestClient(create_app(rate_per_minute=100_000))
    bodies: list[str] = []
    for path in ("exhume", "autopsy", "resurrect", "prove", "gate", "grimoire"):
        response = client.post(f"/v1/{path}", json={"config": config, "budget": 5})
        assert response.status_code == 200, (path, response.text[:200])
        bodies.append(response.text)
        if path == "grimoire":
            data = response.json()
            bodies.extend([data["markdown"], data["html"]])
    return bodies


@pytest.mark.pbt
@settings(max_examples=6, deadline=None, suppress_health_check=list(HealthCheck))
@example(sample=SAMPLE_FILES[0], secrets=FIXED)
@given(sample=st.sampled_from(SAMPLE_FILES), secrets=secrets_st)
def test_no_injected_secret_reaches_any_api_response_or_cli_output(
    sample: Path, secrets: list[str]
) -> None:
    config = inject(sample.read_text(encoding="utf-8"), secrets)
    outputs = api_outputs(config)
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / sample.name
        path.write_text(config, encoding="utf-8")
        outputs += cli_outputs(path)
    joined = "\n".join(outputs)
    leaked = [s for s in secrets if s in joined]
    assert not leaked, f"{len(leaked)} secret(s) leaked, first: {leaked[0]}"


@pytest.mark.pbt
@settings(max_examples=200, deadline=None)
@given(secrets=secrets_st)
def test_every_form_redacts_its_secrets_line_by_line(secrets: list[str]) -> None:
    """The redactor alone, fast: each form on its own line leaves no secret behind."""
    for i, form in enumerate(FORMS):
        out = redact(_line(i, secrets))
        assert secrets[2 * i] not in out, form
        assert secrets[2 * i + 1] not in out or "{p}" not in form, form
