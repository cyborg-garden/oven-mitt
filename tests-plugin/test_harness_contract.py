"""Contract with the real harness: its session context, its platform enum
and a real platform adapter, receiving a `resolve_path` path.

Runs only where the harness is importable, i.e. inside the agent image:
    tests/run-in-agent-image.sh
Everything below the adapter (the network call) is replaced; everything
above it is the harness's own code.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import types

import pytest

signal_mod = pytest.importorskip("gateway.platforms.signal")
pytestmark = pytest.mark.skipif(not hasattr(os, "memfd_create"), reason="Linux only")

from gateway.config import Platform, PlatformConfig  # noqa: E402
from gateway.session_context import clear_session_vars, set_session_vars  # noqa: E402

from ovenmitt import VaultClient  # noqa: E402

PLATFORM = Platform.SIGNAL.value


@pytest.fixture
def signal_daemon(tmp_path, monkeypatch):
    import conftest

    monkeypatch.setattr(conftest, "PLATFORM", PLATFORM)
    d = conftest.Daemon(tmp_path)
    try:
        yield d
    finally:
        d.stop()


def test_real_adapter_inlines_the_resolved_file(plugin, signal_daemon, monkeypatch):
    import gateway.run

    adapter = signal_mod.SignalAdapter(
        PlatformConfig(extra={"account": "+640000000000", "http_url": "http://127.0.0.1:9"})
    )
    calls: list[tuple[str, dict]] = []

    async def fake_rpc(method, params, *a, **kw):
        calls.append((method, params))
        return {"timestamp": 1}

    monkeypatch.setattr(adapter, "_rpc", fake_rpc)
    runner = types.SimpleNamespace(adapters={Platform.SIGNAL: adapter}, _gateway_loop=None)
    monkeypatch.setattr(gateway.run, "_gateway_runner_ref", lambda: runner)

    body = secrets.token_hex(64).encode()
    cred = signal_daemon.issue_credential()
    with VaultClient(str(signal_daemon.socket)) as c:
        info = c.put(body, "private", mime="text/plain")
    group = "group:" + base64.b64encode(secrets.token_bytes(32)).decode()  # contains / + =

    tokens = set_session_vars(platform=PLATFORM, chat_id=group)
    try:
        out = json.loads(
            plugin._Bridge(str(signal_daemon.socket), cred).send(
                {"handle": info.handle, "filename": "transcript-20261016-1530.txt", "caption": "here you go"}
            )
        )
    finally:
        clear_session_vars(tokens)

    assert out["sent"] is True, out
    sends = [p for m, p in calls if m == "send"]
    assert len(sends) == 1
    params = sends[0]
    assert params["groupId"] == group[len("group:"):]
    assert params["message"] == "here you go"
    [attachment] = params["attachments"]
    head, b64 = attachment.split(";base64,", 1)
    assert head == "data:text/plain;filename=transcript-20261016-1530.txt"
    assert base64.b64decode(b64) == body
    assert f"{PLATFORM}/" in signal_daemon.audit_text()
