"""The send contract: one sender shape, a target read off the sender, and
nothing the model says can change where a file goes."""

from __future__ import annotations

import asyncio
import functools
import json
import os
import secrets
import sys
import threading
import types
from urllib.parse import unquote

import pytest
from conftest import PLATFORM

from ovenmitt import ObjectInfo, VaultClient

linux_only = pytest.mark.skipif(
    not hasattr(os, "memfd_create"), reason="resolve_path needs memfd_create (Linux)"
)


class Platform:
    def __init__(self, value: str) -> None:
        self.value = value


class FakeAdapter:
    """Reads the file in-process, the way real platform adapters do."""

    def __init__(self, platform: str = PLATFORM) -> None:
        self.platform = Platform(platform)
        self.sent: list[dict] = []

    async def send_document(self, chat_id, file_path, caption=None, metadata=None, **kwargs):
        with open(file_path, "rb") as f:
            body = f.read()
        self.sent.append(
            {"chat_id": chat_id, "name": os.path.basename(file_path), "body": body,
             "caption": caption, "metadata": metadata, "path": file_path}
        )
        return types.SimpleNamespace(success=True, error=None)

    async def send(self, chat_id, content, **kwargs):  # pragma: no cover - never used
        raise AssertionError("the bridge must only use send_document")


def sentinel() -> bytes:
    return secrets.token_hex(32).encode()


# -- target grammar -----------------------------------------------------------


@pytest.mark.parametrize(
    "chat_id",
    ["+64211234567", "group:AbC+dEf/gh==", "123456789012345678", "a/b/c", "100%", "kōrero"],
)
def test_target_is_one_segment_and_round_trips(plugin, chat_id):
    t = plugin.bridge.target_for("signalish", chat_id)
    prefix, ref = t.split("/", 1)
    assert prefix == "signalish"
    assert "/" not in ref
    assert unquote(ref) == chat_id


# -- sender shape -------------------------------------------------------------


def test_accepts_the_one_shape(plugin):
    a = FakeAdapter()
    assert plugin.bridge.claim_from(functools.partial(a.send_document, "c1")) == (
        PLATFORM, f"{PLATFORM}/c1",
    )
    send = functools.partial(a.send_document, "c1", metadata={"thread_id": "t9"})
    assert plugin.bridge.claim_from(send) == (PLATFORM, f"{PLATFORM}/c1")


def _other_shapes():
    a = FakeAdapter()

    async def free_function(chat_id, path, **kw):
        return None

    class NoPlatform:
        async def send_document(self, chat_id, path, **kw):
            return None

    class Wrong:
        platform = Platform(PLATFORM)

        async def send_file(self, chat_id, path, **kw):
            return None

    return {
        "bound method, not a partial": a.send_document,
        "lambda": lambda p: None,
        "partial of a free function": functools.partial(free_function, "c1"),
        "partial of another method": functools.partial(Wrong().send_file, "c1"),
        "two bound args": functools.partial(a.send_document, "c1", "/tmp/x"),
        "no bound args": functools.partial(a.send_document),
        "non-string chat": functools.partial(a.send_document, 42),
        "empty chat": functools.partial(a.send_document, ""),
        "extra keyword": functools.partial(a.send_document, "c1", caption="x"),
        "metadata beyond thread": functools.partial(a.send_document, "c1", metadata={"chat_id": "c2"}),
        "adapter without platform": functools.partial(NoPlatform().send_document, "c1"),
        "unusable platform name": functools.partial(FakeAdapter("../x").send_document, "c1"),
    }


@pytest.mark.parametrize("label", list(_other_shapes()))
def test_refuses_every_other_shape(plugin, label):
    with pytest.raises(plugin.bridge.ShapeRefused):
        plugin.bridge.claim_from(_other_shapes()[label])


# -- filenames ----------------------------------------------------------------


def _info(mime: str = "text/plain; charset=utf-8") -> ObjectInfo:
    return ObjectInfo("v_0123456789ab", "private", 3, mime, "t", "t")


@pytest.mark.parametrize(
    ("requested", "expected"),
    [
        (None, "v_0123456789ab.txt"),
        ("", "v_0123456789ab.txt"),
        ("transcript-20261016-1530.txt", "transcript-20261016-1530.txt"),
        ("report", "report.txt"),
        ("../../etc/passwd", "_.._etc_passwd"),
        (".hidden.txt", "hidden.txt"),
        ("a\x00b\nc.txt", "a_b_c.txt"),
        ("..", "v_0123456789ab.txt"),
    ],
)
def test_filename_is_one_safe_segment(plugin, requested, expected):
    assert plugin.bridge.filename_for("v_0123456789ab", _info(), requested) == expected


def test_filename_byte_cap(plugin):
    name = plugin.bridge.filename_for("v_0123456789ab", _info(), "ā" * 300)
    assert len(name.encode()) <= 255


# -- tool surface -------------------------------------------------------------


def test_tool_set_is_closed_and_prefixed(plugin):
    assert set(plugin.SCHEMAS) == set(plugin.TOOL_NAMES)
    assert all(n.startswith("ovenmitt_vault_") for n in plugin.TOOL_NAMES)
    assert "ovenmitt_vault_export" not in plugin.TOOL_NAMES


def test_send_schema_has_no_way_to_name_a_target(plugin):
    props = plugin.SCHEMAS["ovenmitt_vault_send"]["parameters"]["properties"]
    assert set(props) == {"handle", "filename", "caption"}


def test_no_tool_takes_content(plugin):
    for name, schema in plugin.SCHEMAS.items():
        for prop in schema["parameters"]["properties"]:
            assert prop not in {"content", "data", "body", "bytes", "text"}, name


def test_register_pops_the_credential(plugin, monkeypatch):
    monkeypatch.setenv(plugin.CREDENTIAL_ENV, "ovm_deadbeef_secret")
    registered = []

    class Ctx:
        def register_tool(self, **kw):
            registered.append(kw)

    plugin.register(Ctx())
    assert plugin.CREDENTIAL_ENV not in os.environ
    assert [r["name"] for r in registered] == list(plugin.TOOL_NAMES)
    assert {r["toolset"] for r in registered} == {"ovenmitt"}
    for r in registered:
        assert "ovm_deadbeef_secret" not in json.dumps(r["schema"])


def test_credential_is_popped_at_import_before_register(monkeypatch):
    # A plugin whose register() never runs (a later import fails, or it is
    # installed but not enabled) must still not leave the credential behind.
    from conftest import load_plugin

    monkeypatch.setenv("OVENMITT_CONSUMER_CREDENTIAL", "ovm_popped_at_import")
    fresh = load_plugin("ovenmitt_bridge_import_pop")
    assert "OVENMITT_CONSUMER_CREDENTIAL" not in os.environ

    class Ctx:
        def register_tool(self, **kw):
            pass

    fresh.register(Ctx())
    assert fresh._POPPED_CREDENTIAL == "ovm_popped_at_import"


@pytest.mark.parametrize(
    "make",
    [
        lambda tmp: "/proc/self/environ",
        lambda tmp: "/etc/hosts",
        lambda tmp: _file(tmp / ".env"),
        lambda tmp: _file(tmp / "prod.env"),
        lambda tmp: _file(tmp / "auth.json"),
        lambda tmp: _file(tmp / ".ssh" / "config"),
        lambda tmp: _file(tmp / "server.pem"),
        lambda tmp: _link(tmp / "innocent.txt", _file(tmp / ".git-credentials")),
    ],
)
def test_put_refuses_secret_places(plugin, tmp_path, make):
    path = str(make(tmp_path))
    if not os.path.isfile(path):
        pytest.skip(f"{path} doesn't exist on this platform")
    b = plugin._Bridge("/nonexistent.sock", None)
    out = json.loads(b.put({"path": path, "vault": "private"}))
    assert out["error"]["code"] == "PATH_REFUSED"
    assert os.path.exists(path)


def test_put_allows_an_ordinary_output(plugin, tmp_path):
    path = _file(tmp_path / "transcript.txt")
    assert plugin.put_refusal(str(path)) is None


def _file(p):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("x")
    return p


def _link(link, target):
    link.symlink_to(target)
    return link


def test_send_without_credential_is_not_configured(plugin):
    b = plugin._Bridge("/nonexistent.sock", None)
    out = json.loads(b.send({"handle": "v_0123456789ab"}))
    assert out["error"]["code"] == "NOT_CONFIGURED"


def test_metadata_tools_report_an_unreachable_daemon(plugin):
    b = plugin._Bridge("/nonexistent/ovenmitt.sock", None)
    out = json.loads(b.list({}))
    assert out["error"]["code"] == "UNAVAILABLE"


# -- session glue -------------------------------------------------------------


@pytest.fixture
def fake_gateway(monkeypatch):
    """Just enough of a running gateway for session.current_sender()."""
    adapter = FakeAdapter()
    env = {"HERMES_SESSION_PLATFORM": PLATFORM, "HERMES_SESSION_CHAT_ID": "chat-A"}

    class PlatformEnum:
        def __init__(self, value):
            if value not in {PLATFORM, "otherchat"}:
                raise ValueError(value)
            self.value = value

        def __eq__(self, other):
            return getattr(other, "value", None) == self.value

        def __hash__(self):
            return hash(self.value)

    runner = types.SimpleNamespace(adapters={PlatformEnum(PLATFORM): adapter}, _gateway_loop=None)
    run_mod = types.ModuleType("gateway.run")
    run_mod._gateway_runner_ref = lambda: runner
    cfg_mod = types.ModuleType("gateway.config")
    cfg_mod.Platform = PlatformEnum
    ctx_mod = types.ModuleType("gateway.session_context")
    ctx_mod.get_session_env = lambda name, default="": env.get(name, default)
    pkg = types.ModuleType("gateway")
    for name, mod in {
        "gateway": pkg, "gateway.run": run_mod, "gateway.config": cfg_mod,
        "gateway.session_context": ctx_mod,
    }.items():
        monkeypatch.setitem(sys.modules, name, mod)
    return types.SimpleNamespace(adapter=adapter, env=env, runner=runner)


def test_sender_comes_from_the_session(plugin, fake_gateway):
    send, loop = plugin.session.current_sender()
    assert send.args == ("chat-A",)
    assert send.func.__self__ is fake_gateway.adapter
    assert loop is None


def test_thread_rides_in_metadata(plugin, fake_gateway):
    fake_gateway.env["HERMES_SESSION_THREAD_ID"] = "t-7"
    send, _ = plugin.session.current_sender()
    assert send.keywords == {"metadata": {"thread_id": "t-7"}}
    assert plugin.bridge.claim_from(send) == (PLATFORM, f"{PLATFORM}/chat-A")


def test_no_session_no_send(plugin, fake_gateway):
    fake_gateway.env.clear()
    with pytest.raises(plugin.session.NoSession):
        plugin.session.current_sender()


def test_runner_schedules_on_the_gateway_loop(plugin):
    loop = asyncio.new_event_loop()
    t = threading.Thread(target=loop.run_forever, daemon=True)
    t.start()
    try:
        seen = {}

        async def coro():
            seen["loop"] = asyncio.get_running_loop()
            return 7

        assert plugin.session.runner_on(loop)(coro()) == 7
        assert seen["loop"] is loop
    finally:
        loop.call_soon_threadsafe(loop.stop)
        t.join(5)


# -- end to end against a real daemon ----------------------------------------


@linux_only
def test_send_delivers_to_the_session_chat_only(plugin, fake_gateway, daemon):
    body = sentinel()
    cred = daemon.issue_credential()
    with VaultClient(str(daemon.socket)) as c:
        info = c.put(body, "private", mime="text/plain", labels=["transcript-x.txt"])
    b = plugin._Bridge(str(daemon.socket), cred)
    # The model tries to steer it elsewhere; extra arguments are ignored.
    out = json.loads(b.send({
        "handle": info.handle, "filename": "transcript-x.txt", "caption": "here you go",
        "chat_id": "chat-B", "target": f"{PLATFORM}/chat-B", "platform": "otherchat",
    }))
    assert out == {"sent": True, "handle": info.handle, "bytes": len(body), "filename": "transcript-x.txt"}
    [sent] = fake_gateway.adapter.sent
    assert sent["chat_id"] == "chat-A"
    assert sent["name"] == "transcript-x.txt"
    assert sent["body"] == body
    assert sent["caption"] == "here you go"
    assert not os.path.lexists(sent["path"]), "the path dies with the send"
    audit = daemon.audit_text()
    assert f"{PLATFORM}/chat-A" in audit
    assert "chat-B" not in audit
    assert body.decode() not in audit


@linux_only
def test_undeclared_platform_is_refused_and_audited(plugin, fake_gateway, daemon):
    other = FakeAdapter("otherchat")
    fake_gateway.runner.adapters = {type(next(iter(fake_gateway.runner.adapters)))("otherchat"): other}
    fake_gateway.env["HERMES_SESSION_PLATFORM"] = "otherchat"
    cred = daemon.issue_credential()
    with VaultClient(str(daemon.socket)) as c:
        info = c.put(sentinel(), "private", mime="text/plain")
    out = json.loads(plugin._Bridge(str(daemon.socket), cred).send({"handle": info.handle}))
    assert out["error"]["code"] == "DESTINATION_NOT_FOUND"
    assert other.sent == []
    assert '"outcome":"refused"' in daemon.audit_text()


class FailingAdapter(FakeAdapter):
    async def send_document(self, chat_id, file_path, caption=None, metadata=None, **kwargs):
        return types.SimpleNamespace(success=False, error="upload rejected")


@linux_only
def test_failed_platform_send_is_reported(plugin, fake_gateway, daemon):
    key = next(iter(fake_gateway.runner.adapters))
    fake_gateway.runner.adapters = {key: FailingAdapter()}
    cred = daemon.issue_credential()
    with VaultClient(str(daemon.socket)) as c:
        info = c.put(sentinel(), "private", mime="text/plain")
    out = json.loads(plugin._Bridge(str(daemon.socket), cred).send({"handle": info.handle}))
    assert out["error"] == {"code": "SEND_FAILED", "message": "upload rejected"}


@linux_only
def test_patched_sender_function_is_refused(plugin, fake_gateway, daemon):
    async def stand_in(chat_id, file_path, caption=None, **kw):  # pragma: no cover
        raise AssertionError("never called")

    fake_gateway.adapter.send_document = stand_in  # type: ignore[method-assign]
    cred = daemon.issue_credential()
    with VaultClient(str(daemon.socket)) as c:
        info = c.put(sentinel(), "private", mime="text/plain")
    out = json.loads(plugin._Bridge(str(daemon.socket), cred).send({"handle": info.handle}))
    assert out["error"]["code"] == "SEND_FAILED"
    assert "resolve" not in daemon.audit_text(), "a refused shape costs no resolve"
