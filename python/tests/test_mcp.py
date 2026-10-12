"""The MCP face is a closed set of metadata-only tools (SI-13, AT-2, AT-29)."""

from __future__ import annotations

import inspect
import secrets

import pytest

from ovenmitt import mcp as mcp_module
from ovenmitt.mcp import TOOL_NAMES, build_server


@pytest.mark.asyncio
async def test_tool_list_is_exactly_the_fixed_set(daemon):
    server = build_server(str(daemon.socket))
    tools = await server.list_tools()
    assert sorted(t.name for t in tools) == sorted(TOOL_NAMES)
    assert len(TOOL_NAMES) == 8
    for t in tools:
        props = t.input_schema.get("properties", {})
        for forbidden in ("content", "data", "bytes", "body", "text"):
            assert forbidden not in props, f"{t.name} accepts {forbidden}"
        assert "read" not in t.name and "get" not in t.name and "resolve" not in t.name


def test_mcp_module_never_mentions_resolve():
    src = inspect.getsource(mcp_module)
    assert "resolve" not in src.replace("# no resolve", "")


@pytest.mark.asyncio
async def test_vault_put_returns_metadata_and_unlinks_after_201(daemon, tmp_path):
    server = build_server(str(daemon.socket))
    content = "".join(chr(ord("a") + b % 26) for b in secrets.token_bytes(64))
    src = tmp_path / "note.txt"
    src.write_text(content)

    result = await server.call_tool(
        "vault_put", {"path": str(src), "vault": "private", "remove_source": True}
    )
    payload = _payload(result)
    assert payload["handle"].startswith("v_")
    assert payload["size"] == 64
    assert payload["name"] == "note.txt"
    assert content not in str(result)
    assert not src.exists()

    stat = _payload(await server.call_tool("vault_stat", {"handle": payload["handle"]}))
    assert stat["handle"] == payload["handle"]
    assert content not in str(stat)

    listed = _payload(await server.call_tool("vault_list", {"vault": "private"}))
    assert [o["handle"] for o in listed] == [payload["handle"]]

    vaults = _payload(await server.call_tool("vault_list_vaults", {}))
    assert [v["name"] for v in vaults] == ["hidden", "private"]

    dests = _payload(await server.call_tool("vault_list_destinations", {"vault": "private"}))
    assert {d["name"] for d in dests} == {"archive", "team-chat"}

    labelled = _payload(await server.call_tool("vault_label", {"handle": payload["handle"], "labels": ["k"]}))
    assert labelled["labels"] == ["k"]

    exported = _payload(await server.call_tool(
        "vault_export", {"handle": payload["handle"], "destination": "archive", "filename": "note-out.txt"}
    ))
    assert exported["size"] == 64
    assert (daemon.export_root / "note-out.txt").read_text() == content

    err = _payload(await server.call_tool("vault_export", {"handle": payload["handle"], "destination": "team-chat", "filename": "x"}))
    assert err["error"]["code"] == "DESTINATION_KIND_MISMATCH"

    deleted = _payload(await server.call_tool("vault_delete", {"handle": payload["handle"]}))
    assert deleted["deleted"] == payload["handle"]

    missing = _payload(await server.call_tool("vault_put", {"path": str(tmp_path / "nope"), "vault": "private"}))
    assert missing["error"]["code"] == "INVALID_REQUEST"


def _payload(result):
    """Unwrap an MCP tool result: structured content if present, else the
    JSON in the first text block."""
    import json

    structured = getattr(result, "structured_content", None)
    if isinstance(structured, dict) and set(structured) == {"result"}:
        return structured["result"]
    if structured is not None:
        return structured
    for block in getattr(result, "content", []) or []:
        text = getattr(block, "text", None)
        if text is not None:
            return json.loads(text)
    raise AssertionError(f"no payload in {result!r}")
