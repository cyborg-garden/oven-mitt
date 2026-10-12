"""The MCP face: `ovenmitt mcp` (PRD R-FAC-2, R-FAC-3, SI-13).

Eight tools, metadata only, no way to read content. ``vault_put`` takes a
path: the server opens it, streams it, and returns a handle. There is no
tool parameter that accepts content and no tool that returns bytes; a
test asserts the tool list equals the fixed set below.
"""

from __future__ import annotations

import os
from typing import Any

from mcp.server.mcpserver import MCPServer

from .client import DEFAULT_SOCKET, VaultClient
from .errors import OvenmittError

TOOL_NAMES: tuple[str, ...] = (
    "vault_list_vaults",
    "vault_list_destinations",
    "vault_put",
    "vault_stat",
    "vault_list",
    "vault_label",
    "vault_delete",
    "vault_export",
)


def build_server(socket_path: str = DEFAULT_SOCKET) -> MCPServer:
    """Construct the server with its closed tool set."""
    server = MCPServer(
        "ovenmitt",
        instructions=(
            "ovenmitt is a write-only vault. You can put files in, label them, "
            "export them to declared destinations and delete them by handle. "
            "There is no way to read an object's content back; that is the point."
        ),
    )
    client = VaultClient(socket_path)

    def _err(e: OvenmittError) -> dict[str, Any]:
        return {"error": {"code": e.code, "message": e.message}}

    @server.tool(
        name="vault_list_vaults",
        description="List the vaults this daemon serves: name, whether original filenames are visible, and TTL. Returns metadata only.",
    )
    def vault_list_vaults() -> list[dict[str, Any]]:
        return [v.__dict__ for v in client.vaults()]

    @server.tool(
        name="vault_list_destinations",
        description="List the destinations declared on a vault: names and kinds (fs or send). Only the operator can add destinations.",
    )
    def vault_list_destinations(vault: str) -> list[dict[str, Any]]:
        try:
            return [d.__dict__ for d in client.destinations(vault)]
        except OvenmittError as e:
            return [_err(e)]

    @server.tool(
        name="vault_put",
        description=(
            "Put a file from the agent's filesystem into a vault by path. Returns a handle and "
            "metadata (size, mime, labels) and never the content. With remove_source=true the "
            "original file is deleted after the daemon confirms the put."
        ),
    )
    def vault_put(
        path: str,
        vault: str,
        remove_source: bool = False,
        mime: str | None = None,
        labels: list[str] | None = None,
    ) -> dict[str, Any]:
        if not os.path.isfile(path):
            return {"error": {"code": "INVALID_REQUEST", "message": "path is not a file"}}
        try:
            info = client.put_path(
                path, vault, remove_source=remove_source, mime=mime, labels=labels or ()
            )
        except OvenmittError as e:
            return _err(e)
        return info.to_dict()

    @server.tool(
        name="vault_stat",
        description="Metadata for one object by handle: vault, size, mime, labels, timestamps. Never content.",
    )
    def vault_stat(handle: str) -> dict[str, Any]:
        try:
            return client.stat(handle).to_dict()
        except OvenmittError as e:
            return _err(e)

    @server.tool(
        name="vault_list",
        description="List objects (metadata only), optionally within one vault.",
    )
    def vault_list(vault: str | None = None) -> list[dict[str, Any]]:
        try:
            return [o.to_dict() for o in client.list(vault)]
        except OvenmittError as e:
            return [_err(e)]

    @server.tool(
        name="vault_label",
        description="Replace an object's labels (up to 16, each up to 256 bytes). Labels are visible to you; do not put content in them.",
    )
    def vault_label(handle: str, labels: list[str]) -> dict[str, Any]:
        try:
            return client.label(handle, labels).to_dict()
        except OvenmittError as e:
            return _err(e)

    @server.tool(
        name="vault_delete",
        description="Delete an object by handle. This is permanent: the key that could decrypt it is destroyed.",
    )
    def vault_delete(handle: str) -> dict[str, Any]:
        try:
            client.delete(handle)
        except OvenmittError as e:
            return _err(e)
        return {"deleted": handle}

    @server.tool(
        name="vault_export",
        description=(
            "Write an object to a declared filesystem destination under a filename you choose "
            "(letters, digits, '. _ -' and spaces; no paths). Fails with EXISTS if the name is "
            "taken, unless the operator configured the destination to overwrite."
        ),
    )
    def vault_export(handle: str, destination: str, filename: str) -> dict[str, Any]:
        try:
            return client.export(handle, destination, filename).__dict__
        except OvenmittError as e:
            return _err(e)

    return server


def main(socket_path: str = DEFAULT_SOCKET) -> None:
    """Serve over stdio."""
    build_server(socket_path).run("stdio")
