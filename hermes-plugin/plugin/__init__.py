"""ovenmitt bridge: native harness tools for a write-only vault.

Seven tools, all prefixed ``ovenmitt_vault_`` so they can't be mistaken for
any other "vault" the harness has. Each returns metadata; none returns
content. ``ovenmitt_vault_send`` delivers an object to the chat this turn
belongs to, through the harness's own sender, and to nowhere else: it has
no argument that could name a different chat.

The consumer credential arrives in the process environment and is popped
out of it as this module's very first statement, before any import that
could fail: a plugin that never loads must not leave the credential behind
for terminal children to inherit. ``register()`` hands it to the tools.
"""

from __future__ import annotations

import os

# First, before anything that can raise. On importlib.reload the module dict
# survives, so a second import keeps the value the first one popped.
_POPPED_CREDENTIAL: str | None = (
    os.environ.pop("OVENMITT_CONSUMER_CREDENTIAL", None) or globals().get("_POPPED_CREDENTIAL")
)

import json  # noqa: E402
import logging  # noqa: E402
import stat  # noqa: E402
from typing import Any  # noqa: E402

import httpx  # noqa: E402
from ovenmitt import OvenmittError, VaultClient

from . import bridge, session  # noqa: E402

logger = logging.getLogger(__name__)

__version__ = "0.2.0"

CREDENTIAL_ENV = "OVENMITT_CONSUMER_CREDENTIAL"
SOCKET_ENV = "OVENMITT_SOCKET"
DEFAULT_SOCKET = "/run/ovenmitt/ovenmitt.sock"
TOOLSET = "ovenmitt"
TOOL_NAMES: tuple[str, ...] = (
    "ovenmitt_vault_put",
    "ovenmitt_vault_list",
    "ovenmitt_vault_stat",
    "ovenmitt_vault_label",
    "ovenmitt_vault_delete",
    "ovenmitt_vault_list_destinations",
    "ovenmitt_vault_send",
)


def _ok(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


def _refused(code: str, message: str) -> str:
    return json.dumps({"error": {"code": code, "message": message}}, ensure_ascii=False)


def _handle_schema(description: str) -> dict[str, Any]:
    return {"type": "string", "description": description, "pattern": "^v_[0-9a-f]{12}$"}


SCHEMAS: dict[str, dict[str, Any]] = {
    "ovenmitt_vault_put": {
        "name": "ovenmitt_vault_put",
        "description": (
            "Put a file into an ovenmitt vault by path. Returns a handle and metadata (size, "
            "MIME type, labels), never the content. From then on, refer to it by handle. "
            "With remove_source=true the original file is deleted once the vault has it."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path of the file to put."},
                "vault": {"type": "string", "description": "Vault name (objects you already hold show theirs)."},
                "labels": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional labels. Visible to you; never put content in them.",
                },
                "mime": {"type": "string", "description": "Optional MIME type, e.g. text/plain."},
                "remove_source": {"type": "boolean", "description": "Delete the original after the put."},
            },
            "required": ["path", "vault"],
        },
    },
    "ovenmitt_vault_list": {
        "name": "ovenmitt_vault_list",
        "description": "List vault objects: handles and metadata only. Omit vault to list every vault.",
        "parameters": {
            "type": "object",
            "properties": {"vault": {"type": "string", "description": "Optional vault name."}},
            "required": [],
        },
    },
    "ovenmitt_vault_stat": {
        "name": "ovenmitt_vault_stat",
        "description": "Metadata for one object: vault, size, MIME type, labels, timestamps, expiry.",
        "parameters": {
            "type": "object",
            "properties": {"handle": _handle_schema("The object's handle.")},
            "required": ["handle"],
        },
    },
    "ovenmitt_vault_label": {
        "name": "ovenmitt_vault_label",
        "description": "Replace an object's labels. Labels are visible to you; never put content in them.",
        "parameters": {
            "type": "object",
            "properties": {
                "handle": _handle_schema("The object's handle."),
                "labels": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["handle", "labels"],
        },
    },
    "ovenmitt_vault_delete": {
        "name": "ovenmitt_vault_delete",
        "description": "Delete an object. Permanent: the key that could decrypt it is destroyed.",
        "parameters": {
            "type": "object",
            "properties": {"handle": _handle_schema("The object's handle.")},
            "required": ["handle"],
        },
    },
    "ovenmitt_vault_list_destinations": {
        "name": "ovenmitt_vault_list_destinations",
        "description": (
            "List the destinations the operator declared on a vault (names and kinds). "
            "A send to this chat works only if a destination for this chat's platform exists."
        ),
        "parameters": {
            "type": "object",
            "properties": {"vault": {"type": "string", "description": "Vault name."}},
            "required": ["vault"],
        },
    },
    "ovenmitt_vault_send": {
        "name": "ovenmitt_vault_send",
        "description": (
            "Send a vault object to the person you are talking to, as a file attachment in this "
            "chat. It can only go to this chat. You never see the content. A refusal means the "
            "operator has not allowed this platform; tell the user, don't try another way."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "handle": _handle_schema("The object to send."),
                "filename": {
                    "type": "string",
                    "description": "Optional attachment name, e.g. a filename label the object carries.",
                },
                "caption": {"type": "string", "description": "Optional short message with the file."},
            },
            "required": ["handle"],
        },
    },
}


# --- what put may take ------------------------------------------------------
#
# `put` reads a file and `send` delivers it without the bytes ever passing the
# model, so nothing the harness does to tool output (redaction, file guards)
# sees it. That makes put a way to mail out anything the gateway can read.
# Refuse the places secrets live: kernel and runtime pseudo-filesystems
# (/proc/self/environ holds the gateway's initial environment), system config,
# and credential files by name. Checked on the fully resolved path, so a
# symlink can't route around it. A hard link can; that is deliberate hunting,
# outside the threat model.

_REFUSED_ROOTS = ("/proc", "/sys", "/dev", "/run", "/var/run", "/etc")
_REFUSED_DIRS = frozenset({".ssh", ".gnupg", ".aws", ".azure", ".docker", ".kube", ".config/gcloud"})
_REFUSED_NAMES = frozenset({
    ".env", "auth.json", ".netrc", ".git-credentials", ".pgpass", "credentials",
    "credentials.json", "id_rsa", "id_ecdsa", "id_ed25519", "id_dsa",
})
_REFUSED_SUFFIXES = (".env", ".pem", ".key", ".p12", ".pfx")


def put_refusal(path: str) -> str | None:
    """Why `path` may not be put in a vault, or None when it may."""
    real = os.path.realpath(path)
    # Both the path as given and as resolved: on some systems /etc itself is
    # a symlink (macOS: /private/etc).
    for candidate in (os.path.abspath(path), real):
        for root in _REFUSED_ROOTS:
            if candidate == root or candidate.startswith(root + "/"):
                return f"files under {root} can't be put in a vault"
    try:
        if not stat.S_ISREG(os.stat(real).st_mode):
            return "only regular files can be put in a vault"
    except OSError:
        return "the file can't be read"
    parts = real.split("/")
    for d in _REFUSED_DIRS:
        seq = d.split("/")
        if any(parts[i:i + len(seq)] == seq for i in range(len(parts))):
            return "credential directories can't be put in a vault"
    name = os.path.basename(real).lower()
    if name in _REFUSED_NAMES or name.endswith(_REFUSED_SUFFIXES):
        return "credential files can't be put in a vault"
    return None


class _Bridge:
    """The tool handlers, sharing one client and the credential."""

    def __init__(self, socket_path: str, credential: str | None) -> None:
        self._socket_path = socket_path
        self._credential = credential  # never logged, never returned
        self._client: VaultClient | None = None

    def _c(self) -> VaultClient:
        if self._client is None:
            self._client = VaultClient(self._socket_path)
        return self._client

    def _call(self, fn) -> str:
        try:
            return _ok(fn())
        except OvenmittError as e:
            return _refused(e.code, e.message)
        except (OSError, httpx.TransportError):
            return _refused("UNAVAILABLE", "the ovenmitt daemon is not reachable")

    def put(self, args: dict[str, Any], **_: Any) -> str:
        path = str(args.get("path") or "")
        if not os.path.isfile(path):
            return _refused("INVALID_REQUEST", "path is not a file")
        why = put_refusal(path)
        if why:
            logger.warning("ovenmitt bridge: put refused (%s)", why)
            return _refused("PATH_REFUSED", f"{why}; only outputs you were asked to protect go in a vault")
        return self._call(
            lambda: self._c()
            .put_path(
                path,
                str(args.get("vault") or ""),
                remove_source=bool(args.get("remove_source")),
                mime=args.get("mime") or None,
                labels=list(args.get("labels") or ()),
            )
            .to_dict()
        )

    def list(self, args: dict[str, Any], **_: Any) -> str:
        return self._call(lambda: [o.to_dict() for o in self._c().list(args.get("vault") or None)])

    def stat(self, args: dict[str, Any], **_: Any) -> str:
        return self._call(lambda: self._c().stat(str(args.get("handle") or "")).to_dict())

    def label(self, args: dict[str, Any], **_: Any) -> str:
        return self._call(
            lambda: self._c().label(str(args.get("handle") or ""), list(args.get("labels") or ())).to_dict()
        )

    def delete(self, args: dict[str, Any], **_: Any) -> str:
        handle = str(args.get("handle") or "")

        def go() -> dict[str, str]:
            self._c().delete(handle)
            return {"deleted": handle}

        return self._call(go)

    def list_destinations(self, args: dict[str, Any], **_: Any) -> str:
        return self._call(
            lambda: [d.__dict__ for d in self._c().destinations(str(args.get("vault") or ""))]
        )

    def send(self, args: dict[str, Any], **_: Any) -> str:
        # Only these three keys are read. The target is never one of them.
        handle = str(args.get("handle") or "")
        filename = args.get("filename") or None
        caption = args.get("caption") or None
        if not self._credential:
            return _refused("NOT_CONFIGURED", "sending is not configured on this agent")
        try:
            sender, loop = session.current_sender()
        except session.NoSession as e:
            return _refused("NO_CHAT", str(e))

        def go() -> dict[str, Any]:
            return bridge.vault_send(
                self._c(),
                self._credential or "",
                handle,
                sender,
                filename=filename,
                caption=caption,
                run=session.runner_on(loop),
            )

        try:
            return self._call(go)
        except bridge.SendFailed as e:
            return _refused("SEND_FAILED", str(e))
        except bridge.ShapeRefused as e:
            logger.error("ovenmitt bridge: sender shape refused: %s", e)
            return _refused("SEND_FAILED", "this chat's sender is not supported")


def register(ctx: Any) -> None:
    """Hermes plugin entry point."""
    global _POPPED_CREDENTIAL
    credential = os.environ.pop(CREDENTIAL_ENV, None) or _POPPED_CREDENTIAL
    _POPPED_CREDENTIAL = credential
    socket_path = os.environ.get(SOCKET_ENV) or DEFAULT_SOCKET
    b = _Bridge(socket_path, credential)
    handlers = {
        "ovenmitt_vault_put": b.put,
        "ovenmitt_vault_list": b.list,
        "ovenmitt_vault_stat": b.stat,
        "ovenmitt_vault_label": b.label,
        "ovenmitt_vault_delete": b.delete,
        "ovenmitt_vault_list_destinations": b.list_destinations,
        "ovenmitt_vault_send": b.send,
    }
    for name in TOOL_NAMES:
        ctx.register_tool(
            name=name,
            toolset=TOOLSET,
            schema=SCHEMAS[name],
            handler=handlers[name],
            description=SCHEMAS[name]["description"],
            emoji="🧤",
        )
    logger.info(
        "ovenmitt bridge %s: %d tools, socket %s, sending %s",
        __version__,
        len(TOOL_NAMES),
        socket_path,
        "configured" if credential else "not configured",
    )
