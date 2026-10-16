"""The send half of the bridge: resolve a handle and hand it to the harness's
own sender, for the current chat only.

Nothing here names a platform. The platform comes from the sender at run
time, and the operator names destinations after it.
"""

from __future__ import annotations

import functools
import mimetypes
import re
import unicodedata
from collections.abc import Callable, Coroutine
from typing import Any
from urllib.parse import quote

from ovenmitt import ObjectInfo, VaultClient

# The only keyword a sender partial may carry: routing inside the same chat
# (a thread or topic), never a different chat.
_ALLOWED_METADATA = frozenset({"thread_id"})
_PLATFORM = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


class ShapeRefused(Exception):
    """The sender is not the one shape the bridge accepts."""


class SendFailed(Exception):
    """The platform sender ran but reported failure."""


def target_for(platform: str, chat_id: str) -> str:
    """`<platform>/<chat ref>`: one destination pattern `<platform>/*` covers
    every chat on the platform. Chat ids may contain `/` (and anything else),
    so the ref is percent-encoded into the one segment the `/*` matches."""
    return f"{platform}/{quote(chat_id, safe='')}"


def claim_from(send: Any) -> tuple[str, str]:
    """Derive (destination, target) from the very callable that will send.

    Accepts exactly `functools.partial(<adapter>.send_document, chat_id)`,
    optionally with `metadata={"thread_id": ...}`. Anything else is refused:
    a claim the bridge can't read off the sender is a claim it can't check.
    """
    if not isinstance(send, functools.partial):
        raise ShapeRefused("sender must be functools.partial(adapter.send_document, chat_id)")
    func = send.func
    adapter = getattr(func, "__self__", None)
    if adapter is None or getattr(func, "__name__", None) != "send_document":
        raise ShapeRefused("sender must be a bound send_document method")
    if len(send.args) != 1 or not isinstance(send.args[0], str) or not send.args[0]:
        raise ShapeRefused("sender must bind exactly one argument, the chat id")
    extra = set(send.keywords) - {"metadata"}
    if extra:
        raise ShapeRefused(f"sender binds unexpected keywords: {sorted(extra)}")
    metadata = send.keywords.get("metadata")
    if metadata is not None and (
        not isinstance(metadata, dict) or set(metadata) - _ALLOWED_METADATA
    ):
        raise ShapeRefused("sender metadata may only carry thread_id")
    platform = getattr(adapter, "platform", None)
    value = getattr(platform, "value", platform)
    if not isinstance(value, str) or not _PLATFORM.match(value):
        raise ShapeRefused("sender's adapter has no usable platform name")
    return value, target_for(value, send.args[0])


def _extension(mime: str) -> str:
    base = mime.split(";", 1)[0].strip().lower()
    if base == "text/plain":
        return ".txt"  # mimetypes may say .bat/.ksh depending on the host
    return mimetypes.guess_extension(base) or ".bin"


def filename_for(handle: str, info: ObjectInfo, requested: str | None) -> str:
    """The attachment name. A suggestion is kept to one safe path segment;
    without one, `<handle><ext>` from the object's MIME type."""
    if requested:
        name = unicodedata.normalize("NFC", requested).strip()
        name = "".join(
            "_" if c in "/\\" or unicodedata.category(c).startswith("C") else c for c in name
        ).lstrip(".")
        name = name.encode()[:200].decode(errors="ignore")
        if name:
            if "." not in name:
                name += _extension(info.mime)
            return name
    return handle + _extension(info.mime)


def vault_send(
    client: VaultClient,
    credential: str,
    handle: str,
    send: Any,
    *,
    filename: str | None,
    caption: str | None,
    run: Callable[[Coroutine[Any, Any, Any]], Any],
) -> dict[str, Any]:
    """Resolve `handle` into a one-shot path and give it to `send`, once.

    `run` executes the sender's coroutine to completion (on the platform
    adapter's own event loop, in the gateway). The path is valid only for
    that one call; after it, the bytes are gone from this process.
    """
    destination, target = claim_from(send)
    info = client.stat(handle)
    name = filename_for(handle, info, filename)
    with client.resolve_path(handle, destination, target, credential, name) as path:
        result = run(send(path, caption=caption))
    if not getattr(result, "success", False):
        raise SendFailed(str(getattr(result, "error", None) or "the platform did not accept the file"))
    return {"sent": True, "handle": handle, "bytes": info.size, "filename": name}
