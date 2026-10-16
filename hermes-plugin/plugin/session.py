"""Glue to the running gateway: who is this turn talking to, and how do we
reach that chat's live sender.

The target comes from the session the gateway bound for this turn, never
from anything the model passed in. Imports are lazy so the module loads
(and its callers can be tested) outside a gateway.
"""

from __future__ import annotations

import asyncio
import functools
from collections.abc import Coroutine
from typing import Any

SEND_TIMEOUT_S = 180.0


class NoSession(Exception):
    """This tool call isn't bound to a chat with a live sender."""


def _runner() -> Any:
    from gateway.run import _gateway_runner_ref  # type: ignore[import-not-found]

    runner = _gateway_runner_ref() if _gateway_runner_ref else None
    if runner is None:
        raise NoSession("no running gateway in this process")
    return runner


def current_sender() -> tuple[functools.partial, Any]:
    """`(partial(adapter.send_document, chat_id[, metadata]), gateway loop)`
    for the chat this turn belongs to."""
    from gateway.config import Platform  # type: ignore[import-not-found]
    from gateway.session_context import get_session_env  # type: ignore[import-not-found]

    platform_name = get_session_env("HERMES_SESSION_PLATFORM", "")
    chat_id = get_session_env("HERMES_SESSION_CHAT_ID", "")
    if not platform_name or not chat_id:
        raise NoSession("this turn is not bound to a chat")
    try:
        platform = Platform(platform_name)
    except ValueError as e:
        raise NoSession(f"unknown platform for this turn: {platform_name}") from e

    runner = _runner()
    profile = get_session_env("HERMES_SESSION_PROFILE", "") or None
    lookup = getattr(runner, "_authorization_adapter", None)
    adapter = lookup(platform, profile) if lookup else runner.adapters.get(platform)
    if adapter is None:
        raise NoSession(f"no live {platform_name} adapter in this gateway")

    thread_id = get_session_env("HERMES_SESSION_THREAD_ID", "")
    if thread_id:
        send = functools.partial(adapter.send_document, chat_id, metadata={"thread_id": thread_id})
    else:
        send = functools.partial(adapter.send_document, chat_id)
    return send, getattr(runner, "_gateway_loop", None)


def runner_on(loop: Any):
    """A `run(coro)` that executes the coroutine on the adapter's own loop.

    Tool handlers run in a worker thread; platform clients are bound to the
    gateway loop, so the send is scheduled there and this thread waits.
    """

    def run(coro: Coroutine[Any, Any, Any]) -> Any:
        try:
            current = asyncio.get_running_loop()
        except RuntimeError:
            current = None
        if loop is not None and loop.is_running():
            if current is loop:
                coro.close()
                raise RuntimeError("cannot wait for a send on the gateway loop itself")
            return asyncio.run_coroutine_threadsafe(coro, loop).result(timeout=SEND_TIMEOUT_S)
        if current is None:
            return asyncio.run(coro)
        coro.close()
        raise RuntimeError("no gateway loop to send on")

    return run
