"""Errors raised by the ovenmitt client.

The code is the wire code, unchanged (PRD §7). Messages are the daemon's
fixed strings; they never carry roots, patterns, paths or secrets.
"""

from __future__ import annotations


class OvenmittError(Exception):
    """A refusal or failure reported by the daemon."""

    def __init__(self, code: str, message: str, status: int) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.status = status


class ProtocolError(OvenmittError):
    """The daemon answered with something that isn't the ovenmitt protocol."""

    def __init__(self, message: str, status: int = 0) -> None:
        super().__init__("PROTOCOL", message, status)
