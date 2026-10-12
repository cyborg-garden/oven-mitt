"""ovenmitt — handle the hot thing without touching it.

Client library and MCP server for the ovenmitt write-only vault daemon.
"""

from .client import DEFAULT_SOCKET, Resolved, VaultClient
from .errors import OvenmittError, ProtocolError
from .types import DestinationInfo, ExportResult, ObjectInfo, VaultInfo

__version__ = "0.1.0"

__all__ = [
    "DEFAULT_SOCKET",
    "DestinationInfo",
    "ExportResult",
    "ObjectInfo",
    "OvenmittError",
    "ProtocolError",
    "Resolved",
    "VaultClient",
    "VaultInfo",
]
