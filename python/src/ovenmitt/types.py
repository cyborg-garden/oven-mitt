"""Records the daemon returns (PRD §4.3)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class VaultInfo:
    name: str
    expose_names: bool
    ttl: str | None = None

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> VaultInfo:
        return cls(name=d["name"], expose_names=bool(d["expose_names"]), ttl=d.get("ttl"))


@dataclass(frozen=True)
class DestinationInfo:
    name: str
    kind: str

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> DestinationInfo:
        return cls(name=d["name"], kind=d["kind"])


@dataclass(frozen=True)
class ObjectInfo:
    """What the agent may know about an object. Never its content."""

    handle: str
    vault: str
    size: int
    mime: str
    created: str
    modified: str
    labels: tuple[str, ...] = field(default_factory=tuple)
    expires_at: str | None = None
    name: str | None = None

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> ObjectInfo:
        return cls(
            handle=d["handle"],
            vault=d["vault"],
            size=int(d["size"]),
            mime=d["mime"],
            created=d["created"],
            modified=d["modified"],
            labels=tuple(d.get("labels") or ()),
            expires_at=d.get("expires_at"),
            name=d.get("name"),
        )

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "handle": self.handle,
            "vault": self.vault,
            "size": self.size,
            "mime": self.mime,
            "created": self.created,
            "modified": self.modified,
            "labels": list(self.labels),
            "name": self.name,
        }
        if self.expires_at is not None:
            d["expires_at"] = self.expires_at
        return d


@dataclass(frozen=True)
class ExportResult:
    destination: str
    filename: str
    size: int

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> ExportResult:
        return cls(destination=d["destination"], filename=d["filename"], size=int(d["size"]))
