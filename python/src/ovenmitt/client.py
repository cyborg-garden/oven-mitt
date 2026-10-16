"""The ovenmitt client library (PRD §10.2).

Thin: one method per endpoint over HTTP/1.1 on the daemon's Unix socket.
Nothing here is load-bearing for security — the daemon's socket protocol
is the boundary — but this is the only place that yields plaintext, and
only through ``resolve`` with a consumer credential.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
import unicodedata
from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager
from typing import IO, Any, BinaryIO
from urllib.parse import quote

import httpx

from .errors import OvenmittError, ProtocolError
from .types import DestinationInfo, ExportResult, ObjectInfo, VaultInfo

DEFAULT_SOCKET = "/run/ovenmitt/ovenmitt.sock"
PROTOCOL = "1"
_CHUNK = 1 << 20


def _encode_header(value: str) -> str:
    """Names and labels travel percent-encoded (header values are ASCII)."""
    return quote(value, safe="")


def _iter_file(f: IO[bytes]) -> Iterator[bytes]:
    while True:
        chunk = f.read(_CHUNK)
        if not chunk:
            return
        yield chunk


def _check_filename(name: str) -> str:
    """The name a ``resolve_path`` file is presented under.

    One path segment the receiving tool can derive a name and MIME type
    from: no separator, no control characters, no leading dot (no hidden
    files, no ``..``), at most 255 bytes like any filename.
    """
    if (
        not name
        or name.startswith(".")
        or "/" in name
        or any(unicodedata.category(c).startswith("C") for c in name)
        or len(name.encode()) > 255
    ):
        raise ValueError(f"unusable filename for resolve_path: {name!r}")
    return name


class Resolved:
    """A resolved object: a stream of plaintext bytes plus its metadata.

    Use as a context manager, or exhaust ``stream``; either closes the
    connection. The target string is never echoed by the daemon.
    """

    def __init__(self, response: httpx.Response, stream_ctx: Any) -> None:
        self._response = response
        self._ctx = stream_ctx
        self.mime: str = response.headers.get("content-type", "application/octet-stream")
        self.size: int = int(response.headers.get("content-length", "0"))
        self.destination: str = response.headers.get("x-ovenmitt-destination", "")

    @property
    def stream(self) -> Iterator[bytes]:
        try:
            yield from self._response.iter_bytes()
        finally:
            self.close()

    def read(self) -> bytes:
        """Everything at once. For small objects; prefer ``stream``."""
        return b"".join(self.stream)

    def close(self) -> None:
        try:
            self._ctx.__exit__(None, None, None)
        except Exception:  # noqa: BLE001 - closing twice is fine
            pass

    def __enter__(self) -> Resolved:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class VaultClient:
    """Client for one daemon socket."""

    def __init__(self, socket_path: str = DEFAULT_SOCKET, timeout: float | None = 300.0) -> None:
        self.socket_path = socket_path
        self._client = httpx.Client(
            transport=httpx.HTTPTransport(uds=socket_path),
            base_url="http://ovenmitt",
            headers={"x-ovenmitt-protocol": PROTOCOL},
            timeout=timeout,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> VaultClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- plumbing ---------------------------------------------------------

    @staticmethod
    def _raise(response: httpx.Response) -> None:
        if 200 <= response.status_code < 300:
            return
        try:
            body = response.json()
            err = body["error"]
            raise OvenmittError(str(err["code"]), str(err["message"]), response.status_code)
        except (ValueError, KeyError, TypeError) as e:
            raise ProtocolError(
                f"unexpected response {response.status_code}", response.status_code
            ) from e

    def _json(self, response: httpx.Response) -> Any:
        self._raise(response)
        try:
            return response.json()
        except ValueError as e:
            raise ProtocolError("response is not JSON", response.status_code) from e

    # -- reads ------------------------------------------------------------

    def health(self) -> dict[str, Any]:
        r = self._client.get("/v1/health")
        return dict(self._json(r))

    def vaults(self) -> list[VaultInfo]:
        return [VaultInfo.from_json(v) for v in self._json(self._client.get("/v1/vaults"))]

    def destinations(self, vault: str) -> list[DestinationInfo]:
        r = self._client.get(f"/v1/vaults/{vault}/destinations")
        return [DestinationInfo.from_json(d) for d in self._json(r)]

    def stat(self, handle: str) -> ObjectInfo:
        return ObjectInfo.from_json(self._json(self._client.get(f"/v1/objects/{handle}")))

    def list(self, vault: str | None = None) -> list[ObjectInfo]:
        params = {"vault": vault} if vault else None
        r = self._client.get("/v1/objects", params=params)
        return [ObjectInfo.from_json(o) for o in self._json(r)]

    # -- writes -----------------------------------------------------------

    def _put_headers(
        self,
        *,
        name: str | None,
        mime: str | None,
        labels: Sequence[str] | None,
        sha256: str | None,
        remove_source_requested: bool,
    ) -> list[tuple[str, str]]:
        headers: list[tuple[str, str]] = [("content-type", mime or "application/octet-stream")]
        if name is not None:
            headers.append(("x-ovenmitt-name", _encode_header(name)))
        for label in labels or ():
            headers.append(("x-ovenmitt-label", _encode_header(label)))
        if sha256 is not None:
            headers.append(("x-ovenmitt-sha256", sha256))
        if remove_source_requested:
            headers.append(("x-ovenmitt-remove-source-requested", "true"))
        return headers

    @staticmethod
    def _as_stream(data: bytes | BinaryIO | Iterable[bytes]) -> bytes | Iterator[bytes]:
        if isinstance(data, (bytes, bytearray)):
            return bytes(data)
        if hasattr(data, "read"):
            return _iter_file(data)  # type: ignore[arg-type]
        return iter(data)  # type: ignore[arg-type]

    def put(
        self,
        data: bytes | BinaryIO | Iterable[bytes],
        vault: str,
        *,
        name: str | None = None,
        mime: str | None = None,
        labels: Sequence[str] = (),
        replace: str | None = None,
        sha256: str | None = None,
    ) -> ObjectInfo:
        """Stream ``data`` into ``vault`` (or over ``replace``'s handle).

        Nothing is buffered: a file object or iterator is sent as it is
        read. Returns metadata only.
        """
        headers = self._put_headers(
            name=name,
            mime=mime,
            labels=labels if (labels or replace is None) else None,
            sha256=sha256,
            remove_source_requested=False,
        )
        content = self._as_stream(data)
        if replace is None:
            r = self._client.post(f"/v1/vaults/{vault}/objects", content=content, headers=headers)
        else:
            r = self._client.put(f"/v1/objects/{replace}", content=content, headers=headers)
        return ObjectInfo.from_json(self._json(r))

    def put_path(
        self,
        path: str | os.PathLike[str],
        vault: str,
        *,
        remove_source: bool = False,
        name: str | None = None,
        mime: str | None = None,
        labels: Sequence[str] = (),
        replace: str | None = None,
        verify: bool = True,
    ) -> ObjectInfo:
        """Put a file by path. With ``remove_source`` the file is unlinked
        only after the daemon has answered 201/200.

        With ``verify`` (default) the file is hashed first and the daemon
        checks the hash (R-OBJ-10); files over 64 MiB skip the extra pass.
        """
        p = os.fspath(path)
        digest: str | None = None
        if verify and os.path.getsize(p) <= 64 * 1024 * 1024:
            h = hashlib.sha256()
            with open(p, "rb") as f:
                for chunk in _iter_file(f):
                    h.update(chunk)
            digest = h.hexdigest()
        if name is None:
            name = os.path.basename(p)
        headers = self._put_headers(
            name=name,
            mime=mime,
            labels=labels if (labels or replace is None) else None,
            sha256=digest,
            remove_source_requested=remove_source,
        )
        with open(p, "rb") as f:
            if replace is None:
                r = self._client.post(
                    f"/v1/vaults/{vault}/objects", content=_iter_file(f), headers=headers
                )
            else:
                r = self._client.put(f"/v1/objects/{replace}", content=_iter_file(f), headers=headers)
        info = ObjectInfo.from_json(self._json(r))
        if remove_source:
            os.unlink(p)
        return info

    def label(self, handle: str, labels: Sequence[str]) -> ObjectInfo:
        r = self._client.patch(f"/v1/objects/{handle}", json={"labels": list(labels)})
        return ObjectInfo.from_json(self._json(r))

    def delete(self, handle: str) -> None:
        self._raise(self._client.delete(f"/v1/objects/{handle}"))

    def export(self, handle: str, destination: str, filename: str) -> ExportResult:
        r = self._client.post(
            f"/v1/objects/{handle}/export",
            json={"destination": destination, "filename": filename},
        )
        return ExportResult.from_json(self._json(r))

    # -- the one read path ------------------------------------------------

    def resolve(self, handle: str, destination: str, target: str, credential: str) -> Resolved:
        """Stream an object's plaintext to consumer tool code.

        Requires a consumer credential; the daemon checks that
        ``destination`` is declared on the object's vault, that ``target``
        matches its pattern, and audits both. The bytes pass through this
        process only; keep the credential out of anything the agent's
        terminal can read.
        """
        ctx = self._client.stream(
            "POST",
            f"/v1/objects/{handle}/resolve",
            json={"destination": destination, "target": target},
            headers={"authorization": f"Bearer {credential}"},
        )
        response = ctx.__enter__()
        if not 200 <= response.status_code < 300:
            try:
                response.read()
                self._raise(response)
            finally:
                ctx.__exit__(None, None, None)
        return Resolved(response, ctx)

    @contextmanager
    def resolve_path(
        self, handle: str, destination: str, target: str, credential: str, filename: str
    ) -> Iterator[str]:
        """``resolve`` for tools that only take a filename.

        The plaintext goes into a ``memfd`` (anonymous, RAM-backed, on no
        filesystem), and the yielded path is a symlink named ``filename``
        in a private temp dir pointing at ``/proc/self/fd/<n>``, so the
        tool sees a real name and extension. The path is one-shot: it is
        valid only inside the ``with`` block (one send call), and on exit
        the descriptor is closed and the dir removed, exception or not.

        ``/proc/self`` means only this process can follow the link, and
        the descriptor is close-on-exec, so hand the path to in-process
        code, not a subprocess. The whole object sits in memory while the
        block runs. Linux only, because ``memfd_create`` is.
        """
        name = _check_filename(filename)
        memfd_create = getattr(os, "memfd_create", None)
        if memfd_create is None:
            raise NotImplementedError("resolve_path needs os.memfd_create (Linux only)")
        # Arguments are checked before resolving, so a bad call costs no
        # resolve and leaves no audit entry behind.
        fd = memfd_create("ovenmitt", os.MFD_CLOEXEC)
        tmpdir: str | None = None
        try:
            with self.resolve(handle, destination, target, credential) as r:
                with os.fdopen(fd, "wb", closefd=False) as f:
                    for chunk in r.stream:
                        f.write(chunk)
            tmpdir = tempfile.mkdtemp(prefix="ovenmitt-")  # mode 0700
            path = os.path.join(tmpdir, name)
            os.symlink(f"/proc/self/fd/{fd}", path)
            yield path
        finally:
            os.close(fd)
            if tmpdir is not None:
                shutil.rmtree(tmpdir, ignore_errors=True)
