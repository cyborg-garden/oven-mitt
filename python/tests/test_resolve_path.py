"""`resolve_path`: one-shot, memory-backed files for filename-only tools.

`memfd_create` is Linux-only, so these skip on macOS; run them in a
container there (`docker/Dockerfile.pytest`).
"""

from __future__ import annotations

import json
import mimetypes
import os
import secrets
import tempfile

import pytest

from ovenmitt import OvenmittError, VaultClient

pytestmark = pytest.mark.skipif(
    not hasattr(os, "memfd_create"), reason="memfd_create is Linux-only"
)


def sentinel() -> bytes:
    return "".join(chr(ord("a") + b % 26) for b in secrets.token_bytes(64)).encode()


def ovenmitt_tmpdirs() -> set[str]:
    tmp = tempfile.gettempdir()
    return {d for d in os.listdir(tmp) if d.startswith("ovenmitt-")}


def resolves(daemon) -> list[dict]:
    entries = [json.loads(line) for line in daemon.audit_lines()]
    return [e for e in entries if e.get("event") == "resolve"]


def setup(daemon, body: bytes) -> tuple[VaultClient, str, str, str]:
    c = VaultClient(str(daemon.socket))
    handle = c.put(body, "private", mime="text/plain").handle
    cred = daemon.issue_credential("private")
    target = f"chat:group/{daemon.pattern_marker}"
    return c, handle, cred, target


def test_round_trip_under_the_given_name(daemon):
    body = sentinel()
    c, handle, cred, target = setup(daemon, body)
    with c.resolve_path(handle, "team-chat", target, cred, "transcript-1.txt") as path:
        assert os.path.basename(path) == "transcript-1.txt"
        assert mimetypes.guess_type(path)[0] == "text/plain"
        assert os.path.getsize(path) == len(body)
        with open(path, "rb") as f:
            assert f.read() == body
        # Readable twice: each open is a fresh description at offset 0.
        with open(path, "rb") as f:
            assert f.read() == body
        assert os.readlink(path).startswith("/proc/self/fd/")
        assert oct(os.stat(os.path.dirname(path)).st_mode & 0o777) == "0o700"
    c.close()


def test_one_shot_everything_gone_after_the_block(daemon):
    c, handle, cred, target = setup(daemon, sentinel())
    before = ovenmitt_tmpdirs()
    with c.resolve_path(handle, "team-chat", target, cred, "a.txt") as path:
        fd = int(os.readlink(path).rsplit("/", 1)[1])
        assert os.readlink(f"/proc/self/fd/{fd}").startswith("/memfd:")
    assert not os.path.lexists(path)
    assert not os.path.exists(os.path.dirname(path))
    assert ovenmitt_tmpdirs() == before
    # The memfd itself is closed (the number may be reused, but not by a memfd of ours).
    try:
        assert not os.readlink(f"/proc/self/fd/{fd}").startswith("/memfd:ovenmitt")
    except FileNotFoundError:
        pass
    c.close()


def test_cleanup_on_exception(daemon):
    c, handle, cred, target = setup(daemon, sentinel())
    before = ovenmitt_tmpdirs()
    with pytest.raises(RuntimeError):
        with c.resolve_path(handle, "team-chat", target, cred, "a.txt") as path:
            raise RuntimeError("send failed")
    assert not os.path.lexists(path)
    assert ovenmitt_tmpdirs() == before
    c.close()


def test_refused_resolve_leaves_nothing(daemon):
    c, handle, cred, _ = setup(daemon, sentinel())
    before = ovenmitt_tmpdirs()
    with pytest.raises(OvenmittError) as ei:
        with c.resolve_path(handle, "team-chat", "chat:group/elsewhere", cred, "a.txt"):
            pytest.fail("a refused resolve must not yield a path")
    assert ei.value.code == "TARGET_NOT_ALLOWED"
    assert ovenmitt_tmpdirs() == before
    c.close()


@pytest.mark.parametrize(
    "name", ["", ".hidden", "..", "a/b.txt", "/etc/x", "a\x00b", "a\nb.txt", "x" * 256]
)
def test_bad_filenames_refused_before_any_resolve(daemon, name):
    c, handle, cred, target = setup(daemon, sentinel())
    with pytest.raises(ValueError):
        with c.resolve_path(handle, "team-chat", target, cred, name):
            pytest.fail("unreachable")
    assert resolves(daemon) == [], "argument errors must cost no resolve"
    c.close()


def test_audited_like_resolve_with_the_declared_target(daemon):
    c, handle, cred, target = setup(daemon, sentinel())
    with c.resolve_path(handle, "team-chat", target, cred, "a.txt"):
        pass
    [entry] = resolves(daemon)
    assert entry["outcome"] == "ok"
    assert entry["dest"] == "team-chat"
    assert entry["target"] == target
    c.close()


def test_no_plaintext_on_disk(daemon):
    body = sentinel()
    c, handle, cred, target = setup(daemon, body)
    roots = {tempfile.gettempdir(), "/var/tmp", os.getcwd()}

    def files_containing_body() -> list[str]:
        hits = []
        for root in roots:
            for dirpath, _dirs, files in os.walk(root):
                for fname in files:
                    p = os.path.join(dirpath, fname)
                    if os.path.islink(p) or not os.path.isfile(p):
                        continue
                    try:
                        with open(p, "rb") as f:
                            if body in f.read():
                                hits.append(p)
                    except OSError:
                        continue
        return hits

    with c.resolve_path(handle, "team-chat", target, cred, "a.txt") as path:
        with open(path, "rb") as f:
            assert f.read() == body
        assert files_containing_body() == []
    c.close()
