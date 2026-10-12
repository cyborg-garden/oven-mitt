"""Client parity with the wire (M7)."""

from __future__ import annotations

import hashlib
import secrets

import pytest

from ovenmitt import OvenmittError, VaultClient


def sentinel() -> bytes:
    return "".join(chr(ord("a") + b % 26) for b in secrets.token_bytes(64)).encode()


def test_put_stat_list_label_export_delete(daemon):
    body = sentinel()
    with VaultClient(str(daemon.socket)) as c:
        assert c.health()["status"] == "ok"
        vaults = c.vaults()
        assert [v.name for v in vaults] == ["hidden", "private"]
        dests = c.destinations("private")
        assert {d.name: d.kind for d in dests} == {"archive": "fs", "team-chat": "send"}

        info = c.put(body, "private", name="hui-nōtes.txt", mime="text/plain", labels=["a", "wāhi"])
        assert info.handle.startswith("v_") and len(info.handle) == 14
        assert info.size == 64
        assert info.mime == "text/plain"
        assert info.labels == ("a", "wāhi")
        assert info.name == "hui-nōtes.txt"  # percent-encoded on the wire, round-trips
        assert info.expires_at is None

        assert c.stat(info.handle) == info
        assert [o.handle for o in c.list("private")] == [info.handle]
        assert c.list("hidden") == []
        with pytest.raises(OvenmittError) as ei:
            c.list("nope")
        assert ei.value.code == "VAULT_NOT_FOUND"
        assert ei.value.status == 404

        info2 = c.label(info.handle, ["x"])
        assert info2.labels == ("x",)

        # stream from an iterator and replace
        new = sentinel()
        info3 = c.put(iter([new[:10], new[10:]]), "private", replace=info.handle)
        assert info3.handle == info.handle
        assert info3.labels == ("x",), "labels carry over on replace"
        assert info3.name == "hui-nōtes.txt"

        res = c.export(info.handle, "archive", "out.txt")
        assert (res.destination, res.filename, res.size) == ("archive", "out.txt", 64)
        assert (daemon.export_root / "out.txt").read_bytes() == new
        with pytest.raises(OvenmittError) as ei:
            c.export(info.handle, "archive", "out.txt")
        assert ei.value.code == "EXISTS"
        with pytest.raises(OvenmittError) as ei:
            c.export(info.handle, "archive", "../x")
        assert ei.value.code == "FILENAME_INVALID"

        hidden = c.put(b"x", "hidden", name="secret.txt")
        assert hidden.name is None

        c.delete(info.handle)
        with pytest.raises(OvenmittError) as ei:
            c.stat(info.handle)
        assert ei.value.code == "NOT_FOUND"

    # nothing in the audit log carries content or hidden names
    text = daemon.audit_log.read_text()
    assert body.decode() not in text and new.decode() not in text
    assert "secret.txt" not in text


def test_put_path_hashes_and_removes_source(daemon, tmp_path):
    src = tmp_path / "upload.bin"
    data = secrets.token_bytes(3 * 1024 * 1024 + 7)
    src.write_bytes(data)
    with VaultClient(str(daemon.socket)) as c:
        info = c.put_path(src, "private", remove_source=True)
        assert info.size == len(data)
        assert info.name == "upload.bin"
        assert not src.exists(), "unlinked only after a 2xx"
        # the daemon verified the client hash: the audit entry carries it
        assert hashlib.sha256(data).hexdigest() in daemon.audit_log.read_text()
        assert '"remove_source_requested":true' in daemon.audit_log.read_text()

        # a refused put leaves the source alone
        src.write_bytes(b"keep me")
        with pytest.raises(OvenmittError) as ei:
            c.put_path(src, "nope", remove_source=True)
        assert ei.value.code == "VAULT_NOT_FOUND"
        assert src.exists()


def test_resolve_streams_with_credential_only(daemon):
    body = sentinel()
    with VaultClient(str(daemon.socket)) as c:
        info = c.put(body, "private", mime="text/plain")
        with pytest.raises(OvenmittError) as ei:
            c.resolve(info.handle, "team-chat", "x", "ovm_00000000_x")
        assert ei.value.code == "CREDENTIAL_INVALID"

        token = daemon.issue_credential("private")
        target = f"chat:group/{daemon.pattern_marker}"
        with c.resolve(info.handle, "team-chat", target, token) as r:
            assert r.mime == "text/plain"
            assert r.size == 64
            assert r.destination == "team-chat"
            assert b"".join(r.stream) == body
        with pytest.raises(OvenmittError) as ei:
            c.resolve(info.handle, "team-chat", "chat:group/other", token)
        assert ei.value.code == "TARGET_NOT_ALLOWED"
        with pytest.raises(OvenmittError) as ei:
            c.resolve(info.handle, "archive", target, token)
        assert ei.value.code == "DESTINATION_KIND_MISMATCH"

        # revoke takes effect without restart
        cid = token.split("_")[1]
        assert daemon.cli("credential", "revoke", cid).returncode == 0
        with pytest.raises(OvenmittError) as ei:
            c.resolve(info.handle, "team-chat", target, token)
        assert ei.value.code == "CREDENTIAL_INVALID"
    # the target is audited, the secret is not
    text = daemon.audit_log.read_text()
    assert target in text
    assert token.rsplit("_", 1)[1] not in text
