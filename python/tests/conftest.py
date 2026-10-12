"""Spawn a real daemon for the Python tests.

The binary comes from ``OVENMITT_BIN`` or ``../target/debug/ovenmitt``
(built by ``cargo build`` at the repo root).
"""

from __future__ import annotations

import os
import secrets
import subprocess
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _binary() -> Path:
    env = os.environ.get("OVENMITT_BIN")
    if env:
        return Path(env)
    for p in (ROOT / "target/debug/ovenmitt", ROOT / "target/release/ovenmitt"):
        if p.exists():
            return p
    pytest.skip("ovenmitt binary not built; run `cargo build` at the repo root")


class Daemon:
    def __init__(self, tmp: Path) -> None:
        self.tmp = tmp
        self.socket = tmp / "sock" / "ovenmitt.sock"
        self.export_root = tmp / "export"
        self.export_root.mkdir()
        self.credentials = tmp / "credentials.toml"
        self.audit_log = tmp / "audit" / "audit.jsonl"
        self.pattern_marker = secrets.token_hex(8)
        self.config = tmp / "ovenmitt.toml"
        self.config.write_text(
            f"""
[daemon]
socket = "{self.socket}"
data_dir = "{tmp / 'data'}"
keys_dir = "{tmp / 'keys'}"
audit_log = "{self.audit_log}"
credentials = "{self.credentials}"

[vault.private]
expose_names = true

[vault.private.destinations.archive]
kind = "fs"
root = "{self.export_root}"

[vault.private.destinations.team-chat]
kind = "send"
match = "chat:group/{self.pattern_marker}"

[vault.hidden]
expose_names = false
"""
        )
        self.bin = _binary()
        self.proc = subprocess.Popen(
            [str(self.bin), "--config", str(self.config), "daemon"],
            stderr=subprocess.PIPE,
        )
        for _ in range(200):
            if self.socket.exists():
                break
            time.sleep(0.02)
        else:
            raise RuntimeError("daemon did not start")

    def cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(self.bin), "--config", str(self.config), *args],
            capture_output=True,
            text=True,
            check=False,
        )

    def issue_credential(self, *vaults: str) -> str:
        args = ["credential", "issue", "--name", "test"]
        for v in vaults:
            args += ["--vault", v]
        out = self.cli(*args)
        assert out.returncode == 0, out.stderr
        return out.stdout.strip()

    def audit_lines(self) -> list[str]:
        return self.audit_log.read_text().splitlines()

    def stop(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()


@pytest.fixture
def daemon(tmp_path: Path):
    d = Daemon(tmp_path)
    try:
        yield d
    finally:
        d.stop()
