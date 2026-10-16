"""Fixtures for the bridge tests.

The plugin directory is imported the way the harness imports it: as a
package from its own directory. A real daemon serves a vault whose one
send destination is named after a fake platform.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import time
import types
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
PLUGIN_DIR = HERE.parent / "plugin"
ROOT = HERE.parents[1]
PLATFORM = "fakechat"


def load_plugin(name: str = "ovenmitt_bridge") -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(
        name, PLUGIN_DIR / "__init__.py", submodule_search_locations=[str(PLUGIN_DIR)]
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def plugin() -> types.ModuleType:
    return load_plugin()


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
        self.bin = _binary()
        self.sock_dir = Path(tempfile.mkdtemp(prefix="ovm-", dir="/tmp"))
        self.socket = self.sock_dir / "s.sock"
        self.audit_log = tmp / "audit" / "audit.jsonl"
        self.config = tmp / "ovenmitt.toml"
        self.config.write_text(
            f"""
[daemon]
socket = "{self.socket}"
data_dir = "{tmp / 'data'}"
keys_dir = "{tmp / 'keys'}"
audit_log = "{self.audit_log}"
credentials = "{tmp / 'credentials.toml'}"

[vault.private]
expose_names = false
ttl = "30d"

[vault.private.destinations.{PLATFORM}]
kind = "send"
match = "{PLATFORM}/*"
"""
        )
        self.proc = subprocess.Popen(
            [str(self.bin), "--config", str(self.config), "daemon"], stderr=subprocess.PIPE
        )
        for _ in range(200):
            if self.socket.exists():
                return
            if self.proc.poll() is not None:
                err = self.proc.stderr.read().decode() if self.proc.stderr else ""
                raise RuntimeError(f"daemon exited with {self.proc.returncode}:\n{err}")
            time.sleep(0.02)
        self.proc.kill()
        raise RuntimeError("daemon did not start within 4s")

    def issue_credential(self) -> str:
        out = subprocess.run(
            [str(self.bin), "--config", str(self.config), "credential", "issue",
             "--name", "bridge", "--vault", "private"],
            capture_output=True, text=True, check=True,
        )
        return out.stdout.strip()

    def audit_text(self) -> str:
        return self.audit_log.read_text()

    def stop(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        shutil.rmtree(self.sock_dir, ignore_errors=True)


@pytest.fixture
def daemon(tmp_path: Path):
    d = Daemon(tmp_path)
    try:
        yield d
    finally:
        d.stop()
