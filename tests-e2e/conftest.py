"""End-to-end suite: drives `docker compose` from the host (DEVELOPMENT.md §10).

Run from the repo root on a machine with Docker:

    uv run --project python pytest tests-e2e -q

Writes a generated config with sentinel markers into docker/test/generated/,
brings the stack up with the test overlay, and tears it down (volumes too).
"""

from __future__ import annotations

import json
import secrets
import shutil
import subprocess
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = [
    "docker",
    "compose",
    "-f",
    str(ROOT / "docker/docker-compose.yml"),
    "-f",
    str(ROOT / "docker/docker-compose.test.yml"),
]


def _run(args: list[str], check: bool = True, input_: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(args, capture_output=True, check=check, input=input_)


class Stack:
    def __init__(self) -> None:
        self.root_marker = f"rootmark{secrets.token_hex(8)}"
        self.pattern_marker = f"patmark{secrets.token_hex(8)}"
        gen = ROOT / "docker/test/generated"
        gen.mkdir(parents=True, exist_ok=True)
        (gen / "ovenmitt.toml").write_text(
            f"""
[daemon]
credentials = "/var/lib/ovenmitt/data/credentials.toml"
ttl_sweep_interval = "1m"

[vault.private]
expose_names = true

[vault.private.destinations.archive]
kind = "fs"
root = "/var/lib/ovenmitt/export/archive"

[vault.private.destinations.sentinel]
kind = "fs"
root = "/var/lib/ovenmitt/export/{self.root_marker}"

[vault.private.destinations.team-chat]
kind = "send"
match = "chat:group/{self.pattern_marker}"

[vault.private.destinations.any-dm]
kind = "send"
match = "chat:dm/*"

[vault.hidden]
expose_names = false
"""
        )

    def up(self) -> None:
        # fs roots must exist at startup (R-DEP-6). The image creates
        # export/archive; the sentinel-named root is created in the export
        # volume before the daemon starts.
        _run(COMPOSE + ["build"])
        _run(
            COMPOSE
            + [
                "run", "--rm", "--no-deps", "--entrypoint", "sh", "ovenmittd", "-c",
                f"mkdir -p /var/lib/ovenmitt/export/{self.root_marker}",
            ]
        )
        _run(COMPOSE + ["up", "-d"])
        for _ in range(100):
            r = _run(COMPOSE + ["exec", "-T", "test-agent", "test", "-S", "/run/ovenmitt/ovenmitt.sock"], check=False)
            if r.returncode == 0:
                return
            time.sleep(0.2)
        logs = _run(COMPOSE + ["logs", "ovenmittd"], check=False)
        raise RuntimeError(f"daemon socket never appeared:\n{logs.stdout.decode()}{logs.stderr.decode()}")

    def down(self) -> None:
        _run(COMPOSE + ["down", "-v", "--remove-orphans"], check=False)
        shutil.rmtree(ROOT / "docker/test/generated", ignore_errors=True)

    # -- helpers -----------------------------------------------------------

    def agent(self, *cmd: str, check: bool = True, input_: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
        return _run(COMPOSE + ["exec", "-T", "test-agent", *cmd], check=check, input_=input_)

    def daemon(self, *cmd: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
        return _run(COMPOSE + ["exec", "-T", "ovenmittd", *cmd], check=check)

    def agent_py(self, code: str) -> str:
        """Run Python inside the test agent with the client library."""
        r = self.agent("python", "-c", code)
        return r.stdout.decode()

    def config_json(self) -> dict:
        r = _run(COMPOSE + ["config", "--format", "json"])
        return json.loads(r.stdout)


@pytest.fixture(scope="session")
def stack():
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    s = Stack()
    s.up()
    try:
        yield s
    finally:
        s.down()
