"""The base package is the client only; the MCP SDK is the `mcp` extra.

Agent images pin their own MCP version, so `import ovenmitt` must work
without `mcp` installed and must never import it.
"""

from __future__ import annotations

import subprocess
import sys


def run(code: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=False)


def test_client_import_does_not_load_mcp():
    r = run("import sys, ovenmitt; assert not any(m == 'mcp' or m.startswith('mcp.') for m in sys.modules)")
    assert r.returncode == 0, r.stderr


def test_client_works_without_mcp_and_cli_says_how_to_get_it():
    # A None entry in sys.modules makes any `import mcp…` fail, as if absent.
    r = run(
        "import sys; sys.modules['mcp'] = None\n"
        "from ovenmitt import VaultClient, OvenmittError\n"
        "from ovenmitt import cli\n"
        "raise SystemExit(cli.main(['mcp']))\n"
    )
    assert r.returncode == 1, r.stderr
    assert "ovenmitt[mcp]" in r.stderr
