"""`ovenmitt mcp [--socket PATH]` — the MCP server over stdio.

This console script lives in the agent container; the daemon's `ovenmitt`
binary lives in the daemon container. They never share an image.
"""

from __future__ import annotations

import argparse
import sys

from .client import DEFAULT_SOCKET


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ovenmitt", description="ovenmitt agent-side tools")
    sub = parser.add_subparsers(dest="command", required=True)
    mcp_p = sub.add_parser("mcp", help="serve the MCP tools over stdio")
    mcp_p.add_argument("--socket", default=DEFAULT_SOCKET, help="daemon socket path")
    args = parser.parse_args(argv)
    if args.command == "mcp":
        from .mcp import main as mcp_main

        mcp_main(args.socket)
        return 0
    parser.print_usage(sys.stderr)
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
