#!/bin/sh
# Run the bridge tests inside a Hermes agent image, so the harness contract
# test (test_harness_contract.py) runs against the real session context,
# platform enum and platform adapter.
#
#   hermes-plugin/tests/run-in-agent-image.sh [agent-image] [daemon-image]
#
# The throwaway container gets the ovenmitt client (from this checkout) and
# pytest installed at start, and the daemon binary on a read-only mount from
# the daemon image. The agent image itself is never modified.
set -eu

AGENT_IMAGE="${1:-hermes-agent-mt:arm64-local}"
DAEMON_IMAGE="${2:-ovenmitt:latest}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"

BIN_DIR="$(mktemp -d)"
trap 'rm -rf "$BIN_DIR"' EXIT
CID="$(docker create "$DAEMON_IMAGE")"
docker cp "$CID:/usr/local/bin/ovenmitt" "$BIN_DIR/ovenmitt" >/dev/null
docker rm "$CID" >/dev/null

docker run --rm --entrypoint "" \
  -v "$REPO:/src:ro" \
  -v "$BIN_DIR:/daemon:ro" \
  -e OVENMITT_BIN=/daemon/ovenmitt \
  -e PYTHONDONTWRITEBYTECODE=1 \
  -w /src/hermes-plugin \
  "$AGENT_IMAGE" \
  sh -c 'mkdir /tmp/ovenmitt-python && cp -r /src/python/pyproject.toml /src/python/README.md /src/python/src /tmp/ovenmitt-python/ && uv pip install --quiet --python /opt/hermes/.venv/bin/python /tmp/ovenmitt-python pytest && /opt/hermes/.venv/bin/python -m pytest tests -q -p no:cacheprovider'
