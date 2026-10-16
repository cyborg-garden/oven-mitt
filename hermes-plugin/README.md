# ovenmitt bridge for Hermes

A [Hermes](https://github.com/NousResearch/hermes-agent) plugin that gives an agent native tools for an ovenmitt vault, plus a generic `ovenmitt` skill that tells the agent how to use them. It sits beside the core because the two version together. It is generic: nothing in it names a platform, provider or use case.

```
hermes-plugin/
├── plugin/   the plugin (plugin.yaml, __init__.py, bridge.py, session.py) → plugins/ovenmitt_bridge/
├── skill/    SKILL.md                                                   → skills/ovenmitt/
└── tests/
```

Install the two directories separately, each pinned to a tag. In a manifest that installs one subdirectory per artifact:

```
plugin: git:<org>/oven-mitt#<tag>:hermes-plugin/plugin   (name: ovenmitt_bridge)
skill:  git:<org>/oven-mitt#<tag>:hermes-plugin/skill    (name: ovenmitt)
```

The agent image needs the client library: `pip install ovenmitt` (no MCP extra needed).

## Tools

| Tool | Arguments | Returns |
|---|---|---|
| `ovenmitt_vault_put` | `path, vault, labels?, mime?, remove_source?` | handle + metadata |
| `ovenmitt_vault_list` | `vault?` | metadata for each object |
| `ovenmitt_vault_stat` | `handle` | metadata |
| `ovenmitt_vault_label` | `handle, labels` | metadata |
| `ovenmitt_vault_delete` | `handle` | `{"deleted": handle}` |
| `ovenmitt_vault_list_destinations` | `vault` | names and kinds |
| `ovenmitt_vault_send` | `handle, filename?, caption?` | `{"sent": true, "bytes": n, ...}` |

No tool returns content, and there is no export tool. The names carry an `ovenmitt_vault_` prefix because native tools have no server namespace, and a harness may already call something else "the vault" (its key store, say). The MCP face (`ovenmitt mcp`) keeps the plain `vault_*` names.

## Sending

`ovenmitt_vault_send` delivers an object to **the chat this turn belongs to**, and it has no argument that could name another. The bridge:

1. reads the platform and chat id from Hermes's session context, finds that platform's live adapter, and builds `functools.partial(adapter.send_document, chat_id)`;
2. derives the claim from that very callable, refusing any other shape: destination = the adapter's platform name, target = `<platform>/<percent-encoded chat id>`;
3. calls `VaultClient.resolve_path(...)` and hands the one-shot path to the adapter on the gateway's own event loop. Adapters read the file in-process, so every platform works the same way, and the path dies when the send returns.

The daemon checks the target against the destination's pattern and audits both. **Operator contract:** name each `send` destination after the platform and match every chat on it:

```toml
[vault.private.destinations.<platform>]
kind  = "send"
match = "<platform>/*"
```

A platform with no destination gets a refusal, which is audited. The bridge is trusted to declare its target truthfully; that is the threat model's line (BRIEF §3).

## Credential

The deployer puts the consumer credential in the gateway's environment as `OVENMITT_CONSUMER_CREDENTIAL`, in a compose `environment:` entry, never a file. `register()` pops it out of `os.environ` into the plugin's memory before any tool runs, so terminal children never inherit it. `OVENMITT_SOCKET` sets the socket path (default `/run/ovenmitt/ovenmitt.sock`). Without a credential, the metadata tools still work and `send` reports `NOT_CONFIGURED`.

Residuals, accepted and documented: the process's initial environment stays readable at `/proc/<gateway-pid>/environ` by the same uid, and the memfd is reachable at `/proc/<pid>/fd/N` while a send is in flight.

## Use from another plugin

Producers send through the same tool, so there is one send path and one target rule:

```python
ctx.dispatch_tool("ovenmitt_vault_send", {"handle": h, "filename": "report.txt"})
```

## Tests

```sh
uv run --project python pytest hermes-plugin/tests -q   # macOS: daemon-backed tests skip (memfd is Linux-only)
hermes-plugin/tests/run-in-agent-image.sh               # everything, inside a Hermes image, incl. a real adapter
```
