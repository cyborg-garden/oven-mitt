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

The deployer puts the consumer credential in the gateway's environment as `OVENMITT_CONSUMER_CREDENTIAL`, in a compose `environment:` entry, never a file. The plugin pops it out of `os.environ` as its module's first statement, before any import that could fail, so terminal children never inherit it, even when the plugin fails to load or isn't enabled. Note that a process manager may keep its own copy (s6-overlay writes every container env var to `/run/s6/container_environment/`): the deployer has to lock that copy down too. `OVENMITT_SOCKET` sets the socket path (default `/run/ovenmitt/ovenmitt.sock`). Without a credential, the metadata tools still work and `send` reports `NOT_CONFIGURED`.

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

## What `ovenmitt_vault_put` refuses

`put` plus `send` would deliver any file the gateway can read, without the bytes passing the model (so the harness's redaction never sees them). `put` therefore refuses, on the path as given and as resolved: anything under `/proc`, `/sys`, `/dev`, `/run`, `/var/run` and `/etc`; anything inside `.ssh`, `.gnupg`, `.aws`, `.azure`, `.docker`, `.kube` or `.config/gcloud`; and credential files by name (`.env` and `*.env`, `auth.json`, `.netrc`, `.git-credentials`, `.pgpass`, `credentials(.json)`, SSH private keys, `*.pem`, `*.key`, `*.p12`, `*.pfx`). The refusal code is `PATH_REFUSED`. A hard link to a secret elsewhere gets through; that is deliberate hunting, outside the threat model.

## Refusal codes from `ovenmitt_vault_send`

`NOT_CONFIGURED` (no consumer credential), `NO_CHAT` (the turn isn't bound to a chat), `UNSUPPORTED` (the chat's adapter has no `send_document` of its own: the harness's fallback would post a notice and report success with no file sent), `SEND_TIMEOUT` (cancelled after the timeout; the file may still have arrived), `SEND_FAILED`, plus the daemon's own codes (`DESTINATION_NOT_FOUND`, …). Another plugin can ask `send_readiness()` on this module first: it returns the reason a send would be refused now, or None.
