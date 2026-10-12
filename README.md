# oven-mitt

[![rust](https://github.com/utunga/oven-mitt/actions/workflows/rust.yml/badge.svg?branch=tumu)](https://github.com/utunga/oven-mitt/actions/workflows/rust.yml)
[![python](https://github.com/utunga/oven-mitt/actions/workflows/python.yml/badge.svg?branch=tumu)](https://github.com/utunga/oven-mitt/actions/workflows/python.yml)
[![e2e](https://github.com/utunga/oven-mitt/actions/workflows/e2e.yml/badge.svg?branch=tumu)](https://github.com/utunga/oven-mitt/actions/workflows/e2e.yml)

*Allow AI agents to manipulate data and files without sending data to their servers.*

oven-mitt is an arms-length vault for AI agents. Data goes in, an opaque handle comes out. The agent can label, export and send that data to their users or on to other processes using the handle — but nothing on the socket can be read back into the agents context without a credential (that the agent doesn't have).

### Motivation

This is intended to be generally useful but was motivated by a desire to comply with the [Kaitiakitanga License](https://github.com/TeHikuMedia/Kaitiakitanga-License/blob/tumu/papareo_api.md), Specifically, from Clause 3:

> You must not send model outputs to third party services that may collect and use them.

To allow agents to use that API and still comply with the license, we use oven-mitt. Data goes straight from the tool-use / api-call into the vault. The agent can then move the data around but it is prevented from entering into the LLM's context. Agents are stochastic and therefore unreliable. This tools makes it very hard for them to read the raw data or load into their context. Combined with appropriate agent tooling (e.g. in [swarm-map](https://github.com/cyborg-garden/swarm-map)) the agent can use a tool to create data and send it to the human while keeping the data encrypted and **inaccessible to the agent**.

### The promise of oven-mitt is, limited

A human user - for instance a human with appropriate rights to the data - can defeat the LLM protections by simple 'copy and paste' into a chat session. This tool is focused on keeping the *agent* honest - even if it has a brain fart and decides to get 'creative' it cannot easily copy data into its context). It makes the agent more reliable - and in an auditable fashion. Using this tool the agent can manipulate data without ever loading it into context or having the ability to do that. The threat which it manages against is primarily accidental leakage: an agent hallucination, careless tool code, or a misconfiguration that might lead to data accidentally entering the context. We prevent that. **However, keeping the data from a determined adversary, from a malicious tool or from a human that has a right to the data, is out of scope.** 

Status: **v1 (0.1.0)**, Docker only. Rust daemon, Python client and MCP server, operator CLI. See [`PRD.md`](PRD.md) for the full specification and [`BRIEF.md`](BRIEF.md) for the design history and the motivating case.

## How it works

```
┌──────────────── agent container ──────────-──┐         ┌──────── daemon container ────────┐
│  LLM ⇄ harness ⇄ MCP server.                 │         │                                  │
│            tool code  ──-─▶ /run/ovenmitt/ovenmitt.sock ─▶ ovenmittd                      │
│                                              │         │   ├─ data/   ciphertext only     │
│                                              │         │   ├─ keys/   never leaves        │
└───────────────────────────-──────────────────┘         │   ├─ audit/  hash-chained JSONL  |
                                                         │   └─ export                    ──-─▶ allowed export paths 
                                                         └──────────────────────────────────┘
```

- **Vault** — a named store declared by the operator. Objects are encrypted at rest with a per-object key wrapped by a per-vault key; the daemon never writes plaintext to its own disk.
- **Handle** — `v_9c1e4a0b2d31`. Stable, opaque, not a secret. Size, MIME type, timestamps and labels are visible to the agent; the original filename only if the cpnfiguration allows.
- **Destination** — a *named* target the operator declares per vault: an `fs` root (for `export`) or a `send` pattern (for `resolve`). The default is deny. The agent sees names, never roots or patterns.
- **Consumer credential** — a token the operator issues to specific tool code. It is the only way to get bytes out through the socket, and the deployer keeps it away from the agent's terminal.
- **Audit log** — append-only, hash-chained. Every put, replace, delete, export, resolve, expiry and **every refusal** is recorded, with the resolve target. `ovenmitt audit review` flags refusals, first-time destinations, bursts, churn and chain breaks, and exits nonzero for cron.

The socket speaks HTTP/1.1 internally but acts as if it is a file handle. A write-only file you mount, not a server you reach: there is no TCP layer and no configuration key that could create one.

## Quick start

```sh
docker compose -f docker/docker-compose.yml up -d --build
# issue a credential for your send tool (printed once, never stored)
docker compose -f docker/docker-compose.yml exec ovenmittd \
    ovenmitt credential issue --name vault_send --vault private
```


### Python usage

From inside the agent container, with the Python package installed:

```python
from ovenmitt import VaultClient

c = VaultClient("/run/ovenmitt/ovenmitt.sock")
info = c.put(some_stream, "private", mime="text/plain", labels=["transcript"])
print(info.handle, info.size)            # metadata only; no content
c.export(info.handle, "archive", "transcript.txt")   # plaintext lands under the declared root

# consumer tool code only — needs the credential
with c.resolve(info.handle, "team-chat", "chat:group/team", credential) as r:
    send_somewhere(r.stream)             # bytes pass through this process, never the model
```

### MCP usage (how an agent will use this)

Or let the model drive it through MCP: `ovenmitt mcp` serves eight tools — `vault_list_vaults`, `vault_list_destinations`, `vault_put`, `vault_stat`, `vault_list`, `vault_label`, `vault_delete`, `vault_export` — and nothing that returns content.

## Operator guide

### Configuration

One TOML file, `/etc/ovenmitt/ovenmitt.toml`, mounted read-only into the daemon container. It is the operator's authority; nothing on the socket can read or change it. Example in [`docker/example/ovenmitt.toml`](docker/example/ovenmitt.toml). Validate with `ovenmitt config check`; the daemon refuses to start on anything it doesn't understand and names the line.

```toml
[vault.private]
expose_names    = false   # governs every object in the vault, past and future
ttl             = "30d"   # optional: objects expire 30 days after their last body write
max_object_size = "2GiB"  # optional

[vault.private.destinations.archive]
kind      = "fs"
root      = "/var/lib/ovenmitt/export/archive"
overwrite = false

[vault.private.destinations.team-chat]
kind  = "send"
match = "chat:group/team"   # a literal, or a literal ending in /* for one more segment
```

Platform names are fine in your own values. They never appear in ovenmitt's code, keys, defaults or examples.

### Credentials

```sh
ovenmitt credential issue --name vault_send --vault private   # token on stdout, once
ovenmitt credential list
ovenmitt credential revoke <id>                               # effective on the next request
```

Only `sha256(secret)` is stored. Deliver the token to the tool that sends, by a route the agent's terminal cannot read: not its environment, not its PATH, not a file in its working directory.

### Audit

Auditing of where the data is read to or from is important to verify that the agent wasn't (deliberately or accidentally) trying to access data it shouldn't.

```sh
ovenmitt audit verify            # walks the chain; exit 1 names the first bad entry
ovenmitt audit head              # head hash — anchor it off-host on a schedule
ovenmitt audit review --since 24h   # findings to stderr; exit 1 at or above the threshold
```

One idea is to put `ovenmitt audit review` in a cron job and let a nonzero exit trigger an alert.

The rules and the thresholds for the review config live in an optional `review.toml` ([example](docker/example/review.toml)).

### Operator checklist

1. Mount **only** the socket volume into any container the agent runs in.  Never mount `data`, `keys`, `audit`, the config, or an export root.
2. Back up `keys` separately from `data`. Losing the keys volume loses every vault; the daemon refuses to start rather than re-key over existing objects.
3. Deliver the consumer credential to tool code only.
4. Run `audit review` on cron; anchor `audit head` somewhere the daemon host can't reach.
5. Treat an export root as plaintext: anything that can read that directory can read what was exported there.

## Tool-author guide

- **Producers** put from a stream: `client.put(response.iter_bytes(), vault, mime=...)`. Bytes go from your HTTP response into the socket and nowhere else. Don't write them to a file first — a file on the agent's disk was readable before it was put.
- **Labels and names are visible to the agent.** Don't put content in them.
- **Senders** resolve with the credential and name both the declared destination and the concrete target: `client.resolve(handle, "team-chat", "chat:group/team", cred)`. The daemon checks the target against the destination's pattern and audits both. It trusts you to declare truthfully; that trust is the threat model's boundary.
- **Every error is a code** from a closed set (`NOT_FOUND`, `TARGET_NOT_ALLOWED`, `EXISTS`, …) with a fixed message. Match on `e.code`.
- Tools that only accept a filename: a future `resolve_path` will hand them a `/dev/fd/N` backed by memory. Until then, stream.

## Limitations

These are known limitations, by design.

1. **Hard, not impossible.** The system makes accidental leakage hard. A determined agent, a lying tool, or an operator who mounts a root into the agent container can defeat it.
2. **Two secrets.** Encryption keys never leave the daemon container. The consumer credential lives in the agent container and is the only read barrier; keep it out of the terminal tool's environment, PATH and readable files.
3. **No credential is needed for intended use.** Putting, labelling, exporting to declared roots, deleting — all credential-free by design.
4. **Export to a path you can see allows you to read the data.** Unavoidable; not defended; Configuration prevents export of raw data to anywhere except allowed paths, however.
5. **MCP `vault_put(path)` protects from commit onward.** Producers that must never expose bytes to the agent put from a stream through the library.
6. **Encryption at rest protects the data volume when it travels alone.** It never substitutes for isolation; the daemon must hold the key to run.
7. **No physical erasure.** Delete destroys the key and unlinks the ciphertext; it doesn't scrub sectors.
8. **`verify` cannot detect tail truncation.** Anchor `audit head` off-host on a schedule.
9. **Caller identity is the credential.** UID/PID in the log are informational.
10. **`expose_names` governs all objects in the vault, past and future.** Operators always see names via `object stat`.
11. **Labels and names can be agent-visible.** Don't put content in them.
12. **Losing `keys_dir` loses every vault.** Back it up separately.
13. **Out of scope:** Determined adversaries, lying tool code, prompt-injection covert channels, disk/log-fill DoS, multiple agent trust domains on one daemon.

## Developing / Contributing

```sh
cargo clippy --all-targets -- -D warnings && cargo test   # Rust: unit + in-process daemon tests
uv run --project python pytest python/tests -q            # Python, against the built binary
uv run --project python pytest tests-e2e -q               # compose stack; needs Docker
```

Layout, decisions and milestones are in [`DEVELOPMENT.md`](DEVELOPMENT.md).

## Licence

AGPL-3.0-only. Copyright, Miles Thompson and contributors - but hoping this will merge to cyborg-garden at some point.
