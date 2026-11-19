# oven-mitt

[![rust](https://github.com/cyborg-garden/oven-mitt/actions/workflows/rust.yml/badge.svg?branch=tumu)](https://github.com/cyborg-garden/oven-mitt/actions/workflows/rust.yml)
[![python](https://github.com/cyborg-garden/oven-mitt/actions/workflows/python.yml/badge.svg?branch=tumu)](https://github.com/cyborg-garden/oven-mitt/actions/workflows/python.yml)
[![e2e](https://github.com/cyborg-garden/oven-mitt/actions/workflows/e2e.yml/badge.svg?branch=tumu)](https://github.com/cyborg-garden/oven-mitt/actions/workflows/e2e.yml)

oven-mitt lets an AI agent move data and files without the data entering the LLM's context.

Data goes into a vault and the agent gets an opaque handle back.
With the handle, the agent can label the data, export it to a declared folder, or have a tool send it to a user.
Nothing on the socket returns the bytes without a credential, and the agent does not hold that credential.

**Who it's for:** people who run AI agents and handle data that must not reach the model provider.
Typical cases are licence terms, contracts, or data-sovereignty obligations.

**Start here:**

1. Run the daemon with Docker: [Quick start](#quick-start).
2. Use it from Python or MCP: [Python usage](#python-usage), [MCP usage](#mcp-usage).
3. Before you deploy, read the [Operator checklist](#operator-checklist) and [Limitations](#limitations).

Status: version 0.2.0, Docker only.
It ships a Rust daemon, a Python client and MCP server, an operator CLI, and a [Hermes plugin](hermes-plugin/README.md).
[`PRD.md`](PRD.md) is the specification.
[`BRIEF.md`](BRIEF.md) holds the design history and the motivating case.

## Why it exists

oven-mitt is meant to be generally useful.
It started as a way to comply with the [Kaitiakitanga License](https://papareo.io/kaitiakitanga), which says in clause 3:

> You must not send model outputs to third party services that may collect and use them.

With oven-mitt, a tool's output goes straight from the API call into the vault.
The agent can move the data around, and the data stays out of its context.
Agents are stochastic, so you cannot rely on them to stay away from data by choice.
oven-mitt makes it hard for them to read the raw bytes.
Combined with agent tooling such as [swarm-map](https://github.com/cyborg-garden/swarm-map), an agent can call a tool, get a result, and send it to a person while the data stays encrypted and **out of the agent's reach**.

### What it does not protect against

oven-mitt guards against *accidental* leakage.
Examples: an agent that hallucinates, careless tool code, or a misconfiguration that would put data into the context.

It does not stop a person who has rights to the data.
That person can copy and paste it into a chat session.
It also does not stop a determined adversary or a malicious tool.

It does keep the agent honest.
The agent cannot easily load vault data into its context.
Every operation goes into an audit log, and a review job can run on a schedule to check where data went.
The full list is under [Limitations](#limitations).

## How it works

```
┌─────────────── agent container ──────────────┐         ┌──────── oven-mitt vault ─────────┐
│  LLM running in an agent harness             │         │                                  │
│        tool-use output  ───▶ /run/ovenmitt/ovenmitt.sock ─▶ ovenmittd                     │
│                                              │         │   ├─ data/   ciphertext only     │
│                                              │         │   ├─ keys/   never leaves        │
└──────────────────────────────────────────────┘         │   ├─ audit/  hash-chained JSONL  │
                                                         │   └─ export                    ───▶ declared export roots
                                                         └──────────────────────────────────┘
```

- **Vault:** a named store the operator declares. Each object is encrypted at rest with its own key, and that key is wrapped by a per-vault key. The daemon never writes plaintext to its own disk.
- **Handle:** for example `v_9c1e4a0b2d31`. Stable and opaque. `list` shows handles to any caller, so they are identifiers and carry no secrecy. The agent can see size, MIME type, timestamps and labels. It sees the original filename only if the vault sets `expose_names = true`.
- **Destination:** a *named* target the operator declares per vault. It is either an `fs` root (used by `export`) or a `send` pattern (used by `resolve`). Anything undeclared is denied. The agent sees destination names, never roots or patterns.
- **Consumer credential:** a token the operator issues to specific tool code. It is the only way to get bytes out through the socket. The deployer keeps it away from the agent's terminal.
- **Audit log:** append-only and hash-chained. It records every put, replace, label, delete, export, resolve and expiry, **every refusal**, and the declared target of each resolve. `ovenmitt audit review` flags refusals, first-time destinations, bursts, churn and chain breaks, and exits nonzero so cron can alert on it.

The socket speaks HTTP/1.1 internally.
Treat it like a mounted file.
There is no TCP listener, and no configuration key can create one.

## Quick start

```sh
docker compose -f docker/docker-compose.yml up -d --build
# issue a credential for your send tool (printed once, never stored)
docker compose -f docker/docker-compose.yml exec ovenmittd \
    ovenmitt credential issue --name vault_send --vault private
```

The compose file starts the daemon and a stub agent container.
The agent container mounts only the socket volume.

### Python usage

Install the client inside the agent container with `pip install ovenmitt`.
Add the MCP server with `pip install 'ovenmitt[mcp]'`.

```python
from ovenmitt import VaultClient

c = VaultClient("/run/ovenmitt/ovenmitt.sock")
info = c.put(some_stream, "private", mime="text/plain", labels=["transcript"])
print(info.handle, info.size)            # metadata only; no content
c.export(info.handle, "archive", "transcript.txt")   # plaintext lands under the declared root

# consumer tool code only: needs the credential
with c.resolve(info.handle, "team-chat", "chat:group/team", credential) as r:
    send_somewhere(r.stream)             # bytes pass through this process, never the model
```

More detail is in [`python/README.md`](python/README.md).

### MCP usage

`ovenmitt mcp` lets the model drive the vault over MCP.
It serves eight tools: `vault_list_vaults`, `vault_list_destinations`, `vault_put`, `vault_stat`, `vault_list`, `vault_label`, `vault_delete` and `vault_export`.
None of them returns content.

For Hermes agents, [`hermes-plugin/`](hermes-plugin/README.md) registers native `ovenmitt_vault_*` tools with no MCP subprocess.
It includes `ovenmitt_vault_send`, which delivers an object to the current chat through the platform's own sender.

## Operator guide

### Configuration

The config is one TOML file at `/etc/ovenmitt/ovenmitt.toml`, mounted read-only into the daemon container.
It is the operator's authority, and nothing on the socket can read or change it.
The full example is [`docker/example/ovenmitt.toml`](docker/example/ovenmitt.toml), and the schema is in [PRD §5](PRD.md#5-configuration-schema).

Check a file with `ovenmitt config check [PATH]`.
The daemon refuses to start on anything it doesn't understand, and the error names the line.
Every CLI command takes `--config PATH` to point at another file.
`OVENMITT_LOG` sets the daemon's log filter (default `info`).

```toml
[vault.private]
expose_names    = false   # show the original filename in metadata (handles are always opaque)
ttl             = "30d"   # optional: delete an object 30 days after its last write
max_object_size = "2GiB"  # optional: largest object the vault accepts

[vault.private.destinations.archive]
kind      = "fs"          # allow exports into this directory
root      = "/var/lib/ovenmitt/export/archive"
overwrite = false

[vault.private.destinations.team-chat]
kind  = "send"              # credentialed tool code may stream bytes out, declaring a target that must match
match = "chat:group/team"   # a literal, or a literal ending in /* for one more segment
```

### Credentials

Only `resolve` needs a credential. It streams an object's bytes to the tool that will send them on.
Any process that can see the socket can put, label, export to a declared root and delete without a credential.
That is by design.

`resolve` is the only gated operation because it is the only one that hands plaintext to the caller.
Export also writes plaintext, but the daemon does the writing, to a root fixed in config, so the caller never holds the bytes.
A resolving tool runs in the agent's container, beside the agent's terminal.
Both reach the same socket, from the same container, as the same UID.
In Docker, the credential is the only thing that tells them apart, so the credential is the read barrier.
If the agent's shell can read the credential, the barrier is gone and the daemon cannot tell.

```sh
ovenmitt credential issue --name vault_send --vault private   # token on stdout, once
ovenmitt credential list
ovenmitt credential revoke <id>                               # effective on the next request
```

Leave out `--vault` to scope a credential to every vault.
The daemon stores only `sha256(secret)`.
Deliver the token to the sending tool by a route the agent's terminal cannot read.
That rules out its environment, its PATH and files in its working directory.

### Audit

The audit log records where every object went: each put, export and resolve, with the declared target.
It also records every request the daemon refused.
Use it to check after the fact that the agent did not reach for data it shouldn't have, by accident or on purpose.

```sh
ovenmitt audit verify               # walks the chain; exit 1 names the first bad entry
ovenmitt audit head                 # head hash; anchor it off-host on a schedule
ovenmitt audit review --since 24h   # findings to stderr; exit 1 at or above the threshold
```

`review` also takes `--threshold low|medium|high|critical` and `--json`.
Put it in a cron job and alert on a nonzero exit.
Rules and thresholds live in an optional `review.toml` ([example](docker/example/review.toml)).

### Operator checklist

1. Mount **only** the socket volume into any container the agent can see. Never mount `data`, `keys`, `audit`, the config or an export root.
2. Back up `keys` separately from `data`. Losing the keys volume loses every vault. The daemon refuses to start rather than re-key over existing objects.
3. Deliver the consumer credential to tool code only.
4. Run `audit review` on cron. Anchor `audit head` somewhere the daemon host can't reach.
5. Treat an export root as plaintext. Anything that can read that directory can read what was exported there.

## Tool-author guide

- **Producers** put from a stream: `client.put(response.iter_bytes(), vault, mime=...)`. The bytes go from your HTTP response into the socket and nowhere else. Don't write them to a file first: a file on the agent's disk is readable before it is put.
- **Labels and names are visible to the agent.** Don't put content in them.
- **Senders** resolve with the credential and name both the declared destination and the concrete target: `client.resolve(handle, "team-chat", "chat:group/team", cred)`. The daemon checks the target against the destination's pattern and audits both. It trusts you to declare the target truthfully, and that trust is where the threat model ends.
- **Every error is a code** from a closed set (`NOT_FOUND`, `TARGET_NOT_ALLOWED`, `EXISTS`, …) with a fixed message. Match on `e.code`. The full set is in [PRD §7](PRD.md#7-error-model).
- **Senders that only take a filename** use `resolve_path`. Most chat platforms' upload APIs take a path. `resolve_path` yields a one-shot path backed by memory:

  ```python
  with client.resolve_path(handle, "team-chat", "chat:group/team", cred, "report.txt") as path:
      platform.send_file(chat, path)   # same process; the path dies with the block
  ```

  The bytes go into a `memfd`, which lives in RAM on no filesystem.
  The path is a symlink named `report.txt` in a private temp dir, so the receiver sees a real name and MIME type.
  It points at `/proc/<pid>/fd/<n>` of the calling process.
  A helper process can open it while the block runs, and nothing can after.
  Linux only.

## Limitations

These limitations are known and by design.

1. **Hard, not impossible.** The system makes accidental leakage hard. A determined agent, a lying tool, or an operator who mounts a root into the agent container can defeat it.
2. **Two secrets.** Encryption keys never leave the daemon container. The consumer credential lives in the agent container and is the only read barrier. Keep it out of the terminal tool's environment, PATH and readable files.
3. **No credential is needed for intended use.** Putting, labelling, exporting to declared roots and deleting are all credential-free.
4. **An export root you can see is a read path.** It can't be prevented and isn't defended. Config limits exports to declared roots, and the shipped compose file never mounts one into the agent container.
5. **MCP `vault_put(path)` protects from commit onward.** The file was readable on the agent's disk before the put. Producers that must never expose bytes to the agent put from a stream through the library.
6. **Encryption at rest protects the data volume when it travels alone.** It never replaces isolation, because the daemon must hold the key to run.
7. **No physical erasure.** Delete destroys the key and unlinks the ciphertext. It doesn't scrub sectors.
8. **`verify` cannot detect tail truncation.** Anchor `audit head` off-host on a schedule.
9. **Caller identity is the credential.** UID and PID in the log are informational.
10. **`expose_names` governs all objects in the vault, past and future.** Operators always see names via `ovenmitt object stat`.
11. **Labels, and names when exposed, are visible to the agent.** Don't put content in them.
12. **Losing `keys_dir` loses every vault.** Back it up separately.
13. **Out of scope:** determined adversaries, lying tool code, prompt-injection covert channels, disk or log-fill denial of service, and multiple agent trust domains on one daemon.

## Developing

```sh
cargo clippy --all-targets -- -D warnings && cargo test   # Rust: unit + in-process daemon tests
uv run --project python pytest python/tests -q            # Python, against the built binary
uv run --project python pytest tests-plugin -q            # Hermes plugin
uv run --project python pytest tests-e2e -q               # compose stack; needs Docker
# Python on Linux (resolve_path) from a Mac:
docker build -f docker/Dockerfile.pytest -t ovenmitt-pytest . && docker run --rm ovenmitt-pytest
```

Layout, decisions and milestones are in [`DEVELOPMENT.md`](DEVELOPMENT.md).
Changes are listed in [`CHANGELOG.md`](CHANGELOG.md).

## Licence

AGPL-3.0-only. Copyright Miles Thompson and contributors.
