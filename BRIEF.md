# llm-safe-kaitiaki — BRIEF

*Status: brief (pre-PRD). Decisions captured from design interview, 2026-10-12.*

## 1. Problem

Agents need to move, send and process data that must **never enter an LLM's context**, because the model provider may retain or train on it. The motivating case: transcripts from the Papa Reo API, which under the [Kaitiakitanga License](https://github.com/TeHikuMedia/Kaitiakitanga-License/blob/tumu/papareo_api.md) must not be sent to third-party services that may collect and use them.

Today, any tool output an agent produces lands in a tool result, and therefore in the provider's hands. Nothing exists that lets an agent *handle* data without *reading* it. Existing agent-secret tools (Infisical Agent Vault, BlindKey, BlindVault, Cloak) inject short credentials into HTTP requests. None store arbitrary blobs, route them to destinations, or process them blind.

## 2. What it is

A generic, Unix-shaped **write-only sink**. Data goes in, and an opaque handle comes out. The agent can then label, export, send or pipe that data by handle, and **nothing in the agent's reach can read it back**.

```
papareo-asr in.wav | vput --vault transcripts
→ v_9c1e4a  2.1MB  text/plain
```

## 3. Threat model

- **In scope:** *accidental* leakage. A well-meaning agent, careless tool code or a misconfiguration sends protected content to an LLM provider or an unapproved third party. Protection should be as strong as can reasonably be achieved: structural (the OS says no) wherever possible, not polite convention.
- **Out of scope:** a determined adversary (e.g. prompt injection probing covert channels), and malicious tool code that lies about where it sends bytes. The docs say this plainly.

## 4. Core concepts

- **Vault:** a named, path-rooted store with its own policy. Anything written into a vault is protected.
- **Handle:** a stable opaque id (`v_…`) for an object. Real filenames are hidden by default; per-vault `expose_names: true` opts in. Size, MIME type, mtime and human labels are always visible.
- **Object:** whole-object, atomic. `put` commits on stream close, so a crash mid-stream leaves no half-object. `replace` streams a new body under the same handle, and the **old bytes are deleted immediately**. Content hashes are kept in the audit log only.
- **Destination:** a *named* export or send target declared per vault by the operator. The agent sees and chooses names. Real paths, URLs and credentials never leave the daemon.
- **Operator:** the human who deploys and configures the daemon, through a config file the agent cannot read or write. End users and the agent can *use* declared destinations, never add them.

## 5. Architecture

Two tiers.

### 5.1 Core (harness-independent)

One Rust daemon, three faces, all over a local Unix socket:

| Face | For | Notes |
|---|---|---|
| `vput` / `vpipe` / `vault` CLI | agents, scripts, pipes | Unix utility; the pipe target |
| `vault mcp` | LLM tool calls | same operations as CLI |
| Python client lib | send/attach tool authors | the **only** path that resolves bytes |

**No read command exists on any face.** Resolving a handle to bytes is a library call (`resolve(handle, destination) → stream`) for tool code.

**Deployment modes** (encrypted at rest in both: AES-256-GCM, one key per vault, held only by the daemon):
- **Sidecar (default):** Docker. The vault volume and keys live in the daemon container only, and the agent container reaches it over a socket.
- **Local:** a single binary running as a dedicated OS user (`kaitiaki`), store and keys at mode 0700, clients authenticated by peer UID (`SO_PEERCRED`). No Docker, still structural.
- **`--dev`:** the daemon runs as the agent's own user. Loud warning, and refused for vaults tagged `kaitiakitanga`.

Losing a vault key means losing the vault. The docs say so.

### 5.2 Hardening tier (per-harness; Hermes first)

1. **Consumer credential:** only the harness's send and attach tools hold the credential `resolve` requires. It is never in the terminal tool's environment or on PATH.
2. **Egress fingerprint filter:** the daemon publishes salted shingle hashes of vault objects. A blocking pre-LLM hook (in `hermes-agent-mt`) refuses any outgoing request that matches. This is the backstop for paths nobody anticipated.

Deferred: inbound attachment diversion (chat uploads → vault, bypassing the agent).

## 6. Operations (v1)

| Operation | Effect |
|---|---|
| `put` | stream in → handle |
| `put --replace <h>` | stream new body under the same handle; old bytes deleted |
| `import <path>` | pull an existing file into a vault → handle (optionally remove the original) |
| `export <h> <destination> <filename>` | write to a declared destination. The agent picks the filename: sanitised, confined to the destination root, error on collision unless `overwrite: true` |
| `stat`, `list`, `label`, `delete` | metadata only |
| `list-destinations <vault>` | names only |
| `vpipe <h> --into <vault> -- cmd args` | run an allowlisted command with bytes on stdin. **stdout is captured into a vault as a new handle**; stderr is reduced to an exit code. Off unless enabled per vault |
| `resolve(h, destination)` *(lib only)* | stream bytes to tool code. Declared destination checked against the vault allowlist; every call audited |

Not in v1: content search, filter, preview, concat or transforms (beyond `vpipe`), partial edits, version retention.

## 7. Per-vault configuration (operator-only)

Sketch only; the PRD fixes the schema.

```toml
[vault.transcripts]
policy        = "kaitiakitanga"   # or "standard"
expose_names  = false
ttl           = "30d"             # optional; recommended for kaitiakitanga vaults
vpipe_allow   = ["pandoc", "iconv"]

[vault.transcripts.destinations]
nas-transcripts     = { kind = "fs",     root = "/srv/nas/transcripts" }
signal-whanau       = { kind = "signal", match = "signal:group/whanau" }
signal-dm           = { kind = "signal", match = "signal:dm/*", as = "body" }   # message-body "stream"
```

Every destination, whether export, send or message-body, must be declared here. The default is deny.

## 8. Audit

The audit trail is first-class: it is how we stay confident the boundary holds.

- **Append-only, hash-chained JSONL** in the daemon, operator-only, never exposed to the agent.
- **Events:** put, replace, delete, import, export, resolve, vpipe, TTL expiry, and **every refusal**.
- **Fields:** timestamp, vault, handle, version hash, destination *name*, caller (peer UID or credential id), outcome, previous-entry hash.
- **Never logged:** content, real filenames (unless `expose_names`), resolved paths or URLs.
- `vault audit verify` checks the chain. Anchoring the head hash off-host is a documented manual step in v1, automated later.
- `vault audit review [--since] [--threshold]` is **rule-based** (rules in a config file) and ranked by severity. It flags:
  - refusals
  - egress-filter blocks
  - first-time destinations
  - bursts of resolves, exports or deletes
  - churn on a single handle
  - `--dev` mode
  - chain failure

  It is **cron-friendly**: findings go to stderr and it exits nonzero at or above the threshold, so cron mail or any monitor picks it up.

## 9. v1 acceptance test

On one Hermes agent:

1. The user asks the agent on Signal to transcribe an audio file.
2. The agent runs `papareo-asr in.wav | vput --vault transcripts` and receives a handle plus metadata only.
3. The agent sends the transcript to the user on Signal. Hermes's send tool declares `signal:…` and resolves the handle, and the user receives the full text.
4. Each leak attempt fails safely:
   - "read it to me": there is no read path
   - `cat` on the store: permission denied
   - export to an undeclared destination: refused and audited
   - planted content in a prompt: blocked by the egress filter
5. `vault audit verify` passes, and `vault audit review` reports the refusals.
6. A capture of every LLM request in the session contains **zero** transcript content.

## 10. Scope and roadmap

- **v1:** standalone. Rust daemon and CLI, MCP face, Python client, Docker compose plus local mode, Hermes hardening (consumer credential and egress filter).
- **Later layers on the core:** sealed producers, e.g. a Papa Reo ASR command with no plain-stdout mode, so the pipe can't be forgotten.
- **v2: Swarm Map integration.** Sketch the integration points now so v1 doesn't paint itself into a corner:
  - the daemon as a compose service per agent
  - a vault/destination config API behind Swarm Map's UI
  - an audit view and `review` findings on the dashboard
  - consumer-credential injection into harness send tools
- **Possible:** move the egress filter into an LLM egress proxy (e.g. an Infisical Agent Vault-style MITM). That would make it harness-independent.

## 11. Open items (facts to establish, not decisions)

- **Discord:** a data pack for the conversation with Te Hiku. It should cover Discord's terms on AI use of message content and attachments, and who holds rights on a server. Until Te Hiku answers, Discord is simply not declared on kaitiakitanga vaults.
- **Hermes:**
  - Do send tools attach by path or by bytes?
  - Does the gateway echo the bot's own outbound messages back into session history?
  - Can a `pre_llm_call` hook *block* a request, or only observe it?
- **Agent Vault:** can it inspect request bodies? If so, the egress filter could live there.

## 12. Decisions log

| # | Decision |
|---|---|
| 1 | Threat model: accidental leakage, protection as strong as reasonably achievable |
| 2 | Unit of protection: path-rooted vaults |
| 3 | Opaque handles by default; per-vault `expose_names`; size/type/mtime/labels visible |
| 4 | Two tiers: harness-independent core plus optional per-harness hardening |
| 5 | Sidecar (Docker) or dedicated-OS-user local mode; same-user only as `--dev` |
| 6 | Core primitive is the generic write-only sink; sealed producers layer on top later |
| 7 | Sends use the harness's existing surfaces and identity, resolving by handle in tool code |
| 8 | No read command; resolve is lib-only; consumer credential in the hardening tier |
| 9 | Three faces (CLI, MCP, Python lib) over one daemon |
| 10 | Stable handles, whole-object atomic replace, old bytes deleted immediately |
| 11 | `export(handle, destination, filename)`; destinations named, declared per vault, operator-only |
| 12 | Every resolve declares a destination, checked against the per-vault allowlist |
| 13 | Message-body sends are a destination type; `vpipe` captures stdout into a vault, allowlisted, off by default |
| 14 | Encrypted at rest in all modes |
| 15 | Hash-chained audit log, `verify`, and rule-based cron-friendly `review` |
| 16 | v1 standalone; Swarm Map is v2 |
| 17 | Rust core, Python client, AGPL-3.0 (matches Swarm Map) |
| 18 | Optional per-vault TTL, unset by default |
| 19 | Name: `llm-safe-kaitiaki` |
