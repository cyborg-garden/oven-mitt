# llm-safe-kaitiaki — BRIEF

*Status: brief (pre-PRD). Decisions captured from design interview, 2026-10-12.*

**Layout:**
- **Part A:** The harness-independent tool, which is this repo.
- **Part B:** The Hermes / Swarm Map integration, which ships as a separate PR.
- **Part C:** The motivating use case.

# Part A — Core (this repo)

## 1. Problem

Agents need to move, send and process data that must **never enter an LLM's context**, because the model provider may retain or train on it. Licences, contracts and data-sovereignty obligations often forbid exactly that. (The motivating case is in Part C.)

Today, any tool output an agent produces lands in a tool result, and therefore in the provider's hands. Nothing exists that lets an agent *handle* data without *reading* it. Existing agent-secret tools (Infisical Agent Vault, BlindKey, BlindVault, Cloak) inject short credentials into HTTP requests. None store arbitrary blobs, route them to destinations, or process them blind.

## 2. What it is

A generic, Unix-shaped **write-only sink**. Data goes in, and an opaque handle comes out. The agent can then label, export, send or pipe that data by handle, and **nothing in the agent's reach can read it back**.

```
some-tool --args | vput --vault private
→ v_9c1e4a  2.1MB  text/plain
```

## 3. Threat model

- **In scope:** *accidental* leakage. A well-meaning agent, careless tool code or a misconfiguration sends protected content to an LLM provider or an unapproved third party. Protection should be as strong as can reasonably be achieved: structural (the OS says no) wherever possible, not polite convention.
- **Out of scope:** a determined adversary (e.g. prompt injection probing covert channels), and malicious tool code that lies about where it sends bytes. The docs say this plainly.

## 4. Core concepts

- **Vault:** a named, path-rooted store with its own configuration. Anything written into a vault is protected.
- **Handle:** a stable opaque id (`v_…`) for an object. Real filenames are hidden by default; per-vault `expose_names: true` opts in. Size, MIME type, mtime and human labels are always visible.
- **Object:** whole-object, atomic. `put` commits on stream close, so a crash mid-stream leaves no half-object. `put --replace` streams a new body under the same handle, and the **old bytes are deleted immediately**. Content hashes are kept in the audit log only.
- **Destination:** a *named* target declared per vault by the operator. It is either an export target (a filesystem root) or a send pattern that tool code must declare when it resolves bytes. The agent sees and chooses names; real paths, URLs and credentials never leave the daemon.
- **Operator:** the human who deploys and configures the vault, through a config file the agent cannot read or write. End users and the agent can *use* declared destinations, never add them.
- **Consumer credential:** issued by the operator to specific tool code (e.g. a send tool). It is required for `resolve`, and never given to the agent's shell.

## 5. Architecture

### 5.1 Daemon and faces

One Rust daemon, three faces, all over a local Unix socket:

| Face | For | Notes |
|---|---|---|
| `vput` / `vpipe` / `vault` CLI | agents, scripts, pipes | Unix utility; the pipe target |
| `vault mcp` | LLM tool calls | same operations as CLI |
| Python client lib | tool authors | the **only** path that resolves bytes, and only with a consumer credential |

**No read command exists on any face.** Resolving a handle to bytes is a library call (`resolve(handle, destination) → stream`) for tool code.

**Deployment modes** (encrypted at rest in both: AES-256-GCM, one key per vault, held only by the daemon):
- **Sidecar (default):** Docker. The vault volume and keys live in the daemon container only, and the agent container reaches it over a socket.
- **Local:** a single binary running as a dedicated OS user (`vaultd`), store and keys at mode 0700, clients authenticated by peer UID (`SO_PEERCRED`). No Docker, still structural.
- **`--dev`:** the daemon runs as the agent's own user. Loud warning at startup, recorded in the audit log, and flagged by `review` at the highest severity.

Losing a vault key means losing the vault. The docs say so.

## 6. Operations (v1)

| Operation | Effect |
|---|---|
| `put [<path> \| -]` | one verb, Unix-style. With no argument or `-` it reads stdin; with a path it reads that file. Either way → handle. `--remove-source` deletes the original after a successful commit. (The CLI client reads the path and streams it, so this works in sidecar mode where the daemon can't see agent paths.) |
| `put --replace <h> [<path> \| -]` | stream a new body under the same handle; old bytes deleted |
| `export <h> <destination> <filename>` | write to a declared destination. The agent picks the filename: sanitised, confined to the destination root, error on collision unless `overwrite: true` |
| `stat`, `list`, `label`, `delete` | metadata only |
| `list-destinations <vault>` | names only |
| `vpipe <h> --into <vault> -- cmd args` | run an allowlisted command with bytes on stdin. **stdout is captured into a vault as a new handle**; stderr is reduced to an exit code. Off unless enabled per vault |
| `resolve(h, destination)` *(lib only)* | stream bytes to tool code holding a consumer credential. Declared destination checked against the vault allowlist; every call audited |

On the MCP face, `put` takes a path only. The LLM has no stdin to give, and it must never be able to send content itself.

Not in v1: content search (a v2 candidate, §10.2), filter, preview, concat or transforms (beyond `vpipe`), partial edits, version retention.

## 7. Per-vault configuration (operator-only)

Sketch only; the PRD fixes the schema.

```toml
[vault.private]
expose_names  = false
ttl           = "30d"             # optional
vpipe_allow   = ["pandoc", "iconv"]

[vault.private.destinations]
nas-archive  = { kind = "fs",   root = "/srv/nas/archive" }
team-chat    = { kind = "send", match = "signal:group/team" }
dm-body      = { kind = "send", match = "signal:dm/*", as = "body" }   # bytes sent as message text
```

Every destination, whether export, send or message-body, must be declared here. The default is deny. The daemon doesn't know what Signal is: a send destination is just a pattern the resolving tool must declare.

## 8. Audit

The audit trail is first-class: it is how we stay confident the boundary holds.

- **Append-only, hash-chained JSONL** in the daemon, operator-only, never exposed to the agent.
- **Events:** put, replace, delete, export, resolve, vpipe, TTL expiry, and **every refusal** of any kind.
- **Fields:** timestamp, vault, handle, version hash, destination *name*, caller (peer UID or credential id), outcome, previous-entry hash.
- **Never logged:** content, real filenames (unless `expose_names`), resolved paths or URLs.
- `vault audit verify` checks the chain. Anchoring the head hash off-host is a documented manual step in v1, automated later.
- `vault audit review [--since] [--threshold]` is **rule-based** (rules in a config file) and ranked by severity. It flags:
  - refusals
  - first-time destinations
  - bursts of resolves, exports or deletes
  - churn on a single handle
  - `--dev` mode
  - chain failure

  It is **cron-friendly**: findings go to stderr and it exits nonzero at or above the threshold, so cron mail or any monitor picks it up.

## 9. Core acceptance test (no harness)

1. `some-tool | vput --vault private` returns a handle plus metadata only.
2. A test consumer holding a credential resolves the handle against a declared send pattern and receives the bytes intact.
3. Each of these fails safely and is audited:
   - there is no read command on the CLI or MCP faces
   - `cat` on the store: permission denied (sidecar and local modes)
   - `resolve` without a credential: refused
   - `resolve` to an undeclared destination: refused
   - export outside the destination root (`../`): refused
4. `vault audit verify` passes, and `vault audit review` reports every refusal and exits nonzero.

The end-to-end test with a real agent is in Part B (§B4).

## 10. Scope and roadmap

### 10.1 v1

Rust daemon and CLI, MCP face, Python client, Docker compose plus local mode. Together with the Part B PR, this makes the v1 deliverable.

### 10.2 Version 2: possible features

None of these is needed to start. Each is recorded so v1 doesn't rule it out.

- **Search:** finding the relevant file when there are many. Any content search is partly a read path: every query reveals whether its terms appear. So results must be handles and labels only, never snippets, and queries need a credential and are audited and rate-limited. Search over labels and metadata alone is safer and may be enough.
- **Content check:** "does this text contain vault content?" The daemon would keep keyed content fingerprints of every object: overlapping word windows (e.g. 8 words), each hashed with a secret key only the daemon holds. `check(text)` would return match or no match plus matching handles, never content. Callers would live outside the core: a harness scrubber (§B7), an LLM proxy, a log or email filter, a git pre-commit hook. Caveats:
  - false positives on short or common passages
  - no detection of paraphrased, translated, summarised or encoded content
  - window size, normalisation (case, whitespace, punctuation, Unicode forms such as macrons) and the match threshold all need careful tuning
- **Sealed producers:** wrappers around a specific tool or API with no plain-stdout mode, so the pipe can't be forgotten.
- **Signed localhost URLs:** one-shot, expiring links (`http://127.0.0.1:…/o/<token>/name`) for consumers that only accept a path or URL. Every fetch is audited.

## 11. Open items

- None at present.

## 12. Decisions log

| # | Decision |
|---|---|
| 1 | Threat model: accidental leakage, protection as strong as reasonably achievable |
| 2 | Unit of protection: path-rooted vaults |
| 3 | Opaque handles by default; per-vault `expose_names`; size/type/mtime/labels visible |
| 4 | Harness-independent core in this repo; harness-specific integration lives elsewhere (Part B) |
| 5 | Sidecar (Docker) or dedicated-OS-user local mode; same-user only as `--dev` |
| 6 | Core primitive is the generic write-only sink; sealed producers layer on top later |
| 7 | Sends use the harness's existing surfaces and identity, resolving by handle in tool code |
| 8 | No read command; resolve is lib-only and needs a consumer credential |
| 9 | Three faces (CLI, MCP, Python lib) over one daemon |
| 10 | Stable handles, whole-object atomic replace, old bytes deleted immediately |
| 11 | `export(handle, destination, filename)`; destinations named, declared per vault, operator-only |
| 12 | Every resolve declares a destination, checked against the per-vault allowlist |
| 13 | Message-body sends are a destination type; `vpipe` captures stdout into a vault, allowlisted, off by default |
| 14 | Encrypted at rest in all modes |
| 15 | Hash-chained audit log, `verify`, and rule-based cron-friendly `review` |
| 16 | No content check, search or LLM proxy in v1; they are v2 candidates (§10.2) |
| 17 | Rust core, Python client, AGPL-3.0 (matches Swarm Map) |
| 18 | Optional per-vault TTL, unset by default |
| 19 | Name: `llm-safe-kaitiaki` |
| 20 | No policy modes. Every behaviour is set by explicit per-vault config; `--dev` is daemon-wide, audited and flagged |
| 21 | No domain-specific names (licences, providers, communities, platforms) in core code, config keys or defaults |
| 22 | One `put` verb: stdin by default or `-`, a file path otherwise; `--remove-source`, `--replace`. No separate import |

# Part B — Harness integration (separate PR to Swarm Map)

*This part is kept separate so that Part A stays harness-independent. Nothing here ships in this repo. It all ships as **one PR to Swarm Map**, because it depends on Hermes internals and on how Swarm Map deploys agents. It's recorded here because the v1 deliverable needs both halves, and the core must be designed so this integration is straightforward.*

## B1. What the PR contains

All Hermes-specific code is packaged as one Hermes plugin (a Python folder with `register(ctx)`), plus deployment wiring:

1. **Producer tool(s):** e.g. the Papa Reo API call, piping its output straight into `vput`.
2. **`vault_send(handle)`:** sends a vault object to the current chat (see B3).
3. **Consumer credential:** given only to `vault_send`. It is never in the terminal tool's environment or on PATH.
4. **Wiring:** the daemon as a compose service; `vault_send` gets the consumer credential.

Later Swarm Map work: a vault/destination config API behind its UI, and an audit view with `review` findings on the dashboard. Deferred: inbound attachment diversion (chat uploads → vault, bypassing the agent).

## B2. Hermes facts (from source, 2026-10-12)

- Hermes has **no agent-callable send tool**, by design. The agent delivers files only by writing `MEDIA:/path` tags in its reply, and only to the current chat. That's why we ship `vault_send`, registered via `ctx.register_tool`.
- Signal goes through an external signal-cli daemon (JSON-RPC). Hermes's adapter attaches files by path, but signal-cli also accepts **RFC 2397 data URIs** (`data:<mime>;filename=<name>;base64,…`), so `vault_send` calls signal-cli directly and never writes a file.
- Sending outside the agent's reply does not write content to session history. Hermes's own `send_message` mirror records only a placeholder such as `[Sent document attachment]`.
- `pre_llm_call` **cannot block**; it can only add context. Hooks that can intervene are `pre_tool_call` (block), `transform_tool_result` (rewrite a tool result) and `transform_llm_output` (rewrite the reply). No Hermes hook can block a whole LLM request.

## B3. `vault_send` flow

1. Read the current platform and chat from Hermes's session context.
2. `resolve(handle, "signal:<chat>")` using the consumer credential. The daemon checks it against the vault's declared send patterns and audits it.
3. Stream the bytes to signal-cli as a data-URI attachment, or as message text for a body destination.
4. Return only `sent ✓` to the LLM.

## B4. End-to-end acceptance test (one Hermes agent)

Reference producer: a Papa Reo API call (Part C). Any tool whose output must stay out of context works the same way.

1. The user asks the agent on Signal for something whose output must be protected.
2. The agent runs `some-tool | vput --vault private` and receives a handle plus metadata only.
3. The agent calls `vault_send(handle)`, and the user receives the file as a Signal attachment.
4. Each leak attempt fails safely:
   - "read it back": there is no read path
   - `cat` on the store: permission denied
   - export to an undeclared destination: refused and audited
5. `vault audit verify` passes, and `vault audit review` reports the refusals.
6. A capture of every LLM request in the session contains **zero** protected content.

## B5. Open items

- **Known gap:** v1 prevents the agent from reading vault content but does not *detect* it. Content that reaches context by another route (e.g. the user pasting it into chat) goes unnoticed.
- Does signal-cli keep a copy of sent attachments in its data dir? If it does, that copy needs the same protection or cleanup.

## B6. Decisions

| # | Decision |
|---|---|
| B1 | All Hermes-specific code (producers, `vault_send`, wiring) ships as one Swarm Map PR |
| B2 | Signal sends use signal-cli data-URI attachments; no temp files |

## B7. Version 2: possible additions

- **Tool-result scrubber:** a `transform_tool_result` hook that calls the core `check` (§10.2) on every tool result and replaces any match with `[redacted: vault content]`. Tool output is the main way content enters context, and this hook can rewrite it.
- **LLM proxy:** Hermes's base URL pointed at a proxy that calls `check` on every outgoing request and refuses on a match. It's the only way to block a whole request, since no Hermes hook can.

# Part C — Motivating case: Papa Reo and the Kaitiakitanga License

This part is context for *why* the design is strict. Nothing in it is a mode, flag or name in the software.

The [Papa Reo API](https://papareo.io) is offered under the [Kaitiakitanga License](https://github.com/TeHikuMedia/Kaitiakitanga-License/blob/tumu/papareo_api.md). Clause 3 of its API terms is the driver:

> If you intend on using Papa Reo API outputs with LLMs, translation services, or other tools, you must ensure that those third parties will not have rights to the data you give them. You must not send model outputs to third party services that may collect and use them.

What follows for this project:

- **Outputs must never reach an LLM provider's context.** Agents may orchestrate the work but must never read the results. That is the write-only sink, with no read path.
- **Every onward destination is a third-party question.** That is why destinations are declared per vault and denied by default, and why every resolve is checked and audited.
- **Hold data no longer than needed.** Papa Reo deletes submitted data once processed. Setting a `ttl` on vaults that hold Papa Reo outputs follows the same posture.
- **Kaitiakitanga of the data stays with the kaitiaki who submitted it.** The audit trail exists so that kaitiaki can be confident about what did and didn't happen to their data.

Open question for Papa Reo outputs:

- **Which messaging platforms can be compatible with the Kaitiakitanga License at all?** Every send destination is a third party under clause 3, so this applies to all of them, not just Discord. Prepare a data pack for each candidate covering: the platform's terms on AI or ML use of message content and attachments, who holds rights to data on a server or in a group, retention, and whether the operator can read content.
  - **Discord:** the doubtful case. It is a central service that can read message content and attachments. Until resolved, it is not declared as a destination on vaults holding Papa Reo outputs.
  - **Signal:** the likely-compatible case. Messages and attachments are end-to-end encrypted, so Signal's servers can't read them. It still needs checking, including signal-cli's local storage (Part B open item).
  - **Self-hosted platforms (e.g. Mattermost):** the operator holds the data, so the question becomes who runs the server.
