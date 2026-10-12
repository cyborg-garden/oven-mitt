# ovenmitt — BRIEF

*Status: brief. Decisions captured from design interview, 2026-10-12; updated the same day after PRD review (decisions 23–34). Project name is `ovenmitt`; the repo is `github.com/utunga/oven-mitt`. The hyphen is for the repo only: binary, daemon, Python package and PyPI name are `ovenmitt`, since a hyphen can't appear in an import or a sensible binary name (cf. `scikit-learn` / `sklearn`).*

*The one-line design criterion: make it **hard** for an agent to accidentally send protected data through its context, not impossible. Simple, elegant, free of foot-guns.*

**Layout:**
- **Part A:** The harness-independent tool, which is this repo.
- **Part B:** The Hermes / Swarm Map integration, which ships as a separate PR.
- **Part C:** The motivating use case.

# Part A — Core (this repo)

## 1. Problem

Agents need to move, send and process data that must **never enter an LLM's context**, because the model provider may retain or train on it. Licences, contracts and data-sovereignty obligations often forbid exactly that. (The motivating case is in Part C.)

Today, any tool output an agent produces lands in a tool result, and therefore in the provider's hands. Nothing exists that lets an agent *handle* data without *reading* it. Existing agent-secret tools (Infisical Agent Vault, BlindKey, BlindVault, Cloak) inject short credentials into HTTP requests. None store arbitrary blobs, route them to destinations, or process them blind.

## 2. What it is

A generic, Unix-shaped **write-only sink**. Data goes in, and an opaque handle comes out. The agent can then label, export or send that data by handle, and **nothing in the agent's reach can read it back without the consumer credential**. Think oven mitt: you can pick the thing up and move it, you can't feel it.

```python
h = vault.put(stream_from_some_tool(), vault="private")
# → v_9c1e4a  2.1MB  text/plain
```

## 3. Threat model

- **In scope:** *accidental* leakage. A well-meaning agent, careless tool code or a misconfiguration sends protected content to an LLM provider or an unapproved third party. Protection should be as strong as can reasonably be achieved: structural (the OS says no) wherever possible, not polite convention.
- **Out of scope:** a determined adversary (e.g. prompt injection probing covert channels), and malicious tool code that lies about where it sends bytes. The docs say this plainly.
- **Unavoidable, and documented rather than defended:** an agent can export to a declared root that it can also see, then read the file. No credential is needed for the intended use (put, label, export to declared roots, delete); the credential only gates `resolve`.
- **Two secrets, kept apart in the docs:** the *encryption keys* never leave the daemon container, which is structural. The *consumer credential* has to live in the agent container, and keeping it away from the terminal tool is the deployer's job. That credential is the read barrier.

## 4. Core concepts

- **Vault:** a named, path-rooted store with its own configuration. Anything written into a vault is protected.
- **Handle:** a stable opaque id (`v_…`) for an object. Real filenames are always stored but hidden from the agent by default; per-vault `expose_names: true` opts in and governs every object in the vault, past and future. The operator can always see names (`ovenmitt object stat`). Size, MIME type, mtime and human labels are always visible.
- **Object:** whole-object, atomic. `put` commits on stream close, so a crash mid-stream leaves no half-object. `put --replace` streams a new body under the same handle, and the **old bytes are deleted immediately**: each object has its own data key, wrapped by the vault key, and delete/replace/expiry destroys that key as well as unlinking the ciphertext. Content hashes are kept in the audit log only.
- **Destination:** a *named* target declared per vault by the operator. It is either an export target (a filesystem root, with `overwrite` set by the operator) or a send pattern that tool code must match when it resolves bytes. The agent sees and chooses names; real paths, patterns and credentials never leave the daemon.
- **Operator:** the human who deploys and configures the vault, through a config file the agent cannot read or write. That config file *is* the operator's authority; there is no separate admin credential. End users and the agent can *use* declared destinations, never add them.
- **Consumer credential:** issued by the operator to specific tool code (e.g. a send tool), scoped to a list of vaults. It is required for `resolve`, and the deployer keeps it away from the terminal tool.

## 5. Architecture

### 5.1 Daemon and faces

One Rust daemon in its own Docker container. In v1 it has two faces for agents and tools, both thin clients over a Unix socket shared into the agent's container:

| Face | For | Notes |
|---|---|---|
| Python client lib | tool authors | `put` from a stream; the **only** path that resolves bytes, and only with a consumer credential |
| `ovenmitt mcp` | LLM tool calls | runs beside the agent, so `put` can take an agent-side path. Tool names are `vault_put`, `vault_export` etc.: to the model, "vault" is the right picture |

There is also an **operator-only admin CLI** inside the daemon's container (`ovenmitt audit verify|review|head`, `ovenmitt credential …`, `ovenmitt vault list`, `ovenmitt object stat`), run with `docker exec`. It isn't reachable from the agent's container.

**No credential-free read exists on any face.** Resolving a handle to bytes is a library call for tool code, `resolve(handle, destination, target) → stream`, and it needs the consumer credential. The library ships in the agent container like everything else, so the credential, not the absence of a code path, is what stops the terminal tool reading. The socket protocol is the boundary; no client-side code is load-bearing.

**Wire:** HTTP/1.1 over the Unix socket, as an internal detail. Think of the socket as a file you mount, not a server you reach. There is no TCP listener and no config key that could create one, ever.

**Deployment (v1 is Docker only):** the vault volume and keys live in the daemon container only, in separate volumes. Objects are encrypted at rest (AES-256-GCM, one key per vault wrapping one key per object, held only by the daemon). Plaintext never touches disk inside the daemon. The agent container sees only the socket, so `cat` on the store is impossible: the files aren't in its filesystem.

Encryption at rest protects the data volume when it travels without the keys volume (backups, snapshots). It never substitutes for isolation: the daemon has to hold the key to run, so something — Docker now, a dedicated OS user in local mode later — always keeps the key away from the agent.

Losing a vault key means losing the vault; the daemon refuses to start and names the vault. The docs say so.

## 6. Operations (v1)

| Operation | Effect |
|---|---|
| `put(stream \| path)` | stream in → handle. The library takes a stream; the MCP face takes a path, which the client reads and streams, since the daemon can't see agent paths. `remove_source` deletes the original after a successful commit |
| `put(…, replace=<h>)` | stream a new body under the same handle; old bytes deleted |
| `export <h> <destination> <filename>` | write to a declared destination. The agent picks the filename: sanitised, confined to the destination root, error on collision unless the destination is configured `overwrite = true`. No credential needed: the root is operator-fixed, so there is nothing to lie about |
| `stat`, `list`, `label`, `delete` | metadata only; `delete` is a real delete (key destroyed) |
| `list-vaults`, `list-destinations <vault>` | names only. No default vault; every call names one |
| `resolve(h, destination, target)` *(lib only)* | stream bytes to tool code holding a consumer credential. The tool names the declared destination *and* the concrete target it will send to; the daemon checks the target against the destination's pattern and audits both. Trusts the tool to declare truthfully, which is where the threat model draws its line |

On the MCP face, `put` takes a path only. The LLM has no stdin to give, and it must never be able to send content itself.

Not in v1: the agent-facing CLI and `vpipe` (§10.2), content search (§10.2), filter, preview, concat or transforms, partial edits, version retention, message-body (inline text) sends.

## 7. Per-vault configuration (operator-only)

Sketch only; the PRD fixes the schema.

```toml
[vault.private]
expose_names  = false
ttl           = "30d"             # optional

[vault.private.destinations]
nas-archive  = { kind = "fs",   root = "/srv/nas/archive", overwrite = false }
team-chat    = { kind = "send", match = "chat:group/team" }
any-dm       = { kind = "send", match = "chat:dm/*" }    # one trailing wildcard segment; that's the whole grammar
```

Every destination, export or send, must be declared here. The default is deny. The daemon doesn't know what any platform is: a send destination is just a pattern the resolving tool's declared target must match. Platform names are fine in an operator's own config values; they never appear in code, keys, defaults or shipped examples (decision 21).

## 8. Audit

The audit trail is first-class: it is how we stay confident the boundary holds.

- **Append-only, hash-chained JSONL** in the daemon, operator-only, never exposed to the agent.
- **Events:** put, replace, delete, export, resolve, TTL expiry, label, and **every refusal** of any kind.
- **Fields:** timestamp, vault, handle, version hash, destination *name*, the declared *target* on resolve (always; there is no switch to turn any part of auditing off), caller (peer UID and PID for forensics, credential id for authorisation — in Docker the UID can't tell processes apart, so only the credential counts), outcome, previous-entry hash.
- **Never logged:** content, label text, real filenames (unless `expose_names`), destination roots and patterns, storage paths, credential secrets.
- `ovenmitt audit verify` checks the chain. Anchoring the head hash off-host (`ovenmitt audit head`) is a documented manual step in v1, automated later.
- `ovenmitt audit review [--since] [--threshold]` is **rule-based** (rules in a config file) and ranked by severity. It flags:
  - refusals
  - first-time destinations
  - bursts of resolves, exports or deletes
  - churn on a single handle
  - chain failure

  It is **cron-friendly**: findings go to stderr and it exits nonzero at or above the threshold, so cron mail or any monitor picks it up.

## 9. Core acceptance test (no harness)

1. `put` through the library and through MCP each return a handle plus metadata only.
2. A test consumer holding a credential resolves the handle against a declared send pattern and receives the bytes intact.
3. Each of these fails safely and is audited:
   - no operation on the library or MCP faces returns bytes without a valid credential
   - the store is not in the agent container's filesystem at all
   - `resolve` without a credential: refused
   - `resolve` to an undeclared destination, or with a target that doesn't match its pattern: refused
   - export outside the destination root (`../`): refused
4. `ovenmitt audit verify` (admin CLI) passes, and `ovenmitt audit review` reports every refusal and exits nonzero.

The end-to-end test with a real agent is in Part B (§B4).

## 10. Scope and roadmap

### 10.1 v1

Docker only. Rust daemon, Python client library, MCP face, operator admin CLI (audit `verify` and `review`), and a compose file. Together with the Part B PR, this makes the v1 deliverable.

### 10.2 Future: possible features

None of these is needed to start. Each is recorded so v1 doesn't rule it out.

- **Agent-facing CLI (`vput`):** a Unix utility so any shell tool can pipe straight into a vault (`some-tool | vput --vault private`). The core use beyond agents.
- **`vpipe`:** run an allowlisted command with bytes on stdin, with stdout captured into a vault as a new handle and stderr reduced to an exit code. Off unless enabled per vault.
- **Local (non-Docker) mode:** the daemon runs as a dedicated OS user (`vaultd`), with the store and keys at mode 0700 and clients authenticated by peer UID (`SO_PEERCRED`). A same-user `--dev` mode only with loud warnings, and flagged by `review`.

- **Search:** finding the relevant file when there are many. Any content search is partly a read path: every query reveals whether its terms appear. So results must be handles and labels only, never snippets, and queries need a credential and are audited and rate-limited. Search over labels and metadata alone is safer and may be enough.
- **Content check:** "does this text contain vault content?" The daemon would keep keyed content fingerprints of every object: overlapping word windows (e.g. 8 words), each hashed with a secret key only the daemon holds. `check(text)` would return match or no match plus matching handles, never content. Callers would live outside the core: a harness scrubber (§B7), an LLM proxy, a log or email filter, a git pre-commit hook. Caveats:
  - false positives on short or common passages
  - no detection of paraphrased, translated, summarised or encoded content
  - window size, normalisation (case, whitespace, punctuation, Unicode forms such as macrons) and the match threshold all need careful tuning
- **Sealed producers:** wrappers around a specific tool or API with no plain-stdout mode, so the pipe can't be forgotten.
- **`resolve_path`:** for consumer tools that only accept a filename. The library resolves into a `memfd` (an anonymous RAM-backed file that never appears on any filesystem) and spawns the tool with the descriptor inherited and `/dev/fd/N` as the path. Looks like a file, exists only for that child process, nothing on disk to race or `cat`, no daemon support, no TCP. (Replaces the earlier "signed localhost URLs" idea, which would have needed a TCP listener.) A FIFO in the socket volume is the fallback for already-running daemons, kept out until something needs it.

## 11. Open items

- None at present. (Repo renamed to `utunga/oven-mitt`; `ovenmitt` confirmed free on crates.io and PyPI.)

## 12. Decisions log

| # | Decision |
|---|---|
| 1 | Threat model: accidental leakage, protection as strong as reasonably achievable |
| 2 | Unit of protection: path-rooted vaults |
| 3 | Opaque handles by default; per-vault `expose_names`; size/type/mtime/labels visible |
| 4 | Harness-independent core in this repo; harness-specific integration lives elsewhere (Part B) |
| 5 | v1 is Docker only; local mode is future |
| 6 | Core primitive is the generic write-only sink; sealed producers layer on top later |
| 7 | Sends use the harness's existing surfaces and identity, resolving by handle in tool code |
| 8 | No credential-free read on any face; resolve is lib-only and needs a consumer credential; the socket protocol is the boundary |
| 9 | v1 faces: Python lib and MCP, plus an operator-only admin CLI in the daemon container; agent-facing CLI is future |
| 10 | Stable handles, whole-object atomic replace, old bytes deleted immediately (per-object key destroyed) |
| 11 | `export(handle, destination, filename)`; destinations named, declared per vault, operator-only; `overwrite` is destination config, not an agent argument |
| 12 | Every resolve declares a destination *and* a concrete target, checked against the per-vault allowlist and the destination's pattern |
| 13 | Message-body sends are **not** in v1; every send is bytes. `vpipe` is future |
| 14 | Encrypted at rest |
| 15 | Hash-chained audit log, `verify`, and rule-based cron-friendly `review` |
| 16 | No content check, search or LLM proxy in v1; they are future candidates (§10.2) |
| 17 | Rust core, Python client, AGPL-3.0 (matches Swarm Map) |
| 18 | Optional per-vault TTL, unset by default |
| 19 | Name: `ovenmitt` (binary `ovenmitt`, daemon `ovenmittd`, Python package `ovenmitt`; MCP tools `vault_*`); repo `utunga/oven-mitt`. Was `llm-safe-kaitiaki` |
| 20 | No policy modes. Every behaviour is set by explicit per-vault config |
| 21 | No domain-specific names (licences, providers, communities, platforms) in core code, config keys, defaults or shipped examples. Operator config values are unrestricted |
| 22 | One `put` operation: a stream (library) or a path (MCP); `remove_source`, `replace`. No separate import |
| 23 | Design criterion: hard, not impossible. Simplicity over marginal guarantees |
| 24 | Two secrets: encryption keys never leave the daemon (structural); the consumer credential is the read barrier and the deployer keeps it from the terminal tool |
| 25 | Export needs no credential: the root is operator-fixed. Export-to-a-root-you-can-see is unavoidable and documented |
| 26 | Encryption at rest kept (cheap; makes delete real; protects a data volume travelling alone). Keys in a separate volume. Never a substitute for isolation |
| 27 | Wire: HTTP/1.1 over the Unix socket as an internal detail. No TCP listener, no config key for one, ever |
| 28 | Send-pattern grammar: a literal, optionally ending in `/*` for one segment. Nothing else |
| 29 | Resolve target is always audited. No switch; no per-vault admin credential — the config file is the operator's authority |
| 30 | Missing vault key: refuse to start, naming the vault |
| 31 | Filenames always stored; agent sees them iff `expose_names` is on now; operator always can |
| 32 | Consumer credentials are scoped to a list of vaults; the vault's destination list is the only allowlist |
| 33 | `list-vaults` exists; there is no default vault |
| 34 | In Docker the peer UID can't identify a caller; credential-or-not is the only distinction. `SO_PEERCRED` is the local-mode fix, future |

# Part B — Harness integration (separate PR to Swarm Map)

*This part is kept separate so that Part A stays harness-independent. Nothing here ships in this repo. It all ships as **one PR to Swarm Map**, because it depends on Hermes internals and on how Swarm Map deploys agents. It's recorded here because the v1 deliverable needs both halves, and the core must be designed so this integration is straightforward.*

## B1. What the PR contains

All Hermes-specific code is packaged as one Hermes plugin (a Python folder with `register(ctx)`), plus deployment wiring:

1. **Producer tool(s):** e.g. the Papa Reo API call, streaming its response straight into `vault.put()` through the library. The agent calls the tool and gets back only a handle.
2. **`vault_send(handle)`:** sends a vault object to the current chat (see B3).
3. **Consumer credential:** given only to `vault_send`. It is never in the terminal tool's environment or on PATH.
4. **Wiring:** the daemon as a compose service, with its socket shared into the agent container; `vault_send` gets the consumer credential.

Later Swarm Map work: a vault/destination config API behind its UI, and an audit view with `review` findings on the dashboard. Deferred: inbound attachment diversion (chat uploads → vault, bypassing the agent).

## B2. Hermes facts (from source, 2026-10-12)

- Hermes has **no agent-callable send tool**, by design. The agent delivers files only by writing `MEDIA:/path` tags in its reply, and only to the current chat. That's why we ship `vault_send`, registered via `ctx.register_tool`.
- Signal goes through an external signal-cli daemon (JSON-RPC). Hermes's adapter attaches files by path, but signal-cli also accepts **RFC 2397 data URIs** (`data:<mime>;filename=<name>;base64,…`), so `vault_send` calls signal-cli directly and never writes a file.
- Sending outside the agent's reply does not write content to session history. Hermes's own `send_message` mirror records only a placeholder such as `[Sent document attachment]`.
- `pre_llm_call` **cannot block**; it can only add context. Hooks that can intervene are `pre_tool_call` (block), `transform_tool_result` (rewrite a tool result) and `transform_llm_output` (rewrite the reply). No Hermes hook can block a whole LLM request.

## B3. `vault_send` flow

1. Read the current platform and chat from Hermes's session context.
2. `resolve(handle, "<destination name>", "signal:<chat>")` using the consumer credential. The daemon checks the target against that destination's pattern and audits both.
3. Stream the bytes to signal-cli as a data-URI attachment.
4. Return only `sent ✓` to the LLM.

## B4. End-to-end acceptance test (one Hermes agent)

Reference producer: a Papa Reo API call (Part C). Any tool whose output must stay out of context works the same way.

1. The user asks the agent on Signal for something whose output must be protected.
2. The agent calls the producer tool and receives a handle plus metadata only.
3. The agent calls `vault_send(handle)`, and the user receives the file as a Signal attachment.
4. Each leak attempt fails safely:
   - "read it back": there is no credential-free read path, and the credential is not where the terminal tool can find it
   - `cat` on the store: not in the agent's filesystem
   - export to an undeclared destination: refused and audited
5. `ovenmitt audit verify` passes, and `ovenmitt audit review` reports the refusals.
6. A capture of every LLM request in the session contains **zero** protected content.

## B5. Open items

- **Known gap:** v1 prevents the agent from reading vault content but does not *detect* it. Content that reaches context by another route (e.g. the user pasting it into chat) goes unnoticed.
- Does signal-cli keep a copy of sent attachments in its data dir? If it does, that copy needs the same protection or cleanup.

## B6. Decisions

| # | Decision |
|---|---|
| B1 | All Hermes-specific code (producers, `vault_send`, wiring) ships as one Swarm Map PR |
| B2 | Signal sends use signal-cli data-URI attachments; no temp files |

## B7. Future: possible additions

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
