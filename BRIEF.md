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

**Added to v1 (2026-10-16): `resolve_path`.** Platform adapters send files by path, so a sender that goes through the harness's own send interface needs bytes that look like a file. `resolve_path(handle, destination, target, credential, filename)` resolves into a `memfd` (an anonymous, RAM-backed file on no filesystem) and yields a symlink named `filename`, in a private temp dir, pointing at `/proc/self/fd/N`. The name matters because adapters derive the attachment name and MIME type from the path. The path is one-shot: it lives for one `with` block, which is one send call, and then the descriptor is closed and the dir removed. No daemon change; the daemon checks and audits it like any `resolve`. Linux only. This supersedes the spawn-a-child-with-`/dev/fd/N` sketch in §10.2. The Python package's `mcp` dependency also became an optional extra (`ovenmitt[mcp]`), so the client installs beside whatever MCP version an agent image pins.

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
- ~~**`resolve_path`**~~: moved to v1 on 2026-10-16, as an in-process named symlink to the `memfd` rather than a spawned child (§10.1). A FIFO in the socket volume remains the fallback for already-running daemons, kept out until something needs it.

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
| 35 | (2026-10-16) `resolve_path` is v1: a one-shot `memfd` behind a named symlink, valid for one send call (§10.1) |
| 36 | (2026-10-16) `mcp` is an optional extra of the Python package; the base package depends on `httpx` only |
| 37 | (2026-10-16) Native harness tools that wrap the vault carry an `ovenmitt_vault_*` prefix, because a native tool has no server namespace and a harness may already call something else "the vault". The MCP face keeps `vault_*` (decision 19): its server namespace already says ovenmitt |

# Part B — Harness integration (Hermes and Swarm Map)

*This part is kept separate so that Part A stays harness-independent. It's recorded here because the v1 deliverable needs both halves, and the core must be designed so this integration is straightforward.*

*Amended 2026-10-16 after a design review. The original plan put all Hermes-specific code in one Swarm Map PR, with `vault_send` calling signal-cli directly. Both changed; the original text survives in git history.*

## B1. Where the integration lives (amended: three homes)

1. **Swarm Map PR, core wiring only:** the daemon as a per-agent compose service with its socket shared into the agent container, the generated operator config, custody of the consumer credential, and a settings card. Secret custody is what earns a place in Swarm Map itself.
2. **`hermes-plugin/` in this repo, the generic bridge:** a Hermes plugin (`register(ctx)`) that holds the consumer credential and registers native tools (`ovenmitt_vault_put`, `_list`, `_stat`, `_label`, `_delete`, `_list_destinations`, `_send`; no export), plus a generic `ovenmitt` skill. It has nothing domain-specific in it (decision 21), and it lives beside the core so the two version together.
3. **Producers in their own repos:** for example a transcription plugin that streams an API's response into `vault.put()` and gets back only a handle.

The consumer credential is given only to the bridge. It arrives as a compose `environment:` entry, never a file, and the plugin pops it out of the process environment into a closure at `register()`, so no terminal child inherits it. Residual, accepted and documented: `/proc/<gateway-pid>/environ` is readable by the same uid.

Later Swarm Map work: a vault/destination config API behind its UI, and an audit view with `review` findings on the dashboard. Deferred: inbound attachment diversion (chat uploads → vault, bypassing the agent).

## B2. Hermes facts (from source, 2026-10-12)

- Hermes has **no agent-callable send tool**, by design. The agent delivers files only by writing `MEDIA:/path` tags in its reply, and only to the current chat. That's why we ship `ovenmitt_vault_send`, registered via `ctx.register_tool`.
- *(Amended 2026-10-16.)* Every platform adapter has the same generic send interface, `send_document(chat_id, file_path, caption=…)`, and carries `self.platform`. The adapters read the file in-process: Signal's inlines it as an RFC 2397 data URI to signal-cli, and Discord's and Telegram's upload it directly. So one mechanism covers every platform: hand the adapter a `resolve_path` path. There is no per-platform code of ours, and no signal-cli special case.
- Sending outside the agent's reply does not write content to session history. Hermes's own `send_message` mirror records only a placeholder such as `[Sent document attachment]`.
- `pre_llm_call` **cannot block**; it can only add context. Hooks that can intervene are `pre_tool_call` (block), `transform_tool_result` (rewrite a tool result) and `transform_llm_output` (rewrite the reply). No Hermes hook can block a whole LLM request.

## B3. `ovenmitt_vault_send` flow (amended)

1. Read the current platform and chat from Hermes's session context, **never from the model's arguments** (the tool has no target argument; tested). Build `functools.partial(adapter.send_document, chat_id)` from the live adapter.
2. The bridge's `vault_send(handle, send)` accepts only that shape and derives the claim from the very callable that will send: destination = the adapter's platform, target = `<platform>/<percent-encoded chat id>`.
3. `with client.resolve_path(handle, destination, target, credential, filename) as p: await send(p)`. The daemon checks the target against that destination's pattern and audits both. The path dies with the block.
4. Return only `sent ✓` and metadata to the LLM.

v1 trusts the bridge to declare truthfully. The control that removes that trust is the content check behind an LLM proxy (§10.2, B7).

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
- ~~Does signal-cli keep a copy of sent attachments in its data dir?~~ Checked 2026-10-16: no. signal-cli streams uploads straight from the source (a data URI is decoded in memory); only *received* attachments go to its attachment store. Re-check against the signal-cli version a deployment actually runs.

## B6. Decisions

| # | Decision |
|---|---|
| B1 | ~~All Hermes-specific code ships as one Swarm Map PR.~~ Amended 2026-10-16: three homes. Core wiring and credential custody in Swarm Map; the generic bridge in `hermes-plugin/` here; producers in their own repos (B1) |
| B2 | ~~Signal sends use signal-cli data-URI attachments.~~ Amended 2026-10-16: every send goes through the platform adapter's own `send_document`, given a one-shot `resolve_path` path |
| B3 | The send target comes from session context only, never from model arguments |

## B7. Future: possible additions

- **Tool-result scrubber:** a `transform_tool_result` hook that calls the core `check` (§10.2) on every tool result and replaces any match with `[redacted: vault content]`. Tool output is the main way content enters context, and this hook can rewrite it.
- **LLM proxy:** Hermes's base URL pointed at a proxy that calls `check` on every outgoing request and refuses on a match. It's the only way to block a whole request, since no Hermes hook can.

# Part C — Motivating case: Papa Reo and the Kaitiakitanga License

This part is context for *why* the design is strict. Nothing in it is a mode, flag or name in the software.

The [Papa Reo API](https://papareo.io) is offered under the [Kaitiakitanga License](https://papareo.io/kaitiakitanga). Clause 3 of its API terms is the driver:

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
