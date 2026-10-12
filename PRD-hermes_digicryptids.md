# PRD — `llm-safe-kaitiaki` Part A (core) v1
**Docker-only. Part B integration treated as an external consumer.**
**Status: PRD draft for review. Derived from BRIEF.md (tumu, 2026-10-12). Ambiguities flagged, not guessed.**

---

## 0. Scope

This PRD covers **Part A v1 only**: the harness-independent core — one Rust daemon in its own Docker container, a Python client library, an MCP face, and an operator-only admin CLI (`audit verify` / `audit review`), plus a compose file.

**Out of scope for v1** (recorded so nothing here forecloses them): agent-facing CLI (`vput`), `vpipe`, local (non-Docker) mode, content search, content check, sealed producers, signed localhost URLs, partial edits, version retention.

**External consumers** (out of scope, contract-only): the Part B Swarm Map PR (Hermes plugin: producer tools, `vault_send`, wiring) consumes only the public surfaces defined here: the client library API (§4.1), the MCP tool schemas (§4.2), the socket protocol (§5), the config schema (§3), and the audit surfaces (§6).

## 1. Problem & goals

Agents must move, send and process data that must **never enter an LLM provider's context** because providers may retain or train on it, and licences/contracts/sovereignty obligations forbid it. Today every tool output an agent produces lands in a tool result, i.e. in the provider's hands.

**Goal:** a generic write-only sink. Data goes in; an opaque handle comes out; the agent can label, export and send **by handle**, and no path within the agent's reach can read the bytes back.

**Non-goals:** defending against a determined adversary (prompt-injection covert channels) or malicious tool code that lies about where it sends bytes. Protection targets **accidental** leakage, structurally (the OS says no), not by convention.

**Success criteria:** the Part B end-to-end acceptance test (BRIEF §B4) passes with a capture of every LLM request in the session containing zero protected content.

## 2. Concepts (normative definitions)

- **Vault** — a named, path-rooted store with its own config. Anything written into a vault is protected.
- **Handle** — stable opaque id, format `v_` + ≥12 base32/hriendly chars (e.g. `v_9c1e4a…`), generated from ≥64 bits of CSPRNG. Handles are **globally unique across the daemon** (see AMB-7).
- **Object** — whole-object, atomic. `put` commits on stream close; a crash mid-stream leaves no half-object. `put(replace=)` streams a new body under the same handle and **deletes old bytes immediately**.
- **Destination** — a **named** target declared per vault by the operator. Kinds: `fs` (export root) and `send` (a pattern string that resolving tool code must declare; the daemon does not know what platforms are). Default **deny**: nothing is a destination until declared.
- **Operator** — the human who deploys and configures, via a config file the agent cannot read or write. Only the operator declares destinations; agent and end users can *use* declared names only.
- **Consumer credential** — a daemon-issued secret given by the operator to specific tool code. Required for `resolve`, never present in the agent's shell/PATH.
- **Faces** — (v1) the Python client library, the `vault mcp` server, and the operator-only admin CLI inside the daemon container. **No read command exists on any face.**

## 3. Configuration (operator-only)

### 3.1 File & precedence
One TOML file, default `/etc/vaultd/config.toml` in the daemon container, path overridable by env `VAULTD_CONFIG`. Mounted read-only from the host. The agent container never sees it.

### 3.2 Schema

```toml
# /etc/vaultd/config.toml — operator-only, agent cannot read or write
socket   = "/run/vaultd/vault.sock"     # Unix socket, bind-mounted into consumer containers
data_dir = "/var/lib/vaultd/store"      # ciphertext objects, daemon container only
key_dir  = "/var/lib/vaultd/keys"       # per-vault keys, daemon container only
audit    = "/var/lib/vaultd/audit.jsonl" # append-only, daemon container only

[vault.private]                          # vault name: generic, no domain names (see NI-15)
expose_names = false                     # default false; real filenames hidden in metadata
ttl          = "30d"                     # OPTIONAL, unset by default

[vault.private.destinations]
nas-archive = { kind = "fs",   root = "/srv/nas/archive" }
team-send   = { kind = "send", match = "chat:group/team" }         # pattern is an OPERATOR VALUE
dm-body     = { kind = "send", match = "chat:dm/*", as = "body" } # bytes sent as message text

[vault.media]
# … same shape, one block per vault

[review]
rules      = "/etc/vaultd/review.toml"   # rule-based review config (§6.4)
# threshold / cron behaviour defined §6.4
```

### 3.3 Validation rules (fail-closed at startup)
V-1 Unknown key in a `vault` block → refuse to start (no silent ignore).
V-2 `ttl` format: integer + `d`/`h`/`m`; unparsable → refuse to start.
V-3 `kind = "fs"` requires `root`; `kind = "send"` requires `match`; `as = "body"` only valid on `send`.
V-4 Destination names unique per vault; vault names match `^[a-z][a-z0-9_-]*$`.
V-5 `match` pattern grammar: a **prefix path with a single trailing `*` wildcard segment allowed** — `chat:group/team`, `chat:dm/*`. (Full grammar in §7-SEND; flagged AMB-4.)
V-6 No domain-specific names (platforms, licences, providers, communities) in **code, config keys or defaults** — operator-*values* (like `match` patterns) are the operator's own and unrestricted (flagged AMB-13).

## 4. Operations & faces

### 4.1 Python client library (tool authors)
```python
h = vault.put(stream, vault="private", *, labels=[], mime=None,
              filename=None, replace=None, remove_source=None)   # → Handle(metadata)
# put accepts a stream ONLY. No bytes-in-args variant exists.
vault.stat(handle)          # metadata only
vault.list(vault)           # handles + metadata only
vault.label(handle, labels) # add human labels (strings), never content
vault.delete(handle)        # delete object; audited
vault.list_destinations(vault)  # names only, never roots/patterns
vault.export(handle, destination, filename, *, overwrite=False)
with vault.resolve(handle, destination) as stream:   # LIB ONLY, credential required
    ...
```
- `resolve` presents the consumer credential (from env/config given to the tool process by the operator, never the agent's env — see NI-13); the daemon checks it and the **declared destination string** against the vault's allowlist, and audits every call.
- `remove_source` deletes the original file after successful commit (client-side unlink).
- Library error surface: Python exceptions carrying the error codes of §8.

### 4.2 MCP face (`vault mcp`)
Runs **beside the agent**, in the agent's container, as a thin client over the shared socket. Tool set (v1):

| Tool | Params | Notes |
|---|---|---|
| `vault_put` | `path`, `vault`, `labels?`, `mime?`, `replace?`, `remove_source?` | **path only** — the MCP server reads the file and streams it; no content param exists in the schema |
| `vault_stat` / `vault_list` / `vault_label` / `vault_delete` | as library | metadata only |
| `vault_export` | `handle`, `destination`, `filename`, `overwrite?` | agent-reachable (see AMB-1) |
| `vault_list_destinations` | `vault` | names only |

No `vault_resolve` tool exists. No tool parameter anywhere accepts content bytes.

### 4.3 Admin CLI (operator-only, inside daemon container)
`vault audit verify [--chain-file]` and `vault audit review [--since] [--threshold]`, run via `docker exec`. Not reachable from the agent container (no socket exposure, no exec rights for the agent user).

### 4.4 Explicitly not in v1
`vput` CLI, `vpipe`, search, filter, preview, concat/transforms, partial edits, version retention, content check, signed localhost URLs.

## 5. Socket & wire protocol (v1)

One Unix domain socket (`socket` config), shared (bind-mounted) into consumer containers. Mode `0660`, owning group shared across the daemon + consumer containers (compose-managed).

**Framing.** Mixed protocol over one connection:
- **Control frames:** NDJSON, one JSON object per `\n`.
- **Data frames (binary):** `0x01` magic, `u32 LE length`, raw bytes. Data frames are only legal in three places: client→server during `put` streaming, server→client during `resolve` streaming, and are illegal everywhere else (protocol error → connection dropped + refusal-audit `proto_violation`).

**Handshake (first control frame):**
```json
{"op":"hello","v":1,"role":"agent"|"consumer","cred":"…"}
```
- `role:"agent"` → MCP/library client without credential: may do everything except `resolve`.
- `role:"consumer"|"agent"` + `cred` → may additionally `resolve` (credential checked per call; see AMB-11 re: peer identity in Docker).

**Operations (control frames, request→response):**

```json
{"op":"put_begin","vault":"private","labels":["memo"],"mime":"audio/mpeg",
 "filename":null,"replace":null}
  → data frames (client streams bytes; daemon spills to a temp file in data_dir)
{"op":"put_end","sha256":"<client-computed>","remove_source":null}
  → {"ok":true,"handle":"v_…","size":2188123,"mime":"audio/mpeg","mtime":"…"}
```
- Daemon verifies the streamed bytes against `sha256` before commit → integrity without reading content into audit (hash is audit-visible by design: BRIEF "content hashes are kept in the audit log only").
- Commit is atomic: temp file → per-vault key encryption (AES-256-GCM, one key per vault, keys in `key_dir`) → rename into place. Crash before rename = no object.

```json
{"op":"stat","handle":"v_…"}            → metadata object
{"op":"list","vault":"private"}         → {"objects":[{handle, size, mime, mtime, labels, name?}]}
{"op":"label","handle":"v_…","labels":[]} → {"ok":true}
{"op":"delete","handle":"v_…"}           → {"ok":true}
{"op":"list_destinations","vault":"private"} → {"destinations":["nas-archive","team-send","dm-body"]}
{"op":"export","handle":"v_…","destination":"nas-archive","filename":"memo.txt","overwrite":false}
                                         → {"ok":true,"path_visible":false}
{"op":"resolve","handle":"v_…","destination":"chat:group/team"}
   → {"ok":true,"stream":true} … data frames … {"end":true}
```

**Metadata object:** `{handle, vault, size, mime, mtime, labels[], name?}` — `name` present **only** when `expose_names: true` (else omitted entirely, not nulled).

**Export filename rules (E-rules):** the daemon sanitises, rejects absolute paths, any `..` component, empty names, NUL/control chars, and rejects collisions unless `overwrite: true`. The destination root is **resolved + confined**: symlink escape from `root` is refused (see NI-6 test).

**Send patterns (§7-SEND):** `resolve(handle, destination)` — here `destination` is the **declared destination name**; the daemon resolves the name to the vault's declared `match` pattern, and the **resolving tool code must additionally declare the live target string** (e.g. `chat:group/team`), which the daemon matches against the pattern. Design decision: matching is **against the declared string only** — the daemon never learns real chat metadata (see AMB-5).

```json
{"op":"resolve","handle":"v_…","destination":"team-send","target":"chat:group/team"}
```

**Versioning:** `"v":1`; unknown ops/fields → protocol refusal (audited).

## 6. Audit

### 6.1 Store
Append-only JSONL at `audit` path. Hash-chained: each entry contains `prev` (the hash of the previous entry); `entry_hash = sha256(canonical-json(entry))`. Chain head anchoring off-host is a **documented manual step** in v1 (operator copies the head hash somewhere durable; automated later).

### 6.2 Record format (one per line)
```json
{"ts":"2026-10-12T09:41:00Z","event":"put|replace|delete|export|resolve|ttl_expiry|refusal|proto_violation",
 "vault":"private","handle":"v_…","version_sha256":"…","dest":"team-send",
 "caller":{"role":"consumer","cred_id":"c-tool"},"target_declared":"chat:group/team",
 "outcome":"ok|refused","reason":null,"prev":"sha256:…"}
```
- **Never logged:** content, real filenames (unless `expose_names`), resolved paths/URLs, destination roots or match patterns.
- **Every refusal of any kind** is an event, with `reason` = error code (§8) and the requested destination name.

### 6.3 `vault audit verify`
Recomputes the chain (prev linkage + entry hashes) over the whole file. Output: `ok N entries, head sha256:…` or a specific first-broken entry; exit 0 / 1.

### 6.4 `vault audit review`
Rule-based, rules in `review.toml`; severity-ranked; **cron-friendly**: findings → stderr as JSONL; exit nonzero at/above `--threshold` (default `warn`).

Built-in rules (all overridable/extendable in rules file):
| Rule | Flags | Default severity |
|---|---|---|
| any `outcome:"refused"` | refusals | high |
| first use of a destination (not seen earlier in log) | first-time destination | warn |
| ≥N `resolve` in window W (default N=20, W=1h) | bursts | high |
| ≥N `export` in window W | bursts | warn |
| ≥N `delete`/`replace` on one handle in window W | churn on a handle | warn |
| chain failure | — | critical |

`--since` filters by timestamp. Review reads the log only; it never resolves bytes.

## 7. Security invariants (testable statements)

| ID | Invariant |
|---|---|
| NI-1 | No operation on the library or MCP faces returns object bytes. |
| NI-2 | The store and key directories do not exist in the agent container's filesystem (only the socket is shared). |
| NI-3 | `resolve` without a valid consumer credential is refused and audited. |
| NI-4 | `resolve` against a destination not declared on that vault is refused and audited. |
| NI-5 | `resolve` whose declared target string does not match the destination's `match` pattern is refused and audited. |
| NI-6 | `export` filenames are confined to the destination root: `..`, absolute paths, symlink escapes and control chars are refused and audited. |
| NI-7 | `put` is atomic: a daemon crash mid-stream leaves no partial object (no new handle, no new store file). |
| NI-8 | `replace` deletes the old bytes immediately: after commit, the previous object's ciphertext is absent from the store. |
| NI-9 | Objects are encrypted at rest (AES-256-GCM, per-vault key); no plaintext byte-run of any object appear in store files. |
| NI-10 | Vault keys never leave the daemon container (no bind-mount of `key_dir`, no key material in any response/audit line). |
| NI-11 | The audit log is append-only and hash-chained; `verify` detects any mutation that breaks the chain. |
| NI-12 | Every refusal of every kind is an audit event. |
| NI-13 | The operator config is not readable/writable by the agent; the admin CLI is unreachable from the agent container. |
| NI-14 | The MCP `vault_put` schema accepts a path only — no parameter carries content bytes. |
| NI-15 | Handles embed ≥64 bits CSPRNG; guessing a live handle is infeasible (per-object authorisation is by handle knowledge + face rules). |
| NI-16 | TTL expiry deletes objects and emits `ttl_expiry` audit events without any read path. |
| NI-17 | No domain-specific names (platforms, licences, providers, communities) appear in core code, config keys or defaults. |

## 8. Error model

String error codes on every face (exceptions in the library, JSON `{"error":"E_…"}` on the wire, tool errors in MCP):

| Code | Meaning | Face |
|---|---|---|
| `E_NOENT` | unknown handle / vault / destination name | all |
| `E_PERM` | missing or invalid consumer credential (resolve) | lib |
| `E_POLICY` | destination not declared on vault; target/pattern mismatch | lib, MCP(export) |
| `E_PATH` | filename sanitisation/confine failure | MCP(export), lib |
| `E_EXISTS` | export collision without `overwrite:true` | lib, MCP |
| `E_ENCODING` | `as="body"` destination received non-UTF-8 bytes (see AMB-9) | lib |
| `E_PROTO` | protocol violation (bad frame, data frame outside stream) | wire |
| `E_IO` | storage/IO failure | all |
| `E_CHAIN` | audit chain broken (verify) | admin |
| `E_VAULTKEY` | vault key missing/unreadable → vault read-degraded: put/export/resolve refused, metadata ops still answer | all |

Refusals (`E_PERM`, `E_POLICY`, `E_PATH`, `E_ENCODING`, `E_PROTO`) are **always audited**.

## 9. Deployment (v1, Docker-only)

`docker-compose.yml` in-repo:
- `vaultd` service: Rust daemon image; volumes: `data_dir`, `key_dir`, `audit`, config (ro), socket dir.
- Socket dir bind-mounted into each **consumer** container (agent containers, tool containers). Nothing else crosses the boundary.
- Agent-side pieces (Python lib, MCP server) install into consumer images; **no store/key material ever mounts into them**.

Key lifecycle v1: keys generated at first vault use, stored in `key_dir` (0600). No KMS. **Losing a vault key = losing the vault** — stated in README (BRIEF: "docs say so").

## 10. Acceptance test plan (no harness)

Environment: compose stack of `vaultd` + a "client" container holding the library + a test MCP client. Each TC lists steps, expected result, and the requirement IDs it covers.

| TC | Test | Requirement IDs |
|---|---|---|
| TC-1 | `put` via library (stream) returns handle + metadata only; no bytes in response. | FR-PUT, NI-1 |
| TC-2 | `put` via MCP (path) same. Schema inspection: `vault_put` has no content param. | FR-PUT, NI-14 |
| TC-3 | Test consumer with credential resolves handle against declared send destination; byte-exact stream received (sha256 compare). | FR-RESOLVE |
| TC-4 | `resolve` with no/invalid credential → `E_PERM`, refusal in audit. | NI-3, NI-12 |
| TC-5 | `resolve` to undeclared destination → `E_POLICY`, audited. | NI-4 |
| TC-6 | `resolve` with non-matching target string → `E_POLICY`, audited. | NI-5 |
| TC-7 | Enumerate all ops on both faces; grep responses for object bytes → zero. | NI-1 |
| TC-8 | `docker exec` into client/agent container: `data_dir`/`key_dir` paths absent; `cat` store impossible. | NI-2 |
| TC-9 | Export filename cases: `../`, absolute, symlink inside root → `E_PATH`, audited. | NI-6 |
| TC-10 | Kill daemon mid-put; restart; `list` shows no new object; store dir has no new file; no half-object. | NI-7 |
| TC-11 | `replace`; immediately after commit, old ciphertext absent from store (byte-scan). | NI-8 |
| TC-12 | Scan store files for plaintext fragments of a known object → none (GCM ciphertext). | NI-9 |
| TC-13 | Attempt `resolve`-stream then read a key file from client container → impossible (no mount). | NI-10 |
| TC-14 | Corrupt/truncate audit log; `vault audit verify` → `E_CHAIN`, exit 1. Clean log → exit 0, head hash printed. | NI-11 |
| TC-15 | Trigger each refusal (TC-4/5/6/9 + `E_EXISTS`); run `review` → every refusal reported, exit nonzero. | FR-REVIEW, NI-12 |
| TC-16 | Agent container: config file unreadable; admin CLI not present; socket is the only daemon surface. | NI-13 |
| TC-17 | Config with unknown key / bad ttl → daemon refuses to start (fail-closed). | V-1, V-2 |
| TC-18 | Handles over ≥10k puts: no collision; entropy check on sampled handles. | NI-15 |
| TC-19 | Vault with `ttl:"1m"`: after expiry, `stat` → gone, audit contains `ttl_expiry`. | FR-TTL, NI-16 |
| TC-20 | Grep daemon source/config defaults for platform/licence/provider names → none. | NI-17 |

**End-to-end with a real agent** is Part B's acceptance (BRIEF §B4) — out of scope here, but nothing in this PRD blocks it (library + MCP + credential + compose are the complete contract Part B needs).

## 11. Requirements index (FR)

| ID | Requirement |
|---|---|
| FR-PUT | `put(stream|path)` → handle+metadata; `remove_source`, `replace=`; atomic commit; sha256-verified |
| FR-RESOLVE | lib-only `resolve(handle, destination, target)` with consumer credential; allowlist + pattern match; streamed bytes |
| FR-EXPORT | `export(handle, destination, filename)`; sanitised, confined, collision → `E_EXISTS` unless overwrite |
| FR-META | `stat`, `list`, `label`, `delete`, `list_destinations` — metadata only; `name` only with `expose_names` |
| FR-TTL | optional per-vault `ttl`; expiry deletes + audits |
| FR-AUDIT | hash-chained JSONL; events per §6.2; never content; `verify` + rule-based `review` (cron-friendly) |
| FR-ENCRYPT | AES-256-GCM per-vault keys, daemon-container-only |
| FR-FACES | library + MCP + operator admin CLI; no read command anywhere |
| FR-CONFIG | TOML operator-only; validation fail-closed; default deny destinations |
| FR-DEPLOY | Docker-only v1; compose file; socket-only boundary |

## 12. Ambiguities & contradictions in the BRIEF (flagged, not guessed)

**AMB-1 — Does `export` require a consumer credential?** The brief requires a credential only for `resolve`. But `export` also moves plaintext bytes out of the vault (to a declared fs root). If the *operator* fully trusts every declared export root and the agent, agent-reachable export without credential is consistent with the accidental-leak threat model; if not, export should be credential-gated like resolve. **PRD assumes: export is agent-reachable without a credential (credential gates resolve only), matching the brief literally — confirm.**

**AMB-2 — Which face(s) may export?** If export is credential-free (AMB-1), is it exposed on MCP, library, or both? PRD assumes both (§4.2 lists `vault_export`). Confirm.

**AMB-3 — `version hash` (audit field) vs "content hashes are kept in the audit log only":** same thing? PRD assumes yes: `version_sha256` = sha256 of the committed object bytes, logged but never returned by `stat`. Confirm.

**AMB-4 — Send-pattern grammar is unspecified.** `match = "signal:group/team"`, `"signal:dm/*"` — prefix? glob? regex? And is `*` only allowed as a trailing segment? PRD defines (§5, V-5): **prefix match with one optional trailing `*` segment**; no regex. Confirm this matches what the resolving tools will declare.

**AMB-5 — Who validates the "live target string" in `resolve`?** The brief says tool code "must declare" the destination pattern when it resolves bytes, and the daemon checks the declared name against the allowlist. But a *pattern* (`chat:dm/*`) needs something concrete to match against. PRD resolves this as: `resolve` takes **destination name + declared target string**; the daemon matches the declared string against the declared pattern. This trusts tool code to declare truthfully (consistent with the threat model: accidental leakage, not malicious tools). Confirm.

**AMB-6 — Handle scope: per-vault or global?** PRD assumes globally unique handles (simplest for audit chains); `replace` confined to the same vault. Confirm.

**AMB-7 — TTL is per-vault only** (no per-object TTL in v1). PRD assumes yes per the config sketch. Confirm.

**AMB-8 — `body` destinations and encoding:** `as = "body"` sends bytes as message text — UTF-8 only? What happens on binary? PRD: `E_ENCODING` refusal on invalid UTF-8 (audited). Confirm.

**AMB-9 — `review` threshold values:** severity names and the default threshold are PRD-invented (`critical > high > warn > info`, default `warn`). Confirm or supply the intended vocabulary.

**AMB-10 — Peer identity in Docker:** audit `caller` is "peer UID or credential id". In v1 Docker, UIDs across containers are host-kernel-comparable, but consumer containers may all run as the same UID. PRD: caller = **credential id when presented, else the client-declared role** (`agent`), with the caveat that role-declaration is self-attested on the socket in v1 — acceptable only because the threat model excludes malicious clients. **Flag: this is the weakest point of v1's story; local-mode SO_PEERCRED (§10.2 future) is the real fix. Confirm acceptable for v1.**

**AMB-11 — `remove_source` on MCP `put`:** deletion happens client-side in the MCP server's container (it's the one that read the path). PRD assumes so. Confirm.

**AMB-12 — Label semantics:** labels are free-form strings, visible in `stat`/`list`; any length/content limit? PRD assumes ≤1KB total, UTF-8. Confirm.

**AMB-13 — Internal tension, §7 vs decision 21:** the config sketch uses `signal:…` patterns while decision 21 forbids platform names in core code/keys/defaults. PRD reading: **values are operator data, not core defaults** — so `signal:` in an operator's config is fine, but no shipped example/default uses platform names (PRD uses `chat:…`). Confirm this reading.

**AMB-14 — Key loss:** "losing a vault key means losing the vault" — v1 behaviour is refusal with `E_VAULTKEY` for any byte-touching op on that vault, metadata ops unaffected. Confirm.

---

*No code has been written. This PRD is posted to the #bounties-work thread for comparison against Miles's independently-drafted PRD. Open items above (AMB-1…14) are questions for the brief author, not assumptions to silently bake in.*