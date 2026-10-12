# llm-safe-kaitiaki — PRD (Part A, core, v1)

*Status: draft 0.2, 2026-10-12. Derived from BRIEF.md (decisions 1–22), reconciled against the independent second review (`PRD-hermes_digicryptids.md`; see Appendix A). Scope: Part A only, Docker only. Part B is treated here as an external consumer of Part A's interfaces (§10). No code exists yet.*

**How to read this.** Requirements carry IDs (`R-xxx-n`), security invariants carry `SI-n`, tests carry `AT-n`. MUST/SHOULD/MAY are RFC 2119. Anything marked **PROVISIONAL** is a position this PRD takes where the brief is silent or inconsistent; §0 lists every such point so they can be decided rather than inherited by accident.

---

## 0. Flags: ambiguities and contradictions in the brief

Each item: where it is in the brief, what's wrong, and the provisional position taken below. The **2nd** column marks items the second, independent review also raised (its `AMB-n`); two reviewers hitting the same seam from the same brief is strong evidence the brief, not the reviewer, is at fault. These should be resolved before the development document; several change the API.

| # | 2nd | Brief ref | Issue | Provisional position in this PRD |
|---|---|---|---|---|
| F-1 | — | §5.1, §9.3 | "No read command exists on any face" and acceptance test 9.3(a) "there is no read command on the library" contradict §5.1's own statement that the library resolves bytes. The library runs in the agent container; anything the agent's shell can `import`, it can call. The *only* barrier to reading is the consumer credential, not the absence of a code path. (The second review repeated the brief's claim verbatim as its NI-1 — which shows how easily this overclaim propagates.) | Restated as: no **credential-free** read exists on any face, and the daemon's socket protocol (not any client) is the enforcement boundary. §9.3(a) becomes AT-7. The docs must say the credential is the read barrier. |
| F-2 | AMB-5 | §6 vs §B3 | `resolve(h, destination)` takes a destination *name* in §6; `resolve(handle, "signal:<chat>")` takes a concrete *target string* in §B3. A name alone enforces nothing about where bytes actually go; a bare target string leaves the audit log without a destination name. **Both reviews independently landed on the same fix.** | `resolve(handle, destination, target)`: the consumer names the declared destination **and** the concrete target; the daemon checks the target against that destination's pattern. Trusts tool code to declare truthfully — consistent with the threat model (malicious tool code out of scope). |
| F-3 | AMB-4 | §7 | `match` pattern language unspecified (`signal:dm/*`). | **Narrowed after review:** a literal string, optionally ending in `/*` meaning "exactly one more non-empty segment with no `/`". No other wildcards, no regex. A security matcher wants the smallest grammar that covers the known cases; widening later is backward-compatible, narrowing is not. The scheme prefix (`chat:`) is a convention between operator and consumer; the daemon does not interpret it. |
| F-4 | AMB-8 | §7 | `as = "body"` ("bytes sent as message text") cannot be enforced by a daemon that "doesn't know what Signal is". It is advice to the consumer. Brief also says nothing about binary bodies or a size bound. | `as` is returned to the consumer in the resolve response and audited; the *send* is the consumer's. The daemon does enforce two cheap preconditions for `body` destinations: valid UTF-8 (`ENCODING_INVALID`, adopted from the second review) and optional `max_size` (`TOO_LARGE`). |
| F-5 | — | §6 | `overwrite: true` on export: an agent-supplied argument or operator config? | Per-destination config key `overwrite` (default `false`). Operator posture: the agent never widens what a destination permits. Alternative (agent argument) noted if you prefer Unix semantics. |
| F-6 | AMB-10 | §8 "caller (peer UID …)" | In Docker, every process in the agent container (MCP server, terminal tool, `vault_send`) shares one UID, and both containers often run as the same UID. Peer UID cannot distinguish callers and must not be relied on for anything. **Both reviews call this the weakest point of v1.** Any client-declared "role" (the second review's `hello` handshake) is self-attestation and adds nothing. | `caller` records `{uid, pid, cred}` for forensics only. Authorisation is: credential present and valid → *consumer*; otherwise → *agent*. Nothing else. The real fix (`SO_PEERCRED` with a dedicated `vaultd` user) is local mode, future. |
| F-7 | — | §5.1 | "Keys live in the daemon container" — if key files sit in the same volume as the ciphertext, encryption at rest defends only against a backup of that one volume. Container isolation already keeps the agent out. What is at-rest encryption *for*? | Keys in a separate named volume (`lsk-keys`) from data (`lsk-data`); docs state exactly what this does and doesn't protect. Operator-supplied passphrase/KMS wrapping deferred. Needs a yes/no. |
| F-8 | — | §4, §6 | "Old bytes are deleted immediately" — `unlink` on overlayfs/SSD is not erasure. | Per-object data key (DEK) wrapped by the per-vault key (KEK). Delete/replace/expire = unlink ciphertext **and** destroy the wrapped DEK (crypto-shred). Docs say no physical erasure is claimed. |
| F-9 | — | §6 | No way for the agent to discover vault names, yet `put` requires one. (Second review has the same gap and didn't notice.) | Add `list_vaults` (names, `expose_names`, `ttl`). |
| F-10 | — | §7, §18 | TTL: measured from creation or last `replace`? On expiry, does the handle vanish or tombstone? Per-object TTL? | From the last body commit (replace resets). Expired = gone; `stat` → `NOT_FOUND`. Per-vault only in v1 (agrees with AMB-7). |
| F-11 | — | §8 events | `label` not listed as audited; `stat`/`list` not mentioned. Churn detection wants metadata writes. | `label` audited (event only, not label text). `stat`/`list` not audited. |
| F-12 | — | §4 | Who determines MIME type? Sniffing is a read, albeit inside the daemon. | Client-declared; default `application/octet-stream`; daemon never sniffs. |
| F-13 | AMB-11 | §6 MCP `put(path)` | Anything on the agent's disk is already readable by the agent; MCP `put` protects from the moment of commit, not before. And `remove_source` runs in the MCP process, so the daemon can only audit it as a client *claim*. The brief should say both. | Documented limitation (§11). `remove_source` is a client-side flag; the daemon records `remove_source_requested`, never that it happened. |
| F-14 | AMB-12 | §4 "human labels are always visible" | Labels are agent-visible and agent-settable. A producer tool that labels an object with content (a transcript's first line, say) leaks through metadata. | Label ≤ 256 bytes, ≤ 16 labels per object, documented warning for tool authors. Label text is never written to the audit log. |
| F-15 | — | §4 `expose_names` | With `expose_names=false`, is the original name stored-but-hidden or discarded? If stored, flipping the flag later reveals history. | Stored in encrypted metadata; shown only while `expose_names=true`. Flip-reveals-history is documented. Alternative: discard at put. |
| F-16 | — | §5.1, §7 `kind="fs"` | An `fs` root that the operator also mounts into the agent container is a read path. Nothing in core can detect it. | Documented as an operator invariant (§11); the shipped compose file never does it; `review` cannot flag it. |
| F-17 | — | §5.1, §2 | Names: binary `vault` collides with HashiCorp Vault; Python module `vault` is too generic for PyPI. (Second review uses `vault`/`vaultd` unflagged.) | **PROVISIONAL** binary `lsk`, daemon `lskd`, Python package `lsk` (`from lsk import VaultClient`), MCP server `lsk mcp`, admin CLI `lsk audit …`. Decide; a global rename is cheap now and expensive later. |
| F-18 | — | §4 consumer credential | Scope unspecified: per vault? per destination? all vaults? | Credential = `{id, name, vaults: [...] \| "*"}`. Destination allowlist is per vault, not per credential. |
| F-19 | — | §7 | Config reload semantics. | Restart only; config SHA-256 recorded in the `start` audit event. |
| F-20 | — | silent | Several agent containers on one daemon? | Out of scope: one daemon, one agent trust domain. Documented. |
| F-21 | AMB-9 | §9.4 | "`review` reports every refusal and exits nonzero" only holds if refusal severity ≥ threshold by default; severity vocabulary is unspecified. | Vocabulary `low < medium < high < critical`; refusal = `high`, default threshold `medium`. |
| F-22 | — | §8 | Log growth and rotation unspecified; chain across files undefined. | Single file in v1, no rotation; `review --since` still scans the whole file (first-time detection needs history). Rotation + cross-file chaining is future. |
| F-23 | — | §5.1 "Unix socket" | Wire format unspecified. | HTTP/1.1 over UDS (§4). Rationale: bidirectional streaming for free, `curl --unix-socket` testable, hyper + httpx both support it. Risk: an HTTP server invites a TCP listener; forbidden by R-DEP-3 / SI-2. The second review chose NDJSON control frames + length-prefixed binary frames; see Appendix A for why this PRD doesn't. |
| F-24 | — | §4 `put --replace` | Mid-stream failure of a replace: is the old body kept? Brief only says no half-object. | Old body retained until the new one commits; then old DEK destroyed. |
| F-25 | — | §B2/§B3 (for Part B) | Hermes's `send_message` mirror records a placeholder for *attachments*. For `as="body"` sends, does the mirror record the message *text*? If so, body sends put content into session history and `as="body"` is unsafe under Hermes. Not Part A's to fix, but it decides whether `as="body"` ships at all. | Part A keeps `as="body"` as a destination type. Part B must answer this before declaring any `body` destination. |
| F-26 | AMB-1/2 | §4, §6 | `export` moves plaintext out of the vault with **no credential**, while `resolve` needs one. The brief never says why. The asymmetry is defensible — an `fs` root is fully operator-fixed, so there is no target for the caller to lie about, whereas `resolve` hands bytes to code that will send them somewhere, so the credential identifies *trusted code* — but it must be a decision, not an accident. | Export stays credential-free and on both faces (library + MCP). Rationale goes in the docs. Alternative: `require_credential = true` per `fs` destination. |
| F-27 | — | §8 vs Part C | The brief says never log "resolved paths or URLs", meaning the daemon's own secrets (roots, storage paths). Is the consumer's declared `target` (a chat id, possibly a phone number) one of those? Not logging it means the audit can only say "went to some DM", which undercuts Part C's "confident about what did and didn't happen to their data". Logging it puts recipient identifiers in the log. (Second review logs it unconditionally as `target_declared`.) | Per-destination `audit_target` (default `false`). The operator, who knows the privacy context of the recipients, decides. |
| F-28 | AMB-14 | §5.1 "losing a vault key means losing the vault" | Daemon behaviour on a missing key is unspecified: refuse to start (loud; takes every vault down) or degrade one vault? | **Changed after review:** start, mark the vault *degraded*, refuse byte-touching ops on it with `VAULT_DEGRADED`, answer metadata ops, write a `start` audit entry naming the degraded vault, and have `review` flag it `critical`. Loud without collateral damage. |
| F-29 | AMB-13 | §7 vs decision 21 | The config sketch uses `signal:` patterns; decision 21 bans platform names in core code, config keys and defaults. | Operator *values* are the operator's and unrestricted. Shipped examples, defaults and tests use generic `chat:…`. (My draft 0.1 violated this in §5.1; fixed.) |

The brief's §11 "Open items: none" is therefore wrong; F-1, F-2, F-6, F-7, F-17, F-26, F-27 at least belong there.

---

## 1. Scope

### 1.1 In scope (v1)
- Rust daemon (`lskd`) in its own Docker container: store, keys, audit log, config, TTL sweep.
- Unix-socket wire protocol (§4) as the sole interface to the daemon.
- Python client library: `put` and metadata ops for anyone; `resolve` for credential holders.
- MCP server (`lsk mcp`) running in the agent container, exposing path-`put` and metadata ops only.
- Operator admin CLI inside the daemon container: `audit verify`, `audit review`, `audit head`, `credential issue|list|revoke`, `config check`.
- A reference `docker-compose.yml` with daemon + socket volume + a stub agent service.
- Docs: threat model, operator invariants, limitations.

### 1.2 Out of scope (v1)
Agent-facing CLI, `vpipe`, local mode, search, content check, sealed producers, signed URLs, transforms, version retention, multi-agent tenancy, log rotation, key rotation, TCP transport. Everything Hermes/Signal/Papa Reo-specific (Part B, Part C).

### 1.3 Deliverables
`lskd` image; `lsk` Python package (client + MCP server); compose file; docs; test suite executing §9.

---

## 2. Actors and trust boundaries

| Actor | Where | Trust |
|---|---|---|
| **Operator** | host; `docker exec` into daemon container | Trusted. Writes config, holds admin CLI, issues credentials. |
| **Daemon** (`lskd`) | daemon container | Trusted. Sole holder of plaintext, keys, audit log, config, destination roots/patterns. |
| **Agent trust domain** | agent container: LLM via harness, terminal tool, MCP server process, Python lib, consumer tool code | Untrusted for *reading*. Everything here can open the socket. |
| **Consumer** | tool code in the agent container holding a credential | Trusted to send bytes only where it declares. Distinguished from the rest of the agent domain by the credential and nothing else (F-6). |

**The boundary is the socket protocol.** No client-side code is load-bearing. Any property that depends on the MCP server or Python library behaving is a convenience, not a guarantee, and §8 says so for each.

---

## 3. Requirements

### 3.1 Vaults (R-VLT)
- **R-VLT-1** A vault is a named store declared in operator config. Name grammar: `^[a-z0-9][a-z0-9_-]{0,63}$`.
- **R-VLT-2** Each vault has its own 256-bit key (KEK), generated by the daemon on first start for that vault, stored only in `keys_dir`. A vault whose key is missing or unreadable at startup is **degraded** (F-28): `put`, `replace`, `export`, `resolve` on it → `VAULT_DEGRADED` (refusal); `stat`, `list`, `label`, `delete` answer normally; the `start` audit entry lists degraded vaults; `review` flags it `critical`. The daemon never generates a replacement key for a vault that has objects.
- **R-VLT-3** Per-vault settings: `expose_names` (default `false`), `ttl` (optional), `max_object_size` (optional), `destinations` (map, default empty = deny all).
- **R-VLT-4** `list_vaults` returns `[{name, expose_names, ttl}]` to any caller. Nothing else about a vault is agent-visible.

### 3.2 Objects and handles (R-OBJ)
- **R-OBJ-1** Handle = `v_` + 12 lowercase hex chars (48 bits) from a CSPRNG; unique across the daemon; stable for the object's life, including across `replace`. Handles are identifiers, not secrets: `list` reveals them, and knowing one grants nothing a listing wouldn't. (The second review's "≥64 bits so guessing is infeasible" assumes a secrecy property this design doesn't rely on.)
- **R-OBJ-2** Agent-visible metadata is exactly: `handle, vault, size, mime, created, modified, labels[], expires_at?` and `name` only while the vault has `expose_names=true`. Never: content hash, storage path, key material, destination details.
- **R-OBJ-3** Objects are whole and atomic. A `put` commits only when the request body terminates cleanly; any other outcome leaves no object and no partial file visible to any operation. Temp files are swept at startup.
- **R-OBJ-4** `replace` streams a new body under an existing handle. The old body remains until the new one commits (F-24); on commit the old ciphertext is unlinked and its DEK destroyed. `modified` updates; `created`, labels and `name` carry over unless `name` is supplied again.
- **R-OBJ-5** `delete` unlinks ciphertext and destroys the DEK. Subsequent ops on the handle → `NOT_FOUND`.
- **R-OBJ-6** TTL: `expires_at = modified + ttl`. A sweep (interval configurable, default 5 min) deletes expired objects with audit event `expire`. Any op on an expired-but-unswept object behaves as `NOT_FOUND` and triggers its deletion.
- **R-OBJ-7** `mime` is client-declared (`Content-Type`); default `application/octet-stream`; daemon never inspects bytes to infer it (F-12).
- **R-OBJ-8** Labels: UTF-8, ≤ 256 bytes each, ≤ 16 per object, settable at `put` and via `label` (replace-all semantics). Label text is agent-visible and never audited (F-14).
- **R-OBJ-9** `max_object_size`, if set, is enforced during streaming; exceeding it aborts the put with `TOO_LARGE` (a refusal), leaving no object.
- **R-OBJ-10** Optional client-supplied `X-Lsk-Sha256` on `put`/`replace`: if present, the daemon compares it to the streamed plaintext hash and refuses the commit with `INTEGRITY` on mismatch. (Adopted from the second review; cheap end-to-end check for path-based puts.)

### 3.3 Destinations (R-DST)
- **R-DST-1** Destinations are declared per vault in operator config, keyed by name (same grammar as vault names). Undeclared = denied. There is no API to create or alter destinations.
- **R-DST-2** `kind = "fs"`: `root` (absolute path inside the daemon container, must exist and be a directory at startup), `overwrite` (default `false`). Used by `export` only.
- **R-DST-3** `kind = "send"`: `match` (pattern per F-3), `as` (`"attachment"` default, or `"body"`), `max_size` (optional), `audit_target` (default `false`, F-27). Used by `resolve` only.
- **R-DST-4** `list_destinations(vault)` returns `[{name, kind, as?}]`. Never `root`, `match`, `overwrite`, `max_size`, `audit_target`.
- **R-DST-5** `export` against a `send` destination, or `resolve` against an `fs` destination → `DESTINATION_KIND_MISMATCH` (refusal).
- **R-DST-6** Pattern grammar: `match` is a literal string over `[A-Za-z0-9:_./+-]`, optionally ending in `/*`. A target matches iff it equals the literal, or (with `/*`) it equals `<literal-without-*>` followed by one non-empty segment containing no `/`. Case-sensitive. No other wildcard, no regex.

### 3.4 Put (R-PUT)
- **R-PUT-1** Wire: `POST /v1/vaults/{vault}/objects`, body = raw bytes (chunked or Content-Length). Optional headers: `Content-Type`, `X-Lsk-Name`, `X-Lsk-Label` (repeatable), `X-Lsk-Sha256`, `X-Lsk-Remove-Source-Requested: true` (informational, F-13).
- **R-PUT-2** Library: `put(data, vault, *, name=None, mime=None, labels=(), replace=None, sha256=None) -> ObjectInfo` where `data` is `bytes`, a binary file object, or an iterator of `bytes`. Streams; never buffers the whole body in memory.
- **R-PUT-3** MCP: `vault_put(path, vault, remove_source=false)`. The MCP process opens the path, streams it (sending `X-Lsk-Sha256` computed while streaming is not possible; the MCP face hashes in a first pass when the file is < 64 MiB, else omits the header), and on a `201` response (and only then) unlinks the source if asked. No inline-content parameter exists. Returns `ObjectInfo` only.
- **R-PUT-4** Response is `201` with `ObjectInfo` (R-OBJ-2). The daemon computes SHA-256 of plaintext during streaming and writes it to the audit entry only.

### 3.5 Export (R-EXP)
- **R-EXP-1** `export(handle, destination, filename)`: decrypts and writes the object to `<root>/<filename>` in the daemon container.
- **R-EXP-2** `filename` grammar: `^[A-Za-z0-9][A-Za-z0-9._ -]{0,254}$`, additionally rejecting `..` anywhere. No separators, no leading dot, NFC-normalised before validation. Violation → `FILENAME_INVALID` (refusal).
- **R-EXP-3** Target path = `realpath(root)` joined with `filename`, re-resolved at export time; if the result does not start with `realpath(root) + "/"` → `PATH_ESCAPE` (refusal). This covers root symlink changes after startup.
- **R-EXP-4** Collision → `EXISTS` (refusal) unless the destination has `overwrite=true`. Write is temp-file-then-rename within `root`; mode `0644`.
- **R-EXP-5** Callable by any socket peer on both faces; no credential required (F-26).

### 3.6 Resolve (R-RES)
- **R-RES-1** `resolve(handle, destination, target, credential)`: `POST /v1/objects/{handle}/resolve` with `Authorization: Bearer <credential>` and JSON `{destination, target}`. Success streams the plaintext body with headers `Content-Type`, `Content-Length`, `X-Lsk-Destination`, `X-Lsk-As`.
- **R-RES-2** Authorisation, in order, each failure a distinct refusal code: credential present (`CREDENTIAL_REQUIRED`); credential valid and not revoked (`CREDENTIAL_INVALID`); credential scoped to the object's vault (`CREDENTIAL_NOT_PERMITTED`); vault not degraded (`VAULT_DEGRADED`); destination exists in that vault (`DESTINATION_NOT_FOUND`); kind is `send` (`DESTINATION_KIND_MISMATCH`); `target` matches `match` (`TARGET_NOT_ALLOWED`); size ≤ `max_size` if set (`TOO_LARGE`); for `as="body"`, body is valid UTF-8 (`ENCODING_INVALID`, checked by a full pass before any byte is sent).
- **R-RES-3** `target` is written to the audit log only when the destination has `audit_target=true` (F-27); it never appears in any response.
- **R-RES-4** Library: `resolve(handle, destination, target, credential) -> Resolved` with `.stream` (iterator of `bytes`), `.mime`, `.size`, `.destination`, `.as_`. The only client path that yields plaintext.
- **R-RES-5** No MCP tool wraps `resolve`. The MCP server's tool list is closed (SI-13).

### 3.7 Metadata ops (R-MET)
- **R-MET-1** `stat(handle)`, `list(vault?)`, `label(handle, labels)`, `delete(handle)`, `list_vaults()`, `list_destinations(vault)` — all callable by any socket peer.
- **R-MET-2** `list` returns `ObjectInfo[]` ordered by `created` ascending; no pagination in v1; hard cap 10 000 entries per response (`TOO_MANY` error, not a refusal).

### 3.8 Credentials (R-CRD)
- **R-CRD-1** Token format: `lsk_<id:8 hex>_<secret:32 bytes base64url>`. Issued once, printed once by `lsk credential issue --name NAME [--vault V]...` (no `--vault` = all vaults). Never retrievable again.
- **R-CRD-2** Daemon stores `{id, name, sha256(secret), vaults, created, revoked?}` in `credentials` file; never the secret (SI-14).
- **R-CRD-3** `lsk credential revoke ID` takes effect on the next request without restart. `lsk credential list` shows id, name, vaults, created, revoked.
- **R-CRD-4** Credentials appear in the audit log as `cred: <id>` only.
- **R-CRD-5** Delivering the credential to consumer tool code *and keeping it from the terminal tool* is the deployer's job (Part B). Core docs state this is the read barrier (F-1).

### 3.9 Cryptography (R-CRY)
- **R-CRY-1** Each object has a random 256-bit DEK; body encrypted with AES-256-GCM in 1 MiB chunks; nonce = 8-byte per-object random prefix ‖ 32-bit chunk counter; AAD = handle ‖ chunk index ‖ final-chunk flag (prevents truncation and reordering). DEK wrapped with the vault KEK (AES-256-GCM, random nonce).
- **R-CRY-2** Metadata (`name`, labels, mime) stored encrypted under the DEK alongside the body; `handle`, `vault`, `size`, timestamps stored in the clear in an index (needed for `list` without decrypting).
- **R-CRY-3** Delete/replace/expire = unlink ciphertext + overwrite-and-unlink the wrapped DEK record (F-8). No physical erasure guarantee is claimed.
- **R-CRY-4** `keys_dir` and `data_dir` are distinct volumes in the reference compose file (F-7). Losing `keys_dir` = losing every vault; documented.
- **R-CRY-5** **Plaintext never touches disk inside the daemon.** `put` encrypts chunk-by-chunk as bytes arrive, directly into the temp file; a crash mid-stream leaves ciphertext, not plaintext. (The second review's design spills the stream to a plaintext temp file and encrypts at commit; that breaks at-rest encryption for the duration of every put and after any crash. Explicitly forbidden here.) Export is the one deliberate plaintext write, and only to a declared `fs` root.

### 3.10 Audit (R-AUD)
- **R-AUD-1** Append-only JSONL at `audit_log`, single writer (the daemon), one entry per line, format in §6.1.
- **R-AUD-2** Hash-chained: each entry's `prev` = SHA-256 of the previous entry's canonical bytes (RFC 8785 JCS); genesis `prev` = 64 zeros. `seq` strictly increments from 1.
- **R-AUD-3** Events: `start`, `put`, `replace`, `delete`, `export`, `resolve`, `expire`, `label`, `request` (any request that could not be mapped to an operation). `stat`/`list`/`list_vaults`/`list_destinations`/`health` are not logged.
- **R-AUD-4** Outcome ∈ `ok | refused | aborted`. **Every** `refused` outcome, including malformed requests and unknown routes, is logged with its error code as `reason` (F-21).
- **R-AUD-5** Never logged: content bytes, label text, `root`, `match`, storage paths, credential secrets, `name` unless the vault has `expose_names=true`, `target` unless the destination has `audit_target=true`.
- **R-AUD-6** The entry is written and fsynced before the response leaves the daemon (so a refusal can't be unlogged by killing the connection).
- **R-AUD-7** `lsk audit verify [--file]` → exit 0 if the chain is intact; exit 1 naming the first bad `seq`; exit 2 on I/O error. `lsk audit head` prints the current head hash for off-host anchoring (manual in v1).
- **R-AUD-8** The audit log path is in the daemon container only; no endpoint exposes it or any entry.

### 3.11 Review (R-REV)
- **R-REV-1** `lsk audit review [--since DUR|TS] [--threshold low|medium|high|critical] [--json]` — rule-based, offline, reads the whole log (history needed for first-time detection), reports findings in the window.
- **R-REV-2** Built-in rules (§6.3): `refusal`, `first_destination`, `burst`, `churn`, `chain`, `degraded`. Severities and parameters come from `review_rules` config; defaults make §9.4 of the brief true (F-21).
- **R-REV-3** Findings go to **stderr**, one per line, severity-descending; stdout is empty unless `--json`. Exit 0 = nothing at/above threshold; 1 = findings at/above threshold; 2 = cannot read/parse log. A chain failure is `critical` and always produces exit 1.
- **R-REV-4** `review` runs `verify` first; a broken chain is reported as a finding and the remaining rules still run over the parseable prefix.

### 3.12 Deployment (R-DEP)
- **R-DEP-1** Daemon image runs `lskd` as a non-root user; config at `/etc/lsk/lsk.toml` (read-only mount); volumes `lsk-data`, `lsk-keys`, `lsk-audit`, `lsk-sock`.
- **R-DEP-2** Socket at `/run/lsk/lsk.sock` inside the `lsk-sock` volume, created mode `0666` (the agent container is one trust domain; see F-6). Configurable (`socket_mode`, `socket_group`).
- **R-DEP-3** The daemon has **no TCP listener and no configuration key that could create one** (SI-2).
- **R-DEP-4** Reference compose mounts into the agent service only `lsk-sock`. Never `lsk-data`, `lsk-keys`, `lsk-audit`, the config, or any `fs` destination root (F-16).
- **R-DEP-5** Admin CLI is the same binary, invoked via `docker exec <daemon> lsk …`; it is not installed in the agent image.
- **R-DEP-6** Daemon refuses to start on invalid config (unknown keys, bad grammar, missing `root` dir, duplicate names) with a line-numbered error; `lsk config check` runs the same validation.

### 3.13 Faces (R-FAC)
- **R-FAC-1** Python package `lsk` ships `VaultClient` (§10.2) and the MCP server entry point `lsk mcp [--socket PATH]`.
- **R-FAC-2** MCP tools, closed list: `vault_list_vaults`, `vault_list_destinations`, `vault_put`, `vault_stat`, `vault_list`, `vault_label`, `vault_delete`, `vault_export`. Tool descriptions must not suggest content can be retrieved.
- **R-FAC-3** MCP tool results contain only `ObjectInfo`/destination/vault records and error codes; never bytes.
- **R-FAC-4** All faces send `X-Lsk-Protocol: 1`; the daemon rejects a missing/unsupported version with `PROTOCOL_UNSUPPORTED` (refusal).

### 3.14 Documentation (R-DOC)
- **R-DOC-1** Threat model verbatim from brief §3, plus the limitations in §11 of this PRD.
- **R-DOC-2** Operator invariants (§11) as a checklist.
- **R-DOC-3** Tool-author guide: `put` from a stream, `resolve` contract, labels-are-visible warning, credential handling.
- **R-DOC-4** No domain names (licences, providers, platforms, communities) in code, config keys, defaults, shipped examples, or tests, other than a clearly marked "motivating case" section (brief decision 21). Operator-supplied config *values* are unrestricted (F-29).

---

## 4. Wire protocol

### 4.1 Transport
HTTP/1.1 over a Unix domain socket (F-23). No TLS, no TCP, no HTTP/2. Requests MUST carry `X-Lsk-Protocol: 1`. Responses carry the same. JSON request/response bodies are `application/json`; object bodies are raw bytes.

Concurrency: the daemon serves concurrent connections; a `put` holds one connection for the duration of its stream. Request header size ≤ 16 KiB. Idle timeout 60 s on headers, none on bodies. A request body on an endpoint that takes none is discarded and the request is refused with `INVALID_REQUEST` (audited); there is no route other than `put`/`replace` that accepts bytes.

### 4.2 Endpoints

| Method & path | Auth | Request | Success | Audited |
|---|---|---|---|---|
| `GET /v1/health` | none | — | `200 {"status":"ok","protocol":1}` | no |
| `GET /v1/vaults` | none | — | `200 [VaultInfo]` | no |
| `GET /v1/vaults/{vault}/destinations` | none | — | `200 [DestinationInfo]` | no |
| `POST /v1/vaults/{vault}/objects` | none | raw body; headers `Content-Type`, `X-Lsk-Name`, `X-Lsk-Label`*, `X-Lsk-Sha256`, `X-Lsk-Remove-Source-Requested` | `201 ObjectInfo` | `put` |
| `PUT /v1/objects/{handle}` | none | raw body; same headers | `200 ObjectInfo` | `replace` |
| `GET /v1/objects?vault={vault}` | none | — | `200 [ObjectInfo]` | no |
| `GET /v1/objects/{handle}` | none | — | `200 ObjectInfo` | no |
| `PATCH /v1/objects/{handle}` | none | `{"labels":[…]}` | `200 ObjectInfo` | `label` |
| `DELETE /v1/objects/{handle}` | none | — | `204` | `delete` |
| `POST /v1/objects/{handle}/export` | none | `{"destination":"…","filename":"…"}` | `200 {"destination","filename","size"}` | `export` |
| `POST /v1/objects/{handle}/resolve` | Bearer credential | `{"destination":"…","target":"…"}` | `200` raw body + `X-Lsk-Destination`, `X-Lsk-As`, `Content-Type`, `Content-Length` | `resolve` |
| anything else | — | — | `404 INVALID_REQUEST` | `request` (refused) |

`resolve` is the only route that ever returns object bytes, and the only route that takes an `Authorization` header. A reviewer can verify SI-1 by reading one routing table.

### 4.3 Records

```json
VaultInfo       {"name":"private","expose_names":false,"ttl":"30d"}
DestinationInfo {"name":"team-chat","kind":"send","as":"attachment"}
ObjectInfo      {"handle":"v_9c1e4a0b2d31","vault":"private","size":2123456,
                 "mime":"text/plain","created":"2026-10-12T08:00:00Z",
                 "modified":"2026-10-12T08:00:00Z","labels":["hui-notes"],
                 "expires_at":"2026-11-11T08:00:00Z","name":null}
Error           {"error":{"code":"TARGET_NOT_ALLOWED","message":"target not permitted for destination 'team-chat'"}}
```

`name` is present and `null` when hidden, so clients can tell "hidden" from "absent". Timestamps RFC 3339 UTC, millisecond precision.

### 4.4 Examples

```
# put (any peer)
curl --unix-socket /run/lsk/lsk.sock -X POST http://lsk/v1/vaults/private/objects \
  -H 'X-Lsk-Protocol: 1' -H 'Content-Type: text/plain' -H 'X-Lsk-Label: hui-notes' \
  --data-binary @transcript.txt
→ 201 {"handle":"v_9c1e4a0b2d31", …}

# resolve (consumer only)
curl --unix-socket /run/lsk/lsk.sock -X POST http://lsk/v1/objects/v_9c1e4a0b2d31/resolve \
  -H 'X-Lsk-Protocol: 1' -H 'Authorization: Bearer lsk_1a2b3c4d_…' \
  -H 'Content-Type: application/json' \
  -d '{"destination":"team-chat","target":"chat:group/team"}'
→ 200, X-Lsk-As: attachment, body = plaintext
```

The `Host` header value is ignored.

---

## 5. Configuration schema

### 5.1 `lsk.toml` (operator-only, read-only mount in the daemon container)

```toml
[daemon]
socket             = "/run/lsk/lsk.sock"      # default
socket_mode        = "0666"                   # octal string; default
socket_group       = ""                       # optional gid/name; chgrp the socket
data_dir           = "/var/lib/lsk/data"      # default
keys_dir           = "/var/lib/lsk/keys"      # default
audit_log          = "/var/lib/lsk/audit/audit.jsonl"
credentials        = "/var/lib/lsk/credentials.toml"   # managed by `lsk credential`
review_rules       = "/etc/lsk/review.toml"   # optional; built-in defaults otherwise
ttl_sweep_interval = "5m"                     # default

[vault.private]
expose_names    = false        # default
ttl             = "30d"        # optional; grammar: <int><s|m|h|d>
max_object_size = "2GiB"       # optional; grammar: <int><B|KiB|MiB|GiB>

[vault.private.destinations.nas-archive]
kind      = "fs"
root      = "/srv/nas/archive"   # absolute; must exist at startup
overwrite = false                # default

[vault.private.destinations.team-chat]
kind         = "send"
match        = "chat:group/team" # literal; operator value — platform names allowed here, never in defaults
as           = "attachment"      # default
audit_target = false             # default; true logs the declared target string

[vault.private.destinations.dm-body]
kind     = "send"
match    = "chat:dm/*"           # one trailing wildcard segment
as       = "body"
max_size = "8KiB"                # optional
```

Validation (R-DEP-6): unknown keys are errors; names match the grammar; `kind`-specific keys only on that kind; `root` exists and is a directory; `match` parses per R-DST-6; durations and sizes parse; no duplicate names within a vault. Relative paths are errors.

### 5.2 `credentials.toml` (daemon-managed; operator reads, never hand-edits)

```toml
[[credential]]
id      = "1a2b3c4d"
name    = "vault_send"
hash    = "sha256:…"            # of the secret part only
vaults  = ["private"]           # or "*"
created = "2026-10-12T08:00:00Z"
revoked = "2026-10-13T09:00:00Z" # absent until revoked
```

### 5.3 `review.toml` (optional; defaults shown)

```toml
threshold = "medium"              # default exit threshold; CLI flag overrides

[rules.refusal]          # every entry with outcome=refused
severity = "high"

[rules.first_destination] # first ever export/resolve to (vault, destination)
severity = "medium"

[rules.burst]            # ≥ count events of one kind within window
severity = "medium"
events   = ["resolve", "export", "delete"]
count    = 20
window   = "10m"

[rules.churn]            # ≥ count body/metadata writes on one handle within window
severity = "low"
count    = 10
window   = "1h"

[rules.chain]            # verify failure
severity = "critical"    # cannot be lowered below "high"

[rules.degraded]         # a `start` entry listing a degraded vault
severity = "critical"
```

Any rule may set `enabled = false`.

---

## 6. Audit

### 6.1 Record format

One JSON object per line. Field set is fixed; absent fields are omitted, not null, except where stated.

```json
{"seq":42,
 "ts":"2026-10-12T08:01:02.123Z",
 "event":"resolve",
 "outcome":"ok",
 "vault":"private",
 "handle":"v_9c1e4a0b2d31",
 "sha256":"3f…e1",
 "size":2123456,
 "dest":"team-chat",
 "as":"attachment",
 "target":"chat:group/team",
 "caller":{"uid":1000,"pid":4321,"cred":"1a2b3c4d"},
 "reason":"TARGET_NOT_ALLOWED",
 "name":"hui-notes.txt",
 "remove_source_requested":true,
 "config_sha256":"ab…",
 "degraded":["media"],
 "prev":"7c…09"}
```

| Field | Present on | Notes |
|---|---|---|
| `seq`, `ts`, `event`, `outcome`, `caller`, `prev` | all | `caller.cred` only when a credential was presented and parsed; `caller.uid/pid` from `SO_PEERCRED`, informational (F-6) |
| `vault`, `handle` | object events | `handle` absent on a refused `put` that never allocated one |
| `sha256`, `size` | `put`, `replace`, `export`, `resolve`, `expire`, `delete` with outcome `ok` | plaintext SHA-256; audit-only (R-OBJ-2) |
| `dest`, `as` | `export`, `resolve` | name only; never `root`, `match` |
| `target` | `resolve` | only when the destination has `audit_target=true` (F-27) |
| `reason` | outcome `refused` or `aborted` | error code from §7 |
| `name` | `put`, `replace` | only when the vault has `expose_names=true` |
| `remove_source_requested` | `put` | client claim, see F-13 |
| `config_sha256`, `degraded` | `start` | SHA-256 of the loaded config file; list of degraded vaults (omitted when empty) |

### 6.2 Chain and verification

- Canonical form: RFC 8785 (JCS) over the entry with `prev` included. `prev(n) = SHA-256(canonical(entry n−1))`; `prev(1) = "0"×64`.
- `verify` walks the file: each line parses; `seq` = line number; `prev` matches; `ts` non-decreasing. First violation → exit 1 with `seq`, kind of failure. Truncation of the tail is **not** detectable by `verify` alone; that is what `audit head` anchoring is for, and the docs say so.
- Head hash = `SHA-256(canonical(last entry))`.

### 6.3 Review rules and output

| Rule | Fires when | Default severity |
|---|---|---|
| `refusal` | any entry in window with `outcome=refused` (one finding per entry; grouped by `reason` in `--json`) | high |
| `first_destination` | an `export`/`resolve` with `outcome=ok` to a `(vault, dest)` pair not seen earlier in the log | medium |
| `burst` | ≥ `count` entries of any one event in `events`, `outcome=ok`, within any sliding `window` | medium |
| `churn` | ≥ `count` entries of `replace`/`label`/`delete` on one handle within `window` | low |
| `chain` | `verify` fails | critical |
| `degraded` | a `start` entry with a non-empty `degraded` list | critical |

stderr line format (one per finding):

```
HIGH     refusal            seq=118            2026-10-12T08:14:01Z  resolve v_9c1e4a0b2d31 dest=team-chat reason=TARGET_NOT_ALLOWED cred=1a2b3c4d
MEDIUM   first_destination  seq=97             2026-10-12T08:02:40Z  export private/nas-archive
MEDIUM   burst              seq=200..231       2026-10-12T08:20:00Z  32 resolve in 10m
CRITICAL chain              seq=57             —                     prev mismatch
CRITICAL degraded           seq=1              2026-10-12T07:59:58Z  vault media has no key
```

`--json` emits `{"findings":[…],"threshold":"medium","exit":1}` on stdout; stderr still gets the lines (cron mail reads stderr).

Cron example in docs: `lsk audit review --since 24h` → nonzero exit mails the operator.

---

## 7. Error model

HTTP status + `{"error":{"code","message"}}`. `message` is for humans and MUST NOT contain roots, patterns, storage paths, targets, credential material, or hidden names (SI-6). A **refusal** is any denial of a well-formed or malformed operation; refusals are audited (R-AUD-4). **Errors** are transport/internal failures; audited only when an operation had started (outcome `aborted`).

| Code | HTTP | Refusal? | When |
|---|---|---|---|
| `INVALID_REQUEST` | 400/404 | yes | unknown route, bad JSON, bad header, bad handle grammar, body on a bodiless route |
| `PROTOCOL_UNSUPPORTED` | 400 | yes | missing/unsupported `X-Lsk-Protocol` |
| `VAULT_NOT_FOUND` | 404 | yes | |
| `VAULT_DEGRADED` | 503 | yes | byte-touching op on a vault with no usable key (R-VLT-2) |
| `NOT_FOUND` | 404 | yes | handle unknown, deleted or expired |
| `DESTINATION_NOT_FOUND` | 404 | yes | name not declared in the object's vault |
| `DESTINATION_KIND_MISMATCH` | 409 | yes | R-DST-5 |
| `CREDENTIAL_REQUIRED` | 401 | yes | resolve without `Authorization` |
| `CREDENTIAL_INVALID` | 401 | yes | unknown id, bad secret, revoked |
| `CREDENTIAL_NOT_PERMITTED` | 403 | yes | credential not scoped to this vault |
| `TARGET_NOT_ALLOWED` | 403 | yes | target fails `match` |
| `ENCODING_INVALID` | 422 | yes | `as="body"` destination, object is not valid UTF-8 |
| `PATH_ESCAPE` | 403 | yes | R-EXP-3 |
| `FILENAME_INVALID` | 400 | yes | R-EXP-2 |
| `EXISTS` | 409 | yes | export collision without `overwrite` |
| `TOO_LARGE` | 413 | yes | `max_object_size` or `max_size` exceeded |
| `INTEGRITY` | 422 | yes | `X-Lsk-Sha256` mismatch (R-OBJ-10) |
| `LABEL_INVALID` | 400 | yes | R-OBJ-8 |
| `TOO_MANY` | 413 | no | `list` cap (R-MET-2) |
| `ABORTED` | — | audited as `aborted` | client closed stream mid-put/replace/resolve |
| `STORAGE` | 507 | no | disk full, I/O error |
| `INTERNAL` | 500 | no | bug; details to daemon stderr only |

Refusal checks are evaluated in the order listed in R-RES-2 so that an attacker learns the least (e.g. a bad credential never learns whether the destination exists).

---

## 8. Security invariants (testable statements)

Each is written so a test can assert it. "Sentinel" = a unique 64-byte random string put into a vault at test setup.

| ID | Invariant | How it's tested |
|---|---|---|
| SI-1 | No response from any endpoint contains object plaintext unless the request carried a valid, correctly scoped credential and a matching send destination/target. | Enumerate every route in §4.2 without `Authorization`, and `resolve` with each failing condition in R-RES-2; assert the sentinel is absent from every response body and header. |
| SI-2 | The daemon process has no listening TCP or UDP socket, and the config schema has no key that could open one. | `ss -ltnup` in the daemon container is empty for `lskd`; schema review. |
| SI-3 | The agent container's filesystem contains no vault ciphertext, keys, audit log, or config. | `docker compose config` shows only `lsk-sock` mounted into the agent; runtime search of the agent container for the sentinel, its ciphertext (by DEK-record id), key files, and the audit file finds nothing. |
| SI-4 | An export can only create a file whose real path is strictly under `realpath(root)`. | Filenames with `..`, `/`, `\`, leading `.`, NUL, overlong, Unicode separators; root replaced by a symlink after start. All refused with `PATH_ESCAPE`/`FILENAME_INVALID`; no file created elsewhere. |
| SI-5 | `resolve` succeeds iff every condition in R-RES-2 holds. | Truth-table test over (credential ∈ {none, bad, revoked, wrong-vault, good}) × (destination ∈ {missing, fs, send}) × (target ∈ {match, no-match}) × (body-encoding ∈ {utf8, binary} for `as="body"`); exactly the expected cells return 200. |
| SI-6 | No response body, header, or error message contains: destination `root`, `match`, storage paths, `target`, credential secrets, content hash, or `name` while `expose_names=false`. | Configure roots/patterns containing sentinel substrings; run every endpoint including failure paths; grep all bytes returned. |
| SI-7 | Every refused request yields exactly one audit entry with `outcome=refused` and the returned `reason`, durable before the response is sent. | Count log lines vs refused requests; kill the client immediately after sending; entry still present. |
| SI-8 | The audit log never contains: content bytes, label text, `root`, `match`, storage paths, credential secrets, `name` while `expose_names=false`, or `target` while `audit_target=false`. | Sentinels in each of these; grep the log after a full operation sweep, under both settings. |
| SI-9 | Plaintext never exists on disk in the daemon container except under a declared `fs` root after `export`. | Sentinel absent from every file under `data_dir` *during* a stalled put (connection held open mid-body), after a crash mid-put, and after commit; ciphertext differs between two puts of identical content (random DEK/nonce). |
| SI-10 | After `delete`, `replace`, or `expire`, the previous body is unrecoverable through the daemon: the ciphertext file is gone and the wrapped DEK record is gone. | File listing of `data_dir` before/after; `stat` → `NOT_FOUND` or new size; attempting resolve of the old body impossible. |
| SI-11 | A put or replace whose stream does not terminate cleanly leaves no object and, after startup sweep, no file. | Close connection mid-body; `list` shows nothing new (or old body intact for replace); restart daemon; `data_dir` has no temp files. |
| SI-12 | Any modification, deletion, insertion, or reordering of an audit line is detected by `verify`. | Mutate one byte / drop a line / swap two lines / duplicate a line; `verify` exits 1 at the right `seq`. |
| SI-13 | The MCP server's tool list is exactly R-FAC-2 and no tool accepts inline content or returns bytes. | `tools/list` equals the fixed set; schema of each tool has no `content`/`data` parameter; a put of the sentinel followed by every MCP tool call returns no sentinel. |
| SI-14 | Credential secrets are not stored anywhere in the daemon container. | After issuing, grep all volumes and the process environment for the secret; only `sha256(secret)` is present. |
| SI-15 | `list_destinations` reveals only `{name, kind, as}`. | Response schema check with sentinel roots/patterns. |
| SI-16 | A vault with objects but no key is degraded, not silently re-keyed, and is loud. | Remove key file; start; `put`/`resolve`/`export` → `VAULT_DEGRADED`; `stat` works; `start` entry lists the vault; `review` exits 1 with `degraded`; no new key file created. |
| SI-17 | No platform, licence, provider or community name appears in core code, config keys, defaults, shipped examples, or tests. | Grep the repo (excluding the brief's Part C and the docs' motivating-case section) for a maintained denylist. |

SI-1, SI-3, SI-9 and SI-10 are the ones that make the brief's promise ("nothing in the agent's reach can read it back") true. SI-6/SI-8 are what keep the protocol from leaking the operator's topology. SI-7/SI-12 are what make the audit trail worth trusting.

---

## 9. Acceptance test plan

Environment: the reference compose file plus a `test-agent` service built from the `lsk` Python package, with a credentialed test consumer script and an uncredentialed "agent" script. Tests run from the host with `docker compose exec`. Rust unit tests cover grammar, pattern matcher, chunked AEAD, JCS canonicalisation, chain verification; the table below is the black-box plan.

| ID | Test | Verifies | Brief §9 |
|---|---|---|---|
| AT-1 | Library `put` from a stream returns `ObjectInfo` with handle + metadata only; sentinel absent from the return value. | R-PUT-2, R-OBJ-2, R-PUT-4 | 9.1 |
| AT-2 | MCP `vault_put(path)` returns `ObjectInfo` only; with `remove_source=true` the source is unlinked only after `201`; audit entry has `remove_source_requested=true`. | R-PUT-3, R-FAC-3, F-13 | 9.1 |
| AT-3 | `replace` under an existing handle: handle stable, `modified` updated, old ciphertext and DEK gone, labels carried. | R-OBJ-4, SI-10 | — |
| AT-4 | Credentialed consumer `resolve(h, "team-chat", "chat:group/team")` returns bytes byte-identical to input; headers `X-Lsk-As`, `Content-Type` correct; audit entry has `dest=team-chat`, `cred=<id>`, no target. | R-RES-1..4, R-AUD-5 | 9.2 |
| AT-5 | SI-5 truth table, including the `body`/binary cell → `ENCODING_INVALID` with zero bytes sent. | R-RES-2, SI-5 | 9.3 c, d |
| AT-6 | `resolve` against an `fs` destination and `export` against a `send` destination → `DESTINATION_KIND_MISMATCH`. | R-DST-5 | — |
| AT-7 | Read-path sweep: every route without credential, every MCP tool, `list`/`stat` after put → no sentinel. (Replaces brief 9.3(a); see F-1.) | SI-1, SI-13 | 9.3 a |
| AT-8 | Store not in agent container: compose inspection + runtime search. | R-DEP-4, SI-3 | 9.3 b |
| AT-9 | Export path confinement matrix. | R-EXP-2, R-EXP-3, SI-4 | 9.3 e |
| AT-10 | Export collision → `EXISTS`; with destination `overwrite=true` → replaced atomically. | R-EXP-4 | — |
| AT-11 | `lsk audit verify` passes after AT-1..10; `lsk audit review --since 1h` lists every refusal generated by AT-5/6/7/9/10 and exits 1 at default threshold; exits 0 with `--threshold critical`. | R-AUD-7, R-REV-1..3, F-21 | 9.4 |
| AT-12 | Tamper matrix on the audit log → `verify` exit 1 at correct `seq`; `review` reports `chain` critical. | SI-12, R-REV-4 | — |
| AT-13 | Topology leak sweep (SI-6, SI-8, SI-15) with sentinel roots/patterns/targets/names, run with `audit_target` both false and true. | R-DST-4, R-AUD-5, F-27 | — |
| AT-14 | Aborted put, aborted replace, aborted resolve: no object / old body intact / audit `aborted`; restart leaves no temp files. | R-OBJ-3, SI-11 | — |
| AT-15 | TTL: vault with `ttl="2s"`, sweep interval 1 s; object disappears, `expire` audited with hash and size, `stat` → `NOT_FOUND`; `replace` resets expiry. | R-OBJ-6, F-10 | — |
| AT-16 | `max_object_size` and `max_size` enforcement mid-stream → `TOO_LARGE`, no object / no bytes delivered. | R-OBJ-9, R-RES-2 | — |
| AT-17 | Credential lifecycle: issue prints once; secret not on disk; revoke takes effect without restart; revoked → `CREDENTIAL_INVALID`. | R-CRD-1..3, SI-14 | — |
| AT-18 | Config validation: each invalid case in R-DEP-6 → startup refused with line number; `lsk config check` agrees. Includes a `match` with a non-trailing `*`. | R-DEP-6, R-DST-6 | — |
| AT-19 | Missing key file with existing objects → degraded vault per SI-16; other vaults unaffected. | R-VLT-2, SI-16 | — |
| AT-20 | No TCP listener. | R-DEP-3, SI-2 | — |
| AT-21 | At-rest check per SI-9, including the stalled-mid-stream and crash-mid-stream cases. | R-CRY-1, R-CRY-5, SI-9 | — |
| AT-22 | `expose_names`: `name` is `null` in every response and absent from audit when `false`; present when `true`. | R-OBJ-2, R-AUD-5, F-15 | — |
| AT-23 | Refusal durability: client sends a refused request and closes immediately; audit entry present. | R-AUD-6, SI-7 | — |
| AT-24 | Review rule unit cases: synthetic logs that trip `first_destination`, `burst`, `churn`, `degraded` exactly at threshold and not one below; `--json` shape. | R-REV-2, §6.3 | — |
| AT-25 | Protocol version: missing or `2` → `PROTOCOL_UNSUPPORTED`, audited. | R-FAC-4 | — |
| AT-26 | Pattern matcher table: literal exact; `/*` matches one non-empty segment; rejects empty segment, extra segment, embedded `/`, prefix-only. | R-DST-6 | — |
| AT-27 | `X-Lsk-Sha256` correct → 201; wrong → `INTEGRITY`, no object, audited. | R-OBJ-10 | — |
| AT-28 | Domain-name denylist grep over the repo. | R-DOC-4, SI-17 | — |

Coverage check: every `R-` and `SI-` ID above appears in at least one AT row (R-DOC-1..3 are reviewed, not tested; R-DEP-1/2/5 are covered by the compose inspection in AT-8).

---

## 10. Interface contract for Part B (external consumer)

Part B depends on Part A only through the following. Anything not listed is not promised.

### 10.1 Deployment contract
- Service `lskd` in compose; volume `lsk-sock` mounted into the agent service at `/run/lsk`; socket `/run/lsk/lsk.sock`.
- Operator declares the messaging destinations in `lsk.toml` under the relevant vault; nothing in Part A knows any platform's name.
- Operator issues one credential (`lsk credential issue --name vault_send --vault <vault>`) and delivers it to `vault_send` by a route the terminal tool cannot see. **Part A cannot enforce this; it is Part B's invariant and must be in Part B's test (B4.4).**

### 10.2 Library contract (`lsk` Python package, protocol 1)

```python
from lsk import VaultClient, ObjectInfo, Resolved, LskError

c = VaultClient(socket_path="/run/lsk/lsk.sock")
c.vaults() -> list[VaultInfo]
c.destinations(vault: str) -> list[DestinationInfo]
c.put(data: bytes | BinaryIO | Iterable[bytes], vault: str, *,
      name: str | None = None, mime: str | None = None,
      labels: Sequence[str] = (), replace: str | None = None,
      sha256: str | None = None) -> ObjectInfo
c.put_path(path: str, vault: str, *, remove_source: bool = False, **kw) -> ObjectInfo
c.stat(handle) -> ObjectInfo
c.list(vault: str | None = None) -> list[ObjectInfo]
c.label(handle, labels: Sequence[str]) -> ObjectInfo
c.delete(handle) -> None
c.export(handle, destination: str, filename: str) -> ExportResult
c.resolve(handle, destination: str, target: str, credential: str) -> Resolved
#   Resolved.stream: Iterator[bytes]; .mime; .size; .destination; .as_ ("attachment"|"body")
# LskError(code: str, message: str, status: int)
```

Semantic versioning on the package; protocol number bumps only on incompatible wire changes.

### 10.3 What Part B must answer before using `as="body"`
F-25. Part A ships the destination type; whether any `body` destination is declared is an operator decision informed by Part B's answer.

### 10.4 What Part A will not do for Part B
Scrub tool results, proxy LLM calls, detect content in context, or know anything about chats, platforms, or data URIs. Those are B7 and §10.2 of the brief.

---

## 11. Documented limitations and operator invariants

These are true by design and go in the docs verbatim, not softened.

1. **The read barrier is the credential.** Anything in the agent container that obtains the consumer credential can read any object in the credential's vaults. Keep it out of the terminal tool's environment, PATH, and any file the agent can read.
2. **MCP `put(path)` protects from commit onward.** A file on the agent's disk was readable before it was put. Producers that must never expose bytes to the agent should `put` from a stream through the library, not via a path.
3. **`fs` roots are plaintext.** An `fs` destination root mounted into the agent container is a read path. The daemon cannot detect this. `export` needs no credential because the root is operator-fixed (F-26).
4. **`as="body"` is advisory.** The daemon checks UTF-8 and size; the consumer does the sending.
5. **No physical erasure.** Delete/replace/expire remove the ciphertext and destroy the key; they do not scrub disk sectors.
6. **At-rest encryption protects the data volume in isolation** (backups, disk forensics without the keys volume). With both volumes, it protects nothing beyond container isolation (F-7).
7. **`verify` cannot detect tail truncation.** Anchor `lsk audit head` off-host on a schedule.
8. **Caller identity is the credential, nothing else.** UID and PID in the audit log are informational.
9. **Out of scope:** determined adversaries, malicious tool code that lies about `target`, prompt injection probing covert channels, denial of service by log or disk fill, multiple agent trust domains on one daemon.
10. **Labels are visible.** Tool authors must not put content in labels or `name`.
11. **Losing `keys_dir` loses every vault.** Back it up separately from `data_dir`.

---

## 12. Glossary of name changes from the brief (pending F-17)

| Brief | PRD (provisional) |
|---|---|
| `vault` binary / `vault mcp` / `vault audit …` | `lsk` / `lsk mcp` / `lsk audit …` |
| daemon (unnamed) | `lskd` |
| `vault.put()` | `VaultClient.put()` from package `lsk` |
| `v_9c1e4a` (example) | `v_` + 12 hex |
| `resolve(h, destination)` | `resolve(h, destination, target, credential)` |

---

## Appendix A — Reconciliation with the second review (`PRD-hermes_digicryptids.md`)

Two PRDs were drafted independently from the same brief. This records what converged, what was adopted from the other draft, and what was rejected and why.

**Converged independently (highest confidence the brief is at fault):** resolve takes name + target (F-2/AMB-5); caller identity is unfixable in Docker v1 (F-6/AMB-10); pattern grammar must be fixed (F-3/AMB-4); content hash is audit-only and never in `stat` (AMB-3); handles global (AMB-6); `remove_source` is client-side (F-13/AMB-11); labels need a bound (F-14/AMB-12); `as="body"` needs rules (F-4/AMB-8); platform names in operator values are fine, never in defaults (F-29/AMB-13).

**Adopted from the second review:** export's credential-free status elevated to a flag (F-26); `ENCODING_INVALID` for binary bodies; optional client-supplied SHA-256 with `INTEGRITY` refusal; degraded-vault behaviour on key loss instead of refuse-to-start (F-28); the narrower trailing-`/*` pattern grammar; generic `chat:` in all examples.

**Rejected, with reasons:**
- *"No operation on the library returns object bytes" (their NI-1).* False: `resolve` is on the library. This is F-1, and the second review inherited the brief's overclaim intact.
- *Plaintext temp file during `put`, encrypted at commit (their §5).* Breaks at-rest encryption during every put and after any crash. R-CRY-5 forbids it.
- *`hello` handshake with client-declared `role`.* Self-attestation; adds a field without adding a fact. Credential-or-not is the only distinction (F-6).
- *Custom NDJSON + binary framing.* Equivalent security; loses `curl --unix-socket` testing and well-trodden streaming code in both languages. Kept HTTP/1.1 over UDS (F-23). Their one real point — bodies are legal only on put/resolve — is enforced here by refusing bodies on bodiless routes.
- *`name` omitted vs `null` when hidden.* Kept `null`: clients can distinguish hidden from absent.
- *≥64-bit handles for guess-resistance.* Handles aren't secrets (`list` returns them). 48 bits is a collision bound, not a security one.
- *Unconditional `target_declared` in the audit log.* Replaced by per-destination `audit_target` (F-27); recipient identifiers in a log are the operator's call.
- *Review findings as JSONL on stderr.* Kept human-readable lines on stderr (cron mail is read by a person) and `--json` on stdout for machines.

**Gaps shared by both drafts, now fixed here only:** `list_vaults` (F-9); TTL reset semantics (F-10); `expose_names` flip-reveals-history (F-15); fs-root-mounted-into-agent (F-16); Hermes mirror for body sends (F-25); binary/module naming (F-17).
