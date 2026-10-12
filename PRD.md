# ovenmitt — PRD (Part A, core, v1)

*Project name: **ovenmitt** — handle the hot thing without touching it. Repo: `github.com/utunga/oven-mitt`. The hyphen is the repo's only; binary, daemon, package and PyPI name are `ovenmitt`.*

*Status: draft 0.5, 2026-10-13 (0.4 + implementation clarifications from M4, marked inline). Derived from BRIEF.md (decisions 1–22), reconciled against the independent second review (`PRD-hermes_digicryptids.md`, Appendix A), then settled in a design interview (Appendix B). Scope: Part A only, Docker only. Part B is treated here as an external consumer of Part A's interfaces (§10). No code exists yet.*

**How to read this.** Requirements carry IDs (`R-xxx-n`), security invariants carry `SI-n`, tests carry `AT-n`. MUST/SHOULD/MAY are RFC 2119. §0 lists every point where the brief was silent or inconsistent and records how it was decided; nothing below is a silent assumption.

**Design criterion, stated once:** simple, elegant, free of foot-guns. The goal is to make it *hard* for an agent to accidentally send protected data through its context, not impossible. Where a feature traded simplicity for a marginal guarantee, simplicity won.

---

## 0. Flags: ambiguities and contradictions in the brief, and how they were decided

The **2nd** column marks items the second, independent review also raised (its `AMB-n`); two reviewers hitting the same seam from the same brief is strong evidence the brief, not the reviewer, is at fault. **Status:** *decided* = settled in the design interview; *default* = this PRD's position, accepted without a round.

| # | 2nd | Brief ref | Issue | Decision |
|---|---|---|---|---|
| F-1 | — | §5.1, §9.3 | "No read command exists on any face" and test 9.3(a) contradict §5.1's own statement that the library resolves bytes. The library runs in the agent container; anything the agent's shell can `import`, it can call. The only barrier to reading is the consumer credential. (The second review repeated the brief's claim verbatim as its NI-1.) | **Decided.** The honest claim: *hard, not impossible.* No credential-free read exists on any face; the socket protocol is the boundary; no credential is needed for intended use (putting, exporting to declared roots); an agent can export to a root it can also see and read it back, and that is unavoidable. The README says all of this, and distinguishes the two secrets: *encryption keys* never leave the daemon container (structural); the *consumer credential* must be kept from the terminal tool (deployer's job). §5.1 and §9.3(a) of the brief need rewording. |
| F-2 | AMB-5 | §6 vs §B3 | `resolve(h, destination)` takes a name in §6, a concrete target string in §B3. A name enforces nothing; a bare target leaves the log nameless. | **Decided.** `resolve(handle, destination, target, credential)`: the consumer names the declared destination *and* the concrete target; the daemon checks target against pattern, logs both. Trusts tool code to declare truthfully, which is where the threat model draws its line. |
| F-3 | AMB-4 | §7 | `match` grammar unspecified. | **Decided.** A literal, optionally ending in `/*` meaning exactly one more non-empty segment. No other wildcard, no regex. Smallest grammar that covers the known cases; can widen later, never narrow. |
| F-4 | AMB-8 | §7 `as = "body"` | The daemon can't enforce "send as text"; binary bodies and size were unspecified; and (F-25) nobody has checked whether Hermes mirrors message *text* into session history. No use case on the table needs it. | **Decided: removed from v1.** Every send is bytes; the consumer attaches them. No `as` key, no encoding check. If inline text sends are ever wanted, the Hermes mirror question gets answered first. |
| F-5 | — | §6 | `overwrite: true` on export — agent argument or operator config? | **Decided.** Per-destination config, default `false`. The agent never widens what a destination permits; on collision it gets `EXISTS` and picks another name. |
| F-6 | AMB-10 | §8 "caller (peer UID …)" | Every process in the agent container shares one UID; both containers often share it too. Peer UID can't distinguish callers. Both reviews call this v1's weakest point. A client-declared "role" is self-attestation. | **Decided.** `caller` records `{uid, pid, cred}` for forensics only. Authorisation: valid credential → *consumer*; otherwise → *agent*. The real fix (`SO_PEERCRED` against a dedicated user) is local mode, future. |
| F-7 | — | §5.1 | What is encryption at rest *for*, given the agent can't see keys or ciphertext anyway? | **Decided.** Keep it; it's cheap. It protects the data volume when it travels without the keys volume (backups, snapshots, pulled disks), and per-object keys make deletion mean something (F-8). It never replaces isolation: the daemon must hold the key to serve requests, so an isolation boundary — Docker now, a dedicated OS user later — is always what keeps the key from the agent. Local mode swaps one isolation mechanism for another; it never drops it. Keys in a separate volume (`ovenmitt-keys`); passphrase/KMS wrapping is future. |
| F-8 | — | §4, §6 | "Old bytes deleted immediately" — `unlink` on overlayfs/SSD is not erasure. | **Decided.** Per-object data key (DEK) wrapped by the vault key (KEK). Delete/replace/expire unlinks the ciphertext *and* destroys the wrapped DEK. `delete` is an explicit agent-callable operation. No physical-erasure claim. |
| F-9 | — | §6 | No way for the agent to discover vault names, yet `put` requires one. | **Decided.** `list_vaults` on every face, including an operator command. No default vault; every call names one. |
| F-10 | — | §7, §18 | TTL start point; expiry semantics; per-object TTL? | Default. From the last body commit (`replace` resets). Expired = gone; `stat` → `NOT_FOUND`. Per-vault only. |
| F-11 | — | §8 events | `label` not listed; `stat`/`list` unmentioned. | Default. `label` audited as an event, never its text. `stat`/`list` not audited. |
| F-12 | — | §4 | Who determines MIME type? | Default. Client-declared; default `application/octet-stream`; never sniffed. |
| F-13 | AMB-11 | §6 MCP `put(path)` | Anything on the agent's disk was readable before it was put; `remove_source` runs in the MCP process, so the daemon can only log it as a claim. | Default. Documented limitation (§11). Log field `remove_source_requested`. |
| F-14 | AMB-12 | §4 labels | Agent-visible, agent-settable; a producer that labels with content leaks. | Default. ≤ 256 bytes, ≤ 16 per object; tool-author warning; label text never logged. |
| F-15 | — | §4 `expose_names` | Store-but-hide or discard the original name? The operator may need names to find something for a human. | **Decided.** Always stored (encrypted). Agent sees it iff the vault's `expose_names` is `true` now. Operator always sees it via `ovenmitt object stat`. The setting governs all objects in the vault, past and future; one doc line says so. No per-object state. |
| F-16 | — | §5.1, §7 | An `fs` root also mounted into the agent container is a read path. | **Decided** (with F-1). Unavoidable, documented, not defended. Shipped compose never does it. |
| F-17 | — | §5.1, §2 | `vault` collides with HashiCorp; `vault` as a Python name is unusable. | **Decided: `ovenmitt`.** Binary `ovenmitt`, daemon `ovenmittd`, Python package and import `ovenmitt`, protocol header `X-Ovenmitt-Protocol`, repo `utunga/oven-mitt`. MCP tool names stay `vault_*` — to the model, "vault" is the right picture. Free on PyPI and crates.io. |
| F-18 | — | §4 credential | Scope? | **Decided.** `{id, name, vaults: [...] \| "*"}`. One allowlist — the vault's destinations. No per-credential destination scope. |
| F-19 | — | §7 | Config reload. | Default. Restart only; config SHA-256 in the `start` entry. |
| F-20 | — | silent | Several agent containers on one daemon? | Default. One daemon, one agent trust domain. |
| F-21 | AMB-9 | §9.4 | Severity vocabulary; "review reports every refusal and exits nonzero" needs defaults that make it true. | Default. `low < medium < high < critical`; refusal = `high`; default threshold `medium`. |
| F-22 | — | §8 | Log rotation. | Default. One file, no rotation in v1; `review` scans the whole file. |
| F-23 | — | §5.1 "Unix socket" | Wire format unspecified. | **Decided.** HTTP/1.1 over the Unix socket, as an *internal detail*: the README describes the socket as a file you mount, not a server you reach. No TCP listener, no config key that could create one — permanent, not a v1 scoping. The brief's "signed localhost URLs" (§10.2) would need TCP and is replaced by `resolve_path` (§10.2 future, below). |
| F-24 | — | §4 `put --replace` | Mid-stream failure of a replace. | Default. Old body kept until the new one commits. |
| F-25 | — | §B2/§B3 | Hermes mirror and body sends. | Closed by F-4: no body sends in v1. |
| F-26 | AMB-1/2 | §4, §6 | `export` needs no credential while `resolve` does; brief never says why. | **Decided** (with F-1). Export stays credential-free, both faces. An `fs` root is operator-fixed, so there's no target to lie about; `resolve` hands bytes to code that will send them somewhere, so the credential identifies trusted code. |
| F-27 | — | §8 vs Part C | Is the consumer's declared `target` a "resolved URL" the brief says never to log? Without it the log says "some DM". | **Decided.** Always logged on `resolve`. No switch. The audit trail is the trust anchor and a trust anchor with an off-switch invites "was it off?". Per-vault admin credentials were considered and rejected: the config file *is* the operator's authority. |
| F-28 | AMB-14 | §5.1 key loss | Refuse to start, or degrade one vault? | **Decided.** Refuse to start, naming the vault. Simpler, louder, no half-working daemon. |
| F-29 | AMB-13 | §7 vs decision 21 | `signal:` in the config sketch vs the ban on platform names. | **Decided.** Operator *values* are unrestricted. Shipped examples, defaults and tests use `chat:…`. |

The brief's §11 "Open items: none" was wrong; F-1, F-2, F-6, F-7, F-17, F-26, F-27 at least should be recorded there as decided.

---

## 1. Scope

### 1.1 In scope (v1)
- Rust daemon (`ovenmittd`) in its own Docker container: store, keys, audit log, config, TTL sweep.
- Unix-socket wire protocol (§4) as the sole interface to the daemon.
- Python client library: `put` and metadata ops for anyone; `resolve` for credential holders.
- MCP server (`ovenmitt mcp`) running in the agent container, exposing path-`put` and metadata ops only.
- Operator admin CLI inside the daemon container: `audit verify|review|head`, `credential issue|list|revoke`, `vault list`, `object stat`, `config check`.
- A reference `docker-compose.yml` with daemon + socket volume + a stub agent service.
- Docs: threat model, operator invariants, limitations.

### 1.2 Out of scope (v1)
Agent-facing CLI, `vpipe`, local mode, search, content check, sealed producers, `resolve_path`, transforms, version retention, multi-agent tenancy, log rotation, key rotation, body (inline-text) sends, TCP transport (ever). Everything Hermes/Signal/Papa Reo-specific (Part B, Part C).

### 1.3 Deliverables
`ovenmittd` image; `ovenmitt` Python package (client + MCP server); compose file; docs; test suite executing §9.

---

## 2. Actors and trust boundaries

| Actor | Where | Trust |
|---|---|---|
| **Operator** | host; `docker exec` into daemon container | Trusted. Writes config, holds admin CLI, issues credentials. The config file is the operator's authority; there is no other admin credential. |
| **Daemon** (`ovenmittd`) | daemon container | Trusted. Sole holder of plaintext, keys, audit log, config, destination roots/patterns. |
| **Agent trust domain** | agent container: LLM via harness, terminal tool, MCP server process, Python lib, consumer tool code | Untrusted for *reading*. Everything here can open the socket. |
| **Consumer** | tool code in the agent container holding a credential | Trusted to send bytes only where it declares. Distinguished from the rest of the agent domain by the credential and nothing else (F-6). |

**The boundary is the socket protocol.** No client-side code is load-bearing. Any property that depends on the MCP server or Python library behaving is a convenience, not a guarantee.

**Two secrets, two sentences.** Encryption keys never leave the daemon container; nothing to keep away. The consumer credential lives in the agent container by necessity and must be kept from the terminal tool by the deployer.

---

## 3. Requirements

### 3.1 Vaults (R-VLT)
- **R-VLT-1** A vault is a named store declared in operator config. Name grammar: `^[a-z0-9][a-z0-9_-]{0,63}$`.
- **R-VLT-2** Each vault has its own 256-bit key (KEK), generated by the daemon on first start for that vault, stored only in `keys_dir`. If a vault has objects but its key is missing or unreadable, the daemon **refuses to start**, naming the vault on stderr (F-28). It never generates a replacement key for a vault that has objects.
- **R-VLT-3** Per-vault settings: `expose_names` (default `false`), `ttl` (optional), `max_object_size` (optional), `destinations` (map, default empty = deny all).
- **R-VLT-4** `list_vaults` returns `[{name, expose_names, ttl}]` to any caller; `ovenmitt vault list` gives the operator the same plus destination names. Nothing else about a vault is agent-visible. There is no default vault.

### 3.2 Objects and handles (R-OBJ)
- **R-OBJ-1** Handle = `v_` + 12 lowercase hex chars (48 bits) from a CSPRNG; unique across the daemon; stable across `replace`. Handles are identifiers, not secrets: `list` reveals them.
- **R-OBJ-2** Agent-visible metadata is exactly: `handle, vault, size, mime, created, modified, labels[], expires_at?` and `name` only while the vault's `expose_names` is `true`. Never: content hash, storage path, key material, destination details.
- **R-OBJ-3** Objects are whole and atomic. A `put` commits only when the request body terminates cleanly; any other outcome leaves no object and no partial file visible to any operation. Temp files are swept at startup.
- **R-OBJ-4** `replace` streams a new body under an existing handle. The old body remains until the new one commits (F-24); on commit the old ciphertext is unlinked and its DEK destroyed. `modified` updates; `created`, labels and `name` carry over unless `name` is supplied again.
- **R-OBJ-5** `delete` unlinks ciphertext and destroys the DEK. Subsequent ops on the handle → `NOT_FOUND`.
- **R-OBJ-6** TTL: `expires_at = modified + ttl`. A sweep (default every 5 min) deletes expired objects with audit event `expire`. Any op on an expired-but-unswept object behaves as `NOT_FOUND` and triggers its deletion.
- **R-OBJ-7** `mime` is client-declared (`Content-Type`); default `application/octet-stream`; never inferred from bytes.
- **R-OBJ-8** Labels: UTF-8, ≤ 256 bytes each, ≤ 16 per object, settable at `put` and via `label` (replace-all). Agent-visible; never audited.
- **R-OBJ-9** `max_object_size`, if set, is enforced during streaming; exceeding it aborts with `TOO_LARGE` (a refusal), leaving no object.
- **R-OBJ-10** Optional client-supplied `X-Ovenmitt-Sha256` on `put`/`replace`: the daemon compares it to the streamed plaintext hash and refuses the commit with `INTEGRITY` on mismatch.
- **R-OBJ-11** The original name is always stored (encrypted with the object). `ovenmitt object stat <handle>` (operator, daemon container) always shows it (F-15).

### 3.3 Destinations (R-DST)
- **R-DST-1** Declared per vault in operator config, keyed by name (same grammar as vault names). Undeclared = denied. No API creates or alters destinations.
- **R-DST-2** `kind = "fs"`: `root` (absolute path inside the daemon container, must exist and be a directory at startup), `overwrite` (default `false`). Used by `export` only.
- **R-DST-3** `kind = "send"`: `match` (pattern per R-DST-6), `max_size` (optional). Used by `resolve` only. Every send is bytes; there is no inline-text mode (F-4).
- **R-DST-4** `list_destinations(vault)` returns `[{name, kind}]`. Never `root`, `match`, `overwrite`, `max_size`.
- **R-DST-5** `export` against a `send` destination, or `resolve` against an `fs` destination → `DESTINATION_KIND_MISMATCH`.
- **R-DST-6** Pattern grammar: `match` is a literal over `[A-Za-z0-9:_./+-]`, optionally ending in `/*`. A target matches iff it equals the literal, or (with `/*`) equals the literal minus `*` followed by one non-empty segment containing no `/`. Case-sensitive. Nothing else.

### 3.4 Put (R-PUT)
- **R-PUT-1** Wire: `POST /v1/vaults/{vault}/objects`, body = raw bytes (chunked or Content-Length). Optional headers: `Content-Type`, `X-Ovenmitt-Name`, `X-Ovenmitt-Label` (repeatable), `X-Ovenmitt-Sha256`, `X-Ovenmitt-Remove-Source-Requested: true` (informational).
- **R-PUT-2** Library: `put(data, vault, *, name=None, mime=None, labels=(), replace=None, sha256=None) -> ObjectInfo`; `data` is `bytes`, a binary file object, or an iterator of `bytes`. Streams; never buffers the whole body.
- **R-PUT-3** MCP: `vault_put(path, vault, remove_source=false)`. The MCP process opens the path, streams it, and on `201` (and only then) unlinks the source if asked. No inline-content parameter exists. Returns `ObjectInfo` only.
- **R-PUT-4** Response `201` with `ObjectInfo`. The daemon computes SHA-256 of plaintext during streaming and writes it to the audit entry only.

### 3.5 Export (R-EXP)
- **R-EXP-1** `export(handle, destination, filename)`: decrypts and writes to `<root>/<filename>` in the daemon container.
- **R-EXP-2** `filename` grammar: `^[A-Za-z0-9][A-Za-z0-9._ -]{0,254}$`, rejecting `..` anywhere; NFC-normalised first. Violation → `FILENAME_INVALID`.
- **R-EXP-3** Target = `realpath(root)` + `filename`, re-resolved at export time; not strictly under `realpath(root)/` → `PATH_ESCAPE`.
- **R-EXP-4** Collision → `EXISTS` unless the destination has `overwrite = true` (F-5). Temp-file-then-rename within `root`; mode `0644`.
- **R-EXP-5** Callable by any socket peer on both faces; no credential (F-26).

### 3.6 Resolve (R-RES)
- **R-RES-1** `POST /v1/objects/{handle}/resolve`, `Authorization: Bearer <credential>`, JSON `{destination, target}`. Success streams plaintext with `Content-Type`, `Content-Length`, `X-Ovenmitt-Destination`.
- **R-RES-2** Checks, in order, each a distinct refusal: credential present (`CREDENTIAL_REQUIRED`); valid and not revoked (`CREDENTIAL_INVALID`); scoped to the object's vault (`CREDENTIAL_NOT_PERMITTED`); destination exists in that vault (`DESTINATION_NOT_FOUND`); kind is `send` (`DESTINATION_KIND_MISMATCH`); `target` matches (`TARGET_NOT_ALLOWED`); size ≤ `max_size` if set (`TOO_LARGE`).
- **R-RES-3** `dest` and `target` are both written to the audit entry (F-27). `target` never appears in any response.
- **R-RES-4** Library: `resolve(handle, destination, target, credential) -> Resolved` with `.stream`, `.mime`, `.size`, `.destination`. The only client path that yields plaintext.
- **R-RES-5** No MCP tool wraps `resolve`.

### 3.7 Metadata ops (R-MET)
- **R-MET-1** `stat`, `list(vault?)`, `label`, `delete`, `list_vaults`, `list_destinations(vault)` — any socket peer.
- **R-MET-2** `list` ordered by `created` ascending; no pagination; hard cap 10 000 (`TOO_MANY`, not a refusal).

### 3.8 Credentials (R-CRD)
- **R-CRD-1** Token `ovm_<id:8 hex>_<secret:32 bytes base64url>`. `ovenmitt credential issue --name NAME [--vault V]...` (no `--vault` = all vaults) prints it once.
- **R-CRD-2** Daemon stores `{id, name, sha256(secret), vaults, created, revoked?}`; never the secret.
- **R-CRD-3** `ovenmitt credential revoke ID` takes effect on the next request. `ovenmitt credential list`.
- **R-CRD-4** Audit log carries `cred: <id>` only.
- **R-CRD-5** Delivering the credential to consumer code *and keeping it from the terminal tool* is the deployer's job. Docs say this is the read barrier.

### 3.9 Cryptography (R-CRY)
- **R-CRY-1** Random 256-bit DEK per object; AES-256-GCM in 1 MiB chunks; nonce = 8-byte per-object random prefix ‖ 32-bit chunk counter; AAD = handle ‖ chunk index ‖ final-chunk flag. DEK wrapped with the vault KEK.
- **R-CRY-2** `name`, labels, mime encrypted under the DEK; `handle`, `vault`, `size`, timestamps in a cleartext index.
- **R-CRY-3** Delete/replace/expire = unlink ciphertext + overwrite-and-unlink the wrapped DEK (F-8). No physical-erasure claim.
- **R-CRY-4** `keys_dir` and `data_dir` are distinct volumes in the reference compose. Losing `keys_dir` = losing every vault.
- **R-CRY-5** **Plaintext never touches disk inside the daemon.** `put` encrypts chunk-by-chunk as bytes arrive, straight into the temp file. (The second review's plaintext-temp-then-encrypt design is forbidden here.) Export is the one deliberate plaintext write, only under a declared `fs` root.

### 3.10 Audit (R-AUD)
- **R-AUD-1** Append-only JSONL at `audit_log`, single writer, one entry per line (§6.1).
- **R-AUD-2** Hash-chained: `prev` = SHA-256 of the previous entry's canonical bytes (RFC 8785 JCS); genesis `prev` = 64 zeros; `seq` from 1.
- **R-AUD-3** Events: `start`, `put`, `replace`, `delete`, `export`, `resolve`, `expire`, `label`, `request` (any request that could not be mapped to an operation, and any *refused* read — a `stat` of an unknown handle is logged as a refused `request`, so SI-7 holds for every refusal). Successful `stat`/`list`/`list_vaults`/`list_destinations`/`health` are not logged.
- **R-AUD-4** Outcome ∈ `ok | refused | aborted`. **Every** `refused`, including malformed requests and unknown routes, is logged with its error code.
- **R-AUD-5** Never logged: content bytes, label text, `root`, `match`, storage paths, credential secrets, `name` unless the vault's `expose_names` is `true`.
- **R-AUD-6** Entry written and fsynced before the response leaves the daemon.
- **R-AUD-7** `ovenmitt audit verify` → 0 intact / 1 first bad `seq` / 2 I/O. `ovenmitt audit head` prints the head hash for off-host anchoring (manual in v1).
- **R-AUD-8** No endpoint exposes the log. There is no way to turn auditing off, in whole or in part.

### 3.11 Review (R-REV)
- **R-REV-1** `ovenmitt audit review [--since DUR|TS] [--threshold low|medium|high|critical] [--json]` — rule-based, offline, reads the whole log.
- **R-REV-2** Built-in rules (§6.3): `refusal`, `first_destination`, `burst`, `churn`, `chain`. Defaults make brief §9.4 true.
- **R-REV-3** Findings → stderr, one per line, severity-descending; `--json` on stdout. Exit 0 / 1 (at or above threshold) / 2 (cannot read log). Chain failure is `critical` and always exits 1.
- **R-REV-4** `review` runs `verify` first and continues over the parseable prefix.

### 3.12 Deployment (R-DEP)
- **R-DEP-1** Daemon image runs `ovenmittd` as non-root; config at `/etc/ovenmitt/ovenmitt.toml` (read-only); volumes `ovenmitt-data`, `ovenmitt-keys`, `ovenmitt-audit`, `ovenmitt-sock`.
- **R-DEP-2** Socket `/run/ovenmitt/ovenmitt.sock` in `ovenmitt-sock`, mode `0666` (configurable `socket_mode`, `socket_group`).
- **R-DEP-3** **No TCP listener, no config key that could create one, ever.** The HTTP framing is an internal detail; documentation presents the socket as a file you mount, not a server you reach.
- **R-DEP-4** Reference compose mounts into the agent service only `ovenmitt-sock`. Never data, keys, audit, config, or any `fs` root.
- **R-DEP-5** Admin CLI = same binary via `docker exec`; not installed in the agent image.
- **R-DEP-6** Invalid config → refuse to start with a line-numbered error; `ovenmitt config check` runs the same validation.

### 3.13 Faces (R-FAC)
- **R-FAC-1** Python package `ovenmitt` ships `VaultClient` (§10.2) and `ovenmitt mcp [--socket PATH]`.
- **R-FAC-2** MCP tools, closed list: `vault_list_vaults`, `vault_list_destinations`, `vault_put`, `vault_stat`, `vault_list`, `vault_label`, `vault_delete`, `vault_export`. Descriptions must not suggest content can be retrieved.
- **R-FAC-3** MCP results carry only records and error codes; never bytes.
- **R-FAC-4** All faces send `X-Ovenmitt-Protocol: 1`; missing/unsupported → `PROTOCOL_UNSUPPORTED` (refusal).

### 3.14 Documentation (R-DOC)
- **R-DOC-1** Threat model from brief §3, in the "hard, not impossible" framing (F-1), plus §11 limitations.
- **R-DOC-2** Operator invariants (§11) as a checklist.
- **R-DOC-3** Tool-author guide: `put` from a stream, `resolve` contract, labels-are-visible warning, credential handling.
- **R-DOC-4** No platform, licence, provider or community names in code, config keys, defaults, shipped examples or tests, outside a marked motivating-case section. Operator config values are unrestricted (F-29).

---

## 4. Wire protocol

### 4.1 Transport
HTTP/1.1 over a Unix domain socket, as an internal framing choice (F-23). No TLS, no TCP, no HTTP/2. Requests carry `X-Ovenmitt-Protocol: 1`. JSON bodies are `application/json`; object bodies are raw bytes. A body on a bodiless route → `INVALID_REQUEST` (audited); only `put`/`replace` accept bytes in, only `resolve` returns bytes out. Header size ≤ 16 KiB; idle timeout 60 s on headers, none on bodies.

Why HTTP: streaming both ways, status codes and headers for free, `curl --unix-socket` tests every endpoint from a shell, hyper and httpx both speak UDS. The Docker daemon itself works this way.

Implementation clarifications (0.5): `/v1/health` is exempt from the protocol header so healthchecks stay one-liners. An unknown route *or an unsupported method on a known route* is `404 INVALID_REQUEST`. `X-Ovenmitt-Name` and `X-Ovenmitt-Label` values are percent-encoded UTF-8 (header values are ASCII; names are not). The server runs HTTP/1.1 with half-close enabled so a client that sends a request and closes before the response still has it processed and audited (R-AUD-6).

### 4.2 Endpoints

| Method & path | Auth | Request | Success | Audited |
|---|---|---|---|---|
| `GET /v1/health` | none | — | `200 {"status":"ok","protocol":1}` | no |
| `GET /v1/vaults` | none | — | `200 [VaultInfo]` | no |
| `GET /v1/vaults/{vault}/destinations` | none | — | `200 [DestinationInfo]` | no |
| `POST /v1/vaults/{vault}/objects` | none | raw body + headers (R-PUT-1) | `201 ObjectInfo` | `put` |
| `PUT /v1/objects/{handle}` | none | raw body + same headers | `200 ObjectInfo` | `replace` |
| `GET /v1/objects?vault={vault}` | none | — | `200 [ObjectInfo]` | no |
| `GET /v1/objects/{handle}` | none | — | `200 ObjectInfo` | no |
| `PATCH /v1/objects/{handle}` | none | `{"labels":[…]}` | `200 ObjectInfo` | `label` |
| `DELETE /v1/objects/{handle}` | none | — | `204` | `delete` |
| `POST /v1/objects/{handle}/export` | none | `{"destination","filename"}` | `200 {"destination","filename","size"}` | `export` |
| `POST /v1/objects/{handle}/resolve` | Bearer | `{"destination","target"}` | `200` raw body + `X-Ovenmitt-Destination`, `Content-Type`, `Content-Length` | `resolve` |
| anything else | — | — | `404 INVALID_REQUEST` | `request` (refused) |

`resolve` is the only route that returns object bytes and the only one that takes `Authorization`; SI-1 is checkable by reading this table.

### 4.3 Records

```json
VaultInfo       {"name":"private","expose_names":false,"ttl":"30d"}
DestinationInfo {"name":"team-chat","kind":"send"}
ObjectInfo      {"handle":"v_9c1e4a0b2d31","vault":"private","size":2123456,
                 "mime":"text/plain","created":"2026-10-12T08:00:00Z",
                 "modified":"2026-10-12T08:00:00Z","labels":["hui-notes"],
                 "expires_at":"2026-11-11T08:00:00Z","name":null}
Error           {"error":{"code":"TARGET_NOT_ALLOWED","message":"target not permitted for destination 'team-chat'"}}
```

`name` is present and `null` when hidden. Timestamps RFC 3339 UTC, millisecond precision.

### 4.4 Examples

```
curl --unix-socket /run/ovenmitt/ovenmitt.sock -X POST http://ovenmitt/v1/vaults/private/objects \
  -H 'X-Ovenmitt-Protocol: 1' -H 'Content-Type: text/plain' -H 'X-Ovenmitt-Label: hui-notes' \
  --data-binary @transcript.txt
→ 201 {"handle":"v_9c1e4a0b2d31", …}

curl --unix-socket /run/ovenmitt/ovenmitt.sock -X POST http://ovenmitt/v1/objects/v_9c1e4a0b2d31/resolve \
  -H 'X-Ovenmitt-Protocol: 1' -H 'Authorization: Bearer ovm_1a2b3c4d_…' \
  -H 'Content-Type: application/json' -d '{"destination":"team-chat","target":"chat:group/team"}'
→ 200, body = plaintext
```

`Host` is ignored.

---

## 5. Configuration schema

### 5.1 `ovenmitt.toml` (operator-only, read-only mount in the daemon container)

```toml
[daemon]
socket             = "/run/ovenmitt/ovenmitt.sock"
socket_mode        = "0666"
socket_group       = ""                              # optional
data_dir           = "/var/lib/ovenmitt/data"
keys_dir           = "/var/lib/ovenmitt/keys"
audit_log          = "/var/lib/ovenmitt/audit/audit.jsonl"
credentials        = "/var/lib/ovenmitt/credentials.toml"   # managed by `ovenmitt credential`
review_rules       = "/etc/ovenmitt/review.toml"     # optional
ttl_sweep_interval = "5m"

[vault.private]
expose_names    = false        # governs all objects in the vault, past and future
ttl             = "30d"        # optional; <int><s|m|h|d>
max_object_size = "2GiB"       # optional; <int><B|KiB|MiB|GiB>

[vault.private.destinations.nas-archive]
kind      = "fs"
root      = "/srv/nas/archive"
overwrite = false              # default

[vault.private.destinations.team-chat]
kind  = "send"
match = "chat:group/team"      # literal; operator value — platform names fine here, never in defaults

[vault.private.destinations.any-dm]
kind     = "send"
match    = "chat:dm/*"         # one trailing wildcard segment
max_size = "8MiB"              # optional
```

Validation (R-DEP-6): unknown keys are errors; names match the grammar; `kind`-specific keys only on that kind; `root` exists and is a directory; `match` parses per R-DST-6; durations and sizes parse; no duplicate names within a vault; relative paths are errors.

### 5.2 `credentials.toml` (daemon-managed)

```toml
[[credential]]
id      = "1a2b3c4d"
name    = "vault_send"
hash    = "sha256:…"
vaults  = ["private"]          # or "*"
created = "2026-10-12T08:00:00Z"
revoked = "2026-10-13T09:00:00Z" # absent until revoked
```

### 5.3 `review.toml` (optional; defaults shown)

```toml
threshold = "medium"

[rules.refusal]
severity = "high"

[rules.first_destination]
severity = "medium"

[rules.burst]
severity = "medium"
events   = ["resolve", "export", "delete"]
count    = 20
window   = "10m"

[rules.churn]
severity = "low"
count    = 10
window   = "1h"

[rules.chain]
severity = "critical"          # cannot be lowered below "high"
```

Any rule may set `enabled = false`.

---

## 6. Audit

### 6.1 Record format

```json
{"seq":42,"ts":"2026-10-12T08:01:02.123Z","event":"resolve","outcome":"ok",
 "vault":"private","handle":"v_9c1e4a0b2d31","sha256":"3f…e1","size":2123456,
 "dest":"team-chat","target":"chat:group/team",
 "caller":{"uid":1000,"pid":4321,"cred":"1a2b3c4d"},
 "reason":"TARGET_NOT_ALLOWED","name":"hui-notes.txt","remove_source_requested":true,
 "config_sha256":"ab…","prev":"7c…09"}
```

| Field | Present on | Notes |
|---|---|---|
| `seq`, `ts`, `event`, `outcome`, `caller`, `prev` | all | `caller.cred` only when a credential was presented; `uid`/`pid` from `SO_PEERCRED`, informational |
| `vault`, `handle` | object events | `handle` absent on a refused `put` that never allocated one |
| `sha256`, `size` | `put`, `replace`, `export`, `resolve`, `expire`, `delete` with outcome `ok` | plaintext SHA-256; audit-only |
| `dest` | `export`, `resolve` | name only |
| `target` | `resolve` | always (F-27) |
| `reason` | `refused` / `aborted` | error code (§7) |
| `name` | `put`, `replace` | only when the vault's `expose_names` is `true` |
| `remove_source_requested` | `put` | client claim |
| `config_sha256` | `start` | SHA-256 of the loaded config |

### 6.2 Chain and verification
Canonical form RFC 8785 over the entry including `prev`. `verify` checks parse, `seq` = line number, `prev` linkage, `ts` non-decreasing; first violation → exit 1 with `seq`. Tail truncation is not detectable by `verify` alone; `audit head` anchoring covers it and the docs say so.

### 6.3 Review rules and output

| Rule | Fires when | Default |
|---|---|---|
| `refusal` | any `outcome=refused` in window | high |
| `first_destination` | first ever `ok` `export`/`resolve` to a `(vault, dest)` pair | medium |
| `burst` | ≥ `count` `ok` entries of one event in `events` within a sliding `window` | medium |
| `churn` | ≥ `count` `replace`/`label`/`delete` on one handle within `window` | low |
| `chain` | `verify` fails | critical |

```
HIGH     refusal            seq=118        2026-10-12T08:14:01Z  resolve v_9c1e4a0b2d31 dest=team-chat reason=TARGET_NOT_ALLOWED cred=1a2b3c4d
MEDIUM   first_destination  seq=97         2026-10-12T08:02:40Z  export private/nas-archive
MEDIUM   burst              seq=200..231   2026-10-12T08:20:00Z  32 resolve in 10m
CRITICAL chain              seq=57         —                     prev mismatch
```

Cron: `ovenmitt audit review --since 24h`; nonzero exit mails the operator.

---

## 7. Error model

HTTP status + `{"error":{"code","message"}}`. `message` never contains roots, patterns, storage paths, targets, credential material, or hidden names. **Refusals** are audited; **errors** only when an operation had started (`aborted`).

| Code | HTTP | Refusal? | When |
|---|---|---|---|
| `INVALID_REQUEST` | 400/404 | yes | unknown route, bad JSON/header/handle, body on a bodiless route |
| `PROTOCOL_UNSUPPORTED` | 400 | yes | missing/unsupported `X-Ovenmitt-Protocol` |
| `VAULT_NOT_FOUND` | 404 | yes | |
| `NOT_FOUND` | 404 | yes | handle unknown, deleted or expired |
| `DESTINATION_NOT_FOUND` | 404 | yes | |
| `DESTINATION_KIND_MISMATCH` | 409 | yes | R-DST-5 |
| `CREDENTIAL_REQUIRED` | 401 | yes | |
| `CREDENTIAL_INVALID` | 401 | yes | unknown id, bad secret, revoked |
| `CREDENTIAL_NOT_PERMITTED` | 403 | yes | not scoped to this vault |
| `TARGET_NOT_ALLOWED` | 403 | yes | target fails `match` |
| `PATH_ESCAPE` | 403 | yes | R-EXP-3 |
| `FILENAME_INVALID` | 400 | yes | R-EXP-2 |
| `EXISTS` | 409 | yes | export collision |
| `TOO_LARGE` | 413 | yes | `max_object_size` / `max_size` |
| `INTEGRITY` | 422 | yes | `X-Ovenmitt-Sha256` mismatch |
| `LABEL_INVALID` | 400 | yes | R-OBJ-8 |
| `TOO_MANY` | 413 | no | `list` cap |
| `ABORTED` | — | audited as `aborted` | stream closed mid-op |
| `STORAGE` | 507 | no | disk full, I/O |
| `INTERNAL` | 500 | no | bug; details to daemon stderr only |

Checks run in the R-RES-2 order so a caller learns the least.

---

## 8. Security invariants (testable statements)

"Sentinel" = a unique 64-byte random string put into a vault at test setup.

| ID | Invariant | Test |
|---|---|---|
| SI-1 | No response from any endpoint contains object plaintext unless the request carried a valid, scoped credential and a matching send destination/target. | Every route without `Authorization`; `resolve` with each failing R-RES-2 condition; sentinel absent from all response bytes. |
| SI-2 | The daemon has no listening TCP/UDP socket and the config schema has no key that could open one. | `ss -ltnup` in the daemon container; schema review. |
| SI-3 | The agent container's filesystem holds no ciphertext, keys, audit log or config. | `docker compose config` shows only the socket volume; runtime search for sentinel, ciphertext, key files, audit file. |
| SI-4 | An export can only create a file strictly under `realpath(root)`. | Filename matrix (`..`, `/`, `\`, leading `.`, NUL, overlong, Unicode separators); root swapped for a symlink after start. |
| SI-5 | `resolve` succeeds iff every R-RES-2 condition holds. | Truth table over credential × destination × target. |
| SI-6 | No response body, header or error message contains `root`, `match`, storage paths, `target`, credential secrets, content hash, or `name` while `expose_names=false`. | Sentinel substrings in each; grep all returned bytes across every endpoint and failure path. |
| SI-7 | Every refused request yields exactly one `refused` audit entry with the returned `reason`, durable before the response. | Count; kill client immediately after send; entry present. |
| SI-8 | The audit log never contains content bytes, label text, `root`, `match`, storage paths, credential secrets, or `name` while `expose_names=false`. | Sentinels; grep after a full sweep. |
| SI-9 | Plaintext never exists on disk in the daemon container except under a declared `fs` root after `export`. | Sentinel absent under `data_dir` during a stalled put, after a crash mid-put, and after commit; two puts of identical content yield different ciphertext. |
| SI-10 | After `delete`/`replace`/`expire`, the previous body is unrecoverable through the daemon: ciphertext and wrapped DEK both gone. | File listing before/after; `stat`. |
| SI-11 | A put/replace whose stream doesn't terminate cleanly leaves no object and, after startup sweep, no file. | Close mid-body; restart; inspect. |
| SI-12 | Any modification, deletion, insertion or reordering of an audit line is detected by `verify`. | Mutate / drop / swap / duplicate; exit 1 at the right `seq`. |
| SI-13 | The MCP tool list is exactly R-FAC-2; no tool accepts inline content or returns bytes. | `tools/list`; schema check; sentinel sweep over every tool. |
| SI-14 | Credential secrets are stored nowhere in the daemon container. | Grep volumes and process env after issue; only the hash present. |
| SI-15 | `list_destinations` reveals only `{name, kind}`. | Schema check with sentinel roots/patterns. |
| SI-16 | A vault with objects but no key prevents startup, loudly, without re-keying. | Remove key; start; nonzero exit naming the vault; no new key file; no data touched. |
| SI-17 | No platform, licence, provider or community name in core code, config keys, defaults, shipped examples or tests. | Denylist grep, excluding the marked motivating-case section. |

---

## 9. Acceptance test plan

Environment: reference compose plus a `test-agent` service with the `ovenmitt` package, a credentialed consumer script and an uncredentialed agent script. Rust unit tests cover grammar, pattern matcher, chunked AEAD, JCS, chain verification.

| ID | Test | Verifies | Brief §9 |
|---|---|---|---|
| AT-1 | Library `put` from a stream → `ObjectInfo` only; sentinel absent. | R-PUT-2, R-OBJ-2, R-PUT-4 | 9.1 |
| AT-2 | MCP `vault_put(path)` → `ObjectInfo` only; `remove_source` unlinks only after `201`; log has `remove_source_requested`. | R-PUT-3, R-FAC-3 | 9.1 |
| AT-3 | `replace`: handle stable, `modified` updated, old ciphertext + DEK gone, labels carried. | R-OBJ-4, SI-10 | — |
| AT-4 | Credentialed `resolve(h, "team-chat", "chat:group/team")` byte-identical; log has `dest`, `target`, `cred`. | R-RES-1..4, R-AUD-5 | 9.2 |
| AT-5 | SI-5 truth table. | R-RES-2, SI-5 | 9.3 c, d |
| AT-6 | Kind mismatches both ways → `DESTINATION_KIND_MISMATCH`. | R-DST-5 | — |
| AT-7 | Read-path sweep: every route without credential, every MCP tool → no sentinel. (Replaces brief 9.3(a); F-1.) | SI-1, SI-13 | 9.3 a |
| AT-8 | Store not in agent container. | R-DEP-4, SI-3 | 9.3 b |
| AT-9 | Export path confinement matrix. | R-EXP-2/3, SI-4 | 9.3 e |
| AT-10 | Collision → `EXISTS`; with destination `overwrite=true` → atomic replace. | R-EXP-4 | — |
| AT-11 | `verify` passes after AT-1..10; `review --since 1h` lists every refusal from AT-5/6/7/9/10, exits 1 at default threshold, 0 at `critical`. | R-AUD-7, R-REV-1..3 | 9.4 |
| AT-12 | Audit tamper matrix → `verify` exit 1 at correct `seq`; `review` reports `chain`. | SI-12, R-REV-4 | — |
| AT-13 | Topology leak sweep with sentinel roots/patterns/names. | SI-6, SI-8, SI-15 | — |
| AT-14 | Aborted put/replace/resolve: no object / old body intact / `aborted` logged; restart leaves no temp files. | R-OBJ-3, SI-11 | — |
| AT-15 | TTL expiry: object gone, `expire` logged with hash and size; `replace` resets. | R-OBJ-6 | — |
| AT-16 | `max_object_size` / `max_size` mid-stream → `TOO_LARGE`, nothing stored / delivered. | R-OBJ-9, R-RES-2 | — |
| AT-17 | Credential lifecycle: printed once, not on disk, revoke without restart. | R-CRD-1..3, SI-14 | — |
| AT-18 | Config validation cases incl. a non-trailing `*` in `match`. | R-DEP-6, R-DST-6 | — |
| AT-19 | Missing key with existing objects → refuse to start per SI-16. | R-VLT-2, SI-16 | — |
| AT-20 | No TCP listener. | R-DEP-3, SI-2 | — |
| AT-21 | At-rest check per SI-9, including stalled and crashed mid-stream. | R-CRY-1, R-CRY-5, SI-9 | — |
| AT-22 | `expose_names` false: `name` null in responses, absent from log; true: present; operator `object stat` shows it either way. | R-OBJ-2, R-OBJ-11, R-AUD-5 | — |
| AT-23 | Refusal durability. | R-AUD-6, SI-7 | — |
| AT-24 | Review rules at threshold and one below; `--json` shape. | R-REV-2 | — |
| AT-25 | Protocol version missing / `2` → `PROTOCOL_UNSUPPORTED`. | R-FAC-4 | — |
| AT-26 | Pattern matcher table. | R-DST-6 | — |
| AT-27 | `X-Ovenmitt-Sha256` correct → 201; wrong → `INTEGRITY`. | R-OBJ-10 | — |
| AT-28 | Denylist grep. | R-DOC-4, SI-17 | — |
| AT-29 | `list_vaults` on MCP, wire and operator CLI. | R-VLT-4 | — |

Every `R-` and `SI-` ID appears in at least one row (R-DOC-1..3 reviewed, not tested; R-DEP-1/2/5 covered by AT-8).

---

## 10. Interface contract for Part B (external consumer)

### 10.1 Deployment contract
- Service `ovenmittd` in compose; volume `ovenmitt-sock` mounted into the agent service at `/run/ovenmitt`.
- Operator declares the messaging destinations under the relevant vault; Part A knows no platform.
- Operator issues one credential (`ovenmitt credential issue --name vault_send --vault <vault>`) and delivers it to `vault_send` by a route the terminal tool can't see. Part A cannot enforce this; it belongs in Part B's test (B4.4).

### 10.2 Library contract (`ovenmitt` Python package, protocol 1)

```python
from ovenmitt import VaultClient, ObjectInfo, Resolved, OvenmittError

c = VaultClient(socket_path="/run/ovenmitt/ovenmitt.sock")
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
#   Resolved.stream: Iterator[bytes]; .mime; .size; .destination
# OvenmittError(code: str, message: str, status: int)
```

**Future (not v1): `resolve_path`.** For consumer tools that only accept a filename: the library resolves as above into a `memfd` (an anonymous RAM-backed file that never appears on any filesystem) and spawns the tool with the descriptor inherited and `/dev/fd/N` as the path. Looks and behaves like a file; exists only for that child process; no name on disk to race or `cat`; no daemon support, no TCP. This replaces the brief's "signed localhost URLs", which would need TCP. A FIFO in the socket volume is the fallback for already-running daemons and is kept out until something needs it.

### 10.3 What Part A will not do for Part B
Scrub tool results, proxy LLM calls, detect content in context, send inline text, or know anything about chats, platforms or data URIs.

---

## 11. Documented limitations and operator invariants

These go in the docs verbatim.

1. **Hard, not impossible.** The system makes accidental leakage hard. A determined agent, a lying tool, or an operator who mounts a root into the agent container can defeat it.
2. **Two secrets.** Encryption keys never leave the daemon container. The consumer credential lives in the agent container and is the only read barrier; keep it out of the terminal tool's environment, PATH and readable files.
3. **No credential is needed for intended use.** Putting, labelling, exporting to declared roots, deleting — all credential-free by design.
4. **Export to a root you can see is a read path.** Unavoidable; not defended; the shipped compose never does it.
5. **MCP `put(path)` protects from commit onward.** Producers that must never expose bytes to the agent `put` from a stream through the library.
6. **Encryption at rest protects the data volume when it travels alone.** It never substitutes for isolation; the daemon must hold the key to run.
7. **No physical erasure.** Delete destroys the key and unlinks the ciphertext; it doesn't scrub sectors.
8. **`verify` cannot detect tail truncation.** Anchor `audit head` off-host on a schedule.
9. **Caller identity is the credential.** UID/PID in the log are informational.
10. **`expose_names` governs all objects in the vault, past and future.** Operators always see names via `object stat`.
11. **Labels and names are agent-visible.** Don't put content in them.
12. **Losing `keys_dir` loses every vault.** Back it up separately.
13. **Out of scope:** determined adversaries, lying tool code, prompt-injection covert channels, disk/log-fill DoS, multiple agent trust domains.

---

## 12. Names

| Brief | PRD |
|---|---|
| project `llm-safe-kaitiaki` | project **ovenmitt**; repo `utunga/oven-mitt` (hyphen in the repo name only) |
| `vault` / `vault mcp` / `vault audit …` | `ovenmitt` / `ovenmitt mcp` / `ovenmitt audit …` |
| daemon (unnamed) | `ovenmittd` |
| `vault.put()` | `VaultClient.put()` from package `ovenmitt` |
| MCP tools | `vault_*` (unchanged; "vault" is the right model for the LLM) |
| `v_9c1e4a` | `v_` + 12 hex |
| `resolve(h, destination)` | `resolve(h, destination, target, credential)` |
| signed localhost URLs (future) | `resolve_path` via memfd (future) |

---

## Appendix A — Reconciliation with the second review (`PRD-hermes_digicryptids.md`, removed from the tree in 8a63eb0; see git history)

**Converged independently:** resolve takes name + target (F-2/AMB-5); caller identity unfixable in Docker v1 (F-6/AMB-10); pattern grammar must be fixed (F-3/AMB-4); content hash audit-only (AMB-3); handles global (AMB-6); `remove_source` client-side (F-13/AMB-11); label bounds (F-14/AMB-12); body sends need rules (F-4/AMB-8); platform names in values not defaults (F-29/AMB-13).

**Adopted from the second review:** export's credential-free status elevated to a flag (F-26); optional client SHA-256 with `INTEGRITY`; the narrower trailing-`/*` grammar; generic `chat:` examples. Its degraded-vault proposal (AMB-14) was adopted in 0.2 and reversed in 0.3 for refuse-to-start (F-28). Its `E_ENCODING` became moot when body sends were removed (F-4).

**Rejected:**
- *"No operation on the library returns object bytes" (NI-1).* False — `resolve` is on the library (F-1).
- *Plaintext temp file during `put`, encrypted at commit.* Breaks at-rest encryption during every put and after any crash; R-CRY-5 forbids it.
- *`hello` handshake with client-declared `role`.* Self-attestation (F-6).
- *Custom NDJSON + binary framing.* Equivalent security, more to build, nothing on the box can test it (F-23).
- *`name` omitted vs `null`.* Kept `null`.
- *≥64-bit handles for guess-resistance.* Handles aren't secrets.
- *Review findings as JSONL on stderr.* Human lines on stderr, `--json` on stdout.

**Gaps shared by both drafts, fixed here only:** `list_vaults` (F-9); TTL reset (F-10); fs-root-into-agent (F-16); Hermes mirror for body sends (F-25, now moot); naming (F-17).

## Appendix B — Design interview, 2026-10-12

Decisions taken, in order: F-1 framing ("hard, not impossible", two secrets); F-7 keep encryption, separate keys volume, never a substitute for isolation; F-17 `ovenmitt`; F-23 HTTP/1.1 over UDS as internal detail, no TCP ever, `resolve_path` via memfd replaces signed URLs; F-27 target always logged, no switch, no per-vault admin credential; F-5 `overwrite` in config; F-4 body sends removed; F-28 refuse to start; F-2/F-3 three-argument `resolve` and minimal grammar; F-15 names stored, operator-visible, vault setting governs all; F-8 per-object keys and crypto-shred, explicit `delete`; F-18 vault-scoped credentials; F-9 `list_vaults`, no default vault. Defaults F-10..14, F-19..22, R-OBJ-1 accepted without a round.
