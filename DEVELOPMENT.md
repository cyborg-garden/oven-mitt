# ovenmitt — Development document

*Status: draft 0.1, 2026-10-12. Sits under PRD.md (0.4). The PRD says what and why; this says how, in what order, and what "done" means at each step. Where this document makes a decision the PRD left open, it's listed in §11 so it can be challenged.*

**Working rule:** every milestone ends with named acceptance tests (PRD §9) passing, not with "code written". No milestone starts until the previous one's tests pass on the Mac.

---

## 1. Shape of the thing

One Rust crate, one binary, three Python modules, one compose file.

- **`ovenmitt` (Rust binary).** `ovenmitt daemon` is the daemon; everything else is the operator CLI (`audit`, `credential`, `vault`, `object`, `config`). One binary because the CLI must read the same config, keys, audit log and credentials file as the daemon, with the same code. The daemon image symlinks `ovenmittd → ovenmitt daemon` for the compose file's readability. Only this image ever contains the binary.
- **`ovenmitt` (Python package).** `client.py` (the library), `mcp.py` (the MCP server), `cli.py` (the `ovenmitt mcp` console script). Only the agent image ever contains this package. The name clash with the Rust binary is harmless because the two never share a container; the docs say so once.
- **Compose.** Two services for the reference deployment (`ovenmittd`, `agent`) and a third for tests (`test-agent`).

The security boundary is the daemon's socket handling (PRD §2). Nothing in the Python package is load-bearing; it exists to be convenient and to make the MCP tool list closed (SI-13).

---

## 2. Repository layout

```
oven-mitt/
├── Cargo.toml                 crate `ovenmitt`, edition 2024, `rust-version = "1.97"`
├── src/
│   ├── lib.rs                 module list; the bin and `tests/` both use the library
│   ├── main.rs                clap dispatch only
│   ├── daemon.rs              startup sequence (§5), serve loop
│   ├── config.rs              TOML schema, validation (R-DEP-6), duration/size grammars
│   ├── pattern.rs             send-pattern grammar + matcher (R-DST-6)
│   ├── handle.rs              `v_` + 12 hex, parse/validate
│   ├── crypto.rs              KEK/DEK, chunked AEAD reader/writer (R-CRY-1)
│   ├── keys.rs                keys_dir: load, create-on-first-use, refuse-if-missing (R-VLT-2)
│   ├── store/
│   │   ├── mod.rs             Store: in-memory index + per-handle locks
│   │   ├── layout.rs          on-disk paths (§4)
│   │   ├── put.rs             streaming commit, replace, temp sweep
│   │   ├── meta.rs            cleartext + encrypted metadata records
│   │   └── ttl.rs             sweep task
│   ├── export.rs              filename grammar, NFC, realpath confinement (R-EXP)
│   ├── credential.rs          token format, hashed store, mtime reload, scope check (R-CRD)
│   ├── audit/
│   │   ├── mod.rs             Entry type, event/outcome enums
│   │   ├── canon.rs           canonical JSON (§6)
│   │   ├── writer.rs          single-writer task, chain state, fsync-before-ack (R-AUD-6)
│   │   ├── verify.rs          chain walk, head hash
│   │   └── review.rs          rules, findings, exit codes (R-REV)
│   ├── api/
│   │   ├── mod.rs             axum Router — the one routing table (PRD §4.2)
│   │   ├── error.rs           ApiError: code → (status, fixed message), refusal flag
│   │   ├── outcome.rs         handler result → audit entry + HTTP response, one path
│   │   ├── peer.rs            SO_PEERCRED into request extensions
│   │   ├── objects.rs         put / replace / stat / list / label / delete
│   │   ├── export.rs
│   │   ├── resolve.rs
│   │   └── vaults.rs          list_vaults / list_destinations / health
│   └── cli/
│       ├── audit.rs           verify | review | head
│       ├── credential.rs      issue | list | revoke
│       ├── vault.rs           list
│       ├── object.rs          stat (operator view, shows name)
│       └── config.rs          check
├── tests/                     Rust integration tests: daemon in-process on a temp socket
│   ├── common/mod.rs          spawn daemon with a generated config + temp dirs
│   ├── api_*.rs               one file per PRD area
│   └── audit_*.rs
├── python/
│   ├── pyproject.toml         package `ovenmitt`, Python ≥ 3.11, deps: httpx, mcp
│   ├── src/ovenmitt/
│   │   ├── __init__.py        VaultClient, types, OvenmittError
│   │   ├── client.py
│   │   ├── types.py
│   │   ├── errors.py
│   │   ├── mcp.py             FastMCP server: the eight tools, nothing else
│   │   └── cli.py             `ovenmitt mcp [--socket PATH]`
│   └── tests/                 pytest against a running daemon (socket path via env)
├── docker/
│   ├── Dockerfile             multi-stage: rust:1.99-bookworm → debian:bookworm-slim, non-root
│   ├── Dockerfile.agent       python:3.12-slim + the package; used for `agent` and `test-agent`
│   ├── docker-compose.yml     reference deployment
│   ├── docker-compose.test.yml  adds test-agent + sentinel fs root
│   └── example/
│       ├── ovenmitt.toml
│       └── review.toml
├── tests-e2e/                 pytest driving `docker compose` from the host: the AT-n table
│   ├── conftest.py            compose up/down, sentinel fixtures, log readers
│   └── test_at_*.py
├── docs/                      README sources: threat model, operator checklist, tool-author guide
├── BRIEF.md  PRD.md  DEVELOPMENT.md  LICENSE
└── .github/workflows/ci.yml   fmt, clippy -D warnings, cargo test, python tests, image build
```

Not a Cargo workspace: one crate is enough and a workspace adds ceremony with no second crate to justify it. Split if a second binary ever appears. The crate has a library target plus the one binary, so integration tests in `tests/` can call modules directly and the binary stays a dispatcher.

No `rust-toolchain.toml`: the cloud shell where day-to-day builds happen has 1.97 and can't download toolchains, so `rust-version = "1.97"` is the floor and anything newer (your Mac has 1.99) is fine. Pin a toolchain file when CI needs reproducibility badly enough to pay for it.

---

## 3. Dependencies

Pin the exact versions at `cargo add` time and commit `Cargo.lock`; the names and roles are what's decided here.

**Rust**

| Crate | Role | Note |
|---|---|---|
| `tokio` (full) | runtime, `UnixListener`, `UnixStream::peer_cred()` | peer_cred gives UID/PID with no extra crate |
| `axum` 0.8 | HTTP router over the Unix listener | `axum::serve` accepts a `UnixListener` directly |
| `hyper`, `http-body-util` | streaming bodies in and out | pulled in by axum; used directly for `Body::from_stream` |
| `tower-http` | request-body limit layer only | `max_object_size` enforced in the chunker too; the layer is a backstop |
| `serde`, `serde_json`, `toml` | config, wire JSON, audit JSON | |
| `clap` (derive) | CLI | |
| `aes-gcm` | AES-256-GCM | RustCrypto; `Aes256Gcm` with 96-bit nonces |
| `rand` | CSPRNG for handles, DEKs, nonces, credential secrets | `OsRng` only |
| `sha2`, `hex`, `base64` | hashes, encodings | |
| `zeroize` | wipe KEK/DEK buffers on drop | |
| `jiff` or `time` | RFC 3339 UTC timestamps | pick one; never `chrono` + `time` both |
| `unicode-normalization` | NFC for export filenames (R-EXP-2) | |
| `thiserror`, `anyhow` | errors: typed in the library-ish modules, `anyhow` only in `main`/CLI | |
| `tracing`, `tracing-subscriber` | daemon logging to stderr | never logs content, names, targets, roots — same rules as audit |
| `tempfile` (dev) | tests | |

Not used, deliberately: a JCS crate (§6 explains why we don't need one), `nix` (tokio covers peer_cred), any database (§4), any TLS.

**Python**

| Package | Role |
|---|---|
| `httpx` | HTTP over UDS: `httpx.HTTPTransport(uds=path)`; streaming request and response bodies |
| `mcp` | official SDK; `FastMCP` for the server |
| `pytest`, `pytest-asyncio` (dev) | |

Built with `uv`; `uv build` produces the wheel the agent image installs.

---

## 4. On-disk layout (daemon container)

```
/var/lib/ovenmitt/
├── data/                       volume ovenmitt-data
│   ├── objects/<handle>/
│   │   ├── meta.json           cleartext: handle, vault, size, mime?, created, modified, expires_at, gen
│   │   └── gen-<N>/
│   │       ├── dek.wrap        12-byte nonce ‖ AES-GCM(KEK, DEK)
│   │       ├── meta.enc        AEAD(DEK): {name, labels, mime}
│   │       └── body.enc        chunked AEAD(DEK) (R-CRY-1)
│   └── tmp/                    in-flight commits; swept at startup
├── keys/<vault>.key            volume ovenmitt-keys; 32 raw bytes, mode 0600
├── audit/audit.jsonl           volume ovenmitt-audit
└── credentials.toml            volume ovenmitt-data (daemon-managed; CLI writes tmp+rename)
/run/ovenmitt/ovenmitt.sock     volume ovenmitt-sock
/etc/ovenmitt/ovenmitt.toml     read-only bind mount
/etc/ovenmitt/review.toml       read-only bind mount, optional
```

**Why `mime` appears in both `meta.json` and `meta.enc`:** `list` needs it without decrypting; it's agent-visible anyway. `name` and `labels` are only in `meta.enc`.

**Commit protocol (R-OBJ-3, R-OBJ-4).** A `put` writes `tmp/<handle>.<rand>/gen-1/…` while streaming, encrypting each chunk as it arrives (R-CRY-5), fsyncs the files and the directory, then writes `meta.json` and renames the directory to `objects/<handle>/`. A `replace` writes `tmp/<handle>.<rand>/gen-<N+1>/…`, moves it into `objects/<handle>/`, rewrites `meta.json` atomically (tmp + rename) with `gen = N+1`, then shreds the old generation: overwrite `dek.wrap` with zeros, fsync, unlink the directory. Any crash before the `meta.json` rename leaves either the old generation intact or a `tmp/` directory the startup sweep removes. `delete` and `expire` are the shred step applied to the current generation, then the object directory.

**Index.** Built at startup by reading every `meta.json` (10k objects is milliseconds). Held in a `RwLock<HashMap<Handle, Meta>>` plus a per-handle `Mutex` for writers. No SQLite in v1; if listing ever hurts, add it then.

**Credentials reload.** `credential.rs` stats the file on each `resolve`; if mtime changed, re-parse. That's how revoke takes effect without a restart (R-CRD-3) and it costs one `stat` per resolve.

---

## 5. Daemon startup sequence

In order, each step fatal on failure with a one-line reason on stderr:

1. Parse config; run every validation in R-DEP-6 (same code as `ovenmitt config check`).
2. For each vault: open key file. Missing key **and** `objects/` has any object of that vault → refuse (R-VLT-2, SI-16). Missing key and no objects → generate, write 0600, fsync.
3. Sweep `data/tmp/`.
4. Build the index; delete anything already expired (audited as `expire`).
5. Open the audit log; walk the chain (§6). Broken chain → refuse (D-1).
6. Write the `start` entry (config SHA-256).
7. Bind the socket (unlink stale socket file first; chmod per `socket_mode`; chgrp if `socket_group`).
8. Spawn the TTL sweep task and the audit writer task; serve.

`SIGTERM`: stop accepting, let in-flight requests finish (bounded, 30 s), write nothing special — the log needs no "stop" entry to verify.

---

## 6. Audit implementation

**Entry shape** is PRD §6.1. The Rust type is a struct with `Option` fields; serialisation drops `None`.

**Canonical form.** RFC 8785 requires keys sorted by UTF-16 code unit and ES6 number formatting. Every key we emit is ASCII, and every number we emit is an integer (`seq`, `size`, `uid`, `pid`) — so sorted-ASCII keys with `serde_json`'s compact output *is* JCS for our records. `canon.rs` serialises into a `BTreeMap<&str, Value>` and asserts (debug and a unit test) that no `Value::Number` is a float. Rule for the codebase: **no floats in audit entries, ever.** That rule is what lets us skip a JCS dependency; it goes in a comment at the top of `canon.rs`.

**Writer.** One task owns the file handle and the chain state (last entry's hash, next `seq`). Handlers send `(Entry, oneshot::Sender<()>)` over an mpsc channel; the task fills `seq`/`prev`, appends the line, `fsync`s, then acks. The handler awaits the ack before returning its response (R-AUD-6). Throughput is irrelevant at our volumes; correctness isn't.

**Startup walk.** Read the whole file, verify the chain, recover the head. A broken chain refuses startup (D-1) rather than appending to a log that can no longer be trusted. The message tells the operator to move the file aside; `verify` on the old file still works.

**Review.** `review.rs` loads the whole log, runs `verify` first, then each enabled rule over entries in the `--since` window with the full history available for `first_destination`. Findings sort by severity then `seq`. Output per PRD §6.3.

---

## 7. API implementation notes

**One routing table** (`api/mod.rs`), in the PRD §4.2 order, with a fallback that audits `request`/`refused`/`INVALID_REQUEST`. Nothing else registers routes.

**Protocol header** is checked in a middleware before routing; failure is a refusal (audited) so it goes through `outcome.rs` like everything else.

**Outcome path.** Every handler returns `Result<Success, ApiError>` plus an `AuditContext { event, vault, handle, dest, target, cred, … }` it fills in as it learns things. `outcome.rs` is the only place that (a) writes the audit entry, (b) builds the HTTP response. Refusal ordering (R-RES-2) is the order the handler performs checks; a handler fills `reason` from the first failing check and stops. This is what makes SI-7 ("exactly one entry per refusal") hold by construction rather than by discipline.

**Error hygiene (SI-6).** `ApiError` carries a code and, optionally, a destination name or handle — never anything else. Messages are fixed strings per code in `error.rs`. There is no `ApiError::Other(String)`.

**Put/replace stream.** `Body` → `DataStream` → chunker (1 MiB) → `crypto::Writer` (encrypt + hash + size count) → temp file. Size limit checked per chunk; exceeding it aborts with `TOO_LARGE` before the next chunk is read. Client disconnect surfaces as a stream error → `aborted`, temp dir removed.

**Resolve stream.** Checks first (all of R-RES-2, in order, before opening the body); then `crypto::Reader` yields decrypted chunks into `Body::from_stream`. If the file lacks a final-chunk marker, the reader errors — that's the truncation detection in R-CRY-1. `Content-Length` is known from `meta.json`.

**Peer credentials.** `api/peer.rs` implements axum's `Connected` for the Unix stream, pulling `peer_cred()` into a `PeerInfo { uid, pid }` extension. Informational only (F-6); nothing branches on it.

**Chunked AEAD detail.** Nonce = 8 random bytes (per object generation) ‖ 4-byte big-endian chunk index. AAD = `handle` bytes ‖ index ‖ `0x01` if final else `0x00`. The final chunk may be zero-length (when the body is an exact multiple of 1 MiB, or empty). File = `[8-byte nonce prefix][chunk…]`, each chunk = `[u32 ciphertext length][ciphertext ‖ tag]`. Reader rejects a missing final marker, an index gap, or trailing bytes after the final chunk.

---

## 8. Python package notes

- `VaultClient` is thin: one method per endpoint, PRD §10.2 signatures exactly. `put` accepts `bytes`, a file object, or an iterator; it hands httpx a generator so nothing is buffered. `resolve` returns a `Resolved` whose `.stream` iterates `httpx` response chunks; the response is closed when the iterator is exhausted or the object is used as a context manager.
- `errors.py`: `OvenmittError(code, message, status)` raised from any non-2xx; the code is the wire code, unchanged.
- `mcp.py`: `FastMCP("ovenmitt")` with exactly the eight tools in R-FAC-2. Tool docstrings are the descriptions the LLM sees; they say what each tool returns (metadata) and never mention reading. `vault_put` opens the path, calls `client.put`, and unlinks only on success when `remove_source` is set. There is one unit test whose whole job is to assert the tool list equals the fixed set (SI-13).
- No `resolve` anywhere in `mcp.py`; `grep -c resolve python/src/ovenmitt/mcp.py` is a CI check, crude and effective.

---

## 9. Containers and compose

**Daemon image.** Stage 1 `rust:1.99-bookworm` builds `--release`; stage 2 `debian:bookworm-slim` copies the binary, creates user `ovenmitt`, declares the four volumes, `ENTRYPOINT ["ovenmitt"]`, `CMD ["daemon"]`. No shell tools beyond what slim ships; `docker exec <id> ovenmitt audit review` is the operator path. Built for the container's own architecture — on the Mac that's arm64, which is fine for local use; CI builds amd64 too.

**Agent image.** `python:3.12-slim`, `pip install` the wheel from `uv build`. `CMD ["ovenmitt", "mcp"]` for the reference `agent` service; the `test-agent` service overrides the command to sleep and tests `exec` into it.

**Reference compose** mounts into `agent` only `ovenmitt-sock` (R-DEP-4). The test compose adds a `sentinel-root` volume mounted into the daemon as an `fs` destination root *and nowhere else*, so AT-8/AT-13 can assert absence from the agent container.

---

## 10. Test layers, and which AT each one owns

| Layer | Runs with | Owns |
|---|---|---|
| Rust unit (`#[cfg(test)]`) | `cargo test` on the Mac, or my shell | grammars (names, filenames, durations, sizes), pattern matcher (AT-26), handle format, chunked AEAD round-trip + truncation/reorder rejection, canonical JSON + no-floats, chain verify + tamper matrix (AT-12), review rules at/under threshold (AT-24), credential token format |
| Rust integration (`tests/`) | `cargo test`; daemon in-process on a temp socket; raw `hyper` client | every route and error code (AT-1, 5, 6, 7, 16, 25, 27), export confinement (AT-9, 10), TTL (AT-15), aborted streams (AT-14), at-rest sentinel scans (AT-21), refusal durability (AT-23), credential lifecycle (AT-17), `expose_names` (AT-22), config validation and key-refusal (AT-18, 19) |
| Python (`python/tests`) | `pytest` against a daemon started by the Rust test helper binary or a local `ovenmitt daemon` | client parity with the wire, MCP tool list (SI-13 / AT-2), `vault_put` unlink-after-201, `list_vaults` on MCP (AT-29) |
| End-to-end (`tests-e2e/`) | `pytest` on the Mac driving `docker compose -f docker/docker-compose.test.yml` | store absent from agent container (AT-8), no TCP listener (AT-20), `verify`/`review` via `docker exec` (AT-11), full sentinel sweep across containers (AT-13), denylist grep (AT-28) |

CI runs the first three on every push and the fourth on a manual trigger and on tags (it needs Docker-in-CI and is slow). The Mac runs all four before any tag.

**Sentinel discipline.** Every test that asserts "X never appears" uses a fresh 64-byte random string generated per test, never a fixed constant, so a stale fixture can't make a leak test pass.

---

## 11. Decisions made here, not in the PRD

| # | Decision | Why |
|---|---|---|
| D-1 | A broken audit chain at startup refuses startup. | Appending to an untrusted chain hides the break; the operator moves the file aside and keeps the old one for `verify`. Same "loud, not half-working" posture as F-28. |
| D-2 | One Rust binary with a `daemon` subcommand; `ovenmittd` is a symlink in the image. | CLI and daemon share config, keys, audit, credentials code; two binaries would drift. |
| D-3 | On-disk layout is directories and files, no database; index rebuilt at startup. | 10k objects reads in milliseconds; a database is a second thing to get wrong and back up. |
| D-4 | Audit entries contain no floats; canonical JSON is sorted-key compact `serde_json`. | Makes RFC 8785 trivial without a dependency. Enforced by test. |
| D-5 | Credentials file is re-read on mtime change, not on a signal. | Revoke-without-restart with one `stat` per resolve and no signal handling. |
| D-6 | `mime` is duplicated in cleartext `meta.json`. | `list` must not decrypt; `mime` is agent-visible anyway. |
| D-7 | Python ≥ 3.11. | `tomllib`, modern typing; nothing older is worth supporting for a new package. |
| D-8 | Daemon image built per-architecture inside Docker, never cross-compiled from the Mac. | The binary that runs in the container is built for the container. |
| D-9 | Work lands on `tumu` in small commits; a feature branch + PR only when a milestone touches more than one layer at once. | Solo project; PR ceremony for every commit slows it down without catching anything a test run doesn't. Change this if a second contributor appears. |

---

## 12. Milestones

Each milestone's "done" is a list of tests passing on the Mac. Order is dependency order; nothing is parallel.

| M | Deliverable | Done when |
|---|---|---|
| **M0** | Scaffold: `Cargo.toml`, `rust-toolchain.toml`, `main.rs` with clap skeleton, `config.rs` + `config check`, CI workflow (fmt, clippy `-D warnings`, test), `python/pyproject.toml` stub, `docker/Dockerfile` that builds. | `cargo clippy` clean; `ovenmitt config check docker/example/ovenmitt.toml` passes and every R-DEP-6 negative case fails with a line number (AT-18); `docker build` succeeds. |
| **M1** | Primitives: `handle.rs`, `pattern.rs`, `crypto.rs`, `keys.rs`, `audit/canon.rs`. | Unit tests: AT-26; AEAD round-trip, truncation, reorder, zero-length final; no-floats assertion; key create / refuse-if-missing (AT-19 at unit level). |
| **M2** | Store: put, replace, stat, list, label, delete, TTL sweep, temp sweep; `export.rs` grammar + confinement. | Unit + in-process tests for commit atomicity, replace shred, expiry (AT-3, 14, 15 logic), filename matrix (AT-9 logic), sentinel scan of `data_dir` (AT-21). |
| **M3** | Audit writer, verify, head; `ovenmitt audit verify|head`. | Tamper matrix (AT-12); fsync-before-ack test (AT-23 logic); startup refuses on broken chain (D-1). |
| **M4** | HTTP API over UDS: all routes except `resolve`; error model; protocol header; peer info; outcome path. | Rust integration: AT-1, 5 (except credential cells), 6, 7, 14, 15, 16, 22, 25, 27; SI-6 sentinel sweep over every route. |
| **M5** | Credentials + `resolve` + `export` end to end; `ovenmitt credential …`. | AT-4, AT-5 full truth table, AT-9, AT-10, AT-17; `target` present in audit entries. |
| **M6** | Review: rules, output, exit codes; `ovenmitt audit review`; `vault list`, `object stat`. | AT-11 (in-process), AT-24. |
| **M7** | Python client + MCP server + `ovenmitt mcp`. | Python tests: AT-2, AT-29, SI-13 tool-list test, parity test for every endpoint. |
| **M8** | Compose (reference + test), agent image, e2e suite. | AT-8, 11 (via `docker exec`), 13, 20, 28 on the Mac. **This is the v1 acceptance gate** — brief §9 maps to AT-1/2, 4, 5–9, 11. |
| **M9** | Docs: README with PRD §11 verbatim, operator checklist, tool-author guide, threat model in the "hard, not impossible" framing; `CHANGELOG`; tag `v0.1.0`. | A reviewer can deploy from the README alone; every R-DOC item has a section. |

Rough shape of effort: M0–M3 are where Rust is learned; expect them to be slow and the rest fast. M4 is the largest single milestone. M8 is where surprises live (socket permissions across containers, arm64/amd64).

---

## 13. Conventions

- `#![forbid(unsafe_code)]` at the crate root. No exceptions; nothing here needs it.
- `cargo fmt` default; `cargo clippy --all-targets -- -D warnings` clean before every commit.
- No `unwrap()`/`expect()` outside tests and `main.rs` startup. Errors are `thiserror` enums per module; `anyhow` only at the CLI edge.
- Logging via `tracing` to stderr at `info` by default; `debug` never includes names, labels, targets, roots or content, same rules as the audit log — a log line is a leak path too.
- Secrets (`KEK`, `DEK`, credential secrets) live in `Zeroizing<[u8; 32]>` and are never `Debug`-printed; the types implement a `Debug` that prints `[redacted]`.
- Tests that assert absence use per-test random sentinels (§10).
- Commit messages: imperative subject, body says why; reference `R-`/`SI-`/`AT-` IDs when a commit makes one pass.
- `CHANGELOG.md` from M0 onward, "Unreleased" section, keep-a-changelog style.

---

## 14. What I need from you before M0

Nothing. `cargo 1.99` and `docker compose v5.1.2` are confirmed. I'll install Rust in my own shell at M0 and run `cargo test` there as I go; you run the same on the Mac at each milestone gate and the e2e suite at M8.
