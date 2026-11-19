# ovenmitt: development

*This document says how ovenmitt is built and how it is tested.
[PRD.md](PRD.md) says what it does and why.
Where this document makes a decision the PRD left open, the decision is listed in [§11](#11-decisions-made-here-not-in-the-prd) so it can be challenged.
First drafted 2026-10-12 against PRD 0.4.
Milestones M0 to M9 are complete; see [§12](#12-milestones).*

To run the tests, see [README § Developing](README.md#developing).
Changes are listed in [CHANGELOG.md](CHANGELOG.md).

**Working rule:** a milestone ends when its named acceptance tests ([PRD §9](PRD.md#9-acceptance-test-plan)) pass.
Written code alone does not end it.
No milestone starts until the previous one's tests pass locally.

---

## 1. Shape of the thing

One Rust crate, one binary, one Python package, one compose file.

- **`ovenmitt` (Rust binary).** `ovenmitt daemon` runs the daemon. Every other subcommand is the operator CLI (`audit`, `credential`, `vault`, `object`, `config`). It is one binary because the CLI must read the same config, keys, audit log and credentials file as the daemon, with the same code. The daemon image symlinks `ovenmittd` to the binary so the compose file reads clearly. Only the daemon image contains the binary.
- **`ovenmitt` (Python package).** `client.py` is the library, `mcp.py` the MCP server, and `cli.py` the `ovenmitt mcp` console script. Only the agent image contains this package. The name clash with the Rust binary is harmless, because the two never share a container.
- **Compose.** The reference deployment has two services (`ovenmittd`, `agent`). The test overlay adds a third (`test-agent`).
- **Hermes bridge.** `hermes-plugin/` and `hermes-skill/` hold the Hermes plugin and its skill. See [hermes-plugin/README.md](hermes-plugin/README.md).

The security boundary is the daemon's socket handling ([PRD §2](PRD.md#2-actors-and-trust-boundaries)).
Nothing in the Python package is load-bearing.
It exists for convenience and to keep the MCP tool list closed (SI-13).

---

## 2. Repository layout

```
oven-mitt/
├── Cargo.toml                 crate `ovenmitt`, edition 2024, `rust-version = "1.97"`
├── src/
│   ├── lib.rs                 module list; the bin and `tests/` both use the library
│   ├── main.rs                clap dispatch only
│   ├── daemon.rs              startup sequence (§5), accept loop, serve
│   ├── config.rs              TOML schema, validation (R-DEP-6), duration/size grammars
│   ├── pattern.rs             send-pattern grammar + matcher (R-DST-6)
│   ├── handle.rs              `v_` + 12 hex, parse/validate
│   ├── crypto.rs              KEK/DEK, chunked AEAD reader/writer (R-CRY-1)
│   ├── keys.rs                keys_dir: load, create-on-first-use, refuse-if-missing (R-VLT-2)
│   ├── time.rs                RFC 3339 timestamps
│   ├── store/
│   │   ├── mod.rs             Store: index, per-handle locks, put/replace, temp sweep, TTL
│   │   ├── layout.rs          on-disk paths (§4), shred
│   │   └── meta.rs            cleartext + encrypted metadata records
│   ├── export.rs              filename grammar, NFC, realpath confinement (R-EXP)
│   ├── credential.rs          token format, hashed store, mtime reload, scope check (R-CRD)
│   ├── audit/
│   │   ├── mod.rs             Entry type, event/outcome enums
│   │   ├── canon.rs           canonical JSON (§6)
│   │   ├── writer.rs          single-writer task, chain state, fsync-before-ack (R-AUD-6)
│   │   ├── verify.rs          chain walk, head hash
│   │   └── review.rs          rules, findings, exit codes (R-REV)
│   ├── api/
│   │   ├── mod.rs             axum Router: the one routing table (PRD §4.2)
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
│   ├── api.rs  resolve.rs  store.rs
│   ├── cli_audit.rs  cli_review.rs  config_check.rs
│   └── denylist.rs            AT-28 domain-name denylist
├── python/
│   ├── pyproject.toml         package `ovenmitt`, Python ≥ 3.11, deps: httpx; extra `mcp`
│   ├── src/ovenmitt/
│   │   ├── __init__.py        VaultClient, types, OvenmittError
│   │   ├── client.py
│   │   ├── types.py
│   │   ├── errors.py
│   │   ├── mcp.py             MCP server: the eight tools, nothing else
│   │   └── cli.py             `ovenmitt mcp [--socket PATH]`
│   └── tests/                 pytest against a real daemon (binary via OVENMITT_BIN or target/debug)
├── hermes-plugin/             Hermes plugin `ovenmitt_bridge`
├── hermes-skill/              the `ovenmitt` skill
├── tests-plugin/              the plugin's tests, incl. run-in-agent-image.sh
├── docker/
│   ├── Dockerfile             multi-stage: rust:1.97-bookworm → debian:bookworm-slim, non-root
│   ├── Dockerfile.agent       python:3.12-slim + the package with the mcp extra
│   ├── Dockerfile.pytest      the Python tests on Linux, for macOS hosts
│   ├── docker-compose.yml     reference deployment
│   ├── docker-compose.test.yml  overlay: test-agent + generated sentinel config
│   └── example/
│       ├── ovenmitt.toml
│       └── review.toml
├── tests-e2e/                 pytest driving `docker compose` from the host
│   ├── conftest.py            compose up/down, sentinel fixtures, log readers
│   └── test_e2e.py
├── scripts/                   check_sanitization.py and its tests
├── README.md  BRIEF.md  PRD.md  DEVELOPMENT.md  CHANGELOG.md  LICENSE
└── .github/workflows/         rust.yml, python.yml, e2e.yml (one per badge), sanitization.yml
```

There is no Cargo workspace.
One crate is enough, and a workspace adds ceremony with no second crate to justify it.
Split if a second binary ever appears.
The crate has a library target plus the one binary, so integration tests in `tests/` can call modules directly and the binary stays a dispatcher.

There is no `rust-toolchain.toml`.
Some development environments have 1.97 and can't download toolchains, so `rust-version = "1.97"` is the floor, and the Docker images build with 1.97.
CI pins 1.99.0 because clippy's lint set changes between releases, and `-D warnings` turns a new lint into a red build.
A lint that only 1.99 knows about is fixed in code.
It is never allowed in `Cargo.toml`, because an unknown lint name is itself a warning on 1.97.

---

## 3. Dependencies

Exact versions are pinned in `Cargo.toml` and `Cargo.lock`.
This table records names and roles.

**Rust**

| Crate | Role | Note |
|---|---|---|
| `tokio` | runtime, `UnixListener`, `UnixStream::peer_cred()` | peer_cred gives UID/PID with no extra crate |
| `axum` 0.8 | HTTP router | serving is our own loop over `hyper` (D-11); axum only routes |
| `hyper`, `hyper-util`, `tower` | HTTP/1 server, per-request dispatch | |
| `serde`, `serde_json`, `toml` | config, wire JSON, audit JSON | |
| `clap` (derive) | CLI | |
| `aes-gcm` | AES-256-GCM | RustCrypto; `Aes256Gcm` with 96-bit nonces |
| `getrandom` | OS randomness for handles, DEKs, nonces, credential secrets | |
| `sha2`, `hex`, `base64`, `percent-encoding` | hashes, encodings | |
| `subtle` | constant-time credential comparison | |
| `zeroize` | wipe KEK/DEK buffers on drop | |
| `jiff` | RFC 3339 UTC timestamps | |
| `unicode-normalization` | NFC for export filenames (R-EXP-2) | |
| `thiserror`, `anyhow` | typed errors in modules; `anyhow` only in `main` and the CLI | |
| `tracing`, `tracing-subscriber` | daemon logging to stderr | never logs content, names, targets or roots: same rules as audit |
| `tempfile`, `http-body-util` (dev) | tests | |

Deliberately not used: a JCS crate (§6 explains why), `nix` (tokio covers peer_cred), any database (§4), any TLS.

**Python**

| Package | Role |
|---|---|
| `httpx` | HTTP over UDS: `httpx.HTTPTransport(uds=path)`; streaming request and response bodies |
| `mcp` (2.x) | official SDK; `MCPServer` (what 1.x called `FastMCP`). Optional extra `ovenmitt[mcp]` since 2026-10-16, because agent images pin their own MCP version and the client must install beside it |
| `pytest`, `pytest-asyncio` (dev) | |

The package is managed with `uv`.

---

## 4. On-disk layout (daemon container)

Paths are those of the shipped [`docker/example/ovenmitt.toml`](docker/example/ovenmitt.toml).

```
/var/lib/ovenmitt/
├── data/                       volume ovenmitt-data
│   ├── objects/<handle>/
│   │   ├── meta.json           cleartext: handle, vault, size, mime?, created, modified, expires_at, gen
│   │   └── gen-<N>/
│   │       ├── dek.wrap        12-byte nonce ‖ AES-GCM(KEK, DEK)
│   │       ├── meta.enc        AEAD(DEK): {name, labels, mime}
│   │       └── body.enc        chunked AEAD(DEK) (R-CRY-1)
│   ├── tmp/                    in-flight commits; swept at startup
│   └── credentials.toml        daemon-managed; the CLI writes tmp + rename
├── keys/<vault>.key            volume ovenmitt-keys; 32 raw bytes, mode 0600
├── audit/audit.jsonl           volume ovenmitt-audit
└── export/<root>/              volume ovenmitt-export; `fs` destination roots
/run/ovenmitt/ovenmitt.sock     volume ovenmitt-sock
/etc/ovenmitt/ovenmitt.toml     read-only bind mount
/etc/ovenmitt/review.toml       read-only bind mount, optional
```

If the config leaves `credentials` unset, the default is `/var/lib/ovenmitt/credentials.toml`, which is outside every volume.
The example config sets it inside the data volume so it survives a container rebuild.

**Why `mime` appears in both `meta.json` and `meta.enc`:** `list` needs it without decrypting, and it is agent-visible anyway.
`name` and `labels` are only in `meta.enc`.

**Commit protocol (R-OBJ-3, R-OBJ-4).**
A `put` writes `tmp/<handle>.<rand>/gen-1/…` while streaming, encrypting each chunk as it arrives (R-CRY-5).
It fsyncs the files and the directory, writes `meta.json`, and renames the directory to `objects/<handle>/`.
A `replace` writes `tmp/<handle>.<rand>/gen-<N+1>/…` and moves it into `objects/<handle>/`.
It then rewrites `meta.json` atomically (tmp + rename) with `gen = N+1` and shreds the old generation: overwrite `dek.wrap` with zeros, fsync, unlink the directory.
A crash before the `meta.json` rename leaves either the old generation intact or a `tmp/` directory that the startup sweep removes.
`delete` and `expire` apply the shred step to the current generation, then remove the object directory.

**Index.** Built at startup by reading every `meta.json` (10k objects take milliseconds).
Held in a `RwLock<HashMap<Handle, Meta>>` plus a per-handle `Mutex` for writers.
No SQLite in v1; add it if listing ever becomes slow.

**Credentials reload.** `credential.rs` stats the file on each `resolve` and re-parses it if the mtime changed.
That is how revoke takes effect without a restart (R-CRD-3), at the cost of one `stat` per resolve.

---

## 5. Daemon startup sequence

In order. Each step is fatal on failure, with a one-line reason on stderr.

1. Parse config and run every validation in R-DEP-6 (the same code as `ovenmitt config check`).
2. For each vault, open the key file. If the key is missing **and** `objects/` holds any object of that vault, refuse (R-VLT-2, SI-16). If the key is missing and there are no objects, generate it, write it with mode 0600, and fsync.
3. Sweep `data/tmp/`.
4. Build the index, and delete anything already expired (audited as `expire`).
5. Open the audit log and walk the chain (§6). A broken chain refuses startup (D-1).
6. Write the `start` entry (config SHA-256).
7. Bind the socket: unlink a stale socket file first, chmod per `socket_mode`, chgrp if `socket_group` is set.
8. Spawn the TTL sweep task and the audit writer task, then serve.

On `SIGTERM` the daemon stops accepting and lets in-flight requests finish, bounded at 30 s.
It writes no "stop" entry, because the log doesn't need one to verify.

---

## 6. Audit implementation

**Entry shape** is [PRD §6.1](PRD.md#61-record-format).
The Rust type is a struct with `Option` fields, and serialisation drops `None`.

**Canonical form.** RFC 8785 requires keys sorted by UTF-16 code unit and ES6 number formatting.
Every key we emit is ASCII, and every number we emit is an integer (`seq`, `size`, `uid`, `pid`).
So sorted-ASCII keys with `serde_json`'s compact output *are* JCS for our records.
`canon.rs` serialises into a `BTreeMap<&str, Value>` and asserts, in debug builds and in a unit test, that no `Value::Number` is a float.
Rule for the codebase: **no floats in audit entries, ever.**
That rule is what lets us skip a JCS dependency, and it is stated at the top of `canon.rs`.

**Writer.** One task owns the file handle and the chain state (last entry's hash, next `seq`).
Handlers send `(Entry, oneshot::Sender<()>)` over an mpsc channel.
The task fills `seq` and `prev`, appends the line, fsyncs, then acks.
The handler waits for the ack before returning its response (R-AUD-6).
Throughput doesn't matter at our volumes; correctness does.

**Startup walk.** Read the whole file, verify the chain, recover the head.
A broken chain refuses startup (D-1) instead of appending to a log that can no longer be trusted.
The message tells the operator to move the file aside; `verify` on the old file still works.

**Review.** `review.rs` loads the whole log and runs `verify` first.
It then runs each enabled rule over entries in the `--since` window, with the full history available for `first_destination`.
Findings sort by severity, then `seq`.
Output follows [PRD §6.3](PRD.md#63-review-rules-and-output).

---

## 7. API implementation notes

**One routing table** (`api/mod.rs`), in the PRD §4.2 order.
A fallback audits unknown routes as `request` / `refused` / `INVALID_REQUEST`.
Nothing else registers routes.

**Protocol header** is checked in a middleware before routing.
A failure is a refusal, so it is audited through `outcome.rs` like everything else.

**Outcome path.** Every handler returns `Result<Success, ApiError>` plus an `AuditContext { event, vault, handle, dest, target, cred, … }` that it fills in as it learns things.
`outcome.rs` is the only place that writes the audit entry and the only place that builds the HTTP response.
Refusal ordering (R-RES-2) is the order in which the handler performs its checks.
A handler fills `reason` from the first failing check and stops.
This makes SI-7 ("exactly one entry per refusal") hold by construction.

**Error hygiene (SI-6).** `ApiError` carries a code and, optionally, a destination name or handle, and nothing else.
Messages are fixed strings per code in `error.rs`.
There is no `ApiError::Other(String)`.

**Put/replace stream.** `Body` → `DataStream` → chunker (1 MiB) → `crypto::Writer` (encrypt, hash, count size) → temp file.
The size limit is checked per chunk.
Exceeding it aborts with `TOO_LARGE` before the next chunk is read.
A client disconnect surfaces as a stream error, which becomes `aborted`, and the temp dir is removed.

**Resolve stream.** All R-RES-2 checks run in order before the body is opened.
Then `crypto::Reader` yields decrypted chunks into `Body::from_stream`.
If the file lacks a final-chunk marker, the reader errors; that is the truncation detection in R-CRY-1.
`Content-Length` comes from `meta.json`.

**Peer credentials.** `api/peer.rs` implements axum's `Connected` for the Unix stream and puts `peer_cred()` into a `PeerInfo { uid, pid }` extension.
It is informational only (F-6); nothing branches on it.

**Chunked AEAD detail.**
Nonce = 8 random bytes (per object generation) ‖ 4-byte big-endian chunk index.
AAD = `handle` bytes ‖ index ‖ `0x01` if final, else `0x00`.
The final chunk may be zero-length, when the body is an exact multiple of 1 MiB or empty.
File = `[8-byte nonce prefix][chunk…]`, and each chunk = `[u32 ciphertext length][ciphertext ‖ tag]`.
The reader rejects a missing final marker, an index gap, or trailing bytes after the final chunk.

---

## 8. Python package notes

- `VaultClient` is thin: one method per endpoint, with the [PRD §10.2](PRD.md#102-library-contract-ovenmitt-python-package-protocol-1) signatures. `put` accepts `bytes`, a file object or an iterator, and hands httpx a generator so nothing is buffered. `resolve` returns a `Resolved` whose `.stream` iterates httpx response chunks. The response closes when the iterator is exhausted or the context manager exits.
- `resolve_path` resolves into a `memfd` and yields a one-shot symlink to `/proc/<pid>/fd/<n>`. Linux only.
- `errors.py`: `OvenmittError(code, message, status)`, raised from any non-2xx response. The code is the wire code, unchanged.
- `mcp.py`: `MCPServer("ovenmitt")` with exactly the eight tools in R-FAC-2. Tool descriptions are what the LLM sees. They say what each tool returns (metadata) and never mention reading. `vault_put` opens the path, calls the client, and unlinks the source only on success when `remove_source` is set.
- `python/tests/test_mcp.py` asserts the tool list equals the fixed set (SI-13), and that `mcp.py` never contains the word `resolve`.

---

## 9. Containers and compose

**Daemon image.** Stage 1 builds `--release` on `rust:1.97-bookworm`.
Stage 2, `debian:bookworm-slim`, copies the binary, creates user `ovenmitt`, declares the data, keys, audit and socket volumes, and sets `ENTRYPOINT ["/usr/local/bin/ovenmitt"]`, `CMD ["daemon"]`.
It adds no shell tools beyond what slim ships.
The operator path is `docker exec <id> ovenmitt audit review`.
The image is built for the container's own architecture: arm64 on Apple silicon, amd64 in CI.

**Agent image.** `python:3.12-slim` with `pip install '.[mcp]'`.
Its command is `ovenmitt mcp --socket /run/ovenmitt/ovenmitt.sock` for the reference `agent` service.
The `test-agent` service overrides the command to `sleep infinity`, and tests `exec` into it.

**Reference compose** mounts only `ovenmitt-sock` into `agent` (R-DEP-4).
The test overlay, `docker-compose.test.yml`, is applied on top of the reference file.
It adds `test-agent` and swaps in a generated config whose export roots and send patterns carry sentinel markers.
The export roots are mounted into the daemon *and nowhere else*, so AT-8 and AT-13 can assert the sentinels never reach the agent container.

---

## 10. Test layers, and which AT each one owns

| Layer | Runs with | Owns |
|---|---|---|
| Rust unit (`#[cfg(test)]`) | `cargo test` | grammars (names, filenames, durations, sizes), pattern matcher (AT-26), handle format, chunked AEAD round-trip + truncation/reorder rejection, canonical JSON + no-floats, chain verify + tamper matrix (AT-12), review rules at/under threshold (AT-24), credential token format |
| Rust integration (`tests/`) | `cargo test`; daemon in-process on a temp socket; raw `hyper` client | every route and error code (AT-1, 5, 6, 7, 16, 25, 27), export confinement (AT-9, 10), TTL (AT-15), aborted streams (AT-14), at-rest sentinel scans (AT-21), refusal durability (AT-23), credential lifecycle (AT-17), `expose_names` (AT-22), config validation and key refusal (AT-18, 19), denylist (AT-28) |
| Python (`python/tests`) | `pytest` against a local `ovenmitt daemon`; on macOS, `docker/Dockerfile.pytest` runs the same suite on Linux | client parity with the wire, MCP tool list (SI-13 / AT-2), `vault_put` unlink-after-201, `list_vaults` on MCP (AT-29), `resolve_path` (Linux only: `memfd_create`), client import without `mcp` |
| Plugin (`tests-plugin`) | `pytest`; `run-in-agent-image.sh` inside a Hermes image | bridge tools, send target rule, put refusals, contract test against a real platform adapter |
| End-to-end (`tests-e2e/`) | `pytest` driving `docker compose` with the test overlay | store absent from agent container (AT-8), no TCP listener (AT-20), `verify`/`review` via `docker exec` (AT-11), full sentinel sweep across containers (AT-13) |

CI runs on every push to `tumu` and on every pull request.
There are three test workflows (`rust`, `python`, `e2e`) so each gets a README badge.
`python` also runs the plugin tests.
e2e takes a few minutes because it builds both images.
A fourth workflow, `sanitization`, gates docs and shipped agent files for secrets and use-case particulars.
Run every layer locally before tagging.

**Sentinel discipline.** Every test that asserts "X never appears" uses a fresh 64-byte random string generated per test.
A fixed constant could let a stale fixture pass a leak test.

---

## 11. Decisions made here, not in the PRD

| # | Decision | Why |
|---|---|---|
| D-1 | A broken audit chain at startup refuses startup. | Appending to an untrusted chain hides the break. The operator moves the file aside and keeps the old one for `verify`. Same "loud, not half-working" posture as F-28. |
| D-2 | One Rust binary with a `daemon` subcommand; `ovenmittd` is a symlink in the image. | CLI and daemon share config, keys, audit and credentials code; two binaries would drift. |
| D-3 | On-disk layout is directories and files, no database; the index is rebuilt at startup. | 10k objects read in milliseconds. A database is a second thing to get wrong and back up. |
| D-4 | Audit entries contain no floats; canonical JSON is sorted-key compact `serde_json`. | Makes RFC 8785 trivial without a dependency. Enforced by test. |
| D-5 | The credentials file is re-read on mtime change, not on a signal. | Revoke without restart, with one `stat` per resolve and no signal handling. |
| D-6 | `mime` is duplicated in cleartext `meta.json`. | `list` must not decrypt, and `mime` is agent-visible anyway. |
| D-7 | Python ≥ 3.11. | `tomllib` and modern typing. Nothing older is worth supporting for a new package. |
| D-8 | The daemon image is built per architecture inside Docker, never cross-compiled from the host. | The binary that runs in the container is built for the container. |
| D-9 | Work lands on the default branch in small commits; a feature branch and PR only when a milestone touches more than one layer at once. | Written for a solo project, where PR ceremony on every commit slows work without catching anything a test run doesn't. Revisit when a second contributor appears. |
| D-10 | An unreadable or corrupt object record, or an object whose vault is no longer in the config, refuses startup. | Same posture as a missing key. A daemon that silently skips an object it can't account for has a `list` that lies. The message names the directory so the operator can move it aside. |
| D-11 | The daemon runs its own accept loop over hyper's HTTP/1 server instead of `axum::serve`. | hyper drops a request whose client half-closed before the response unless `half_close(true)` is set, and `axum::serve` can't set it. Without it, a client could send a refused request, close, and leave no audit entry, which R-AUD-6 forbids. Found by AT-23. |
| D-12 | Each handler runs on its own Tokio task, spawned by the guard middleware. | hyper cancels the in-flight service future when the connection dies. Spawning makes the handler and its audit write run to completion regardless. |
| D-13 | A refused read (`stat`/`list` of something that isn't there) is audited as a refused `request`; successful reads are not logged. | Keeps SI-7 literally true ("every refused request yields exactly one entry") without logging every successful stat. An agent probing handles is worth seeing in `review`. |

---

## 12. Milestones

All milestones are complete, and v0.1.0 was tagged at M9.
Later changes are in [CHANGELOG.md](CHANGELOG.md).

Each milestone was done when its listed tests passed locally.
The order is dependency order; nothing ran in parallel.

| M | Deliverable | Done when |
|---|---|---|
| **M0** | Scaffold: `Cargo.toml`, `main.rs` with clap skeleton, `config.rs` + `config check`, CI workflow (fmt, clippy `-D warnings`, test), `python/pyproject.toml` stub, `docker/Dockerfile` that builds. | `cargo clippy` clean; `ovenmitt config check docker/example/ovenmitt.toml` passes and every R-DEP-6 negative case fails with a line number (AT-18); `docker build` succeeds. |
| **M1** | Primitives: `handle.rs`, `pattern.rs`, `crypto.rs`, `keys.rs`, `audit/canon.rs`. | Unit tests: AT-26; AEAD round-trip, truncation, reorder, zero-length final; no-floats assertion; key create / refuse-if-missing (AT-19 at unit level). |
| **M2** | Store: put, replace, stat, list, label, delete, TTL sweep, temp sweep; `export.rs` grammar + confinement. | Unit + in-process tests for commit atomicity, replace shred, expiry (AT-3, 14, 15 logic), filename matrix (AT-9 logic), sentinel scan of `data_dir` (AT-21). |
| **M3** | Audit writer, verify, head; `ovenmitt audit verify` and `head`. | Tamper matrix (AT-12); fsync-before-ack test (AT-23 logic); startup refuses on broken chain (D-1). |
| **M4** | HTTP API over UDS: all routes except `resolve`; error model; protocol header; peer info; outcome path. | Rust integration: AT-1, 5 (except credential cells), 6, 7, 14, 15, 16, 22, 25, 27; SI-6 sentinel sweep over every route. |
| **M5** | Credentials + `resolve` + `export` end to end; `ovenmitt credential …`. | AT-4, AT-5 full truth table, AT-9, AT-10, AT-17; `target` present in audit entries. |
| **M6** | Review: rules, output, exit codes; `ovenmitt audit review`; `vault list`, `object stat`. | AT-11 (in-process), AT-24. |
| **M7** | Python client + MCP server + `ovenmitt mcp`. | Python tests: AT-2, AT-29, SI-13 tool-list test, parity test for every endpoint. |
| **M8** | Compose (reference + test), agent image, e2e suite. | AT-8, 11 (via `docker exec`), 13, 20, 28 locally. **This was the v1 acceptance gate.** Brief §9 maps to AT-1/2, 4, 5–9, 11. |
| **M9** | Docs: README with the PRD §11 limitations, operator checklist, tool-author guide, threat model in the "hard, not impossible" framing; `CHANGELOG`; tag `v0.1.0`. | A reviewer can deploy from the README alone; every R-DOC item has a section. Tagged only after the M8 gate passed locally. |

M0 to M3 were where Rust was learned, and were the slow part.
M4 was the largest single milestone.
M8 held the surprises: socket permissions across containers, and arm64 versus amd64.

---

## 13. Conventions

- `#![forbid(unsafe_code)]` at the crate root, also set in `Cargo.toml` lints. No exceptions; nothing here needs it.
- `cargo fmt` default. `cargo clippy --all-targets -- -D warnings` clean before every commit.
- No `unwrap()` or `expect()` outside tests and `main.rs` startup. Errors are `thiserror` enums per module; `anyhow` only at the CLI edge.
- Logging goes through `tracing` to stderr, at `info` by default (`OVENMITT_LOG` overrides). `debug` never includes names, labels, targets, roots or content. Those are the audit log's rules too, because a log line is also a leak path.
- Secrets (KEK, DEK, credential secrets) live in `Zeroizing<[u8; 32]>` and are never `Debug`-printed. Their types implement a `Debug` that prints `[redacted]`.
- Tests that assert absence use per-test random sentinels (§10).
- Commit messages: imperative subject, body says why. Reference `R-`/`SI-`/`AT-` IDs when a commit makes one pass.
- `CHANGELOG.md` uses keep-a-changelog style with an "Unreleased" section.
- **GitHub org: `cyborg-garden`.** The repo lives at `cyborg-garden/oven-mitt`. Use that path for repo URLs, `git:` pins, badges and a package's `repository` field. Producers live in their own repos under the same org.

---

## 14. Prerequisites

Rust 1.97 or later (CI uses 1.99.0), `uv`, and Docker with `docker compose`.
Run `cargo test` as you go.
Run the full suite and the e2e suite before tagging.
