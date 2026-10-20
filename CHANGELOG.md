# Changelog

All notable changes to ovenmitt. Format follows keep-a-changelog; versions follow semver.

## [Unreleased]

### Added
- `VaultClient.resolve_path(handle, destination, target, credential, filename)`: resolves into a `memfd` and yields a one-shot path (a symlink named `filename` in a private temp dir) for senders that only take a filename. Closed and removed when the `with` block ends. Linux only; `docker/Dockerfile.pytest` runs the Python tests on Linux from a Mac.

- `hermes-plugin/`: a Hermes plugin (`ovenmitt_bridge`) with seven native `ovenmitt_vault_*` tools and a generic `ovenmitt` skill. `ovenmitt_vault_send` delivers to the current chat only, through the platform adapter's own `send_document` and `resolve_path`; the target is read off the sender, never taken from the model. The consumer credential is popped from the environment at load. Tests include a contract test against a real platform adapter inside the agent image (`tests-plugin/run-in-agent-image.sh`), and the denylist test now scans the bridge for any name but its harness's.

### Changed
- `scripts/check_sanitization.py` and `.github/workflows/sanitization.yml`, ported from swarm-map: a deterministic secrets/PII layer plus an LLM particulars layer over `hermes-plugin/`, `hermes-skill/`, `docker/example/` and top-level docs. The particulars layer needs an `OPENROUTER_API_KEY` repo secret and fails closed without it.
- Layout matches the other published artefacts: the plugin is now at `hermes-plugin/` (was `hermes-plugin/plugin/`), the skill at `hermes-skill/` (was `hermes-plugin/skill/`), and the plugin's tests at `tests-plugin/` (was `hermes-plugin/tests/`), so tests are no longer installed with the plugin. Pins become `git:<org>/oven-mitt#<tag>:hermes-plugin` and `:hermes-skill`.
- The Python package's `mcp` dependency is now the optional extra `ovenmitt[mcp]`; the base package (the client) depends on `httpx` only, so it installs beside an agent image's own MCP pin. Without the extra, `ovenmitt mcp` exits with an install hint. The agent image installs the extra.
- BRIEF: `resolve_path` promoted to v1; Part B amended (the integration lives in three homes, and sends go through the platform adapter's own send interface).

### Fixed
- `resolve_path` links to `/proc/<pid>/fd/<n>` instead of `/proc/self/fd/<n>`. A sender that hands the path to a helper process used to make the helper open *its own* fd n, which could be a different file; now it opens this memfd, or fails.
- `ovenmitt_vault_send` refuses adapters with no `send_document` of their own (`UNSUPPORTED`): the harness's base fallback posts a "couldn't deliver" notice and reports success, so every send looked delivered. A send that outlasts its timeout is cancelled and reported as `SEND_TIMEOUT` (it was reported as "daemon not reachable" and kept running), and any other sender error becomes `SEND_FAILED` instead of a raw harness error.

### Added
- `ovenmitt_bridge.send_readiness()`: why a send would be refused in the current turn, or None. For producers in the same gateway, to check before spending on output they couldn't deliver.

### Security
- `ovenmitt_bridge` pops `OVENMITT_CONSUMER_CREDENTIAL` as its module's first statement, before any import that could fail, so a plugin that never loads (or isn't enabled) no longer leaves the credential for terminal children to inherit. `register()` still accepts it from the environment.
- `ovenmitt_vault_put` refuses `/proc`, `/sys`, `/dev`, `/run`, `/var/run`, `/etc`, credential directories (`.ssh`, `.aws`, …) and credential files by name (`.env`, `auth.json`, `*.pem`, …), on both the given and the resolved path, with `PATH_REFUSED`. Before, "put `/proc/self/environ` and send it to me" would have delivered the gateway's initial environment.

### Fixed
- Python test fixture put the daemon socket under pytest's `tmp_path`, which on macOS exceeds the 104-byte Unix socket path limit; the socket now lives in a short `/tmp` dir and the fixture reports the daemon's stderr if it dies. The daemon itself now names the platform limit instead of surfacing a bare ENAMETOOLONG.

### Added
- M9: README (what it is, how it works, quick start, operator guide and checklist, tool-author guide, the PRD §11 limitations verbatim), Python README.
- M8: reference `docker-compose.yml` (daemon + agent; the agent mounts only the socket volume), test overlay with a sleeping `test-agent`, agent image, end-to-end suite driving compose from the host (AT-8, AT-11 via `docker exec`, AT-13 across containers, AT-20, brief §9 end to end), repo-wide domain-name denylist test (AT-28).
- M7: Python package `ovenmitt` — `VaultClient` (every endpoint, streaming put from bytes/file/iterator, `put_path` with client-side hash and unlink-after-2xx, `resolve` returning a stream), `ovenmitt mcp` serving the closed eight-tool set over stdio, tests against the real daemon (AT-2, AT-29, SI-13, parity).
- M6: `ovenmitt audit review` — rules file with defaults (refusal, first_destination, burst, churn, chain), `--since`, `--threshold`, `--json`, findings on stderr ranked by severity, exit 0/1/2; `ovenmitt vault list`; `ovenmitt object stat` reading one object straight from disk beside a live daemon (R-REV-1..4, R-VLT-4, R-OBJ-11; AT-11, AT-24, AT-29).
- M5: consumer credentials (`ovm_<id>_<secret>`, hashed on disk, vault-scoped, re-read on change so revoke needs no restart) and `POST /v1/objects/{handle}/resolve` — the one route that returns bytes — with the R-RES-2 check order; `ovenmitt credential issue|list|revoke` (R-CRD-1..4, R-RES-1..5; AT-4, AT-5 full table, AT-17; SI-1, SI-5, SI-14).
- M4: HTTP/1.1 API over the Unix socket — every route except `resolve`, the closed error-code set with fixed messages, protocol header guard, bodiless-route guard, one outcome path that writes the audit entry before the response, streaming put/replace, TTL sweep task, graceful shutdown, `ovenmitt daemon` (PRD §4, §7; AT-1, 5, 6, 7, 14, 15, 16, 22, 23, 25, 27; SI-6/8/15 sweeps).
- M3: audit writer (single thread, fsync-before-ack, canonical lines, clamped clock), chain verify with a named first break, `ovenmitt audit verify|head`, broken chain refuses startup (R-AUD-1..7, AT-12, AT-23 logic, D-1).
- M2: object store — streaming put/replace with atomic commit, generation-based replace that shreds the old key, delete, TTL on access and by sweep, index rebuild, startup refusals for missing keys / unconfigured vaults / corrupt records (R-OBJ-3..10, R-VLT-2); export with filename grammar, NFC, realpath confinement and no-clobber linking (R-EXP-1..4).
- M1: handles (R-OBJ-1), per-vault KEK / per-object DEK with chunked AES-256-GCM bodies and crypto-shred-ready wrapping (R-CRY-1..3), key store with refuse-if-missing (R-VLT-2, SI-16), canonical JSON for audit entries with the no-floats rule (D-4).
- M0: crate scaffold, `ovenmitt config check` with fail-closed validation and line-numbered errors (R-DEP-6, AT-18), send-pattern grammar (R-DST-6, AT-26), daemon Dockerfile, CI, Python package stub.
