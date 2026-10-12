# Changelog

All notable changes to ovenmitt. Format follows keep-a-changelog; versions follow semver.

## [Unreleased]

### Added
- M4: HTTP/1.1 API over the Unix socket — every route except `resolve`, the closed error-code set with fixed messages, protocol header guard, bodiless-route guard, one outcome path that writes the audit entry before the response, streaming put/replace, TTL sweep task, graceful shutdown, `ovenmitt daemon` (PRD §4, §7; AT-1, 5, 6, 7, 14, 15, 16, 22, 23, 25, 27; SI-6/8/15 sweeps).
- M3: audit writer (single thread, fsync-before-ack, canonical lines, clamped clock), chain verify with a named first break, `ovenmitt audit verify|head`, broken chain refuses startup (R-AUD-1..7, AT-12, AT-23 logic, D-1).
- M2: object store — streaming put/replace with atomic commit, generation-based replace that shreds the old key, delete, TTL on access and by sweep, index rebuild, startup refusals for missing keys / unconfigured vaults / corrupt records (R-OBJ-3..10, R-VLT-2); export with filename grammar, NFC, realpath confinement and no-clobber linking (R-EXP-1..4).
- M1: handles (R-OBJ-1), per-vault KEK / per-object DEK with chunked AES-256-GCM bodies and crypto-shred-ready wrapping (R-CRY-1..3), key store with refuse-if-missing (R-VLT-2, SI-16), canonical JSON for audit entries with the no-floats rule (D-4).
- M0: crate scaffold, `ovenmitt config check` with fail-closed validation and line-numbered errors (R-DEP-6, AT-18), send-pattern grammar (R-DST-6, AT-26), daemon Dockerfile, CI, Python package stub.
