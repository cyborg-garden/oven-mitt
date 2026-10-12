# Changelog

All notable changes to ovenmitt. Format follows keep-a-changelog; versions follow semver.

## [Unreleased]

### Added
- M1: handles (R-OBJ-1), per-vault KEK / per-object DEK with chunked AES-256-GCM bodies and crypto-shred-ready wrapping (R-CRY-1..3), key store with refuse-if-missing (R-VLT-2, SI-16), canonical JSON for audit entries with the no-floats rule (D-4).
- M0: crate scaffold, `ovenmitt config check` with fail-closed validation and line-numbered errors (R-DEP-6, AT-18), send-pattern grammar (R-DST-6, AT-26), daemon Dockerfile, CI, Python package stub.
