# Contributor Specification

Contributor-facing specification for implementing cargo-barbican. This document
captures the current build plan, dependency discipline, and shipped-template
boundary.

## Scope

cargo-barbican is a Cargo subcommand for Rust supply-chain hardening. The v0.1
goal is a local-install-first tool that replaces the equivalent Rust workflow
currently implemented in undertask's Python and shell scripts.

## Source material

Read the matching undertask sources before redesigning behaviour:

- `scripts/check-crate-release-age.py`
- `scripts/check-cargo-lock-release-age.py`
- `scripts/select-cargo-package-id.py`
- `scripts/deps-rust-routine-update.sh`
- `docs/dependency-management.md`
- `deny.toml`
- `docs/dependency-reviews/`

The reference repo is
[undertask](https://github.com/rob-morris/undertask). Re-implement faithfully;
deviations should be documented explicitly.

## Dependency discipline

Every entry must have a corresponding record in `docs/dependency-reviews/`
before it is added to `Cargo.toml`. All planned crates except `ureq` are
expected to inherit from undertask.

| Crate | Version | Source | Notes |
|---|---|---|---|
| `serde` | 1 (derive) | crates.io | Inherited from undertask |
| `serde_json` | 1 | crates.io | Inherited from undertask; used for crates.io API and `cargo metadata` |
| `toml` | 1.1 | crates.io | Inherited from undertask; used for lockfile parsing if hand-rolled |
| `clap` | 4 (derive) | crates.io | Inherited from undertask; subcommand parsing |
| `chrono` | 0.4 (serde) | crates.io | Inherited from undertask; ISO 8601 parsing |
| `thiserror` | 2 | crates.io | Inherited from undertask; error enums |
| `ureq` | TBD | crates.io | First-principles review required; pure-Rust blocking HTTP boundary |

`ureq` is preferred over a heavier HTTP stack because the surface is small and
blocking I/O is acceptable at the CLI boundary.

## Implementation bootstrap sequence

1. Layer 0 scaffolding already exists. Do not recreate the workspace.
2. Establish self-policy first:
   - copy undertask's `deny.toml` into this repo root
   - install `cargo-audit` and `cargo-deny`
   - write the tool-install review records under `docs/dependency-reviews/`
   - run `cargo audit` and `cargo deny check` against the empty workspace as a smoke test
3. Write inherited review records for the planned crates that already exist in undertask's trust set.
4. Choose and review a `ureq` version that satisfies the minimum release-age policy.
5. Add reviewed dependencies to `crates/barbican/Cargo.toml`, then run `cargo audit` and `cargo deny check`.
6. Implement the library crate in dependency order:
   - lockfile parsing
   - `cargo metadata` parsing
   - crates.io API client behind a trait
   - release-age computation
   - lockfile-diff support
7. Implement the binary crate as a thin CLI shim over the library.
8. Self-host with `cargo barbican audit` and `cargo barbican verify`.
9. Populate `templates/` with the consumer-facing policy files and templates.
10. Keep the user adoption guide in `docs/user/integration.md` in step with the shipped consumer flow.

## Constraints

- No new dependencies without a review record.
- No second HTTP client. Replace `ureq` if necessary; do not add a peer.
- The library must remain testable without network access.
- The binary is the subprocess boundary for `git` and `cargo`.
- Templates are shipped content for consumer repos, not repo-facing documentation.

## Open questions

- Whether `cargo_lock` is acceptable instead of hand-rolling over `toml`.
- Whether `chrono` remains the right time crate once implementation begins.
- Whether v0.1 should ship the templates immediately or defer them to the first post-tool release.
