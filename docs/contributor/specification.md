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
before it is added to `Cargo.toml`. Most planned crates inherit from
Undertask. `ureq` and `time` are first-principles reviews in cargo-barbican
itself because they define the HTTP and time/parsing boundaries directly.

| Crate | Version | Source | Notes |
|---|---|---|---|
| `serde` | 1 (derive) | crates.io | Inherited from undertask |
| `serde_json` | 1 | crates.io | Inherited from undertask; used for crates.io API and `cargo metadata` |
| `toml` | 1.1 | crates.io | Inherited from undertask; used for lockfile parsing if hand-rolled |
| `clap` | 4 (derive) | crates.io | Inherited from undertask; subcommand parsing |
| `thiserror` | 2 | crates.io | Inherited from undertask; error enums |
| `time` | 0.3 (`std`, `parsing`) | crates.io | First-principles review; RFC 3339 parsing and UTC comparisons with smaller target surface than `chrono` |
| `ureq` | TBD | crates.io | First-principles review required; pure-Rust blocking HTTP boundary |

`ureq` is preferred over a heavier HTTP stack because the surface is small and
blocking I/O is acceptable at the CLI boundary.

## Implementation bootstrap sequence

1. Layer 0 scaffolding already exists. Do not recreate the workspace.
2. Establish self-policy first:
   - copy undertask's `deny.toml` into this repo root
   - install `cargo-audit` and `cargo-deny`
   - write the tool-install review records under `docs/dependency-reviews/`
   - run `cargo audit` and `cargo deny check advisories bans sources` against the empty workspace as a smoke test
3. Write inherited review records for the planned crates that already exist in undertask's trust set.
4. Choose and review a `ureq` version that satisfies the minimum release-age policy.
5. Add reviewed dependencies to `crates/barbican/Cargo.toml`, then run `cargo audit` and `cargo deny check advisories bans sources`.
6. Implement the library crate in dependency order:
   - lockfile parsing
   - `cargo metadata` parsing
   - crates.io API client behind a trait
   - RFC 3339 publish-time parsing and release-age computation
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

## Current slice note

Slice 2 wires the first minimal `barbican.toml` shape into the repo. The
checked-in root file carries the phase-1 sections:

- `[release_age]`
- `[high_scrutiny]`
- `[delegates]`

`[release_age].minimum_days` is active for `age`, `age-lock`, `resolve`, and
the first `assess` slice.

The first active `high_scrutiny` keys are:

- `new_direct_dependencies`
- `non_crates_io_direct_dependencies`
- `non_crates_io_source_changes`
- `build_rs_changes`
- `proc_macro_changes`
- `native_sys_crates`

Those keys drive the first post-add Rust-only `cargo barbican assess`
implementation. Do not add broader `high_scrutiny` keys until a later slice
proves a concrete need.

The first `assess` slice is fail-closed. If the tool cannot complete a
required dependency-surface inspection for that slice, it reports a blocking
finding rather than silently treating the package as safe.

## Slice 3 implemented baseline

The next shaped intake surface was `cargo barbican inspect`, not a broader
second expansion of `assess`. That first `inspect` slice is now implemented
with this contract:

- Rust-only and crates.io-only
- exact `crate@version` input only
- release-age aware, using the same default and override rules as `age`
- checksum-oriented: local tarball SHA-256 must match the published crates.io checksum
- provenance-aware: inspect `.cargo_vcs_info.json` when present
- high-scrutiny oriented: enumerate `build.rs`, `proc-macro`, and native
  `-sys` / FFI surfaces, then run a fixed IOC scan over build-time and
  proc-macro-relevant sources
- fail-closed for routine intake: checksum mismatches, IOC hits, and required
  inspection failures are blocking; surfaced high-scrutiny execution surfaces
  are elevated-risk

What is still explicitly deferred at this stage:

- review-record existence enforcement
- lockfile-vs-review pin reconciliation
- any `pin-check` command surface

Do not add broader `high_scrutiny` keys or a `pin-check` CLI surface until the
review-record and checked-pin contract is shaped explicitly.

## Open questions

- Whether `cargo_lock` is acceptable instead of hand-rolling over `toml`.
- Whether the current `time` feature set should stay at `std` + `parsing`, or grow only if implementation proves it necessary.
- Whether v0.1 should ship the templates immediately or defer them to the first post-tool release.
- What the machine-readable review-record contract must be before `pin-check` can become a real command rather than a design placeholder.
