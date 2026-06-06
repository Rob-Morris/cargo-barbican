# Contributor Specification

Contributor-facing specification for cargo-barbican. This document captures the
current contributor constraints, dependency discipline, and shipped-template
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
before it is added to `Cargo.toml`. Most listed crates inherit from
Undertask's reviewed set. Crates that do not inherit from Undertask are
reviewed first-principles in cargo-barbican itself before they define or
support a local boundary such as HTTP, time parsing, archive inspection, or
diff rendering.

| Crate | Version | Source | Notes |
|---|---|---|---|
| `serde` | 1 (derive) | crates.io | Inherited from undertask |
| `serde_json` | 1 | crates.io | Inherited from undertask; used for crates.io API and `cargo metadata` |
| `toml` | 1.1 | crates.io | Inherited from undertask; used for lockfile parsing if hand-rolled |
| `clap` | 4 (derive) | crates.io | Inherited from undertask; subcommand parsing |
| `similar` | =3.1.1 (`default-features = false`, `features = [\"text\"]`) | crates.io | First-principles review for the explicit non-git review renderer experiment |
| `thiserror` | 2 | crates.io | Inherited from undertask; error enums |
| `time` | 0.3 (`std`, `parsing`) | crates.io | First-principles review; RFC 3339 parsing and UTC comparisons with smaller target surface than `chrono` |
| `ureq` | 3.3 (`default-features = false`, `features = ["rustls"]`) | crates.io | First-principles review; pure-Rust blocking HTTP boundary |
| `miniz_oxide` | =0.9.1 (`default-features = false`, `features = [\"with-alloc\"]`) | crates.io | Direct dependency for `.crate` gzip handling in the library and test support in the binary |
| `sha2` | =0.10.9 (`default-features = false`, `features = [\"force-soft\"]`) | crates.io | Direct dependency for reviewed artefact SHA-256 verification and test support |
| `tar` | =0.4.46 (`default-features = false`) | crates.io | Direct dependency for `.crate` tarball inspection and test support |

`ureq` is preferred over a heavier HTTP stack because the surface is small and
blocking I/O is acceptable at the CLI boundary.

## Constraints

- No new dependencies without a review record.
- No second HTTP client. Replace `ureq` if necessary; do not add a peer.
- The library must remain testable without network access.
- The binary is the subprocess boundary for `git` and `cargo`.
- Templates are shipped content for consumer repos, not repo-facing documentation.
- Future planning, slice sequencing, and deferred design work live in Brain,
  not in the canonical repo docs.

## Current implemented policy surface

The checked-in root `barbican.toml` carries these sections:

- `[release_age]`
- `[high_scrutiny]`
- `[delegates]`

`[release_age].minimum_days` is active for `age`, `age-lock`, `resolve`,
`assess`, and `inspect`.

The current baseline rules for comparative commands are:

- `age-lock` defaults to `--base-ref HEAD` and also accepts
  `--base-lockfile <path>` as an explicit non-git baseline
- `assess` defaults to `--base-ref HEAD` and also accepts
  `--base-dir <path>` as an explicit non-git dependency-state baseline
- `review` keeps the existing git-backed default path and also accepts
  `--base-dir <path>` as an explicit non-git review baseline
- `resolve` no longer depends on `HEAD`; it rechecks against an internal
  pre-update `Cargo.lock` snapshot
- `resolve` also supports `--dry-run`, which executes the targeted update in an
  internal temp workspace and prints a summary/diff preview of the would-be
  `Cargo.lock` change instead of mutating the repo

The first active `high_scrutiny` keys are:

- `new_direct_dependencies`
- `non_crates_io_direct_dependencies`
- `non_crates_io_source_changes`
- `build_rs_changes`
- `proc_macro_changes`
- `native_sys_crates`

`cargo barbican assess` is fail-closed. If the tool cannot complete a required
dependency-surface inspection for the current implemented surface, it reports a
blocking finding rather than silently treating the package as safe.

`cargo barbican inspect` is currently:

- Rust-only and crates.io-only
- exact `crate@version` input only
- release-age aware, using the same default and override rules as `age`
- checksum-oriented: local tarball SHA-256 must match the published crates.io
  checksum
- provenance-aware: inspect `.cargo_vcs_info.json` when present
- high-scrutiny oriented: enumerate `build.rs`, `proc-macro`, and native
  `-sys` / FFI surfaces, then run a fixed IOC scan over build-time and
  proc-macro-relevant sources
- fail-closed for routine intake: checksum mismatches, IOC hits, and required
  inspection failures are blocking; surfaced high-scrutiny execution surfaces
  are elevated-risk

The reviewed-target enforcement baseline is:

- repo-root `reviewed-targets.toml` is the machine-enforced source of truth
- checked-in Markdown review records remain the human explanation and evidence
  surface
- each active `[[rust.families]]` entry carries:
  - `name`
  - `review_record`
  - optional `direct` exact manifest requirements, including the leading `=`
  - `resolved` exact `Cargo.lock` versions
- `pin-check` validates that every active `review_record` path actually exists
  before the family declaration is trusted
- `pin-check` checks exact resolved `Cargo.lock` parity plus any configured
  exact direct manifest requirements
- `verify` reuses that same default reviewed-target gate before executing
  `cargo build --locked` and `cargo test --locked`

For crates.io reviewed families, `resolved` can use a structured artefact form:

```toml
[rust.families.resolved]
serde = { version = "1.0.228", checksum_sha256 = "..." }
serde_derive = { version = "1.0.228", checksum_sha256 = "..." }
```

Contract notes:

- the existing exact-string form remains acceptable for compatibility
- the structured form is the intended path for crates.io reviewed families
- `checksum_sha256` is the reviewed `.crate` tarball digest, expected to match
  both crates.io metadata and the resolved `Cargo.lock` checksum chain
- `pin-check` remains read-only and local-only; it does not fetch from the
  network during enforcement
- when a structured `checksum_sha256` is present, `pin-check` fails closed on
  checksum drift even if the resolved version still matches
- the current implementation does not claim stronger installed-tree or broader
  non-crates.io artefact parity beyond this gate
