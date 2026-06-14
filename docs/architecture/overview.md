# Architecture Overview

A portable, policy-first Rust supply-chain hardening tool: it gives a Rust repo
one gate for what enters its dependency graph. Pure Rust, a single versioned
implementation that every Rust repo can install and pin. Distributed today by
local/git install-and-pin; crates.io publication is a deferred decision, not
foreclosed.

## Why this exists

[undertask](https://github.com/rob-morris/undertask) implements supply-chain
hardening as Python scripts plus a shell wrapper. The hardening model is sound:
release-age gating, `--locked` verification, targeted updates, advisory checks,
and checked-in review records for dependency changes.

The problem is duplication. As soon as multiple Rust repos need the same
hardening, copy-pasted scripts drift. cargo-barbican exists to replace that
duplication with one versioned Rust policy tool that consumer repos pin and
re-sync deliberately — a portable policy gate in its own right, not only a
deduplication of undertask's scripts.

## Platform Support

cargo-barbican is developed and tested on Unix-like systems: macOS and Linux.
It may work on Windows, but Windows is not currently a supported or tested
platform. In particular, fail-closed path-containment guarantees for static
repo state around symlinks, directory junctions, and reparse points are
unverified on Windows.

Treat Windows use as experimental and use-at-your-own-risk until full Windows
support is explicitly delivered.

## Goals

1. Be the single, portable source of truth for Rust supply-chain policy — one dependency-intake gate that many repos install, pin, and enforce consistently.
2. Pure Rust installation and execution, with no Python prerequisite.
3. Inherit existing trust decisions from undertask where possible instead of re-reviewing by default.
4. Match undertask's surface closely enough that existing muscle memory transfers.
5. Apply the same supply-chain discipline to cargo-barbican itself that it will enforce on consumers.

## Current non-goals

- Public crates.io release (deferred, not foreclosed). Local/git install-and-pin via `cargo install --path` or `cargo install --git` is the current distribution; publishing is a later decision requiring explicit sign-off.
- Porting undertask's full mixed-ecosystem dependency-assessment workflow.
- JavaScript ecosystem support.
- Multi-workspace orchestration.

## Current implemented surface

The simple hardening path is implemented. `age`, `age-lock`, `resolve`,
`assess`, `inspect`, `gatehouse candidate`, `policy init`, `pin-check`,
`review`, `audit`, and `verify` are implemented.

The current intake layer is:

- `assess` remains the post-add diff classifier
- `inspect` is the implemented first Rust-only, crates.io-only deep-review surface
- `pin-check` is now the implemented first reviewed-target enforcement surface
- the current enforcement baseline is checked-in review records plus a repo-root
  `reviewed-targets.toml` manifest for active Rust families
- `pin-check` now validates that each active reviewed family points at a real
  checked-in review record path before it trusts the reviewed-target declaration
- the first gate trusts exact `Cargo.lock` parity plus optional exact direct
  manifest requirements
- `verify` now reuses that same reviewed-target gate before `cargo build --locked`
  and `cargo test --locked`
- the current reviewed-target gate now supports crates.io reviewed-artefact
  reconciliation: record the reviewed tarball digest in `reviewed-targets.toml`
  and verify it against the resolved `Cargo.lock` checksum chain
- reviewed families can declare exact `allowed_age_exceptions` for
  checksum-bound too-fresh versions; release-age-aware commands honour them at
  one shared evaluation seam while yanked releases and checksum mismatches
  remain blocking
- comparative command baselines and review ergonomics are now partially
  decoupled from `git`:
  `age-lock` can compare against an explicit baseline lockfile,
  `assess` and `review` can compare against an explicit baseline directory,
  and `resolve` rechecks against an internal pre-update `Cargo.lock` snapshot
  instead of relying on `HEAD`
- `resolve` also supports a non-mutating `--dry-run` preview that shows the
  would-be `Cargo.lock` diff without changing the working tree
  - the copied workspace preserves relative symlinks only when their resolved
    target remains inside the source workspace and outside skipped `.git` /
    `target` paths; unsupported symlinks fail closed
- `policy init` creates the explicit adoption scaffold for consumer repos:
  `barbican.toml`, `reviewed-targets.toml`, and dependency-review conventions
  without reviewing or certifying existing dependencies; scaffold items are
  created independently so repairable pieces can be laid down even when another
  item is blocked

## Deferred / Non-Sequenced Design Work

### Full Windows Support (Non-Sequenced)

Full Windows support is explicitly parked. It is not scheduled in the current
phase plan, and until it lands Windows remains outside the supported platform
posture above.

Delivering supported Windows operation requires a comprehensive Windows audit
and review of the codebase, with particular attention to:

- filesystem path handling and fail-closed containment paths
- symlink, directory junction, and reparse-point classification under
  `symlink_metadata`
- path canonicalisation and confinement
- `create_dir_all` / `fs::write` write-through behaviour
- subprocess invocation and shell-free argument boundaries
- path separators, prefixes, and `OsStr` / encoding behaviour

It also requires a methodology for post-hardening cross-platform parity:

- Windows CI that runs the relevant command and library tests
- a platform-parity test matrix for scaffold and containment paths
- golden behavioural tests that run on both Unix-like systems and Windows
- explicit verification that wrong-type, symlink, junction, and reparse-point
  scaffold paths fail closed on Windows

Modern Rust may already classify some Windows junction/reparse-point cases in
a fail-closed way under `symlink_metadata`; the audit must verify that fact
rather than assume it.

### Race-Free Filesystem Containment (Non-Sequenced)

Race-free filesystem containment is explicitly parked. Current scaffold and
workspace-copy containment checks are designed for static checked-in repo
state; they do not claim to defeat a concurrent local writer racing a
check-then-act sequence between `symlink_metadata` and later `create_dir_all` /
`fs::write` calls.

Delivering race-free containment would require platform-specific design and
verification, such as descriptor-relative operations and no-follow resolution
primitives where available (`openat2(RESOLVE_NO_SYMLINKS)` / `O_NOFOLLOW` on
Unix-like systems), plus an equivalent Windows strategy.

### Reviewed-Target Source-Kind Enforcement (Non-Sequenced)

Version-only reviewed targets are currently retained for backwards-compatible
policy manifests. The safe preferred form for crates.io artefacts is the
structured `{ version = "...", checksum_sha256 = "..." }` entry, which binds
the reviewed target to Cargo.lock's crates.io checksum chain.

Future reviewed-target hardening should make source-kind expectations explicit
for all reviewed targets. In particular, version-only entries should not be
source-agnostic: a same-version git, path, or alternate-registry source must
not satisfy a reviewed crates.io target merely because the version string
matches. The likely direction is either to require checksums by default for
crates.io artefacts or to add an explicit reviewed source kind for legacy
version-only entries.

## Architectural boundary

The codebase is split into a library crate and a Cargo-subcommand binary from
the start:

- `crates/barbican/` — pure policy logic, domain types, and HTTP-behind-trait boundaries
- `crates/cargo-barbican/` — CLI dispatch, subprocess integration, and concrete HTTP implementation

That split keeps the library testable without network access and confines
shelling out to the binary.

## Dependency model

Every dependency addition or dependency-tool install is documented in
`docs/dependency-reviews/` before it lands. Most direct dependencies inherit
from Undertask's reviewed set; local first-principles reviews cover direct
dependencies that define cargo-barbican-specific boundaries such as HTTP,
time parsing, archive inspection, checksum computation, and diff rendering.

## Repo shape

```text
Cargo.toml              workspace
rust-toolchain.toml     pinned toolchain
crates/
  barbican/             library: types + pure functions, network behind trait
  cargo-barbican/       binary: CLI dispatch, subprocesses, HTTP impl
templates/              shipped content copied into consumer repos
docs/
  user/                 consumer adoption docs
  functional/           CLI and behaviour contracts
  architecture/         goals, boundaries, and design decisions
  contributor/          contributor constraints and repo workflow
  dependency-reviews/   review records and policy template
  standards/            adopted documentation standards
```
