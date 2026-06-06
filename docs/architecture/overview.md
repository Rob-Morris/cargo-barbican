# Architecture Overview

A portable Rust supply-chain hardening tool. Pure Rust, single versioned
implementation that every Rust repo in this constellation can install and pin.
Local use first; public crate later if warranted.

## Why this exists

[undertask](https://github.com/rob-morris/undertask) implements supply-chain
hardening as Python scripts plus a shell wrapper. The hardening model is sound:
release-age gating, `--locked` verification, targeted updates, advisory checks,
and checked-in review records for dependency changes.

The problem is duplication. As soon as multiple Rust repos need the same
hardening, copy-pasted scripts drift. cargo-barbican exists to replace that
duplication with one versioned Rust tool that consumer repos can pin and
re-sync deliberately.

## Goals

1. Single source of truth for this Rust supply-chain hardening workflow.
2. Pure Rust installation and execution, with no Python prerequisite.
3. Inherit existing trust decisions from undertask where possible instead of re-reviewing by default.
4. Match undertask's surface closely enough that existing muscle memory transfers.
5. Apply the same supply-chain discipline to cargo-barbican itself that it will enforce on consumers.

## Non-goals for v0.1

- Public crates.io release. Local installation via `cargo install --path` or `cargo install --git` is enough.
- Porting undertask's full mixed-ecosystem dependency-assessment workflow.
- JavaScript ecosystem support.
- Multi-workspace orchestration.

## Current implemented surface

The simple hardening path is implemented. `age`, `age-lock`, `resolve`,
`assess`, `inspect`, `pin-check`, `review`, `audit`, and `verify` all exist on
`dev`.

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
- comparative command baselines and review ergonomics are now partially
  decoupled from `git`:
  `age-lock` can compare against an explicit baseline lockfile,
  `assess` and `review` can compare against an explicit baseline directory,
  and `resolve` rechecks against an internal pre-update `Cargo.lock` snapshot
  instead of relying on `HEAD`
- `resolve` also supports a non-mutating `--dry-run` preview that shows the
  would-be `Cargo.lock` diff without changing the working tree

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
