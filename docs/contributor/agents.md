# Contributing — Agent Instructions

Read [../CONTRIBUTING.md](../CONTRIBUTING.md) first for the repo-level
documentation structure and maintenance rules.

For commit-time workflow, also read
[`process.md`](process.md) and
[`../standards/canary.md`](../standards/canary.md).

Route-map for agents working in this repo. Read
[`../architecture/overview.md`](../architecture/overview.md) for the
authoritative design, then
[`specification.md`](specification.md) for the implementation plan and
contributor-facing constraints.

## What you are building

A Cargo subcommand for Rust supply-chain hardening. Pure Rust. Replaces the
Python scripts currently in [`undertask`](https://github.com/rob-morris/undertask).

The full design, bootstrap sequence, and constraints are in the architecture,
functional, and contributor docs. This file is a route-map.

## Hard stops — request user input before any of these

- Adding a dependency that does not appear in undertask's reviewed set,
  unless you have completed a first-principles review and written a record
  in `docs/dependency-reviews/`.
- Changing the subcommand surface from what `docs/functional/cli.md` specifies.
- Adding a second HTTP client (`ureq` is the chosen boundary).
- Wrapping libgit2 or cargo-as-a-library instead of shelling out to `git`
  and `cargo`.
- Coupling the library crate to subprocess concerns. The library uses a
  trait for HTTP; subprocesses live in the binary.
- Publishing to crates.io. v0.1 is local-install only.

## Invariants

- The library (`crates/barbican/`) is testable without network access.
- The binary (`crates/cargo-barbican/`) is the only crate that shells out.
- Every dependency in `Cargo.toml` has a corresponding review record in
  `docs/dependency-reviews/` written **before** the dependency is added.
- Behaviour matches undertask where the surface overlaps; deviations are
  documented in `docs/functional/cli.md` and `docs/architecture/overview.md`.
- Shipped repo versions are tracked in `docs/CHANGELOG.md` and
  `docs/changelog/`, and the two crate manifest versions move together.
- Commit subjects follow `docs/standards/commit-messages.md`, and versioned
  commits reuse the canonical changelog `Summary`.
- The pre-commit canary receipt in `.canary--pre-commit` is transient local
  state; it must stay unstaged and untracked.

## Layout

```
Cargo.toml              workspace
rust-toolchain.toml     pinned to 1.95.0
crates/
  barbican/             library: types + pure functions, network behind trait
  cargo-barbican/       binary: clap dispatch, subprocesses, HTTP impl
templates/              shipped to consumers (deny.toml, policy doc, review template)
docs/
  user/                 user-facing adoption docs
  functional/           CLI and behaviour contracts
  architecture/         goals, boundaries, and design-decision routing
  dependency-reviews/   review records (written before each dep is added)
  contributor/          route-map, specification, and contributor docs
  standards/            adopted documentation standards
```

## Current state

Layer 0 implementation scaffolding only. The documentation structure now
follows the agent-ready standard, but the code remains at the empty-crate /
placeholder-binary stage.

Next steps are in `specification.md` under `Implementation bootstrap sequence`.

## Source material to read before implementing

In undertask:

- `scripts/check-crate-release-age.py`
- `scripts/check-cargo-lock-release-age.py`
- `scripts/select-cargo-package-id.py`
- `scripts/deps-rust-routine-update.sh`
- `docs/dependency-management.md`
- `deny.toml`
- `docs/dependency-reviews/` (samples — the format we adopt)

These are the reference. Re-implement faithfully; don't redesign.

## Conventions

- Locale: Australian English in prose.
- No comments explaining what code does. Comment only non-obvious *why*.
- Tests for the library go in the library. Integration tests for the
  binary go under `crates/cargo-barbican/tests/`.

## Before committing

1. `cargo build --locked` passes.
2. `cargo test --locked` passes.
3. `cargo audit` and `cargo deny check advisories bans sources` pass (once deps and `deny.toml`
   exist).
4. Any new dependency has a checked-in review record.
5. If either crate version changed, `docs/CHANGELOG.md` and the matching
   `docs/changelog/vX.Y.Z.md` entry changed with it.
6. `.canaries/pre-commit.md` was followed and `.canary--pre-commit` was
   written locally, left unstaged, and allowed to be deleted by the hook.
7. The commit subject matches `docs/standards/commit-messages.md`.
