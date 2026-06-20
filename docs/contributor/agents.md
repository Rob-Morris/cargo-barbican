# Contributing — Agent Instructions

Read [../CONTRIBUTING.md](../CONTRIBUTING.md) first for the repo-level
documentation structure and maintenance rules.

For commit-time workflow, also read
[`process.md`](process.md) and
[`../standards/canary.md`](../standards/canary.md).

Route-map for agents working in this repo. Read
[`../architecture/overview.md`](../architecture/overview.md) for the
authoritative design, then
[`specification.md`](specification.md) for the current contributor-facing
constraints.

## What you are building

A Cargo subcommand for Rust supply-chain hardening. Pure Rust. A portable,
policy-first tool that gives a Rust repo one dependency-intake gate — extracted
from [`undertask`](https://github.com/rob-morris/undertask)'s Rust scripts as
its origin and reference, but a product in its own right, not a 1:1 port.

The full current design, behaviour, and contributor constraints are in the
architecture, functional, and contributor docs. This file is a route-map.

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
- Publishing to crates.io. Publication is a deliberate future distribution
  decision, not foreclosed; the current release line is local/git
  install-and-pin. Get explicit sign-off before publishing.

## Invariants

- The library (`crates/barbican/`) is testable without network access.
- The binary (`crates/cargo-barbican/`) is the only crate that shells out.
- Every dependency in `Cargo.toml` has a corresponding review record in
  `docs/dependency-reviews/` written **before** the dependency is added.
- Where the surface overlaps undertask, behaviour matches its proven workflow;
  cargo-barbican also extends beyond undertask, and both deviations and
  extensions are documented in `docs/functional/cli.md` and
  `docs/architecture/overview.md`.
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

The repo has now moved beyond scaffolding and the dependency baseline. The
current implemented surface is:

- `cargo barbican age`
- `cargo barbican age-lock`
- `cargo barbican resolve`
- `cargo barbican assess`
- `cargo barbican inspect`
- `cargo barbican gatehouse candidate`
- `cargo barbican policy init`
- `cargo barbican inventory`
- `cargo barbican pin-check`
- `cargo barbican review`
- `cargo barbican audit`
- `cargo barbican verify`

The checked-in `barbican.toml` shape exists with `[release_age]`,
`[high_scrutiny]`, and `[delegates]`. The library owns pure policy and parsing
logic, while the binary owns subprocesses and the concrete `ureq` HTTP
boundary.

The current comparative baseline behaviour is:

- `age-lock` defaults to `HEAD` but can compare against an explicit baseline
  lockfile with `--base-lockfile`
- `assess` defaults to `HEAD` but can compare against an explicit baseline
  directory with `--base-dir`
- `review` keeps the git-backed default path but can compare against an
  explicit baseline directory with `--base-dir`
- `resolve` rechecks against an internal pre-update `Cargo.lock` snapshot
  rather than a git ref
- `resolve --dry-run` now previews the would-be `Cargo.lock` diff without
  mutating the working tree
  - the copied workspace preserves relative symlinks only when their resolved
    target stays inside the source workspace and outside skipped `.git` /
    `target` paths; unsupported symlinks fail closed

The current intake layer now includes the first pre-add deep-review slice:

- `cargo barbican inspect` exists as the first Rust-only, crates.io-only
  pre-add deep-review surface
- `cargo barbican gatehouse candidate` exists as the first workflow
  convenience surface for isolated exact-candidate intake dossiers
- `cargo barbican policy init` exists as the deterministic policy scaffold
  command for consumer adoption; it creates missing explicit policy files but
  does not review or certify existing dependencies
- `cargo barbican inventory` exists as the first read-only dependency
  inventory and policy-coverage audit; the current slice is offline and reports
  live execution surfaces as not collected
- `cargo barbican pin-check` now exists as the first reviewed-target
  enforcement surface over repo-root `reviewed-targets.toml`
- `pin-check` now validates that every active reviewed family points at a real
  checked-in review record path before it trusts that reviewed-target entry
- the first gate trusts exact `Cargo.lock` parity plus optional exact direct
  manifest requirements; stronger build-input parity remains deferred
- for structured crates.io `resolved` entries, `pin-check` also reconciles the
  reviewed `checksum_sha256` against the resolved `Cargo.lock` checksum chain
- reviewed families can now declare exact `allowed_surfaces` for reviewed
  `build-rs`, `proc-macro`, and `native-sys` execution surfaces
- `assess` renders matched reviewed execution-surface allowances separately and
  excludes them from elevated-risk classification, but fails closed if the
  matching family review record is missing
- reviewed families can now declare exact `allowed_age_exceptions` for
  checksum-bound too-fresh crates already present in the same family `resolved`
  map
- release-age-aware commands honour those reviewed release-age exceptions at
  the shared release-age seam, while yanked releases and exception checksum
  mismatches remain blocking
- `cargo barbican verify` now reuses the default `pin-check` gate before
  running locked build/test verification

## Source material to read before implementing

In undertask:

- `scripts/check-crate-release-age.py`
- `scripts/check-cargo-lock-release-age.py`
- `scripts/select-cargo-package-id.py`
- `scripts/assess-dependency-update.py`
- `scripts/deps-rust-routine-update.sh`
- `docs/dependency-management.md`
- `deny.toml`
- `docs/dependency-reviews/` (samples — the format we adopt)

These are the reference. Re-implement their proven behaviour faithfully where
surfaces overlap; extensions beyond undertask are expected as the policy
product grows.

## Conventions

- Locale: Australian English in prose.
- No comments explaining what code does. Comment only non-obvious *why*.
- Tests for the library go in the library. Integration tests for the
  binary go under `crates/cargo-barbican/tests/`.

## Before committing

Follow [`.canaries/pre-commit.md`](../../.canaries/pre-commit.md), write
`.canary--pre-commit`, and leave it unstaged. The canary brief is the
canonical before-commit checklist; see [`process.md`](process.md) for the
supporting workflow and local hook details.

The default verification command is `sh scripts/verify.sh` with no flags. Do
not manually substitute the raw cargo/audit/deny sequence for that dogfooded
gate. Off `main`, use `--vanilla` or `--skip REASON` only for a known
intermediate state, and record the reason in `.canary--pre-commit`.
`VERIFY_BRANCH_OVERRIDE` exists only for tests and controlled local validation
of the branch guard; do not use it for normal commit verification.
