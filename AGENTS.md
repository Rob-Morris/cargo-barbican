# cargo-barbican

A Cargo subcommand for Rust supply-chain hardening: a policy-first tool that
gives a Rust repo one gate for what enters its dependency graph. Pure Rust,
designed as a portable product that consumer repos install and pin. Distributed
today by local/git install-and-pin; crates.io publication is a deferred
decision, not foreclosed.

ALWAYS DO FIRST: Read [`docs/contributor/agents.md`](docs/contributor/agents.md)
for the agent route-map (constraints, current state, what to build).

## Design And Specification

Read [`docs/architecture/overview.md`](docs/architecture/overview.md) for the
product goals, boundaries, and system shape, then
[`docs/contributor/specification.md`](docs/contributor/specification.md) for
the current contributor-facing constraints.

## Source Material

cargo-barbican was extracted from the Rust supply-chain policy tooling in
[`~/Development/undertask/scripts/`](https://github.com/rob-morris/undertask).
undertask is the origin and a working reference, not the specification:
cargo-barbican is a portable policy product in its own right and has grown a
surface beyond the original scripts. Read undertask's scripts as reference
before reinventing equivalent behaviour.

Relevant undertask files:

- `scripts/check-crate-release-age.py`
- `scripts/check-cargo-lock-release-age.py`
- `scripts/select-cargo-package-id.py`
- `scripts/deps-rust-routine-update.sh`
- `docs/dependency-management.md` (policy doc, Rust + JS)
- `deny.toml` (cargo-deny config)

## Documentation

This repo follows the
[`Agent-Ready Documentation Standard v1.0.0`](docs/standards/agent-ready-documentation.md).
[`docs/README.md`](docs/README.md) is the documentation entry point.

## Before Committing

Follow [`.canaries/pre-commit.md`](.canaries/pre-commit.md), write
`.canary--pre-commit`, and leave it unstaged. The canary brief is the
canonical before-commit checklist; it covers verification, dependency
provenance, docs routing, version bundles, and commit-subject policy.

## Local Overrides

If `AGENTS.local.md` exists in the repo root, read it for machine-specific
configuration.
