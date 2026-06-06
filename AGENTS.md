# cargo-barbican

A Cargo subcommand for Rust supply-chain hardening. Pure Rust. Local use first;
public crate later if warranted.

ALWAYS DO FIRST: Read [`docs/contributor/agents.md`](docs/contributor/agents.md)
for the agent route-map (constraints, current state, what to build).

## Design And Specification

Read [`docs/architecture/overview.md`](docs/architecture/overview.md) for the
product goals, boundaries, and system shape, then
[`docs/contributor/specification.md`](docs/contributor/specification.md) for
the implementation plan and contributor-facing constraints.

## Source Material

This tool ports Python scripts from
[`~/Development/undertask/scripts/`](https://github.com/rob-morris/undertask)
into Rust. The Python implementation works; this is a re-implementation, not
a clean-slate design. Read undertask's scripts before reinventing anything.

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

1. `cargo build --locked` and `cargo test --locked` pass.
2. Every dependency added is recorded in `docs/dependency-reviews/`.
3. `cargo deny check advisories bans sources` passes.
4. `cargo audit` passes.
5. Follow `.canaries/pre-commit.md`, write `.canary--pre-commit`, and leave it unstaged.
6. Commit subjects follow `docs/standards/commit-messages.md`.

## Local Overrides

If `AGENTS.local.md` exists in the repo root, read it for machine-specific
configuration.
