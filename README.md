# cargo-barbican

`cargo barbican` is a Cargo subcommand for Rust supply-chain policy.

It gives a Rust repo one dependency gate: check what is being updated, apply
minimum release-age policy, surface higher-risk dependency behaviour, run the
standard advisory and deny checks, and verify the locked build before the
change lands.

cargo-barbican exists to replace per-repo Rust hardening scripts with one
versioned tool that consumer repos can install, pin, and run consistently.

## Why it exists

Rust already has strong specialist tools in this space:

- `cargo-audit` for known advisories
- `cargo-deny` for advisories, bans, sources, duplicates, and licences

cargo-barbican sits above those tools as the policy layer. Its job is to make
dependency intake deliberate and reviewable, especially in the gap between
"known-bad" and "too new or too risky to trust yet."

## What it is for

The initial workflow is centered on routine Rust dependency updates:

- exact `crate@version` release-age checks
- `Cargo.lock` diff checks for newly selected transitive crates
- targeted resolution for multi-version lockfiles
- assessment of higher-scrutiny Rust surfaces such as `build.rs`,
  `proc-macro`, and native `-sys` / FFI crates
- delegated `cargo-audit` and `cargo-deny` checks
- locked build and test verification

The goal is simple: make ordinary Rust dependency best practice easy.

## Scope

cargo-barbican is a Rust-only tool.

It is not:

- a replacement for `cargo-audit` or `cargo-deny`
- a cross-ecosystem package-management tool
- a general-purpose security scanner

It is the policy checkpoint in front of the existing Rust dependency toolchain.

## Repo shape

- `crates/barbican/` — policy logic, domain types, and testable core behaviour
- `crates/cargo-barbican/` — CLI dispatch, subprocesses, and concrete I/O boundaries
- `docs/` — user, functional, architectural, and contributor documentation
- `templates/` — shipped repo content for consumer adoption

## Documentation

- [docs/README.md](docs/README.md) — documentation index
- [docs/CHANGELOG.md](docs/CHANGELOG.md) — shipped version history
- [docs/functional/cli.md](docs/functional/cli.md) — command surface
- [docs/architecture/overview.md](docs/architecture/overview.md) — goals and boundaries
- [docs/contributor/specification.md](docs/contributor/specification.md) — implementation constraints
- [docs/standards/README.md](docs/standards/README.md) — changelog, commit-message, and documentation standards
- [AGENTS.md](AGENTS.md) — agent route-map for repo work
