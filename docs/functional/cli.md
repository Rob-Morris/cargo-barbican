# CLI Contract

Planned `cargo barbican` surface for v0.1. The current implementation scaffold
may lag this contract; this document describes the intended behaviour.

## Planned subcommands

```text
cargo barbican age <crate@version>...
    Check that each crate@version was published at least N days ago
    (default 7). Pure HTTP GET to the crates.io API.

cargo barbican age-lock [--base-ref HEAD] [--min-age-days 7]
    Diff Cargo.lock against a git ref. For every newly selected crates.io
    version, verify release age. Catches too-fresh transitive selections.

cargo barbican resolve <crate@version>...
    1. Run `age` on each spec.
    2. Use `cargo metadata` to disambiguate package IDs when a crate name
       appears at multiple versions in the lockfile.
    3. Run `cargo update --workspace -p <package-id> --precise <version>`
       for each spec.
    4. Run `age-lock` on the resulting diff.

cargo barbican review
    Print a `git diff` of policy-relevant files (Cargo.toml, Cargo.lock,
    deny.toml, member Cargo.toml files) with a checklist printed above.

cargo barbican audit
    Run `cargo audit` and `cargo deny check advisories bans sources`.
    Fail if either fails.

cargo barbican verify
    Run `cargo build --locked` and `cargo test --locked`.
```

## Exit codes

- `0` — success
- `1` — policy violation, such as an age-gate failure, advisory finding, or disallowed source
- `2` — usage error

## Behavioural boundaries

- `crates/barbican/` owns pure policy logic and remains testable without network access.
- `crates/cargo-barbican/` owns CLI parsing, subprocess calls, and the concrete HTTP implementation.
- Behaviour should match undertask where the surface overlaps unless the docs explicitly say otherwise.
