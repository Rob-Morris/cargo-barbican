# CLI Contract

Planned `cargo barbican` surface for v0.1. The current implementation scaffold
may lag this contract; this document describes the intended behaviour.

## Planned subcommands

```text
cargo barbican age [--min-age-days N] <crate@version>...
    Check that each crate@version was published at least N days ago
    (default 7). The default comes from `barbican.toml`
    `[release_age].minimum_days`, falling back to 7 when the file or key is
    absent. `--min-age-days` overrides the config for the current command.
    Pure HTTP GET to the crates.io API.

cargo barbican age-lock [--base-ref HEAD] [--lockfile Cargo.lock] [--min-age-days N]
    Diff Cargo.lock against a git ref. For every newly selected crates.io
    version, verify release age. Catches too-fresh transitive selections.
    When `--min-age-days` is absent, the command uses the same
    `barbican.toml` release-age default as `age`.

cargo barbican resolve <crate@version>...
    1. Run `age` on each spec.
    2. Use `cargo metadata` to disambiguate package IDs when a crate name
       appears at multiple versions in the lockfile.
    3. Run `cargo update --workspace -p <package-id> --precise <version>`
       for each spec.
    4. Run `age-lock` on the resulting diff.

cargo barbican assess [--base-ref HEAD] [--lockfile Cargo.lock] [--min-age-days N]
    Diff the current Rust dependency state against a git ref and classify the
    change as `routine-safe`, `elevated-risk`, or `policy-violating`.
    The first slice is post-add Rust assessment only. It checks:
    - new direct dependencies across workspace Cargo.toml files
    - new non-crates.io direct dependency specs
    - newly selected crates.io versions below the minimum age
    - newly selected yanked crates.io versions
    - non-crates.io source changes in Cargo.lock
    - newly introduced native `-sys` crates
    - new or changed `build.rs` and `proc-macro` surfaces in newly selected packages
    - failed inspection of dependency surfaces required by the first slice
    When `--min-age-days` is absent, the command uses the same
    `barbican.toml` release-age default as `age`.
    Enabled `[high_scrutiny]` keys decide which elevated-risk findings are
    active. The first slice is fail-closed: any blocking finding, including a
    required inspection failure, or any enabled elevated-risk finding returns
    exit 1.

cargo barbican inspect [--min-age-days N] <crate@version>...
    Pre-add deep review for one or more exact crates.io candidates.
    The first slice is Rust-only and crates.io-only. For each exact spec it:
    - checks the version against the same release-age policy used by `age`
    - fetches crates.io version metadata and the published `.crate` tarball
    - computes the tarball SHA-256 locally and cross-checks it against the
      published checksum
    - inspects `.cargo_vcs_info.json` when present for upstream provenance hints
    - enumerates `build.rs`, `proc-macro`, and native `-sys` / FFI surfaces
    - runs a fixed high-scrutiny IOC scan over build-time and proc-macro-relevant sources
    - prints a structured report suitable for a checked-in dependency review record
    The command classifies each candidate as `routine-safe`,
    `elevated-risk`, or `policy-violating`.
    IOC hits, checksum mismatches, and required-inspection failures are
    `policy-violating`. `build.rs`, `proc-macro`, and native `-sys` / FFI
    surfaces are `elevated-risk` unless a later slice proves a narrower rule.
    The first slice is fail-closed for routine intake: any non-routine result
    returns exit 1.
    When `--min-age-days` is absent, the command uses the same
    `barbican.toml` release-age default as `age`.

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
- `1` — blocking policy failure, such as an age-gate failure, advisory finding, disallowed source, or fail-closed inspection failure
- `2` — usage error

## Behavioural boundaries

- `crates/barbican/` owns pure policy logic and remains testable without network access.
- `crates/cargo-barbican/` owns CLI parsing, subprocess calls, and the concrete HTTP implementation.
- Behaviour should match undertask where the surface overlaps unless the docs explicitly say otherwise.
- The deeper intake path is now shaped as a separate `inspect` command rather than additional scope hidden inside `assess`.
- Review-record reconciliation and lockfile pin enforcement remain a later surface. `pin-check` is the current intended follow-on name, but it is not yet part of the CLI contract.
