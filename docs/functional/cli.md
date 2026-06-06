# CLI Contract

Current `cargo barbican` surface for v0.1. This document describes the
intended behaviour of the implemented command set on `dev`.

## Subcommands

```text
cargo barbican age [--min-age-days N] <crate@version>...
    Check that each crate@version was published at least N days ago
    (default 7). The default comes from `barbican.toml`
    `[release_age].minimum_days`, falling back to 7 when the file or key is
    absent. `--min-age-days` overrides the config for the current command.
    Pure HTTP GET to the crates.io API.

cargo barbican age-lock [--base-ref REF | --base-lockfile PATH] [--lockfile Cargo.lock] [--min-age-days N]
    Diff Cargo.lock against a baseline lockfile. By default the baseline is
    `HEAD:<lockfile>`. `--base-lockfile` provides an explicit non-git baseline
    file instead. For every newly selected crates.io version, verify release
    age. Catches too-fresh transitive selections.
    When `--min-age-days` is absent, the command uses the same
    `barbican.toml` release-age default as `age`.

cargo barbican resolve [--dry-run] [--min-age-days N] <crate@version>...
    1. Run `age` on each spec.
    2. Use `cargo metadata` to disambiguate package IDs when a crate name
       appears at multiple versions in the lockfile.
    3. Run `cargo update --workspace -p <package-id> --precise <version>`
       for each spec.
    4. Recheck newly selected crates.io versions against the pre-update
       `Cargo.lock` snapshot.
    With `--dry-run`, perform the update in an internal temp workspace and
    print a summary/diff preview of the would-be `Cargo.lock` change instead
    of mutating the repo.
    Dry-run preview honours Cargo configuration at or below the copied
    workspace root and in `$CARGO_HOME`. Ancestor `.cargo/config.toml` files
    between the workspace root and `$HOME` are not copied into the preview
    workspace, so they can make dry-run resolution differ from an in-place run.
    When `--min-age-days` is absent, the command uses the same
    `barbican.toml` release-age default as `age`.

cargo barbican assess [--base-ref REF | --base-dir PATH] [--lockfile Cargo.lock] [--min-age-days N]
    Diff the current Rust dependency state against a baseline dependency
    state and classify the change as `routine-safe`, `elevated-risk`, or
    `policy-violating`. By default the baseline is the current workspace
    state at `HEAD`. `--base-dir` provides an explicit non-git baseline
    directory containing the comparison `Cargo.lock` and workspace manifests.
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

cargo barbican pin-check [--config reviewed-targets.toml]
    Check active reviewed Rust families against the current workspace manifests
    and `Cargo.lock`.
    The first slice is local-only and read-only. It:
    - reads the repo-root `reviewed-targets.toml` manifest by default
    - skips successfully when that file is absent
    - skips successfully when no active Rust families are configured
    - checks that each active `review_record` path exists in the repo
    - checks optional exact direct manifest requirements, including the leading `=`
    - checks exact resolved `Cargo.lock` versions for every active reviewed family
    - for structured crates.io `resolved` entries, also checks the reviewed
      `checksum_sha256` against the resolved `Cargo.lock` checksum chain
    The first slice treats exact `Cargo.lock` parity as the load-bearing
    execution gate. It does not yet verify installed-tree or stronger
    build-input parity.
    Structured crates.io reviewed-artefact form:
    - `serde = { version = "1.0.228", checksum_sha256 = "..." }`
    - legacy string entries such as `serde = "1.0.228"` remain accepted
    - stronger installed-tree or broader non-crates.io artefact parity remains
      out of scope for this slice

cargo barbican review [--base-dir PATH]
    Print a diff of policy-relevant files with a checklist printed above.
    By default the command uses the existing git-backed path.
    `--base-dir` switches to an explicit non-git baseline directory and
    renders the same review file set without relying on `git`.
    This includes:
    - repo-root `Cargo.toml`, `Cargo.lock`, `barbican.toml`, `deny.toml`,
      and `reviewed-targets.toml` when present
    - workspace member `Cargo.toml` files
    - checked-in dependency review records under `docs/dependency-reviews/`

cargo barbican audit
    Run `cargo audit` and `cargo deny check advisories bans sources`.
    Fail if either fails.

cargo barbican verify
    Run the local execution gates in order:
    1. `pin-check` with the default repo-root `reviewed-targets.toml`
    2. `cargo build --locked`
    3. `cargo test --locked`
    If no reviewed-target manifest is present, or no active Rust families are
    configured, the pin-check step skips successfully and verification
    continues.
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
- Reviewed-target enforcement has a dedicated `pin-check` surface, and `verify`
  now reuses that same gate before code-executing build/test steps. The
  foundation for that work is checked-in review records plus a repo-root
  `reviewed-targets.toml` manifest for active Rust families.
- The current reviewed-target hardening step includes crates.io
  artefact-digest reconciliation in `reviewed-targets.toml`, not a direct port
  of the JS installed-tree gate.
