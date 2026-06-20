# CLI Contract

Current `cargo barbican` surface. This document describes the intended
behaviour of the implemented command set.

## Subcommands

```text
cargo barbican age [--min-age-days N] <crate@version>...
    Check that each crate@version was published at least N days ago
    (default 7). The default comes from `barbican.toml`
    `[release_age].minimum_days`, falling back to 7 when the file or key is
    absent. `--min-age-days` overrides the config for the current command.
    A matching reviewed release-age exception in `reviewed-targets.toml` can
    allow a too-fresh exact version when its review record exists and its
    reviewed checksum matches the fetched crates.io artefact.
    Pure HTTP GET to the crates.io API.

cargo barbican age-lock [--base-ref REF | --base-lockfile PATH] [--lockfile Cargo.lock] [--min-age-days N]
    Diff Cargo.lock against a baseline lockfile. By default the baseline is
    `HEAD:<lockfile>`. `--base-lockfile` provides an explicit non-git baseline
    file instead. For every newly selected crates.io version, verify release
    age. Catches too-fresh transitive selections.
    When `--min-age-days` is absent, the command uses the same
    `barbican.toml` release-age default as `age`.
    Reviewed release-age exceptions are honoured through the same shared
    release-age policy path as `age`.

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
    The dry-run workspace copy preserves relative symlinks only after proving
    their fully resolved target remains inside the source workspace and does
    not point into skipped `.git` or `target` paths. Absolute, broken,
    looping, escaping, or skipped-target symlinks fail the dry-run setup rather
    than being dereferenced or silently skipped.
    When `--min-age-days` is absent, the command uses the same
    `barbican.toml` release-age default as `age`.
    The initial candidate age check and the post-update lockfile recheck both
    honour the same reviewed release-age exceptions.

cargo barbican assess [--base-ref REF | --base-dir PATH] [--policy-mode strict|elevated-risk] [--lockfile Cargo.lock] [--min-age-days N]
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
    Matching reviewed release-age exceptions are rendered in
    `Allowed policy exceptions:` and do not contribute to age-violation
    findings. Yanked crates and exception checksum mismatches remain blocking.
    Enabled `[high_scrutiny]` keys decide which elevated-risk findings are
    active. The default `--policy-mode strict` path is fail-closed: any
    blocking finding, including a required inspection failure, or any enabled
    elevated-risk finding returns exit 1. `--policy-mode elevated-risk`
    accepts elevated-risk findings with exit 0 while still printing the
    elevated-risk classification and still failing any `policy-violating`
    result.

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
    surfaces are `elevated-risk` unless they match an exact reviewed
    execution-surface allowance in `reviewed-targets.toml`.
    The first slice is fail-closed for routine intake: any non-routine result
    returns exit 1.
    When `--min-age-days` is absent, the command uses the same
    `barbican.toml` release-age default as `age`.
    Matching reviewed release-age exceptions are rendered visibly in the
    release-age line. They can only allow too-fresh releases; yanked releases
    and checksum mismatches remain `policy-violating`.
    Matching reviewed execution-surface allowances are rendered in an
    `Allowed policy exceptions:` section and do not contribute to the
    `elevated-risk` classification by themselves. The matching family
    `review_record` must exist before `assess` trusts the allowance.

cargo barbican gatehouse candidate [--preserve-sandbox] <crate@version>
    Assemble a human-readable candidate-intake dossier for one exact crates.io
    dependency candidate without mutating the current repo. This is a workflow
    convenience layer over the base evidence commands, not a separate policy
    engine. The first slice:
    - runs the same exact-candidate inspection used by `inspect`
    - creates a disposable minimal Cargo project pinned to `=version`
    - generates the sandbox `Cargo.lock` with Cargo
    - runs `cargo tree --edges normal` in the sandbox
    - runs `cargo audit` in the sandbox
    - renders one dossier on stdout
    The command does not build, test, or execute the candidate package. It
    resolves metadata and lockfile state, runs static inspection of the
    published crate tarball, renders Cargo's dependency graph, and audits the
    generated lockfile.
    Because the dossier uses the same inspection path as `inspect`, reviewed
    release-age exceptions are rendered visibly in the inspect evidence and
    checksum mismatches remain blocking.
    The sandbox is removed by default. `--preserve-sandbox` keeps it for
    manual inspection and prints the sandbox path. Any failed required evidence
    step returns exit 1 after rendering the failure in the dossier.

cargo barbican policy init
    Create the explicit policy scaffold for adopting cargo-barbican in a repo.
    The first slice creates missing:
    - `barbican.toml`
    - `reviewed-targets.toml`
    - `docs/dependency-reviews/`
    - `docs/dependency-reviews/README.md`
    It does not create `deny.toml`, active reviewed families, dependency
    review records, or inventory reports.
    Existing regular files are preserved. Existing `barbican.toml` is read
    and validated. Malformed config fails before dependent scaffold files are
    created. Symlinks, directories, and other wrong-type paths at scaffold
    locations or existing scaffold ancestors fail closed rather than being
    followed or overwritten.
    For Windows, see the project-level Platform Support posture in
    `docs/architecture/overview.md`; until full Windows support lands, run
    from trusted checkouts without junctions in scaffold paths.
    The command prints an action report and next-step guidance pointing to
    the manual adoption guide.

cargo barbican inventory
    Print a read-only, whole-repo dependency inventory and policy-coverage
    audit. The first slice is offline and local-only. It:
    - reads `Cargo.lock` as the resolved inventory source
    - reads workspace `Cargo.toml` manifests, including root
      `[workspace.dependencies]` used by `{ workspace = true }` member
      dependencies
    - reports direct dependency exact-pin status and whether a requirement was
      inherited from the workspace root
    - buckets non-crates.io sources separately from ordinary uncovered
      crates.io packages
    - reads `reviewed-targets.toml` when present and reports reviewed-family
      coverage, declared allowed execution surfaces, and missing review records
      as policy coverage gaps
    - reports live graph execution surfaces as `not collected` in this offline
      slice
    Missing `reviewed-targets.toml` is not an error; the report states that no
    reviewed-target policy is configured yet. Malformed `reviewed-targets.toml`,
    malformed workspace manifests, and missing or malformed `Cargo.lock` fail
    closed because inventory facts cannot be established.
    Observational findings and policy coverage gaps are informational, and the
    command returns exit 0 when it can render the report.

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
    - validates any `allowed_surfaces` entries point at crates in the same
      family `resolved` map
    - validates any `allowed_age_exceptions` entries point at crates in the
      same family `resolved` map and that the referenced resolved target
      carries `checksum_sha256`
    The first slice treats exact `Cargo.lock` parity as the load-bearing
    execution gate. It does not yet verify installed-tree or stronger
    build-input parity.
    Structured crates.io reviewed-artefact form:
    - `serde = { version = "1.0.228", checksum_sha256 = "..." }`
    - legacy string entries such as `serde = "1.0.228"` remain accepted
    - execution-surface allowances are declared separately, for example:
      `serde = ["build-rs", "proc-macro"]` under
      `[rust.families.allowed_surfaces]`
    - release-age exceptions are declared separately, for example:
      `serde = "1.0.228"` under `[rust.families.allowed_age_exceptions]`;
      they require the same family's structured `resolved` entry to carry
      `checksum_sha256`
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
    The standalone `pin-check` command skips successfully when no
    reviewed-target manifest is present or no active Rust families are
    configured. `verify` fails closed instead: build/test execution requires an
    explicit reviewed-target policy.
```

## Exit codes

- `0` — success
- `1` — blocking policy failure, such as an age-gate failure, advisory finding, disallowed source, or fail-closed inspection failure
- `2` — usage error

## Behavioural boundaries

- `crates/barbican/` owns pure policy logic and remains testable without network access.
- `crates/cargo-barbican/` owns CLI parsing, subprocess calls, and the concrete HTTP implementation.
- Where the surface overlaps undertask, behaviour should match its proven workflow unless the docs explicitly say otherwise; cargo-barbican also owns surface beyond undertask.
- The deeper intake path is now shaped as a separate `inspect` command rather than additional scope hidden inside `assess`.
- `gatehouse candidate` is a workflow-convenience layer for isolated
  candidate intake evidence. It composes existing policy/evidence primitives
  and delegated Cargo checks; it does not define new policy semantics.
- Reviewed-target enforcement has a dedicated `pin-check` surface, and `verify`
  now reuses that same gate before code-executing build/test steps. The
  foundation for that work is checked-in review records plus a repo-root
  `reviewed-targets.toml` manifest for active Rust families.
- The current reviewed-target hardening step includes crates.io
  artefact-digest reconciliation in `reviewed-targets.toml`, not a direct port
  of the JS installed-tree gate.
