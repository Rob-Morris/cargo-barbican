# CLI Contract

Current `cargo barbican` surface. This document describes the intended
behaviour of the implemented command set.

## Workspace-root anchoring

Every subcommand resolves the workspace root before doing anything else, so
commands behave identically from any directory inside a consumer repo.
For a readable, parseable nearest manifest, discovery delegates to `cargo
locate-project --workspace`, so Cargo owns membership, `[workspace].exclude`,
glob, explicit workspace-pointer, and path-normalisation semantics. A Cargo
spawn/IO failure fails closed. For `audit` only, a non-zero Cargo lookup uses
the malformed-manifest fallback so the advisory verdict still renders with
unavailable remediation context and no reviewed exceptions bound. Wherever
this contract says "repo-root", it means that discovered workspace root.

All root-anchored inputs and outputs — `barbican.toml`,
`reviewed-targets.toml`, `Cargo.lock`, `deny.toml`, workspace manifests,
review records under `docs/dependency-reviews/`, and `policy init` /
`pin add` / `pin exception` scaffold writes — resolve against the discovered
root, as do relative path arguments such as `--lockfile`, `--base-dir`, and
`--base-lockfile`.

When no `Cargo.toml` exists in the invocation directory or any parent, every
command fails closed with a `FAIL workspace root not found: ...` line on
stderr naming the discovery rule, and exits `1`. A nearest manifest that
cannot be read or parsed still anchors discovery to its own directory (or to
an enclosing `[workspace]` root); the command that actually consumes that
manifest then reports the failure through its own error or degradation path.

## Subcommands

```text
cargo barbican --version
    Print the shipped cargo-barbican version.

cargo barbican age [--min-age-days N] <crate@version>...
    Check that each crate@version was published at least N days ago
    (default 7). The default comes from `barbican.toml`
    `[release_age].minimum_days`, falling back to 7 when the file or key is
    absent. `--min-age-days` overrides the config for the current command.
    A matching reviewed release-age exception in `reviewed-targets.toml` can
    allow a too-fresh exact version when its review record is completed and its
    reviewed checksum matches the fetched crates.io artefact. Completed means a
    regular, non-symlink, non-empty record without the scaffold pending marker.
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

cargo barbican pick [--min-age-days N] <crate|crate@range>
    Discover the newest crates.io version matching a Cargo semver requirement
    while applying release-age policy. When no range is supplied, all stable
    versions are candidates. The command drops yanked versions, pre-releases,
    semver-incompatible versions, and versions below the minimum release age,
    then prints the selected exact `crate@version`.
    The excluded-candidate list itemises the policy-driven exclusions (yanked,
    pre-release, too-fresh, and malformed versions) one per line, but collapses
    the plain out-of-range versions into a single
    `N versions excluded: outside requested range` summary line, so a wide range
    such as `serde@^1` does not bury the policy-relevant exclusions under one
    line per non-matching version.
    When `--min-age-days` is absent, the command uses the same
    `barbican.toml` release-age default as `age`.
    Reviewed release-age exceptions are honoured through the same shared
    release-age policy path as `age`.
    Pure HTTP GET to the crates.io API.

cargo barbican resolve [--min-age-days N]
    1. Snapshot the current `Cargo.lock`.
    2. Run `cargo generate-lockfile` against the current manifests.
    3. Recheck newly selected crates.io versions against the pre-resolve
       `Cargo.lock` snapshot.
    4. Restore the original `Cargo.lock` and exit 1 if any newly selected
       crates.io version is too fresh, yanked, or otherwise violates release-age
       policy.
    When `--min-age-days` is absent, the command uses the same
    `barbican.toml` release-age default as `age`.
    The post-resolution lockfile recheck honours the same reviewed release-age
    exceptions as `age`.

cargo barbican update [--dry-run] [--min-age-days N] <crate@version>...
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
    honour the same reviewed release-age exceptions. They are printed as two
    distinctly labelled phases so the pre-update candidate check and the
    post-update recheck read as two phases rather than a repeated line.

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
    Matching reviewed execution-surface allowances are rendered in the same
    `Allowed policy exceptions:` section and do not contribute to the
    `elevated-risk` classification by themselves. The matching family
    `review_record` must exist before `assess` trusts the allowance.
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
    surfaces are `elevated-risk`.
    The first slice is fail-closed for routine intake: any non-routine result
    returns exit 1.
    On a `policy-violating` verdict the report adds a `verdict basis:` line
    naming which evidence drove it — the release-age gate, a checksum mismatch,
    the IOC hits, or inspection failures. When IOC hits drove it, it also prints
    reviewed-family remediation: review the flagged execution surface in the
    crate source and, if it is acceptable, record the crate in a reviewed family
    with an `allowed_surfaces` allowance so the repo intake gate (`assess`,
    `pin check`, `verify`) admits the surface. Recording does not change what
    `inspect` reports, which stays fail-closed and never consults allowances.
    The remediation points at `cargo barbican pin add`, at
    `docs/user/configuration.md` for the `allowed_surfaces` mechanism, and at
    `gatehouse candidate` for a fuller dossier. A checksum mismatch, yanked or
    too-fresh release, or inspection failure prints the `verdict basis:` line
    without that remediation, since `allowed_surfaces` cannot address them.
    When `--min-age-days` is absent, the command uses the same
    `barbican.toml` release-age default as `age`.
    Matching reviewed release-age exceptions are rendered visibly in the
    release-age line. They can only allow too-fresh releases; yanked releases
    and checksum mismatches remain `policy-violating`.
    Unlike `assess`, `inspect` does not consult reviewed execution-surface
    allowances: its verdict is fail-closed and never suppressed by an
    `allowed_surfaces` entry.

cargo barbican gatehouse pre-release
    Run the standard pre-release supply-chain workflow over the current Rust
    workspace. The workflow is fail-fast and runs, in order:
    - exact `rust-toolchain.toml` and active toolchain conformance
    - `inventory --enforce`, as the blocking direct-dependency coverage floor
    - `audit`, as a blocking advisory and source-policy gate
    - `verify`, as the blocking reviewed-target, locked-build, and locked-test gate
    Missing or floating toolchain policy, higher-precedence toolchain
    executable controls, unverifiable rustup/Cargo/rustc/rustdoc facts, uncovered direct
    dependencies, external direct sources, unavailable exact
    graph facts, or missing reviewed policy stop before audit. Uncovered
    transitive packages and undeclared execution surfaces remain labelled
    observational backlog. `verify` includes the default `pin check`, so the
    workflow does not run a duplicate pin-check step. The base commands retain
    their existing policy semantics and output. The workflow adds no exceptions
    or policy configuration. Success ends with `Gatehouse pre-release: PASS`.

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
    checksum mismatches remain blocking. A `policy-violating` inspect verdict
    carries the same `verdict basis:` line and reviewed-family remediation into
    the dossier, minus the self-referential pointer back to `gatehouse
    candidate`.
    The sandbox is removed by default. `--preserve-sandbox` keeps it for
    manual inspection and prints the sandbox path. Any failed required evidence
    step returns exit 1 after rendering the failure in the dossier.

cargo barbican policy init [--toolchain <exact-channel>] [--ci <system>]
    Create the explicit policy scaffold for adopting cargo-barbican in a repo.
    The first slice creates missing:
    - `barbican.toml`
    - `deny.toml`
    - `reviewed-targets.toml`
    - `docs/dependency-reviews/`
    - `docs/dependency-reviews/README.md`
    - `rust-toolchain.toml`, only when absent and `--toolchain` supplies an
      exact full release, numbered beta prerelease, or dated nightly; the
      generated file uses rustup's `minimal` profile and reports that choice
    `deny.toml` carries a normal `[advisories]` table for direct cargo-deny use
    plus the preserved bans and sources posture. `cargo barbican audit` still
    owns advisory disclosure at runtime: it forces maximum disclosure when
    invoking cargo-deny and treats native ignores only as compatibility input,
    never as authorisation.
    It does not create active reviewed families, dependency review records, or
    inventory reports.
    Existing regular files are preserved. Existing `barbican.toml` is read
    and validated. Existing `rust-toolchain.toml` is validated and preserved;
    missing, floating, path-based, legacy-shadowed, or conflicting toolchain
    policy blocks that item and blocks CI workflow creation. Malformed config fails before dependent scaffold files are
    created. Symlinks, directories, and other wrong-type paths at scaffold
    locations or existing scaffold ancestors fail closed rather than being
    followed or overwritten.
    `--ci <system>` additionally emits a ready-to-run CI enforcement workflow.
    The only supported value is `github`, which writes
    `.github/workflows/barbican.yml`: a workflow that installs cargo-barbican,
    cargo-deny, and cargo-audit with `--locked`, pins its third-party actions
    by full commit SHA, fetches the locked dependency graph for every target
    platform (`cargo fetch --locked` with no `--target`, because the gate
    resolves frozen cross-platform cargo metadata and would otherwise fail on
    a runner cache missing other platforms' crates), and runs the gate —
    `cargo barbican gatehouse pre-release`, plus `cargo barbican age-lock` and
    `cargo barbican assess` against the pull-request base. This flag is
    independent of the base scaffold above and of `barbican.toml` validity.
    Unlike the idempotent base scaffold, an existing
    `.github/workflows/barbican.yml` is not overwritten: the command fails
    closed (exit 1), reports the path as blocked, and re-prints the intended
    workflow contents so the difference can be reconciled by hand. Wrong-type
    paths at the workflow location fail closed the same way as other scaffold
    paths.
    For Windows, see the project-level Platform Support posture in
    `docs/architecture/overview.md`; until full Windows support lands, run
    from trusted checkouts without junctions in scaffold paths.
    The command prints an action report and next-step guidance pointing to
    the manual adoption guide, offering the CI enforcement workflow (or
    confirming it when `--ci` wrote one), and offering the advisory
    client-side pre-commit hook shipped at `templates/hooks/pre-commit`
    (installable via `git config core.hooksPath` or by copying it into
    `.git/hooks/pre-commit`), which runs the cheap `pin check` and
    `inventory --enforce` subset and is skippable with `git commit
    --no-verify`.

cargo barbican inventory [--enforce]
    Print a read-only, whole-repo dependency inventory and policy-coverage
    audit. It:
    - reads `Cargo.lock` as the resolved inventory source; Cargo lockfile
      formats V2 through V4 are supported, while legacy V1 `[root]` lockfiles
      or V1 `[metadata]` checksum tables and unknown newer format versions
      fail closed
    - reads workspace `Cargo.toml` manifests, including root
      `[workspace.dependencies]` used by `{ workspace = true }` member
      dependencies
    - runs `cargo metadata --format-version 1 --frozen` once to collect Cargo's
      parsed direct-dependency declarations and live graph execution surfaces;
      direct declarations are resolved through the workspace packages' exact
      `Cargo.lock` dependency edges without rewriting the lockfile
    - reports direct dependency exact-pin status and whether a requirement was
      inherited from the workspace root
    - buckets non-crates.io sources separately from ordinary uncovered
      crates.io packages
    - reads `reviewed-targets.toml` when present and reports reviewed-family
      coverage, declared allowed execution surfaces, and incomplete review records
      as policy coverage gaps
    - reports live graph execution surfaces as declared or undeclared against
      the checked-in `allowed_surfaces` policy
    - reports reviewed advisory exceptions with status active, soon-to-expire,
      expired, or stale, and separately reports each exception's binding state
      against the current lockfile (`resolved-target` matched or not matched)
      and review record (completed or not completed)
    - reports advisory delegation config: selected lockfile scanner, the
      resolved `cargo-deny` check set with its source (an explicit
      `delegates.cargo_deny.checks` list, or the presence-driven default),
      the licences posture (enforced, skipped, or disabled, with the reason),
      unmanaged delegated-ignore policy, native advisory ignores in
      `deny.toml` / `.cargo/audit.toml`, and whether `cargo-deny` would use a
      checked-in `deny.toml` or Barbican's generated default base for
      non-advisory posture
    Missing `reviewed-targets.toml` is not an error; the report states that no
    reviewed-target policy is configured yet. Malformed `reviewed-targets.toml`,
    malformed workspace manifests, and missing or malformed `Cargo.lock` fail
    closed because inventory facts cannot be established.
    If frozen cargo metadata cannot be collected, the command still renders the
    offline inventory sections and marks live graph surfaces and exact direct
    package identities as not collected. Uncovered crates.io packages and
    non-crates.io sources are then labelled unclassified rather than asserted
    to be direct, transitive, enforced, or observational.
    The summary labels the direct-dependency coverage-floor readiness,
    uncovered direct and external direct blockers, observational uncovered
    transitive backlog, observational undeclared execution surfaces, and other
    findings separately. The detailed reviewed-policy section explains which
    sibling gate owns each category. In the default mode (no `--enforce`), the
    report is informational and returns exit 0 whenever it can render; this is
    an audit view, not an enforcement gate.
    `--enforce` applies a coverage-floor gate on top of the same report. The
    coverage floor is the minimum bar for adoption: every direct dependency
    must be covered by an active reviewed family — the shape a raw
    `cargo add <crate>` breaks, since it pulls an unreviewed crate straight
    into the graph. The gate fails closed (exit 1) when any of the following
    hold:
    - no `reviewed-targets.toml` policy is configured (nothing can be covered);
    - exact direct-package facts could not be collected;
    - a crates.io direct dependency has entered the graph without an active
      reviewed family covering its exact resolved crate;
    - a direct dependency resolves through a non-crates.io source a crates.io
      reviewed family can never cover — a git dependency, an alternate
      registry, or a path outside the workspace. First-party workspace-member
      path dependencies are not flagged.
    On a failure the appended coverage-floor section names each offending crate:
    an uncovered crates.io crate points at `cargo barbican pin add <crate>`; a
    non-crates.io direct dependency is named with its source and must be
    reviewed and pinned to crates.io or removed.
    Cargo's parsed declarations plus exact lockfile edges make this
    version-precise and immune to manifest renames: optional dependencies and
    normal, development, build, and target-specific declarations are gated,
    while an uncovered same-name transitive version remains observational.
    Declared execution
    surfaces (build.rs / proc-macro / native-sys) are not gated — undeclared
    live surfaces remain observationally reported above.
    Reviewed-record completeness is not part of this floor either; `pin check`
    owns that gate, and the shipped CI and pre-commit templates run both
    `pin check` and `inventory --enforce`. `--enforce` does not change any of
    the report body above it, so the default output is unchanged when the flag
    is absent.

cargo barbican pin add <crate>[@version]
    Scaffold a reviewed-target family and review-record stub for one crate
    already resolved in `Cargo.lock`, fully offline. It:
    - reads the resolved version and `checksum_sha256` from `Cargo.lock`
      (no crates.io fetch)
    - appends a `[[rust.families]]` stub to the repo-root
      `reviewed-targets.toml`: family name, review-record path, and a
      `[rust.families.resolved]` entry with the resolved version and, when
      present in `Cargo.lock`, the checksum
    - includes a `[rust.families.direct]` entry only when the crate is a
      direct dependency and every observed manifest requirement is already the
      exact `=version` pin from a source kind the direct gate enforces —
      exactly the condition under which the scaffolded direct check passes;
      otherwise a note reports why no direct entry was scaffolded
    - creates a review-record markdown stub under `docs/dependency-reviews/`
      pre-filled with the resolved facts and the required record sections
    - prints next steps (complete the record, then run `pin check`)
    The family name and record filename derive from the crate name and the
    current UTC date, matching the record naming convention.
    The version component may be omitted when the crate resolves to exactly
    one version; multiple resolved versions require an exact `crate@version`.
    Fail-closed: exits 1 without mutating anything when the crate or requested
    version is not in `Cargo.lock`, when `reviewed-targets.toml` is absent
    (adopters run `policy init` first), when the crate is already covered by
    an existing reviewed family, when the scaffold family name already exists,
    or when the review-record path already exists. Scaffold writes follow the
    same wrong-type/symlink containment posture as `policy init`, and the
    appended policy text is re-parsed before it is written.
    The scaffold registers the family in `reviewed-targets.toml` and writes a
    review-record stub carrying the `BARBICAN-REVIEW-PENDING` marker.
    Registering the family is not passing the gate: `pin check` fails this
    family until a human reviewer completes the record and deletes the marker
    line, so scaffolding cannot silently satisfy its own gate.

cargo barbican pin exception <crate>[@version] <advisory-id>... [--review-by YYYY-MM-DD]
    Scaffold the governed acceptance of one or more RustSec advisories for a
    crate already resolved in `Cargo.lock`, fully offline. This is the
    audit-side parallel to `pin add`: the governed way to accept an advisory
    finding should be at least as easy as an ungoverned `deny.toml` ignore,
    while staying bounded and evidence-backed. It:
    - validates each advisory id against the RUSTSEC-YYYY-NNNN form
    - reads the resolved version and `checksum_sha256` from `Cargo.lock`;
      advisory exceptions require the checksum-bound resolved form, so a
      lockfile entry without a crates.io checksum fails closed
    - appends a `[[rust.families]]` stub exactly like `pin add`, plus a
      `[rust.families.allowed_advisories]` entry binding each advisory with a
      `review_by` re-review deadline — 30 days from today by default,
      overridable with `--review-by`
    - creates a review-record markdown stub pre-filled with the accepted
      advisories alongside the resolved facts
    - prints next steps: complete the record, prefer remediation over keeping
      the exception, then run `gatehouse pre-release`
    The version component may be omitted when the crate resolves to exactly
    one version. When the crate is already covered by an active reviewed
    family, the command refuses to rewrite the existing family block and
    instead prints the exact `allowed_advisories` fragment to add manually
    plus the family's review record to update — appending TOML text cannot
    attach a sub-table to a mid-file family, and a mechanical rewrite would
    clobber policy comments.
    Fail-closed: exits 1 without mutating anything on an invalid advisory id
    or `--review-by` date, a crate or version missing from `Cargo.lock`, a
    checksumless lockfile entry, an advisory already allowed by a reviewed
    family, a covered family whose resolved version drifts from `Cargo.lock`,
    a covered version-only entry without a checksum, a family-name or
    record-path collision, or when `reviewed-targets.toml` is absent
    (adopters run `policy init` first). Scaffold writes follow the same
    wrong-type/symlink containment posture as `pin add`, and the appended
    policy text is re-parsed before it is written.
    The scaffolded review-record stub carries the `BARBICAN-REVIEW-PENDING`
    marker, and both `pin check` and `audit` reject the family — audit
    reporting the finding as unreviewed — until a human reviewer completes the
    record and deletes the marker line. Even once completed, `audit` fails the
    exception again after `review_by` passes.

cargo barbican pin check [--config reviewed-targets.toml]
    Check active reviewed Rust families against the current workspace manifests
    and `Cargo.lock`.
    The first slice is local-only and read-only. It:
    - reads the repo-root `reviewed-targets.toml` manifest by default
    - skips successfully when that file is absent
    - skips successfully when no active Rust families are configured
    - checks that each active `review_record` path resolves to a completed
      review: a regular non-symlink file that is non-empty and no longer
      carries the scaffold marker `BARBICAN-REVIEW-PENDING`. A missing,
      empty/whitespace-only, or still-marked scaffold record fails closed,
      naming the family, the record file, and — for a scaffold stub — the
      marker, so an unfinished `pin add` / `pin exception` scaffold cannot
      satisfy the gate it was written to prepare
    - checks optional exact direct manifest requirements, including the leading `=`
    - checks exact resolved `Cargo.lock` versions for every active reviewed family
    - for every `Cargo.lock` entry whose name matches a reviewed family's
      resolved crate, requires a crates.io source; a git, path, alternate-registry,
      or sourceless (workspace/path member) entry is a blocking mismatch, even
      when another entry for the same name and version carries the expected
      crates.io source and checksum — this closes a doppelgaenger hole where a
      second, non-crates.io locked entry for a reviewed crate name previously
      went unnoticed
    - for structured crates.io `resolved` entries, also checks the reviewed
      `checksum_sha256` against the resolved `Cargo.lock` checksum chain; a
      matching-version `Cargo.lock` entry with no checksum is a distinct
      mismatching observation, not an absent one, and fails the check even if
      another entry for the same name and version carries the expected checksum
    - validates any `allowed_surfaces` entries point at crates in the same
      family `resolved` map
    - validates any `allowed_age_exceptions` entries point at crates in the
      same family `resolved` map and that the referenced resolved target
      carries `checksum_sha256`
    - fails closed when any workspace manifest `[patch]` table (under any
      registry key, for example `[patch.crates-io]`) targets a crate name
      covered by an active reviewed family's `resolved` or `direct` map, since
      a patch repoints an already-reviewed crate at a different source without
      touching `Cargo.lock`
    - fails closed when any effective `.cargo/config` or `.cargo/config.toml`
      from the workspace root, its ancestors, or Cargo home includes indirect
      configuration, declares a
      `[source]` table, a config-defined `[patch]` table (stable since Rust
      1.56, works exactly like a manifest `[patch]`), or a top-level `paths`
      dependency override, while any reviewed family is active, since each of
      these can or may repoint a reviewed crate name away from
      crates.io — or substitute local source code for it, with `Cargo.lock`
      keeping its crates.io source and checksum — without any change to
      `Cargo.toml` or `Cargo.lock`; repository and ancestor config symlinks are
      refused, while a Cargo-home config symlink is inspected when Cargo home
      and its target both resolve outside the workspace, and the target is a
      readable regular file
    The first slice treats exact `Cargo.lock` parity as the load-bearing
    execution gate. It does not yet verify installed-tree or stronger
    build-input parity.
    Structured crates.io reviewed-artefact form:
    - `serde = { version = "1.0.228", checksum_sha256 = "..." }`
    - legacy string entries such as `serde = "1.0.228"` remain accepted; both
      forms now require every matching `Cargo.lock` entry to be crates.io
      sourced, but only the structured form binds the resolved artefact
      checksum — the structured form is the stronger guarantee and is
      recommended
    - execution-surface allowances are declared separately, for example:
      `serde = ["build-rs", "proc-macro"]` under
      `[rust.families.allowed_surfaces]`
    - release-age exceptions are declared separately, for example:
      `serde = "1.0.228"` under `[rust.families.allowed_age_exceptions]`;
      they require the same family's structured `resolved` entry to carry
      `checksum_sha256`
    - stronger installed-tree or broader non-crates.io artefact parity remains
      out of scope for this slice; `[replace]` manifest tables are also out of
      scope and are not yet detected

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
    On the default git-backed path, `review` also lists any untracked
    policy-relevant files that git is not tracking yet — for example a freshly
    scaffolded `barbican.toml`, `reviewed-targets.toml`, or new review record
    during adoption — so files absent from the tracked diff stay visible. This
    is a visibility note only: it does not change what `review` counts as a
    tracked change or the command's exit code. The `--base-dir` path does not
    emit the note, since a new file there already appears as an added-file diff.

cargo barbican audit [--format text|json]
    Enumerate the complete advisory finding set from the configured
    scanner(s) (`cargo-deny` and/or `cargo-audit`) with native advisory
    ignores neutralised, reconcile each finding against reviewed advisory
    exceptions, and compute a Barbican-owned verdict. Fail on any unreviewed
    or expired advisory finding, any non-advisory scanner error
    (`cargo-deny` bans/sources/licenses), incomplete enumeration, or — when
    `delegates.unmanaged_delegated_policy = "deny"` — any unmanaged native
    delegated advisory ignore. A native ID is rendered as governed only when
    every current occurrence is accepted by active Barbican governance;
    accepted exceptions and all native delegated ignores remain visible.

    Native ignores are compatibility input, never authorisation: for an
    unchanged graph and Barbican policy, adding an ID to a native ignore list
    cannot change the Barbican verdict from failure to success.

    When `delegates.cargo_deny.checks` is unset, the `cargo-deny` check set
    is presence-driven: `advisories`, `bans`, and `sources` always run, and
    `licenses` joins them whenever the checked-in `deny.toml` declares a
    `[licenses]` policy — a checked-in licence policy is expressed intent to
    enforce it. An explicit `checks` list is authoritative in both
    directions. Both report formats always state the resulting licences
    posture (`enforced`, `skipped`, or `disabled`, with the reason), so the
    effective state is never invisible.

    Before delegating, `audit` checks that each required scanner binary is on
    `PATH` (`cargo-deny` always; `cargo-audit` only when it is the configured
    lockfile scanner). A missing binary fails closed with an actionable
    `FAIL <tool>: not found on PATH; install with <install command>` line on
    stderr and no report body, in both text and JSON mode. If a delegate is
    present but its run fails, `audit` surfaces the delegate's exit status and
    a stderr excerpt (`FAIL <tool>: exited with status <code>; stderr: ...`)
    rather than a JSON-parse error. These `FAIL` diagnostics are fail-closed
    messages on stderr, not stable parse targets.

    The default `--format text` report is human-oriented. When scanner output
    carries advisory metadata, finding lines include the advisory title, risk
    label, and patched-version ranges. When frozen Cargo metadata can be
    collected, unaccepted findings also include the shortest dependency path
    from a workspace member to the affected package. Unreviewed and expired
    findings with patched-version ranges also include a read-only remediation
    hint. A manifest requirement only classifies a finding as direct when it
    can admit the finding's resolved version, so a vulnerable duplicate
    version capped by a parent is treated as transitive rather than pointed
    at the safe direct copy.
    When frozen Cargo metadata is available, classification is
    metadata-first: a workspace-member edge onto the exact vulnerable package
    in the resolve graph decides the direct case, which is version-precise
    and immune to manifest rename and duplicate-version blindness.
    Direct non-exact dependencies get a `cargo barbican update <crate>@<version>`
    template plus a `pick` pointer for selecting a patched release; direct
    exact `=` pins are reported as manifest edits because lockfile-only
    updates cannot move them.
    For transitive findings, `audit` reads the declared requirement edges
    from cargo metadata (`packages[].dependencies[].req`) across all resolved
    parents — not only the shortest-path parent — and decides by exact
    semver-interval overlap whether any parent provably caps the patched
    range:
    - provably capped findings name each blocking parent and its requirement
      ("capped by plist@1.9.0 (requires ^0.39)") and direct the fix at the
      blocker — a manifest edit when the blocker is exact-pinned, an `update`
      otherwise;
    - provably uncapped findings report that the vulnerable crate itself can
      move with a lockfile-only `cargo barbican update`;
    - anything indeterminate (pre-release comparators, unparseable
      requirements, resolve edges without a matching declaration, or missing
      metadata) keeps the conservative nearest-parent hedge rather than
      guessing.
    These hints do not mutate the repo and must be verified with `--dry-run`.
    Remediation hints are best-effort enrichment: when workspace manifests
    cannot be read or parsed, the hints are omitted, a `note:` diagnostic is
    written to stderr, and the report and verdict still render.
    Unreviewed findings with RustSec-form ids also carry a
    `governed exception:` pointer to `cargo barbican pin exception`, rendered
    after the remediation hint so the governed acceptance path is as
    discoverable as a native `deny.toml` ignore without outranking the fix.

    `--format json` emits a stable JSON report on stdout with
    `schema_version`, `status`, `success`, structured advisory `findings`,
    scanner completeness failures, delegated scanner diagnostics, native
    delegated ignores, patched-version ranges, optional dependency paths, and
    per-finding remediation objects when a read-only suggestion is available.

cargo barbican verify
    Run the local execution gates in order:
    1. exact `rust-toolchain.toml` and active toolchain conformance
    2. `pin check` with the default repo-root `reviewed-targets.toml`
    3. `cargo build --locked`
    4. `cargo test --locked`
    The standalone `pin check` command skips successfully when no
    reviewed-target manifest is present or no active Rust families are
    configured. `verify` fails closed in both cases: build/test execution
    requires an explicit reviewed-target policy with at least one active
    reviewed family.
    The toolchain step establishes Rust toolchain executable identity, not
    binary provenance or a sandbox for Cargo's wider execution surface.
    `RUSTUP_HOME` may select the rustup installation tree, and target runners,
    linkers, rustflags, and Cargo `[env]` settings remain ordinary inputs to
    the subsequent build/test delegates.
    On success, `verify` confirms each executed step explicitly
    (`OK   cargo build --locked`, `OK   cargo test --locked`) and ends with
    `Verify: PASS`, so a passing gate is distinguishable from a skipped one.
    The build and test delegates stream their output to the terminal while
    they run, with stdout inherited directly and each stderr line carrying a
    `delegate stderr: ` prefix. That output is delegate evidence, not part of
    the report body, and is not a stable parse target. Delegate stdin is
    closed. When a delegate fails, the terminal failure line on stderr
    carries only the delegate's exit status — the delegate's own output has
    already streamed above it.
```

`<crate@version>` candidate specs are exact crates.io package specs. A single
optional leading `=` on the version is accepted for CLI ergonomics:
`crate@=1.2.3` is normalised to `crate@1.2.3`. Version ranges such as
`crate@^1`, `crate@>=1`, `crate@=^1`, and wildcard specs remain invalid.

## Exit codes

- `0` — success
- `1` — blocking policy failure, such as an age-gate failure, advisory finding, disallowed source, or fail-closed inspection failure
- `2` — usage error

## Policy provenance and environment inputs

Two ways of overriding release-age policy announce themselves on stdout so a
CI log records that the configured policy was not the one actually applied:

- When `--min-age-days N` sets an effective minimum that differs from the
  configured value (or the built-in default of 7 when `barbican.toml` is
  absent), the release-age-aware commands (`age`, `age-lock`, `pick`,
  `resolve`, `update`, `inspect`) print
  `note: release-age minimum overridden to N days via --min-age-days (configured M)`.
  No note is printed when there is no override or the override matches the
  configured value.
- The `CARGO_BARBICAN_CRATES_IO_BASE_URL` environment variable redirects the
  crates.io endpoint the release-age evidence is fetched from (it must be an
  `https://` URL or a loopback `http://` URL; it exists primarily as a test
  seam). HTTPS endpoints remain HTTPS-only across redirects; the loopback HTTP
  test seam is the only mode that permits plain-HTTP transport. When it is set
  to anything other than the default endpoint, the tool
  prints `note: crates.io source overridden to <url> via CARGO_BARBICAN_CRATES_IO_BASE_URL`
  before running the command.

Both notes are diagnostic and non-stable (see below); match on the stable
tokens and exit codes, not on this text.

## Output-stability contract

Exit codes (above) and the following terminal tokens on stdout are stable
parse targets. A script or CI step may match on these literal strings; a
future change to the wording of any of them is a breaking change to the CLI
contract, not a routine rewording.

- `Pin check: PASS` / `Pin check: FAIL` — printed by `pin check` (and reused
  by `verify`, which calls the same reviewed-target check before its build
  and test steps)
- `Audit: PASS` / `Audit: FAIL` — printed by `audit`
  when `--format text` is selected
- `Inventory: PASS (direct-dependency coverage floor)` / `Inventory: FAIL
  (direct-dependency coverage floor)` — printed whenever inventory coverage
  enforcement is active: standalone `inventory --enforce` or the first step of
  `gatehouse pre-release`. Plain `inventory` never prints an `Inventory:` line
  and always exits 0.
- `cargo barbican audit --format json` emits a stable JSON report on stdout.
  Its top-level `schema_version` identifies the JSON contract version. Adding,
  removing, or renaming fields, changing field meaning, or changing existing
  field types requires a new `schema_version`. In schema version `5`,
  consumers may rely on the top-level `schema_version`, `status` (`"pass"` or
  `"fail"`), `success`, `dependency_paths_available`,
  `remediations_available`, `findings`, `completeness_failures`,
  `cargo_deny`, `cargo_audit`, and `native_delegated_ignores` fields, plus
  each finding's advisory id, package object, disposition (`"accepted"`,
  `"expired"`, or `"unreviewed"`), title/risk/severity metadata, nullable
  `cvss` and `informational` strings, patched ranges, dependency path,
  reviewed-exception object, remediation object, and `governed_exception` —
  `null`, or an object with a `command_hint` string for the `pin exception`
  scaffolder on unreviewed findings with RustSec-form ids.
  Each `native_delegated_ignores` entry carries its original `advisory_ids`
  plus `governed_advisory_ids` and `unmanaged_advisory_ids`; only the latter
  are subject to the reported `policy`. Schema version `4` added
  `cargo_deny.licenses`: an object with `posture`
  (`"enforced"`, `"skipped"`, or `"disabled"`) and `reason`
  (`"deny-toml-policy"`, `"explicit-checks"`, or `"no-deny-toml-policy"`)
  reporting whether the `cargo-deny` licenses check ran and why.
  `remediation` is either `null` or an object with `kind`, `patched`,
  `target_crate`, `nearest_parent`, `command_hint`, and `blockers`.
  `target_crate` is the crate the suggested action applies to: the vulnerable
  crate itself for the direct kinds and for `transitive-update`, the blocking
  parent for capped transitive findings, or the nearest parent for hedged
  transitive hints. The stable remediation kinds are `direct-pinned-edit`,
  `direct-update`, `transitive-update`, and `transitive-bump`.
  `blockers` is `null` when the requirement-edge analysis could not run or
  was indeterminate, `[]` when it proved no parent caps the patched range,
  and otherwise a list of `{crate, version, requirement}` objects naming each
  resolved parent whose declared requirement provably excludes every patched
  range. `command_hint` is a template with `<version>` when an update target
  is known; it is `null` for exact-pin manifest edits (including exact-pinned
  blockers) and for generic transitive hints where no parent dependency path
  was available.
- `Toolchain check: PASS` / `Toolchain check: FAIL` — printed by the
  toolchain preflight used by standalone `verify` and `gatehouse pre-release`.
- `Gatehouse pre-release: PASS` / `Gatehouse pre-release: FAIL (toolchain)` / `Gatehouse pre-release: FAIL (inventory)` /
  `Gatehouse pre-release: FAIL (audit)` / `Gatehouse pre-release: FAIL (verify)` — printed by `gatehouse pre-release`
  after its blocking primitives pass or fail. Operational errors that prevent
  a primitive from producing a verdict use the ordinary stderr `FAIL` contract.
- `Verify: PASS` — printed by `verify` on success; there is no matching
  `Verify: FAIL` token. A failing `verify` run stops at the failing step
  (`pin check`, `cargo build --locked`, or `cargo test --locked`), reports the
  failure through that step's own output — `Toolchain check: FAIL` or `Pin
  check: FAIL` on stdout for a
  reviewed-target failure, or a build/test error on stderr — and exits `1`
  without printing a `Verify:` line at all.

During `verify`'s build and test steps, dependency-controlled delegate output
shares stdout with the stable tokens. Consumers must therefore accept a token
as a verdict only together with the command's exit code; stdout text alone is
not authoritative.

All other output — evidence reports, dossiers, inventory findings, review
diffs, and human-oriented notes such as `verify`'s scope-honesty pointer to
`audit`, `inspect`'s `verdict basis:` line and reviewed-family remediation
guidance, and the release-age override and `CARGO_BARBICAN_CRATES_IO_BASE_URL`
provenance notes — is not a stable parse target and may change wording or
formatting between versions. Match on the tokens and JSON schema above and the
exit code, not on other output text.

## Stream discipline

Every command follows one rule for where output goes:

- **stdout** carries reports and evidence: structured findings, dossiers, and
  every per-finding detail line that is part of a report body, including
  lines that themselves start with `FAIL` or `OK` — for example, the
  per-finding lines inside `audit`, `pin check`, and `gatehouse candidate`
  reports, and the per-candidate release-age lines `age`, `age-lock`,
  `inspect`, and `assess` print for each spec or finding they evaluate. These
  lines are evidence, not the terminal failure signal, and are covered by the
  output-stability contract above only where explicitly listed.
- **stderr** also carries non-failure `note:` diagnostics when best-effort
  report enrichment degrades — for example `audit`'s dependency-path and
  remediation context notes — so a missing enrichment stays visible without
  entering the stdout report body or changing the verdict.
- **Streaming delegates are the one exception to captured execution:**
  `verify`'s `cargo build --locked` and `cargo test --locked` steps inherit
  terminal stdout and relay each stderr line with a `delegate stderr: `
  prefix while they run. Stdin is closed so a delegate cannot block on or
  consume operator input. Streamed output is non-stable delegate evidence;
  the distinguishing stderr prefix reserves line-leading `FAIL ` for the
  terminal failure rendered by cargo-barbican, which carries the delegate's
  exit status.
- **stderr** carries the terminal failure line and every propagated error.
  Any `CommandError` that reaches the top of a command — a missing or
  malformed input file, a failed `git`/`cargo` subprocess, an invalid
  environment variable, or any other internal failure a command does not
  render itself — is rendered by one central renderer as a single
  `FAIL <detail>` line on stderr. Commands that choose to report a blocking
  condition directly, without a stdout report body (invalid candidate specs,
  release-age gate failures reported outside a report, fetch failures), also
  write their `FAIL` line to stderr, matching the same stream.

Because every failure path funnels through that one renderer (or writes to
stderr directly using the same `FAIL` token), grepping stderr for
line-leading `^FAIL ` reliably surfaces every failure, not just the ones a
given command happened to render itself. The renderer also escapes the detail
through the same terminal-injection guard used for evidence fields — untrusted
crate names, requirements, network-sourced strings, and policy file paths
cannot inject ANSI or bidi control sequences into the terminal — and never
changes the exit code: a propagated error still exits `1`.

## Behavioural boundaries

- `crates/barbican/` owns pure policy logic and remains testable without network access.
- `crates/cargo-barbican/` owns CLI parsing, subprocess calls, and the concrete HTTP implementation.
- The command surface is a single versioned contract in its own right; this document is authoritative for its behaviour.
- The deeper intake path is now shaped as a separate `inspect` command rather than additional scope hidden inside `assess`.
- `gatehouse candidate` and `gatehouse pre-release` are workflow-convenience
  layers. They compose existing policy/evidence primitives and delegated Cargo
  checks; they do not define new policy semantics.
- Reviewed-target enforcement has a dedicated `pin check` surface, and `verify`
  now reuses that same gate before code-executing build/test steps. The
  foundation for that work is checked-in review records plus a repo-root
  `reviewed-targets.toml` manifest for active Rust families.
- The current reviewed-target hardening step includes crates.io
  artefact-digest reconciliation in `reviewed-targets.toml`, not a direct port
  of the JS installed-tree gate.
