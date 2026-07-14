# CLI Contract

Current `cargo barbican` surface. This document describes the intended
behaviour of the implemented command set.

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

cargo barbican pick [--min-age-days N] <crate|crate@range>
    Discover the newest crates.io version matching a Cargo semver requirement
    while applying release-age policy. When no range is supplied, all stable
    versions are candidates. The command drops yanked versions, pre-releases,
    semver-incompatible versions, and versions below the minimum release age,
    then prints the selected exact `crate@version`.
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
    - `deny.toml`
    - `reviewed-targets.toml`
    - `docs/dependency-reviews/`
    - `docs/dependency-reviews/README.md`
    `deny.toml` carries the preserved non-advisory `cargo-deny` posture for
    bans and sources. It deliberately contains no `[advisories]` section:
    `cargo barbican audit` owns advisory disclosure at runtime and forces that
    section when invoking `cargo-deny`.
    It does not create active reviewed families, dependency review records, or
    inventory reports.
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
    audit. It:
    - reads `Cargo.lock` as the resolved inventory source
    - reads workspace `Cargo.toml` manifests, including root
      `[workspace.dependencies]` used by `{ workspace = true }` member
      dependencies
    - runs `cargo metadata --format-version 1 --frozen` once to collect live
      graph execution surfaces without resolving or rewriting the lockfile
    - reports direct dependency exact-pin status and whether a requirement was
      inherited from the workspace root
    - buckets non-crates.io sources separately from ordinary uncovered
      crates.io packages
    - reads `reviewed-targets.toml` when present and reports reviewed-family
      coverage, declared allowed execution surfaces, and missing review records
      as policy coverage gaps
    - reports live graph execution surfaces as declared or undeclared against
      the checked-in `allowed_surfaces` policy
    - reports reviewed advisory exceptions with status active, soon-to-expire,
      expired, or stale, and separately reports each exception's binding state
      against the current lockfile (`resolved-target` matched or not matched)
      and review record (exists or missing)
    - reports advisory delegation config: selected lockfile scanner,
      configured `cargo-deny` checks, unmanaged delegated-ignore policy,
      native advisory ignores in `deny.toml` / `.cargo/audit.toml`, and whether
      `cargo-deny` would use a checked-in `deny.toml` or Barbican's generated
      default base for non-advisory posture
    Missing `reviewed-targets.toml` is not an error; the report states that no
    reviewed-target policy is configured yet. Malformed `reviewed-targets.toml`,
    malformed workspace manifests, and missing or malformed `Cargo.lock` fail
    closed because inventory facts cannot be established.
    If frozen cargo metadata cannot be collected, the command still renders the
    offline inventory sections and marks live graph surfaces as not collected.
    Observational findings and policy coverage gaps are informational, and the
    command returns exit 0 when it can render the report.

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
    The scaffold activates the family for `pin check` but is not a completed
    review; the record stub must be completed by a human reviewer.

cargo barbican pin check [--config reviewed-targets.toml]
    Check active reviewed Rust families against the current workspace manifests
    and `Cargo.lock`.
    The first slice is local-only and read-only. It:
    - reads the repo-root `reviewed-targets.toml` manifest by default
    - skips successfully when that file is absent
    - skips successfully when no active Rust families are configured
    - checks that each active `review_record` path exists in the repo
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
    - fails closed when a repo-root `.cargo/config.toml` (or legacy
      `.cargo/config`) declares a `[source]` table, a config-defined `[patch]`
      table (stable since Rust 1.56, works exactly like a manifest `[patch]`),
      or a top-level `paths` dependency override, while any reviewed family is
      active, since each of these can repoint a reviewed crate name away from
      crates.io — or substitute local source code for it, with `Cargo.lock`
      keeping its crates.io source and checksum — without any change to
      `Cargo.toml` or `Cargo.lock`; this check only reads the repo-root file —
      hierarchical cargo config in parent directories or `CARGO_HOME` is a
      documented residual boundary, not inspected
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

cargo barbican audit [--format text|json]
    Enumerate the complete advisory finding set from the configured
    scanner(s) (`cargo-deny` and/or `cargo-audit`) with native advisory
    ignores neutralised, reconcile each finding against reviewed advisory
    exceptions, and compute a Barbican-owned verdict. Fail on any unreviewed
    or expired advisory finding, any non-advisory scanner error
    (`cargo-deny` bans/sources/licenses), incomplete enumeration, or — when
    `delegates.unmanaged_delegated_policy = "deny"` — any native delegated
    advisory ignore. Accepted exceptions and native delegated ignores are
    rendered.

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
    Direct non-exact dependencies get a `cargo barbican update <crate>@<version>`
    template plus a `pick` pointer for selecting a patched release; direct
    exact `=` pins are reported as manifest edits because lockfile-only
    updates cannot move them; transitive findings name the nearest parent from
    the dependency path when one is known and otherwise stay generic. These
    hints do not mutate the repo and must be verified with `--dry-run`.
    Remediation hints are best-effort enrichment: when workspace manifests
    cannot be read or parsed, the hints are omitted, a `note:` diagnostic is
    written to stderr, and the report and verdict still render.

    `--format json` emits a stable JSON report on stdout with
    `schema_version`, `status`, `success`, structured advisory `findings`,
    scanner completeness failures, delegated scanner diagnostics, native
    delegated ignores, patched-version ranges, optional dependency paths, and
    per-finding remediation objects when a read-only suggestion is available.

cargo barbican verify
    Run the local execution gates in order:
    1. `pin check` with the default repo-root `reviewed-targets.toml`
    2. `cargo build --locked`
    3. `cargo test --locked`
    The standalone `pin check` command skips successfully when no
    reviewed-target manifest is present or no active Rust families are
    configured. `verify` fails closed in both cases: build/test execution
    requires an explicit reviewed-target policy with at least one active
    reviewed family.
    On success, `verify` confirms each executed step explicitly
    (`OK   cargo build --locked`, `OK   cargo test --locked`) and ends with
    `Verify: PASS`, so a passing gate is distinguishable from a skipped one.
```

`<crate@version>` candidate specs are exact crates.io package specs. A single
optional leading `=` on the version is accepted for CLI ergonomics:
`crate@=1.2.3` is normalised to `crate@1.2.3`. Version ranges such as
`crate@^1`, `crate@>=1`, `crate@=^1`, and wildcard specs remain invalid.

## Exit codes

- `0` — success
- `1` — blocking policy failure, such as an age-gate failure, advisory finding, disallowed source, or fail-closed inspection failure
- `2` — usage error

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
- `cargo barbican audit --format json` emits a stable JSON report on stdout.
  Its top-level `schema_version` identifies the JSON contract version. Adding,
  removing, or renaming fields, changing field meaning, or changing existing
  field types requires a new `schema_version`. In schema version `2`,
  consumers may rely on the top-level `schema_version`, `status` (`"pass"` or
  `"fail"`), `success`, `dependency_paths_available`, `findings`,
  `completeness_failures`, `cargo_deny`, `cargo_audit`, and
  `native_delegated_ignores` fields, plus each finding's advisory id, package
  object, disposition (`"accepted"`, `"expired"`, or `"unreviewed"`),
  title/risk/severity metadata, nullable `cvss` and `informational` strings,
  patched ranges, dependency path, reviewed-exception object, and
  remediation object. `remediation` is either `null` or an object with
  `kind`, `patched`, `target_crate`, `nearest_parent`, and `command_hint`.
  `target_crate` is the crate the suggested action applies to: the vulnerable
  crate itself for the direct kinds and for generic transitive hints, or the
  nearest parent for parent-bump transitive hints.
  The stable remediation kinds are `direct-pinned-edit`, `direct-update`, and
  `transitive-bump`. `command_hint` is a template with `<version>` when an
  update target is known; it is `null` for exact-pin manifest edits and for
  generic transitive hints where no parent dependency path was available.
- `Verify: PASS` — printed by `verify` on success; there is no matching
  `Verify: FAIL` token. A failing `verify` run stops at the failing step
  (`pin check`, `cargo build --locked`, or `cargo test --locked`), reports the
  failure through that step's own output — `Pin check: FAIL` on stdout for a
  reviewed-target failure, or a build/test error on stderr — and exits `1`
  without printing a `Verify:` line at all.

All other output — evidence reports, dossiers, inventory findings, review
diffs, and human-oriented notes such as `verify`'s scope-honesty pointer to
`audit` — is not a stable parse target and may change wording or formatting
between versions. Match on the tokens and JSON schema above and the exit code,
not on other output text.

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
stderr directly using the same `FAIL` token), grepping stderr for `FAIL`
reliably surfaces every failure, not just the ones a given command happened
to render itself. The renderer also escapes the detail through the same
terminal-injection guard used for evidence fields — untrusted crate names,
requirements, network-sourced strings, and policy file paths cannot inject
ANSI or bidi control sequences into the terminal — and never changes the exit
code: a propagated error still exits `1`.

## Behavioural boundaries

- `crates/barbican/` owns pure policy logic and remains testable without network access.
- `crates/cargo-barbican/` owns CLI parsing, subprocess calls, and the concrete HTTP implementation.
- Where the surface overlaps undertask, behaviour should match its proven workflow unless the docs explicitly say otherwise; cargo-barbican also owns surface beyond undertask.
- The deeper intake path is now shaped as a separate `inspect` command rather than additional scope hidden inside `assess`.
- `gatehouse candidate` is a workflow-convenience layer for isolated
  candidate intake evidence. It composes existing policy/evidence primitives
  and delegated Cargo checks; it does not define new policy semantics.
- Reviewed-target enforcement has a dedicated `pin check` surface, and `verify`
  now reuses that same gate before code-executing build/test steps. The
  foundation for that work is checked-in review records plus a repo-root
  `reviewed-targets.toml` manifest for active Rust families.
- The current reviewed-target hardening step includes crates.io
  artefact-digest reconciliation in `reviewed-targets.toml`, not a direct port
  of the JS installed-tree gate.
