# Command Guide

This guide explains how to use `cargo barbican` from a consumer Rust
repository. Start with the workflow sections when you know what task you need
to complete. Use the command reference when you need exact command syntax,
inputs, outputs, and exit behaviour.

The commands are deliberately composable. You can run the granular evidence,
assessment, review, and verification commands directly, or use a `gatehouse`
workflow when you want cargo-barbican to package a common sequence.

For exact parser rules and behaviour contracts, see
[../functional/cli.md](../functional/cli.md).

## Command Map

| Command | Role | Task |
| --- | --- | --- |
| `cargo barbican age` | Base evidence | Check release age for exact crates.io versions. |
| `cargo barbican age-lock` | Base evidence | Check new lockfile selections against a baseline. |
| `cargo barbican pick` | Base evidence | Discover a policy-compliant exact crates.io version from a semver range. |
| `cargo barbican inspect` | Base evidence | Inspect exact crates.io candidates before adding them. |
| `cargo barbican resolve` | Base action | Generate `Cargo.lock` for current manifests under release-age policy. |
| `cargo barbican update` | Base action | Update existing locked dependencies to exact versions. |
| `cargo barbican assess` | Base assessment | Classify a dependency diff. |
| `cargo barbican policy init` | Policy management | Create the explicit policy scaffold for adoption; `--toolchain` creates an absent exact native pin and `--ci github` also emits the CI workflow. |
| `cargo barbican inventory` | Base audit / gate | Report dependency inventory and reviewed-policy coverage; `--enforce` gates direct-dependency coverage. |
| `cargo barbican pin add` | Policy management | Scaffold a reviewed family and review-record stub from `Cargo.lock`. |
| `cargo barbican pin exception` | Policy management | Scaffold a governed, checksum-bound acceptance of a RustSec advisory finding. |
| `cargo barbican pin check` | Base policy gate | Enforce reviewed-target policy. |
| `cargo barbican review` | Base review aid | Print a policy-focused review diff. |
| `cargo barbican audit` | Base delegated gate | Run delegated advisory and source-policy checks. |
| `cargo barbican verify` | Base execution gate | Run the final local execution gate. |
| `cargo barbican gatehouse` | Workflow namespace | Run supported gatehouse workflows over the base commands. |

## Glossary

- **Family** — a named entry under `[[rust.families]]` in
  `reviewed-targets.toml`, covering one or more crates that were reviewed
  together and share one checked-in review record. A family carries an exact
  `resolved` set, optional `direct` requirements, and optional
  `allowed_surfaces` / `allowed_age_exceptions` / `allowed_advisories`.
- **Reviewed target** — an exact crate version (and, for the structured
  crates.io form, a `checksum_sha256`) recorded in a family's `resolved` map.
  `pin check` and `verify` reconcile the current `Cargo.lock` against these
  exact targets.
- **Gate** — a command whose job is to fail closed: `pin check`, `audit`,
  `verify`, `inventory --enforce`, and `gatehouse pre-release`. A base gate passes with a stable terminal
  token (`Pin check: PASS`, `Audit: PASS`, `Verify: PASS`, or — under
  `--enforce` — `Inventory: PASS`), blocks and explains why, or — for
  standalone `pin check` only — skips successfully when no reviewed-target
  policy is configured yet. Evidence and workflow commands (`age`, `inspect`,
  `assess`, `review`, plain `inventory`, `gatehouse candidate`) are not gates
  in this sense, even where they also exit non-zero on failure.
- **Gatehouse** — the workflow namespace. `gatehouse candidate` assembles a
  pre-add dossier for an exact crates.io release; `gatehouse pre-release`
  composes the standard whole-repo toolchain, inventory, audit, and verify
  sequence.
- **Surface** — an execution surface a dependency's code runs through:
  `build-rs` (build scripts), `proc-macro`, or `native-sys` (native linking
  and FFI). Declared per crate under a family's `allowed_surfaces`.
- **Exception** — a recorded, checksum-bound acceptance of an otherwise
  blocking finding for a crate already present in a family's `resolved` map:
  `allowed_age_exceptions` for too-fresh releases, `allowed_advisories` for
  advisory findings with a `review_by` re-review deadline.
- **Dossier** — the human-readable pre-add intake report `gatehouse candidate`
  produces, combining candidate inspection, an isolated sandbox lockfile,
  `cargo tree`, and `cargo audit` into one document. It is evidence for a
  review, not itself a policy verdict.

## Common Workflows

### Adopting Cargo-Barbican In A Repo

Create the minimal policy scaffold:

```bash
cargo barbican policy init --toolchain 1.95.0
```

Then follow [adoption.md](adoption.md) to manually review current
dependencies, create dependency review records, populate `reviewed-targets.toml`,
and run `pin check` / `verify`.

`policy init` does not certify existing dependencies. It only creates missing
policy files and reports scaffold issues.

Inspect the current dependency set, observational findings, and policy
coverage gaps:

```bash
cargo barbican inventory
```

`inventory` is read-only. It reports direct dependencies, resolved
`Cargo.lock` entries, exact-pin status, reviewed-target coverage, missing review
records, non-crates.io sources, uncovered crates.io packages, and live graph
execution surfaces collected with `cargo metadata --frozen`. Live surfaces are
cross-referenced against declared `allowed_surfaces`; if metadata collection
fails, inventory still renders the offline sections and marks live graph
surfaces as not collected. It also reports reviewed advisory-exception status
and advisory delegation configuration without running the delegated scanners.

### Before Adding A New Dependency

Start with the granular base commands when you want to control the review
steps yourself.

```bash
cargo barbican pick fast_log@^1
cargo barbican age fast_log@1.7.7
cargo barbican inspect fast_log@1.7.7
```

`pick` discovers the newest semver-compatible version that satisfies
release-age policy. `age` answers the narrow release-age question for an exact
version. `inspect` gathers static artefact evidence from crates.io and the
published `.crate` tarball.

After adding the dependency or changing the manifest, resolve the workspace
lockfile under policy and then use the base post-add commands:

```bash
cargo barbican resolve
cargo barbican age-lock
cargo barbican assess
cargo barbican review
cargo barbican audit
cargo barbican verify
```

Or run the blessed composition of the blocking inventory coverage floor,
audit, and verify gates:

```bash
cargo barbican gatehouse pre-release
```

Use `gatehouse candidate` when you want the convenience dossier instead of
assembling that pre-add evidence manually:

```bash
cargo barbican gatehouse candidate fast_log@1.7.7
```

The dossier combines exact candidate inspection with an isolated minimal Cargo
project, generated sandbox `Cargo.lock`, `cargo tree --edges normal`, and
`cargo audit`. It does not replace the base commands; it packages a common
pre-add evidence workflow.

If the candidate is `elevated-risk`, write or update the relevant dependency
review record before adopting it. If the candidate is `policy-violating`, do
not add it unless the underlying policy problem is fixed.

### Reviewing A Rust Tool Before Local Installation

For a Cargo-installed tool published on crates.io, the base evidence command is:

```bash
cargo barbican inspect cargo-audit@0.22.1
```

Then decide whether you need additional manual review of the tool's dependency
graph, advisories, provenance, and high-risk transitive crates.

`gatehouse candidate` is useful when you want cargo-barbican to assemble an
isolated pre-install dossier:

```bash
cargo barbican gatehouse candidate cargo-audit@0.22.1
```

Treat the dossier as partial review evidence, not full install proof. For a
tool crate, `gatehouse candidate` builds a synthetic single-dependency library
graph; it does not model `cargo install --locked` semantics or prove the
tool's real install graph. It also does not build, test, or execute the tool.
For large dependency graphs, follow up with manual review of high-risk
transitive crates, especially crates with build scripts, proc macros, native
code, unusual provenance, or advisory history.

### Updating An Existing Dependency

Preview the exact update first:

```bash
cargo barbican update --dry-run serde@1.0.228
```

Apply the update when the preview is acceptable:

```bash
cargo barbican update serde@1.0.228
```

Then classify and review the resulting dependency state:

```bash
cargo barbican assess
cargo barbican review
```

Before committing, run the local gates:

```bash
cargo barbican pin check
cargo barbican audit
cargo barbican verify
```

`update` mutates `Cargo.lock` unless `--dry-run` is present. The dry-run path
uses an internal temporary workspace and prints a lockfile diff preview instead
of changing the repo.

### Reviewing A Dependency PR

For a normal git-backed review, run:

```bash
cargo barbican age-lock
cargo barbican assess
cargo barbican review
cargo barbican audit
cargo barbican verify
```

`age-lock` catches too-fresh transitive versions selected into `Cargo.lock`.
`assess` classifies the overall dependency change. `review` prints the files
that deserve human attention. `audit` delegates to `cargo-audit` and
`cargo-deny`. `verify` runs the final local execution gate.

A Dependabot or Renovate bump of a crate already covered by a reviewed family
fails `pin check` by design: the bot moved `Cargo.lock` (and possibly the
manifest requirement) away from the exact version and checksum the family
recorded, and that mismatch is exactly what `pin check` exists to catch. This
is not a false positive to suppress. Treat it as a re-review trigger: review
the bumped version the same way any other update would be reviewed, then
update the family's `resolved` entry (and `direct` entry, if pinned) in
`reviewed-targets.toml` and the review record to match, before merging the
bot's PR.

### Maintaining Reviewed Targets

Use reviewed targets when a dependency family has been deliberately reviewed
and should be pinned before build or test execution.

The repo-root `reviewed-targets.toml` records active reviewed families. Each
family points at a checked-in review record and exact resolved `Cargo.lock`
targets.

Use `pin add` to scaffold a new family and its review-record stub from the
resolved `Cargo.lock` facts instead of hand-authoring both:

```bash
cargo barbican pin add serde
```

For crates.io entries, prefer the structured form with the reviewed
tarball checksum:

```toml
[rust.families.resolved]
serde = { version = "1.0.228", checksum_sha256 = "..." }
```

Reviewed families can also carry exact release-age exceptions:

```toml
[rust.families.allowed_age_exceptions]
serde = "1.0.228"
```

The crate must already be present in the same family `resolved` map with
`checksum_sha256`. Release-age-aware commands honour the exception only when
the family review record is completed and the fetched crates.io checksum matches the
reviewed checksum. `age`, `age-lock`, `resolve`, `update`, and `assess` use
crates.io's published checksum metadata; `inspect` and `gatehouse candidate`
also verify downloaded tarball bytes.

Run `pin check` after editing `reviewed-targets.toml`:

```bash
cargo barbican pin check
```

`pin check` is local-only and read-only. It verifies that active review records
exist, direct requirements match when configured, resolved versions match
`Cargo.lock`, checksums match when configured, and allowed execution surfaces
refer to crates in the same reviewed family.

Use `inventory` when you need an audit view rather than an enforcing gate:

```bash
cargo barbican inventory
```

It distinguishes a repo with no reviewed-target policy yet from a configured
policy with uncovered dependencies or incomplete review records.

### Comparing Against Non-Git Baselines

Most day-to-day use compares against `HEAD`. For generated, vendored, or
staged review flows, use explicit baselines:

```bash
cargo barbican age-lock --base-lockfile /path/to/base/Cargo.lock
cargo barbican assess --base-dir /path/to/base/workspace
cargo barbican review --base-dir /path/to/base/workspace
```

The explicit baseline directory for `assess` and `review` should contain the
comparison `Cargo.lock` and workspace manifests.

## How Results Work

### Classifications

Some commands report dependency state using three classifications:

- `routine-safe` means the current checks found no blocking or elevated-risk
  findings.
- `elevated-risk` means the change may be acceptable after explicit human
  review, but should not pass the default fail-closed gate.
- `policy-violating` means the change violates a blocking policy condition.

The default stance is fail-closed. If cargo-barbican cannot establish a policy
fact it needs, it should block and explain the missing evidence.

### Exit Codes

Common exit codes are:

- `0` for success
- `1` for policy failure or failed delegated evidence
- `2` for CLI usage errors reported by Clap

Some commands intentionally treat elevated-risk findings as failure by default.
For `assess`, `--policy-mode elevated-risk` accepts elevated-risk findings with
exit `0` while still failing `policy-violating` results.

### Exact Candidate Syntax

Candidate commands expect exact crates.io specs in this form:

```text
crate-name@1.2.3
```

Use exact versions for `age`, `inspect`, `gatehouse candidate`, and `update`.
Do not use semver ranges, feature flags, registry URLs, or git/path specs as
exact candidate specs. Use `pick` when you need to turn a semver range into an
exact `crate@version`.

### Exact Candidate Specs

Commands that accept exact candidate specs use the `crate@version` form. A
single optional leading `=` is accepted on the CLI version component:
`crate@=1.2.3` is equivalent to `crate@1.2.3`. Version ranges remain invalid
for exact-spec commands, including `crate@^1`, `crate@>=1`, `crate@=^1`, and
wildcard specs. `pick` is the range-aware command.

### Global Options

```bash
cargo barbican --version
cargo-barbican --version
```

Prints the shipped cargo-barbican version.

### Repository Mutation

| Command | Mutates repo files? | Notes |
| --- | --- | --- |
| `age` | No | Performs crates.io metadata checks. |
| `age-lock` | No | Reads current and baseline lockfiles. |
| `pick` | No | Fetches crates.io version metadata and prints an exact candidate. |
| `inspect` | No | Fetches and inspects published crates.io artefacts. |
| `gatehouse` | Depends on workflow | `candidate` creates a temporary sandbox outside the repo; `pre-release` runs Cargo build/test output under `target/`. |
| `resolve` | Yes | Runs `cargo generate-lockfile`; restores `Cargo.lock` if release-age policy fails. |
| `update` | Yes | Updates `Cargo.lock` through Cargo. |
| `update --dry-run` | No | Uses a temporary workspace and prints a preview. |
| `assess` | No | Reads manifests, lockfiles, policy files, and inspection evidence. |
| `inventory` | No | Reads manifests, lockfile, and reviewed-target policy to report findings and coverage gaps. |
| `pin add` | Yes | Appends a reviewed family to `reviewed-targets.toml` and creates a review-record stub; never overwrites existing entries or files. |
| `pin exception` | Yes | Appends an `allowed_advisories` family and a review-record stub when the crate is uncovered; prints a manual fragment instead when it is already covered. Never overwrites existing entries or files. |
| `pin check` | No | Local-only reviewed-target enforcement. |
| `review` | No | Prints review-focused diffs. |
| `audit` | No intended repo mutation | Delegated tools may update their own caches. |
| `verify` | Yes, through Cargo build output | Runs `cargo build --locked` and `cargo test --locked`; Cargo writes build artefacts under `target/`. |

## Supported Gatehouse Workflows

`gatehouse` contains workflow affordances built from the lower-level evidence,
assessment, review, and delegated-tool commands. Treat each workflow as a
packaged sequence, not as a new policy source.

### `pre-release`

Runs the standard whole-repo pre-release supply-chain gate:

```bash
cargo barbican gatehouse pre-release
```

It first proves exact toolchain conformance, then runs blocking `inventory
--enforce`, blocking `audit`, and blocking `verify`. A missing, floating, or
non-conforming compiler pin stops before dependency inventory. Uncovered
transitive packages and undeclared execution surfaces stay visible as
observational backlog, while a direct coverage-floor failure stops before
audit. `verify` already includes the default `pin check`, so Gatehouse does not
run it twice. The workflow fails fast, names the failed primitive, and ends
with `Gatehouse pre-release: PASS` only when all four gates pass.

### `candidate`

Builds a human-readable pre-add intake dossier for one exact crates.io
candidate.

```bash
cargo barbican gatehouse candidate [--preserve-sandbox] <crate@version>
```

Use this when you want cargo-barbican to bundle the common pre-add evidence
workflow. Run the base commands directly when you want finer control over the
manual review sequence.

Examples:

```bash
cargo barbican gatehouse candidate fast_log@1.7.7
cargo barbican gatehouse candidate --preserve-sandbox fast_log@1.7.7
```

Evidence gathered:

- the same exact-candidate inspection used by `inspect`
- a disposable minimal Cargo project pinned to `=version`
- generated sandbox `Cargo.lock`
- `cargo tree --edges normal`
- `cargo audit`

Outputs:

- one dossier on stdout
- exit `0` when required evidence succeeds and policy is routine-safe
- exit `1` when required evidence fails or the candidate is non-routine

The sandbox is deleted by default. Use `--preserve-sandbox` when you want to
inspect the generated project manually.

## Command Reference

### `cargo barbican age`

Checks that each exact crates.io version was published at least the configured
minimum number of days ago.

```bash
cargo barbican age [--min-age-days N] <crate@version>...
```

Use this for a quick release-age check before deeper review.

Examples:

```bash
cargo barbican age serde@1.0.228
cargo barbican age --min-age-days 30 serde@1.0.228 toml@0.9.8
```

Inputs:

- exact crates.io candidate specs
- optional `barbican.toml` release-age policy

Outputs:

- per-candidate release-age results
- exit `0` when all candidates satisfy policy
- exit `1` when a candidate is too fresh or cannot be checked

`--min-age-days` is invocation-scoped. When omitted, cargo-barbican reads
`[release_age].minimum_days` from `barbican.toml`, falling back to `7` when the
file or key is absent.

### `cargo barbican age-lock`

Checks newly selected crates.io versions in `Cargo.lock` against a baseline
lockfile.

```bash
cargo barbican age-lock [--base-ref REF | --base-lockfile PATH] [--lockfile Cargo.lock] [--min-age-days N]
```

Use this when the lockfile has changed and you want to catch too-fresh
transitive selections.

Examples:

```bash
cargo barbican age-lock
cargo barbican age-lock --base-ref main
cargo barbican age-lock --base-lockfile /tmp/base/Cargo.lock
```

Inputs:

- current lockfile, defaulting to `Cargo.lock`
- baseline lockfile from `HEAD:<lockfile>`, another git ref, or
  `--base-lockfile`
- optional `barbican.toml` release-age policy

Outputs:

- release-age results for newly selected crates.io versions
- exit `0` when new selections satisfy policy
- exit `1` when any new selection violates policy

### `cargo barbican inspect`

Performs pre-add static review for exact crates.io candidates.

```bash
cargo barbican inspect [--min-age-days N] <crate@version>...
```

Use this when you need candidate evidence but do not need the full gatehouse
dossier.

Examples:

```bash
cargo barbican inspect fast_log@1.7.7
cargo barbican inspect --min-age-days 30 serde@1.0.228
```

Checks include:

- release age
- crates.io version metadata
- published `.crate` tarball checksum
- `.cargo_vcs_info.json` provenance hints when present
- `build.rs`
- proc-macro surfaces
- native `-sys` and FFI surfaces
- fixed high-scrutiny indicators in build-time and proc-macro-relevant sources

Outputs:

- a structured report suitable as evidence for a checked-in dependency review
  record
- `routine-safe`, `elevated-risk`, or `policy-violating` classification
- exit `0` only when every candidate is routine-safe

`inspect` can supply evidence for a review record, but it does not activate an
entry in `reviewed-targets.toml` by itself.

### `cargo barbican pick`

Discovers the newest stable crates.io version matching a semver requirement
while preserving the release-age gate.

```bash
cargo barbican pick [--min-age-days N] <crate|crate@range>
```

Use this before `inspect` or `gatehouse candidate` when you want the tool to
choose the exact version from a range.

Examples:

```bash
cargo barbican pick serde
cargo barbican pick serde@^1
cargo barbican pick --min-age-days 30 serde@>=1.0,<2.0
```

What it does:

- fetches the crates.io version list for one crate
- interprets the optional range with Cargo-compatible semver semantics
- drops yanked versions, pre-releases, semver-incompatible versions, and
  versions below release-age policy
- prints the selected exact `crate@version`

`pick` is read-only. It does not edit manifests or `Cargo.lock`; feed the
selected exact version into `inspect`, `gatehouse candidate`, or a manifest
edit followed by `resolve`.

### `cargo barbican gatehouse`

Runs gatehouse workflow subcommands.

`gatehouse` is a workflow namespace. Its subcommands coordinate existing
policy and evidence primitives with delegated Cargo checks; they do not define
separate policy semantics.

Currently supported workflows:

- `pre-release` - whole-repo toolchain, inventory, audit, and verify workflow
- `candidate` - pre-add intake dossier for one exact crates.io candidate

### `cargo barbican resolve`

Generates `Cargo.lock` for the current manifests while preserving the
release-age gate after Cargo resolution.

```bash
cargo barbican resolve [--min-age-days N]
```

Use this after editing manifests or adding dependencies.

Examples:

```bash
cargo barbican resolve
cargo barbican resolve --min-age-days 30
```

What it does:

- snapshots the current `Cargo.lock`
- runs `cargo generate-lockfile` against the current manifests
- rechecks newly selected crates.io versions against the pre-resolve
  `Cargo.lock`
- restores the original `Cargo.lock` and exits 1 when the selected versions
  violate release-age policy

### `cargo barbican update`

Updates existing locked dependencies to exact versions while preserving the
release-age gate before and after Cargo resolution.

```bash
cargo barbican update [--dry-run] [--min-age-days N] <crate@version>...
```

Use this for routine exact-version dependency updates.

Examples:

```bash
cargo barbican update --dry-run serde@1.0.228
cargo barbican update serde@1.0.228
cargo barbican update serde@1.0.228 toml@0.9.8
```

What it does:

- checks release age for each requested exact version
- uses `cargo metadata` to disambiguate package IDs
- runs `cargo update --workspace -p <package-id> --precise <version>`
- rechecks newly selected crates.io versions against the pre-update
  `Cargo.lock`

`--dry-run` performs the update in a temporary workspace and prints a summary
and diff preview instead of mutating the repo.

Dry-run caveat: Cargo configuration at or below the copied workspace root and
in `$CARGO_HOME` is honoured. Ancestor `.cargo/config.toml` files between the
workspace root and `$HOME` are not copied into the preview workspace, so they
can make dry-run resolution differ from an in-place run.

### `cargo barbican assess`

Classifies the current Rust dependency state against a baseline.

```bash
cargo barbican assess [--base-ref REF | --base-dir PATH] [--policy-mode strict|elevated-risk] [--lockfile Cargo.lock] [--min-age-days N]
```

Use this after adding or updating dependencies to decide whether the diff is
routine-safe, elevated-risk, or policy-violating.

Examples:

```bash
cargo barbican assess
cargo barbican assess --policy-mode elevated-risk
cargo barbican assess --base-ref main
cargo barbican assess --base-dir /tmp/base-workspace
```

Checks include:

- new direct dependencies across workspace manifests
- new non-crates.io direct dependency specs
- newly selected crates.io versions below the minimum age
- newly selected yanked crates.io versions
- non-crates.io source changes in `Cargo.lock`
- newly introduced native `-sys` crates
- new or changed `build.rs` and proc-macro surfaces
- failed required inspection of dependency surfaces

Policy modes:

- `strict` is the default. Blocking findings and enabled elevated-risk
  findings return exit `1`.
- `elevated-risk` accepts elevated-risk findings with exit `0`, while still
  printing the elevated-risk classification and still failing
  policy-violating results.

Use `--policy-mode elevated-risk` only for an explicit, reviewed invocation.
It is not a permanent policy exception.

### `cargo barbican policy init`

Creates the explicit policy scaffold for adopting cargo-barbican.

```bash
cargo barbican policy init [--toolchain <exact-channel>] [--ci <system>]
```

The command creates missing files:

- `barbican.toml`
- `deny.toml`
- `reviewed-targets.toml`
- `docs/dependency-reviews/`
- `docs/dependency-reviews/README.md`
- `rust-toolchain.toml` only when it is absent and an exact `--toolchain`
  value is supplied

It preserves existing regular files, validates existing `barbican.toml`, and
fails closed on wrong-type scaffold paths or ancestors such as directories in
file positions and symlinks that would otherwise be followed. The generated
`deny.toml` carries the non-advisory `cargo-deny` bans/sources posture only;
it does not contain `[advisories]`, because `cargo barbican audit` forces the
advisory section at runtime.

An existing `rust-toolchain.toml` is validated and preserved. Without an
existing valid pin, init reports the item blocked until the operator supplies
a full stable release, numbered beta prerelease such as `1.96.0-beta.2`, or
dated nightly. A created file uses rustup's `minimal` profile and the action
report states that choice. Bare versioned beta channels remain moving inputs
and are rejected. Conflicting
requested and existing pins are never reconciled automatically. `--ci` output
is also blocked until the toolchain pin is valid.

The output reports each scaffold item as created, already present, or blocked.
On success it points to the manual adoption guide. Init is intentionally not a
review command: it does not add reviewed families, write review records, or
certify existing dependencies.

`--ci <system>` additionally writes a ready-to-run CI enforcement workflow. The
only supported value is `github`:

```bash
cargo barbican policy init --toolchain 1.95.0 --ci github
```

This writes `.github/workflows/barbican.yml`: a single fail-closed gate job (on
pull requests and pushes to `main`) that installs the tooling with `--locked`,
pins its third-party actions by commit SHA, and runs `gatehouse pre-release`
plus `age-lock` and `assess` against the pull-request base. Gatehouse owns
toolchain conformance and the blocking inventory coverage floor. The flag is
independent of `barbican.toml` validity but requires a valid exact toolchain
pin. Unlike the idempotent base scaffold, an existing
`.github/workflows/barbican.yml` is never overwritten: the command fails closed
(exit `1`), reports the path as blocked, and re-prints the intended workflow so
the difference can be reconciled by hand.

`policy init` also points at the shipped advisory client-side pre-commit hook
(`templates/hooks/pre-commit`), which runs the cheap `pin check` /
`inventory --enforce` subset. See [ci.md](ci.md#pre-commit-hook) for install
instructions and [integration.md](integration.md) for the full consumer flow.

### `cargo barbican inventory`

Prints a read-only dependency inventory and reviewed-policy coverage audit for
the current workspace.

```bash
cargo barbican inventory [--enforce]
```

The command is local-only and read-only. It reads:

- `Cargo.lock`
- workspace `Cargo.toml` manifests
- root `[workspace.dependencies]` used by `{ workspace = true }`
- `reviewed-targets.toml` when present
- checked-in review-record paths
- `cargo metadata --format-version 1 --frozen` output for Cargo-parsed direct
  dependency declarations and live graph execution surfaces; exact direct
  package identities come from matching those declarations to `Cargo.lock`
  dependency edges

The report includes rollups, direct dependency exact-pin status, resolved
crates.io packages and checksums, non-crates.io sources, reviewed-family
coverage, declared allowed execution surfaces, incomplete review records, and
uncovered resolved crates. Live graph execution surfaces are reported as
declared when they match checked-in `allowed_surfaces` policy and undeclared
otherwise.

Inventory also reports reviewed advisory exceptions without running
`cargo-deny` or `cargo-audit`. Each configured exception is shown with its
binding state against the current `Cargo.lock` and review record, plus an
expiry status: active, soon-to-expire, expired, or stale. The
soon-to-expire window is currently 30 days and is printed in the report.

The advisory delegation section shows the configured lockfile scanner,
`cargo-deny` checks, unmanaged delegated-ignore policy, native advisory ignores
found in `deny.toml` / `.cargo/audit.toml`, and whether non-advisory
`cargo-deny` posture would come from a checked-in `deny.toml` or Barbican's
generated default base.

Missing `reviewed-targets.toml` is not an error. Malformed policy, malformed
workspace manifests, and missing or malformed `Cargo.lock` fail closed.
If `cargo metadata --frozen` cannot collect graph facts, inventory still
renders the offline sections and marks live graph surfaces as not collected.
It labels uncovered crates.io packages and non-crates.io sources unclassified
because their direct/transitive ownership cannot be established.
The summary separates direct coverage-floor readiness and blockers from the
observational uncovered transitive backlog, undeclared execution surfaces,
and other findings. The detailed reviewed-policy section explains which
sibling gate owns each category. In the default mode (no `--enforce`) the
report remains informational and does not change the exit code.

`--enforce` adds a coverage-floor gate on top of the same report. The coverage
floor is the minimum bar for adoption: every direct dependency must be covered
by an active reviewed family. The gate fails closed (exit `1`, concluding with
`Inventory: FAIL (direct-dependency coverage floor)`) when no `reviewed-targets.toml` policy is configured, when
exact direct-package facts could not be collected, or when a direct
dependency has entered the graph — as a raw `cargo add` of an unreviewed crate
does — without an active reviewed family covering its exact resolved crate.
The appended coverage-floor section names each offending crate and
points at `cargo barbican pin add <crate>` to scaffold coverage; a clean floor
prints `Inventory: PASS (direct-dependency coverage floor)`. Cargo's parsed declarations and exact lockfile edges
make direct coverage version-precise and immune to manifest renames. Optional,
development, build, and target-specific direct dependencies are included;
same-name transitive versions stay observational. Enforcing declared execution surfaces
(`build.rs` / proc-macro / native-sys) is a documented follow-up: undeclared
live surfaces are still reported above but not yet gated. Reviewed-record
completeness is `pin check`'s gate, not this floor; the shipped CI and
pre-commit templates run both. Without `--enforce` the report body is unchanged
and `inventory` never prints an `Inventory:` line.

Workspace-member discovery for the offline manifest sections is approximate,
not Cargo-exact: literal `[workspace] members` paths are read directly, but
glob member patterns are resolved by walking the matched root directories for
any `Cargo.toml`, not by evaluating the glob pattern itself, and a
`[workspace] exclude` list is not honoured. `crates/` is always scanned as an
extra root regardless of whether the workspace declares a glob there. In a
monorepo with directories that look like workspace members but are excluded,
or with an unrelated `Cargo.toml` under a scanned root, `inventory` can report
phantom manifest entries that `cargo metadata` would not consider part of the
workspace. Cross-check against `cargo metadata` output when the two disagree.
The `--enforce` verdict does not use this approximation: declarations and
workspace-member identities come from Cargo metadata, and exact resolved
direct identities come from `Cargo.lock` dependency edges.

### `cargo barbican pin add`

Scaffolds a reviewed-target family and a review-record stub for one crate
already resolved in `Cargo.lock`.

```bash
cargo barbican pin add <crate>[@version]
```

Use this when bringing a dependency under reviewed-target policy, instead of
hand-authoring the `reviewed-targets.toml` family and record file.

Examples:

```bash
cargo barbican pin add serde
cargo barbican pin add serde@1.0.228
```

The command is fully offline. It:

- reads the resolved version and `checksum_sha256` for the crate from
  `Cargo.lock` (the same source `inventory` uses; nothing is fetched from
  crates.io)
- appends a family stub to `reviewed-targets.toml` with the family name,
  review-record path, and a `[rust.families.resolved]` entry carrying the
  resolved version and checksum
- when the crate is a direct dependency whose manifest requirement is already
  the exact `=version` pin everywhere it appears, also includes the matching
  `[rust.families.direct]` entry; a direct dependency without a uniform exact
  pin is reported with a note instead
- creates a review-record markdown stub under `docs/dependency-reviews/`
  pre-filled with the resolved facts
- prints next steps

The version may be omitted when the crate resolves to exactly one version in
`Cargo.lock`; with multiple resolved versions, pass an exact `crate@version`.

Fail-closed behaviour — the command exits `1` without mutating anything when:

- the crate (or requested version) is not present in `Cargo.lock`
- `reviewed-targets.toml` is absent (run `cargo barbican policy init` first)
- the crate is already covered by an existing reviewed family
- the scaffold family name or the review-record path already exists

The scaffold is not a completed review. Complete the review record, then run
`pin check`.

### `cargo barbican pin exception`

Scaffolds the governed acceptance of one or more RustSec advisories for a crate
already resolved in `Cargo.lock`, fully offline. This is the audit-side
parallel to `pin add`: the governed way to accept an advisory finding when
there is no adoptable patched release yet, instead of an ungoverned `deny.toml`
or `.cargo/audit.toml` ignore (which `audit` neutralises regardless).

```bash
cargo barbican pin exception <crate>[@version] <advisory-id>... [--review-by YYYY-MM-DD]
```

Use this when `audit` reports a finding and remediation is not yet possible.

Examples:

```bash
cargo barbican pin exception vulnerable-crate RUSTSEC-2026-0001
cargo barbican pin exception vulnerable-crate@1.2.3 RUSTSEC-2026-0001 RUSTSEC-2026-0002
cargo barbican pin exception vulnerable-crate@1.2.3 RUSTSEC-2026-0001 --review-by 2026-09-01
```

The command:

- validates each advisory id against the `RUSTSEC-YYYY-NNNN` form
- reads the resolved version and `checksum_sha256` from `Cargo.lock`; the
  acceptance is checksum-bound, so a lockfile entry without a crates.io
  checksum fails closed
- appends a `[[rust.families]]` stub (like `pin add`) with a
  `[rust.families.allowed_advisories]` entry binding each advisory to a
  `review_by` re-review deadline — 30 days from today by default, overridable
  with `--review-by`
- creates a review-record stub under `docs/dependency-reviews/` pre-filled with
  the accepted advisories

The version may be omitted when the crate resolves to exactly one version in
`Cargo.lock`. When the crate is already covered by an active reviewed family,
the command does not rewrite the existing block; it prints the exact
`allowed_advisories` fragment to add by hand plus the review record to update.

Fail-closed behaviour — the command exits `1` without mutating anything on an
invalid advisory id or `--review-by` date, a crate or version missing from
`Cargo.lock`, a checksumless lockfile entry, an advisory already allowed by a
reviewed family, a family-name or record-path collision, or when
`reviewed-targets.toml` is absent (run `cargo barbican policy init` first).

The scaffold is not a completed review. The stub carries the
`BARBICAN-REVIEW-PENDING` marker, and both `pin check` and `audit` reject the
family until a reviewer completes the record and deletes the marker; `audit`
also fails the exception again once `review_by` passes. Complete the record,
then run `gatehouse pre-release`. See
[configuration.md](configuration.md) for the `allowed_advisories` mechanism and
[operations.md](operations.md) for the failing-audit workflow this fits into.

### `cargo barbican pin check`

Checks active reviewed Rust families against current manifests and
`Cargo.lock`.

```bash
cargo barbican pin check [--config reviewed-targets.toml]
```

Use this after editing `reviewed-targets.toml` and before running build/test
execution.

Examples:

```bash
cargo barbican pin check
cargo barbican pin check --config reviewed-targets.toml
```

Checks include:

- active review records exist in the repo
- configured direct requirements match workspace manifests exactly
- configured resolved versions match `Cargo.lock`
- every `Cargo.lock` entry sharing a reviewed crate's name is crates.io
  sourced; a git, path, alternate-registry, or sourceless entry blocks the
  check even when a sibling entry for the same name and version is a clean
  crates.io match — this applies to both structured and version-only
  `resolved` entries
- configured crates.io checksums match the resolved `Cargo.lock` checksum
  chain; a matching-version entry with no checksum is its own mismatch, not
  treated as absent
- allowed execution surfaces reference crates in the same reviewed family
- allowed release-age exceptions reference crates in the same reviewed family
  and require structured `checksum_sha256` entries
- no workspace manifest `[patch]` table (any registry key) targets a crate
  covered by an active reviewed family
- no effective `.cargo/config.toml` / `.cargo/config` from the workspace root,
  its ancestors, or Cargo home declares an indirect include, `[source]`,
  `[patch]`, or top-level `paths` key while a reviewed family is active

Standalone `pin check` skips successfully when no reviewed-target manifest is
present or no active Rust families are configured. `verify` is stricter and
requires at least one active reviewed family before build/test execution.

Version-only `resolved` entries (for example `serde = "1.0.228"`) now still
enforce the crates.io source requirement above, but they do not bind an
artefact checksum. Prefer the structured
`{ version = "...", checksum_sha256 = "..." }` form so the gate also catches a
same-version crates.io re-publish with a different checksum.

### `cargo barbican review`

Prints a policy-focused dependency review diff with a checklist.

```bash
cargo barbican review [--base-dir PATH]
```

Use this when a human needs to review what changed.

Examples:

```bash
cargo barbican review
cargo barbican review --base-dir /tmp/base-workspace
```

The diff includes policy-relevant files when present:

- repo-root `Cargo.toml`
- `Cargo.lock`
- `barbican.toml`
- `deny.toml`
- `reviewed-targets.toml`
- workspace member `Cargo.toml` files
- checked-in dependency review records under `docs/dependency-reviews/`

`review` does not decide whether a change is acceptable. Pair it with
`assess`, `audit`, and human judgement.

### `cargo barbican audit`

Runs delegated advisory and source-policy checks.

```bash
cargo barbican audit [--format text|json]
```

Use this as the routine delegated advisory and deny-policy check.

`audit` does not inherit `cargo-audit` or `cargo-deny` exit codes as the policy
verdict. Instead, it generates a max-disclosure runtime `cargo-deny` config
that forces `[advisories]` and strips graph suppression, runs the configured
scanner(s), parses the complete structured advisory finding set, reconciles
each finding against checksum-bound reviewed `allowed_advisories` exceptions,
and owns pass/fail itself. A non-zero scanner exit is normal when findings are
present; incomplete or unparsable scanner evidence fails closed.

Reviewed advisory exceptions are honoured only when the resolved target and
checksum still match, the review record is completed, and `review_by` has not
expired. Native advisory ignores in `deny.toml` or `.cargo/audit.toml` are
neutralised. IDs for which every current occurrence is accepted by active
Barbican governance are reported as governed compatibility entries; all other
native IDs are reported according to `delegates.unmanaged_delegated_policy`
(`warn` | `deny` | `allow`). Adding a native ignore never authorises a
Barbican pass.

By default `audit` runs the `cargo-deny` `advisories`, `bans`, and `sources`
checks, and adds the `licenses` check whenever the checked-in `deny.toml`
declares a `[licenses]` policy — a checked-in licence policy is enforced, not
silently skipped. An explicit `delegates.cargo_deny.checks` list overrides
this in either direction, and the report always states the resulting licences
posture. See
[configuration.md](configuration.md) for the resolution rules.

To accept a finding when no patched release is adoptable yet, use the governed
`cargo barbican pin exception` path first. A matching native ignore may then be
added for direct-tool compatibility; it supplies no authority to Barbican.

`--format` selects the report format. The default `text` report is
human-oriented and prints the stable `Audit: PASS` / `Audit: FAIL` token.
`--format json` emits a schema-versioned JSON report on stdout — top-level
`schema_version`, `status`, `success`, structured `findings`, and per-finding
remediation objects — for CI consumption. The `Audit:` token is a text-mode
signal only, so a JSON consumer keys off `status` / `success` and the exit code
instead of grepping for it.

See [../functional/cli.md](../functional/cli.md) for the full audit contract,
including the JSON schema.

### `cargo barbican verify`

Runs the final local execution gate.

```bash
cargo barbican verify
```

Use this before commit and in local CI-equivalent checks.

It first proves exact `rust-toolchain.toml`, rustup, Cargo, rustc, and rustdoc
conformance. It then runs, in order, the default `pin check`, `cargo build
--locked`, and `cargo test --locked`.

`verify` requires explicit reviewed-target policy. Unlike standalone
`pin check`, it fails closed when `reviewed-targets.toml` is absent, not a
regular file, or configures no active reviewed family.

On success, `verify` confirms each executed step explicitly (`OK   cargo build
--locked`, `OK   cargo test --locked`), then prints a scope-honesty note —
`note: advisory audit is a separate gate; run cargo barbican audit` —
immediately before the final `Verify: PASS` line, so a passing run is
distinguishable from a skipped one and does not read as an advisory-clean
verdict on its own.

This command executes normal Cargo build and test behaviour. That can run build
scripts, proc macros, and tests from the dependency graph. Run it after the
policy and review steps have made that execution acceptable.

#### `audit` and `verify` stay separate primitives

`cargo barbican audit` plus `cargo barbican verify` together are the
enforcement gate a repo runs before trusting its dependency state. They are
kept as two separate commands rather than merged into one because their
verdicts depend on different things:

- after the active Rust toolchain conforms to the exact native pin, `verify`'s
  reviewed-target verdict is a function of the repo. The overall command also
  fails when machine toolchain facts or locked build/test execution diverge.
- `audit`'s verdict also depends on the advisory landscape at the moment it
  runs. A new RustSec advisory against an already-locked crate can flip
  `audit` from PASS to FAIL with no repo change at all.

Run them directly when you need independent scheduling or diagnostics. For the
standard release path, `cargo barbican gatehouse pre-release` composes them
without merging their semantics and applies toolchain conformance plus the
blocking inventory coverage floor first. See [ci.md](ci.md) for the
scheduled-audit pattern.
