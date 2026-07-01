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
| `cargo barbican inspect` | Base evidence | Inspect exact crates.io candidates before adding them. |
| `cargo barbican resolve` | Base action | Generate `Cargo.lock` for current manifests under release-age policy. |
| `cargo barbican update` | Base action | Update existing locked dependencies to exact versions. |
| `cargo barbican assess` | Base assessment | Classify a dependency diff. |
| `cargo barbican policy init` | Policy management | Create the explicit policy scaffold for adoption. |
| `cargo barbican inventory` | Base audit | Report dependency inventory and reviewed-policy coverage. |
| `cargo barbican pin-check` | Base policy gate | Enforce reviewed-target policy. |
| `cargo barbican review` | Base review aid | Print a policy-focused review diff. |
| `cargo barbican audit` | Base delegated gate | Run delegated advisory and source-policy checks. |
| `cargo barbican verify` | Base execution gate | Run the final local execution gate. |
| `cargo barbican gatehouse` | Workflow namespace | Run supported gatehouse workflows over the base commands. |

## Common Workflows

### Adopting Cargo-Barbican In A Repo

Create the minimal policy scaffold:

```bash
cargo barbican policy init
```

Then follow [adoption.md](adoption.md) to manually review current
dependencies, create dependency review records, populate `reviewed-targets.toml`,
and run `pin-check` / `verify`.

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
cargo barbican age fast_log@1.7.7
cargo barbican inspect fast_log@1.7.7
```

`age` answers the narrow release-age question. `inspect` gathers static
artefact evidence from crates.io and the published `.crate` tarball.

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
cargo barbican pin-check
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

### Maintaining Reviewed Targets

Use reviewed targets when a dependency family has been deliberately reviewed
and should be pinned before build or test execution.

The repo-root `reviewed-targets.toml` records active reviewed families. Each
family points at a checked-in review record and exact resolved `Cargo.lock`
targets. For crates.io entries, prefer the structured form with the reviewed
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
the family review record exists and the fetched crates.io checksum matches the
reviewed checksum. `age`, `age-lock`, `resolve`, `update`, and `assess` use
crates.io's published checksum metadata; `inspect` and `gatehouse candidate`
also verify downloaded tarball bytes.

Run `pin-check` after editing `reviewed-targets.toml`:

```bash
cargo barbican pin-check
```

`pin-check` is local-only and read-only. It verifies that active review records
exist, direct requirements match when configured, resolved versions match
`Cargo.lock`, checksums match when configured, and allowed execution surfaces
refer to crates in the same reviewed family.

Use `inventory` when you need an audit view rather than an enforcing gate:

```bash
cargo barbican inventory
```

It distinguishes a repo with no reviewed-target policy yet from a configured
policy with uncovered dependencies or missing review records.

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

Use exact versions for intake and update commands. Do not use semver ranges,
feature flags, registry URLs, or git/path specs as candidate specs.

### Exact Candidate Specs

Commands that accept exact candidate specs use the `crate@version` form. A
single optional leading `=` is accepted on the CLI version component:
`crate@=1.2.3` is equivalent to `crate@1.2.3`. Version ranges remain invalid,
including `crate@^1`, `crate@>=1`, `crate@=^1`, and wildcard specs.

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
| `inspect` | No | Fetches and inspects published crates.io artefacts. |
| `gatehouse` | No | Workflow namespace. Supported workflows may create temporary sandboxes outside the repo. |
| `resolve` | Yes | Runs `cargo generate-lockfile`; restores `Cargo.lock` if release-age policy fails. |
| `update` | Yes | Updates `Cargo.lock` through Cargo. |
| `update --dry-run` | No | Uses a temporary workspace and prints a preview. |
| `assess` | No | Reads manifests, lockfiles, policy files, and inspection evidence. |
| `inventory` | No | Reads manifests, lockfile, and reviewed-target policy to report findings and coverage gaps. |
| `pin-check` | No | Local-only reviewed-target enforcement. |
| `review` | No | Prints review-focused diffs. |
| `audit` | No intended repo mutation | Delegated tools may update their own caches. |
| `verify` | Yes, through Cargo build output | Runs `cargo build --locked` and `cargo test --locked`; Cargo writes build artefacts under `target/`. |

## Supported Gatehouse Workflows

`gatehouse` contains workflow affordances built from the lower-level evidence,
assessment, review, and delegated-tool commands. Treat each workflow as a
packaged sequence, not as a new policy source.

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

### `cargo barbican gatehouse`

Runs gatehouse workflow subcommands.

`gatehouse` is a workflow namespace. Its subcommands coordinate existing
policy and evidence primitives with delegated Cargo checks; they do not define
separate policy semantics.

Currently supported workflows:

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
cargo barbican policy init
```

The command creates missing files:

- `barbican.toml`
- `deny.toml`
- `reviewed-targets.toml`
- `docs/dependency-reviews/`
- `docs/dependency-reviews/README.md`

It preserves existing regular files, validates existing `barbican.toml`, and
fails closed on wrong-type scaffold paths or ancestors such as directories in
file positions and symlinks that would otherwise be followed. The generated
`deny.toml` carries the non-advisory `cargo-deny` bans/sources posture only;
it does not contain `[advisories]`, because `cargo barbican audit` forces the
advisory section at runtime.

The output reports each scaffold item as created, already present, or blocked.
On success it points to the manual adoption guide. Init is intentionally not a
review command: it does not add reviewed families, write review records, or
certify existing dependencies.

### `cargo barbican inventory`

Prints a read-only dependency inventory and reviewed-policy coverage audit for
the current workspace.

```bash
cargo barbican inventory
```

The command is local-only and read-only. It reads:

- `Cargo.lock`
- workspace `Cargo.toml` manifests
- root `[workspace.dependencies]` used by `{ workspace = true }`
- `reviewed-targets.toml` when present
- checked-in review-record paths
- `cargo metadata --format-version 1 --frozen` output for live graph execution
  surfaces

The report includes rollups, direct dependency exact-pin status, resolved
crates.io packages and checksums, non-crates.io sources, reviewed-family
coverage, declared allowed execution surfaces, missing review records, and
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
If `cargo metadata --frozen` cannot collect the graph surfaces, inventory still
renders the offline sections and marks live graph surfaces as not collected.
Reported observational findings and policy coverage gaps do not change the
exit code; this command is an audit view, not an enforcement gate.

### `cargo barbican pin-check`

Checks active reviewed Rust families against current manifests and
`Cargo.lock`.

```bash
cargo barbican pin-check [--config reviewed-targets.toml]
```

Use this after editing `reviewed-targets.toml` and before running build/test
execution.

Examples:

```bash
cargo barbican pin-check
cargo barbican pin-check --config reviewed-targets.toml
```

Checks include:

- active review records exist in the repo
- configured direct requirements match workspace manifests exactly
- configured resolved versions match `Cargo.lock`
- configured crates.io checksums match the resolved `Cargo.lock` checksum
  chain
- allowed execution surfaces reference crates in the same reviewed family
- allowed release-age exceptions reference crates in the same reviewed family
  and require structured `checksum_sha256` entries

Standalone `pin-check` skips successfully when no reviewed-target manifest is
present or no active Rust families are configured. `verify` is stricter and
requires explicit reviewed-target policy before build/test execution.

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
cargo barbican audit
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
checksum still match, the review record exists, and `review_by` has not
expired. Native advisory ignores in `deny.toml` or `.cargo/audit.toml` are
neutralised and reported according to
`delegates.unmanaged_delegated_policy` (`warn` | `deny` | `allow`).

See [../functional/cli.md](../functional/cli.md) for the full audit contract.

### `cargo barbican verify`

Runs the final local execution gate.

```bash
cargo barbican verify
```

Use this before commit and in local CI-equivalent checks.

It runs, in order:

```bash
cargo barbican pin-check
cargo build --locked
cargo test --locked
```

`verify` requires explicit reviewed-target policy. Unlike standalone
`pin-check`, it fails closed when `reviewed-targets.toml` is absent or not a
regular file.

This command executes normal Cargo build and test behaviour. That can run build
scripts, proc macros, and tests from the dependency graph. Run it after the
policy and review steps have made that execution acceptable.
