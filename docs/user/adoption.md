# Adopting Cargo-Barbican

This guide covers existing Rust repositories and new projects adopting
cargo-barbican as a dependency policy gate.

`cargo barbican policy init` creates policy scaffolding. It does not review,
approve, or certify the dependencies already in the repository.

The insiders release supports macOS and Linux and installs from an immutable
git tag. It does not claim universal transitive human review: bring direct and
elevated-risk dependencies under policy first, while the inventory keeps the
remaining registry-transitive and execution-surface backlog visible. Exact
Git dependencies are supported through [explicit source review](git-sources.md);
every locked Git package, including repository children, requires completed
review before execution. Windows, crates.io publication, external path and
alternate-registry admission, and hostile-checkout race-free containment remain
out of scope for this release.

Adoption requires a rustup-managed Rust installation with `rustup`, `cargo`,
`rustc`, and `rustdoc` on `PATH`. The execution gates fail closed when rustup is absent
because the active toolchain cannot then be reconciled with native
`rust-toolchain.toml` policy.

## 1. Choose the toolchain and scaffold policy

After the [reviewed installation](integration.md#consumer-flow) and
[configured prerequisites](integration.md#prerequisites), work from the intended
Cargo workspace root. Choose an exact channel, rather than copying a default:

```sh
cargo barbican policy init --toolchain <exact-channel>
```

For example, **only if 1.95.0 is the compiler you deliberately selected**:

```bash
cargo barbican policy init --toolchain 1.95.0
```

The command creates missing scaffold files:

- `barbican.toml`
- `deny.toml`
- `reviewed-targets.toml`
- `docs/dependency-reviews/`
- `docs/dependency-reviews/README.md` — consumer-owned process
- `docs/dependency-reviews/record-template.md` — reusable pending starting point
- `rust-toolchain.toml`, when and only when `--toolchain` supplies an exact
  stable release, numbered beta prerelease such as `1.96.0-beta.2`, or dated
  nightly; generated files use rustup's `minimal` profile, which the init
  report states explicitly

Choose the toolchain deliberately for the consumer repo; do not copy `1.95.0`
blindly. If `rust-toolchain.toml` already exists, omit `--toolchain` or pass the
same exact channel. Floating `stable`, `beta`, and undated `nightly` channels
and bare versioned beta channels such as `1.96.0-beta` are not accepted. A
missing or invalid pin blocks `--ci github`, because the
generated gate must not start from an unpinned compiler.

Install the chosen compiler explicitly, then diagnose agreement:

```sh
rustup toolchain install 1.95.0
cargo barbican toolchain check
```

The numeric channel above belongs to the same worked example, not a universal
recommendation. Ordinary Cargo/rustup bootstrap and configuration still apply;
init is not an executable sandbox or a promise to suppress rustup downloads.

Scaffold items are created independently in dependency order. For example,
dependency-review docs may still be created while a malformed existing
`reviewed-targets.toml` is reported as blocked.

The record template follows usable config/review-directory gating; a blocked
toolchain does not suppress those docs. Requested `--pre-commit-hook` copying
is independent of report-level config/toolchain blocks, but those blocks still
make init fail. Fatal workspace/I/O errors can stop later outputs.

Existing regular files and modes are preserved. Wrong-type scaffold paths, including
symlinks at scaffold locations or existing scaffold ancestors, fail closed and
must be resolved manually.

New template/hook writes use exclusive creation. If a write fails after creating
its file, inspect/remove the retained partial file manually before rerunning;
init preserves an existing regular file without certifying its completeness.

For Windows, see the project-level
[Platform Support](../architecture/overview.md#platform-support) posture before
relying on scaffold path-containment guarantees.

Review `barbican.toml` before enforcing the policy. It is explicit repo policy,
not hidden runtime default state.

`cargo barbican policy init --toolchain 1.95.0 --ci github` additionally emits a ready-to-run
`.github/workflows/barbican.yml` enforcement workflow (it fails closed rather
than overwriting an existing one). See [ci.md](ci.md) for the CI gate and the
client-side pre-commit hook.

## Starting a new project

After creating the Rust project and choosing the policy/toolchain scaffold in
step 1, generate its first dependency graph through the normal command:

```bash
cargo barbican resolve
cargo barbican inventory
```

`resolve` accepts genuine absence of the workspace-root `Cargo.lock` and checks
every selected crates.io version, including transitive selections, under the
same age/yank/exception policy as ordinary resolution. A graph with no registry
dependencies needs no release HTTP requests. Invalid, unreadable, symlinked or
multiply-linked lockfiles are refused; they are not treated as new projects.

Continue with the review steps below: inventory, `pin add` scaffolds, completed
human review and explicit source permission, then `gatehouse pre-release`.
Resolution prepares a graph for review; it does not approve dependencies or run
workspace build/test. Ordinary Cargo executable/configuration/credential trust
still applies. See [lockfile recovery](operations.md#lockfile-mutation-and-baseline-recovery).

Comparative commands still need the actual baseline requested. With no usable
Git commit or no committed baseline lockfile, choose their explicit baseline
options only when you have real prior evidence. Establish an intentional
reviewed initial commit at the appropriate point; do not fabricate an empty
lockfile or commit unreviewed dependencies just to silence a comparison.
Generated first-PR evidence has no empty-baseline fallback.

## Existing locked projects

Start with `cargo barbican inventory`; do not resolve a valid existing graph
merely to adopt policy. Review the labelled direct/source/execution backlog.
Existing registry-family drift uses `pin refresh` or explicit-baseline
`gatehouse re-pin`, followed by the reopened review, rather than duplicate
`pin add`. Preserve custom process, templates, hooks, workflows and records.

## 2. Review Current Dependencies

Treat the existing dependency graph as inventory to review, not as already
trusted state.

Run `cargo barbican inventory` first to see the coverage-gap list: direct
dependencies, non-crates.io sources, and live `build.rs` / proc-macro /
native-sys execution surfaces that are not yet covered by a reviewed family.
Triage that list before reviewing crate by crate. Bring direct dependencies
and elevated-risk execution surfaces under reviewed-target policy first;
routine transitive crates with no elevated-risk surface can follow later, once
the direct and high-risk coverage gaps are closed.

For each dependency family (a named group of one or more crates covered by
one review record and one `reviewed-targets.toml` entry — see the
[glossary](commands.md#glossary)) you want to bring under reviewed-target
policy:

1. Identify the direct manifest requirement and resolved `Cargo.lock` version.
2. Confirm the crates.io checksum from `Cargo.lock` for registry artefacts.
3. Review relevant risk signals, including release age, source, build scripts,
   proc macros, native linking, and advisory status.
4. Write a checked-in review record under `docs/dependency-reviews/`.
5. Add the reviewed family to `reviewed-targets.toml`.

`cargo barbican pin add <crate>` scaffolds steps 4 and 5 offline from the
resolved `Cargo.lock` facts: it appends the family stub (version plus
`checksum_sha256`) to `reviewed-targets.toml` and creates the review-record
stub under `docs/dependency-reviews/`. The scaffold is not the review itself —
complete the record before treating the family as reviewed.

Every new stub is PENDING. The sibling `record-template.md` is also PENDING
when copied as a record; never cite that reusable template as completed evidence.
Complete the review and record the decision **before** removing the pending
marker. The classifier checks text/marker presence, not review authenticity.
For manual records, tailor the template; first-principles reviews need no
inherited corpus, and tool installs need no fictional graph family.

### Evidence without a historical baseline

For each exact registry selection, gather independent evidence even before a
first reviewed Git commit exists. For example, substituting the selected exact
crate/version:

```sh
cargo barbican age semver@1.0.28
cargo barbican inspect semver@1.0.28
cargo barbican audit
```

Install the configured scanners before `audit`. Review the output and native
exit status of each command independently; do not chain them with `&&` if that
would hide later evidence after a finding. A non-zero inspect can be useful
evidence of execution surfaces or IOC findings, not permission to proceed.
Investigate IOC signals separately: later gates do not automatically accept or
re-run them. Record source/release notes, exact checksum, advisory results,
execution surfaces, reasoned decisions and commands before completing review.
`inspect` is registry-only; Git uses the [source review guide](git-sources.md),
full commit/URL identity for every locked Git package and separate native
source permission. Tool-install trust remains independent of graph coverage.

Use structured crates.io `resolved` entries with `checksum_sha256` wherever
possible so `pin check` can reconcile the reviewed artefact against
`Cargo.lock`. Both structured and version-only `resolved` entries require
every matching `Cargo.lock` entry to be crates.io sourced — a git, path, or
alternate-registry entry for the same crate name is a blocking mismatch, even
alongside a clean crates.io entry at the reviewed version. Only the structured
checksum form additionally binds the resolved artefact digest, so prefer it
over the version-only form.

If a reviewed exact crate version is intentionally accepted before the minimum
release-age window has elapsed, add it under the family's
`allowed_age_exceptions` only after recording the reason in the review record.
The crate must already be present in the same family `resolved` map with a
`checksum_sha256`; cargo-barbican verifies that checksum before honouring the
exception.

For advisory findings that are intentionally accepted — for example when
`audit` fails and there is no adoptable patched release yet — use the governed
`cargo barbican pin exception <crate>[@version] <RUSTSEC-id>...` path rather
than hand-authoring the entry or relying on a native `deny.toml` ignore. It
scaffolds a checksum-bound `allowed_advisories` entry (with a `review_by`
re-review deadline, 30 days by default) plus a review-record stub, creating the
reviewed family when the crate is not yet covered. `audit` reconciles each
finding against the bound resolved target, checksum, review record, and
deadline before accepting the risk, and fails it again once `review_by` passes.
See [operations.md](operations.md) for the full failing-audit workflow.
After governance is complete, repositories that run cargo-deny directly may
mirror the same ID into its native ignore list without weakening Barbican.

Review `[delegates]` in `barbican.toml` before enforcing audit. It selects the
lockfile scanner (`cargo-deny`, `cargo-audit`, or `both`), configures the
`cargo-deny` check groups, and controls how native advisory ignores in
`deny.toml` / `.cargo/audit.toml` are reported when they do not match active
governance. Native ignores are neutralised regardless of the reporting mode.

## 3. Check Reviewed-Target Policy

After adding reviewed families and records:

```bash
cargo barbican pin check
```

`pin check` is local-only and read-only. It verifies that active reviewed
families point at real review records and match the current manifests and
`Cargo.lock`. It also fails closed when a manifest `[patch]` table targets a
reviewed crate, or when any effective Cargo config from the workspace root,
its ancestors, or Cargo home includes indirect configuration, declares a
`[source]` table, a config-defined `[patch]` table, or a top-level `paths`
override — all of these can or may repoint a reviewed crate at an unreviewed
source without touching `Cargo.lock`. Repository and ancestor config symlinks
are refused as policy inputs. A Cargo-home config symlink is followed only
when both Cargo home and the target resolve outside the workspace and the
target is a readable regular file; its contents remain subject to the same
checks. A repo-local
`CARGO_HOME` retains the repository symlink refusal.

## 4. Run The Enforcement Gate

Install the scanners chosen by `[delegates]`, using the reviewed
[prerequisite instructions](integration.md#prerequisites). The default selects
cargo-deny; cargo-audit is needed only when configured. After deliberate review:

```sh
cargo barbican gatehouse policy-check
cargo barbican gatehouse pre-release
```

`policy-check` checks toolchain, direct coverage, audit and strict pins without
workspace build/test. `pre-release` also runs locked execution. Both require
at least one active reviewed Rust family **even with no dependencies**; a
successful standalone `pin check` skip is not completed adoption. Do not add a
dummy family to get a dependency-free project green. Genuine empty-graph
strict admission remains a separate policy decision.

`audit` and `verify` stay separate primitives on purpose. After toolchain
conformance, the reviewed-target portion of `verify` is derived from checked-in
repo policy; the overall command also observes active compiler and locked
build/test facts. `audit` additionally depends on the
advisory landscape at the moment it runs, so a new RustSec advisory can flip
it from PASS to FAIL with no repo change at all. `verify` fails closed when
`reviewed-targets.toml` is absent, not a regular file, or configures no active
reviewed family — the gate requires at least one. It runs the reviewed-target
gate before locked build/test verification and confirms each passing step,
ending with `Verify: PASS`. When run standalone, `verify` prints a note
pointing at `audit` as the separate advisory gate; Gatehouse suppresses that
note after its audit step has passed. See
[ci.md](ci.md) for how to schedule both in CI.

The toolchain preflight establishes the identity and agreement of rustup,
Cargo, rustc, and rustdoc; it does not prove those binaries' provenance or
sandbox every executable Cargo may invoke. `RUSTUP_HOME` may select the rustup
installation tree, and target runner/linker, rustflags, and Cargo `[env]`
settings remain normal build inputs. Treat the subsequent locked build and
test as ordinary Cargo execution and review the dependency execution surface
accordingly.

The first Gatehouse step applies the same coverage floor as
`cargo barbican inventory --enforce`. It fails closed (`Inventory: FAIL`) when
a direct dependency has entered the graph without an active reviewed family —
the shape a raw `cargo add` of an unreviewed crate takes — so an uncovered
direct dependency cannot slip through CI. It enforces direct-dependency
coverage; declared execution-surface enforcement is a documented follow-up.
The pre-commit template runs the cheaper standalone floor alongside `pin check`
for earlier feedback.

## 5. Activate CI and optional local feedback

After adoption, review generated CI and configure required status checks,
branch protection and policy/workflow review. Keep scheduled audit to detect
advisories published after merge. Workflow presence alone does not prevent
bypass. See [CI](ci.md).

`policy init --pre-commit-hook` optionally copies `.barbican/hooks/pre-commit`
without executable bits. Plain init creates no hook directory and links to the
same [manual install/existing-hook integration instructions](ci.md#pre-commit-hook).
No hook activation, Git configuration or execution occurs in init. Review first;
local checks remain advisory and skippable.

## Recovery at a handoff

| Symptom | Next action |
|---|---|
| Frozen metadata lacks cached inputs for a consistent manifest/lock graph | Explicitly review/run `cargo fetch --locked` without `--target`, then retry inventory; include all platform inputs. |
| Manifest and lockfile intentionally disagree | Use Barbican `resolve`, review new facts and reopen affected reviews. Repeated fetch cannot repair a stale graph. |
| Toolchain/conformance/executable-control rejection | Run `toolchain check`, preinstall the selected exact toolchain and resolve the reported executable/configuration input. |
| PENDING/incomplete record | Complete the actual evidence and decision, not just marker removal. |
| Existing family version/checksum drift | Review the change, then `pin refresh` or explicit-baseline `gatehouse re-pin`; complete reopened evidence. |
| External path/alternate registry or unavailable Git comparison | Follow the supported source/baseline boundary; no fake baseline, dummy policy or automatic fallback. |
| Scaffold write failure / wrong-type path | Inspect the named path and any retained partial output; repair manually before rerunning. |

For manual setup and safe upgrades, use the
[matching-tag scratch-copy workflow](integration.md#manual-template-adoption).
For day-2 lockfile and baseline diagnostics, see [operations](operations.md#lockfile-mutation-and-baseline-recovery).

## Exact Git sources

Exact reviewed Git dependencies use the existing `pin add` / `pin check`,
inventory, audit and verification workflow. See the
[Git source guide](git-sources.md) for the tagged policy
schema, full-commit requirement, per-package review, source-bound allowances,
manual intake and advisory/build-input limitations. Registry age/advisory
exceptions never authorise Git targets; cargo-deny permission remains separate.


## Existing Family Management

Use [Reviewed Families](families.md) to discover exact names and shared review
scope before an explicit `pin add --family=<name> <crate>...` extension.
Shared evidence becomes PENDING before policy publication; new members gain
no permissions, and successful diagnostics/no-ops never substitute for gates.
