# Architecture Overview

A portable, policy-first Rust supply-chain hardening tool: it gives a Rust repo
one gate for what enters its dependency graph. Pure Rust, a single versioned
implementation that every Rust repo can install and pin. Distributed today by
local/git install-and-pin; crates.io publication is a deferred decision, not
foreclosed.

## Why this exists

cargo-barbican grew out of undertask, a private predecessor project that
implements supply-chain hardening as Python scripts plus a shell wrapper. That
hardening model is sound: release-age gating, `--locked` verification, targeted
updates, advisory checks, and checked-in review records for dependency changes.

The problem is duplication. As soon as multiple Rust repos need the same
hardening, copy-pasted scripts drift. cargo-barbican exists to replace that
duplication with one versioned Rust policy tool that consumer repos pin and
re-sync deliberately — a portable policy gate in its own right, not only a
deduplication of undertask's scripts.

## Platform Support

cargo-barbican is developed and tested on macOS and Linux. The current binary
requires Unix APIs and does not support Windows.

Rust distribution metadata and native installer qualification are separate.
The checked toolchain handoff/static installed mapping currently admits only
the exact qualified macOS ARM64 Rustup build; unqualified hosts, evaluators
and preferred encodings refuse. Broader metadata support is not a claim of
native installation support. See [toolchain operation](../user/toolchains.md).

## Goals

1. Be the single, portable source of truth for Rust supply-chain policy — one dependency-intake gate that many repos install, pin, and enforce consistently.
2. Pure Rust installation and execution, with no Python prerequisite.
3. Inherit existing trust decisions from undertask where possible instead of re-reviewing by default.
4. Match undertask's surface closely enough that existing muscle memory transfers.
5. Apply the same supply-chain discipline to cargo-barbican itself that it will enforce on consumers.

## Current non-goals

- Public crates.io release (deferred, not foreclosed). Local/git install-and-pin via `cargo install --path` or `cargo install --git` is the current distribution; publishing is a later decision requiring explicit sign-off.
- Porting undertask's full mixed-ecosystem dependency-assessment workflow.
- JavaScript ecosystem support.
- Multi-workspace orchestration.

## Current implemented surface

The simple hardening path is implemented. `age`, `age-lock`, `pick`, `resolve`,
`update`, `assess`, `inspect`, `gatehouse candidate`, `gatehouse pre-release`, `gatehouse policy-check`, `toolchain check`, `policy init`,
`inventory`, `pin add`, `pin exception`, `pin check`, `review`, `audit`, and
`verify` are implemented.

The `toolchain` namespace also provides exact-stable distribution review,
explicit personal acceptance, repository admission, checked Rustup handoff,
static adoption/installation checks and separate pin activation. The pure
`rust_distribution` and `toolchain_admission` modules own identities, mapping,
bounded parsing and eligibility; binary `toolchain_intake` owns HTTP, public
verification, private storage, repository publication and native effects.
Neither library module imports process/filesystem concerns.

Component evidence is owned by the existing admission records and source collector.
Schema-2 evidence binds every selected archive to its source relationship and
represented inventory, while source inclusion and binary reachability remain
distinct. Missing required provenance is blocking; explicit residual coverage is
assessed by the existing human-assessment owner. Docs asset hashes/counts are
static evidence, not a browser execution or complete dependency analysis. Legacy
minimal evidence keeps its content identity; older generic default/docs evidence
cannot gain the new scope through cached admission.

Installed verification checks the existing cancellation flag while traversing
entries, hashing bounded chunks and rechecking filesystem identities. The native
install owner checks success boundaries, and the admission/store owners check
before continuing-use binding publication. Existing bindings and diagnostic
history survive cancellation; late observed cancellation reports completed effects.
Activation retains its separate post-verification publication guard.

Static entry runs before Cargo workspace discovery. Opted-in existing gates
check admission and current installed correspondence before runtime probes;
legacy configurations retain conformance-only behaviour. Per-user authority,
disposable downloads and portable checked-in evidence remain distinct. New
admission/install requires fresh evidence by default; explicit bounded cached
operations do not become defaults or expire unchanged continuing local use.
The public supplier baseline uses explicit material-change proposals, not a
new signing service or personal GPG trust. Normal Rustup destinations and
defaults remain native; acceptance precedes its internal candidate probe.
This is scoped admission and correspondence, not binary benignness,
reproducible-build proof, compatibility testing or a hostile-process sandbox.

Ordinary repository dispatch checks effective Cargo configuration for unsupported
lockfile selection before Cargo workspace discovery, independently of optional
reviewed-family policy. The pure Cargo-config classifier owns presence detection;
the binary's shared lockfile-identity guard owns configuration loading and safe
diagnostics. Changed execution roots and candidate/update-preview temporary roots
are checked before their graph operations. Toolchain preflight applies the same
rule to its captured configuration before returning the snapshot used by strict
verification and Gatehouse. This preserves the default workspace `Cargo.lock`
boundary without introducing alternate-lockfile support or constraining static
toolchain intake. See the [CLI contract](../functional/cli.md#cargo-lockfile-identity)
for exact keys and the existing filesystem/concurrent-writer limits below.

`pin refresh` updates existing registry pin facts, withdraws changed targets'
grants and reopens review records. `gatehouse re-pin` composes explicit-baseline
proof and existing age/assessment before one aggregate refresh. Record writes
precede policy publication; failures may retain safe PENDING evidence. See
[DD-004](decisions/dd-004-reviewed-pin-refresh.md).

The current intake layer is:

- `gatehouse policy-check` composes exact toolchain conformance, blocking direct
  coverage, audit and strict reviewed pins without workspace execution; it shares
  verify's required-policy rule and captured Cargo configuration, while standalone
  pin check retains optional adoption. It adds no framework or new policy.

- `assess` remains the post-add diff classifier
- `gatehouse pre-release` is the blessed fail-fast composition of exact Rust
  toolchain conformance, the blocking direct-dependency inventory floor,
  blocking audit, and blocking verify; the base primitives retain their own
  semantics
- `pick` is the implemented read-only exact-version discovery surface for
  crates.io semver ranges
- `inspect` is the implemented first Rust-only, crates.io-only deep-review surface
- `pin check` is now the implemented first reviewed-target enforcement surface
- the current enforcement baseline is checked-in review records plus a repo-root
  `reviewed-targets.toml` manifest for active Rust families
- `pin check` now validates that each active reviewed family points at a real
  checked-in review record path before it trusts the reviewed-target declaration
- the first gate trusts exact `Cargo.lock` parity plus optional exact direct
  manifest requirements
- `verify` first requires an exact `rust-toolchain.toml` pin and proves the
  active rustup, Cargo, rustc, and rustdoc toolchain conforms to it; only then does it
  reuse the reviewed-target gate before `cargo build --locked` and `cargo test
  --locked`
- that preflight is an identity gate for Cargo's Rust toolchain executables,
  not a binary-provenance proof or a sandbox around Cargo's wider execution
  surface; build/test still runs with ordinary Cargo runner, linker, flag, and
  environment semantics after policy review
- the current reviewed-target gate now supports crates.io reviewed-artefact
  reconciliation: record the reviewed tarball digest in `reviewed-targets.toml`
  and verify it against the resolved `Cargo.lock` checksum chain
- reviewed families can declare exact `allowed_age_exceptions` for
  checksum-bound too-fresh versions; release-age-aware commands honour them at
  one shared evaluation seam while yanked releases and checksum mismatches
  remain blocking
- comparative command baselines and review ergonomics are now partially
  decoupled from `git`:
  `age-lock` can compare against an explicit baseline lockfile,
  `assess` and `review` can compare against an explicit baseline directory,
  and `update` rechecks against an internal pre-update `Cargo.lock` snapshot
  instead of relying on `HEAD`
- `resolve` generates `Cargo.lock` for the current manifests with `cargo
  generate-lockfile`, then rechecks newly selected crates.io versions against
  the original graph; genuine prior absence selects the first graph and checks
  every registry selection. Resolve/update share one observed-output guard:
  original bytes/permissions or absence are restored on supported returned
  failures, while detected conflicts are preserved and fail. Metadata and each
  precise update are checkpointed separately. This is single-writer recovery,
  not a race-free transaction or an executable sandbox
- `update` also supports a non-mutating `--dry-run` preview that shows the
  would-be `Cargo.lock` diff without changing the working tree
  - the copied workspace preserves relative symlinks only when their resolved
    target remains inside the source workspace and outside skipped `.git` /
    `target` paths; unsupported symlinks fail closed
- `policy init` creates the explicit adoption scaffold for consumer repos:
  `barbican.toml`, `reviewed-targets.toml`, dependency-review conventions, and
  an absent `rust-toolchain.toml` only from an explicit exact `--toolchain`
  operator choice, using and reporting rustup's `minimal` profile; it does not
  review or certify existing dependencies, and
  scaffold items are created independently so repairable pieces can be laid
  down even when another item is blocked

## Deferred / Non-Sequenced Design Work

### Full Windows Support (Non-Sequenced)

Full Windows support is explicitly parked. It is not scheduled in the current
phase plan, and until it lands Windows remains outside the supported platform
posture above.

Delivering supported Windows operation requires a comprehensive Windows audit
and review of the codebase, with particular attention to:

- filesystem path handling and fail-closed containment paths
- symlink, directory junction, and reparse-point classification under
  `symlink_metadata`
- path canonicalisation and confinement
- `create_dir_all` / `fs::write` write-through behaviour
- subprocess invocation and shell-free argument boundaries
- path separators, prefixes, and `OsStr` / encoding behaviour

It also requires a methodology for post-hardening cross-platform parity:

- Windows CI that runs the relevant command and library tests
- a platform-parity test matrix for scaffold and containment paths
- golden behavioural tests that run on both Unix-like systems and Windows
- explicit verification that wrong-type, symlink, junction, and reparse-point
  scaffold paths fail closed on Windows

Modern Rust may already classify some Windows junction/reparse-point cases in
a fail-closed way under `symlink_metadata`; the audit must verify that fact
rather than assume it.

### Race-Free Filesystem Containment (Non-Sequenced)

Race-free filesystem containment is explicitly parked. Current scaffold and
workspace-copy containment checks are designed for static checked-in repo
state; they do not claim to defeat a concurrent local writer racing a
check-then-act sequence between `symlink_metadata` and later `create_dir_all` /
`fs::write` calls.

Delivering race-free containment would require platform-specific design and
verification, such as descriptor-relative operations and no-follow resolution
primitives where available (`openat2(RESOLVE_NO_SYMLINKS)` / `O_NOFOLLOW` on
Unix-like systems), plus an equivalent Windows strategy.

### Cross-Command Symlink Containment (Non-Sequenced)

Workspace-member and review-record discovery currently use lexical path guards,
but some filesystem reads still follow symlinks. A symlinked search root,
symlinked member directory, or intermediate symlink inside a `review_record`
path can read or probe files outside the repo when cargo-barbican is run on an
untrusted checkout.

This is pre-existing and repo-wide: `review`, `pin check`, `assess`, and
`inventory` all depend on the same discovery model. The intended hardening is
to canonicalise the repo root once and assert every walked or read path remains
within it before using the path. That closes the workspace-member discovery and
intermediate-review-record symlink cases together.

## Reviewed source identity

Reviewed targets distinguish crates.io archives from exact Git repositories and
commits. The shared pure matcher owns source parity; Cargo owns resolution and
the binary retains filesystem/subprocess integration. Every locked Git package
requires explicit review before build/test execution, including in-repository
children. Registry and Git identities and allowances cannot substitute for one
another. Advisory source attribution precedes deduplication and reconciliation;
Git scanner coverage is disclosed rather than inferred from a version label.
See [Git admission](../user/git-sources.md) and the
[functional contract](../functional/cli.md#exact-git-reviewed-source-admission).

## Verification runner boundary

Checked-in `[verify]` policy selects cargo-test (default) or an exact-version
cargo-nextest delegate. The library owns runner/version validation and pure
Cargo metadata scope selection; the binary owns prepared-Cargo invocation and
streamed execution. This is a closed branch in the existing gate, with no
runner framework, installation engine or new product dependency. Gatehouse
passes the selected config into nested verify and retains one preflight.
That preflight rejects nextest-specific environment/config aliases when the
runner is selected, because Cargo aliases can shadow external subcommands.

Nextest isolates unit/integration test processes, while Cargo runs doctests.
Doctest commands include every default member so binary roots keep their
feature activation. Mixed enabled/disabled doctest libraries fail closed,
rather than reproduce Cargo's resolver or execute disabled tests. Consumers
own native harness configuration, binary provenance and external resource
isolation. See [functional contract](../functional/cli.md) and
[user configuration](../user/configuration.md#verify).

## Architectural boundary

Git comparisons capture one validated immutable commit; blob readers also
capture the workspace's Git prefix and map logical workspace paths into actual
Git objects. Re-pin shares that context with its primitive checks, while review
needs only captured HEAD. Explicit filesystem comparisons stay independent of
Git and map absolute current paths into the requested baseline. Missing evidence
fails without an empty graph or alternative-ref fallback. Current-path parent
aliases are reconciled without requiring a baseline file to exist on disk.

The codebase is split into a library crate and a Cargo-subcommand binary from
the start:

- `crates/barbican/` — pure policy logic, domain types, and HTTP-behind-trait boundaries
- `crates/cargo-barbican/` — CLI dispatch, subprocess integration, and concrete HTTP implementation

That split keeps the library testable without network access and confines
shelling out to the binary.

## Dependency model

Every dependency addition or dependency-tool install is documented in
`docs/dependency-reviews/` before it lands. Most direct dependencies inherit
from Undertask's reviewed set; local first-principles reviews cover direct
dependencies that define cargo-barbican-specific boundaries such as HTTP,
time parsing, archive inspection, checksum computation, and diff rendering.

## Repo shape

```text
Cargo.toml              workspace
rust-toolchain.toml     pinned toolchain
crates/
  barbican/             library: types + pure functions, network behind trait
  cargo-barbican/       binary: CLI dispatch, subprocesses, HTTP impl
templates/              shipped content copied into consumer repos
docs/
  user/                 consumer adoption docs
  functional/           CLI and behaviour contracts
  architecture/         goals, boundaries, and design decisions
  contributor/          contributor constraints and repo workflow
  dependency-reviews/   review records and policy template
  standards/            adopted documentation standards
```


`toolchain check` exposes the existing canonical conformance owner for diagnosis
and generated post-gate PR evidence. Gatehouse and verify continue using the
internal owner directly; no persisted receipt or subprocess recursion is added.
Generated evidence keeps independent strict commands, exact base and native
failures, with fresh eligibility and recognised-cancellation checks. See the
functional CLI contract and user CI migration guidance.


Policy init also creates a consumer-owned PENDING record template and optionally
copies a disabled advisory hook with exclusive creation. Activation/Git config
stay consumer-owned; the library composer and policy verdicts are unchanged.
See the [adoption guide](../user/adoption.md).


## Family Management

Focused pin list/show diagnostics and explicit existing-family batches share the
reviewed-target owners. Addition uses an independent pure expected policy, and
the binary shares refresh snapshot/PENDING-first publication protection. See
[DD-005](decisions/dd-005-family-management.md); creation, identity refresh and
enforcement retain their distinct contracts.
