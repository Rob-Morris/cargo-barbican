# Adopting Cargo-Barbican

This guide is for an existing Rust repository adopting cargo-barbican as a
dependency policy gate.

`cargo barbican policy init` creates policy scaffolding. It does not review,
approve, or certify the dependencies already in the repository.

The insiders release supports macOS and Linux and installs from an immutable
git tag. It does not claim universal transitive human review: bring direct and
elevated-risk dependencies under policy first, while the inventory keeps the
remaining transitive and execution-surface backlog visible. Windows,
crates.io publication, positive reviewed policy for external git/path/alternate
registry dependencies, and hostile-checkout race-free containment remain out
of scope for this release.

## 1. Create The Policy Scaffold

From the consumer repository root:

```bash
cargo barbican policy init
```

The command creates missing scaffold files:

- `barbican.toml`
- `deny.toml`
- `reviewed-targets.toml`
- `docs/dependency-reviews/`
- `docs/dependency-reviews/README.md`

Scaffold items are created independently in dependency order. For example,
dependency-review docs may still be created while a malformed existing
`reviewed-targets.toml` is reported as blocked.

Existing regular files are preserved. Wrong-type scaffold paths, including
symlinks at scaffold locations or existing scaffold ancestors, fail closed and
must be resolved manually.

For Windows, see the project-level
[Platform Support](../architecture/overview.md#platform-support) posture before
relying on scaffold path-containment guarantees.

Review `barbican.toml` before enforcing the policy. It is explicit repo policy,
not hidden runtime default state.

`cargo barbican policy init --ci github` additionally emits a ready-to-run
`.github/workflows/barbican.yml` enforcement workflow (it fails closed rather
than overwriting an existing one). See [ci.md](ci.md) for the CI gate and the
client-side pre-commit hook.

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
than hand-authoring the entry or reaching for a native `deny.toml` ignore. It
scaffolds a checksum-bound `allowed_advisories` entry (with a `review_by`
re-review deadline, 30 days by default) plus a review-record stub, creating the
reviewed family when the crate is not yet covered. `audit` reconciles each
finding against the bound resolved target, checksum, review record, and
deadline before accepting the risk, and fails it again once `review_by` passes.
See [operations.md](operations.md) for the full failing-audit workflow.

Review `[delegates]` in `barbican.toml` before enforcing audit. It selects the
lockfile scanner (`cargo-deny`, `cargo-audit`, or `both`), configures the
`cargo-deny` check groups, and controls how native advisory ignores in
`deny.toml` / `.cargo/audit.toml` are reported. Native ignores are neutralised
regardless of the reporting mode.

## 3. Check Reviewed-Target Policy

After adding reviewed families and records:

```bash
cargo barbican pin check
```

`pin check` is local-only and read-only. It verifies that active reviewed
families point at real review records and match the current manifests and
`Cargo.lock`. It also fails closed when a manifest `[patch]` table targets a
reviewed crate, or when a repo-root `.cargo/config.toml` declares a `[source]`
table, a config-defined `[patch]` table, or a top-level `paths` override —
all of these can repoint a reviewed crate at an unreviewed source without
touching `Cargo.lock`.

## 4. Run The Enforcement Gate

`audit` delegates to `cargo-deny` (and `cargo-audit` when configured), so
install both before running it, following the same review-then-pin approach the
tool asks of its own dependents:

```bash
cargo install --locked cargo-deny@0.19.6 cargo-audit@0.22.1
```

A missing delegate fails `audit` closed with an actionable install line; see
[integration.md](integration.md#prerequisites) for the detail. When
reviewed-target policy is ready, run the direct coverage floor and the
pre-release workflow:

```bash
cargo barbican gatehouse pre-release
```

`audit` and `verify` stay separate primitives on purpose. `verify`'s verdict is a pure
function of the repo — the same manifests, lockfile, and reviewed-target
policy always produce the same result. `audit`'s verdict also depends on the
advisory landscape at the moment it runs, so a new RustSec advisory can flip
it from PASS to FAIL with no repo change at all. `verify` fails closed when
`reviewed-targets.toml` is absent, not a regular file, or configures no active
reviewed family — the gate requires at least one. It runs the reviewed-target
gate before locked build/test verification and confirms each passing step,
ending with `Verify: PASS`. When run standalone, `verify` prints a note
pointing at `audit` as the separate advisory gate; Gatehouse suppresses that
note after its audit step has passed. See
[ci.md](ci.md) for how to schedule both in CI.

The first Gatehouse step applies the same coverage floor as
`cargo barbican inventory --enforce`. It fails closed (`Inventory: FAIL`) when
a direct dependency has entered the graph without an active reviewed family —
the shape a raw `cargo add` of an unreviewed crate takes — so an uncovered
direct dependency cannot slip through CI. It enforces direct-dependency
coverage; declared execution-surface enforcement is a documented follow-up.
The pre-commit template runs the cheaper standalone floor alongside `pin check`
for earlier feedback.

## Manual Template Adoption

If `policy init` is not available, copy the templates from the pinned
cargo-barbican version instead. Review the copied files before committing them.

```bash
cp templates/barbican.toml /path/to/consumer/barbican.toml
cp templates/deny.toml /path/to/consumer/deny.toml
cp templates/reviewed-targets.toml /path/to/consumer/reviewed-targets.toml
mkdir -p /path/to/consumer/docs/dependency-reviews
cp templates/dependency-reviews/README.md /path/to/consumer/docs/dependency-reviews/README.md
```

If the consumer repo already has a `deny.toml`, keep it and review the diff
against `templates/deny.toml` manually. `policy init` follows the same
create-if-missing rule and never overwrites an existing regular file.
