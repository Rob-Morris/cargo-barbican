# Adopting Cargo-Barbican

This guide is for an existing Rust repository adopting cargo-barbican as a
dependency policy gate.

`cargo barbican policy init` creates policy scaffolding. It does not review,
approve, or certify the dependencies already in the repository.

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

For advisory findings that are intentionally accepted, record the exception in
the same reviewed family under `allowed_advisories` with the `RUSTSEC-*` id and
a `review_by` deadline. The crate must already be present in that family's
`resolved` map with `checksum_sha256`; `audit` reconciles findings against the
bound target, review record, and deadline before accepting the risk.

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

When reviewed-target policy is ready, run both `audit` and `verify`:

```bash
cargo barbican audit
cargo barbican verify
```

They stay two separate commands on purpose. `verify`'s verdict is a pure
function of the repo — the same manifests, lockfile, and reviewed-target
policy always produce the same result. `audit`'s verdict also depends on the
advisory landscape at the moment it runs, so a new RustSec advisory can flip
it from PASS to FAIL with no repo change at all. `verify` fails closed when
`reviewed-targets.toml` is absent, not a regular file, or configures no active
reviewed family — the gate requires at least one. It runs the reviewed-target
gate before locked build/test verification and confirms each passing step,
ending with `Verify: PASS`; immediately before that line it also prints a note
pointing at `audit` as the separate advisory gate. See
[ci.md](ci.md) for how to schedule both in CI.

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
