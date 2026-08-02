# Dependency Review Records

This directory contains checked-in review records for every deliberate
dependency change in this repo and every dependency-tool install used by
its workflow.

A review record is a short, dated Markdown file that captures why one exact
crate version (or dependency tool) was accepted: its classification, the
release-age check, the advisory and source review, the commands run, and the
outcome. Each record is the durable evidence behind a single intake decision.

A first-principles review — evaluating the target on its own merits — is the
norm, and the default for any repo adopting cargo-barbican fresh. A record may
instead **inherit** from a matching prior review when the source, exact
version, and trust model all line up: it then cites that prior record and skips
repeating the first-principles work. This repo's own records inherit some
entries from undertask, the private predecessor project cargo-barbican grew out
of; a repo with no such predecessor simply records first-principles reviews and
leaves the inheritance fields empty.

For later checked-pin enforcement, the machine-readable companion file is
`reviewed-targets.toml` at the repo root. Active Rust families there carry:

- `name` — stable family label used by the review record and later tooling
- `review_record` — checked-in Markdown record that activated the family
- optional `direct` — exact manifest requirements for direct crates, including
  the leading `=`
- `resolved` — exact `Cargo.lock` targets; for crates.io reviewed artefacts the
  preferred form is `{ version = "...", checksum_sha256 = "..." }`
- optional `allowed_surfaces` — reviewed `build-rs`, `proc-macro`, or
  `native-sys` execution surfaces for crates already present in the same
  `resolved` map
- optional `allowed_advisories` — reviewed advisory exceptions for crates
  already present in the same `resolved` map, recorded as `{ id, review_by }`
  entries with a `RUSTSEC-*` id and a re-review deadline

When a crates.io family carries `checksum_sha256`, `pin check` reconciles that
digest against the resolved `Cargo.lock` checksum chain as part of the local
execution gate.

When a reviewed family carries `allowed_surfaces`, `assess` can suppress the
matching execution-surface elevated-risk signal while still rendering the
reviewed exception in an `Allowed policy exceptions:` section. The family
`review_record` is the evidence path for those allowances.

When a reviewed family carries `allowed_advisories`, `audit` can accept the
matching advisory finding only while the resolved crate/version/checksum still
matches, the family review record is a completed review (non-empty and no
longer carrying the `BARBICAN-REVIEW-PENDING` scaffold marker), and `review_by`
has not expired. Once the deadline is past, `audit` fails the exception and
requires re-review.

`inspect` can supply evidence for a review record, but it does not by itself
activate an entry in `reviewed-targets.toml`.

## When to add a record

- Adding any direct dependency to a workspace `Cargo.toml`.
- Updating a direct dependency version.
- Installing a dependency-tool (`cargo-audit`, `cargo-deny`).
- Changes to `deny.toml`.

## Naming

```
YYYY-MM-DD-short-subject.md
```

## Required sections

1. `Summary`
2. `Classification` (routine / elevated-risk)
3. `Targets`
4. `Inheritance` (cite upstream record, or "first-principles")
5. `Reviewed Target Set` when the review activates or changes a family in
   `reviewed-targets.toml`
6. `Release Age`
7. `Advisory Review`
8. `Source / Upstream Review`
9. `Commands Run`
10. `Outcome`
11. `Follow-ups`

## Template

```md
# Dependency Review: <subject>

## Summary

- Date:
- Reviewer:
- Scope:

## Classification

- Routine or elevated-risk:
- Reason:

## Targets

- `<crate>` -> `<exact-version>` (from `crates.io`)

## Inheritance

- Upstream record:
- Trust model match:
- Deltas from upstream:

## Reviewed Target Set

- Active family name:
- `reviewed-targets.toml` updated:
- Direct reviewed set:
- Resolved reviewed set:
  For crates.io families, record the reviewed tarball `checksum_sha256` when
  activating or changing the machine gate.
- Allowed execution surfaces:
  List any reviewed `build-rs`, `proc-macro`, or `native-sys` allowances added
  under `[rust.families.allowed_surfaces]`.
- Allowed advisory exceptions:
  List any reviewed advisory acceptances added under
  `[rust.families.allowed_advisories]`, including the `RUSTSEC-*` id, the
  affected exact crate already present in `resolved`, and the `review_by`
  re-review deadline.

## Release Age

- Minimum policy: 7 days
- Observed publish date / age:
- Pass / fail:

## Advisory Review

- Sources checked:
- Findings:

## Source / Upstream Review

- Release notes reviewed:
- `build.rs` / `proc-macro` / `-sys` surfaces:
- Additional notes:

## Commands Run

```bash
# commands
```

## Outcome

- Installed / updated:
- Verification:

## Follow-ups

- Remaining risks or next actions:
```
