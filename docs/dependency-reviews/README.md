# Dependency Review Records

This directory contains checked-in review records for every deliberate
dependency change in this repo and every dependency-tool install used by
its workflow.

The format and policy are inherited from [undertask's review process](https://github.com/rob-morris/undertask/tree/main/docs/dependency-reviews).
Records here may **inherit** from undertask's records: a record for
`serde @ 1.0.228` may cite undertask's matching record and skip the
first-principles review.

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
5. `Release Age`
6. `Advisory Review`
7. `Source / Upstream Review`
8. `Commands Run`
9. `Outcome`
10. `Follow-ups`

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
