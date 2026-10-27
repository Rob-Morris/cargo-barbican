<!-- Synced from cargo-barbican v0.36.0; consumer-owned: tailor locally and review upstream diffs when upgrading. -->

# Dependency Review: <subject>

<!-- BARBICAN-REVIEW-PENDING: complete the evidence and decision below; remove this line only after deliberate review. -->

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

- Upstream record (or none — first-principles review):
- Trust model match:
- Deltas from upstream:

## Reviewed Target Set

- Active family name (not applicable for tool installs without a graph family):
- `reviewed-targets.toml` updated:
- Direct reviewed set:
- Resolved reviewed set:
  For crates.io families, record the reviewed tarball `checksum_sha256` when
  activating or changing the machine gate.
- Allowed execution surfaces:
  List any reviewed `build-rs`, `proc-macro`, or `native-sys` allowances added
  under `[rust.families.allowed_surfaces]`.
- Allowed release-age exceptions:
  List any exact too-fresh crates accepted under
  `[rust.families.allowed_age_exceptions]`, including the reviewed reason and
  the matching `resolved.checksum_sha256` entry.
- Allowed advisory exceptions:
  List any advisory acceptances recorded under
  `[rust.families.allowed_advisories]`, including the `RUSTSEC-*` id, the exact
  crate already present in the same `resolved` map, and the `review_by`
  deadline used by `audit` for re-review.

## Release Age

- Minimum policy:
- Observed publish date / age:
- Pass / fail:

## Advisory Review

- Sources checked:
- Findings:

## Source / Upstream Review

- Release notes reviewed:
- `build.rs` / `proc-macro` / `-sys` surfaces:
- Additional notes:
- For Git targets: record exact repository URL/full commit, each locked package, source permission and source/build-input review; registry inspection is not Git evidence.

## Commands Run

```bash
# commands
```

## Outcome

- Installed / updated:
- Verification:

## Follow-ups

- Remaining risks or next actions:
