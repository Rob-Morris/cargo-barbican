# Dependency Review: cargo-barbican self-adoption reviewed targets

## Summary

- Date: 2026-06-08
- Reviewer: Codex
- Scope: adopt cargo-barbican's own reviewed-target policy inside this repo by exact-pinning existing direct dependencies, adding root `reviewed-targets.toml`, and enforcing reviewed resolved artefact checksums through `cargo barbican verify`

## Classification

- Routine or elevated-risk: elevated-risk
- Reason:
  - policy-enforcement change for a security-policy tool
  - tightens existing dependency requirements and CI verification semantics
  - adds reviewed execution-surface allowances for already-reviewed proc-macro crates
  - does not add any new dependency source code

## Targets

- Direct manifest requirements tightened:
  - `serde` -> `=1.0.228`
  - `serde_json` -> `=1.0.149`
  - `thiserror` -> `=2.0.18`
  - `time` -> `=0.3.47`
  - `toml` -> `=1.1.2`
  - `clap` -> `=4.6.1`
  - `ureq` -> `=3.3.0`
- Already-exact direct dependencies reaffirmed in policy:
  - `miniz_oxide` -> `=0.9.1`
  - `sha2` -> `=0.10.9`
  - `tar` -> `=0.4.46`
  - `similar` -> `=3.1.1`
- Reviewed execution-surface allowances added for resolved proc-macro crates:
  - `serde_derive 1.0.228`
  - `thiserror-impl 2.0.18`
  - `clap_derive 4.6.1`

## Inheritance

- Upstream records:
  - `docs/dependency-reviews/2026-05-25-rust-bootstrap-inherited-core-set.md`
  - `docs/dependency-reviews/2026-05-25-ureq-3.3.0.md`
  - `docs/dependency-reviews/2026-05-26-time-0.3.47.md`
  - `docs/dependency-reviews/2026-05-27-inspect-direct-dependencies.md`
  - `docs/dependency-reviews/2026-05-30-similar-3.1.1.md`
- Trust model match:
  - yes; this change strengthens enforcement over the same reviewed dependency set rather than accepting new code
- Deltas from upstream:
  - direct manifest requirements are now exact where they were previously broad semver ranges
    - `serde`, `serde_json`, `thiserror`, `toml`, and `clap` inherit source review from the bootstrap core-set record and are tightened here rather than by rewriting that historical record
    - `time` and `ureq` inherit source review from their per-dependency records and are tightened here rather than by rewriting those historical records
  - root `reviewed-targets.toml` now enforces resolved versions and SHA-256 checksums
  - `cargo barbican verify` can now run in this repo without the off-main `--vanilla` fallback

## Release Age

- Minimum policy: 7 days
- New crates introduced: none
- Pass / fail:
  - not re-assessed as new dependency intake; all targets inherit existing reviewed dependency records

## Advisory Review

- Sources checked:
  - inherited dependency review records
  - `cargo barbican audit`
  - `cargo barbican verify`
- Findings:
  - no new dependency source was added
  - `cargo barbican audit` completed successfully through `scripts/verify.sh`
  - `cargo barbican verify` completed successfully with the new reviewed-target policy

## Source / Upstream Review

- Release notes reviewed:
  - not applicable; this is a policy adoption and pinning change over already-reviewed versions
- `build.rs` / `proc-macro` / `-sys` surfaces:
  - direct source review inherited from the existing records
  - reviewed-target allowances are deliberately attached to the actual resolved proc-macro crates:
    - `serde_derive`
    - `thiserror-impl`
    - `clap_derive`
  - allowances are not attached to parent packages such as `serde`, `thiserror`, or `clap`
- Additional notes:
  - `toml` has a semver metadata nuance:
    - manifest-safe direct requirement is `=1.1.2`
    - resolved reviewed target is `1.1.2+spec-1.1.0` with checksum
  - exact pins are deliberately brittle: if a future transitive dependency requires a newer patch of a shared direct crate, resolution should fail until the manifest and reviewed-target policy are deliberately updated
  - checksum coverage in this first self-adoption policy is direct reviewed dependencies plus the proc-macro surface crates with explicit allowances; the broader transitive graph remains bound by `Cargo.lock --locked`, `cargo audit`, and `cargo deny`
  - the policy is grouped by existing review records rather than collapsed into one flat family, so future drift points back to the review decision that admitted each family
  - `reviewed-targets.toml` enforces resolved SHA-256 checksums for all listed crates.io artefacts

## Commands Run

```bash
cargo metadata --locked --format-version 1
cargo run --locked --bin cargo-barbican -- pin-check
cargo run --locked --bin cargo-barbican -- verify
cargo run --locked --bin cargo-barbican -- assess --policy-mode elevated-risk
sh scripts/verify.sh
sh scripts/check_doc_versions.sh --worktree
git diff --check
```

## Outcome

- Installed / updated:
  - added root `reviewed-targets.toml`
  - exact-pinned all direct registry dependencies in:
    - `crates/barbican/Cargo.toml`
    - `crates/cargo-barbican/Cargo.toml`
  - added reviewed-target checksum enforcement for the current reviewed direct families
  - added reviewed proc-macro allowances for the actual resolved proc-macro crates
  - added `scripts/verify.sh` as the repo-level verification entry point
- Verification:
  - `cargo barbican pin-check` passed
  - `cargo barbican verify` passed
  - `cargo barbican assess --policy-mode elevated-risk` reported `routine-safe`
  - `scripts/verify.sh` passed with normal Cargo advisory/cache access
  - `scripts/check_doc_versions.sh --worktree` passed
  - `git diff --check` passed

## Follow-ups

- Keep future dependency updates flowing through the reviewed-target policy rather than broadening manifest requirements casually.
- If a future command generates reviewed-target drafts, it should preserve the distinction between manifest-safe direct requirements and lockfile resolved versions with semver metadata.
- Inventory/onboarding tooling should identify execution surfaces on the resolved packages that actually provide them, not only on their direct parent dependencies.
