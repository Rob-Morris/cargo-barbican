# Dependency Review: cargo-audit 0.22.1

## Summary

- Date: 2026-05-25
- Reviewer: Codex
- Scope: accept the already-installed `cargo-audit 0.22.1` binary for cargo-barbican's Rust dependency policy workflow

## Classification

- Routine or elevated-risk: elevated-risk
- Reason:
  - workflow tool acceptance for an executable outside the workspace
  - third-party Rust build and runtime surface even though no fresh install was needed on this machine

## Targets

- `cargo-audit` -> `0.22.1`

## Inheritance

- Upstream record: first-principles
- Trust model match: not applicable
- Deltas from upstream: no matching Undertask review record exists for this exact tool version

## Release Age

- Minimum policy: 7 days
- Observed publish date / age:
  - `cargo-audit 0.22.1` — `2026-02-04T21:08:41.110267Z` (109d old at review time)
- Pass / fail: pass

## Advisory Review

- Sources checked:
  - local RustSec advisory DB clone populated by `cargo audit`
  - `cargo audit`
- Findings:
  - no RustSec advisory entries matched `cargo-audit`
  - `cargo audit` completed successfully against cargo-barbican's resolved lockfile

## Source / Upstream Review

- Release notes reviewed:
  - no separate release notes review was needed for this bootstrap pass
- `build.rs` / `proc-macro` / `-sys` surfaces:
  - published crate metadata shows `build = false`
  - published crate metadata shows no proc-macro surface
  - published crate is the expected RustSec-maintained `cargo-audit` binary from `https://github.com/rustsec/rustsec`
- Additional notes:
  - crates.io metadata reports `Apache-2.0 OR MIT`
  - published crate metadata reports `binary-scanning` as the default feature and no suspicious feature surface beyond the tool's expected role
  - no fresh install was performed because the exact reviewed version was already present locally

## Commands Run

```bash
cargo audit --version
python3 check-crate-release-age.py --min-age-days 7 cargo-audit@0.22.1
curl -L --max-time 30 https://crates.io/api/v1/crates/cargo-audit/0.22.1
curl -L --max-time 30 https://crates.io/api/v1/crates/cargo-audit/0.22.1/download
tar -tzf /tmp/cargo-audit-0.22.1.crate
tar -xOf /tmp/cargo-audit-0.22.1.crate cargo-audit-0.22.1/Cargo.toml
rg -n 'package *= *"cargo-audit"|name *= *"cargo-audit"' ~/.cargo/advisory-db
cargo audit
```

## Outcome

- Installed / updated:
  - no repo dependency change
  - accepted existing local `cargo-audit 0.22.1` for cargo-barbican's workflow
- Verification:
  - `cargo audit --version` returned `cargo-audit 0.22.1`
  - `cargo audit` completed successfully against the resolved lockfile

## Follow-ups

- if cargo-barbican later documents a pinned tool-install command, keep it at an exact reviewed version and re-review on each tool bump
