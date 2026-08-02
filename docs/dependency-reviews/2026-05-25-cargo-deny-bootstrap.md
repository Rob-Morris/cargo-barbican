# Dependency Review: cargo-deny bootstrap

## Summary

- Date: 2026-05-25
- Reviewer: Codex
- Scope: accept `cargo-deny 0.19.6` for workflow use in cargo-barbican and import the matching baseline `deny.toml` policy from Undertask

## Classification

- Routine or elevated-risk: elevated-risk
- Reason:
  - workflow tool acceptance for an executable outside the workspace
  - repo policy bootstrap via a new `deny.toml`

## Targets

- `cargo-deny` -> `0.19.6`
- `deny.toml` -> imported baseline from Undertask

## Inheritance

- Upstream record:
  - Undertask `2026-05-21-cargo-deny-0.19.6.md`
- Trust model match:
  - yes; same crates.io source, same exact tool version, and the same advisories / bans / sources role in the Rust routine workflow
- Deltas from upstream:
  - Undertask accepted `0.19.6` under an explicit 10-day tool-install exception on 2026-05-21
  - cargo-barbican accepted the same exact version after it had aged past the default 7-day minimum
  - cargo-barbican imports the generic deny baseline without Undertask-specific app policy additions

## Release Age

- Minimum policy: 7 days
- Observed publish date / age:
  - `cargo-deny 0.19.6` — `2026-05-11T10:50:10.984569Z` (13d old at review time)
- Pass / fail: pass

## Advisory Review

- Sources checked:
  - inherited Undertask review
  - local `cargo-deny` run against cargo-barbican
  - local RustSec advisory DB search
- Findings:
  - no RustSec advisory entries matched `cargo-deny`
  - `cargo deny check advisories bans sources` returned `advisories ok, bans ok, sources ok` on cargo-barbican's resolved lockfile

## Source / Upstream Review

- Release notes reviewed:
  - inherited Undertask review for `0.19.6`
- `build.rs` / `proc-macro` / `-sys` surfaces:
  - inherited Undertask source review for the exact tool version
  - imported `deny.toml` is a plain repo policy file, not executable code
- Additional notes:
  - imported `deny.toml` matches the generic Undertask baseline:
    - deny unknown registries and unknown git sources
    - deny yanked crates
    - warn on multiple versions
    - allow only the crates.io index

## Commands Run

```bash
cargo deny --version
python3 check-crate-release-age.py --min-age-days 7 cargo-deny@0.19.6
rg -n 'package *= *"cargo-deny"|name *= *"cargo-deny"' ~/.cargo/advisory-db
cargo deny check advisories bans sources
```

## Outcome

- Installed / updated:
  - no fresh tool install was needed on this machine
  - imported `deny.toml` into the cargo-barbican repo root
  - accepted existing local `cargo-deny 0.19.6` for workflow use
- Verification:
  - `cargo deny --version` returned `cargo-deny 0.19.6`
  - `cargo deny check advisories bans sources` returned `advisories ok, bans ok, sources ok`

## Follow-ups

- if cargo-barbican later needs repo-specific deny policy beyond the inherited baseline, review that `deny.toml` change as its own deliberate dependency-policy update
