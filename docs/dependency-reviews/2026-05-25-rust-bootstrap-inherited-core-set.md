# Dependency Review: Rust bootstrap inherited core set

## Summary

- Date: 2026-05-25
- Reviewer: Codex
- Scope: add the inherited direct Rust crate set needed for cargo-barbican's first implementation tranche, alongside separately reviewed `time` and `ureq` boundaries, and pin `serde_json` back to the reviewed age-compliant exact version when the first lockfile resolution floated forward

## Classification

- Routine or elevated-risk: elevated-risk
- Reason:
  - new direct Rust dependencies across the workspace
  - expected proc-macro surface via `clap_derive`, `serde_derive`, and `thiserror-impl`

## Targets

- direct dependencies:
  - `serde` -> `1.0.228`
  - `serde_json` -> `1.0.149`
  - `thiserror` -> `2.0.18`
  - `toml` -> `1.1.2+spec-1.1.0`
  - `clap` -> `4.6.1`
- resulting lockfile pin adjusted back to the reviewed compatible version:
  - `serde_json` -> `1.0.149`

## Inheritance

- Upstream record:
  - Undertask `2026-05-21-rust-clap-tokio-elevated.md` for `clap 4.6.1`, `serde 1.0.228`, `serde_json 1.0.149`, and `thiserror 2.0.18`
  - Undertask `2026-05-21-rust-remaining-direct-refresh.md` for `toml 1.1.2+spec-1.1.0`
- Trust model match:
  - yes; same crates.io sources, same exact direct versions, same 7-day age gate, and the same high-scrutiny treatment for proc-macro surface
- Deltas from upstream:
  - cargo-barbican resolves a smaller workspace graph
  - the HTTP and time boundaries are reviewed separately here as first-principles choices:
    - `docs/dependency-reviews/2026-05-25-ureq-3.3.0.md`
    - `docs/dependency-reviews/2026-05-26-time-0.3.47.md`
  - the first naive resolution in cargo-barbican selected `serde_json 1.0.150`, which was too fresh for the 7-day gate
  - the lockfile was pinned back to `serde_json 1.0.149`, matching the already accepted Undertask version

## Release Age

- Minimum policy: 7 days
- Observed publish date / age:
  - direct dependencies:
    - `serde 1.0.228` — `2025-09-27T16:51:35.265429Z`
    - `serde_json 1.0.149` — `2026-01-06T16:23:34.585926Z`
    - `thiserror 2.0.18` — `2026-01-18T16:14:37.836574Z`
    - `toml 1.1.2+spec-1.1.0` — `2026-04-01T21:24:09.084250Z`
    - `clap 4.6.1` — `2026-04-15T18:59:05.142929Z`
  - age-gate-driven lockfile pin:
    - `serde_json 1.0.149` — `2026-01-06T16:23:34.585926Z`
- Pass / fail: pass after pinning the lockfile back to that compatible reviewed version

## Advisory Review

- Sources checked:
  - inherited Undertask records
  - `cargo audit`
  - `cargo deny check advisories bans sources`
- Findings:
  - `cargo audit` completed successfully against cargo-barbican's resolved lockfile
  - `cargo deny check advisories bans sources` returned `advisories ok, bans ok, sources ok`
  - no blocking advisory or source-policy findings remained after the pin

## Source / Upstream Review

- Release notes reviewed:
  - inherited Undertask review for the exact direct versions
- `build.rs` / `proc-macro` / `-sys` surfaces:
  - elevated assessor returned `elevated-risk`, not `policy-violating`, after the pin
  - expected proc-macro surface:
    - `clap_derive 4.6.1`
    - `serde_derive 1.0.228`
    - `thiserror-impl 2.0.18`
- Additional notes:
  - the elevated assessor's initial run was valuable: it caught the too-fresh `serde_json 1.0.150` before any build step was trusted
  - cargo-barbican's final inherited direct dependency set matches the intended reviewed versions exactly:
    - `serde 1.0.228`
    - `serde_json 1.0.149`
    - `thiserror 2.0.18`
    - `toml 1.1.2+spec-1.1.0`
    - `clap 4.6.1`
  - the final workspace direct tree also includes the separately reviewed first-principles boundaries:
    - `time 0.3.47`
    - `ureq 3.3.0`

## Commands Run

```bash
python3 /Users/robmorris/Development/undertask/scripts/check-crate-release-age.py --min-age-days 7 \
  serde@1.0.228 \
  serde_json@1.0.149 \
  clap@4.6.1 \
  thiserror@2.0.18 \
  toml@1.1.2+spec-1.1.0

cargo generate-lockfile

python3 /Users/robmorris/Development/undertask/scripts/check-cargo-lock-release-age.py --min-age-days 7 --base-ref HEAD
python3 /Users/robmorris/Development/undertask/scripts/assess-dependency-update.py --ecosystem rust --policy-mode elevated-risk

cargo tree -i serde_json
cargo update -p serde_json --precise 1.0.149

python3 /Users/robmorris/Development/undertask/scripts/check-cargo-lock-release-age.py --min-age-days 7 --base-ref HEAD
python3 /Users/robmorris/Development/undertask/scripts/assess-dependency-update.py --ecosystem rust --policy-mode elevated-risk

cargo tree --depth 1
cargo audit
cargo deny check advisories bans sources
cargo build --locked --target-dir docs/.cargo-target
cargo test --locked --target-dir docs/.cargo-target
```

## Outcome

- Installed / updated:
  - added the inherited direct set to:
    - `crates/barbican/Cargo.toml`
    - `crates/cargo-barbican/Cargo.toml` (`clap`)
  - generated `Cargo.lock`
  - pinned `serde_json` back to the reviewed age-compliant exact version
- Verification:
  - inherited direct tree summary:
    - `serde 1.0.228`
    - `serde_json 1.0.149`
    - `thiserror 2.0.18`
    - `toml 1.1.2+spec-1.1.0`
    - `clap 4.6.1`
  - the final workspace direct tree also includes separately reviewed `time 0.3.47` and `ureq 3.3.0`
  - lockfile age gate passed after the pin
  - elevated assessor returned `elevated-risk` only, with no blocking policy findings
  - `cargo audit` completed successfully
  - `cargo deny check advisories bans sources` returned `advisories ok, bans ok, sources ok`
  - `cargo build --locked --target-dir docs/.cargo-target` passed
  - `cargo test --locked --target-dir docs/.cargo-target` passed

## Follow-ups

- keep the current `serde_json` pin until a deliberate later review moves it again
- when cargo-barbican starts using these crates in earnest, preserve the reason each crate exists so later dependency pruning remains straightforward
