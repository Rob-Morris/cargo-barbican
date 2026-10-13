# Dependency Review: cargo-nextest 0.9.146 test runner

## Summary

- Date: 2026-10-14
- Reviewer: Codex first-principles review, independently delegated by the implementation owner.
- Scope: exact external, test-only development/CI tool; no new Barbican Cargo dependency and no library integration. Source installation must use `--version '=0.9.146' --locked --no-default-features`.

## Classification

- Elevated-risk.
- Reason: executes Cargo and reviewed test binaries, has build scripts/proc macros and a mandatory native zstd surface; the published all-features lockfile contains advisory findings. Acceptance is scoped to the minimal-feature tool graph and the version/run commands, not an assertion that the full upstream lockfile is clean.

## Targets

- `cargo-nextest` -> `0.9.146` from crates.io, exact version requirement `=0.9.146`.
- Published archive SHA-256: `97c474ea32d2d16b6e93659a30b201104053ec044d48b1e52567fd038bb0f4a6`, matches the crates.io sparse index entry.
- Downloaded runner archive SHA-256 `5374974ef7c8ca7d0268fe48cd843041132580b26dd2ea3006c18cb4ef11a702` matches its published lockfile entry.
- Published exact runner components: `nextest-filtering =0.22.0`, `nextest-metadata =0.15.0`, `nextest-runner =0.124.0`.
- Rust MSRV 1.91; compatible with this repo's exact Rust 1.95.0 toolchain.

## Inheritance

- First-principles; no inherited trust record.
- Existing local cargo-nextest 0.9.128 is not endorsed for fresh installation.

## Release Age

- Minimum policy: 7 days.
- Sparse-index `pubtime`: `2026-09-21T18:39:40Z`; non-yanked; age at review date exceeds 22 days: pass.
- Alternative 0.9.148 published `2026-10-08T03:34:31Z` remains under seven days at this review. Its full lockfile still has three vulnerabilities and the same three unsound notices, so its minimal graph provides no reason to waive quarantine.

## Advisory Review

- Scanner: installed `cargo-audit`; RustSec database 1,310 advisories, commit `6aed84668c23d7f535077a9fe918bf1fa0f6a5bc`, last updated `2026-10-13T17:07:33+02:00`.
- The published 493-package Cargo.lock scan fails with four vulnerabilities. None occurs in the `--no-default-features`, normal/build graph for either `aarch64-apple-darwin` or `x86_64-unknown-linux-gnu`:
  - `RUSTSEC-2026-0258`: h2 0.4.10, patched >=0.4.16. Absent from the accepted graph; retained for optional experimental console dependencies in the full lockfile.
  - `RUSTSEC-2026-0194` and `RUSTSEC-2026-0195`: quick-xml 0.38.4, patched >=0.41.0. Vulnerable version belongs to optional self-update; accepted JUnit dependency uses quick-xml 0.41.0.
  - `RUSTSEC-2026-0285`: rustls 0.23.43, patched >=0.23.45. Optional self-update TLS dependency; absent from the accepted graph.
- A scanner-parsable projection of the published lockfile to the 295 Linux normal/build package identities returned by `cargo tree` also reports zero vulnerabilities and exactly the three notices below. This projection is synthetic feature-reachability evidence, not a changed install lockfile or a claim about the full published lockfile.
- Three unsoundness notices are compiled into the minimal graph via the mandatory builtin pager dependency. Each is accepted only on the API-reachability evidence below, not hidden or globally ignored:
  - `RUSTSEC-2026-0190`: anyhow 1.0.98 via termwiz 0.23.3 -> sapling-streampager 0.12.0. Affected API is `Error::downcast_mut` after context. No `downcast_mut` call exists in the reviewed Cargo-nextest, nextest-runner, termwiz or streampager sources.
  - `RUSTSEC-2026-0253`: lru 0.16.3 via sapling-streampager 0.12.0. Vulnerability requires `LruCache::pop()` with a panicking key Drop and later cache use after caught unwind. Pager caches have keys `usize` or `(usize, WrappingMode)`, neither has a Drop implementation, and the reviewed pager sources do not call `LruCache::pop()`.
  - `RUSTSEC-2026-0186`: memmap2 0.9.8 via sapling-streampager 0.12.0. Affected range advise/flush APIs do not occur in pager sources: uses are anonymous/file mapping constructors and access, not range advise/flush.
- Successful `run` and `--version` do not instantiate a pager. This is an additional scope boundary, not the sole justification for the three notices; help/list/store commands have pager paths.
- This record does not alter Barbican's own RustSec exception policy or reviewed-target graph. Re-review this tool acceptance by 2026-11-14, or before enabling default features, self-update, tracing, archive reuse or other nextest commands.

## Source / Upstream Review

- Upstream: https://github.com/nextest-rs/nextest ; release notes: https://www.nexte.st/changelog/ . Version 0.9.146 fixes dependencies previously pointing to yanked chacha20/der releases.
- Published `Cargo.toml.orig` and `build.rs` byte-match the public `cargo-nextest-0.9.146` tag. The normalised manifest pins nextest's three companion crates exactly.
- The tag is an annotated tag at `59c08abdc0ef6a0538f2c2fcb62ebe53321fff60`, targeting release commit `8af696ddcce8fff2962d6a5168b6d138b8616a35`; published `nextest-commit-info` agrees. Published `.cargo_vcs_info.json` separately records packaging commit `63a8eb6db492ee6735444b8d82ab50e4d8585000`; its raw source URL returned 404. Provenance established here is checksum plus released manifest/build-script parity, not full archive/repository equality or a verified signature. GitHub reports the tag signature as unverified (`bad_cert`); no signature trust claim is made.
- Cargo-nextest's build.rs only embeds target and Git/release metadata; optional `git log` requires a sibling `.git`. No network fetch or native build occurs in that script.
- `--no-default-features` removes self-update HTTP/TLS, aws-lc native crypto and platform USDT tracing dependencies. Upstream's `default-no-update` still enables USDT, so it is not the smallest feature set.
- Mandatory native surface remains `zstd-sys 2.1.0+zstd.1.5.7` through archive support. Its build script compiles the vendored zstd C tree using cc, or honours explicit pkg-config/system-library selection; no build-time download was observed in the reviewed script. Cargo compilation therefore requires a normal C toolchain even for this reduced external-tool build. It is not a native dependency of Barbican itself.
- Macro/build-time surfaces include Cargo-nextest's own build.rs and normal derive dependencies (clap, serde, thiserror, tokio, miette, tracing and the pager's derive stack). Workspace-hack build scripts are empty and exist to retain Cargo build dependency consideration.
- Source inspection confirms `run --locked --retries 0 --profile default --ignore-default-filter --no-tests pass --fail-fast` is supported. CLI values override corresponding NEXTEST environment defaults; no external filter/partition/test-name argument is forwarded.
- Cargo-nextest uses the `CARGO` environment variable for its Cargo subprocess. Barbican must supply its already checked exact Cargo path and preserve the existing compiler-control preflight; clearing only inherited CARGO and relying on PATH is weaker.
- Nextest runs reviewed test binaries and honours Cargo runners and nextest setup scripts/configuration. Per-test process separation is an execution model, not a sandbox for shared files, services or subprocesses. Doctests remain a separate `cargo test --locked --doc` step.

## Commands Run

```bash
# Review directory: /private/tmp/barbican-nextest-review-0146
curl --fail --silent --show-error https://index.crates.io/ca/rg/cargo-nextest -o index.jsonl
curl --fail --silent --show-error https://static.crates.io/crates/cargo-nextest/cargo-nextest-0.9.146.crate -o cargo-nextest-0.9.146.crate
shasum -a 256 cargo-nextest-0.9.146.crate
tar -xzf cargo-nextest-0.9.146.crate
# Within the extracted crate:
cargo audit --file Cargo.lock --json
cargo metadata --locked --no-default-features --format-version 1
cargo tree --locked --no-default-features --edges normal,build --target aarch64-apple-darwin
cargo tree --locked --no-default-features --edges normal,build --target x86_64-unknown-linux-gnu
cargo tree --locked --no-default-features --edges normal,build -i anyhow
cargo tree --locked --no-default-features --edges normal,build -i lru
cargo tree --locked --no-default-features --edges normal,build -i memmap2
# Reviewed release-tag manifest/build.rs, core nextest-runner manifest/source,
# pager sources, zstd-sys build.rs and feature graph using cat, cmp and rg.
# Also checksum-verified and audited published 0.9.148 for comparison.
# Projected the Linux normal/build package identities to a temporary scanner
# lockfile (not used for installation), then scanned it with:
cargo audit --file minimal-linux.Cargo.lock --no-fetch --json
# Isolated source install after the scoped review record was written:
cargo +1.95.0 install cargo-nextest --version '=0.9.146' --locked --no-default-features --root /private/tmp/barbican-nextest-install-0146
/private/tmp/barbican-nextest-install-0146/bin/cargo-nextest nextest --version
# In ordinary and empty dependency-free fixtures:
NEXTEST_PROFILE=missing NEXTEST_RETRIES=2 NEXTEST_NO_TESTS=fail RUSTUP_TOOLCHAIN=1.95.0 /private/tmp/barbican-nextest-install-0146/bin/cargo-nextest nextest run --locked --retries 0 --profile default --ignore-default-filter --no-tests pass --fail-fast
cargo +1.95.0 test --locked --doc
```

## Outcome

- Accepted for source installation as an exact external test-only CI/development tool with `--locked --no-default-features`, accepted by the implementation owner after reviewing the advisory scope. Full default-feature installation is not accepted by this record.
- Installed / updated: source-built with Rust 1.95.0 into fresh isolated `/private/tmp/barbican-nextest-install-0146`, using exact `--version '=0.9.146' --locked --no-default-features`; no change to `~/.cargo/bin` or Barbican manifests. Release compilation completed in 4m 14s.
- Observed executable: `/private/tmp/barbican-nextest-install-0146/bin/cargo-nextest`; `nextest --version` reports 0.9.146, commit `8af696ddcce8fff2962d6a5168b6d138b8616a35`, commit-date 2026-09-21, host aarch64-apple-darwin. The output contains a first version line and additional release/commit/host fields, rather than one line.
- Verification: archive checksum, publish-age and non-yanked status verified; exact published lockfile advisory evidence and minimal normal/build graphs reviewed; required flags and Cargo selection behaviour checked from source. Real tool fixture validation passed with every fixed run flag. Inherited `NEXTEST_PROFILE=missing`, `NEXTEST_RETRIES=2`, `NEXTEST_NO_TESTS=fail` and checked-in profile default-filter `none()` were overridden as intended: one test ran and passed. Its separate Cargo doctest also passed. An empty binary fixture passed nextest with zero tests; the direct unconditional Cargo doctest command failed with `no library targets found`, confirming the need for conditional doctest-target discovery in Barbican. Barbican real-subprocess integration coverage remains the implementation owner's verification responsibility.

## Follow-ups

- Finish Barbican real-subprocess integration verification with ordinary, binary-only, empty, doctest-only and doctest-disabled packages plus hostile inherited Cargo/compiler controls. Direct tool flag and empty-suite behaviour have been checked above.
- Re-review by 2026-11-14, or before expanding the accepted features/command scope. Prefer a later quarantined upstream release that patches the three pager advisories when available.
- Continue auditing the external tool independently: the project Cargo.lock gate does not scan dependencies compiled into a separately installed tool.
