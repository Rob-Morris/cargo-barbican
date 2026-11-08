# Dependency Review: nextest prerequisite follow-up installation

## Summary

- Date: 2026-11-08.
- Reviewer: delegated Codex qualification agent.
- Scope: recreate the deleted scratch installation of exact cargo-nextest 0.9.146
  for the prerequisite-ordering follow-up. This record is written before build.
  The implementation owner runs the real verification journey separately.

## Classification

Elevated-risk, inherited: external test execution, proc macros/build scripts and
mandatory vendored zstd C compilation. No product dependency or policy change.

## Targets

- crates.io `cargo-nextest =0.9.146`, `--locked --no-default-features`.
- Source archive SHA-256:
  `97c474ea32d2d16b6e93659a30b201104053ec044d48b1e52567fd038bb0f4a6`.
- Published lockfile SHA-256:
  `ba7be8ca62c4692b7f70db661eb0fcfb6691e6c9861c2f15bd5a9493b4498eff`.
- Existing trusted Rust 1.95.0, native `aarch64-apple-darwin` build.
- Owned scratch root: `/private/tmp/barbican-publish-followup.3aaYlg`;
  installation `nextest-install`, build target `nextest-target`, isolated Cargo
  home `nextest-cargo-home`, evidence `nextest-review` beneath that root.

## Inheritance

Inherits the [current bounded qualification](2026-11-08-nextest-qualification.md)
and its [exact receipt](2026-11-08-nextest-qualification.json), including original
[build/source acceptance](2026-10-14-cargo-nextest-0.9.146.md). The prior receipt
SHA-256 is `b3a5f50afb66dc2c780f01398fbb5d078a8f2a7568585408d171e540dca42ea1`.
The old installation was cleaned up; this new installation does not alter its
historical execution results.

Before compilation, fresh downloads established exact archive/index and lockfile
identity. Metadata-only locked resolution and normal/build trees re-derived
294 macOS ARM64 and 295 Linux x86_64 packages. Parsed package, source, checksum
and enabled-feature inventories compare **exactly equal** to both inventories
in the checked-in receipt. All 296 distinct registry archives across the two
graphs were individually SHA-256 checked against the published lockfile. Every
source file in the prior receipt's `source_evidence_sha256` map also matches.
No feature, transitive version, licence or source delta is accepted here.

## Release Age

Fresh crates.io sparse-index entry remains non-yanked with publication time
`2026-09-21T18:39:40Z`; over 47 days old, passing the seven-day floor.

## Advisory Review

Fresh `git ls-remote https://github.com/RustSec/advisory-db.git HEAD` returns
`309392b18f6b17022f82c701f300433126901068`, exactly the current-day review's
scanner database revision. No database or graph delta exists, so the previous
cargo-audit 0.22.1 findings and source-reachability analysis are inherited rather
than described as a new scan. Full lockfile: 20 vulnerability occurrences and
24 unsound notices; each minimal native projection: 10 vulnerability occurrences
and 24 notices. Findings remain visible in the linked receipt.

Acceptance is still only the reviewed version/ordinary fixed-run proof with
`NEXTEST_USER_CONFIG_FILE=none` and `NEXTEST_EXPERIMENTAL_RECORD=0`. The shared
verification script forces these controls. It excludes default features,
portable-recording reruns, record/replay, archive reuse and unrestricted runner
use. Original pager notices and all newer findings retain the same bounded
non-exposure evidence and **2026-11-14** deadline. No new waiver or deadline
extension is made.

## Source / Upstream Review

Exact-source inheritance preserves the earlier provenance limitations and
mandatory native zstd build surface. Registry/source digest comparisons precede
any candidate build; metadata/tree commands execute no candidate code. The
vendored product source guard passed before direct Cargo operations.

## Commands Run

Fresh source/index downloads, `git ls-remote`, SHA-256 checks, and these
metadata-only commands used the owned scratch Cargo home and trusted Rust 1.95.0:

```sh
cargo metadata --locked --no-default-features --format-version 1
cargo tree --offline --locked --no-default-features --edges normal,build \
  --target aarch64-apple-darwin --prefix none --format '{p}|{f}'
cargo tree --offline --locked --no-default-features --edges normal,build \
  --target x86_64-unknown-linux-gnu --prefix none --format '{p}|{f}'
```

Python standard-library parsing/hashing compared the inventories and source
files with the checked-in receipt. Scratch `inheritance-comparison.json` retains
these checks. The approved source installation command is:

```sh
CARGO_HOME=/private/tmp/barbican-publish-followup.3aaYlg/nextest-cargo-home \
CARGO_TARGET_DIR=/private/tmp/barbican-publish-followup.3aaYlg/nextest-target \
RUSTUP_TOOLCHAIN=1.95.0 cargo install cargo-nextest --version '=0.9.146' \
  --locked --no-default-features \
  --root /private/tmp/barbican-publish-followup.3aaYlg/nextest-install
```

## Outcome

Accepted before compilation under the unchanged bounded qualification above.
The exact source installation completed with exit 0 in 1m 13s. Its bounded
version probe also exited 0 and reports `cargo-nextest 0.9.146`, release commit
`8af696ddcce8fff2962d6a5168b6d138b8616a35`, date `2026-09-21`, host
`aarch64-apple-darwin`.

New executable SHA-256:
`a75444813bb8e2507ee01b8601257373f06e216c2ea109ebf7b0461f187888fc`.
This identifies this local build; it is not a reproducible-build claim or a
replacement for its source qualification. The normal installed executable's
post-build SHA-256 exactly matches the pre-build value below.

The qualification agent initially ran only the bounded version probe:

```sh
NEXTEST_USER_CONFIG_FILE=none NEXTEST_EXPERIMENTAL_RECORD=0 \
  /private/tmp/barbican-publish-followup.3aaYlg/nextest-install/bin/cargo-nextest nextest --version
```

At that preparation stage no real tests were run. The scratch
`inheritance-comparison.json`, `install.log` and `version.txt` retain execution
evidence. Installation log SHA-256: `cccf1d3274430eeb6d8790a37e6287e453e8bcd05aea4962d9f0705f5a4ee091`;
version-output SHA-256: `a147daa445fa0b62fd907b6e865d026c57ca9d2e385551428f9070c9252de3c7`.

After the prerequisite changes were ready, the implementation owner ran the
updated `scripts/verify-nextest.sh` with this exact isolated tool and the same
recording/configuration bounds. The macOS ARM64 `cargo-barbican` integration
target `tests/nextest.rs` passed **14 tests, 0 failures, 0 ignored and 0 filtered
out**, in 21.88s. This includes
`real_nextest_version_mismatch_blocks_build_and_tests`, which checks that the
wrong runner version blocks the fixture build and test execution. Build output
used `/private/tmp/barbican-publish-followup.3aaYlg/target`; the execution log is
`/private/tmp/barbican-publish-followup.3aaYlg/real-nextest-followup.log`, SHA-256
`8cb26a677d2485a7da034a773d0bbd57cff42591d1a1205096c6654d8e84f89b`.
This later proof does not change the pre-build acceptance, historical receipt,
qualified command scope or review deadline.

## Follow-ups

Re-review by 2026-11-14 or before any execution-scope change. The normal
nextest installation must remain unchanged; its pre-install executable SHA-256
is `45755e74d5e140b481adf5b3509bd32b7de553bcff92ca97abf6d86d1180ea00`.
