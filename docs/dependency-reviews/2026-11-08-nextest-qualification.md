# Dependency Review: isolated nextest 0.9.146 release proof refresh

## Summary

- Date: 2026-11-08.
- Reviewer: delegated Codex source and dependency qualification.
- Scope: rebuild the exact previously accepted external test runner into scratch
  space, then run its version check and `scripts/verify-nextest.sh`. This record
  precedes compilation. No product dependency, lockfile, policy or tool pin changes.
- The [machine-readable receipt](2026-11-08-nextest-qualification.json) retains
  exact package/checksum/feature inventories and all current scanner findings.

## Classification

Elevated-risk: test execution, proc macros/build scripts and mandatory vendored
zstd C compilation. Acceptance is only for the bounded invocation below.

## Targets

- crates.io `cargo-nextest =0.9.146`, `--locked --no-default-features`.
- Archive SHA-256: `97c474ea32d2d16b6e93659a30b201104053ec044d48b1e52567fd038bb0f4a6`.
- Published Cargo.lock SHA-256:
  `ba7be8ca62c4692b7f70db661eb0fcfb6691e6c9861c2f15bd5a9493b4498eff`.
- Trusted installed Rust 1.95.0; host `aarch64-apple-darwin`.
- Destination `/private/tmp/barbican-release.JUALo6/nextest-install`; tool build
  target and Cargo home are separate scratch directories. Default binaries and
  normal user configuration are not changed.

## Inheritance

Inherits exact source, locked graph, licences and build-surface review from
[14 October acceptance](2026-10-14-cargo-nextest-0.9.146.md). The current source
archive and sparse-index checksum exactly match that record; hence the published
manifest, lockfile and source bytes are unchanged. Metadata/tree commands did
not build or execute candidate dependencies. The normal/build graphs contain
294 macOS and 295 Linux package identities; the latter matches the original
record. All 296 distinct registry archives across these target graphs were
individually hashed against the original published lockfile checksums. The
receipt records current feature sets; root defaults, self-update and USDT remain
disabled, with no source override or lockfile update. The original raw graph
receipt is unavailable, so this is deterministic re-derivation from identical
archive/lockfile and the same compiler/feature/target inputs, not a claimed
byte comparison with a missing historical graph file.

## Release Age

Sparse-index `pubtime` remains `2026-09-21T18:39:40Z`, non-yanked. More than
47 days old: passes the seven-day floor.

## Advisory Review

Trusted installed `cargo-audit 0.22.1`, freshly cloned RustSec revision
`309392b18f6b17022f82c701f300433126901068`, committed
`2026-11-06T16:34:32+01:00`, 1,422 advisories. Audits used `--no-fetch` against
that isolated checkout with no advisory ignores or target filters. Scanner JSON
reports null database revision fields for this no-fetch checkout; the revision
above was obtained independently with `git log -1`.

The full 493-package published lockfile reports **20 vulnerability occurrences
and 24 unsound notices**. Synthetic package-only lockfile projections of each
normal/build graph report **10 vulnerability occurrences and 24 unsound
notices**. These projections preserve package identity/checksum for advisory
matching and omit dependency edges; they are audit evidence, never installation
lockfiles. Counts include findings against both zstd/zstd-safe versions. Neither
scan is described as clean. All findings, including full-lock-only findings,
are retained in the receipt.

Current bounded non-exposure findings, established from the exact downloaded
sources before compilation:

- `RUSTSEC-2026-0412` (cargo-nextest): portable-recording build-argument injection
  requires `run --rerun`/`-R` plus experimental recording. The fixed Barbican
  invocation passes no rerun selector or archive. `dispatch/core/run.rs` defines
  `rerun` without an environment binding. For this proof, explicitly set
  `NEXTEST_USER_CONFIG_FILE=none` and `NEXTEST_EXPERIMENTAL_RECORD=0` throughout.
  `nextest-runner/src/user_config/imp.rs` recognises `none` as isolated defaults;
  `experimental.rs` enables the environment switch only for exactly `1`.
  `cargo-nextest/src/dispatch/core/run.rs:1164` only creates a recording session
  when the experimental feature is enabled. This disables recording and prevents
  inherited user config from expanding the reviewed execution scope.
- `RUSTSEC-2026-0414` and `RUSTSEC-2026-0433` (pulldown-cmark 0.13.4): both require
  `ENABLE_WIKILINKS`. Build-time `clap_derive/src/utils/doc_comments.rs:235` uses
  only `ENABLE_STRIKETHROUGH`; runner `src/help_render.rs:845` uses definition
  lists and strikethrough. Neither enables wikilinks or `Options::all()`.
- `RUSTSEC-2026-0386` (Tokio 1.53.1): affected `AsyncFd` module is behind
  `cfg_net_unix!` in `src/io/mod.rs:255`; that macro requires feature `net`
  (`src/macros/cfg.rs:374`). Neither accepted target graph enables `net`.
- `RUSTSEC-2026-0410` (zstd-sys): allocator shim is compiled only for wasm32
  (`src/lib.rs:9`), excluded from both native reviewed targets.
- `RUSTSEC-2026-0391` (zstd 0.13.3 and 0.14.0), `RUSTSEC-2026-0398` and
  `RUSTSEC-2026-0403` (zstd-safe 7.2.4 and 8.0.0), and the twenty new unsound
  occurrences `RUSTSEC-2026-0395`, `0396`, `0397`, `0399`, `0400`, `0401`,
  `0402`, `0404`, `0405`, `0406` across both zstd-safe versions are outside
  this invocation's compression paths. Runner's direct zstd 0.13.3 calls occur
  under `reuse_build/{archiver,unarchiver}.rs` or `record/`; zstd 0.14.0 enters
  through eazip, whose runner runtime calls are likewise in `record/`.
  Accepted version/ordinary run commands do not request archive reuse and the
  explicit environment disables recording. No compression context or attacker
  archive enters this proof. In addition, seekable/experimental zstd-safe APIs
  implicated by several notices are absent from the minimal feature graph.
  This is command-reachability non-exposure, not a claim that compiled zstd is
  patched or that all other tool commands are safe.
- Original pager notices `RUSTSEC-2026-0190` (anyhow), `RUSTSEC-2026-0253` (lru)
  and `RUSTSEC-2026-0186` (memmap2) retain the original exact-source API analysis
  and 2026-11-14 deadline. No new pager path is enabled.

This refresh does not approve unrestricted nextest use, default features,
record/replay/rerun, archive reuse or inherited user recording configuration.
The shared `scripts/verify-nextest.sh` now exports both controls before its
version probe and real test subprocesses, so its macOS/Linux CI invocation
preserves this exact bounded scope. Unrestricted external tool use remains
outside acceptance. No product
RustSec exception is added and no scanner finding is ignored.

## Source / Upstream Review

The unchanged top-level archive inherits original tag/manifest/build-script
provenance limitations (including no verified signature claim). Registry archive
checksums bind the transitive source inspection. Mandatory `zstd-sys` vendored
C compilation remains an explicitly inherited surface; it is not a new product
native dependency. No dependency upgrades, patches or licence waivers are made.

## Commands Run

Evidence directory: `/private/tmp/barbican-release.JUALo6/nextest-review`.

```sh
curl --fail --silent --show-error https://index.crates.io/ca/rg/cargo-nextest
curl --fail --silent --show-error https://static.crates.io/crates/cargo-nextest/cargo-nextest-0.9.146.crate
git clone --depth 1 https://github.com/RustSec/advisory-db.git advisory-db
cargo +1.95.0 metadata --locked --no-default-features --format-version 1
cargo +1.95.0 tree --offline --locked --no-default-features --edges normal,build --target aarch64-apple-darwin --prefix none --format '{p}|{f}'
cargo +1.95.0 tree --offline --locked --no-default-features --edges normal,build --target x86_64-unknown-linux-gnu --prefix none --format '{p}|{f}'
cargo-audit audit --db advisory-db --no-fetch --file Cargo.lock --json
# Repeat scanner on each synthetic minimal target projection.
```

Metadata downloads used an isolated Cargo home. Python standard-library parsing
and hashing checked the sparse-index entry, archives, lockfile and inventories.
A sandboxed audit could not acquire the database lock; it was stopped, and the
same trusted scanner succeeded outside the sandbox using the isolated database.

## Outcome

Accepted before build solely for the isolated version/ordinary-run proof under
the explicit environment above, retaining the original 2026-11-14 review deadline.
Source/feature identity is inherited; current findings have bounded source
non-exposure evidence. The shared script now enforces the same bounds for the
existing macOS/Linux CI test job. Independent source review confirmed these
command and feature boundaries before completion.

Source installation completed successfully in 1m 49s with Rust 1.95.0 and the
exact locked minimal-feature registry command below. The binary reports
`cargo-nextest 0.9.146 (8af696ddc 2026-09-21)`, full commit
`8af696ddcce8fff2962d6a5168b6d138b8616a35`, host `aarch64-apple-darwin`.
Executable SHA-256:
`18d18061a9d42eb3de47adb9f201d299d45c4d18892e012757ad5dd0300bf950`.
No normal installed binary was replaced.

After another passing vendored-source guard, the actual shared verification
script passed **all 14 real subprocess tests**, zero failed/ignored/filtered,
in 21.01s. The receipt retains every test name and log digests. This covers the
required native macOS journey; Linux has source/feature/command qualification,
not a claimed local execution result. The ordinary canonical release gate
remains separate.

```sh
CARGO_HOME=/private/tmp/barbican-release.JUALo6/nextest-cargo-home \
CARGO_TARGET_DIR=/private/tmp/barbican-release.JUALo6/nextest-target \
RUSTUP_TOOLCHAIN=1.95.0 cargo install cargo-nextest --version '=0.9.146' \
  --locked --no-default-features --root /private/tmp/barbican-release.JUALo6/nextest-install
NEXTEST_USER_CONFIG_FILE=none NEXTEST_EXPERIMENTAL_RECORD=0 \
  /private/tmp/barbican-release.JUALo6/nextest-install/bin/cargo-nextest nextest --version
sh scripts/check_vendored_source.sh
PATH=/private/tmp/barbican-release.JUALo6/nextest-install/bin:$PATH \
CARGO_HOME=/Users/robmorris/.cargo \
CARGO_TARGET_DIR=/private/tmp/barbican-release.JUALo6/target \
RUSTUP_TOOLCHAIN=1.95.0 sh scripts/verify-nextest.sh
```

## Follow-ups

Re-review by 2026-11-14 or before any command, feature, target or environment
scope expansion. Prefer a separately reviewed patched runner for ongoing use;
this temporary qualification does not choose a replacement or change the pin.
