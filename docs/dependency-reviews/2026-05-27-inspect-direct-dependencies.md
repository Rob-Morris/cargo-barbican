# Dependency Review: inspect direct dependencies

## Summary

- Date: 2026-05-27
- Reviewer: Codex
- Scope: add the direct Rust crate set for the first `cargo barbican inspect` slice: read-only tarball inspection, gzip/deflate decoding, and local SHA-256 verification

## Classification

- Routine or elevated-risk: elevated-risk
- Reason:
  - new direct Rust dependencies across the workspace
  - archive and compression parsing over untrusted bytes
  - one direct crate (`tar`) has a meaningful history of extraction and parser advisories
  - one direct crate (`sha2`) pulls transitive `unsafe` code and a small transitive `build.rs`

## Targets

- `tar` -> `0.4.46` (from `crates.io`)
- `miniz_oxide` -> `0.9.1` (from `crates.io`)
- `sha2` -> `0.10.9` (from `crates.io`)

## Inheritance

- Upstream record: first-principles
- Trust model match: not applicable
- Deltas from upstream:
  - no matching Undertask review record exists for this exact set and purpose
  - the dependency choice was narrowed during review:
    - `flate2` was rejected for this slice because the chosen pure-Rust backend still pulls `crc32fast`, which has a `build.rs` and SIMD `unsafe`
    - `libflate` was rejected because it also pulls `crc32fast` and has prior RustSec history

## Release Age

- Minimum policy: 7 days
- Observed publish date / age:
  - `tar 0.4.46` — `2026-05-18T19:12:11.033813Z` (8d old at review time)
  - `miniz_oxide 0.9.1` — `2026-03-13T00:19:26.378812Z` (75d old at review time)
  - `sha2 0.10.9` — `2025-04-30T14:38:09.894118Z` (392d old at review time)
- Pass / fail: pass

## Advisory Review

- Sources checked:
  - local RustSec advisory DB clone populated by `cargo audit`
  - crates.io version metadata for exact reviewed versions
- Findings:
  - `tar`:
    - `RUSTSEC-2018-0002` patched in `>= 0.4.16`
    - `RUSTSEC-2021-0080` patched in `>= 0.4.36`
    - `RUSTSEC-2026-0067` patched in `>= 0.4.45`
    - `RUSTSEC-2026-0068` patched in `>= 0.4.45`
    - chosen `0.4.46` is outside all affected ranges
  - `sha2`:
    - `RUSTSEC-2021-0100` patched in `>= 0.9.8`
    - chosen `0.10.9` is outside the affected range
  - transitive `generic-array 0.14.7`:
    - `RUSTSEC-2020-0146` patched in `>= 0.13.3`
    - resolved `0.14.7` is outside the affected range
  - `miniz_oxide`:
    - no RustSec entry found for `miniz_oxide`
  - rejected alternatives:
    - `libflate` has `RUSTSEC-2019-0010`
    - `flate2` itself was not adopted because its reviewed feature path still adds `crc32fast` and its `build.rs`

## Source / Upstream Review

- Release notes reviewed:
  - no separate release notes pass was needed beyond the advisory and published-source review for this first implementation slice
- `build.rs` / `proc-macro` / `-sys` surfaces:
  - `tar 0.4.46`:
    - published metadata shows `build = false`
    - no proc-macro surface
    - default `xattr` feature will be disabled
    - unconditional transitive dependencies are `filetime` and `libc`
  - `miniz_oxide 0.9.1`:
    - published metadata shows `build = false`
    - no proc-macro surface
    - chosen feature set is `default-features = false, features = ["with-alloc"]`
    - this keeps the optional `simd` feature off and leaves the dependency graph at `miniz_oxide -> adler2`
  - `sha2 0.10.9`:
    - published metadata shows `build = false`
    - no proc-macro surface
    - chosen feature set is `default-features = false, features = ["force-soft"]`
    - this avoids the hardware-accelerated runtime paths in `sha256.rs` / `sha512.rs`
    - resolved transitive `generic-array 0.14.7` has a small `build.rs` that only gates `relaxed_coherence` on compiler version via `version_check`
- Additional notes:
  - `tar 0.4.46` published provenance is present in both crates.io `trustpub_data` and the packaged `.cargo_vcs_info.json`, both pointing to `fc459c149f83bf4daceaa52e17d351989002e1a9`
  - `miniz_oxide 0.9.1` packaged `.cargo_vcs_info.json` points to `4e582392df3a739d2b0dfd2c537dc33e8942be38`
  - `sha2 0.10.9` packaged `.cargo_vcs_info.json` points to `82c36a428f8d6f05f3bfccdedb243e9d1f85359d`
  - `tar` contains substantial internal `unsafe` and historical risk is concentrated in unpack / filesystem-mutating paths; this slice will use it strictly as a read-only parser over already-verified tarball bytes and will not call `unpack`, `unpack_in`, or related extraction helpers
  - `miniz_oxide 0.9.1` states that the chosen non-`simd` path contains no `unsafe`; source inspection matched that claim
  - `sha2 0.10.9` still compiles transitive `unsafe` through `block-buffer`, `generic-array`, and target-specific helper crates, but the selected `force-soft` feature keeps the active hashing path on the pure software implementation

## Commands Run

```bash
curl -L --max-time 20 https://crates.io/api/v1/crates/tar/0.4.46
curl -L --max-time 20 https://crates.io/api/v1/crates/miniz_oxide/0.9.1
curl -L --max-time 20 https://crates.io/api/v1/crates/sha2/0.10.9
sed -n '1,240p' ~/.cargo/advisory-db/crates/tar/RUSTSEC-2018-0002.md
sed -n '1,240p' ~/.cargo/advisory-db/crates/tar/RUSTSEC-2021-0080.md
sed -n '1,240p' ~/.cargo/advisory-db/crates/tar/RUSTSEC-2026-0067.md
sed -n '1,240p' ~/.cargo/advisory-db/crates/tar/RUSTSEC-2026-0068.md
sed -n '1,240p' ~/.cargo/advisory-db/crates/sha2/RUSTSEC-2021-0100.md
sed -n '1,240p' ~/.cargo/advisory-db/crates/generic-array/RUSTSEC-2020-0146.md
rg -n 'package = "miniz_oxide"' ~/.cargo/advisory-db/crates -g 'RUSTSEC-*.md'
curl -L --max-time 20 https://crates.io/api/v1/crates/tar/0.4.46/download
curl -L --max-time 20 https://crates.io/api/v1/crates/miniz_oxide/0.9.1/download
curl -L --max-time 20 https://crates.io/api/v1/crates/sha2/0.10.9/download
tar -tzf /tmp/tar-0.4.46.crate
tar -tzf /tmp/miniz_oxide-0.9.1.crate
tar -tzf /tmp/sha2-0.10.9.crate
tar -xzf /tmp/tar-0.4.46.crate
tar -xzf /tmp/miniz_oxide-0.9.1.crate
tar -xzf /tmp/sha2-0.10.9.crate
sed -n '1,240p' /tmp/tar-0.4.46/Cargo.toml
sed -n '1,240p' /tmp/miniz_oxide-0.9.1/Cargo.toml
sed -n '1,240p' /tmp/sha2-0.10.9/Cargo.toml
sed -n '1,120p' /tmp/tar-0.4.46/.cargo_vcs_info.json
sed -n '1,120p' /tmp/miniz_oxide-0.9.1/.cargo_vcs_info.json
sed -n '1,120p' /tmp/sha2-0.10.9/.cargo_vcs_info.json
rg -n '\bunsafe\b|build = |proc-macro|asm!|global_asm!' /tmp/tar-0.4.46 -g '!tests' -g '!examples' -g '!benches'
rg -n '\bunsafe\b|build = |proc-macro|asm!|global_asm!' /tmp/miniz_oxide-0.9.1 -g '!tests' -g '!examples' -g '!benches'
rg -n '\bunsafe\b|build = |proc-macro|asm!|global_asm!' /tmp/sha2-0.10.9 -g '!tests' -g '!examples' -g '!benches'
cargo tree --edges normal
sed -n '1,220p' ~/.cargo/registry/src/index.crates.io-*/generic-array-0.14.7/build.rs
sed -n '1,220p' ~/.cargo/registry/src/index.crates.io-*/crc32fast-1.5.0/build.rs
```

## Outcome

- Installed / updated:
  - approved for addition as exact direct dependencies:
    - `tar = { version = "=0.4.46", default-features = false }`
    - `miniz_oxide = { version = "=0.9.1", default-features = false, features = ["with-alloc"] }`
    - `sha2 = { version = "=0.10.9", default-features = false, features = ["force-soft"] }`
- Verification:
  - direct and transitive advisory review completed for the chosen set
  - the chosen set intentionally avoids the rejected `flate2` / `libflate` paths and their extra build-script / advisory baggage

## Follow-ups

- keep the `inspect` implementation on the constrained paths reviewed here:
  - `tar` for read-only enumeration and file reads only
  - no archive extraction helpers
  - `miniz_oxide` without `simd`
  - `sha2` on `force-soft`
- if later slices need streaming gzip, checksum footer validation, or faster hashing, re-review that as a deliberate trust expansion rather than silently widening features
