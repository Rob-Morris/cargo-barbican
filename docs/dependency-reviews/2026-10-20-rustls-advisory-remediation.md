# Dependency Review: rustls 0.23.46 advisory remediation

## Summary

- Date: 2026-10-20
- Reviewer: OpenAI Codex, with independent source-delta review.
- Scope: update transitive `rustls 0.23.45` to `0.23.46` after the release
  gate found four new advisories. Only this dependency changes in Cargo.lock.

## Classification

Elevated risk: a fresh TLS implementation with a build script. Archive
identity, source changes and consumer integration were reviewed.

## Targets

- crates.io `rustls 0.23.46`, SHA-256
  `48e13bd8c0e9365c43cfa5c9e8f9ad49d3c8444926c9aac819e0e4dc503c8fdf`.
- Path: `cargo-barbican -> ureq 3.3.0 -> rustls`.
- `rustls-webpki 0.103.15` remains unchanged.

## Inheritance

The [previous review](2026-09-15-rustls-advisory-remediation.md) supplies
baseline feature, trust-model and WebPKI evidence. The Rustls source delta
was independently reviewed here. No Subcortex implementation is involved.

## Reviewed Target Set

- Active family: `rustls-advisory-remediation-2026-10-20`.
- Direct set: none.
- Resolved set: Rustls above; unchanged WebPKI `0.103.15`, checksum
  `f3c3cf1d8b1e7d4927e2d154c3fcb02979afb9939629c62cd9048d4f07b60ac2`.
- Allowed execution surfaces: Rustls `build-rs`, unchanged script.
- Allowed age exceptions: none; remove the obsolete `0.23.45` allowance.
- Allowed advisory exceptions: none.

## Release Age

Publication: `2026-10-14T09:54:15.075873Z`, below the seven-day minimum at
review. Accept the exact security patch because waiting retains four known
findings. The inspection's age failure remains explicit; no ongoing age
exception or policy reduction is added. Age-aware commands remain governed
by the seven-day policy.

## Advisory Review

RustSec reports all four patched in `>=0.23.46`:

- [RUSTSEC-2026-0346](https://rustsec.org/advisories/RUSTSEC-2026-0346):
  session debug output can expose secrets; explicit Debug excludes them.
- [RUSTSEC-2026-0347](https://rustsec.org/advisories/RUSTSEC-2026-0347):
  ECH rejection now aborts before encrypting queued application data.
- [RUSTSEC-2026-0348](https://rustsec.org/advisories/RUSTSEC-2026-0348):
  Brotli uses strict state and requires complete input/output consumption.
- [RUSTSEC-2026-0349](https://rustsec.org/advisories/RUSTSEC-2026-0349):
  KX hints move from unauthenticated ServerHello to successful Finished.

Added tests cover secret exclusion, ECH decisions and large Brotli windows;
the delta adds no dedicated KX-hint poisoning regression. The composed
release gate supplies the final delegated advisory check.

## Source / Upstream Review

- Archive checksum independently matches crates.io. Embedded provenance:
  `f04804fa13341a9b1dc02b5d1dd8a746f2c4b7fb`; this does not independently
  verify the upstream Git commit.
- Manifests change only package version; no new dependency or feature.
  Consumer features remain `ring`, `std`, `tls12`, and `logging`.
- `build.rs` remains byte-identical, SHA-256
  `380b9a051325baa7d4957bd9a4f1a637c27a663610b1b502f9524530f6995f4d`.
  It emits nightly-only `read_buf` cfg without network, process or file I/O.
- Inspection: no proc-macro/native-FFI surface or IOC hit.
- Additional reviewed maintenance changes cover record/key-update limits,
  compressed input, ECH retries, HPKE nonce accounting, early-data PSK
  selection, certificate context, protected CCS, cache bounds and stream
  error/flush behavior. No new execution permission is needed.
- The package's own Cargo.lock updates development dependency `itertools`;
  this does not enter Barbican's graph.

## Commands Run

```sh
cargo-barbican inspect rustls@0.23.46
cargo update -p rustls --precise 0.23.46
cargo tree --locked -e features -i rustls@0.23.46
cargo test --workspace --locked
sh scripts/verify.sh
```

Inspection's age failure is expected. The final gate and tests must pass
before the release commit is made.

## Outcome

Accept the patched artefact and unchanged build-script allowance. No ignore
or source/age policy reduction is introduced.

## Follow-ups

Re-review version, checksum, feature or execution-surface changes. Upstream
tests were inspected, not run locally; static review and consumer tests do
not prove cryptographic correctness.
