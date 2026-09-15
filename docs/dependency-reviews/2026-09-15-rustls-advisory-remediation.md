# Dependency Review: rustls 0.23.45 advisory remediation

## Summary

- Date: 2026-09-15
- Reviewer: OpenAI Codex; release-age exception requested by the repository
  owner on 2026-09-15
- Scope: remediate `RUSTSEC-2026-0285` in cargo-barbican's crates.io HTTPS path
  by updating `rustls` from `0.23.40` to `0.23.45`. Cargo also updates the
  coupled `rustls-webpki` package from `0.103.13` to `0.103.15`.

## Classification

- Routine or elevated-risk: elevated-risk
- Reason: `rustls 0.23.45` was less than one day old at review, below the
  seven-day quarantine, and declares `build.rs`. It is also the first patched
  version for a live moderate-severity TLS state-machine advisory. The exact
  artefacts, cumulative changes, build surface and cargo-barbican integration
  were reviewed before accepting a checksum-bound age exception.

## Targets

- `rustls` -> `0.23.45` (from crates.io), resolved through
  `cargo-barbican` -> `ureq 3.3.0`; active features are `ring`, `std`, `tls12`
  and `logging`.
- `rustls-webpki` -> `0.103.15` (from crates.io), resolved with `rustls`.

The update changes no manifest requirement and moves only these two lockfile
packages.

## Inheritance

- Upstream record: Subcortex
  `docs/dependency-reviews/2026-09-15-rustls-advisory-remediation.md`, committed
  as `4e7d5823` and released in `subcortex-stable/v0.97.5`.
- Trust model match: both consumers use the exact same crates.io artefacts and
  checksums with Rustls' `ring`, `std` and `tls12` features in an HTTPS client.
- Deltas from upstream:
  - cargo-barbican reaches Rustls through `ureq` rather than
    `reqwest` / `hyper-rustls`
  - cargo-barbican also activates Rustls' `logging` feature; this adds the
    `log` facade but does not enable key logging, and Rustls retains
    `NoKeyLog` by default
  - cargo-barbican starts from `rustls 0.23.40`, so the `0.23.41` and `0.23.42`
    changes were reviewed in addition to the Subcortex `0.23.42` baseline

The material inherited evidence is reproduced below so this public record does
not rely on access to the Subcortex repository.

## Reviewed Target Set

- Active family name: `rustls-advisory-remediation-2026-09-15`
- `reviewed-targets.toml` updated: yes
- Direct reviewed set: none; both packages are transitive.
- Resolved reviewed set:
  - `rustls` `0.23.45`, checksum
    `0d41d731c7d2f962d1ccc364cec258de3c0e93b38c2fb3ba97ac74513048d634`
  - `rustls-webpki` `0.103.15`, checksum
    `f3c3cf1d8b1e7d4927e2d154c3fcb02979afb9939629c62cd9048d4f07b60ac2`
- Allowed execution surfaces: `rustls = ["build-rs"]`; the reviewed script is
  byte-identical to `0.23.42` and only emits `cargo:rustc-cfg=read_buf` for a
  nightly compiler.
- Allowed release-age exceptions: `rustls = "0.23.45"`, exact-version and
  checksum bound. It becomes inert when the release reaches seven days old.
- Allowed advisory exceptions: none. This update fixes the advisory instead of
  accepting it.

## Release Age

- Minimum policy: seven days.
- `rustls 0.23.45`: published `2026-09-14T15:11:17.808465Z`; less than one day
  old at review. Fail, explicitly accepted because waiting leaves the live
  crates.io TLS client on a version affected by `RUSTSEC-2026-0285`.
- `rustls-webpki 0.103.15`: published `2026-08-21T16:40:00.687282Z`; more than
  three weeks old at review. Pass.

## Advisory Review

- [`RUSTSEC-2026-0285` / `GHSA-2mjx-qc3c-rqvc`](https://github.com/rustls/rustls/security/advisories/GHSA-2mjx-qc3c-rqvc),
  "TLS 1.3 handshake messages incorrectly accepted across encryption-level
  boundaries", affects Rustls `0.23.13` through `0.23.44` and is fixed in
  `0.23.45`. Severity is moderate (CVSS 5.3).
- The affected path is `cargo-barbican` -> `ureq 3.3.0` -> `rustls 0.23.40`.
- An exact candidate audit with the current local RustSec database reports no
  vulnerability after the update.
- No advisory exception is introduced.

## Source / Upstream Review

- Provenance: `rustls` git commit
  `2976d90fd1c2db6b518700dd101b714069cfcb17`; `rustls-webpki` git commit
  `c14836d8de33c0ad0ac7dcb28fe9aade20831a4d`.
- Published archive inventory: `rustls 0.23.42` and `0.23.45` each contain 119
  regular members; `rustls-webpki 0.103.13` and `0.103.15` each contain 28. No
  path traversal, symlink, special-file, executable, oversized or unexpected
  binary payload was present, and the archive hashes match crates.io.
- The cumulative `rustls 0.23.40` -> `0.23.45` change aligns with the published
  releases:
  - [`0.23.41`](https://github.com/rustls/rustls/releases/tag/v%2F0.23.41)
    updates a nightly-only `read_buf` API
  - [`0.23.42`](https://github.com/rustls/rustls/releases/tag/v%2F0.23.42)
    adds opt-in RFC 9149 ticket-request support while preserving the default
    client and server behaviour
  - [`0.23.43`](https://github.com/rustls/rustls/releases/tag/v%2F0.23.43)
    fixes AWS-LC and QUIC paths not used by cargo-barbican
  - [`0.23.44`](https://github.com/rustls/rustls/releases/tag/v%2F0.23.44)
    adds AWS-LC ML-DSA support and hardens key-log-file permissions, alongside
    an ECH certificate-name fix
  - [`0.23.45`](https://github.com/rustls/rustls/releases/tag/v%2F0.23.45)
    contains the
    [encryption-level validation fix](https://github.com/rustls/rustls/pull/3265)
    and related backports
- `rustls-webpki 0.103.13` -> `0.103.15` changes cover stable ML-DSA/FIPS
  support, CRL simplification and docs.rs configuration. cargo-barbican uses
  Rustls' `ring` feature, so the AWS-LC ML-DSA implementation is not compiled.
- The `rustls` build script has SHA-256
  `380b9a051325baa7d4957bd9a4f1a637c27a663610b1b502f9524530f6995f4d`
  and is byte-identical in `0.23.40`, the inherited `0.23.42` baseline and
  `0.23.45`. It performs no network, subprocess or filesystem activity.
- Rustls forbids unsafe code, and neither target source tree introduced an
  unexplained unsafe, process, network, install-time filesystem or IOC hit.
- Rustls' `logging` feature only activates the `log` facade. The client config
  still defaults to `NoKeyLog`; cargo-barbican does not opt into key logging.

## Commands Run

```bash
cargo tree --locked -e features -i rustls@0.23.40
target/debug/cargo-barbican inspect --min-age-days 0 rustls@0.23.45
target/debug/cargo-barbican inspect --min-age-days 0 rustls-webpki@0.103.15
target/debug/cargo-barbican update --dry-run --min-age-days 0 rustls@0.23.45

# In an isolated copy with the exact two-package lockfile update:
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo audit --no-fetch
cargo run --locked --bin cargo-barbican -- \
  age --min-age-days 0 rustls@0.23.45
```

The final command made a real HTTPS request to crates.io through the updated
`ureq` / Rustls stack.

## Outcome

Accepted the exact two-package update. The security benefit justifies the
narrow release-age exception, while the inherited artefact review and the
cargo-barbican-specific feature, build, test, lint, audit and live HTTPS checks
show no concerning unexplained change.

## Follow-ups

- Remove the now-inert `allowed_age_exceptions.rustls` entry at the next family
  review after `2026-09-21T15:11:17.808465Z`.
- Re-run this review if either exact version, checksum or active feature set
  changes.
