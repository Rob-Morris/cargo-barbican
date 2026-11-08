# Rust distribution public trust seed

Date: 2026-11-04. Scope: official Rust distribution manifest authentication,
not publisher identity for unrelated artefacts, local GPG ownertrust, or signing.

This review is independent of the Phase0 conditional fixture anchor. It
establishes the explicit supplier trust basis for a production bundled seed.
The supplier is the Rust Project and its HTTPS publication infrastructure.

## Sources and exact identity

[Current Rust Forge installation guidance](https://forge.rust-lang.org/infra/other-installation-methods)
links directly to [the official public release key](https://static.rust-lang.org/rust-key.gpg.ascii)
and states its purpose as signing the official Rust binaries through Rust build
infrastructure. The downloaded public file on 2026-11-04 has SHA-256
`e54b09a439647e006b4831eec9785cbaaf3e07ab371c3a6ee6a68e1bdb9fbc6b`.
The same exact public bytes are independently published in the
[official Rustup 1.25.1 source](https://github.com/rust-lang/rustup/blob/1.25.1/src/rust-key.pgp.ascii).
This historical source corroborates identity and purpose, not current validity.
Rustup 1.29.0 does not contain that path; no current Rustup signature enforcement
is inferred. Forge explicitly distinguishes HTTPS downloads from manual
signature verification.

The embedded public-only adapter parses the complete v4 primary fingerprint
`108F66205EAEB0AAA8DD5E1C85AB96E6FA1BE5FE`, and refuses a different identity,
secret-key packets, unsupported algorithms and unapproved material. The
Phase0 authentic signed Rust 1.99.1 manifest verifies under this exact material
at the current clock. The seed is an explicit trust in Rust's official
supplier channels; neither this review nor an unchanged fetch proves fresh
nonrevocation or universal absence of compromise.

## Policy and lifecycle

Allowed purpose is official exact-stable Rust distribution manifests. Original
manifest bytes are authenticated, and their complete selected archive URLs and
digests are validated before decode. The existing qualified adapter admits
legacy SHA-1 structural certificate signatures only within the exact approved
packet baseline; document signatures require SHA-256/384/512. Current primary,
component, purpose, cross-signature and expiry checks remain required. The
rpgpie detached verifier also consults its own current clock: production calls
use actual UTC time and intersect both current checks; historical caller clocks
never bypass the upstream current-time check.

The first local bootstrap may use this reviewed seed. Later certificate,
purpose or provenance changes stage exact proposals bound to the old baseline;
explicit approval is required even for nonconflicting bundled updates. An
unchanged fetch only updates successful observation time. Authenticated adverse
observations are persisted before any refusal/proposal is reported, retained
across omission and cannot be cleared by baseline replacement. Unknown keys do
not become trusted through network discovery or personal GPG configuration.

Decision: this exact public seed and narrowly described purpose are suitable
for the product baseline, subject to implementation design/security review and
focused tamper, material-change, stale-proposal and adverse-persistence tests.
No new package or private key is introduced.
