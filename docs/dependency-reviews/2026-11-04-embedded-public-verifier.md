# Dependency Review: embedded public Rust distribution verifier

## Summary

- Date: 2026-11-04.
- Scope: Phase0 public RSA verification foundation only. No CLI, trust approval, admission or installation is enabled by this record.
- Reviewer: delegated Codex implementation review; independent design/security reviews and integration checks remain required before commit.

## Classification

Elevated-risk: experimental certificate policy owner, cryptographic parsing and a substantial transitive graph with build scripts/proc macros. This is scoped verification acceptance, never signing/decryption or general OpenPGP clearance.

## Targets

- rpgpie 0.12.0, upstream registry archive SHA256 `2049db9b867c7a430535e6628d449afbcb058ad67d674c71143e62c86e7564af`, commit `81ed54b4976d66a7f63b826dcad1d7e7f2279acf`, MIT OR Apache-2.0. Vendored source requires explicit provenance/patch receipt and independent review.
- pgp 0.21.0, SHA256 `ae70f4d9325a391db30d115d6191a7bb67cec856aa0bba131290f0c4e09a532a`, MIT OR Apache-2.0. Disable default features on both direct roots; no CLI/PQC/optional bzip2.

## Inheritance

The 3 November first-principles scratch review is incorporated as evidence, not represented as an existing product record: brain://_Temporal/Research/project~cargo-barbican/design~cargo-barbican/design~barbican-rust-toolchain-review-update/20261103-research~Permissive Rust Verifier Current-Policy Qualification Evidence.md and paired report. Same exact 151-package aarch64-apple-darwin graph, public-only APIs, trusted Rust 1.95.0. All 151 downloaded archive digests were independently rechecked on 4 November against that inventory before execution. Existing 33 exact repository selections retain their existing reviews; 118 new selections inherit the explicit scratch source review only within this scope.

## Reviewed Target Set

The exact selected graph, feature/surface observations and checksums are in [the graph receipt](2026-11-04-embedded-public-verifier-graph.json). Registry artefacts need corresponding exact machine declarations; the vendored path is an explicitly maintained repository workspace member with offline tree custody checking, not a registry-checksum claim. Excluded external path dependencies remain refused; no generic path admission or source override is added. Root integration owns manifest, policy and lockfile changes and must reconcile its actual union graph. Native proof here covers aarch64-apple-darwin only.

## Release Age

Minimum seven days. Retained authenticated sparse-index receipts dated 3 November show all selected versions older than seven days and non-yanked; exact archive checksums match. rpgpie published 3 October 2026; pgp 3 October 2026. No age waiver. Fresh metadata resolution retained the same lock selections. MSRV maximum 1.88, below trusted 1.95.

## Advisory Review

RustSec snapshot `965bf9ad083b58e6340d65829d85217b18be9290` (3 November 2026) reports RUSTSEC-2023-0071 (rsa 0.9.10) and RUSTSEC-2026-0387 (crypto-bigint 0.5.5). These are active findings, not a clean audit. Proposed exact checksum-bound governed exceptions must expire by 2026-12-04; fresh integration audit may reveal additional findings requiring review.

The public parser refuses secret packets before rPGP parsing. Public RSA verification follows rPGP verify to rsa PKCS#1 v1.5 VerifyingKey::verify_prehash and public exponentiation; no private signing/decryption or secret integer construction occurs. The two advisories expose secret-operation timing, and there are no secret operands on this route. Fixtures are authored with already-trusted isolated GPG; consumers require no GPG. Any secret-key operation, algorithm expansion, dependency or feature change invalidates this non-exposure assessment.

## Source / Upstream Review

Reviewed Checked/current-signer ownership, detached verified full component identity, public packet/dearmor and certificate parsers, existing binding/revocation primitives and policy/time semantics. Keep upstream active-binding selection; correct exact key expiry in that owner. Guard the demonstrated later-UID primary revocation masking and unchecked unhashed embedded cross-signature with existing cryptographic primitives. Preserve exact approved legacy material only; never accept SHA1 data or shift the policy clock.

The cited source review inspected new build entrypoints (crc24 table generation; curve25519-dalek compiler cfg; libm cfg; num-bigint-dig i128 cfg; num-traits/autocfg compiler probe; radium target atomics; rustversion compiler probe/OUT_DIR; zerocopy compiler cfg) and macro entrypoints/helpers (bitfields, darling, derive_builder, derive_more, num_enum, rustversion, snafu, zeroize). They generate tables/tokens/cfg for known sources; no unexpected network effects. Exact source checksums preserve that review. Existing macro/build selections remain under existing records. No new external toolkit/-sys build occurs; Apple core-foundation-sys is bindings. Broad crypto/compression dependencies remain despite defaults disabled; public input ceilings do not claim exhaustive hostile-input/fuzz proof.

rpgpie 0.12.1 was inspected as a newer route: retained source has unchanged checked.rs/signature.rs and the same key-expiry comparisons. It is not semantic remediation; no speculative replacement is adopted.

## Commands Run

Trusted absolute Cargo 1.95.0: `cargo metadata --locked --filter-platform aarch64-apple-darwin --format-version 1` in owned scratch, followed by Python SHA256 verification of every selected downloaded archive. Metadata/download does not execute dependency code. Native qualification follows only after this review.

## Outcome

Accept the exact selected graph for bounded offline public-only Phase0 implementation/tests, with scoped advisory governance and the separately recorded Zlib refinement. This record precedes product dependency additions. Full product enablement remains blocked until semantic controls, actual integration graph, canonical gates and independent reviews pass.

## Follow-ups

Reconcile union graph/platform source review and exact machine policy before execution; preserve honest advisory findings. Record meaningful native controls and vendor patch identity. No release/install/activation authority follows from Phase0 tests.


## Native semantic qualification

4 November: seven native regression groups passed against the actual maintained
adapter and owner patch with trusted absolute Rust 1.95.0, locked/offline scratch
execution on aarch64-apple-darwin. Groups cover the authentic Rust manifest and
valid subkey; original refusal categories; primary/selected-subkey expiry -1,
equality and +1; genuinely authenticated future embedded signature; adverse
retention before changed benign proposals; native current/future/obsolete hash/
critical/expired revocation classification plus invalid-crypto no-authority;
and unbound benign components that the composed parser drops. The future test
proves both outer/embedded cryptography separately before time refusal.

The adapter compares the full primary key body, excluding packet framing, before
extracting adverse revocations with existing verification primitives. Extraction
precedes the composed parser and baseline rejection so benign dropped components
cannot hide authenticated adverse information. Exact approved structural packets
remain required for acceptance. SHA1 is allowed only for that exact reviewed
structural baseline; data and admissible new revocations use SHA256/384/512.
Authenticated future/obsolete/unsupported-critical/expired observations are
indeterminate and retained, never labelled currently admissible. Invalid crypto
cannot populate adverse state. Unknown current nonrevocation remains unknown.

[Fixture provenance](../../crates/cargo-barbican/tests/fixtures/toolchain-intake/verifier/README.md)
describes synthetic generation and the damaged historical future fixture. No
private key or generation executable is shipped. The adapter is Phase0 test-only
registered until later prerequisite gates and actual trust consumers exist.
