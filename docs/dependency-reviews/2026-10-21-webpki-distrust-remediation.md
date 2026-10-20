# Dependency Review: WebPKI distrust remediation

## Summary

- Date: 2026-10-21.
- Reviewer: OpenAI Codex, with independent source-delta/security review.
- Scope: two transitive TLS artefacts after the v0.31.0 release CI reported
  RUSTSEC-2026-0381 and RUSTSEC-2026-0382. Preserve the published tag and ship
  the remediation in v0.31.1.

## Classification

Elevated risk: fresh certificate-validation code and trust-anchor data.
Prefer the reviewed security patches to retaining known distrusted-key trust.

## Targets

- `webpki-roots 1.0.10`, SHA-256
  `1c1c8e20c8a38fc7d65abfe74eb7280e4aa667e8eec8bc84996d2874810748d9`.
- `rustls-webpki 0.103.16`, SHA-256
  `4443b1b6d39d7c663139942cc4558262562d2c84123bb6282ef177009ca8b281`.
- Both crates.io archive hashes independently match the version API metadata;
  neither release is yanked.

## Inheritance

First-principles source-delta review against the installed locked artefacts
`webpki-roots 1.0.7` and `rustls-webpki 0.103.15`. The existing
[Rustls review](2026-10-20-rustls-advisory-remediation.md) supplies the unchanged
Rustls 0.23.46 identity, features and build-script permission. No new HTTP
client, dependency feature or source authority is introduced.

## Reviewed Target Set

- Existing family: `rustls-advisory-remediation-2026-10-20`; point its record
  at this review and retain unchanged Rustls 0.23.46 plus its reviewed digest.
- Replace WebPKI with the exact reviewed version/digest above; add the bundled
  root store to this TLS family.
- Direct requirements: none; both are transitive through `ureq 3.3.0`.
- Execution permissions: retain only unchanged Rustls `build-rs` permission.
  The two updated crates have `build = false`, no proc-macro target and no
  native-link declaration. No new execution grant is needed.
- Age/advisory exceptions: none.

## Release Age

The seven-day minimum is not met: root store published
`2026-10-19T20:11:32.333071Z`; WebPKI published
`2026-10-20T08:58:28.008618Z`. Accept these exact reviewed security fixes
because waiting retains the reported certificate-trust vulnerabilities.
Do not lower the minimum or create an ongoing exception; age-aware intake
commands continue enforcing their configured policy.

## Advisory Review

Authoritative RustSec records:

- [RUSTSEC-2026-0381](https://github.com/RustSec/advisory-db/blob/main/crates/webpki-roots/RUSTSEC-2026-0381.md):
  patched in 1.0.10; removes emSign ECC Root CA - G3.
- [RUSTSEC-2026-0382](https://github.com/RustSec/advisory-db/blob/main/crates/rustls-webpki/RUSTSEC-2026-0382.md):
  patched in 0.103.16 on the current stable line; rejects paths containing
  explicitly distrusted intermediate public keys, including cross-signs.

Both concern CVE-2026-111943. Do not introduce native or governed ignores.
The final delegated audit remains required to establish no remaining findings.

## Source / Upstream Review

- Downloaded exact archives over HTTPS, verified their SHA-256 values against
  crates.io metadata, and compared every changed file against cached old
  archives without executing downloaded code during review.
- WebPKI's production changes thread a fixed eight-key distrust set through
  chain construction; check every path head before issuer search and check
  the candidate trust anchor before accepting its chain. `CertDistrusted`
  participates in the existing error ranking. The delta adds tests for
  root/intermediate/leaf rejection, unrelated keys and cross-signed paths.
- The eight binary SPKI resources are compiled through `include_bytes!`;
  no runtime fetch, file access or mutable distrust configuration is added.
- Root-store production changes are static trust-anchor data: remove emSign
  G3, SecureSign Root CA12 and Atos TrustedRoot 2011; add Telia RSA/EC v3 and
  SECOM RSA/ECC 2024. No executable logic is added.
- Independent review matched all 116 old and 117 new compiled subjects/SPKIs
  to their embedded PEM certificates and fingerprints: the four additions
  and three removals above are exact, with no changed retained key. The
  removed emSign SPKI also matches the upstream removal's fingerprint.
- Normalised manifests add no production dependency or feature; root-store
  rust-version rises from 1.64 to 1.71, within this repo's pinned 1.95.0.
  WebPKI remains 1.71. Package Cargo.lock changes are not consumer lock data.
- Embedded upstream Git identities: roots
  `70760478b9d3ea729b22faa0b5324da38a297c1c`; WebPKI
  `8ecdcc76f56b68fda67a6adf7976f5eed5006a4c`. These are archive provenance
  claims, not independent Git-signature attestations.

## Commands Run

Metadata/archive fetch and checksum/source comparison preceded lock mutation.

```sh
cargo update -p webpki-roots --precise 1.0.10
cargo update -p rustls-webpki --precise 0.103.16
cargo tree --locked -e features -i rustls-webpki
cargo tree --locked -e features -i webpki-roots
sh scripts/verify.sh
```

The final command used the canonical no-flag gate with isolated build output.

## Outcome

Accept these exact artefacts for targeted remediation. Cargo.lock changes
only the two transitive versions/digests and local workspace versions. Feature
paths remain unchanged. Canonical verification passed Clippy, all 714 tests,
and Toolchain/Inventory/Audit/Verify/Gatehouse checks. In particular the fresh
delegated audit passes without ignoring either advisory. Remote CI and the
published-tag installation proof follow the release commit.
The independent six-concern design/security review found no remaining finding.

## Follow-ups

Re-review future identity, trust-data, feature or execution-surface changes.
Source inspection and consumer tests do not prove cryptographic correctness;
the upstream test delta was inspected, not executed in isolation here.
