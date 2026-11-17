# Dependency review for the maintained public verifier

## Decision and scope

On 18 November 2026 the repository audit reported RUSTSEC-2026-0543 against chrono 0.4.45. RustSec describes the entire crate as unmaintained and lists no patched release. The installed cargo-deny database assigned the advisory on 17 November at commit 233155b4025b854c68a4b199c0e32d7fd53291a2. A chrono upgrade cannot resolve this finding. The advisory describes a maintenance risk. [RustSec record](https://github.com/RustSec/advisory-db/blob/233155b4025b854c68a4b199c0e32d7fd53291a2/crates/chrono/RUSTSEC-2026-0543.md)

The only incoming lockfile edge is the private, non-publishable rpgpie 0.12.0 workspace member. The product verifier uses its Certificate, Checked and detached verification APIs. Its timestamp and validity checks use pgp::types::Timestamp. The fork's public presentation model, its print_cert wrapper and the algorithm-name display helper have no product callers. The disabled upstream CLI is the only caller of the wrapper. Remove that export and its two helpers from the compiled fork. Keep the excluded model and CLI source in the reviewed inventory for provenance.

Remove the fork's direct chrono dependency and the serde and serde_json edges used by presentation. Other workspace dependencies continue to own the two serialisation crates. The remaining in-source expiry fixture tests retain their dates, checked timestamp conversion and assertions. Their only date parser becomes the already-selected time 0.3.47, as a dev-dependency. This requires no exception. Replacing the public presentation model's timestamp types would add a port and serialisation contract to an unused interface.

## Dependency and trust review

The parser takes fixed RFC 3339 strings from authored test code and converts them through SystemTime into the existing pgp timestamp type. The production verifier continues to obtain authority time from its caller. No runtime parsing, date arithmetic, signature/expiry decision, process or network capability enters the product through this change.

The exact time version has archive SHA256 743bd48c283afc0388f9b8827b976905fb217ad9e647fae3a379a9283c4def2c and was published on 5 February 2026. The workspace's existing reviewed feature selection is std and parsing with defaults disabled. The same selection supplies the test edge. This release's previously reviewed RustSec boundaries include the RFC 2822 fix in 0.3.47. Its manifest declares no build script or procedural macro. The existing review covers the package, licence and selected subtree. [time review](2026-05-26-time-0.3.47.md)

The maintained source derives from the rpgpie 0.12.0 archive, SHA256 2049db9b867c7a430535e6628d449afbcb058ad67d674c71143e62c86e7564af. The retained original bytes and SPDX notices continue to identify upstream material. Source comparison against the previously verified tree isolates the manifest, library module export, two presentation helpers and fixture-only parser. The original primary/subkey expiry fixes and the product's detached verification, authenticated revocation handling and cross-signature checks remain the reviewed security boundary. [Verifier review](2026-11-04-embedded-public-verifier.md)

The 18 November source inventory covers all 30 retained files and has SHA256
`f58647efea01d6548743acfb975062d75d5f68a3967ec2df52d379cd1533e3ff`. The cumulative patch reproduces the six
modified upstream files from the authenticated archive. [Current inventory](rpgpie-0.12.0-tree.sha256) · [Cumulative patch](2026-11-18-rpgpie.patch)

## Qualification

Check that the cumulative patch applies to the authenticated archive and reproduces every retained, modified upstream file. Compare the complete candidate tree with its receipt and run the repository's pre-build custody guard before Cargo. Qualify the active lockfile and exact pin ownership, clippy with all targets, the static public verifier fixture suite, the canonical gate, and the required Cargo-tool native journeys. The vendor manifest disables the omitted upstream fixture suite. Existing product fixture controls exercise boundary-equal expiry, invalid bindings and revocation handling. A successful build of the retained in-source fixture code does not establish execution of those omitted upstream fixtures.
