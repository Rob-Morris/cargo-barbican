# Complete crypto dependency update review

## Summary

Date: 19 November 2026. This completes the source, API, graph and security
applicability review of the proposed public-verifier dependency updates before
changing the live dependency set. It is not a request for another review slice.

**One recommendation:** update both exact `pgp` declarations to `0.21.1`, retain
the maintained `rpgpie 0.12.0` source and its semantic fixes, and preserve the two
existing exact advisory exceptions with their unchanged 4 December deadline.
Implement this as one pin, lock, custody, regression and version transaction.
Do not add independent RSA/bigint major pins, an unreleased PGP source fork or
a replacement cryptographic implementation as part of this update.

## Classification

Elevated risk: cryptographic parsing and public signature verification.
Approval remains limited to the bounded v4 public RSA certificate and binary
detached-signature route. A source-level refusal is a completed disposition;
it does not approve executing the refused dependency graph.

## Targets

| Candidate | Final disposition | Concrete basis |
|---|---|---|
| `pgp 0.21.1` | Accept in both exact owners | Complete delta review, unchanged production dependency/features, exact graph/custody reconciliation, actual baseline/candidate verifier controls and canonical gate pass. |
| `rsa 0.10.0` | Refuse this integration | Released PGP still requires RSA 0.9.10. A fork-only bump retains that version, adds an incompatible RSA family, and does not replace the verifier's actual RSA dispatch. Key, integer, digest and RNG APIs also change. |
| `crypto-bigint 0.7.11` | Refuse this integration | Two independent old-version owners remain: `cx448 0.1.1` and `elliptic-curve 0.13.8`. Neither accepts a lockfile-only replacement, and their source APIs are incompatible with the new integer family. |
| Published `rpgpie 0.12.1` | Retain maintained 0.12.0 base | Still uses old RSA and retains the expiry/cross-signature defects addressed locally. Its additional text-normalisation fix is outside the binary-only product route. Reintroducing presentation/Chrono or rebasing solely for that unused path has no product benefit. |
| EC 0.14.3, ECDSA 0.17.0, p256/p384/p521/k256/primeorder 0.14.0, DSA 0.7.0 | Refuse independent additions | These are a coupled new EC/signature/digest family, not compatible replacements under released PGP's current declarations and generic types. Adding them leaves the old graph; even a coordinated EC update leaves cx448's separate bigint dependency. |
| Upstream PGP migration PR 573 | Refuse as a dependency | Unmerged source integration using mandatory prerelease 448 replacements and other changed crypto families. It is not a released compatible parent update. |
| Stable alternative `ed448-goldilocks-plus 0.18.1` | Do not introduce | Newer integer/EC dependencies alone are insufficient: its secret/shared-secret/RNG APIs differ from PGP's current 448 protocol adapter. Adopting it requires a separately maintained PGP/crypto port, not a dependency pin update. |

## Inheritance

The [PGP source/native qualification](2026-11-19-pgp-0.21.1.md) supplies approval
for the selected exact patch. The [original public-verifier review](2026-11-04-embedded-public-verifier.md)
and [maintained presentation removal](2026-11-18-rpgpie-presentation-removal.md)
supply the unchanged public-only model and source baseline. Independent Astra
source/API and security reviews agree on all dispositions above.

## Reviewed Target Set

Only PGP changes in `phase0-product-integration-2026-11-04`:
`=0.21.0` to `=0.21.1`, archive SHA256
`c7275cbf21850789239e1be05d9a887e6bba6aa8085a81be09ca021c8379baef`.
Update the binary and maintained-fork manifests, one registry lock identity,
direct/resolved reviewed entries, maintained provenance/cumulative patch and
full source receipt together. No maintained verification source changes and
no new runtime feature or execution-surface grant.

The baseline and selected PGP graph contain 225 packages. The actual inert
fork-only RSA-major model contains 243, including both RSA 0.9/0.10 and both
bigint 0.5/0.7. It removes neither affected old package. These counts include
workspace packages; they are not a claim that every package is crates.io.

## Release Age

PGP 0.21.1 was published 11 November, non-yanked, MSRV 1.88. RSA 0.10.0 and
bigint 0.7.11 were published 8 November, MSRV 1.87. All fit trusted Rust 1.95
and the seven-day minimum. Age/MSRV eligibility does not establish compatible
integration. Bigint 0.7.6 through 0.7.8 are yanked and are not fresh targets.

## Advisory Review

[RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html)
identifies RSA versions fixed at >=0.10.0;
[RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387.html)
identifies bigint versions fixed at >=0.7.6. The proposed fixed versions meet
those thresholds individually, but the selected PGP patch still resolves
`rsa 0.9.10` and `crypto-bigint 0.5.5`.

The existing exposure reasoning remains public-only verification with public
operands; secret/message packet tags are refused before body decoding. This
does not make either advisory globally inapplicable to the library. Keep the
exact checksum-bound exceptions, still due **4 December 2026**. No deadline is
extended, native ignore imported, or exception widened. Remove an exception
only after its affected versions have left the entire governed graph and fresh
policy/verification passes. Neither exception is removable by this update.

## Source / Upstream Review

The exact published archive checksums reviewed for the refused primary targets
are RSA 0.10.0:
`23e77fd77e0dea28b3011fd62d15445b7de7959333b0276d930e03be0f755699`,
bigint 0.7.11:
`914c195c4d7fbc5ed7f88d14cbf85914d5c664967658d43404b263913a477e82`,
and rpgpie 0.12.1:
`eac9294fce57b6da911c7a8b36a92a9208de047cea5c658e84c2b9772af9ddee`.
They are source/applicability evidence, not an execution approval.

### RSA source/API boundary

PGP `types/params/public/rsa.rs` stores its own RSA 0.9 `RsaPublicKey`; its MPI
conversions use `num_bigint::BigUint`. RSA 0.10 `public_key.rs` instead takes
`BoxedUint`, and `PublicKeyParts` returns a different integer family. The
maintained fork's `policy.rs` imports its directly selected RSA trait to query
that PGP-owned key. Merely changing that declaration makes the trait/type
identity disagree.

The fork's `util.rs` imports `rsa::signature::digest::DynDigest`, while PGP
`crypto/hash.rs` produces digest 0.10 trait objects. RSA 0.10 reexports
signature 3/digest 0.11 and uses the new RNG trait family. These are concrete
cross-package type obligations, not a guessed semver risk. Bridging only the
fork would still leave detached verification dispatching through PGP's old RSA
implementation. No claimed remediation follows from such a bridge.

### Bigint, EC and 448 closure

Old `cx448` and EC resolve to bigint 0.5.5 under manifest ranges `^0.5.5` and
`^0.5`, respectively. cx448's field code uses
`modular::constant_mod::{Residue, ResidueParams}` and `impl_modulus!`; bigint
0.7.11 exposes `ConstMontyForm`/`ConstMontyParams` and a changed feature/API
family. cx448 also directly depends on old EC types. Updating only one parent
does not remove the other dependency chain.

EC 0.14.3 requires bigint ^0.7.8. New ECDSA/curve packages use the new EC,
signature 3 and digest 0.11 types. Released PGP composes its EC generics with
the selected curve types, including SEC1/ECDH operations. They must migrate
together. The [upstream migration](https://github.com/rpgp/rpgp/pull/573),
reviewed head `5bac6ac4c0edd18fd34cd43c47715deb20ff43f2`, illustrates the
broader change, including mandatory prerelease 448 replacements. Default
features off does not remove these mandatory current PGP dependencies.

A stable alternate 448 implementation was also evaluated rather than assuming
prereleases are the only possible route. Its [published source API](https://docs.rs/crate/ed448-goldilocks-plus/0.18.1/source/src/x448.rs)
uses new secret/shared-secret and rand_core 0.10 interfaces, differing from
PGP's current fallible shared-secret and `Secret::new` adapter. A custom port
is technically different work with additional source custody and protocol
maintenance. It is not justified merely to turn two scanner findings green
when the actual bounded public-only exposure has not changed.

That alternative's published archive was authenticated against its registry
index SHA256 `ade2f948c0176fd311668a767449034786d2d0db2c247ca4c99c6471f53370dd`.
The inspected `src/x448.rs` makes contributory shared-secret checking a separate
API, while the current PGP adapter expects fallible shared-secret creation.
This source/API comparison is a refusal basis, not a security approval of a
replacement implementation.

## Commands Run

- Authenticated exact archive/manifest/source comparison and independent API
  call-path/trait/feature review for all table entries.
- Trusted Cargo metadata-only models of baseline, PGP patch and owner-only RSA
  major edit. No refused dependency code was built or executed.
- PGP actual source-custody guard, locked graph/feature comparison, original
  upstream archive patch replay, pre-execution audit and licenses/bans/sources.
- Native baseline and candidate verifier: eight groups pass on each version.
- Native selected-candidate `sh scripts/verify.sh` with no flags: 1,141 passed,
  zero failed, 19 existing ignored tests; all-target warnings-denied Clippy and
  final Verify/Gatehouse PASS. Exact receipts and bounds are in the linked PGP
  qualification record. Live integration receives its own final gate/reviews.

## Outcome

**Full proposed-target review complete.** Implement the single selected PGP
update, preserve the maintained source and bounded policy, and reject the
incompatible independent major/fork substitutions. The rejected alternatives
are evaluated decisions, not dependencies awaiting approval in this update.

Implemented together in the v0.44.1 workspace. Fresh actual pre-execution
audit, licenses/bans/sources, source custody and the no-flags canonical gate
pass. The live gate runs all eight verifier groups and totals 1,141 tests
passed, zero failed and 19 existing tests ignored. The
[integration receipt](2026-11-19-crypto-update-integration.json) binds the
actual graph, changed build inputs, source receipt, results and retained logs.

## Follow-ups

No unresolved product decision blocks this integration. The existing advisory
deadline remains a separate maintenance obligation; this update neither
claims to clear it nor silently chooses a new cryptographic fork. Any future
compatible parent release or explicit backend replacement is a new concrete
candidate to assess against the same public-only contract.
