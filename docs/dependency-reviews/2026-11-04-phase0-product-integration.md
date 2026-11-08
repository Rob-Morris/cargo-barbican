# Dependency Review: Phase0 product graph and maintained source custody

## Summary

4 November 2026. Astra integration source review of the actual product union,
following the pre-add [public verifier review](2026-11-04-embedded-public-verifier.md)
and [decoder review](2026-11-04-rust-distribution-decoder.md). This record
approves bounded data-only qualification inputs. It does not approve CLI trust,
admission, installation, activation or additional native platforms.

## Classification

Elevated-risk: cryptographic parsing, compressed input, build scripts/proc
macros, locally maintained third-party source and two active advisories.
Independent design/security review and the canonical gate remain required.

## Targets and exact graph

[Product graph receipt](2026-11-04-phase0-product-graph.json) records all 220
registry selections, checksums, actual union features and discovered execution
surfaces. The candidate lock has 223 packages including the two product members
and maintained rpgpie. All 96 pre-add package name/version/checksum identities
are retained; 126 registry selections and the maintained member are additive.
No broad latest-version refresh was performed.

The initial 151-package selected-host verifier receipt is evidence, not a
claim that it covered the whole product graph. Existing exact selections
retain their original records. The new decoder closure has its own preceding
source review. The remaining platform/feature-dependent packages are reviewed
below. Unsupported targets are not granted runtime support by a lock entry.

## Maintained rpgpie source

rpgpie 0.12.0 is an explicit non-publishable locally maintained workspace member, not an
excluded unreviewed path or registry checksum exception. Original archive
SHA256 is `2049db9b867c7a430535e6628d449afbcb058ad67d674c71143e62c86e7564af`,
upstream commit `81ed54b4976d66a7f63b826dcad1d7e7f2279acf`.
Original notices and licence files are retained. The
[bounded patch](2026-11-04-rpgpie.patch) and
[provenance](../../vendor/rpgpie/BARBICAN-PROVENANCE.md) describe the semantic
expiry fixes and manifest changes.

All runtime dependencies are exact reviewed pins. Upstream CLI/test targets,
dev dependencies and optional CLI/PQC/wasm feature expansion are removed.
The library's test/doctest targets are disabled; the product adapter's native
regressions exercise the changed behaviour. The summary-format fixture-only
in-source test module is omitted because its rstest dependency and external
fixtures are outside this maintained package. The exact removed module is
preserved in the patch; `clippy --all-targets` compiles in-source tests despite
`lib.test = false`. No upstream fixture-suite pass is claimed. The other
compilable in-source test modules are retained. Chrono defaults are disabled;
`std,serde` supports the actual UTC DateTime/Duration conversions. Source
inspection found no Chrono local clock calls, and the verifier's seven native
test groups passed with this final manifest. This removes unused timezone,
browser and platform dependencies, including an otherwise selected Haiku C++
build. pgp defaults remain disabled. No `[patch]`, source substitution or
inventory admission rule is relaxed.

The [fixed tree receipt](rpgpie-0.12.0-tree.sha256) inventories every one of 30
files; its SHA256 is
`3d23f7470fe5738e04f56f2decf3266c8bc8e0753393171d8167e1f49ee76be5`.
The offline shell guard checks this inventory before Cargo in canonical
verification and CI, rejects missing/extra/changed files, symlinks and special
files, confines receipt paths and never regenerates expected hashes. This
is reviewed static source custody under one-writer ownership, not registry
checksum enforcement or hostile same-user race protection.

## Additional source review

Three exact selections absent from the selected-host verifier receipt remain:

- curve25519-dalek-derive 0.1.1, SHA256
  `f46882e17999c6cc590af592290432be3bce0428cb0d5f8b6715e4dc7b383eb3`.
  MIT/Apache-2.0. Reviewed its attribute parser, specialised module/function
  rewriting and target-feature wrappers. It emits tokens for the existing
  curve implementation; no network, filesystem mutation or subprocess route.
  This is a proc-macro execution surface on applicable targets, not a new
  secret-operation approval.
- fiat-crypto 0.2.9, SHA256
  `28dea519a9695b9977216879a3ebfddf92f1c08c05d984f8996aecd6ecdc811d`.
  MIT OR Apache-2.0 OR BSD-1-Clause, accepted through MIT/Apache. Reviewed
  manifest, generated field-arithmetic module boundary and curve25519 limb,
  carry and serialisation implementation. No dependencies, build script,
  macro, network or subprocess. Generated arithmetic is not independently
  formally proved by this review; secret-key use remains outside scope.
- zerocopy-derive 0.8.63, SHA256
  `863ad3ac83293fb4d740aedbfdc9240dd8d1a50c1099acd76ce80ce7c7230c7f`.
  BSD-2-Clause OR Apache-2.0 OR MIT, accepted through Apache/MIT. Reviewed
  derive entrypoints, representation/field-bound checks and FromZeros/
  FromBytes invariant refusal. Produces trait implementations from source
  tokens for matching zerocopy. Filesystem blessing code is test-only;
  dependency tests are not selected. No production network/subprocess route.
  Macro correctness remains relevant to downstream unsafe layout code.

All source archives in the actual union were independently SHA256-checked
against their candidate lock checksums before any build. Other verifier
sources inherit the exact bounded source review. The union adds the existing
reviewed `sha2 0.10.9/force-soft` feature and decoder-reviewed
`typenum/const-generics` to that selected graph; no other feature broadening
was observed. Existing source/review grants are preserved.

## Release age, advisories and licences

The installed trusted 0.36.0 Barbican `age-lock` against the exact pre-add
snapshot passed for all 126 newly selected registry versions using fresh
crates.io queries on 4 November. Minimum seven days; no age exception or
yanked selection. All newly selected checksum comparisons passed.

Freshly fetched RustSec snapshot
`965bf9ad083b58e6340d65829d85217b18be9290` reports exactly
RUSTSEC-2023-0071 on rsa 0.9.10 and RUSTSEC-2026-0387 on crypto-bigint 0.5.5;
no other findings or warnings. This is not a clean audit. Exact checksum-bound
`allowed_advisories`, with deadline 2026-12-04, use the public-only RSA
non-exposure reasoning in the preceding verifier record. No scanner ignores
are added. Private operations or widened algorithm/input scope invalidate
that assessment.

Trusted cargo-deny on the actual metadata union passed licences, bans and
sources. Duplicate-version warnings remain visible. The only licence-policy
addition is the separately reviewed [Zlib refinement](2026-11-04-zlib-licence-refinement.md).
No copyleft allowance or unrelated policy relaxation is authorised.

## Commands and outcomes

- Trusted Cargo 1.95.0 metadata in an isolated candidate workspace, starting
  with the exact pre-add lock; offline resolution plus exact missing-source
  downloads. No dependency build during discovery. Existing selections were
  compared before publication. This explicit additive route avoids the broad
  `generate-lockfile` refresh used by `resolve`.
- Trusted installed Barbican `age-lock --base-lockfile <pre-add snapshot>
  --lockfile <candidate lock>`: passed.
- Trusted cargo-audit against the candidate with fresh explicit RustSec DB,
  `--no-fetch` and the populated isolated Cargo home: exactly two findings
  above; scanner exit 1 honestly retained.
- Trusted cargo-deny `check licenses bans sources` with actual candidate
  metadata: passed.
- Source guard positive/negative tests: changed bytes, missing/extra build.rs,
  symlink leaf/directory, wrong type, FIFO, malformed/traversing/duplicate
  receipt, unterminated final line and pre-Cargo refusal; passed.
- Existing verification branch guard tests: 4 passed.

## Exact sibling integration

The actual decoder union requires sha2 0.10.9 and 0.11.1, and the verifier
requires serdect 0.2.0 and 0.3.0. Each version is declared separately across
active families. Enforcement now preserves complete observed LockedPackage
tuples and reconciles the whole governed name bidirectionally: every expected
target is present and every observed identity is explicitly reviewed. Duplicate
locked identities, unreviewed versions/sources, checksumless siblings, swapped
checksums and conflicting strong declarations fail. A weak same-identity
declaration cannot dilute a strong checksum. Diagnostic version/checksum sets
remain only for rendering; they do not decide acceptance.

Advisory bindings reuse that canonical predicate, require all same-name family
records completed, and remain exact target/checksum/deadline bound. Existing
pre-add age and assessment surface grants already bind exact target identities
and retain their independent record/metadata checks. Direct requirements,
source override prohibitions and per-package Git coverage are unchanged.

The candidate lock and exact declarations cover all 220 registry identities;
no old identity or grant is removed. Focused sibling and existing Git admission
regressions verify the new representation; canonical verification and separate
independent reviews remain the final integration gates.

Final patch packaging uses zero-context unified diff, applied only to the
verified original archive with `git apply --no-index --unidiff-zero`; see the
maintained provenance. The redundant final blank line in the curated summary
source was removed. Earlier native/canonical logs remain historical evidence
for their source cut; the packaging follow-up records the final identities.
