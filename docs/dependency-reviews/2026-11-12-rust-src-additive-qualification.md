# Rust source and additive installation qualification — 12 November 2026

This record covers the target-independent `rust-src` identity and the explicit
additive operation on an occupied macOS ARM64 Rustup slot. The separate
[official evaluator record](2026-11-12-official-rustup-evaluator.md) owns the
1.29.3 executable's provenance, advisory assessment and execution approval.

## Completed bounded outcome

The approved authentic public journey passed with cargo-barbican 0.41.0 on
macOS ARM64: a fresh Rust 1.95.0 minimal-plus-source installation, and a
separately seeded compatible minimal slot expanded through explicit
`install FINAL_REVIEW --add-components`. Each final slot passed static
installation inspection, explicit adoption and a complete verified no-op with
an absent evaluator. Both slots contained 2,467 checked files and 574
directories. Independent security reconstruction passed before cleanup.

This qualifies the reviewed installation machinery using the already-trusted
1.95.0 runtime bytes and exact official Rustup 1.29.3. It does not approve a
new compiler, general Cargo use or source execution. All 60 represented
RustSec findings, seven Cargo API advisories (two affected) and ten residual
unknowns remain in the [companion evidence summary](2026-11-12-rust-src-additive-qualification.json).
The complete static assessment is retained there without discarding its
original scope or pre-execution authority limits. The failed preliminary
harness attempts are retained below; neither required a production change.

## Inputs and authority

The previously authenticated Rust 1.95.0 manifest has SHA-256
`821ff14e4c4a1cbe1e8915f35aff0a3fbbdf8d293ad48ab8f31e3b0440c581f9`.
Its retained detached signature has SHA-256
`3a675df488a0be0e110c99b8c944c2ff4b6a416f34a4862e600a8144e7152dc3`.
The exact signed `rust-src` XZ identity is
`67b09138c8db96afc4bbfc69ea771ac9a091fd777698acb43f6dfd9fb7dea363`;
the package names Rust source revision
`59807616e1fa2540724bfbac14d7976d7e4a3860` and release date 16 April 2026.
These identities do not themselves approve execution or establish a current
personal/repository admission. A fresh final-scope review must authenticate
and reconstruct its own inputs before acceptance.

The signed host closure names `rust-src` with target `*`. Its archive root is
`rust-src-1.95.0`, its component and installed ownership name are `rust-src`,
and its URL has no host suffix. Only this named source package receives the
wildcard rule; host compiler/tool components and unsupported cross targets
remain under their existing restrictions. The old six-package selections do
not gain an implicit source component or a new identity.

Static inspection of the authentic source archive found regular files and
directories, with no links or ASCII case collisions. The signed Rust tree's
`library/Cargo.lock` represents the standard-library source corpus. The
retained `library/std/Cargo.toml`, library workspace and distribution recipe
connect that corpus to `rust-src`; the exact source tree also records the
LLVM submodule identity used for bundled libunwind. Source advisory findings
for `std` apply to the source package as well as the binary standard library.
The lock is not a complete inventory of libunwind, vendored/path dependencies
or every distributed source file. Archive correspondence is not a proof of
reproducible source inclusion, benignness, editor/build/runtime reachability
or complete advisory coverage.

## Native metadata and operation contract

Source review and actual harmless native runs establish two representations:

- Fresh `--component rust-src`: `pkg='rust-src'`, `target='*'`,
  `is_extension=false`.
- Later `component add rust-src`: the same package/target with
  `is_extension=true`.

The wildcard target is present, not omitted. A true extension flag must match
an exact extension in the original accepted host manifest projection; false
is the qualified fresh-install representation. Neither flag establishes how
an installation was historically obtained. During addition, every existing
component's representation must remain unchanged.

`toolchain install FINAL_REVIEW --add-components` derives an untrusted
component-set hypothesis from the occupied slot, reconstructs that base
exclusively from the final accepted manifest and inventories, and verifies the
complete base before any native delegate. The subset must include the minimal
compiler closure. Unknown components, missing files, extra paths, changed
payload, different original metadata, unsafe ownership and destination
conflicts refuse. No prior-review ID or historical acceptance is inferred.

The existing operation evidence records `operation='add-components'` and
`component_addition.installed_components` / `added_components` as canonical
`[package,target]` pairs under its final `subject_id`. The verified scope is
retained before even the isolated evaluator help call. The base is checked
again at mutation handoff. Final success requires full accepted correspondence,
unchanged old payload/ownership/directory identities, unchanged old component
flags, settings and update hash. A complete final slot is a verified no-op
before evaluator and creation-mode requirements. The older narrower subject
fails correspondence after expansion and cannot silently acquire continuing
use of the broader slot.

Failure or cancellation can leave native data behind. This contract does not
claim atomic rollback. The final continuing-use binding is not published on
failed final verification; a subsequent explicit retry can verify a complete
slot without running Rustup again.

## Observed qualification

The retained scratch root is `/private/tmp/barbican-parity-native.BRUXy8`.
Raw five-case receipts cover successful addition, unavailable local archive,
invalid extra component, occupied payload collision and fresh source install.
The original failed expectations are retained separately.

Homebrew Rustup 1.29.0 SHA-256
`16c7599bf448e4e7512779154f6b05042bf2ff715e5e09d9cf5d465a3b750496`
processes component arguments sequentially: a valid source addition can remain
when a later unknown component fails. Official 1.29.3 SHA-256
`63752a1919a3a4793173ec70f8f212621a7ce38ba6a246095984482f4de20f9f`
validates the full component list before one update, so the same invalid-list
case preserves the complete base. This source-specific difference is qualified
without relaxing the final correspondence or retained-failure requirements.

The actual product test
`native_targetless_source_fresh_and_additive_preserve_verified_base` passed
through the official evaluator at a protected private path named `rustup-init`.
Explicit Unix `argv0='rustup'` selected the Rustup CLI; digest qualification
preceded the isolated help/version-prefix check. It exercised fresh install,
add, exact predelegate scope, base identity/probe/settings preservation, old
subject refusal, absent-slot refusal and complete no-op with a deliberately
absent evaluator. The test used the existing reviewed harmless compiler/Cargo/
stdlib fixtures and source-only archive SHA-256
`2b488e5c5378f48f4f1cd926204ec268c61c17d391053a535fd9996c6369e9b0`.
Its receipt is `official-product-adapter-receipt.json`, SHA-256
`c0a0968a29099bdb556dbf7337b2f495efa7fcd81a3644fb78d51c471d6dca66`.
An exact hashed test-executable repeat also passed with retained stdout/stderr
in `official-product-adapter-logged/`; its `receipt.json` has SHA-256
`c5ccd7d397abfd20a2f6c0d06252b6d677b59e8a0d788d22807dc679752af302`.
The existing Rust fixture cleanup removed its temporary installation trees.
Raw five-case trees remain retained.

Additional product regressions passed for tampered payload, extra paths,
changed channel/config metadata, cancellation during base verification, and
same-content inode replacement after native effects. The latter refuses
success and reports retained data. Pure tests cover wildcard identity,
release/URL mismatch, extension flags and standard-library source evidence.

The fixture evidence above is separate from the completed authentic final Rust
1.95.0 plus source journey recorded below. Its public review, scoped acceptance,
installation, addition, inspection, adoption and no-op outcomes are now observed.
The proxy proof separately establishes positive private-pin Cargo/rustc
selection. Its absent rustdoc fixture fails under a restricted PATH; Rustup
source permits PATH lookup for an absent selected binary, so that test is not
a general no-fallback or real Cargo/rustdoc conformance proof.

## Authentic pre-execution checkpoint

The fresh public static review is
`a08b30fae034cb71a7363fe5511c0f006030ce0953c1240c0f92afb8ef7500b6`,
subject `27ba20ccc711c7c47b7b91233ae67d828b885d9db808a027a3c2b6f26e5757ce`.
Its original signature, source snapshots and current observations are retained
under `authentic-static-v1/` in the scratch root above. The exact final archives
are:

| Component | SHA-256 |
| --- | --- |
| Cargo | `6c2ffed8e1ac9cf4dc9e80f282a869a6b237a153e7c55cca039d33de29d80aaf` |
| rustc | `149e85a285b6eba58eb6c8bdf7deb1b93763890598e62cb635a712e3a8454f04` |
| rust-std | `9b30089b0f767cb91b2190ffec55a9beeb2a21a1405d8da0f664d7e09d08e6d8` |
| rust-src | `67b09138c8db96afc4bbfc69ea771ac9a091fd777698acb43f6dfd9fb7dea363` |

A fresh data-only comparison matched all 146 regular runtime payload files
(Cargo 44, rustc 43, standard library 59) against the operator's existing
trusted 1.95.0 installation, including rustdoc and the compiler dylib. The
comparison receipt has SHA-256
`7629591c76067a75949a0629dfb305fd1608e661ae33118d1ffd2bd96ce518d3`.
The authentic source archive includes 25 executable-mode source/CI scripts;
all source payload is treated as data and none is dispatched by this proof.

Independent security assessment retains all 60 RustSec rows (Cargo 39,
rustc 19, standard library 1, source 1), all seven published Cargo API
advisories, and all ten residual-unknown observations. The `rand` source
finding is attributed separately to standard library and source. Current
OpenSSL and rustix rows are assessed explicitly rather than inheriting an
older clean conclusion. Two Cargo API advisories affect represented Cargo
0.96.0: `GHSA-p688-r7jv-fm6f` and `GHSA-jq42-7mfv-hm57`. The proposed proof
supplies no registry credentials and never invokes Cargo, accesses third-party
registries, builds dependencies, or executes source/editor/browser code.

The exact assessment artefacts in `authentic-static-v1/` are:

- `security-assessment.md`, SHA-256
  `2c6744b4b0a86055c1860173345129693b52e79443428c6dee145090c6f3e196`.
- `security-assessment.json`, SHA-256
  `51e2e4f010879dd09696f845cff621aa8d03a0295f99dcef540ac3a342396e4a`.
- Coordinating-agent completed scoped acceptance prose `completed-review.md`,
  SHA-256 `12f30a3d4531e50745aaa3021a93346ffcd1e0ef38b9ffae2611276bfac824bc`.

The exact proposed program `authentic-public-journey.py` has SHA-256
`005a02ac939cfdb69eb230f1682826cb69ca083c4684d0b27fe49d2bbef6a7ce`.
It binds the product, evaluator, final review record, raw review output and
completed prose before dispatch. It retains owned process-group completion,
stop uncertainty, cancellation, logs, old/final payload trees and normal-state
snapshots. Existing proof roots cannot be reused or have their receipts
overwritten.

At this checkpoint execution still awaits configured approval. The intended
journey uses two new private Rustup homes with unrelated sentinel defaults:
fresh final install/check/static-adopt/verified no-op, and manual compatible
minimal installation followed by product add/check/static-adopt/verified no-op.
The evaluator is exact `63752…` Rustup 1.29.3; only the already-trusted 1.95.0
compiler's native version probe may run. The source scripts and Cargo stay
unexecuted. Normal user homes, default and repository pin remain unchanged.

Acceptance, installation and adoption explicitly request cached admission
with the recorded reason that this is a fresh, exact, independently assessed
source replay for the private machinery proof. Static installation inspection
uses its existing local mode, as corrected in the revised checkpoint below.
This is not an implicit default or a claim of a new online refresh during
native work. Private acceptance is scoped by the
reviewed proof and does not recommend general online use of the older Cargo.

### Retained first refusal and revised pre-execution checkpoint

The first approved authentic harness stopped at `accept`: the product rejected
a duplicate reserved `Subject:` line introduced when the coordinating agent
embedded the independent assessment without quoting it. No personal acceptance,
Rustup invocation or compiler probe completed. The first program, prose,
`authentic-native-v1/` and `control/accept.stderr` remain retained. A separate
error-reporting typo in the harness masked its error text after the product's
refusal; it did not change the product outcome or dispatch a further phase.

The revised completed prose, `completed-review-v2.md`, has SHA-256
`d9a93bdb7b005e866b7a1f8489c160ccda5c539f51eaf437a28755d57b7354b3`.
Blockquoting the incorporated assessment preserves it byte-for-byte when
unquoted while keeping exactly one reserved identity/decision/rationale line.
All 60 exact finding markers and ten unknown-scope markers remain intact.
Independent security review checked that transformation.

The new `authentic-public-journey-v2.py` has SHA-256
`2c28ba99030bf766ef385cd85d60d6400e3f0e525031a6101498883e0e04765e`.
Its only changes are the revised prose path, a fresh `authentic-native-v2/`
root, and corrected exception type reporting. The input and execution scope
above is unchanged. Independent security clearance is retained; a separate
configured approval must precede this revised run. No production code changed
in response to the refusal.


### Authentic fresh success and operation-mode correction

The separately approved v2 run personally accepted the exact scoped review
(54.95 seconds), then completed a fresh authentic minimal-plus-source
installation and final correspondence: 2,467 files checked, no initial default
assignment, in 128.29 seconds. Its installed tree, output and other artefacts
remain in `authentic-native-v2/`.

The following standalone `installation-check` refused the harness's inappropriate
`--cached-admission` option after 89.88 seconds. Static inspection deliberately
requires local mode; it does not constitute fresh admission. That correct
product refusal ended the run before adoption, manual-base addition or no-op
coverage. The fresh-install success is retained, but the whole v2 journey is
not marked successful. These debug-build timings include repeated authenticated
archive reconstruction and are not release-build performance measurements.

The revised program `authentic-public-journey-v3.py`, SHA-256
`5db1e33fc5c6120731037f565bbe3fc1f839678cfcbce632efadf13f8e27b2d1`,
uses a fresh `authentic-native-v3/` root and the same completed prose
`d9a93bdb7b005e866b7a1f8489c160ccda5c539f51eaf437a28755d57b7354b3`.
Its helper passes explicit cache reason/admission only to acceptance,
installation and adoption. It passes no freshness flag to `installation-check`,
which the frontend maps to local static inspection. The other three operations
retain the existing 24-hour bounded cached-admission policy. No operation
performs a new online source refresh, and the helper refuses any unreviewed
command name. All other inputs, process controls and intended native scope are
unchanged. This checkpoint precedes independent delta review and a separate
configured approval; no production code changed.


## Observed authentic completion and independent reconstruction

After independent delta review and configured approval, the exact v3 program
`5db1e33fc5c6120731037f565bbe3fc1f839678cfcbce632efadf13f8e27b2d1`
ran once against revised completed prose
`d9a93bdb7b005e866b7a1f8489c160ccda5c539f51eaf437a28755d57b7354b3`.
It exited successfully. The full 2,177,460-byte raw receipt remains at
`/private/tmp/barbican-parity-native.BRUXy8/authentic-native-v3/receipt.json`,
SHA-256 `00d4f19810a3c4171cbd8ad5e1defd75c2bc14489b33027f92cb32b6c41b4a05`.
The companion JSON retains exact inputs, command arguments/environments,
phase results, all 22 log hashes, product outputs and canonical tree digests;
the large raw tree snapshots remain external rather than being duplicated in
the repository.

| Case | Phase | Result | Observed seconds |
| --- | --- | --- | ---: |
| Control | Exact scoped acceptance | PASS | 55.07 |
| Fresh | Final installation | PASS | 128.72 |
| Fresh | Static installation inspection | PASS | 90.59 |
| Fresh | Explicit final adoption | PASS | 90.37 |
| Fresh | Complete add, absent evaluator | Verified no-op | 102.76 |
| Manual base | Same-manifest minimal seed | PASS | 7.53 |
| Manual base | Final inspection before source addition | Expected refusal, exit 1 | 65.80 |
| Manual base | Explicit source addition | PASS | 179.81 |
| Manual base | Static final inspection | PASS | 89.72 |
| Manual base | Explicit final adoption | PASS | 89.75 |
| Manual base | Complete add, absent evaluator | Verified no-op | 102.44 |

The eleven commands took 1,002.55 seconds in total. These are one observed
debug-build run, including repeated authenticated archive reconstruction;
they are not release-build benchmarks. Acceptance, installation and adoption
used the explicit bounded cached-admission reason recorded above. Inspection
used local static mode. The successful acceptance reused the exact matching
private acceptance already written by v2; it did not broaden its scope.

Both final trees contain 3,041 entries: 2,459 authenticated regular payloads
(Cargo 44, compiler 43, standard library 59, source 2,313), eight generated
metadata files and 574 directories. Fresh source metadata has target `*` and
`is_extension=false`; additive source metadata has target `*` and
`is_extension=true`. The three existing host-component flags remain false.
The added operation reports exactly Cargo/compiler/standard-library as its
verified base and `rust-src/*` as its sole delta under the final subject.
Both retries report an empty delta, `already_present=true`, and no initial
default assignment despite an absent evaluator path.

Independent reconstruction retained and checked all 171 base file/directory
identities, both final trees, original manifest projections, archive bytes,
ownership metadata, configuration, 22 logs, private settings and unrelated
sentinels. The three native-authorised aggregate metadata paths are checked
against final scope rather than required to retain their old identities;
installer-version content/identity remains protected with only its mtime
excluded. Update-hash identity equality was asserted by the exact passing
harness, but its before snapshot was not serialised: independent review
verified current original-manifest-prefix content and does not claim an
independently reconstructed prior update-hash identity.

All five monitored normal-state files retained their identities and bytes:
normal Rustup settings, the installed cargo-barbican binary, repository pin,
and existing trusted rustc/Cargo binaries. This is bounded observed state
preservation, not a whole-filesystem trace. All owned process groups were
absent at phase completion; `cancellation_observed=false`. No authentic
cancellation or rollback result is inferred. No Cargo, dependency build,
third-party registry, credential provider or source script was executed;
only Rustup's internal version probe used the already-trusted compiler bytes.

The independent report is retained at
`/private/tmp/barbican-parity-native.BRUXy8/authentic-final-independent-reconstruction.json`,
SHA-256 `2b1c0147c75ffd5d0cc88c83d68a790b1e56060e389dd17ae075b30f27e080e3`,
and reproduced in the companion JSON. It clears the reviewed implementation
scope subject to unchanged reviewed production source and retained canonical
verification, with no expansion of execution authority. The original failed
v1/v2 programs, prose, receipts and logs remain separate evidence. Live
private homes remain held until the coordinating agent confirms durable
retention and authorises cleanup.


## Optimised-build timing comparison — 12 November 2026

A fresh private replay used an optimised build of the same reviewed production
source at `edf135113fbb6461d9cfc116ea78e06003c729af`; later changes were confined
to user documentation. No verification rule, default, source permission or
cache freshness bound changed. The input copies contained only review data,
snapshots, archives and knowledge; acceptance/bindings/trust were not copied.
The same scoped prose was explicitly accepted into the fresh private context.

The eleven outcomes match: ten successes and the expected incomplete-scope
refusal. Both cases again verified 2,467 files/3,041 entries, including successful
inspection, adoption and absent-evaluator no-ops. The phase-duration sum fell
from 1,002.55 seconds (16m43s) in debug to 207.17 seconds (3m27s) optimised.
The separate 83-second optimised build is excluded from both journey totals.

| Case | Phase | Debug seconds | Optimised seconds |
| --- | --- | ---: | ---: |
| control | accept | 55.07 | 8.54 |
| fresh | fresh-install | 128.72 | 29.36 |
| fresh | final-inspection | 90.59 | 14.04 |
| fresh | static-adopt | 90.37 | 15.39 |
| fresh | complete-add-noop | 102.76 | 17.75 |
| manual-base-add | seed-manual-minimal | 7.53 | 11.12 |
| manual-base-add | incomplete-final-inspection | 65.80 | 12.09 |
| manual-base-add | add-components | 179.81 | 46.36 |
| manual-base-add | final-inspection | 89.72 | 19.05 |
| manual-base-add | static-adopt | 89.75 | 18.05 |
| manual-base-add | complete-add-noop | 102.44 | 15.41 |

These are single sequential observations on one machine, with OS-cache and
background-load differences, not statistical benchmarks or a latency promise.
The raw minimal seed was slower in this replay; no per-phase universal speedup
is inferred. This supplies a release-build baseline before considering future
profiling; no caching, parallelism or reduced security check was introduced.

Optimised binary SHA256:
`e499ec264b8ba98e0e9c0c5586ddc60072188023616e1823171939c6e03f2e76`.
Reviewed adaptation SHA256:
`56e1ca10e9fb31d0731c28da5eb28d7621f1dbb3cc0c9a816eab6730f91a1ff8`.
Raw receipt SHA256:
`923c74fabae907eabd6fc5d7c3f6788cda98c2c516bdb42637f116fc2399b7e0`.
Independent post-run verification SHA256:
`9bd5a728f1b784003705fb2907fd3efe5ecc6a2862d2c52a03b71b116001f428`.
The companion JSON retains exact phase output hashes/timings and verification.

The explicit cached-admission reason replays the exact assessed source facts
within their 24-hour bound; this is not an online security refresh. All 60 RustSec
rows, seven Cargo advisory facts and ten coverage unknowns remain. Only existing
trusted 1.95 compiler version probes ran; Cargo and source scripts were not
executed. The five monitored normal-state files matched before/after/live,
with the same update-hash before-identity and cancellation limits as above.
Complete replay evidence remains under
`/private/tmp/barbican-doc-amendments.7bCxNp`; private homes/live authority and
owned build targets are removed after retention and review.
