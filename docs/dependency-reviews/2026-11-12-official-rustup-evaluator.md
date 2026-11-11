# Official Rustup 1.29.3 ARM64 native evaluator

Date: 12 November 2026 (Australia/Sydney).
Status: **Static review and exact-build native/product qualification complete.** The original static record below
preceded the first candidate execution.

## Exact artefact and supplier boundary

The candidate is the official prebuilt `aarch64-apple-darwin` Rustup 1.29.3
`rustup-init` distribution, 11,408,656 bytes, SHA256
`63752a1919a3a4793173ec70f8f212621a7ce38ba6a246095984482f4de20f9f`.
It matches the [official checksum](https://static.rust-lang.org/rustup/archive/1.29.3/aarch64-apple-darwin/rustup-init.sha256).
The original remains a non-executable independent data file in owned scratch.
The source revision is `edbc831cec44dc2858a4a4dce768c74361d027dc`;
retained source archive SHA256 is
`2c18f9d3a2935a4e9da395e168dd53af39b0723f6652f95979a2c2aa6d4367db`.

The [3 November release](https://blog.rust-lang.org/2026/11/03/Rustup-1.29.3/)
clears the ordinary seven-day maturity floor at this review. It includes the
TLS correction from 1.29.2. The initially investigated official 1.29.0 build
is not selected for new ordinary onboarding: source similarity to the already
qualified Homebrew build does not justify recommending an older vulnerable
online Rustup. Existing trusted tools retain their separate operating trust.

The checksum is supplier data obtained over official HTTPS, not independent
publisher signing. Static inspection observes ARM64, an ad-hoc linker signature
and system-library dependencies; it does not establish a publisher signature,
reproducible source-to-binary correspondence or absence of supplier compromise.
Rust distribution signing-key approval does not itself approve this executable.

## Current source/advisory assessment

Independent security review retained all 353 represented lock packages and
170 advisory/version matches at RustSec revision
`fd6f39814c4d3c359fdbe223d0280dec4933f78f`: 167 patched/unaffected,
two withdrawn and one unresolved supplier-build finding. This is not a clean
audit or proof that each source dependency is present/reachable in this binary.

The unresolved [RUSTSEC-2026-0418](https://rustsec.org/advisories/RUSTSEC-2026-0418.html)
match is `libz-sys 1.1.24` with `cc 1.10.0`. Its build-script probe can print
compiler environment into cached build output. `curl-sys` reaches this source
on macOS, and the inspected supplier macOS build does not force the static
libz path that avoids the affected probe. Explicit AWS credential setup appears
after compilation, but the job has OIDC permission and its actual historical
environment/cache was not inspected. No claim is made that secrets were absent
or the supplier was compromised. The build script does not execute when using
the prebuilt binary, and no local Rustup source build is proposed.

The represented graph, exact ranges, withdrawn status, raw advisory hashes,
source URLs and rationale are retained in the companion JSON and source ledger.
Remaining native/system-library and supplier-build uncertainties stay explicit.
No dependency, vendor, licence or source-permission change to Barbican is made.

## Proposed private execution envelope

Independent Astra security reviewed the concrete authored program
`/private/tmp/barbican-parity-native.BRUXy8/native-official-1.29.3-proof.py`,
SHA256 `023776e3f9bc3c45d737edd062d7dcb413931cd1fc21b9ec1d5781c50d540502`,
and its unchanged input ledger
`f7499883122fcc384dc67bf3f5dcbb26215e93fe2fa6c667543c9ee5689e5460`.
The proposed invocation is `python3 <that-program> --execute-reviewed-native-proof`.
Configured approval for this exact action remains a prerequisite.

Only after that approval, the program creates a new private directory and an
independent protected executable copy named `rustup`; it verifies its exact hash
before every dispatch and leaves the original data untouched. It uses cleared
environment, owned normal-layout homes, a selected-only local file mirror,
disabled auto-install/update controls, known harmless compiler/Cargo/std fixtures
and a non-executable authored rust-src file. No genuine new Rust compiler,
Cargo build/test, documentation renderer or normal-user installation is involved.

Five cases check native addition, missing selected archive, sequential partial
effect, preserved destination conflict and fresh rust-src installation. Capture
actual metadata, old payload/ownership/directory identities, settings, unrelated
slot/default, probe counts and complete expected paths/types/modes. Signal
handlers latch cancellation; owned process-group termination and reaping finish
before another phase. Any unexpected upstream concurrency/bookkeeping behaviour
is a failed qualification, not permission to repair output or weaken checks.

These controls constrain intended execution; they are not an OS network sandbox,
general malicious-input proof or qualification of every cancellation route.
Source/native behaviour cannot be inherited from the Homebrew 1.29.0 binary:
upstream changed component concurrency, file locking and settings since then.

## Evidence and enabled-support rule

Static assessment JSON SHA256:
`c6bdd5b20d26a0c82e0b750bb77141a5a8626b1fb424d002a49166ec8d3a4ae9`.
Its input/result ledger SHA256:
`f84b87482c7578784f3bdf188fd53e8aa4acaff1218b179a3f92b30bbf6ee605`.
Data-only reproduction script SHA256:
`88b6acd4c45368f618668f3bcfa908c1fbf6ef806839ca176a2e1ea05de7f4ed`.
Raw snapshots remain under
`/private/tmp/barbican-parity-native.BRUXy8/static-assessment-1.29.3/`.

The eventual product route must remain a closed exact-build qualification,
checking identity before isolated help/effects and using only reviewed inputs.
It is not general online Rustup approval or a Rustup installer/updater. A new
Rust distribution still requires its own current evidence and explicit local
acceptance before its first probe. This document alone enables no new hash,
acceptance, continuing binding or native support; approval, observed proof and
final independent code/security review must be recorded first.


## First execution and narrowly revised proof

Configured approval authorised the exact original private program after the
record above. Native installation and rust-src addition succeeded; a missing
selected archive refused. The old sequential-partial expectation then failed:
1.29.3 resolves every requested component before applying the update, so an
unknown later name left the minimal base unchanged. All 13 captured base
identities plus settings, update hash, unrelated sentinels and probe bytes
matched. The complete qualification is recorded as failed, not a pass or repair.
This specific prevalidation behaviour is not a universal rollback guarantee.

The revised program uses fresh evaluator/run roots and exactly expects that
source-proved unchanged state. Its SHA256 is
`b0b49f387c10b40ccbdb2ecfb466b7b401feaa912180d75c438e0f72212ded75`.
Independent security rechecked the exact delta and recommends scoped configured
approval. Configured approval authorised this exact revised program. It completed with
all five cases passing: native addition, missing selected archive, whole-list
invalid-component prevalidation, preserved destination conflict and fresh
rust-src installation. Original failed files/receipt remain untouched.

The successful receipt SHA256 is
`cad9724d3509a733871c6a30bcceb118d2e08c9182c87fa83a52bf80dfd4dd74`.
This qualifies the specified fixture effects and metadata for this exact build;
it does not establish real Cargo/rustdoc conformance, universal rollback or
cancellation behaviour. The actual adapter and authentic operation results below complete the product
invocation proof; the supplier-build uncertainty remains unchanged.


## Product integration and authentic machinery outcome

The enabled closed route checks this exact protected independent regular file
before any process, binds version1.29.3 to its digest, and deliberately supplies
Unix `argv0=rustup` even when the path ends in `rustup-init`. Unknown hashes,
symlinks, multiple hardlinks and unqualified hosts remain refusals. There is no
automatic evaluator download, update or diagnostic execution fallback.

The actual product adapter fixture passed with retained stdout/stderr and receipt
SHA256 `c5ccd7d397abfd20a2f6c0d06252b6d677b59e8a0d788d22807dc679752af302`;
independent security rechecked its exact test executable and output. The
[authentic source/addition qualification](2026-11-12-rust-src-additive-qualification.md)
then passed public acceptance, fresh install/check/adopt/no-op and manual minimal
base plus explicit add/check/adopt/no-op. Both cases verified2,467 files through
this evaluator, using only byte-matched existing trusted Rust1.95 and authenticated
source as data. Final receipt SHA256:
`00d4f19810a3c4171cbd8ad5e1defd75c2bc14489b33027f92cb32b6c41b4a05`.
Normal user state is unchanged. Failed earlier harness expectations and safe
product refusals remain separately retained; none were converted into a pass.

Shared real signal/process-group/reap and publication-boundary tests qualify the
unchanged cancellation owner. Source inspection of this evaluator found no
session/group escape path in its added concurrency. The raw five-case and
authentic runs did not observe cancellation; they imply no atomic rollback,
crash durability or precise interrupted native state. This record grants no
new compiler acceptance, general Cargo use, broad online Rustup approval or
source-to-binary reproducibility claim.
