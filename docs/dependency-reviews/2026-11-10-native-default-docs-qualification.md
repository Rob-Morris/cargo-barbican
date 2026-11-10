# Authentic macOS ARM64 Rust default/docs qualification

Date: 10 November 2026. **Completed — bounded macOS ARM64 machinery qualification.**
This record was written before authentic native handoff and now records outcomes. It qualifies a bounded machinery
route using the operator's already-trusted Rust 1.95.0 bytes; it is not a new
general compiler approval, a clean audit, or acceptance of Rust 1.99.1.

## Scope and authority

The operator has explicitly authorised use of already-trusted tools and the
reviewed implementation/qualification plan. The exact installed Rust 1.95.0
compiler/runtime is the inherited trust baseline. Test homes, data/cache,
repository pins and installations are confined to task-owned normal-layout
directories below `/private/tmp/barbican-native-default.CcQ6ha`. Normal user
Rustup/Cargo homes, defaults, repository pins and unrelated slots are unchanged.

Intended authentic execution is the existing qualified Rustup installer and its
ordinary internal compiler identity probe against matching 1.95.0 bytes.
No Cargo build/Git/network operation through candidate Cargo, rustdoc rendering,
documentation browser, Clippy or rustfmt invocation is included in that proof.
Ordinary product compilation separately uses the existing trusted repository
Rust 1.95 toolchain.

## Authenticated selected inputs

The trusted installed Barbican 0.38 collector performed a fresh data-only
default-profile review. Status remains `human-review-required`.
Original signed manifest SHA256:
`821ff14e4c4a1cbe1e8915f35aff0a3fbbdf8d293ad48ab8f31e3b0440c581f9`.
Signature SHA256:
`3a675df488a0be0e110c99b8c944c2ff4b6a416f34a4862e600a8144e7152dc3`.
Certificate SHA256:
`e54b09a439647e006b4831eec9785cbaaf3e07ab371c3a6ee6a68e1bdb9fbc6b`.
Approved primary/signing fingerprint:
`108F66205EAEB0AAA8DD5E1C85AB96E6FA1BE5FE`.

The original publication date is 16 April 2026; the ordinary seven-day floor
is satisfied without an age override. The six XZ archive identities and hashes
are retained in the companion receipt: Cargo, Clippy, rust-docs, host rust-std,
rustc/rustdoc and rustfmt. No manifest/format rewrite or preferred-format fallback
is proposed. Current public review uses XZ.

## Static inherited-byte correspondence

An independent streaming standard-library check hashed each complete authenticated
archive before parsing, derived selected file/directory ownership from its
component manifest and compared the selected content/types/normalised modes to
the existing trusted installation without extraction or execution.

| Component | Matched selected entries | Missing / mismatched |
| --- | ---: | --- |
| Cargo | 44 | 0 / 0 |
| Clippy | 5 | 0 / 0 |
| rust-docs | 53,415 | 0 / 0 |
| host rust-std | 59 | 0 / 0 |
| rustc/rustdoc | 43 | 0 / 0 |
| rustfmt | 5 | 0 / 0 |

These are per-component entries, including directories, not a unique-file count.
Both all-selected and compiler/runtime correspondence flags are true.
The check took about 47 seconds including archive decoding and installed hashing;
it is a single observation, not a latency guarantee. Script and inventories are
hash-bound in the receipt. It does not replace production complete-slot,
generated-metadata, ownership or publication checks.

Inherited executable SHA256 values:

- rustc: `b829b733131d4e1673eeebd1f34d06ae1e9ff4977b051313cf42e2a9e79ecf1c`.
- Cargo: `c512bff73c86143b557463f021d0c3d5b0490d97d65040ba59ea2b3427784758`.
- rustdoc: `59bc6a1caf617032284a2edc2aa03916396e70589c435a8b51e3957887f90ce5`.
- Qualified native Rustup 1.29.0 libexec:
  `16c7599bf448e4e7512779154f6b05042bf2ff715e5e09d9cf5d465a3b750496`.

## Current source findings and bounded assessment

The initial fresh source corpus snapshot is RustSec
`d9cb059f3217db87aeccd190b81eaffe8cc29cb9`.
It reports 104 scoped occurrences representing 40 advisory IDs.
All occurrences remain visible. Generic source inventory membership does not
prove a package shipped or a function is reachable in the installer/probe.

Independent security assessment grouped the 40 IDs as follows:

| Group | IDs / occurrences | Disposition for the proposed narrow proof |
| --- | ---: | --- |
| Maintenance notices | 7 / 16 | Retain supplier-maintenance risk; no immediate trigger inferred. |
| Explicit architecture exclusions | 2 / 2 | Reported affected architectures exclude ARM64. |
| Cargo-only recorded findings | 18 / 18 | Cargo is installed as data and not invoked; no claim its binary lacks affected code. |
| Build-script trigger | 1 / 5 | No libz-sys build script runs in prebuilt installation or the identity probe. |
| Git conditions | 3 / 14 | No Git workflow; compiler-root inclusion/reachability uncertainty remains explicit. |
| Archive conditions | 2 / 8 | Authenticated selected inputs, bounded parser policy and controlled private destinations constrain the reported symlink/PAX cases; parser/source provenance limits remain. |
| Compiler-source uncertainty | 7 / 41 | Retain specific unproved runtime conditions; trusted byte identity and narrow argv are not complete reachability proof. |

The companion receipt retains every occurrence and exact grouped IDs.
Compiler-source uncertainty includes RNG/logger re-entrancy, thin-vec panicking
destructors, invalid mmap ranges, anyhow contextual mutable downcast, cxx
initialisation panic, invalid-pointer formatting and crafted zstd/debug-symbol
decompression. For RUSTSEC-2026-0204 retain the advisory's title/narrative
Pointer-versus-Display inconsistency rather than inventing a general formatting
exemption. The proof relies on explicitly inherited operating trust for these
same already-used 1.95 bytes and retains these uncertainties; no clean-audit or
fresh general safe-compiler verdict is asserted.

Before the public accept/install journey, fresh schema2 collection supplied
the actual component/source/inventory/coverage matrix and an exact completed
private qualification record assessing all findings/unknowns. The initial
schema1 source report is evidence only and cannot satisfy the new default/docs
matrix requirement. Static low-level machinery proofs and the full reviewed
public-command journey remain distinct outcomes.

## Required pre-execution checkpoint

Independent review must approve the concrete script/test identity, original
signed inputs, all selected hashes, exact qualified evaluator, cleared private
environment/homes/argv and initial-default intent before authentic native
handoff. The current implementation must retain early acceptance/input binding,
unsupported-scope refusals, cancellation at final static verification and
success/binding boundaries, and honest retained-state outcomes.

Fresh schema2 review is now retained as
`0eec3c21973c8618bcf532a699b5520231d6a1eb3e62d0a36a0e7d66ce44cbcc`:
six actual component rows, the same 104 findings, and specific docs asset/source
limits. Its exact evidence and completed scoped-assessment input digest are
in the receipt. A separate scoped public acceptance and journey has now passed.

The proposed low-level launcher is `authentic-native-matrix.sh`, SHA256
`d1abbd9a0fcd4b788001ffc1adb68467037542e19aec9cc38498fba0fb4e29cd`.
It pins the exact product test executable SHA256
`bf22717faf93ca77d957455d75bb26ca27b070427bad839e9cb1de04c5aaf719`,
clears its environment, uses private homes and the exact qualified Rustup,
and requires a new owned proof root. The single isolated test installs the
existing native cancellation handler and exercises four authenticated real
1.95 selections through production mapping/install/verification/activation
owners. Captured baseline-qualification authority is a machinery control;
it is explicitly not fabricated personal admission. The full public default
command journey is a separate reviewed proof, recorded below.

The first native attempt under launcher umask077 refused installed output mode
`0700/0600` against the strict `0755/0644` mapping. It restored the owned initial
default and retained the private slot; it is recorded as a failed qualification
case. The revised matrix is
recorded separately; this failed case is never counted as a successful result. No new product
dependency, source permission, vendor change or compiler acceptance is inferred.


## Additional current official Cargo advisories

The retained GitHub Cargo security-announcement source also reports CVE-2026-5222 / GHSA-p688-r7jv-fm6f (sparse-registry credential URL normalisation) and CVE-2026-5223 / GHSA-jq42-7mfv-hm57 (third-party registry symlink source-cache overwrite), affecting Cargo before 0.97.0, including represented Cargo 0.96.0. These are additional to the 104 RustSec occurrences / 40 IDs; those counts are not total advisory coverage. Neither operation is activated in this private proof because Cargo is never invoked and no registry authentication/source-cache workflow is requested. Do not transfer that disposition to arbitrary Cargo use or claim those sources were clean. Current official blog index supplies title/link evidence rather than exhaustive historical advisory or full-article review. The official security policy limits upstream updates to latest stable; inherited use of already-trusted 1.95 is not a claim of current upstream maintenance or recommendation for new general adoption.

## Applied-mode qualification refinement

The revised low-level launcher creates its private parent homes under077, then
sets022 only for the proof process before native dispatch. It uses a fresh
`authentic-native-matrix-022` root and the same pinned test executable, evaluator
and authenticated inputs. Script SHA256:
`aada523346c71eaa545d288cce568a64bd641a3d0019e13c4e2163f6b7cc7763`.
It received independent Astra security and root GO before execution. The original
failed root and logs remain unchanged. No failed files were chmodded or repaired.

The product refinement validates observed creation modes in its existing private
Scratch before new-install Rustup help/install dispatch: requested file0666 and
directory0777 must actually yield0644/0755. Unsupported modes refuse before
installer/candidate execution, with command-local022 guidance. Existing-slot
static checks do not acquire an irrelevant input-mode prerequisite. This is not
a raw-umask query or destination-specific ACL attestation; final independent
installed verification remains authoritative. No global mask mutation, new
subprocess/dependency, relaxed mapper or post-install repair is added.

## Separate public default-profile journey

The release-build static review in a separate private evidence store has exactly
the same subject, six component rows, 104 findings and assessment identity as
the reviewed schema2 inputs. This avoids modifying the captured low-level
matrix store while it runs. No copied personal acceptance supplies authority.

The concrete Python launcher invokes the real public review-ID commands with
a completed scoped inherited-trust record: accept/publish private repo admission,
install with explicit initial-default intent, installed/admission checks, static
adopt and explicit pin activation/no-op. The private policy names an explicit
task-only admission scope and the same seven-day floor. Child-only mode022 and
cleared private homes are recorded; normal user state is hash-checked before/after.
It owns and forwards INT/TERM to its child, whose native cancellation owner
controls Rustup. Input/script/release-binary hashes are pinned in the receipt.
The exact launcher received independent Astra security and root GO, then ran
all eight phases successfully. Every stdout/stderr digest was independently
rechecked, along with protected normal-state bytes and modes.


## Observed public-command outcomes

The optimised product binary completed the real public default-profile route
with exact schema2 review `0eec3c21973c8618bcf532a699b5520231d6a1eb3e62d0a36a0e7d66ce44cbcc`
and the hash-bound completed inherited-trust assessment. All commands exited 0:

| Command | Observed outcome | Seconds |
| --- | --- | ---: |
| accept | Personally accepted; task-only repository admission | 18.50 |
| install --allow-initial-default | Installed and statically verified 52,137 files | 43.75 |
| installation-check | Installed-verified | 24.14 |
| admission-check explicit review | Admitted and installed-verified | 25.08 |
| adopt | Adopted and installed-verified | 30.12 |
| activate | Private pin changed; compatibility unchecked | 23.90 |
| admission-check from pin | Admitted and installed-verified | 24.06 |
| activate again | Pin unchanged; compatibility unchecked | 23.74 |

These are single observed phase costs, not performance guarantees. The private
pin retained its comment, unrelated declaration and 0640 mode. Normal Rustup
settings, installed Barbican and real repository Rust pin remained unchanged
in both bytes and modes; independent security rehashed them. Complete argv,
cleared environment, statuses and output digests are in the companion receipt.
The private repository acceptance is real but purpose-bounded; it must never be
imported into normal user authority or treated as a new compiler approval.

The four-selection low-level matrix and canonical verification passed. Other hosts, cross targets, unqualified evaluator builds
and unsupported native encodings remain refused. No normal-user binary or Rust
toolchain update, publication, dependency/source grant or clean advisory verdict
is claimed.


## Observed authentic profile matrix

All four exact selections passed real installation, complete static installed
correspondence, already-present no-delegate installation and explicit private
pin activation followed by unchanged activation. The docs selections also
refused tampered, missing, wrong-mode, wrong-type and unexpected extra docs;
restored controls passed final complete inspection. No silent repair obtained
PASS. The original failed 077 attempt remains recorded separately.

| Selection | Checked files | Install seconds | Inspection seconds |
| --- | ---: | ---: | ---: |
| minimal | 153 | 44.39 | 26.15 |
| minimal + docs | 52,125 | 115.01 | 75.09 |
| minimal + Clippy/rustfmt | 165 | 47.23 | 27.81 |
| default | 52,137 | 96.57 | 68.78 |

This explicit ignored test ran alone with no ignored tests in that invocation:
1 passed, 0 failed; total 1,507.21 seconds in the debug test build. Total includes
repeated complete negative-control inspections; it is not an ordinary command
latency. The companion receipt binds final logs and per-case subjects. This
low-level test uses captured inherited-baseline machinery authority, whereas the
separate public journey proves actual scoped personal/repository acceptance.

The current product creation-mode preflight separately passed four isolated
077/022 × existing/absent-default controls before these final receipts. Actual
SIGINT/TERM tests cover final fresh/existing installed verification, success
and continuing-binding publication boundaries. Canonical tests re-ran
those regression controls with the final source and passed.


## Final verification and review

The canonical `sh scripts/verify.sh` ran with no flags and exited 0, reporting
`Verify: PASS` and `Gatehouse pre-release: PASS`. It passed 937 tests with
19 declared ignores and no failures. The authentic four-selection test above
was explicitly run separately rather than counted as skipped qualification.
The vendor custody guard and scoped product formatting passed. No runner or
consumer adoption execution surface changed, so their separately triggered
real-tool suites were not required; ordinary scaffold/version tests passed.

Sol reviewed all six software-design concerns and independently cross-checked
code, scope documentation, version bundle, actual native/public receipts and
normal-state hashes. No findings remain. Independent Astra security reviewed
source/advisory applicability, exact pre-execution checkpoints, code and actual
receipts. No code or qualification security finding remains.

The result enables only the observed host/evaluator/encoding/component route.
A release still needs its own current review and explicit acceptance; this
record grants no normal-user authority and does not assert a clean compiler.
Task-owned builds, native homes and private admission authority are removed
after evidence retention. No normal binary upgrade or publication is included.
