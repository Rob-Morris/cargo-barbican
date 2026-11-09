# Cargo-only qualification and native lockfile fixture

Date: 9 November 2026. **Completed: independent security review cleared the exact
bounded fixture, root authorised its pinned script and inventory, and all three
native metadata calls passed.** This is a Cargo-only qualification, not acceptance,
installation, adoption or activation of the Rust 1.99.1 toolchain. No repository
toolchain pin or normal user trust store changed.

## Exact identity and fresh authentication

The candidate is the existing native ARM64 Cargo executable:
`/Users/robmorris/.rustup/toolchains/1.99.1-aarch64-apple-darwin/bin/cargo`,
SHA-256 `6d576d8058f8ca643e8fce55b64ee3c614ba64c9da2e536bae843e6a2e1f3951`.
It is a regular 0755 file, 32,182,376 bytes, one hardlink, owned by the user.
Its parent directories through `.rustup` are regular user-owned directories.
Static Mach-O inspection identifies ARM64 and system-only dynamic-library imports;
it does not require candidate execution or the 1.99.1 compiler libraries.

The already trusted direct Barbican 0.38 collector performed a fresh, data-only
standalone minimal/aarch64 review at **2026-11-09 05:45 UTC**. It authenticated the
original signed manifest with the reviewed public seed, collected the official
publication/security/source material, and inspected the complete bounded current
RustSec corpus. All ten source observations completed; its result remains
`human-review-required`, with thirty whole-minimal source findings, twenty-one of
which concern the Cargo source corpus. No acceptance command was called.

- Signed manifest SHA-256: `fb152be80975c194aa5fc684b2aec3a6e14e2b855efe2faa4e5f8ae6e590f463`.
- Official Cargo XZ SHA-256: `685e563d94db1f003ffa5f5831439eec02569b9950b69867953c8213269c1eaf`.
- Supplier primary/signing fingerprint: `108F66205EAEB0AAA8DD5E1C85AB96E6FA1BE5FE`.
- Fresh review ID: `2321919172fc30690873a35b58e38d5506de6e54f204afa12af228bab9bae2d4`.
- RustSec snapshot: `7a40350e1b8ba5b656d909f88222a8059a83d88d`.

All **44 Cargo component files** were independently compared with the freshly
authenticated official archive: regular-file type, bytes, size and mode match.
This is archive correspondence, not reproducible-build proof. The installed
Rustup-rewritten channel manifest was not used as an authentication source.
The fresh manifest also matches the historically authenticated manifest recorded
in the [native qualification](2026-11-04-native-toolchain-qualification.md).

The signed Rust source commit is `58cf8f9c35b355199727627d07ae34a4e2846d67`.
Its independently fetched Cargo gitlink is
`5f94df4789f005f9a352888e8355ffc645b7ed0e`, whose source package is Cargo 0.100.0.
The archive version text agrees. Exact source was downloaded as nonexecutable data;
Cargo.toml and Cargo.lock agree with the collector's pinned source documents.

## Source semantics and execution boundary

[Exact Cargo workspace source](https://github.com/rust-lang/cargo/blob/5f94df4789f005f9a352888e8355ffc645b7ed0e/src/workspace/workspace.rs)
loads `resolver.lockfile-path` and makes its parent the lockfile root.
[Official configuration documentation](https://doc.rust-lang.org/cargo/reference/config.html#resolverlockfile-path)
identifies the default workspace lockfile, environment equivalent and 1.97 minimum.
The trusted 1.95 source already parses that field but only honours it behind the
nightly feature gate; enabling or bypassing that gate is not part of this proof.

[Exact metadata source](https://github.com/rust-lang/cargo/blob/5f94df4789f005f9a352888e8355ffc645b7ed0e/src/ops/cargo_metadata.rs)
resolves package metadata and may probe compiler target information. Every such
probe is forced to the explicitly trusted 1.95 compiler by an absolute `RUSTC`:
`/Users/robmorris/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc`,
SHA-256 `b829b733131d4e1673eeebd1f34d06ae1e9ff4977b051313cf42e2a9e79ecf1c`.
No candidate compiler/rustdoc, Rustup proxy, build script, proc macro or package
code is permitted. Candidate Cargo is not used for build, test, run, generation,
update, install, publication or even a preliminary version probe.

Cargo's `[env]` table is a child-process environment, separate from its captured
configuration environment. The exact source rejects `[env]` CARGO_HOME,
RUSTUP_HOME and RUSTUP_TOOLCHAIN; HOME can affect a nested default home when no
explicit CARGO_HOME exists. External Cargo subcommand dispatch sets CARGO and
jobserver context but does not itself apply the `[env]` table. These distinctions
are source facts; this direct resolver fixture does not claim to prove
every nested-process route.

## Prepared fixture and approved commands

All fixture state lives below the private task directory
`/private/tmp/barbican-lockfile-identity.aydBhg/native-proof/`.
`fixture-proof.py` and `fixture-pre-execution.json` retain the exact script,
environment, working directory and file/hash/mode inventory. The companion
[receipt](2026-11-09-cargo-lockfile-fixture.json) pins their hashes.

The trusted 1.95 Cargo seeded two authored local Git revisions and both complete
lockfiles/caches. Both manifests use edition 2021 and `build = false`. The only
dependency is a local file URL with version requirement `1`; no registry, optional,
platform, artifact, dev, build-script, proc-macro or native dependencies exist.
Both source files contain only a function returning a small integer.

- Version 1.0.0 commit: `36c7ed7e0c17e595921f066ea8103d8ea6bf0df6`.
- Version 1.1.0 commit: `65c072600b7384319470483cd181f0a94ac433ee`.
- Root lock SHA-256: `98811b93c0770b154f290e4f1e8aea6ff43c4375fc0072091c7f2d606404bd57`.
- Alternate lock SHA-256: `684e1769de101d3464a7df461fccfcd25fca07e6128bc9ef83972f4738e9c307`.

Trusted 1.95 frozen metadata confirmed the old lock, new lock, and restored old
lock each independently sufficient for the identical root manifest.

The approved candidate command was exactly the pinned Cargo executable followed by
`metadata --format-version 1 --frozen`, run three times: root configuration absent,
then an authored `resolver.lockfile-path` pointing to `alternate/Cargo.lock`, then
configuration removed. Expected selected versions are 1.0.0, 1.1.0 and 1.0.0.
Both lockfile hashes must remain unchanged throughout.

The script supplies a fresh environment rather than inheriting one: system-only
PATH, private HOME/CARGO_HOME/RUSTUP_HOME/target directory, absolute trusted RUSTC,
`CARGO_NET_OFFLINE=true`, `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`,
noninteractive Git and harmless fixed fixture author identity. No ancestor Cargo
config was present. Owned Git configs contain only ordinary local settings and
local cache origin URLs, with no filters, active hooks or alternates.
The candidate phase rechecks executable/compiler digests and the complete
pre-execution fixture inventory before spawning. Expected writes are confined to
owned Cargo cache/target bookkeeping and logs. Frozen/cache failures stop the run.

## Current Cargo findings and bounded assessment

Each row preserves the current finding rather than treating source-lock presence
as binary inclusion. The bounded operation uses no network peer, credentials,
private signing keys or untrusted package code. Offline alone does not dispose of
memory-safety findings; their exact source paths are assessed separately.

| Advisory | Bounded assessment |
| --- | --- |
| [RUSTSEC-2026-0173](https://rustsec.org/advisories/RUSTSEC-2026-0173.html) | Unmaintained proc-macro-error2: build-time macro dependency; no compilation of Cargo or its dependencies in this proof. Maintenance risk remains. |
| [RUSTSEC-2026-0204](https://rustsec.org/advisories/RUSTSEC-2026-0204.html) | Exact epoch affected fmt::Pointer implementations have no callers in epoch/deque; deque public Debug implementations emit literal strings. Exact source-lock reverse path is epoch → deque → ignore → Cargo. No affected formatter on this route. |
| [RUSTSEC-2026-0247](https://rustsec.org/advisories/RUSTSEC-2026-0247.html) | Unmaintained bitmaps: retained maintenance risk in resolver data structures; no universal library-safety claim. |
| [RUSTSEC-2026-0250](https://rustsec.org/advisories/RUSTSEC-2026-0250.html) | Unmaintained im-rc: used by Cargo resolver; retained maintenance risk. |
| [RUSTSEC-2026-0251](https://rustsec.org/advisories/RUSTSEC-2026-0251.html) | Unmaintained sized-chunks: used through im-rc; retained maintenance risk. |
| [RUSTSEC-2026-0255](https://rustsec.org/advisories/RUSTSEC-2026-0255.html) | Trigger requires element Drop to panic. Resolver im-rc elements are Cargo-owned data: PackageId (Copy), Summary/Dependency (Arc-owned metadata), DepsFrame (Summary plus RcVecIter<DepInfo>); DepInfo contains Dependency, Rc<Vec<Summary>>, Rc<BTreeSet<InternedString>>. im-rc has no custom Drop implementation; its non-pool wrappers use std::rc::Rc, and refpool is absent from source lock. Tiny fixture introduces no artifact/platform values or executable code into these types. Narrow trigger assessment, not a general soundness claim. |
| [RUSTSEC-2026-0258](https://rustsec.org/advisories/RUSTSEC-2026-0258.html) | HTTP/2 empty DATA-frame peer input absent: mandatory frozen metadata over already cached authored Git objects cannot contact HTTP peers. |
| [RUSTSEC-2026-0285](https://rustsec.org/advisories/RUSTSEC-2026-0285.html) | TLS handshake boundary peer input absent in mandatory offline fixture. |
| [RUSTSEC-2026-0306](https://rustsec.org/advisories/RUSTSEC-2026-0306.html) | Affected architecture is x86/x86_64 AVX2; exact executable and host are ARM64. Local Git hex parsing does not change that architecture constraint. |
| [RUSTSEC-2026-0346](https://rustsec.org/advisories/RUSTSEC-2026-0346.html) | No TLS sessions or custom session-cache Debug output in offline fixture; no secrets in the child environment. |
| [RUSTSEC-2026-0348](https://rustsec.org/advisories/RUSTSEC-2026-0348.html) | No Brotli certificate decompression or TLS peer in offline fixture. |
| [RUSTSEC-2026-0349](https://rustsec.org/advisories/RUSTSEC-2026-0349.html) | No unauthenticated ServerHello or persistent TLS session store in offline fixture. |
| [RUSTSEC-2026-0382](https://rustsec.org/advisories/RUSTSEC-2026-0382.html) | No certificate-chain verification or TLS peer in offline fixture. |
| [RUSTSEC-2026-0385](https://rustsec.org/advisories/RUSTSEC-2026-0385.html) | No secret-integer cryptographic operation in fixture; no credentials or private key material in child environment. |
| [RUSTSEC-2026-0386](https://rustsec.org/advisories/RUSTSEC-2026-0386.html) | Exact source-lock Tokio paths pass through reqwest/gix-transport HTTP. Cargo cached locked-OID branch returns before transport; offline missing-cache branch refuses before fetching. No direct AsyncFd use in Cargo source. This closes the proposed cached metadata route without asserting Tokio is absent from every distributor build. |
| [RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387.html) | No secret-integer cryptographic operation in fixture; no credentials or private key material in child environment. |
| [RUSTSEC-2026-0414](https://rustsec.org/advisories/RUSTSEC-2026-0414.html) | Requires ENABLE_WIKILINKS Markdown parser. Source-lock reverse dependency is mdman workspace tooling; metadata proof has no Markdown/wikilink operation. |
| [RUSTSEC-2026-0418](https://rustsec.org/advisories/RUSTSEC-2026-0418.html) | Requires compiling libz-sys build.rs with cc >=1.6. This uses prebuilt Cargo and metadata only, compiling no dependency. Git object decompression is not the affected build-script API. |
| [RUSTSEC-2026-0426](https://rustsec.org/advisories/RUSTSEC-2026-0426.html) | Listed affected architectures are s390x/x86/x86_64, not ARM64; no ML-KEM/ML-DSA operation in fixture. |
| [RUSTSEC-2026-0428](https://rustsec.org/advisories/RUSTSEC-2026-0428.html) | No BLAKE2b keyed reset or authentication operation in fixture. |
| [RUSTSEC-2026-0433](https://rustsec.org/advisories/RUSTSEC-2026-0433.html) | Requires ENABLE_WIKILINKS Markdown parser. Source-lock reverse dependency is mdman workspace tooling; metadata proof has no Markdown/wikilink operation. |

Exact dependency source archives used for the three memory-safety assessments
were checked against the independently mapped Cargo source lock. Retained sources
include crossbeam-epoch 0.9.18, crossbeam-deque 0.8.6, ignore 0.4.26, im-rc 15.1.0,
sized-chunks 0.6.5, gix 0.85.0 and gix-transport 0.57.2. The independent reviewer
confirmed the bounded dispositions before execution was authorised.

The Cargo default transport feature is curl; reqwest is a separate alternative.
[Exact Rust bootstrap source](https://github.com/rust-lang/rust/blob/58cf8f9c35b355199727627d07ae34a4e2846d67/src/bootstrap/src/core/build_steps/tool.rs)
can add `all-static` and configured per-tool features. Defaults therefore do not
prove every compiled feature in the shipped binary. The Tokio disposition instead
also relies on the exact cached Git branch: a locked OID already in the database
returns before any transport; offline cache misses refuse before fetching. This
assessment does not establish general safe network use or broad toolchain trust.

## Observed result and retained evidence

Exactly three direct candidate Cargo metadata calls ran after independent security
clearance and explicit root approval of script SHA-256
`564da124ed67e8f517799f7943e0896907f2ed20ef9d791315a4199b269758ff`
and inventory SHA-256
`49219fd1b0779756fb843b5e068edf09acd7ca828755d8ca8dceb69a4e31fed0`.
All exited zero with empty stderr: root selected 1.0.0 / `36c7ed7...`, alternate
selected 1.1.0 / `65c0726...`, and restored selected 1.0.0 / `36c7ed7...`.
Both lockfile hashes remained unchanged. No additional candidate probe or command
ran; every compiler probe used the trusted absolute 1.95 compiler.

The fixed direct Barbican binary separately refused `pin check` with the same
alternate configuration and exited one with the default-workspace-lockfile
explanation. Root/restored controls exited zero with the documented no-policy
skip. This is a pre-policy guard proof, not full reviewed-family conformance:
the authored file-URL Git dependency is outside Barbican's accepted Git-source
policy. That check used the same cleared private environment with trusted 1.95's
binary directory added to PATH for workspace discovery; it did not use candidate
Cargo. Both lock hashes again stayed unchanged. The receipt pins the fixed binary,
exact environment, outputs and result files.

The private task directory retains the fresh JSON/dossier, original signed inputs,
static component comparison, exact source, raw twenty-one advisories, source archive
checksums, seed outputs, executable script, complete fixture inventory and observed
native/fixed results. The companion receipt retains result objects and evidence
hashes. Independent security review separately rechecked the observed native
outputs. This evidence does not establish whole-toolchain admission, general
compiler compatibility, network-use safety or universal absence of vulnerabilities.
