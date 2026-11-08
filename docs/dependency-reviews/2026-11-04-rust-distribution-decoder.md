# Dependency Review: bounded Rust distribution decoder

## Summary

- Date: 2026-11-04.
- Reviewer: Astra implementation agent; independent design/security review remains a separate gate.
- Scope: data-only, single-threaded XZ decoding for exact Rust distribution archive inspection. No CLI, trust, admission, native installation or candidate execution is authorised by this record.

## Classification

Elevated-risk: public compressed input and a new decoder boundary. Pure Rust does not imply memory-safety of every transitive implementation or immunity to resource exhaustion. Source review precedes the first qualification build; runtime qualification is recorded separately below.

## Targets

`lzma-rust2 =0.23.0`, default features disabled, only `std,xz`. Exclude encoder, optimisation and lzip features. The selected decoder calls `XzReader::new_mem_limit`, single-stream mode, never the multithreaded reader or unbounded constructor. Existing `miniz_oxide =0.9.1` supplies streaming raw DEFLATE; its crate-inspector allocation/header shortcut is not reused. Existing `tar =0.4.46` supplies header values only, with bounded physical headers and explicit GNU long-name handling. Existing `sha2 =0.10.9` remains the archive/file identity owner.

## Inheritance

First-principles for the XZ route and seven new SHA-2 dependency selections. Existing exact cfg-if, libc and typenum selections retain their existing reviews; this change does not refresh them. Existing miniz/tar/toml/sha2 records do not establish distribution format or resource compatibility.

## Reviewed Target Set

| Package | Exact version | SHA-256 |
|---|---|---|
| lzma-rust2 | 0.23.0 | f1c46f3fcd2e888afdb01a07efc071cb21300e07c68d32c3e8b01b5c8cb1fcaa |
| sha2 | 0.11.1 | 47d7069beb7d6ac7b9acd1039986e73443f24234f41074da099d6f994ac9ad19 |
| digest | 0.11.3 | f1dd6dbb5841937940781866fa1281a1ff7bd3bf827091440879f9994983d5c2 |
| block-buffer | 0.12.1 | d2f6c7dbe95a6ed67ad9f18e57daf93a2f034c524b99fd2b76d18fdfeb6660aa |
| crypto-common | 0.2.2 | ce6e4c961d6cd6c9a86db418387425e8bdeaf05b3c8bc1411e6dca4c252f1453 |
| hybrid-array | 0.4.15 | 27f864f10dfb56725ce5ce5472bc52252c8f93a4ab86327122cebf62c5f59a17 |
| cpufeatures | 0.3.1 | 5ca28b0ae3115b884660db4118d803791fd6756b6e88f39c0f3f7859060d7566 |
| const-oid | 0.10.2 | a6ef517f0926dd24a1582492c791b6a4818a4d94e789a334894aa15b0d12f55c |

Preserve existing cfg-if1.0.4/libc0.2.186/typenum1.20.0. No new build.rs, proc-macro, native-sys or advisory allowances. No licence-policy expansion: decoder Apache-2.0, new RustCrypto dependencies MIT OR Apache-2.0. SHA-2 0.11 defaults enable alloc/oid, digest block-api/oid; optional random/MAC/zeroize/dev features are absent. Native CPU capability detection is pure Rust plus existing libc OS queries, not an external native toolkit. Highest selected MSRV is sha2's1.88, below repository1.95.

## Release Age

Registry index publication times: lzma-rust2 2026-10-18T05:55:43Z; sha2 2026-10-12T18:58:22Z; block-buffer 2026-06-11T15:40:05Z; digest 2026-05-03T12:54:48Z; crypto-common 2026-05-19T16:01:22Z; hybrid-array 2026-09-08T18:21:39Z; cpufeatures 2026-08-26T18:39:59Z; const-oid 2026-01-07T23:11:57Z. All exceed seven days and were not yanked in inspected registry metadata. Source archive hashes match registry identities. API metadata endpoint returned403; static registry index/source routes supplied the successful evidence.

## Advisory Review

Initial local RustSec snapshot40f5be6fb12ed93fc591bf4ab23b7d793b3f2239 (2026-10-28) has only historical sha2 RUSTSEC-2021-0100 among these package names, fixed >=0.9.8;0.11.1 is outside its affected range. Fresh cargo-audit --no-fetch on the exact isolated decoder lock against freshly fetched RustSec revision965bf9ad083b58e6340d65829d85217b18be9290 (checked4Nov) reports zero vulnerabilities and warnings across12packages. Fresh integration audit remains mandatory before commit; absence of a package advisory is not a safety proof.

## Source / Upstream Review

Primary source: https://github.com/hasenbanck/lzma-rust2 and exact crates.io0.23.0 source archive. Maintained fork of lzma-rust, ported from Tukaani XZ for Java. The0.21–0.23 changelog addresses pre-allocation memory checks, incremental dictionary allocation, reserved flags/filter chains, empty-stream iteration and streamed index parsing. Pinning an older release solely to retain sha2 0.10 would lose relevant public-input fixes. `lzma-rs` has a smaller older codec surface but is not a drop-in qualified bounded reader; native xz2/liblzma contradict the pure-Rust product boundary.

Reviewed XzReader/filter chain, stream/header/block/index/footer parsers, LZMA2 reader memory calculation and dictionary growth, CRC implementation and feature gates. With optimisation disabled the decoder forbids unsafe Rust. `new_mem_limit` checks LZMA2 dictionary plus estimated overhead before construction, and dictionary growth uses fallible bounded reservations. The wrapper reserves a fixed-buffer margin within512MiB, caps compressed1GiB/expanded8GiB, drains the full decoded tar and compressed stream, rejects concatenation/nonpadding trailing data, and checks complete compressed SHA-256 before decoding a caller-owned independent snapshot. Checksum validation covers blocks and framing CRCs; known index semantics below must not be misrepresented.

**Known bounded-reader limitation:** XzReader checks index CRC and record count, but does not reconcile each index size with decoded block sizes or its backward-size field with index length. XzStream validates more index semantics but retains per-block records without a public record-budget API; a claimed small index count cannot bound actual block records. The selected XzReader route has constant index memory. This record does not claim full XZ conformance validation. Three native authored cases on exact trusted macOS arm64 Rustup1.29.0 (binary SHA25616c7599bf448e4e7512779154f6b05042bf2ff715e5e09d9cf5d465a3b750496) showed valid and valid-CRC index-size/backward-size mutations all decode10240tar bytes and each installs its own four expected files with matching SHA-256 (the authored sentinel path differs per case); harmless authored rustc sentinel is probed in each. Python/liblzma full decoding rejects the two malformed variants. Rustup source package.rs passes XzDecoder to tar entries without a final decoder drain, consistent with the native result. There is no downstream index-refusal guarantee. Root accepted the scoped payload-integrity route: index sizes/backward sizes never authorise allocation, mapping, byte budgets or safety; exact compressed hashes still bind accepted inputs, and the wrapper must fully consume/reject extra decoded or compressed payload. No actual downloaded compiler/installer payload executed; this is exact evaluator/platform fixture proof, not authentic installation or all-platform proof.

Reviewed the additional RustCrypto manifest/feature graph and selected hash dispatch, block-buffer bounds and initialisation, hybrid-array slice-length/layout invariants, const-oid fixed-size values and CPU feature queries. SHA-2 0.11 uses feature-gated hardware intrinsics (and fallback software), with runtime capability checks; block-buffer/hybrid-array contain unsafe layout/initialisation code. This is a scoped first-principles review, not a formal proof or claim that transitive code is all safe Rust. No networking, subprocess or new generated build/proc source is selected. Existing digest identity remains sha2 0.10.9 force-soft.

## Commands Run

- HTTPS static.crates.io source download and index.crates.io exact-version metadata; SHA-256 comparison before review/build.
- `cargo metadata --offline --format-version 1` on isolated decoder-only resolution; precise existing-version reconciliation for libc/cfg-if/typenum; no build during discovery.
- Source/feature/execution-surface review of resolved manifests and relevant implementation owners; local RustSec source review.

## Outcome

The source/licence/age record preceded execution of the **exact reviewed decoder graph** and its product dependency addition. It does not claim that every scratch dependency execution obeyed that order: an expanded harness accidentally resolved newer transitive versions and started compilation without prior review. The [execution incident receipt](2026-11-04-rust-distribution-execution-incident.json) records the command, eight selected versions/checksums, observed compilation, interruption and unavailable initial build outputs. Independent security review was retrospective, not prior approval. Subsequent execution used an explicitly reconciled exact lock, offline/locked mode and trusted compiler/wrapper controls after root released the review hold.

The [qualification receipt](2026-11-04-rust-distribution-proof.json) records the observed result: all six authentic1.99.1 aarch64-apple-darwin XZ archives completed in23.1763seconds, with1332193280 actual expanded tar bytes and67644 mapped entries. Every destination, type, size, mode and regular-file SHA256 matches independent retained Python JSONL receipts; zero missing/unexpected/changed entries. Docs accounts for125063 physical/67505 effective headers and67488 recursively mapped entries. LLVM143609472bytes was streamed. Original manifest SHA256 is fb152be80975c194aa5fc684b2aec3a6e14e2b855efe2faa4e5f8ae6e590f463. Product TSV SHA256 is3d7e90140913f2f8b577b364d5564496822aecf349eeda09aea2a256b9f0d838; comparison receipt SHA256 is a767ac70daf82e9d2608c4bd347b6616ad7857055df67b51b5160fe75b134dc0.

Initial authentic inspection refused Cargo's omitted LICENSE-THIRD-PARTY root metadata filename. The independent reference inventory explicitly lists it; that exact metadata classification was added, then all six were successfully rechecked. It grants no installed-payload authority. Five pre-existing archives were read/hash-checked without deletion; only the docs archive was fetched into task-owned scratch. No authentic payload was extracted, installed or executed. Fresh conditional GPG verification under the explicit full test fingerprint preceded decoding; it is not independent approval of the publisher anchor.

Final isolated exact-source suite:19tests passed (17distribution plus2existingSHA), zero failures,8.40seconds after the two equivalent clippy lint corrections. The same-fixture index-only mutation produces identical payload mapping/actual expanded counts, while block/payload corruption, truncation, extra streams, nonpadding trailing data, unsupported tar shapes, dangerous paths/modes, oversized bodies and bounded-header floods refuse. Tests stream128MiB+1 individual bytes and exercise real200001-header floods. The preserving editor's cases pass without a new dependency.

## Follow-ups

This closes the bounded decoder/authentic mapping prerequisite for one release/host/XZ sample, not complete feature qualification. Native index controls qualify only the recorded trusted Rustup build and authored fixtures; GZip has authored decoder controls, not an authentic six-archive native proof. Authentic installed/generated bookkeeping, other promised hosts/evaluators, acceptance/admission/install routing and independent final review remain separately gated. Integration owns exact checked-in lock/pin enforcement, fresh union audit and canonical verification. Keep all product trust/admission/install routes unavailable until root reconciles the applicable gates.
