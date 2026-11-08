# Dependency Review: scoped toolchain cancellation

## Summary

- Date: 2026-11-04.
- Reviewer: Codex root first-principles source/graph review; independent Sol and Astra pre-commit review remains required.
- Scope: SIGINT/SIGTERM observation during one explicit native toolchain CLI operation, so owned Rustup children can be stopped/reaped before reporting cancellation. No general process framework, native toolkit installer or changes to existing Cargo test-runner selection.

## Classification

Elevated-risk: process-wide signal state and unsafe platform FFI inside established dependencies. Application code keeps the workspace unsafe-code prohibition and uses only safe atomic-flag registration.

## Targets

| Package | Version | Archive SHA256 | Published |
|---|---|---|---|
| signal-hook | 0.3.18 | d881a16cf4426aa584979d30bd82cb33429027e42122b169753d6ef1085ed6e2 | 2025-05-09T10:44:51Z |
| signal-hook-registry | 1.4.8 | c4db69cba1110affc0e9f7bcd48bbf87b3f4fc7c61fc9155afd4c469eb3d6c1b | 2025-12-25T17:35:43Z |
| errno | 0.3.14 | 39cab71617ae0d63f51a36d69f866391735b51691dbda63cf6f96d042b63efeb | 2025-09-09T04:35:15Z |

Direct edge: `signal-hook = { version = "=0.3.18", default-features = false }` in the binary only. Current minimal lock has six registry packages: the three additions above and existing reviewed libc0.2.186, windows-sys0.61.2 and windows-link0.2.1. Metadata resolution retained those existing versions. No channel/iterator/extended-siginfo/cc/serial_test feature or development dependency is selected.

## Inheritance

First-principles for the three new exact sources and their selected APIs. Existing libc and Windows bindings inherit the actual matching repository records/checksums; source and features are still reconciled at product integration. The standalone metadata-only root and lock are evidence, not product graph approval or a build receipt.

## Reviewed Target Set

The binary manifest addition must follow this record. Product integration must declare the exact three new registry checksums in normal reviewed families and `signal-hook = ["build-rs"]` as the reviewed execution surface. Its selected build script is intentionally a no-op. Preserve every existing reviewed target/grant and verify the final additive graph before execution. No source-policy or advisory exception is introduced here.

## Release Age

Fresh sparse-index entries and downloaded archives were compared on4November. All three exact versions are non-yanked and older than the effective seven-day floor. No age exception. The selected MSRVs (registry1.26, errno1.56, inherited libc1.65) fit the trusted Rust1.95 compiler; actual integration compilation remains required.

## Advisory Review

Trusted cargo-audit read the exact isolated lock with `--no-fetch --db` against freshly checked RustSec commit965bf9ad083b58e6340d65829d85217b18be9290. Exit0: zero vulnerabilities and no informational warnings across seven packages including the inert review root. The JSON omits database commit fields for this explicit local directory; the Git revision was obtained independently, not fabricated from that JSON. No advisory acceptance is needed. This does not replace the final full-product audit.

## Source / Upstream Review

Primary sources: [signal-hook repository](https://github.com/vorner/signal-hook), exact published0.3.18/registry1.4.8 sources, [errno repository](https://github.com/lambda-fairy/rust-errno), and fresh registry index identities. Archive digests matched before bounded source-only extraction; extracted files were made non-executable.

Traced `flag::register` into the registry. Its installed action only stores a shared atomic flag with SeqCst ordering; allocation and handler registration occur outside signal delivery. Registry signal dispatch uses its existing reader/writer generation mechanism; handler reads avoid locks/allocations, and ErrnoGuard restores the interrupted thread's errno. Mutations are serialised outside the handler. The Unix registration/dispatch and lifetime implementation uses reviewed unsafe libc FFI internally; Barbican adds none. This is a proportionate source review, not a formal proof of all dependency APIs.

Read registry registration, previous-handler delegation, unregister behavior, half_lock and vec_map ownership. **Unregister does not restore the default/previous handler** when the last action is removed; termination signals can subsequently be ignored. The accepted application scope therefore holds flag handlers through the entire single real CLI operation (child termination/reap, output verification, retained-state/default handling and command shutdown), rather than advertising restoration on an early guard drop. Do not use abrupt conditional shutdown/exit to bypass owned-child cleanup. Any reusable/embedded long-lived handler lifecycle needs separate qualification.

Read errno's selected Unix getter/setter and description code: platform thread-local errno access through existing libc, no network/process/filesystem effects. Signal registry only needs numeric get/set in its handler. Windows bindings add the existing diagnostics feature but Windows native toolchain operations remain unsupported; no Windows signal-race guarantee is inferred.

The signal-hook0.3.18 `build.rs` has an empty main when extended-siginfo-raw is disabled. The optional C build/cc dependency is absent from the resolved feature graph. Registry and errno declare build=false; no new proc macro or external native build is selected. Existing libc build behavior remains inherited. Licences are MIT OR Apache-2.0 (signal-hook's deprecated slash expression is the same disjunction), compatible with the current minimal permissive policy; no allow-list expansion.

## Commands Run

- HTTPS exact source/archive and sparse-index fetch; SHA256 comparison.
- Source-only bounded archive extraction and API/feature/build/unsafe-effect inspection.
- Trusted absolute Cargo/rustc1.95 metadata-only resolution seeded from the existing lock; no new dependency code built.
- Trusted cargo-audit against the isolated lock and explicit current local database, no-fetch; source package-name cross-check of the database.

Metadata, audit JSON and non-executable source receipts are retained under /private/tmp/barbican-rust-impl.21mZWk/signal-* for the implementation/review handoff. No compilation/execution of these additions occurred during this source decision.

## Outcome

Accept this exact minimal graph for scoped Unix cancellation implementation and tests after the product edge/lock/policy reconciliation. The native owner must prove real SIGINT/SIGTERM behavior, bounded group termination/reap, no late effects and a deliberately broken abandonment control. Existing runner behavior and unqualified hosts remain unchanged. Runtime correctness, independent review and full canonical verification are still required before commit.

## Follow-ups

Re-review feature/version/API expansion or long-lived handler reuse; preserve honest global signal lifetime and cancellation uncertainty. Final source, graph and native results must be recorded without rewriting this pre-execution decision.
