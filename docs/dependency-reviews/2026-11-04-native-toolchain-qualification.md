# Native Rust toolchain qualification

Date: 4 November 2026. Implementation evidence for the pending 0.37.0 change;
independent design/security review and final canonical verification remain
separate requirements. This record adds no dependency or toolchain acceptance.

## Closed native scope

The sole qualified evaluator is the pre-existing native **Rustup 1.29.0**
for **aarch64-apple-darwin**, SHA256
`16c7599bf448e4e7512779154f6b05042bf2ff715e5e09d9cf5d465a3b750496`.
The test executable is
`/opt/homebrew/Cellar/rustup/1.29.0_1/libexec/bin/rustup`.
Source inspection uses official commit
`28d1352dbcb436d3111c3594b9e1588e94950464`; this is not a reproducible
binary-to-source attestation.

| Boundary | Qualified scope |
| --- | --- |
| Native selection | Explicit minimal: host rustc, Cargo and rust-std; optional host clippy-preview and rustfmt-preview |
| Compression | Preferred XZ, otherwise Gzip; each connected handoff tested with authored inputs |
| Encoding refusal | Zstd advertisement or unaccepted preferred XZ refuses before delegation; original manifest is not rewritten |
| Installed mapping | Source-derived regular files/directories, bounded ownership actions and exact generated metadata; observed mode normalisation |
| Unsupported | Default profile, rust-docs, cross targets, other packages/hosts/evaluator builds, non-ASCII paths and unqualified links/transformations |

Metadata collection and review remain available for broader selections. They
do not enable unqualified native installation, adoption, installed checking or
activation. Other evaluator builds are refused with the required identity;
there is no automatic evaluator fetch or diagnostic fallback.

## Connected harmless native controls

The focused test run passed **13 tests**, including the subprocess signal
helper; these cover twelve substantive groups:

1. Gzip selected-only mirror, explicit synthetic acceptance before Rustup's
   internal harmless `rustc --version` probe, then independent output mapping.
2. The same connected XZ handoff/probe/mapping against the actual
   `install_selected` implementation, with original manifest and exact bytes.
3. Missing initial-default intent, corrupt input, preferred-format and ancestor
   path refusals before candidate execution.
4. Closed default/docs/cross-target native qualification refusals.
5. Existing default, ambient complete profile and unrelated state preservation;
   repeated installation becomes static checking without another probe.
6. Post-install policy failure retains installed data; only the still-owned
   initial default is unset. External default edits survive as conflicts.
7. Static payload, permission, hardlink, generated bookkeeping and unexpected
   same-slot changes are rejected without candidate execution.
8. Activation resolves the preserved proposed pin through the canonical strict
   selection parser and authenticated manifest. Wider default/component pins
   refuse without changing original bytes or mode 0600; valid activation and
   external-edit conflict controls also pass.
9. TERM-resistant owned process groups are stopped and the direct child reaped
   before a delayed effect can occur.
10. A deliberately abandoned process produces its late marker, demonstrating
    that the cancellation detector is non-vacuous.
11. Real SIGINT, SIGTERM and repeated signals reach the CLI-lifetime flag
    handler without abandoning children or dispatching another phase.
12. Unsafe update-hash leaves refuse before delegation. A separate raw-native
    dangling-symlink control demonstrates the actual external fixture write;
    guarded dangling-symlink, hardlink and directory controls preserve state.

All native execution uses task-owned homes and authored harmless payloads. The
real user Rustup home/default is not mutated. Cancellation uses the separately
reviewed [minimal signal graph](2026-11-04-toolchain-cancellation.md); handlers
remain for the single CLI lifetime, with no claim that unregister restores
default handlers or that escaped daemons/crash recovery are contained.

The update-hash finding was source-confirmed: [`dist/mod.rs` install_into](https://github.com/rust-lang/rustup/blob/28d1352dbcb436d3111c3594b9e1588e94950464/src/dist/mod.rs#L954)
tests `Path::exists` before stray removal; [`install.rs`](https://github.com/rust-lang/rustup/blob/28d1352dbcb436d3111c3594b9e1588e94950464/src/install.rs#L107)
then publishes through the [`raw write helper`](https://github.com/rust-lang/rustup/blob/28d1352dbcb436d3111c3594b9e1588e94950464/src/utils/raw.rs#L71),
which opens with create/truncate. A dangling symlink can therefore survive
removal and be followed. Barbican captures and rechecks the exact leaf,
including prior absence, alongside its parent before handoff.

## Authentic XZ static correspondence

A separate explicitly invoked test independently decoded the five authentic
Rust 1.99.1 XZ archives for minimal plus clippy/rustfmt, derived their expected
mapping, and checked the pre-existing matching local slot: **165 files passed**,
including generated component/config/ownership/channel metadata. Original
manifest SHA256:
`fb152be80975c194aa5fc684b2aec3a6e14e2b855efe2faa4e5f8ae6e590f463`.

This was strictly read-only with respect to the existing installation: no
Rustup call, compiler probe, installation, acceptance or adoption. Its
historical execution provenance is unchanged. It proves neither authentic
new-install execution nor default-profile/docs output. The independent
six-archive source inventory is a separate decoder/mapping result.

## Fixtures and verification limits

The checked-in [XZ fixture content](../../crates/cargo-barbican/src/toolchain_intake/installation/fixtures/README.md)
is authored test data generated offline with already-trusted Python standard
library tools; neither product nor test execution needs Python or an encoder
dependency. Compressed fixtures are non-executable files:

| Fixture | Bytes | SHA256 |
| --- | ---: | --- |
| rustc.tar.xz | 400 | `affc2b6b94cfc4f23ae3f1871659ff3d0e49e901179a4055085eb2313cd48d30` |
| cargo.tar.xz | 356 | `7f9d8681134cdcd203fed42a9ce9b3f15a21ee9e73a0e75d77df6c21499b9a3e` |
| rust-std.tar.xz | 480 | `414bcce3caf74fdb2b7587efbf30284d473a37e01f1473a2cf9937cb99fbe31d` |

Commands use the reviewed graph, `--locked --offline`, and the owned target:
`cargo test -p cargo-barbican toolchain_intake::installation -- --nocapture`;
the authentic static test is ignored by default and separately invoked with
explicit retained input/slot paths. Vendored-source checks pass. Evidence logs
are retained under `/private/tmp/barbican-rust-impl.21mZWk/` as
`native-review-fixes.log` and `authentic-native-static.log`.

A metadata-only Linux comparison found 209 nodes versus macOS's 208: the only
additional source is already-reviewed curve25519-dalek-derive 0.1.1, with no
extra shared-node features. The root authorised a compiler-only Linux check
against the installed Rust 1.95 target. It stopped in ring 0.17.14 because
`x86_64-linux-gnu-gcc` is absent. No toolkit/target was installed and no target
code ran. **Linux compilation and native execution are not established.**
The Homebrew-specific fixture module is compiled only on macOS ARM64;
unsupported-host refusal and Unix process tests remain available separately.

No filesystem race-free sandbox, shared-state rollback, hardware attestation,
durable transaction or universal distribution qualification is claimed.
