# Native fixture evaluator CI provisioning

Date: 8 November 2026. Scope: retrieve the **already qualified** Rustup
executable for macOS ARM64 fixture tests. This record precedes execution of
the retrieved copy. It grants no new evaluator, host, component or real Rust
toolchain acceptance; the [native qualification](2026-11-04-native-toolchain-qualification.md)
remains authoritative.

## Provenance and static review

The official Homebrew registry's
[`rustup` index](https://ghcr.io/v2/homebrew/core/rustup/manifests/1.29.0_1)
identifies the `1.29.0_1.arm64_tahoe` bottle. Metadata was retrieved over
HTTPS with GHCR's public anonymous `Bearer QQ==` marker, not account credentials.
The immutable OCI manifest was independently retrieved with the OCI manifest
Accept header and its SHA256 checked:

- [Manifest](https://ghcr.io/v2/homebrew/core/rustup/manifests/sha256:f975bc2ecc501a95e09fc40773461fd0c547975dbab895653da7b90afafc63c6):
  `f975bc2ecc501a95e09fc40773461fd0c547975dbab895653da7b90afafc63c6`.
- [Bottle blob](https://ghcr.io/v2/homebrew/core/rustup/blobs/sha256:040e2eb689f99acefa1849bd9c5f7591ba100fda29323901859b7a86e68d6bf5):
  SHA256 `040e2eb689f99acefa1849bd9c5f7591ba100fda29323901859b7a86e68d6bf5`,
  exactly 4,863,566 bytes.
- Sole selected member: `rustup/1.29.0_1/libexec/bin/rustup`, a regular file,
  exactly 11,031,216 bytes, SHA256
  `16c7599bf448e4e7512779154f6b05042bf2ff715e5e09d9cf5d465a3b750496`.

The downloaded archive hash matches the official manifest. Member-only stdout
extraction produced a non-executable inspection file; both SHA256 and bytewise
`cmp` independently matched the previously qualified local executable.
Static Mach-O inspection reports ARM64, minimum macOS 11.0, and only system
Security/CoreFoundation, curl, iconv and libSystem dependencies. The bottle
metadata declares no Homebrew runtime dependencies. Its build environment
(macOS 26, Xcode 26.4) matches the existing local installation receipt.

The registry references Homebrew formula commit
[`9de02e34a581a60d2ca3dce416f00a341e0a4f59`](https://github.com/Homebrew/homebrew-core/blob/9de02e34a581a60d2ca3dce416f00a341e0a4f59/Formula/r/rustup.rb).
That source was read without executing Ruby: Rustup 1.29.0 source archive,
revision 1, Cargo build with `no-self-update`, renamed `rustup-init`, and
wrapper generation. The formula at that commit contains different rebuilt
bottle hashes and is **not** used as the archive digest authority. The
independently fetched OCI manifest and exact match to the existing qualified
binary establish the selected artifact identity. This is not a reproducible
binary-to-source attestation or an independent review of Rustup 1.29.0 source;
the prior qualification's official Rustup source commit remains unchanged.

## Execution boundary

`scripts/provision-native-test-evaluator.sh` retrieves only the immutable blob,
bounds transfer size/time, checks exact archive size and digest before parsing,
and extracts only the reviewed member to stdout into a private new directory.
It checks executable size and digest before setting executable permission.
No Homebrew formula, installer, wrapper or downloaded binary runs during
provisioning. No normal Cargo/Rustup home or default is changed. A retained
local bottle may be supplied explicitly; it passes the same checks.

CI publishes the resulting absolute path as `BARBICAN_TEST_RUSTUP` before
tests and dogfooded verification on its macOS runner. Provisioning refuses a
non-ARM64 macOS host, so a runner-label change cannot silently lose native
coverage. Tests fail with setup guidance when the path is absent, invalid or
has the wrong digest. Production executable/ancestor/mode/identity checks
remain unchanged and authoritative at the native handoff.

Both CI matrices select `macos-26`, the explicit standard ARM64 runner in
[GitHub's runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
and [macOS 26 availability announcement](https://github.blog/changelog/2026-02-26-macos-26-is-now-generally-available-for-github-hosted-runners/),
checked 8 November 2026. The provisioner's host assertion also fails if that
label ever resolves to another architecture.

The connected tests use task-owned homes and authored harmless compiler
payloads only. Real Rust distribution installation, broader native host
support and the CI runner's own compiler provenance are outside this record.
Public artifact availability and hosted-runner execution remain operational
dependencies; a failed fetch must fail CI rather than change the identity.

## Local verification

The exact provisioner completed both its public network retrieval and retained
local bottle routes. Its offline shell controls passed: exact selection,
missing input, wrong archive size, same-size archive corruption (refused before
the extractor was called), wrong extracted size and same-size extracted
corruption. These controls execute no evaluator.

After this record's static review was written, the native fixture suite ran
against the provisioned byte-identical executable under the task-owned target:
`cargo test --locked --offline -p cargo-barbican toolchain_intake::installation -- --nocapture`.
Result: **14 passed, 0 failed**, with the pre-existing authentic static-only
test still requiring its explicit retained-input invocation. The new fixture
selection test covers absent/relative/missing/mismatched and selected matching
paths. Separate process controls invoked the connected XZ test with an unset
variable and a mismatched file; both failed with the expected setup/identity
diagnostic before delegation. Source custody, product formatting and diff
whitespace checks passed. Evidence is retained in the release task's scratch
directory as `native-fixture-portability.log`, `native-missing-evaluator.log`
and `native-mismatched-evaluator.log`. Canonical verification, independent
review and hosted CI execution are separate evidence.
