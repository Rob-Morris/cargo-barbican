# Maintained rpgpie source

Original author: Heiko Schaefer. Upstream https://codeberg.org/heiko/rpgpie,
registry release 0.12.0, commit 81ed54b4976d66a7f63b826dcad1d7e7f2279acf.
Archive SHA256: 2049db9b867c7a430535e6628d449afbcb058ad67d674c71143e62c86e7564af.
Source is MIT OR Apache-2.0; original SPDX headers and LICENSES retained.
Cargo/REUSE metadata are CC0-1.0; retained original notices govern those files.

This is a modified, explicitly maintained, non-publishable workspace member. It is not a registry
package cleared through registry checksum parity. Repository review and the
pre-build actual-tree guard own its source custody. The src tree is retained
with the bounded changes below; README, REUSE.toml and LICENSES are retained. Published upstream test/fixture,
lockfile and development tooling files are omitted; upstream tests/CLI targets
and dev-dependencies are removed from the local manifest. The fixture-only
`model/summary.rs` test module is also omitted: it imports the excluded rstest
dev-dependency and reads absent upstream fixture files. Cargo clippy
`--all-targets` still compiles in-source tests despite `lib.test = false`, so
retaining that module would contradict this package boundary. The original
module is preserved in the explicit patch. No upstream fixture suite is run;
the remaining compilable in-source test modules do not establish fixture proof. Unsupported CLI/PQC/wasm
features and optional clap are removed; retained runtime dependencies are pinned
to exact reviewed selected versions. Chrono disables unused default clock/timezone/
wasm features, retaining only std and serde; the source uses date/time conversions
and obtains current time through pgp, not Chrono local-clock APIs. Inactive upstream pqc cfg names remain
recognised by check-cfg without exposing that feature. Native public-only
adapter regression tests own the changed behaviour. No consumer secret-key
operation is enabled by retaining unused upstream source APIs.

Semantic changes: primary expiry refuses equality in checked.rs; selected
subkey expiry refuses equality in key.rs using widened integer addition.
The adapter refuses unrepresentable primary/signature expiry before calling
Checked. It also explicitly verifies embedded cross-signatures and preserves
same-anchor authenticated revocation knowledge before refusing material changes.
Neither active-binding selection nor the global clock is replaced.

Review and minimal patch: docs/dependency-reviews/2026-11-04-embedded-public-verifier.md
and docs/dependency-reviews/2026-11-04-rpgpie.patch (repository-relative).
Unmodified published 0.12.1 retains the expiry and cross-signature defects and is
not a remediation. Re-evaluate maintained upstream releases before rebasing this
source; regenerate the explicit patch/source receipt and rerun native controls.

The patch uses zero context to keep its checked-in representation free of
trailing whitespace without altering unified-diff syntax. Verify the original
`.crate` archive SHA256 above, extract that exact archive into a disposable
directory, enter its `rpgpie-0.12.0` root, then run
`git apply --no-index --unidiff-zero /absolute/path/to/2026-11-04-rpgpie.patch`.
Do not apply it to another release or unverified source. The patch covers the
four changed upstream files; omitted package files and added provenance remain
described separately above and bound by the full maintained-tree inventory.
