# Toolchain local-record Serde boundary

Date: 2026-11-04. Classification: inherited exact dependency and feature set.

The binary adds direct `serde = { version = "=1.0.228", features = ["derive"] }`
for bounded, strict versioned local trust, proposal, adverse-knowledge and
acceptance records. This inherits the exact source/version/features and
proc-macro review from [the bootstrap core set](2026-05-25-rust-bootstrap-inherited-core-set.md)
and the library's existing direct dependency. No new registry package,
feature, compiler or resolver update is required.

The boundary is deserialisation of bounded JSON, with unknown fields refused,
explicit schema versions, validated content identities and domain validation.
Deserialisation alone grants no authority: local private-store custody and
explicit approved-baseline/review bindings remain separate requirements.
The existing serde_json 1.0.149 parser remains unchanged. This is not a new
cryptographic primitive or a signing service.

Decision: reuse this exact reviewed dependency for the binary record owner.
The lockfile change must only add serde to the cargo-barbican dependency edge;
registry versions/checksums and the reviewed 220-package graph stay unchanged.
Validation is the focused strict-record tests and ordinary repository gate.
