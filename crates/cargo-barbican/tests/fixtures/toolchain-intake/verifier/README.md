# Public verifier fixtures

These are public, non-executable qualification inputs, not bundled trust approval.
No synthetic private key is retained or needed to run the tests. GPG is an
already-trusted fixture author/oracle only; consumers and native tests do not
invoke GPG. Native verification uses the actual reviewed rPGP/rpgpie route.

The original 37 fixture/data inputs come from the 3 November 2026 bounded native
qualification recorded in brain://_Temporal/Research/project~cargo-barbican/design~cargo-barbican/design~barbican-rust-toolchain-review-update/20261103-research~Permissive Rust Verifier Current-Policy Qualification Evidence.md.
`rust-key.asc` is the exact official public certificate SHA256
`e54b09a439647e006b4831eec9785cbaaf3e07ab371c3a6ee6a68e1bdb9fbc6b`,
primary `108F66205EAEB0AAA8DD5E1C85AB96E6FA1BE5FE`. `rust-manifest.*` is the
original authentic 1.99.1 signed manifest; no compiler/archive code is executed.
The corpus includes valid primary/subkey signatures, expired keys, purpose,
revocation/later-UID masking, malformed/oversized/secret/compressed input,
critical data extensions and corrupted/missing cross-signatures. The old
`future-cross-signature.bin` is intentionally damaged and is NOT proof of valid
future-signature time refusal.

The 4 November additions use synthetic primary
`C128E78E278729E42B015DCC77E807A8B887B26E`, RSA2048, created 1 January 2020
12:00 UTC, and a signing subkey created the next day. The original document was
signed 3 January 2020 with SHA512. For `future-cross-authored.asc`, the old
unhashed embedded signature was removed from the synthetic exported secret
fixture before importing it into a second isolated GPG home. GPG `cross-certify`
at 1 January 2040 12:00 UTC authored a new valid embedded signature. The native
test transplants only that unhashed field into the original binding, verifies
both the outer binding and embedded cryptography, then proves current-time
refusal. This is not timestamp mutation of an old signature.

`revocation-{current,future,obsolete,critical,expired}.bin` use the existing
trusted GPG agent's RSA signing primitive on authored public revocation digests.
The authored v4 KeyRevocation signature hashes the exact public primary and its
hashed signature fields/trailer. GPG signs SHA256 (SHA1 only for obsolete). The
current creation time is 3 January 2020; future is 1 January 2040; critical adds
unknown critical subpacket 100; expired adds one-second signature validity.
Native tests separately authenticate every signature before checking its status.
Invalid crypto is derived independently by altering a hashed creation field and
must grant no adverse authority. Authenticated obsolete/future/critical/expired
observations remain conservative adverse knowledge, not currently admissible
revocations. No generic soft/hard revocation ordering is claimed.

Native tests inject an explicit fixed current reference second and exercise the
existing semantic owner's exact primary and selected-subkey expiry at -1, =, +1.
They do not shift the global verification clock to bypass current policy.
