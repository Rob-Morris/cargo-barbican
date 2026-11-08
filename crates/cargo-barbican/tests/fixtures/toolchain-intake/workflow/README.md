# Authored signed workflow fixtures

These are synthetic test inputs, not an official Rust release, supplier signature,
or production trust seed. The official-looking URLs are canonical-format test
identities; tests supply the local bytes without fetching those URLs. The repeated
`1` source commit is invented. The synthetic default profile contains only the
three core packages; this does not qualify native default-profile installation.

The fixtures support fresh-state portable import and independent authentication.
Tests must explicitly seed trust with this fixture certificate. Never add this
certificate to the bundled production seed or interpret fixture acceptance as
acceptance of a supplier toolchain.

## Public authentication inputs

- Primary and signing fingerprint: `D876DF286C33E94B5CFEA6538E16ED03DD101204`.
- Primary-only RSA3072 certificate, signing/certification capabilities, no expiry.
- Key creation: `1767225600` (2026-01-01 00:00:00 UTC).
- Manifest date and SHA512 detached signature creation: `1792022400`
  (2026-10-15 00:00:00 UTC).
- Fixed verification clock: `1793750400` (2026-11-04 00:00:00 UTC).

Generated offline with the existing GPG installation using a dedicated temporary
GNUPGHOME, loopback pinentry, `--quick-generate-key ... rsa3072 sign 0`, fixed
`--faked-system-time`, and SHA512 certificate/signature digests. GPG verification
at the fixed test clock returned VALIDSIG with this primary/signing fingerprint,
public-key algorithm 1 (RSA), hash algorithm 10 (SHA512), and signature time
1792022400. Only the public certificate and detached signature are retained. The
dedicated agent was stopped and the temporary private-key home removed.

## Archive provenance and contents

The three XZ archives derive from the existing authored native-handoff fixtures
in `src/toolchain_intake/installation/fixtures/`. Trusted Python standard-library
`tarfile`/`lzma` renamed the tar roots and rustc banner from 1.99.99 to 1.99.1,
then emitted GNU tar and XZ with CRC64, preset 6. Python is a generation tool,
not a product or test runtime dependency. Archive uid, gid, and mtime are zero;
directories are 0755 and installer metadata files 0644.

Each archive contains `rust-installer-version` (`3\n`), `components`, and its
component `manifest.in` with one `file:` entry. The selected host is
`aarch64-apple-darwin`, profile minimal, encoding XZ. There are no additional
components or targets. Component names are rustc, cargo, and
rust-std-aarch64-apple-darwin.

The rustc payload at `bin/rustc` (raw mode 0700) is authored shell text:

```sh
#!/bin/sh
printf '%s\n' "$*" >> "$RUSTUP_HOME/../candidate-probes"
printf 'rustc 1.99.1 (authored XZ fixture)\n'
```

The cargo payload at `bin/cargo` (0755) is authored shell text:

```sh
#!/bin/sh
printf 'authored XZ cargo fixture\n'
```

The standard-library payload at
`lib/rustlib/aarch64-apple-darwin/lib/libstd-fixture.rlib` (0600) is exactly
`accepted authored XZ standard library fixture`, without a trailing newline.
These are not compiler or Cargo implementations. Static import/authentication
requires no payload execution. Any native handoff test must use isolated homes.

## Subject reconstruction recipe

Verify the original manifest bytes and detached signature with
`ApprovedCertificate::from_reviewed_bytes`, this full fingerprint, and the
explicit fixed clock. Parse the original manifest as release 1.99.1, then select
minimal/aarch64-apple-darwin/XZ with no extras or additional targets. Open each
selected archive and run the real `inspect_archive` against its exact selected
identity. Pass those complete inventories to `Subject::reconstruct`, including
payload, package metadata, and captured installer metadata. Build
`AuthenticationIdentity` from the actual artifact SHA256 values, the verifier's
primary/signing fingerprints, and the product verification-policy digest. Do
not substitute invented or empty inventories or infer authentication from GPG's
local trust label. Source observations in workflow tests are explicitly synthetic.

## SHA256 inventory

| File | Bytes | SHA256 |
| --- | ---: | --- |
| cargo-1.99.1-aarch64-apple-darwin.tar.xz | 356 | `9d9197ace28c4b125f9d9fa69d4c4d091ae281e9cbd3943192897c1451453ad0` |
| channel-rust-1.99.1.toml | 1645 | `109745352f843efcc6ffefc951e4c92775c746ed31dc8d2f8510cda89a471d32` |
| channel-rust-1.99.1.toml.asc | 699 | `6a437af7fe3f67aa8b2c9d40bdd80fb89f04adbf3c1b243bba12283bcb8c6881` |
| fixture-public-key.asc | 1392 | `afd474437cc7086a46fc3061fa0ec0ee92b34af7bad352a6f779ad36cc0a19af` |
| rust-std-1.99.1-aarch64-apple-darwin.tar.xz | 448 | `e6379501bd5dc1d3b05d7c3151e1a8085d23c6c33616450a956295e4f1d9af93` |
| rustc-1.99.1-aarch64-apple-darwin.tar.xz | 400 | `353aeeca0deac2cd93bc74488be0f095d828dcebe9619b86826fe4903fdf683a` |
