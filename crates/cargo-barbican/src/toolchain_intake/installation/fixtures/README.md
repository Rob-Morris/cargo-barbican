# Authored XZ handoff fixtures

These three compressed test inputs contain only authored fixture content. They
are not Rust releases and confer no production acceptance. Each uses synthetic
release `1.99.99`, host `aarch64-apple-darwin`, installer format 3, one component,
and one `file:` action in its `manifest.in`. Package/component roots follow the
same identity rules as the dynamic Gzip fixture in `../tests.rs`.

The `rustc` payload is `bin/rustc`, archive mode 0700:

```sh
#!/bin/sh
printf '%s\n' "$*" >> "$RUSTUP_HOME/../candidate-probes"
printf 'rustc 1.99.99 (authored XZ fixture)\n'
```

Its only write is the probe marker within the test-owned home’s parent. The
`cargo` payload is `bin/cargo`, mode 0755:

```sh
#!/bin/sh
printf 'authored XZ cargo fixture\n'
```

The `rust-std` payload is
`lib/rustlib/aarch64-apple-darwin/lib/libstd-fixture.rlib`, mode 0600, containing
`accepted authored XZ standard library fixture` without a trailing newline.

All directory modes are 0755; metadata files are 0644. Headers have zero
uid/gid/mtime. The files were generated offline with the already-trusted Python
standard-library `tarfile` GNU format and `lzma` XZ/CRC64/preset 6, then stored
with filesystem mode 0644. Python is not used by the product or test execution;
the tests include these exact bytes and use the reviewed decoder.

Checksums and observed native qualification are recorded in
[the native qualification record](../../../../../../docs/dependency-reviews/2026-11-04-native-toolchain-qualification.md).
