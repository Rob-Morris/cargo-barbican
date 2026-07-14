# Templates

Files in this directory are **shipped to consumer repos** by copying. They
are not documentation about cargo-barbican; they are configuration and
documentation that *uses* cargo-barbican.

## Planned templates

- `deny.toml` — cargo-deny config for consumers. Copy to consumer repo root.
- `barbican.toml` — explicit cargo-barbican policy config for consumers.
  Copy to consumer repo root, then review and edit for the repo's policy.
- `dependency-management.md` — policy doc. Copy to consumer's
  `docs/contributor/`.
- `dependency-reviews/README.md` — record template + naming conventions.
  Copy to consumer's `docs/dependency-reviews/`.
- `reviewed-targets.toml` — active reviewed-family gate manifest. Copy to the
  consumer repo root when checked-pin enforcement is needed. The current Rust
  gate supports structured crates.io `resolved` entries with reviewed
  `checksum_sha256` digests.

## Status

This directory is now partially populated.

Available now:

- `barbican.toml`
- `deny.toml`
- `dependency-reviews/README.md`
- `reviewed-targets.toml`

Still pending:

- `dependency-management.md`

## Sync header convention

Each template file shipped to a consumer should include a header comment:

```
# Synced from cargo-barbican v0.21.1
```

Template-specific follow-up comments may differ. Some copied templates, such
as `barbican.toml`, are intended to be reviewed and edited locally after
adoption. The sync header still makes drift detectable and re-sync deliberate.
