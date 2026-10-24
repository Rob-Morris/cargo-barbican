# Templates

Files in this directory are **shipped to consumer repos** by copying. They
are not documentation about cargo-barbican; they are configuration and
documentation that *uses* cargo-barbican.

## Available templates

- `barbican.toml` — explicit cargo-barbican policy config for consumers.
  Copy to consumer repo root, then review and edit for the repo's policy.
- `deny.toml` — cargo-deny config for consumers. Copy to consumer repo root.
- `reviewed-targets.toml` — active reviewed-family gate manifest. Copy to the
  consumer repo root when checked-pin enforcement is needed. The current Rust
  gate supports structured crates.io `resolved` entries with reviewed
  `checksum_sha256` digests.
- `dependency-reviews/README.md` — consumer-owned process and naming conventions.
- `dependency-reviews/record-template.md` — reusable PENDING record; complete
  evidence and the decision before removing the marker. Copy both review files
  to the consumer's `docs/dependency-reviews/`; preserve existing content.
- `hooks/pre-commit` — optional advisory helper (`pin check` and
  `inventory --enforce`). `policy init --pre-commit-hook` copies it to
  `.barbican/hooks/pre-commit` without executable bits. Plain init links the
  [manual installation/existing-hook guide](../docs/user/ci.md#pre-commit-hook).
  Activation stays explicit; review PATH, Cargo cwd and existing hooks first.
  CI needs operator-configured required checks/branch protection.

`barbican.toml`, `deny.toml`, `reviewed-targets.toml`, and the
`docs/dependency-reviews/` scaffold are also created directly by
`cargo barbican policy init`. Supply `--toolchain <exact-channel>` when the
consumer lacks `rust-toolchain.toml`; the tool creates that native pin only
from the explicit operator choice. `cargo barbican policy init --ci github`
additionally emits a ready-to-run enforcement workflow to
`.github/workflows/barbican.yml`.

## Planned templates

- `dependency-management.md` — policy doc. Copy to consumer's
  `docs/contributor/`.

## Sync header convention

Each template file shipped to a consumer should include a header comment:

```
# Synced from cargo-barbican v0.35.0
```

Template-specific follow-up comments may differ. Some copied templates, such
as `barbican.toml`, are intended to be reviewed and edited locally after
adoption. The sync header still makes drift detectable and re-sync deliberate.
