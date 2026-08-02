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
- `dependency-reviews/README.md` — record template + naming conventions.
  Copy to consumer's `docs/dependency-reviews/`.
- `hooks/pre-commit` — advisory client-side git pre-commit hook. It runs the
  cheap subset of the gate (`cargo barbican pin check` and
  `cargo barbican inventory --enforce`) and is skippable with
  `git commit --no-verify`. Install it by pointing `git config core.hooksPath`
  at this directory, or by copying it to `.git/hooks/pre-commit`. The
  server-side CI workflow is the authoritative gate, not this hook.

`barbican.toml`, `deny.toml`, `reviewed-targets.toml`, and the
`docs/dependency-reviews/` scaffold are also created directly by
`cargo barbican policy init`. `cargo barbican policy init --ci github`
additionally emits a ready-to-run enforcement workflow to
`.github/workflows/barbican.yml`.

## Planned templates

- `dependency-management.md` — policy doc. Copy to consumer's
  `docs/contributor/`.

## Sync header convention

Each template file shipped to a consumer should include a header comment:

```
# Synced from cargo-barbican v0.24.0
```

Template-specific follow-up comments may differ. Some copied templates, such
as `barbican.toml`, are intended to be reviewed and edited locally after
adoption. The sync header still makes drift detectable and re-sync deliberate.
