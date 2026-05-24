# Changelog

How shipped repo versions are documented in cargo-barbican.

This repo currently carries one shared semver across both crate manifests:

- `crates/barbican/Cargo.toml`
- `crates/cargo-barbican/Cargo.toml`

Until a dedicated repo `VERSION` file exists, those two manifest versions move
together and define the changelog version.

## Package

The live changelog is a small package:

- `docs/CHANGELOG.md` — newest-first index of shipped version events
- `docs/changelog/vX.Y.Z.md` — one file per shipped repo version
- `docs/changelog/releases/vX.Y.Z-<slug>.md` — optional later stable-release note for a shipped version, if this repo ever needs that distinction

## Update Flow

When shipping a new repo version:

1. Bump both crate manifest versions together.
2. Create `docs/changelog/vX.Y.Z.md`.
3. Add the new row to `docs/CHANGELOG.md`.
4. Update any user-facing version references if this repo starts carrying them.

If the repo later distinguishes stable release promotions from ordinary shipped
versions:

1. Create `docs/changelog/releases/vX.Y.Z-<slug>.md`.
2. Add the matching `Release: <title>` row to `docs/CHANGELOG.md`.

Do not silently rewrite older shipped entries to make history look cleaner. If
a correction is needed, record it explicitly in a newer entry.

## Per-Version Files

Each `docs/changelog/vX.Y.Z.md` file documents one shipped repo version.

Required shape:

- `# vX.Y.Z — YYYY-MM-DD` heading
- a top-line bold `**Summary**` line: one short sentence describing the contributor-visible or downstream-visible effect of the version
- optional short prose context
- top-level detail bullets as needed to describe the shipped surface clearly

Rules:

- reuse the same `Summary` text in the matching `docs/CHANGELOG.md` row
- keep references repo-relative and public-safe
- anchor detail bullets in important identifiers such as file paths, crate names, commands, config files, or docs surfaces
- vague bullets such as "refactor code", "tests added", or "docs updated" are not acceptable without named identifiers
- if an entry is backfilled or serves as a baseline note, say so explicitly in the file

## Index

`docs/CHANGELOG.md` is the scannable entry point.

- newest first
- version rows use full `X.Y.Z` semver numbers and link to `docs/changelog/vX.Y.Z.md`
- stable-release rows, if later used, reuse that same version link and use `Release: <title>` in the `Summary` column
- insert each new event directly under the table header
- keep one canonical short summary per version row

## Historical Note

Structured changelog tracking starts with this repo's initial `v0.1.0`
workspace and documentation baseline.

## Local Enforcement

When distributed hooks are enabled with `git config core.hooksPath
tools/git-hooks`, the companion `commit-msg` hook relies on the per-version
top-line `**Summary**` and the matching `docs/CHANGELOG.md` row as the
canonical source for versioned commit subjects.
