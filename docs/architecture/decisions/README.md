# Design Decisions

cargo-barbican will record non-obvious architectural decisions here as the
implementation matures. Each decision should preserve the reasoning that led to
the outcome so later contributors can recover context without reverse-engineering
old diffs.

## Purpose

Living docs in `docs/architecture/` and `docs/functional/` describe how the
system works today. Decision records explain why it ended up that way.

## Conventions

- Use `dd-NNN-slug.md` filenames with zero-padded numbers.
- Start each file with `# DD-NNN: Title`.
- Include sections for Context, Decision, Alternatives Considered, and Consequences.
- Keep the body immutable once accepted. If direction changes later, add a new DD that supersedes or extends the old one.
- Add every DD to the index below when it lands.

## Index

- [DD-001: CLI Command Vocabulary For Resolution, Lockfile Generation, And Updates](dd-001-cli-command-vocabulary.md)
  — `pick` (discover a version), `resolve` (reclaimed for whole-graph lockfile
  resolution), and `update` (renamed from `resolve`).
