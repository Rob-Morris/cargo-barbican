# Contributing to cargo-barbican

Guide for anyone working on cargo-barbican.

**Agent contributors:** read [contributor/agents.md](contributor/agents.md)
first for the repo-specific route-map.

## Documentation Layers

This repo follows the
[Agent-Ready Documentation Standard v1.0.0](standards/agent-ready-documentation.md).
Start with [README.md](README.md), which routes to the documentation layers:

- [User](user/README.md) — consumer adoption and integration guidance
- [Functional](functional/README.md) — CLI and behaviour contracts
- [Architecture](architecture/README.md) — goals, boundaries, and decision routing
- [Contributor](contributor/README.md) — contributor constraints and workflow
- [Standards](standards/README.md) — shared standards adopted by this repo

Convention-based exceptions at the docs root:

- [CHANGELOG.md](CHANGELOG.md) — shipped version-history index
- [CONTRIBUTING.md](CONTRIBUTING.md) — contributor landing page

When you add, move, remove, or rename docs, update the relevant `README.md`
indexes so the routing chain stays explicit.

## When To Update Which Layer

| Change type | Update |
|---|---|
| Consumer adoption or re-sync flow changes | `user/integration.md` |
| Subcommand surface, exit codes, or behavioural contract changes | `functional/cli.md` |
| System goals, boundaries, library/binary split, or architectural rationale changes | `architecture/overview.md` |
| Non-obvious architectural decisions that should be preserved historically | add a DD under `architecture/decisions/` and update its index |
| Contributor constraints, dependency discipline, or shipped-template boundary changes | `contributor/specification.md` |
| Repo-specific agent workflow or hard stops | `contributor/agents.md` |
| Dependency review policy or record format changes | `dependency-reviews/README.md` |
| Changelog policy or structure changes | `standards/changelog.md`, `standards/README.md`, and `CHANGELOG.md` if the index contract changes |
| Commit-message policy changes | `standards/commit-messages.md`, `standards/README.md`, and any contributor docs that cite the rule |
| Canary / hook policy changes | `standards/canary.md`, `standards/README.md`, `contributor/process.md`, and any contributor docs that cite the hook workflow |
| Shipping a new repo version | crate manifest versions, `CHANGELOG.md`, and `changelog/vX.Y.Z.md` |

## Dependency Review Discipline

Every direct dependency change, dependency-tool install, and `deny.toml`
policy change needs a checked-in record under `docs/dependency-reviews/`
before the change lands.

First-principles reviews are the default. A record may instead inherit from a
matching review in undertask (the private predecessor project cargo-barbican
grew out of) when the source, version, and trust model match; anything outside
that inherited set is reviewed first-principles.

## Version History

Shipped repo history lives in [CHANGELOG.md](CHANGELOG.md) and
`docs/changelog/`.

For now, the repo version is the shared semver carried by:

- `crates/barbican/Cargo.toml`
- `crates/cargo-barbican/Cargo.toml`

Those versions should move together. When a shipped version changes, add the
matching changelog entry in the same change, and use the canonical changelog
`Summary` as the versioned commit subject per
[standards/commit-messages.md](standards/commit-messages.md).

## Branch Flow

This repo uses a simple two-branch flow:

- `main` is the stable branch
- `dev` is the default ongoing development branch

The hook and commit-message rules treat `main` as stricter: `WIP:` commits do
not belong there, and versioned amend exceptions are not allowed there. Do
day-to-day implementation work on `dev`, then merge or promote coherent
versioned slices when ready.

## Hook Activation

This repo ships opt-in distributed `pre-commit` and `commit-msg` hooks under
`tools/git-hooks/`.

Enable them locally with:

```bash
git config core.hooksPath tools/git-hooks
```

The hook package is described in:

- [standards/canary.md](standards/canary.md)
- [contributor/process.md](contributor/process.md)

## Before Committing

1. `cargo build --locked` passes.
2. `cargo test --locked` passes.
3. `cargo audit` and `cargo deny check advisories bans sources` pass.
4. Any new dependency has a checked-in review record.
5. If the repo version changed, `CHANGELOG.md` and `docs/changelog/vX.Y.Z.md` were updated together.
6. Follow [`.canaries/pre-commit.md`](../.canaries/pre-commit.md), write the transient `.canary--pre-commit` receipt, and leave it unstaged.
7. The commit subject matches [standards/commit-messages.md](standards/commit-messages.md).
