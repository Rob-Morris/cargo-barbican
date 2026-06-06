# Contributor Process

Shared contributor workflow for this repo.

## Hook Package

This repo ships opt-in distributed Git hooks:

- brief: [`.canaries/pre-commit.md`](../../.canaries/pre-commit.md)
- pre-commit checker: [`tools/git-hooks/pre-commit`](../../tools/git-hooks/pre-commit)
- commit-message checker: [`tools/git-hooks/commit-msg`](../../tools/git-hooks/commit-msg)
- reusable shell checks:
  - [`scripts/check_pre_commit_canary.sh`](../../scripts/check_pre_commit_canary.sh)
  - [`scripts/check_commit_msg.sh`](../../scripts/check_commit_msg.sh)

Enable them locally with:

```bash
git config core.hooksPath tools/git-hooks
```

When enabled:

- `tools/git-hooks/pre-commit` runs `git diff --cached --check`, then enforces a complete local `.canary--pre-commit` receipt against the canary brief and deletes the receipt on success
- `tools/git-hooks/commit-msg` enforces the documented commit-subject policy, including version-bundle coherence for versioned commits and `WIP:` branch rules
- no tracked files are auto-edited by the hooks

## Canary Workflow

Before committing:

1. read [`.canaries/pre-commit.md`](../../.canaries/pre-commit.md)
2. perform each task
3. write `.canary--pre-commit` at the repo root
4. leave the receipt unstaged and untracked
5. let the hook validate and delete it on success

Receipt format:

```text
[1] Verification: done
[2] Delegated inspectors: skip, cargo-audit not yet installed on this machine
```

See [Canary](../standards/canary.md) for the full rules.

## Commit, Changelog, And Version Bundle

Follow:

- [Commit Messages](../standards/commit-messages.md)
- [Changelog](../standards/changelog.md)
- [CHANGELOG.md](../CHANGELOG.md)

The `commit-msg` hook enforces:

- support-only subjects: `docs:`, `test:`, `chore:`
- branch-local work: `WIP: ...` and never on `main`
- versioned subjects: `<Summary> (vX.Y.Z)` with the exact canonical changelog `Summary`
- no amend exception for versioned commits on `main`
- version-bundle coherence for versioned commits across:
  - `crates/barbican/Cargo.toml`
  - `crates/cargo-barbican/Cargo.toml`
  - `docs/changelog/vX.Y.Z.md`
  - the matching `docs/CHANGELOG.md` row

Repo branch policy is simple:

- `main` is stable and keeps the stricter rules above
- `dev` is the default working branch for ongoing implementation

## Verification Expectations

The hook package is deliberately light. It does not replace the repo's actual
verification commands or dependency-review policy.

Normal pre-commit expectations still include:

- `cargo build --locked`
- `cargo test --locked`
- `cargo audit`
- `cargo deny check advisories bans sources`
- checked-in dependency review records for direct dependency and `deny.toml` changes

Those expectations are recorded in the canary brief and contributor docs even
when the hook cannot prove every one of them mechanically from the staged
diff alone.
