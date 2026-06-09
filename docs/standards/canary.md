# Canary

How subjective pre-commit checks are recorded and enforced in cargo-barbican,
alongside the small objective checks bundled with the local hook.

## Package

This repo's canary package is:

- `.canaries/pre-commit.md` — the contributor checklist brief
- `.canary--pre-commit` — the transient local receipt written at the repo root
- `scripts/verify.sh` — repo-level verification entry point with explicit
  off-`main` escape hatches
- `scripts/check_doc_versions.sh` — objective README/version/template consistency checker
- `scripts/check_pre_commit_canary.sh` — reusable checker logic
- `tools/git-hooks/pre-commit` — distributed hook entry point

Enable the distributed hooks locally with:

```bash
git config core.hooksPath tools/git-hooks
```

The receipt file is transient local state. It must stay unstaged and
untracked; `.gitignore` already covers `.canary--*`.

## Receipt Format

Write one line per task ID from `.canaries/pre-commit.md`:

```text
[1] Label: done
[2] Label: skip, reason
```

Accepted statuses:

- `done`
- `done, <note>`
- `skip, <reason>`

The checker ignores indentation, but it requires every bracketed task line to
use one of those shapes.

## Behaviour

The distributed pre-commit hook:

1. runs `git diff --cached --check`
2. runs `scripts/check_doc_versions.sh --staged`
3. rejects the commit if `.canary--pre-commit` is staged
4. reads `.canaries/pre-commit.md`
5. verifies `.canary--pre-commit` exists
6. verifies the receipt covers every task ID from the brief
7. verifies every bracketed receipt line uses valid formatting
8. deletes `.canary--pre-commit` on success so it cannot go stale

The canary does not replace objective verification. It is the local receipt
for checks that are partly policy- or judgment-driven, such as confirming that
dependency review records exist or that the version bundle moved coherently.
README badges, install tags, Rust toolchain badges, and template sync headers
are checked objectively against the staged commit by
`scripts/check_doc_versions.sh --staged`.

For manual worktree checks before staging, run:

```bash
scripts/check_doc_versions.sh --worktree
```

## When To Update The Brief

Update `.canaries/pre-commit.md` when:

- the repo's before-commit expectations change
- a new cross-cutting maintenance obligation appears
- a task becomes obsolete and should stop gating commits

Adding or removing bracket IDs in the brief automatically changes what the
checker enforces; no script edits are needed for ordinary task-list changes.
Adding or changing objective checks, such as README badge or template header
validation, requires updating the relevant script and hook documentation.

## Related

- [Commit Messages](commit-messages.md) — subject rules enforced by the companion `commit-msg` hook
- [Changelog](changelog.md) — canonical source for versioned commit summaries
- [Contributing](../CONTRIBUTING.md) — contributor landing page
