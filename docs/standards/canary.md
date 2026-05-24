# Canary

How subjective pre-commit checks are recorded and enforced in cargo-barbican.

## Package

This repo's canary package is:

- `.canaries/pre-commit.md` — the contributor checklist brief
- `.canary--pre-commit` — the transient local receipt written at the repo root
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
- `skip, <reason>`

The checker ignores indentation, but it requires every bracketed task line to
use that exact shape.

## Behaviour

The distributed pre-commit hook:

1. runs `git diff --cached --check`
2. rejects the commit if `.canary--pre-commit` is staged
3. reads `.canaries/pre-commit.md`
4. verifies `.canary--pre-commit` exists
5. verifies the receipt covers every task ID from the brief
6. verifies every bracketed receipt line uses valid formatting
7. deletes `.canary--pre-commit` on success so it cannot go stale

The canary does not replace objective verification. It is the local receipt
for checks that are partly policy- or judgment-driven, such as confirming that
dependency review records exist or that the version bundle moved coherently.

## When To Update The Brief

Update `.canaries/pre-commit.md` when:

- the repo's before-commit expectations change
- a new cross-cutting maintenance obligation appears
- a task becomes obsolete and should stop gating commits

Adding or removing bracket IDs in the brief automatically changes what the
checker enforces; no script edits are needed for ordinary task-list changes.

## Related

- [Commit Messages](commit-messages.md) — subject rules enforced by the companion `commit-msg` hook
- [Changelog](changelog.md) — canonical source for versioned commit summaries
- [Contributing](../CONTRIBUTING.md) — contributor landing page
