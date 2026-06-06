# Commit Messages

How to write commit messages in cargo-barbican. Applies to every contributor,
human and agent.

A good commit message does three things:

- makes the subject scannable in `git log`
- explains the *why* in the body when that context is not obvious from the diff
- names specific identifiers when they add meaning

## Process

Before drafting, read:

1. `git diff` and `git diff --stat`
2. `git log --oneline -15`
3. If the change ships a new repo version, the matching `docs/CHANGELOG.md` row and `docs/changelog/vX.Y.Z.md` `Summary`

If this standard changes later, follow the current rule going forward; do not
try to rewrite older commits retroactively.

## Subject Line

Versioned template: `<Summary> (vX.Y.Z)`

Non-versioned support template: `<prefix> <specific subject>`, where
`<prefix>` is `docs:`, `test:`, or `chore:`

Non-versioned branch-work template: `WIP: <specific subject>`

Rules:

- short — under about 70 characters
- specific — name the real thing by identifier when possible
- no period at the end
- imperative mood

### Versioned Commits

A versioned commit uses `<Summary> (vX.Y.Z)` as its subject, reusing the
canonical `Summary` from `docs/changelog/vX.Y.Z.md` verbatim with the
`(vX.Y.Z)` suffix appended.

Every versioned commit must keep the version bundle coherent at that commit:

- `crates/barbican/Cargo.toml`
- `crates/cargo-barbican/Cargo.toml`
- `docs/changelog/vX.Y.Z.md`
- the matching `docs/CHANGELOG.md` row

Versioned commits stay prefix-free.

### Non-Versioned Support Commits

Use prefixes only for support-only work that does not ship a new repo version:

- `docs:` — documentation-only work
- `test:` — test-only work
- `chore:` — repo-only maintenance that does not ship a new version

Keep the prefix set narrow. Add a new prefix only if a real recurring support
category appears.

### Non-Versioned Branch Work

For non-support work that is still in flight, you may use:

- `WIP: <specific subject>`

Use this for branch-local work that is not yet ready to become a shipped
version. `WIP:` commits should not land on `main`.

## Body

The body explains *why* the change exists — the motivation, mechanism,
trade-off, or downstream effect. It is optional for trivial commits.

When used:

- prefer short concept-level bullets
- keep bullets concise and specific
- explain facts a reviewer cannot get from the subject or diff alone
- avoid repeating file lists the diff already shows

Use prose only when the change has one causal chain that is clearer as a short
paragraph than as bullets.

## Worked Examples

Good:

```text
docs: add changelog and commit-message standards
chore: expand local gitignore for agent and canary files
Establish cargo-barbican scaffolding, policy, and hook workflow (v0.1.0)
WIP: port lockfile diffing into the library crate
```

Avoid:

```text
update files
misc cleanup
docs update
```

## Rules

**Why, not what.** The diff already shows what changed.

**Specific beats generic.** Name the command, config key, module, or contract
when it matters.

**One logical change per commit.** Split unrelated changes even if staging them
together would be convenient.

**Versioned commits use the canonical `Summary`.** Do not paraphrase the
`docs/changelog/vX.Y.Z.md` `Summary` into a different subject line.

**Support-only commits use the narrow prefix set.** Do not use `docs:`,
`test:`, or `chore:` for version bumps.

**`WIP:` is for branch work only.** It is the escape hatch for non-versioned,
non-support commits before they are ready to ship.

**In this repo, that normally means `dev`.** `main` is the stable branch;
ongoing implementation work belongs on `dev` unless there is a deliberate
reason to do otherwise.

## Local Enforcement

When distributed hooks are enabled with `git config core.hooksPath
tools/git-hooks`, [`tools/git-hooks/commit-msg`](../../tools/git-hooks/commit-msg)
enforces this subject policy locally.

The hook rejects:

- malformed support prefixes
- `WIP:` commits on `main`
- versioned subjects whose `Summary` does not match `docs/changelog/vX.Y.Z.md`
- versioned subjects whose crate-manifest version and changelog bundle are not coherent

On non-`main` branches, it also permits amending the current versioned commit
for the same `vX.Y.Z` bundle without forcing an additional version bump, as
long as the bundle remains coherent at that commit.

## Related

- [Changelog](changelog.md) — canonical source for versioned commit summaries
- [Canary](canary.md) — companion pre-commit receipt workflow
