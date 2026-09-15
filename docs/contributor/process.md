# Contributor Process

Shared contributor workflow for this repo.

## Hook Package

This repo ships opt-in distributed Git hooks:

- brief: [`.canaries/pre-commit.md`](../../.canaries/pre-commit.md)
- pre-commit checker: [`tools/git-hooks/pre-commit`](../../tools/git-hooks/pre-commit)
- commit-message checker: [`tools/git-hooks/commit-msg`](../../tools/git-hooks/commit-msg)
- reusable shell checks:
  - [`scripts/verify.sh`](../../scripts/verify.sh)
  - [`scripts/check_pre_commit_canary.sh`](../../scripts/check_pre_commit_canary.sh)
  - [`scripts/check_commit_msg.sh`](../../scripts/check_commit_msg.sh)
  - [`scripts/check_release_tag.sh`](../../scripts/check_release_tag.sh)
- behaviour tests for the shell checks:
  - [`scripts/tests/check_commit_msg_test.sh`](../../scripts/tests/check_commit_msg_test.sh)
  - [`scripts/tests/check_release_tag_test.sh`](../../scripts/tests/check_release_tag_test.sh)
  - [`scripts/tests/verify_branch_guard_test.sh`](../../scripts/tests/verify_branch_guard_test.sh)

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
[1] Verification: done, sh scripts/verify.sh passed
[2] Dependency provenance: done
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

For an immutable-tag release, commit the complete version bundle before
creating the tag. Then prove that the manifest-derived tag resolves to the
intended release commit:

```bash
git tag vX.Y.Z <release-commit>
sh scripts/check_release_tag.sh <release-commit>
```

Only after that check passes should the commit and tag be pushed. Finish with
a clean install from the published tag; that remote install is the deployment
proof that the release identity advertised in user documentation is usable.

```bash
cargo install --locked \
  --git https://github.com/Rob-Morris/cargo-barbican --tag vX.Y.Z \
  --root /tmp/barbican-install-proof cargo-barbican
```

`--root` keeps the proof out of `~/.cargo/bin` until you actually want the
binary installed.

**If a tag name is being reused for a different commit** — a re-cut release
after amending, which the insiders sequence has done repeatedly — cargo may
reuse its cached checkout under `~/.cargo/git` and rebuild the *old* commit
while still reporting success. Pass `--force` and confirm the commit hash cargo
prints matches the tag:

```text
Installed package `cargo-barbican vX.Y.Z (…?tag=vX.Y.Z#<short-sha>)`
```

If that SHA is not the intended release commit, the cache served a stale
checkout; clear `~/.cargo/git/db/cargo-barbican-*` and retry. Exit status alone
does not prove the drill built the tagged tree.

## Verification Expectations

The repo-level verification entry point is:

```bash
sh scripts/verify.sh
```

The default path dogfoods cargo-barbican by running:

```bash
cargo run --locked --bin cargo-barbican -- gatehouse pre-release
```

Outside `--skip`, it first runs the policy-script behaviour tests under
[`scripts/tests/`](../../scripts/tests/) so the commit-subject gate stays
covered.

Because `verify` is the CI enforcement gate, it fails closed when the repo has
not adopted `reviewed-targets.toml`. Off `main` only, contributors may use one
of the explicit escape hatches and must record the reason in
`.canary--pre-commit`:

```bash
sh scripts/verify.sh --vanilla
sh scripts/verify.sh --skip "known breaking refactor: <reason>"
```

`--vanilla` runs the raw underlying checks:

```bash
cargo audit
cargo deny check advisories bans sources
cargo build --locked
cargo test --locked
```

`--vanilla` and `--skip` are rejected on `main`.

## Local Invocation Notes

When dogfooding cargo-barbican inside this repo:

- non-mutating commands may be run through Cargo, for example:
  - `cargo run --locked --bin cargo-barbican -- inspect ...`
  - `cargo run --locked --bin cargo-barbican -- assess ...`
- mutating commands that intentionally change the repo `Cargo.lock` should be
  run through the built binary directly, for example:
  - `target/debug/cargo-barbican resolve`
  - `target/debug/cargo-barbican update serde@1.0.228`

Reason:

- `cargo run --locked ...` asks Cargo itself to keep the workspace lockfile
  unchanged while it builds and launches the binary
- that is the wrong launcher contract for commands such as `resolve` and
  `update` that are supposed to mutate `Cargo.lock`

Normal pre-commit expectations still include checked-in dependency review
records for direct dependency and `deny.toml` changes.

Those expectations are recorded in the canary brief and contributor docs even
when the hook cannot prove every one of them mechanically from the staged
diff alone.
