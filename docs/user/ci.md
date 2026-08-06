# Continuous Integration

How to wire `cargo barbican` gates into GitHub Actions. This is a worked
example, not the only valid layout — adapt it to your existing workflow files.

See [commands.md](commands.md#glossary) for term definitions (gate, family,
reviewed target, and so on) used below.

## Why pull-request and scheduled runs differ

`cargo barbican pin check` evaluates checked-in reviewed-target policy.
`cargo barbican verify` additionally proves that the active Rust toolchain conforms
to the checked-in exact toolchain pin and runs locked build/test execution.
Run both on every pull request; use clean, reproducible runners so the machine
toolchain facts do not drift around the repo policy.

`cargo barbican audit` is not deterministic in that sense. Its verdict also
depends on the advisory landscape at the moment it runs — a new RustSec
advisory against an already-merged dependency can flip `audit` from PASS to
FAIL with no repo change at all. Running `audit` only on pull requests misses
advisories published after merge. Run it on every pull request **and** on a
schedule (nightly is a reasonable default) so newly published advisories
against crates already in the lockfile are caught even when nobody opens a
PR.

## Prerequisites

Pin every tool the workflow shells out to, the same way you pin
cargo-barbican itself:

```bash
cargo install --locked --git https://github.com/Rob-Morris/cargo-barbican --tag v0.28.0
cargo install --locked cargo-deny@0.19.6 cargo-audit@0.22.1
```

See [integration.md](integration.md#prerequisites) for the review-then-pin
rationale for `cargo-deny` and `cargo-audit`, and what it looks like when
`audit` cannot find them.

### Installing from a private cargo-barbican repository

While the cargo-barbican repository is private, a consumer workflow cannot
install it with the snippet above unmodified, and the failure is not obvious
from the error. Two things are missing in CI:

- **Credentials with read access.** A job's default `GITHUB_TOKEN` is scoped to
  its own repository, so it cannot read cargo-barbican. Supply a token or
  deploy key that can, via a repository secret.
- **A fetch path that uses those credentials.** Cargo's built-in git fetcher
  cannot invoke a shell-command `credential.helper`, so set
  `CARGO_NET_GIT_FETCH_WITH_CLI=true` (or `[net] git-fetch-with-cli = true`)
  to make cargo fetch through the `git` CLI, which honours the credential
  configuration the runner already has.

Without both, the install step fails with
`failed to authenticate when downloading repository` before any cargo-barbican
code runs.

Both requirements are artefacts of the repository being private during the
insiders window. Once it is public the clone is anonymous, no token is needed,
and the snippet above works as written. The local install path is verified;
the private-repository CI path depends on how you provision the token, so
treat the above as the constraint to satisfy rather than a drop-in recipe.

## Generating the workflow

The fastest way to get a working gate is to let cargo-barbican emit it:

```bash
cargo barbican policy init --toolchain 1.95.0 --ci github
```

This writes `.github/workflows/barbican.yml` — a single fail-closed gate job
that runs on pull requests and pushes to `main`, installs the tooling with
`--locked`,
pins its third-party actions by commit SHA, fetches the locked dependency
graph for every target platform (the gate resolves frozen cross-platform
cargo metadata, so the cache must hold crates a build on the runner's own
platform never downloads), and runs `gatehouse pre-release`
plus `age-lock` and `assess`
against the pull-request base. If the file already exists it is never
overwritten: the command fails closed and re-prints the intended contents so
you can reconcile the difference by hand.

Choose the exact channel for the consumer repo; `1.95.0` is only an example.
If a valid exact `rust-toolchain.toml` already exists, omit `--toolchain`.
Workflow generation is blocked while the pin is absent or invalid. At runtime,
Gatehouse requires `rustup`, Cargo, rustc, and rustdoc on `PATH` and checks
their conformance before inventory, audit, build, or test work begins.

The generated workflow deliberately has no scheduled job. `audit`'s verdict can
change with no repo change (see above), so add a nightly `audit` run as shown in
the worked example below. Everything else in the worked example mirrors the
generated gate; treat it as the version to adapt when your repo already has
workflow files.

## Worked example

```yaml
name: dependency-policy

on:
  pull_request:
  push:
    branches: [main]
  schedule:
    # Nightly: catches advisories published after a PR merged, with no repo
    # change to trigger a pull-request run.
    - cron: "17 3 * * *"

jobs:
  pin-and-verify:
    # Deterministic gates: safe to run only on pull requests and pushes to
    # main, because nothing about the result can change without a repo change.
    if: github.event_name != 'schedule'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6.0.3
        with:
          # Full history so age-lock and assess can diff against the PR base.
          fetch-depth: 0

      - name: Install cargo-barbican (pinned)
        run: |
          cargo install --locked --git https://github.com/Rob-Morris/cargo-barbican --tag v0.28.0

      - name: Install cargo-deny and cargo-audit (pinned)
        run: cargo install --locked cargo-deny@0.19.6 cargo-audit@0.22.1

      - name: Fetch dependencies for every target platform
        # The gate resolves frozen cross-platform cargo metadata, which needs
        # every platform's crates in the local cache — including ones a build
        # on this runner never downloads (e.g. Windows-only crates). Plain
        # `cargo fetch` with no --target populates them all.
        run: cargo fetch --locked

      - run: cargo barbican gatehouse pre-release

      - name: Age-lock and assess against the PR base
        if: github.event_name == 'pull_request'
        env:
          BASE_SHA: ${{ github.event.pull_request.base.sha }}
        run: |
          cargo barbican age-lock --base-ref "$BASE_SHA"
          cargo barbican assess --base-ref "$BASE_SHA"

  audit-nightly:
    # Advisory landscape can change with no repo change, so this also runs on
    # a schedule against the current default branch.
    if: github.event_name == 'schedule'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6.0.3

      - name: Install cargo-barbican (pinned)
        run: |
          cargo install --locked --git https://github.com/Rob-Morris/cargo-barbican --tag v0.28.0

      - name: Install cargo-deny and cargo-audit (pinned)
        run: cargo install --locked cargo-deny@0.19.6 cargo-audit@0.22.1

      - run: cargo barbican audit
```

Notes on this layout:

- `gatehouse pre-release` proves exact toolchain conformance, enforces the
  inventory coverage floor, then runs blocking `audit` and blocking `verify`;
  `verify` includes the reviewed-target `pin check` before its build/test steps.
  The scheduled job still runs
  standalone `audit` because the advisory landscape can change without a repo
  change.
- The Gatehouse inventory step fails closed
  (`Inventory: FAIL`) when a direct dependency has entered the graph without an
  active reviewed family — the shape a raw `cargo add` of an unreviewed crate
  takes. Optional, development, build, and target-specific declarations are
  included because they can execute on developer or CI hosts. Declared
  execution-surface enforcement is a documented follow-up. The floor is
  deterministic, so it belongs in the pull-request Gatehouse job, not the
  nightly audit-only job.
- `age-lock` and `assess` run against the pull-request base — `fetch-depth: 0`
  gives the checkout enough history to diff against it — so a lockfile-only
  change that pulled unreviewed transitive crates into `Cargo.lock` is caught
  rather than slipping past the deterministic gates. `age-lock` catches
  too-fresh selections a raw `cargo update` introduced; `assess` classifies the
  whole dependency diff (new sources, execution surfaces, yanked or unreviewed
  crates). They only have a base to diff against on pull requests, so both are
  guarded with `if: github.event_name == 'pull_request'`.
- The pull-request job does not need `--locked` reinstalls to be cached
  identically to the scheduled job, but pinning both jobs to the same install
  lines keeps the two runs comparable.
- Treat `audit` failures from the scheduled job the same as a pull-request
  failure: something in the current dependency graph now has an unreviewed or
  expired advisory finding, and it blocks the same way a pull request would.

## Pre-commit hook

For fast local feedback before a commit reaches CI, cargo-barbican ships an
advisory client-side pre-commit hook at `templates/hooks/pre-commit`. It runs
the cheap subset of the gate — `pin check` and `inventory --enforce` — so
obvious policy breaks surface at commit time:

```sh
#!/bin/sh
set -eu
cargo barbican pin check
cargo barbican inventory --enforce
```

The hook ships in the template set but is not auto-installed; `policy init`
points at it. Get the file into the repo, then enable it one of two ways:

```bash
# Option A: point git at the directory holding the hook
git config core.hooksPath <directory containing the hook>

# Option B: copy it into the repo's git hooks and make it executable
cp templates/hooks/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

The hook is advisory and skippable with `git commit --no-verify`, and coding
agents skip hooks routinely — so it is a convenience, not the gate. The
authoritative, unskippable gate is the server-side workflow above. The hook
deliberately leaves out `verify` (a full `cargo build` and `cargo test`, too
slow for every commit) and `audit` (slower, and its verdict can change
independently of what the commit touches, which makes a commit-time failure
confusing when nothing in the commit is at fault). Run those two in CI, where an
advisory-driven failure is expected and actionable rather than surprising at
commit time.
