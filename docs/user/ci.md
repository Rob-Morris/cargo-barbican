# Continuous Integration

How to wire `cargo barbican` gates into GitHub Actions. This is a worked
example, not the only valid layout — adapt it to your existing workflow files.

See [commands.md](commands.md#glossary) for term definitions (gate, family,
reviewed target, and so on) used below.

## Why pull-request and scheduled runs differ

`cargo barbican pin check` and `cargo barbican verify` are deterministic: for
a fixed commit, manifests, lockfile, and reviewed-target policy, the result
never changes. Running them on every pull request is sufficient — nothing
about them can change between two runs of the same commit.

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
cargo install --locked --git https://github.com/rob-morris/cargo-barbican --branch main
cargo install --locked cargo-deny cargo-audit
```

See [integration.md](integration.md#prerequisites) for the review-then-pin
rationale for `cargo-deny` and `cargo-audit`, and what it looks like when
`audit` cannot find them.

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
      - uses: actions/checkout@v4

      - name: Install cargo-barbican (pinned)
        run: |
          cargo install --locked --git https://github.com/rob-morris/cargo-barbican --branch main

      - name: Install cargo-deny and cargo-audit (pinned)
        run: cargo install --locked cargo-deny cargo-audit

      - run: cargo barbican pin check
      - run: cargo barbican audit
      - run: cargo barbican verify

  audit-nightly:
    # Advisory landscape can change with no repo change, so this also runs on
    # a schedule against the current default branch.
    if: github.event_name == 'schedule'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install cargo-barbican (pinned)
        run: |
          cargo install --locked --git https://github.com/rob-morris/cargo-barbican --branch main

      - name: Install cargo-deny and cargo-audit (pinned)
        run: cargo install --locked cargo-deny cargo-audit

      - run: cargo barbican audit
```

<!-- PRE-RELEASE: cargo-barbican is not yet publicly released and no v* git
     tag is cut, so the install lines above pin to a branch rather than a
     tag. Once a public release ships, restore the --tag install line to
     match README.md. Tracked in the brain project release checklist. -->

Notes on this layout:

- `pin check` is run explicitly before `audit` and `verify` here for a
  readable failure signal (a pin-check failure surfaces on its own step);
  `verify` re-runs the same reviewed-target gate before its build/test steps
  regardless, so this is not required for correctness.
- The pull-request job does not need `--locked` reinstalls to be cached
  identically to the scheduled job, but pinning both jobs to the same install
  lines keeps the two runs comparable.
- Treat `audit` failures from the scheduled job the same as a pull-request
  failure: something in the current dependency graph now has an unreviewed or
  expired advisory finding, and it blocks the same way a pull request would.

## Pre-commit hook

For local enforcement before a commit reaches CI at all, add a pre-commit hook
that runs the deterministic gates:

```bash
#!/bin/sh
set -eu
cargo barbican pin check
cargo barbican verify
```

Leave `audit` out of the pre-commit hook. It is slower (it shells out to
`cargo-deny` and `cargo-audit`) and its verdict can change independently of
what the commit touches, which makes a pre-commit failure confusing when
nothing in the commit is at fault. Run `audit` in CI (and nightly) instead,
where an advisory-driven failure is expected and actionable rather than
surprising at commit time.
