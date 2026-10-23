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
cargo install --locked --git https://github.com/Rob-Morris/cargo-barbican --tag v0.34.0
cargo install --locked cargo-deny@0.19.6 cargo-audit@0.22.1
```

See [integration.md](integration.md#prerequisites) for the review-then-pin
rationale for `cargo-deny` and `cargo-audit`, and what it looks like when
`audit` cannot find them.

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
plus independent `age-lock` and `assess` checks against the exact PR base.
After ordinary gate rejection those checks can still run, provided setup,
fresh toolchain conformance and base availability succeed. Native failures
remain red; recognised cancellation stops further evidence. A PR job summary
shows each outcome and explains unavailable reports. If the file already exists it is never
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

permissions:
  contents: read

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

jobs:
  gate:
    if: github.event_name != 'schedule'
    name: cargo-barbican gate
    runs-on: ubuntu-latest
    steps:
      - id: checkout
        uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6.0.3
        with:
          # Full history so age-lock and assess can diff against the PR base commit.
          fetch-depth: 0
      - id: toolchain
        name: Install the pinned Rust toolchain
        # Reads rust-toolchain.toml; pin your toolchain there for reproducible gates.
        run: rustup toolchain install
      - uses: Swatinem/rust-cache@c19371144df3bb44fab255c43d04cbc2ab54d1c4 # v2.9.1
      - id: tools
        name: Install cargo-barbican, cargo-deny, and cargo-audit
        run: |
          cargo install --locked --git https://github.com/Rob-Morris/cargo-barbican --tag v0.34.0 cargo-barbican
          cargo install --locked cargo-deny@0.19.6
          cargo install --locked cargo-audit@0.22.1
      - id: fetch
        name: Fetch dependencies for every target platform
        # The gate resolves frozen cross-platform cargo metadata, which needs
        # every platform's crates in the local cache — including ones a build
        # on this runner never downloads (e.g. Windows-only crates). Plain
        # `cargo fetch` with no --target populates them all.
        run: cargo fetch --locked
      - id: pre_release
        name: Pre-release supply-chain gate
        run: cargo barbican gatehouse pre-release
      - id: evidence_toolchain
        name: Check toolchain before PR evidence
        if: >-
          ${{ !cancelled() && github.event_name == 'pull_request' &&
              steps.checkout.outcome == 'success' && steps.toolchain.outcome == 'success' &&
              steps.tools.outcome == 'success' && steps.fetch.outcome == 'success' }}
        run: cargo barbican toolchain check
      - id: pr_base
        name: Check explicit PR base availability
        if: >-
          ${{ !cancelled() && github.event_name == 'pull_request' &&
              steps.checkout.outcome == 'success' && steps.toolchain.outcome == 'success' &&
              steps.tools.outcome == 'success' && steps.fetch.outcome == 'success' }}
        shell: bash
        env:
          BASE_SHA: ${{ github.event.pull_request.base.sha }}
        run: |
          if [[ ! "$BASE_SHA" =~ ^[0-9a-fA-F]{40}$ ]]; then
            printf '%s\n' 'FAIL PR evidence unavailable: invalid or missing PR base SHA' >&2
            exit 1
          fi
          if ! git cat-file -e "$BASE_SHA^{commit}"; then
            printf '%s\n' 'FAIL PR evidence unavailable: PR base commit is not available locally' >&2
            exit 1
          fi
      - id: age_lock
        name: Check release age against the PR base
        if: >-
          ${{ !cancelled() && github.event_name == 'pull_request' &&
              steps.checkout.outcome == 'success' && steps.toolchain.outcome == 'success' &&
              steps.tools.outcome == 'success' && steps.fetch.outcome == 'success' &&
              steps.evidence_toolchain.outcome == 'success' && steps.pr_base.outcome == 'success' }}
        env:
          BASE_SHA: ${{ github.event.pull_request.base.sha }}
        run: cargo barbican age-lock --base-ref "$BASE_SHA"
      - id: assess
        name: Assess against the PR base
        if: >-
          ${{ !cancelled() && github.event_name == 'pull_request' &&
              steps.checkout.outcome == 'success' && steps.toolchain.outcome == 'success' &&
              steps.tools.outcome == 'success' && steps.fetch.outcome == 'success' &&
              steps.evidence_toolchain.outcome == 'success' && steps.pr_base.outcome == 'success' }}
        env:
          BASE_SHA: ${{ github.event.pull_request.base.sha }}
        run: cargo barbican assess --base-ref "$BASE_SHA"
      - name: Summarise PR evidence
        if: ${{ !cancelled() && github.event_name == 'pull_request' }}
        shell: bash
        env:
          BASE_SHA: ${{ github.event.pull_request.base.sha }}
          CHECKOUT_OUTCOME: ${{ steps.checkout.outcome }}
          TOOLCHAIN_OUTCOME: ${{ steps.toolchain.outcome }}
          TOOLS_OUTCOME: ${{ steps.tools.outcome }}
          FETCH_OUTCOME: ${{ steps.fetch.outcome }}
          GATE_OUTCOME: ${{ steps.pre_release.outcome }}
          ELIGIBILITY_OUTCOME: ${{ steps.evidence_toolchain.outcome }}
          BASE_OUTCOME: ${{ steps.pr_base.outcome }}
          AGE_OUTCOME: ${{ steps.age_lock.outcome }}
          ASSESS_OUTCOME: ${{ steps.assess.outcome }}
        run: |
          native_outcome() {
            case "$1" in
              success|failure|skipped|cancelled) printf '%s' "$1" ;;
              *) printf '%s' 'unavailable' ;;
            esac
          }
          setup_missing=
          for prerequisite in "checkout:$CHECKOUT_OUTCOME" "toolchain:$TOOLCHAIN_OUTCOME" "tools:$TOOLS_OUTCOME" "fetch:$FETCH_OUTCOME"; do
            if [[ "$prerequisite" != *:success ]]; then
              setup_missing="${setup_missing}${setup_missing:+, }${prerequisite%%:*}"
            fi
          done
          unavailable=
          if [[ -n "$setup_missing" ]]; then
            unavailable="setup incomplete: $setup_missing"
          fi
          if [[ "$ELIGIBILITY_OUTCOME" != success ]]; then
            unavailable="${unavailable}${unavailable:+; }toolchain conformance $(native_outcome "$ELIGIBILITY_OUTCOME")"
          fi
          if [[ "$BASE_OUTCOME" != success ]]; then
            unavailable="${unavailable}${unavailable:+; }PR base $(native_outcome "$BASE_OUTCOME")"
          fi
          evidence_outcome() {
            case "$1" in
              success|failure) native_outcome "$1" ;;
              *) printf 'unavailable — %s' "${unavailable:-did not run}" ;;
            esac
          }
          if [[ "$BASE_SHA" =~ ^[0-9a-fA-F]{40}$ ]]; then
            base_label=$BASE_SHA
          else
            base_label='unavailable (invalid event SHA)'
          fi
          if current_revision=$(git rev-parse --verify HEAD 2>/dev/null) && [[ "$current_revision" =~ ^[0-9a-fA-F]{40}$ ]]; then
            current_label=$current_revision
          else
            current_label=unavailable
          fi
          {
            printf '%s\n' '## PR dependency evidence' '' '| Check | Native outcome / availability |' '| --- | --- |'
            printf '| Requested PR base | %s |\n' "$base_label"
            printf '| Checked-out revision | %s |\n' "$current_label"
            printf '| Checkout | %s |\n' "$(native_outcome "$CHECKOUT_OUTCOME")"
            printf '| Toolchain installation | %s |\n' "$(native_outcome "$TOOLCHAIN_OUTCOME")"
            printf '| Tool installation | %s |\n' "$(native_outcome "$TOOLS_OUTCOME")"
            printf '| Dependency fetch | %s |\n' "$(native_outcome "$FETCH_OUTCOME")"
            printf '| Pre-release gate | %s |\n' "$(native_outcome "$GATE_OUTCOME")"
            printf '| Evidence toolchain conformance | %s |\n' "$(native_outcome "$ELIGIBILITY_OUTCOME")"
            printf '| PR base availability | %s |\n' "$(native_outcome "$BASE_OUTCOME")"
            printf '| age-lock | %s |\n' "$(evidence_outcome "$AGE_OUTCOME")"
            printf '| assess | %s |\n' "$(evidence_outcome "$ASSESS_OUTCOME")"
            printf '\n%s\n' 'Failures retain their command logs and keep the job red. Unavailable evidence is not a passing policy verdict.'
          } | tee -a "$GITHUB_STEP_SUMMARY"


  audit-nightly:
    # Advisory landscape can change with no repo change, so this also runs on
    # a schedule against the current default branch.
    if: github.event_name == 'schedule'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6.0.3

      - name: Install cargo-barbican (pinned)
        run: |
          cargo install --locked --git https://github.com/Rob-Morris/cargo-barbican --tag v0.34.0

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


## Policy-only consumers

`gatehouse policy-check` supports consumers that independently own locked
execution and its reuse. It does not certify cached execution artefacts and
does not replace the generated `gatehouse pre-release` release gate. Existing
consumer workflows are not rewritten. See the [integration recipe](integration.md#policy-checks-without-buildtest).


## PR evidence availability and migration

The complete gate job above replaces the old default-success-gated combined
age/assessment step. Both independent checks require successful named setup
steps, a fresh post-gate `toolchain check`, and the exact event-base commit.
Neither depends on the gate or the other evidence command succeeding. A valid
base missing a required file remains a native command failure; a newly added
manifest absent from that base remains an intentional dependency addition.

Use `!cancelled()` rather than unconditional `always()`: once cancellation is
recognised no new evidence is scheduled. Cancellation of an already-running
process follows GitHub's ordinary runner semantics. Main pushes still run the
whole gate and skip PR-only eligibility, baseline, evidence and summary steps.

A summary is diagnostic presentation of native outcomes, not another policy
verdict. Setup/toolchain/base failures make evidence unavailable, not passing.
Every failed setup/gate/evidence step retains its failure; no `continue-on-error`
or weaker assessment mode is used. Keep full predicates during [manual
migration](integration.md#migrating-pr-evidence-after-gate-failure), including
step IDs and the new minimum tool version; existing consumer files are not
rewritten by an upgrade.

These checks share the ordinary runner/worktree. Prior builds/tests may have
changed inputs; assess uses ordinary metadata and can update Cargo state. Fresh
conformance protects continuation through rejected executable controls, not
binary provenance or isolation from prior execution. Earlier Cargo install/fetch
configuration exposure remains the existing bootstrap trust boundary. Action
SHAs select commits; Barbican version-tag installation relies on the project's
immutable-tag release discipline, and `--locked` selects dependency lockfiles.
