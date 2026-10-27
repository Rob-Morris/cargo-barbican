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
cargo install --locked --git https://github.com/Rob-Morris/cargo-barbican --tag v0.36.0
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

Configure required CI status checks, branch protection and policy/workflow
review separately; the generated file alone cannot prevent bypass.

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
          cargo install --locked --git https://github.com/Rob-Morris/cargo-barbican --tag v0.36.0 cargo-barbican
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
          cargo install --locked --git https://github.com/Rob-Morris/cargo-barbican --tag v0.36.0

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

The optional helper runs only `cargo barbican pin check`, then
`cargo barbican inventory --enforce`. It provides fast advisory feedback; no
build/test, audit, tool installation or fetch command is run by the helper.
It can be skipped with `git commit --no-verify`. CI needs separately configured
required checks, branch protection and policy/workflow review; a workflow file
alone cannot make checks unskippable. Keep the scheduled audit too.

### Prerequisites and working directory

Complete adoption before activation. Git and POSIX `sh`, `cargo-barbican` and
the usable selected Rust/Cargo toolchain must be on the hook's PATH, including
in GUI Git clients. Preinstall that exact toolchain; ordinary rustup bootstrap
semantics still apply. Policy, completed records and a consistent lockfile must
exist, together with cached inputs for frozen inventory metadata. A cold but
consistent graph may require explicit reviewed `cargo fetch --locked` without
`--target`; a stale manifest/lock requires Barbican resolve/review instead.
Missing tools/facts fail visibly. No hook framework, cargo-deny, cargo-audit or
nextest is needed for these two checks.

Native Git pre-commit runs from the **Git worktree root**, which may differ
from the intended Cargo workspace root. A nested hooksPath does not change
that working directory. Relative hooksPath values resolve against Git's hook
invocation context, not the shell directory where you set the configuration.

### Optional disabled copy

From the intended Cargo workspace:

```sh
cargo barbican policy init --pre-commit-hook
```

Init copies `.barbican/hooks/pre-commit` only when absent, without executable
bits even under permissive umask. Existing regular bytes/modes are preserved;
that can include an already-enabled custom hook. Check the per-item report.
No Git configuration, chmod, activation or execution occurs. Plain init creates
no hook directory and directs you here for manual installation/integration.

### Manual installation without an upstream checkout

Use the same immutable release as your installed binary. From the intended
Cargo workspace, retrieve into a scratch directory, inspect the script, and
copy only to an absent destination:

```sh
barbican_source=$(mktemp -d) &&
git clone --depth 1 --branch v0.36.0 \
  https://github.com/Rob-Morris/cargo-barbican "$barbican_source/upstream" &&
cat "$barbican_source/upstream/templates/hooks/pre-commit"
```

Stop on any retrieval error. Review the displayed script before the next step.
Preserve an existing destination and merge manually. This copy stage verifies
and reads the source before opening an absent destination; failure stays visible
and retains the scratch source for inspection:

```sh
(
  set -eu
  hook_source="${barbican_source:?}/upstream/templates/hooks/pre-commit"
  test -s "$hook_source" &&
  test ! -e .barbican/hooks/pre-commit &&
  test ! -L .barbican/hooks/pre-commit &&
  hook_contents=$(cat "$hook_source") &&
  mkdir -p .barbican/hooks &&
  (set -C; umask 077; printf '%s\n' "$hook_contents" > .barbican/hooks/pre-commit)
) && rm -rf "$barbican_source"
```

The new copy is non-executable. These commands assume trusted static scaffold
directories without symlinks; init performs the supported path checks itself.
An unpublished candidate uses its matching source checkout; do not silently
replace a missing tag with main. Review upstream diffs on upgrades and retain
consumer-owned changes.

### Integrate an existing hook or hook manager

First inspect `git config --get core.hooksPath` and the current hooks/manager.
Preserve their paths and steps, including other hook types. From the intended
Cargo workspace root, a consumer-owned POSIX shell hook can include:

```sh
# Existing steps remain before/after this check.
sh .barbican/hooks/pre-commit || exit $?
```

Adding this invocation is explicit activation; the copied helper can remain
non-executable. Keep failure propagation. Hook managers use their existing
local-command facility and PATH; install no new framework for Barbican.

For a Cargo workspace in `app/` inside the Git repository, integrate this
wrapper into the existing hook, which Git starts at its own worktree root:

```sh
(cd app && sh .barbican/hooks/pre-commit) || exit $?
```

The subshell preserves the parent hook's cwd for subsequent existing steps.
Use the actual relative workspace path; do not guess `.git/hooks` (worktrees,
submodules and configured managers need their existing route).

### Direct activation for coincident Git and Cargo roots

Only when the Git worktree root **is** the intended Cargo workspace root, and
after inspecting/preserving existing hooks and any manager, an operator can
choose the dedicated directory:

```sh
chmod u+x .barbican/hooks/pre-commit
git config core.hooksPath .barbican/hooks
```

Setting core.hooksPath redirects **all hook types**, not just pre-commit.
Choose existing-hook integration above if that would displace another hook or
manager. An already-selected hooksPath does not execute the newly copied
non-executable file; chmod here is the explicit activation. For nested Cargo
workspaces, use the wrapper route rather than pointing Git directly at the
nested helper. After any route, test both a passing commit and an intentional
policy failure with the actual CLI/GUI environment.

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
