# cargo-barbican

[![CI](https://github.com/Rob-Morris/cargo-barbican/actions/workflows/ci.yml/badge.svg)](https://github.com/Rob-Morris/cargo-barbican/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE) [![Version](https://img.shields.io/badge/version-0.25.0-blue)](docs/CHANGELOG.md) [![Docs](https://img.shields.io/badge/docs-repo-brightgreen.svg)](docs/README.md) [![Rust](https://img.shields.io/badge/Rust-1.95.0-fc8d62?logo=rust&logoColor=white)](https://blog.rust-lang.org/2026/04/16/Rust-1.95.0/) [![Install](https://img.shields.io/badge/install-git%20tag-B7410E?logo=rust&logoColor=white)](docs/user/integration.md)

`cargo barbican` is a Cargo subcommand that makes it easier for Rust projects to
manage dependency risk and defend against supply-chain attacks. It gives a Rust
repository one policy gate for deciding what can enter the dependency graph,
what needs human review, and what must be blocked before build/test execution.

> [!WARNING]
> **Early insiders release — use at your own risk.** cargo-barbican is
> pre-1.0 and distributed as an early-adopter build for maintainers who can
> review the policy and CI changes it generates. Command surfaces, output
> contracts, and config keys may change between releases without a
> deprecation period. It is a policy checkpoint, not a security guarantee: a
> passing gate does not certify a dependency is safe. Provided as-is with no
> warranty of any kind — see [LICENSE](LICENSE). macOS and Linux are the
> supported platforms; Windows is untested and experimental. Read
> [Insiders Release Scope](#insiders-release-scope) before adopting it.

Use it to:

- block too-new or yanked crate versions before they enter the lockfile
- inspect exact crates.io candidates before adding them
- classify dependency diffs as `routine-safe`, `elevated-risk`, or `policy-violating`
- enforce checked-in reviewed-target policy before build/test execution
- run the delegated advisory and deny checks through one workflow
- produce review-focused output for humans deciding whether to trust a dependency

## Approach

cargo-barbican is not a replacement for `cargo-audit`, `cargo-deny`, or human
review. It is the policy checkpoint that coordinates them and fills the gaps
between "known bad" and "not yet trusted": minimum release age, higher-risk Rust
execution surfaces, reviewed-target records, lockfile integrity, and repeatable
operator workflows.

The default stance is fail-closed. When cargo-barbican cannot establish the
policy facts it needs, it blocks and explains what needs review instead of
silently treating uncertainty as safe.

cargo-barbican is complementary to, not competing with, `cargo-vet` and
`cargo-crev`: those tools build shared crate-level trust attestations across
the ecosystem. cargo-barbican is the per-repo policy checkpoint that
coordinates specialist tools (`cargo-deny` and `cargo-audit` today) and fills
the gaps none of them own outright: a minimum release-age gate,
execution-surface policy for `build.rs`/proc-macro/native-sys code,
checked-in reviewed-target records bound to exact checksums, and one intake
workflow that ties evidence gathering, review, and enforcement together.

## Insiders Release Scope

The initial release is an early, Rust-only insiders build distributed by an
immutable git tag. It is intended for maintainers who can review the generated
policy and CI changes and report workflow friction.

The current boundary is deliberately narrower than universal supply-chain
certification:

- `inventory --enforce` holds exact direct-dependency coverage; uncovered
  routine transitive crates and undeclared execution surfaces remain clearly
  labelled review backlog
- legitimate git, path-outside-workspace, and alternate-registry direct
  dependencies do not yet have a positive reviewed-target model and fail the
  coverage floor
- crates.io publication and Windows support are not part of this release
- cross-command hostile-checkout symlink containment and race-free filesystem
  guarantees remain deferred
- `gatehouse candidate` gathers crates.io candidate evidence; it does not prove
  a Cargo tool-install workflow or execute the candidate

## Platform Support

cargo-barbican is developed and tested on Unix-like systems: macOS and Linux.
It may work on Windows, but Windows is not currently a supported or tested
platform. In particular, fail-closed path-containment guarantees for static
repo state around symlinks, directory junctions, and reparse points are
unverified on Windows.

Treat Windows use as experimental and use-at-your-own-risk until full Windows
support is explicitly delivered.

## Quickstart

Install the insiders release candidate from its immutable git tag:

```bash
cargo install --locked --git https://github.com/Rob-Morris/cargo-barbican --tag v0.25.0
```

The tag is the install identity; do not replace it with a moving branch in
consumer CI.

Set up the minimal policy files in the repository that will use the gate:

```bash
cargo barbican policy init
```

Then follow the manual adoption guide to review current dependencies, create
review records, and populate `reviewed-targets.toml`.

`cargo barbican audit` shells out to `cargo-deny` (and `cargo-audit` when
configured), so install those before running it — a fresh machine without them
fails closed with an install hint:

```bash
cargo install --locked cargo-deny@0.19.6 cargo-audit@0.22.1
```

When policy is ready, run the standard pre-release gate:

```bash
cargo barbican gatehouse pre-release
```

`gatehouse pre-release` first applies the direct-dependency coverage floor,
blocking uncovered crates.io dependencies and unsupported external direct
sources. It then runs the blocking advisory/source-policy `audit` and the
blocking `verify` sequence: reviewed-target policy plus locked build/test
verification.

`cargo barbican audit` and `cargo barbican verify` together are the
enforcement gate: they stay two separate commands because their verdicts
depend on different things. `verify`'s verdict is a pure function of the
repo — the same manifests, lockfile, and reviewed-target policy always
produce the same result, so it is deterministic and reproducible. `audit`'s
verdict also depends on the advisory landscape at the moment it runs — a new
RustSec advisory can flip `audit` from PASS to FAIL with no repo change at
all. Keeping them separate as primitives lets CI schedule `audit`
independently; the Gatehouse command is the blessed pre-release composition.
See [docs/user/ci.md](docs/user/ci.md) for a worked example.

See [docs/user/adoption.md](docs/user/adoption.md) for the full adoption flow,
[docs/user/integration.md](docs/user/integration.md) for install/template
integration notes, [docs/user/ci.md](docs/user/ci.md) for a CI workflow
example, and [docs/user/commands.md](docs/user/commands.md) for command
workflows and per-command usage.

## High-Level Usage

### Check a candidate before adding it

Use `pick` when you need cargo-barbican to discover the newest version that
matches a range and satisfies release-age policy:

```bash
cargo barbican pick serde@^1
```

Use `inspect` when you want the policy verdict for an exact crates.io release:

```bash
cargo barbican inspect serde@1.0.228
```

Use `gatehouse candidate` when you want a fuller human-review dossier without
mutating the current repo:

```bash
cargo barbican gatehouse candidate serde@1.0.228
```

The dossier combines crate inspection, an isolated exact-pin Cargo sandbox,
`cargo tree`, and `cargo audit`. It does not build, test, or execute the
candidate package.

### Perform a routine update

Use `update` to age-check exact candidates, run `cargo update --precise`, and
then recheck any newly selected transitive crates:

```bash
cargo barbican update serde@1.0.228
```

Preview the lockfile result without mutating the working tree:

```bash
cargo barbican update --dry-run serde@1.0.228
```

After editing manifests, use `resolve` to regenerate `Cargo.lock` for the
current workspace and apply the same release-age gate to newly selected
crates.io versions:

```bash
cargo barbican resolve
```

### Scaffold a reviewed family

Use `pin add` to scaffold the reviewed-target policy entry and review-record
stub for a crate already resolved in `Cargo.lock`, fully offline:

```bash
cargo barbican pin add serde
```

It reads the resolved version and checksum from `Cargo.lock`, appends a
reviewed family to `reviewed-targets.toml`, and creates a review-record stub
under `docs/dependency-reviews/`. The scaffold is not a completed review:
finish the record, then run `pin check`.

### Review the dependency diff

Classify the current dependency state against the default git baseline:

```bash
cargo barbican assess
```

Accept elevated-risk findings for an explicitly reviewed invocation while still
failing policy violations:

```bash
cargo barbican assess --policy-mode elevated-risk
```

Render the policy-relevant review diff:

```bash
cargo barbican review
```

For non-git baselines, `age-lock`, `assess`, and `review` also support explicit
baseline files or directories. See [docs/functional/cli.md](docs/functional/cli.md)
for the exact flags.

### Enforce the final gate

The standard pre-release gate composes the blocking inventory coverage floor,
`audit`, and `verify`:

```bash
cargo barbican gatehouse pre-release
```

The inventory step applies the same direct-dependency floor as standalone
`inventory --enforce`. `audit` runs the delegated advisory and deny checks and owns their combined
pass/fail verdict. `verify` requires a repo-root `reviewed-targets.toml` with
at least one active reviewed family, runs the default reviewed-target policy
check, then runs locked build and test verification and confirms each passing
step. When run standalone, `verify` prints a note pointing at `audit`
immediately before its final `Verify: PASS` line, because a passing `verify`
says nothing about the advisory landscape on its own. Gatehouse suppresses
that note only after `audit` has passed and ends with
`Gatehouse pre-release: PASS`. Standalone `pin check` remains a diagnostic
command and skips successfully when no reviewed-target policy or no active
family is configured; `verify` fails closed in both cases.

## Configuration and Policy Files

The main files, all documented in the
[configuration reference](docs/user/configuration.md):

- [`barbican.toml`](docs/user/configuration.md) — release-age, high-scrutiny, and delegate settings
- [`reviewed-targets.toml`](docs/user/configuration.md) — active reviewed dependency families and exact resolved targets
- [`docs/dependency-reviews/`](docs/user/configuration.md) — checked-in human review records
- [`deny.toml`](docs/user/configuration.md) — native `cargo-deny` policy, delegated rather than redefined

The current tool is Rust-only. It intentionally stays above specialist Rust
tools instead of becoming a cross-ecosystem package-management framework.

## Repo Shape

- `crates/barbican/` — policy logic, domain types, and testable core behaviour
- `crates/cargo-barbican/` — CLI dispatch, subprocesses, and concrete I/O boundaries
- `docs/` — user, functional, architectural, and contributor documentation
- `templates/` — shipped repo content for consumer adoption

## Documentation

- [docs/README.md](docs/README.md) — documentation index
- [docs/user/adoption.md](docs/user/adoption.md) — adoption and manual onboarding guide
- [docs/user/commands.md](docs/user/commands.md) — command workflows and usage reference
- [docs/user/configuration.md](docs/user/configuration.md) — `barbican.toml` and `reviewed-targets.toml` reference
- [docs/user/integration.md](docs/user/integration.md) — install and template integration
- [docs/user/ci.md](docs/user/ci.md) — GitHub Actions CI workflow example
- [docs/user/operations.md](docs/user/operations.md) — day-2 operations: failing audits, updates, family lifecycle
- [docs/user/hardening.md](docs/user/hardening.md) — making the gate hard to bypass
- [docs/functional/cli.md](docs/functional/cli.md) — command contract
- [docs/architecture/overview.md](docs/architecture/overview.md) — goals and boundaries
- [docs/contributor/specification.md](docs/contributor/specification.md) — contributor constraints
- [docs/CHANGELOG.md](docs/CHANGELOG.md) — shipped version history
- [AGENTS.md](AGENTS.md) — route-map for agents working in this repo

## Security

Report suspected vulnerabilities privately — please do not open a public
issue. [SECURITY.md](SECURITY.md) names the reporting channels, the response
windows you can expect, and which release lines receive fixes.

## Contributing

Contributions are welcome, and the bar for dependency changes is deliberately
high — this repo runs its own gate on itself. Start with
[docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) for the contributor workflow, then
[docs/contributor/process.md](docs/contributor/process.md) for the commit-time
checks and [docs/contributor/specification.md](docs/contributor/specification.md)
for the constraints on new work.

Every direct dependency change, dependency-tool install, and `deny.toml` policy
change needs a checked-in review record under
[docs/dependency-reviews/](docs/dependency-reviews/README.md) before it lands.

## Licence

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 Rob Morris.
