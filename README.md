# cargo-barbican

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE) [![Version](https://img.shields.io/badge/version-0.12.0-blue)](docs/CHANGELOG.md) [![Docs](https://img.shields.io/badge/docs-repo-brightgreen.svg)](docs/README.md) [![Rust](https://img.shields.io/badge/Rust-1.95.0-fc8d62?logo=rust&logoColor=white)](https://blog.rust-lang.org/2026/04/16/Rust-1.95.0/) [![Install](https://img.shields.io/badge/install-git%20tag-B7410E?logo=rust&logoColor=white)](docs/user/integration.md)

`cargo barbican` is a Cargo subcommand that makes it easier for Rust projects to
manage dependency risk and defend against supply-chain attacks. It gives a Rust
repository one policy gate for deciding what can enter the dependency graph,
what needs human review, and what must be blocked before build/test execution.

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

## Platform Support

cargo-barbican is developed and tested on Unix-like systems: macOS and Linux.
It may work on Windows, but Windows is not currently a supported or tested
platform. In particular, fail-closed path-containment guarantees for static
repo state around symlinks, directory junctions, and reparse points are
unverified on Windows.

Treat Windows use as experimental and use-at-your-own-risk until full Windows
support is explicitly delivered.

## Quickstart

Install the pinned release from git:

```bash
cargo install --locked --git https://github.com/rob-morris/cargo-barbican --tag v0.12.0
```

Set up the minimal policy files in the repository that will use the gate:

```bash
cargo barbican policy init
```

Then follow the manual adoption guide to review current dependencies, create
review records, and populate `reviewed-targets.toml`. When policy is ready, run
the main gates:

```bash
cargo barbican pin-check
cargo barbican audit
cargo barbican verify
```

`pin-check` validates reviewed-target policy against the current manifests and
lockfile. `audit` runs the delegated advisory and deny checks. `verify` is the
final CI-oriented gate: it requires `reviewed-targets.toml`, then runs
reviewed-target policy plus locked build/test verification.

See [docs/user/adoption.md](docs/user/adoption.md) for the full adoption flow,
[docs/user/integration.md](docs/user/integration.md) for install/template
integration notes, and [docs/user/commands.md](docs/user/commands.md) for
command workflows and per-command usage.

## High-Level Usage

### Check a candidate before adding it

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

Use `resolve` to age-check exact candidates, run `cargo update --precise`, and
then recheck any newly selected transitive crates:

```bash
cargo barbican resolve serde@1.0.228
```

Preview the lockfile result without mutating the working tree:

```bash
cargo barbican resolve --dry-run serde@1.0.228
```

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

`verify` is the CI-oriented execution gate:

```bash
cargo barbican verify
```

It requires a repo-root `reviewed-targets.toml`, runs the default reviewed-target
policy check, then runs locked build and test verification. Standalone
`pin-check` remains a diagnostic command and skips successfully when no
reviewed-target policy is configured; `verify` does not.

## Configuration and Policy Files

The main files are:

- `barbican.toml` — release-age, high-scrutiny, and delegate settings
- `reviewed-targets.toml` — active reviewed dependency families and exact resolved targets
- `docs/dependency-reviews/` — checked-in human review records
- `deny.toml` — native `cargo-deny` policy, delegated rather than redefined

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
- [docs/user/integration.md](docs/user/integration.md) — install and template integration
- [docs/functional/cli.md](docs/functional/cli.md) — command contract
- [docs/architecture/overview.md](docs/architecture/overview.md) — goals and boundaries
- [docs/contributor/specification.md](docs/contributor/specification.md) — contributor constraints
- [docs/CHANGELOG.md](docs/CHANGELOG.md) — shipped version history
- [AGENTS.md](AGENTS.md) — route-map for agents working in this repo
