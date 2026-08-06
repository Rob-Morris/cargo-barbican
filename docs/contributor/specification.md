# Contributor Specification

Contributor-facing specification for cargo-barbican. This document captures the
current contributor constraints, dependency discipline, and shipped-template
boundary.

## Scope

cargo-barbican is a Cargo subcommand for Rust supply-chain hardening: a
portable, policy-first tool that gives a Rust repo one dependency-intake gate.
It was extracted from the equivalent Rust workflow in undertask's Python and
shell scripts and has grown its own product surface beyond them. Local/git
install-and-pin is the current distribution; crates.io publication is deferred,
not foreclosed.

## Source material

cargo-barbican's origin and reference implementation is undertask, a private
predecessor project. For maintainers with access to that private repo, the
matching sources worth consulting before redesigning behaviour are:

- `scripts/check-crate-release-age.py`
- `scripts/check-cargo-lock-release-age.py`
- `scripts/select-cargo-package-id.py`
- `scripts/deps-rust-routine-update.sh`
- `docs/dependency-management.md`
- `deny.toml`
- `docs/dependency-reviews/`

undertask is a working reference, not the specification: re-implement its proven
behaviour faithfully where surfaces overlap, and expect cargo-barbican to extend
beyond it as a policy product. Document both deviations and extensions
explicitly.

## Dependency discipline

Every entry must have a corresponding record in `docs/dependency-reviews/`
before it is added to `Cargo.toml`. Most listed crates inherit from
Undertask's reviewed set. Crates that do not inherit from Undertask are
reviewed first-principles in cargo-barbican itself before they define or
support a local boundary such as HTTP, time parsing, archive inspection, or
diff rendering.

| Crate | Version | Source | Notes |
|---|---|---|---|
| `serde` | 1 (derive) | crates.io | Inherited from undertask |
| `serde_json` | 1 | crates.io | Inherited from undertask; used for crates.io API and `cargo metadata` |
| `toml` | 1.1 | crates.io | Inherited from undertask; used for lockfile parsing if hand-rolled |
| `clap` | 4 (derive) | crates.io | Inherited from undertask; subcommand parsing |
| `similar` | =3.1.1 (`default-features = false`, `features = [\"text\"]`) | crates.io | First-principles review for the explicit non-git review renderer experiment |
| `thiserror` | 2 | crates.io | Inherited from undertask; error enums |
| `time` | 0.3 (`std`, `parsing`) | crates.io | First-principles review; RFC 3339 parsing and UTC comparisons with smaller target surface than `chrono` |
| `ureq` | 3.3 (`default-features = false`, `features = ["rustls"]`) | crates.io | First-principles review; pure-Rust blocking HTTP boundary |
| `miniz_oxide` | =0.9.1 (`default-features = false`, `features = [\"with-alloc\"]`) | crates.io | Direct dependency for `.crate` gzip handling in the library and test support in the binary |
| `sha2` | =0.10.9 (`default-features = false`, `features = [\"force-soft\"]`) | crates.io | Direct dependency for reviewed artefact SHA-256 verification and test support |
| `tar` | =0.4.46 (`default-features = false`) | crates.io | Direct dependency for `.crate` tarball inspection and test support |
| `semver` | =1.0.28 | crates.io | First-principles review; Cargo-compatible semver range evaluation for `pick` |

`ureq` is preferred over a heavier HTTP stack because the surface is small and
blocking I/O is acceptable at the CLI boundary.

## Constraints

- No new dependencies without a review record.
- No second HTTP client. Replace `ureq` if necessary; do not add a peer.
- Crates.io requests that begin from an HTTPS base URL remain HTTPS-only across
  redirects; plain HTTP is limited to the validated loopback test seam.
- The library must remain testable without network access.
- The binary is the subprocess boundary for `git` and `cargo`.
- Templates are shipped content for consumer repos, not repo-facing documentation.
- Future planning, slice sequencing, and deferred design work live in Brain,
  not in the canonical repo docs.

## Current implemented policy surface

The checked-in root `barbican.toml` carries these sections:

- `[release_age]`
- `[high_scrutiny]`
- `[delegates]`

`[release_age].minimum_days` is active for `age`, `age-lock`, `pick`,
`resolve`, `update`, `assess`, and `inspect`.

The current baseline rules for comparative commands are:

- `age-lock` defaults to `--base-ref HEAD` and also accepts
  `--base-lockfile <path>` as an explicit non-git baseline
- `assess` defaults to `--base-ref HEAD` and also accepts
  `--base-dir <path>` as an explicit non-git dependency-state baseline
- `review` keeps the existing git-backed default path and also accepts
  `--base-dir <path>` as an explicit non-git review baseline
- `resolve` generates `Cargo.lock` for the current manifests and rechecks newly
  selected crates.io versions against an internal pre-resolve `Cargo.lock`
  snapshot, restoring the snapshot on release-age failure
- `update` no longer depends on `HEAD`; it rechecks against an internal
  pre-update `Cargo.lock` snapshot
- `update` also supports `--dry-run`, which executes the targeted update in an
  internal temp workspace and prints a summary/diff preview of the would-be
  `Cargo.lock` change instead of mutating the repo
  - the dry-run workspace copy preserves relative symlinks only when their
    fully resolved target remains inside the source workspace and outside
    skipped `.git` / `target` paths
  - absolute, broken, looping, escaping, or skipped-target symlinks fail the
    dry-run setup rather than being dereferenced or silently skipped

The first active `high_scrutiny` keys are:

- `new_direct_dependencies`
- `non_crates_io_direct_dependencies`
- `non_crates_io_source_changes`
- `build_rs_changes`
- `proc_macro_changes`
- `native_sys_crates`

`cargo barbican assess` is fail-closed by default under
`--policy-mode strict`. If the tool cannot complete a required
dependency-surface inspection for the current implemented surface, it reports a
blocking finding rather than silently treating the package as safe.
`--policy-mode elevated-risk` may accept elevated-risk classifications with
exit 0 for an invocation-scoped review workflow, but it still fails any
`policy-violating` classification.

`cargo barbican inspect` is currently:

- Rust-only and crates.io-only
- exact `crate@version` input only
- release-age aware, using the same default and override rules as `age`
- checksum-oriented: local tarball SHA-256 must match the published crates.io
  checksum
- provenance-aware: inspect `.cargo_vcs_info.json` when present
- high-scrutiny oriented: enumerate `build.rs`, `proc-macro`, and native
  `-sys` / FFI surfaces, then run a fixed IOC scan over build-time and
  proc-macro-relevant sources
- fail-closed for routine intake: checksum mismatches, IOC hits, and required
  inspection failures are blocking; surfaced high-scrutiny execution surfaces
  are elevated-risk

`cargo barbican pick` is currently:

- Rust-only and crates.io-only
- read-only
- one crate name or crate plus Cargo semver requirement input
- release-age aware, using the same default and override rules as `age`
- range-aware through the reviewed `semver` crate
- conservative: yanked versions, pre-releases, versions outside the range, and
  too-fresh versions are excluded from selection
- exact-output oriented: successful output prints the selected `crate@version`
  to feed into `inspect`, `gatehouse candidate`, or a manifest edit followed by
  `resolve`

`cargo barbican gatehouse candidate` is currently:

- an exact `crate@version` workflow convenience for isolated candidate intake
- a composition layer over existing evidence primitives, not a separate policy
  engine
- non-mutating with respect to the current repo
- backed by a disposable minimal Cargo sandbox pinned to the exact candidate
- dossier-oriented: it renders inspect evidence, sandbox lockfile status,
  `cargo tree --edges normal`, `cargo audit`, and a suggested next step on
  stdout
- non-executing with respect to the candidate: it does not build, test, run
  build scripts, or load proc macros from the candidate package
- fail-closed for evidence gathering: failed inspect, lockfile generation,
  `cargo tree`, or `cargo audit` evidence returns exit 1 after rendering the
  dossier
- cleanup-first by default, with `--preserve-sandbox` available for manual
  inspection of the generated sandbox
- not a repo-integration simulation; repo adoption remains covered by
  `resolve`, `update`, `assess`, `review`, `pin check`, and `verify`

`cargo barbican gatehouse pre-release` is currently:

- the blessed fail-fast whole-repo composition for release use
- ordered as the blocking `inventory --enforce` coverage floor, blocking
  `audit`, then blocking `verify`
- fail-fast on uncovered direct dependencies, external direct sources, or
  unavailable graph/policy facts, while leaving transitive backlog and
  undeclared execution surfaces observational
- non-duplicating: the reviewed-target `pin check` runs once inside `verify`
- a composition layer only; `audit` and `verify` keep their standalone policy
  meanings, exit behaviour, and report bodies
- text-only in this first slice, with no workflow configuration, policy
  overrides, exception flags, or JSON contract

`cargo barbican policy init` is currently:

- the deterministic setup command for explicit repo policy scaffolding
- non-interactive and non-certifying: it does not review existing dependencies
  or generate active reviewed families
- template-backed: it writes the shipped `barbican.toml`, `deny.toml`,
  `reviewed-targets.toml`, and dependency-review README templates when absent
- toolchain-explicit: it validates an existing `rust-toolchain.toml`, creates
  one only from `--toolchain <exact-channel>`, and does not emit CI scaffolding
  while the exact compiler pin is absent or invalid
- explicit about generated rustup policy: a created toolchain file uses
  `profile = "minimal"`, and the init report names that profile rather than
  silently narrowing the installed component set
- advisory-owned: the shipped `deny.toml` carries a normal `[advisories]`
  table for direct cargo-deny use plus bans/sources posture; `cargo barbican
  audit` still forces maximum disclosure and never derives authorisation from
  native ignores
- conservative with existing files: regular files are preserved, existing
  `barbican.toml` is validated, and symlinks or wrong-type scaffold paths fail
  closed
- adoption-guidance oriented: successful output points operators to the manual
  adoption guide before `pin check` / `verify`

`cargo barbican verify` and `gatehouse pre-release` are toolchain-gated:

- `rust-toolchain.toml` is required and must name a full stable release, exact
  numbered beta prerelease (for example `1.96.0-beta.2`), or dated nightly;
  bare versioned beta channels, floating channels, custom/path toolchains,
  legacy `rust-toolchain` shadowing, and symlinked policy files fail closed
- the gate compares the active rustup toolchain with verbose Cargo, rustc, and
  rustdoc release/host facts before any dependency-policy or build/test delegate runs
- the documented Cargo Rust-toolchain executable environment variables
  (`RUSTC`, `CARGO_BUILD_RUSTC`, `RUSTC_WRAPPER`,
  `CARGO_BUILD_RUSTC_WRAPPER`, `RUSTC_WORKSPACE_WRAPPER`, and
  `CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER`, plus `RUSTDOC` and
  `CARGO_BUILD_RUSTDOC`), effective hierarchical Cargo
  `[build].rustc`, `[build].rustc-wrapper`,
  `[build].rustc-workspace-wrapper`, `[build].rustdoc`, and indirect Cargo
  config includes fail closed because they prevent the pinned toolchain facts
  from being established
- inability to resolve the user-level Cargo config location from `CARGO_HOME`
  or `HOME` also fails closed rather than being treated as verified clean
- repo and ancestor Cargo config files retain the policy-file symlink refusal;
  a Cargo-home config may itself be a symlink only when Cargo home and its
  target both resolve outside the workspace, and the target is a readable
  regular file; a repo-local `CARGO_HOME` retains the repository refusal
- a dated nightly's exact date is established from rustup's active-toolchain
  identity; Cargo, rustc, and rustdoc must then agree on the verbose nightly
  release and host that those tools actually report
- Gatehouse performs the toolchain preflight once as its first blocking step;
  standalone `verify` performs the same preflight itself, and nested verify
  requires the resulting completed-preflight evidence
- this gate establishes Rust toolchain executable identity, not binary
  provenance or a sandbox for every executable Cargo may invoke. `RUSTUP_HOME`
  remains an allowed installation-location control, and target runners,
  linkers, rustflags, and Cargo `[env]` configuration remain ordinary
  build/test inputs. The later Cargo build and test delegates execute under
  Cargo's normal semantics and must run only after dependency review makes
  that execution acceptable

`cargo barbican inventory` is currently:

- a read-only whole-repo dependency inventory and reviewed-policy coverage
  audit
- local and read-only: it reads `Cargo.lock`, workspace manifests, root
  `[workspace.dependencies]`, optional `reviewed-targets.toml`, checked-in
  review-record facts, and `cargo metadata --format-version 1 --frozen` output
  for live graph execution surfaces
- pure at the library seam: `barbican` builds an `Inventory` model from parsed
  inputs, while `cargo-barbican` owns filesystem reads and rendering
- adoption-friendly: absent `reviewed-targets.toml` is reported as no policy
  configured rather than failing
- fail-closed on malformed required inputs: missing or malformed `Cargo.lock`,
  malformed manifests, and malformed reviewed-target policy stop the command
- explicit about readiness categories: the summary separates the
  direct-dependency coverage floor and its direct blockers from observational
  uncovered transitive backlog, observational undeclared execution surfaces,
  enforced incomplete review records, and other observational manifest/source
  findings; the detailed reviewed-policy section names which sibling gate owns
  each category
- informational by default: findings do not change the exit code without
  `--enforce`; the opt-in floor gates exact direct-dependency coverage only and
  ends with an explicitly scoped `Inventory: PASS/FAIL (direct-dependency
  coverage floor)` token
- scoped to Cargo's ordinary crates.io source identity: source replacement or
  mirror configurations that rewrite the lockfile source string are outside the
  supported coverage model for this slice and may be reported as
  non-crates.io sources
- approximate about workspace membership in this manifest-discovery slice: member
  discovery uses local manifest paths and directory walks rather than Cargo's
  exact glob-depth and `[workspace] exclude` semantics, so nested or excluded
  non-member manifests under walked roots can appear in the inventory; the
  enforcement floor separately uses Cargo metadata's parsed declarations and
  workspace-member identities plus exact `Cargo.lock` dependency edges
- explicit about graph collection failure: if `cargo metadata --frozen` fails
  because the graph is unresolved or metadata cannot be parsed, inventory still
  renders the offline report, while `inventory --enforce` fails closed because
  exact direct-package identities are unavailable; unresolved crates.io and
  non-crates.io source gaps remain neutral unclassified facts rather than being
  labelled enforced or observational

`cargo barbican audit` is currently:

- delegated-scanner based: it runs `cargo-deny` (and/or `cargo-audit`,
  per `delegates.advisories.lockfile_scanner`) with native advisory ignores
  neutralised, then computes a Barbican-owned verdict rather than inheriting
  scanner exit codes
- reconciliation-driven: every enumerated finding is reconciled against
  reviewed advisory exceptions in `reviewed-targets.toml`; unreviewed and
  expired findings fail, accepted exceptions are rendered visibly
- native-tool compatible: a native ignore is classified as governed only when
  every current occurrence is accepted by active Barbican governance; adding
  a native ignore cannot turn a Barbican failure into a pass
- machine-consumable: `--format json` emits a stable `schema_version`ed
  report whose fields and value sets are defined in the CLI output-stability
  contract
- remediation-oriented: failing findings with patched releases carry the
  shortest workspace-member dependency path and a conservative read-only
  remediation hint that never suggests moving an exact `=` pin with a
  lockfile-only update; a manifest requirement classifies a finding as
  direct only when it can admit the finding's resolved version
- blocker-precise where provable: requirement edges from cargo metadata
  across all resolved parents feed an exact semver-interval overlap
  analysis, so transitive findings either name the provable blocking
  parents with their requirements, prove the vulnerable crate can move with
  a lockfile-only update, or keep the conservative hedge when any edge is
  indeterminate — precise claims come only from decidable interval proofs
- explicit about degraded enrichment: dependency-path and remediation
  context failures produce stderr notes (and the JSON
  `dependency_paths_available` flag) while the report and
  advisory-disposition verdict still render; enumeration completeness
  failures and scanner errors remain blocking
- paired with a governed acceptance path: each unreviewed RustSec finding
  carries a pointer to `cargo barbican pin exception`, the offline
  scaffolder that composes a checksum-bound reviewed family with bounded
  `allowed_advisories` entries and a review-record stub, so the governed
  exception is as easy as a native `deny.toml` ignore without being
  ungoverned

The reviewed-target enforcement baseline is:

- repo-root `reviewed-targets.toml` is the machine-enforced source of truth
- checked-in Markdown review records remain the human explanation and evidence
  surface
- each active `[[rust.families]]` entry carries:
  - `name`
  - `review_record`
  - optional `direct` exact manifest requirements, including the leading `=`
  - `resolved` exact `Cargo.lock` versions
  - optional `allowed_surfaces` reviewed execution-surface allowances for
    crates already present in the same `resolved` map
- `pin check` validates that every active `review_record` path actually exists
  before the family declaration is trusted
- `pin check` checks exact resolved `Cargo.lock` parity plus any configured
  exact direct manifest requirements
- `pin check` validates `allowed_surfaces` manifest integrity, but does not
  inspect live metadata surfaces
- `inventory` reports live metadata surfaces and cross-references them against
  `allowed_surfaces`, but does not enforce the result
- `assess` suppresses matching reviewed `build-rs`, `proc-macro`, and
  `native-sys` execution-surface signals from elevated-risk findings, while
  rendering them in `Allowed policy exceptions:`
- `assess` validates the matching family `review_record` is completed before trusting
  an applicable allowance
- review-record checks require a regular non-symlink, non-empty file without
  the scaffold pending marker; they do not authenticate the review content, so
  reviewers must inspect reviewed-target changes and their cited records together
- release-age-aware commands honour matching `allowed_age_exceptions` from the
  same reviewed family only when the referenced `resolved` target carries
  `checksum_sha256` and the family `review_record` is completed
- `age`, `age-lock`, `resolve`, `update`, and `assess` compare that reviewed
  digest against crates.io's published checksum metadata; `inspect` and
  `gatehouse candidate` also verify downloaded tarball bytes through the
  inspect path
- applied release-age exceptions are rendered visibly as allowed policy
  exceptions; yanked releases and exception artefact checksum mismatches remain
  blocking
- `verify` reuses that same default reviewed-target gate before executing
  `cargo build --locked` and `cargo test --locked`

For crates.io reviewed families, `resolved` can use a structured artefact form:

```toml
[rust.families.resolved]
serde = { version = "1.0.228", checksum_sha256 = "..." }
serde_derive = { version = "1.0.228", checksum_sha256 = "..." }
```

Contract notes:

- the existing exact-string form remains acceptable for compatibility
- the structured form is the intended path for crates.io reviewed families
- `checksum_sha256` is the reviewed `.crate` tarball digest, expected to match
  both crates.io metadata and the resolved `Cargo.lock` checksum chain
- `pin check` remains read-only and local-only; it does not fetch from the
  network during enforcement
- when a structured `checksum_sha256` is present, `pin check` fails closed on
  checksum drift even if the resolved version still matches
- inventory coverage is version-level: a resolved crate is considered covered
  when its name and version appear in a reviewed family; checksum drift remains
  the `pin check` / `verify` gate
- inventory treats review-record backing as a separate policy signal: a
  resolved crate can be version-covered by a family whose review record is
  missing, and that missing record is reported as its own gap
- `allowed_surfaces` accepts exactly `build-rs`, `proc-macro`, and
  `native-sys`; unknown identifiers, empty lists, and crates absent from the
  same family `resolved` map fail closed
- `allowed_age_exceptions` accepts exact version strings for crates already
  present in the same family `resolved` map; the referenced target must use the
  structured `checksum_sha256` form, and the exception version must match the
  resolved version exactly
- `review_record` paths must be relative repo paths with no `..` traversal
- the current implementation does not claim stronger installed-tree or broader
  non-crates.io artefact parity beyond this gate
