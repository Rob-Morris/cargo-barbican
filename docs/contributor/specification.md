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

Read the matching undertask sources before redesigning behaviour:

- `scripts/check-crate-release-age.py`
- `scripts/check-cargo-lock-release-age.py`
- `scripts/select-cargo-package-id.py`
- `scripts/deps-rust-routine-update.sh`
- `docs/dependency-management.md`
- `deny.toml`
- `docs/dependency-reviews/`

The reference repo is
[undertask](https://github.com/rob-morris/undertask). It is a working reference,
not the specification: re-implement its proven behaviour faithfully where
surfaces overlap, and expect cargo-barbican to extend beyond it as a policy
product. Document both deviations and extensions explicitly.

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

`ureq` is preferred over a heavier HTTP stack because the surface is small and
blocking I/O is acceptable at the CLI boundary.

## Constraints

- No new dependencies without a review record.
- No second HTTP client. Replace `ureq` if necessary; do not add a peer.
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

`[release_age].minimum_days` is active for `age`, `age-lock`, `resolve`,
`assess`, and `inspect`.

The current baseline rules for comparative commands are:

- `age-lock` defaults to `--base-ref HEAD` and also accepts
  `--base-lockfile <path>` as an explicit non-git baseline
- `assess` defaults to `--base-ref HEAD` and also accepts
  `--base-dir <path>` as an explicit non-git dependency-state baseline
- `review` keeps the existing git-backed default path and also accepts
  `--base-dir <path>` as an explicit non-git review baseline
- `resolve` no longer depends on `HEAD`; it rechecks against an internal
  pre-update `Cargo.lock` snapshot
- `resolve` also supports `--dry-run`, which executes the targeted update in an
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
  `resolve`, `assess`, `review`, `pin-check`, and `verify`

`cargo barbican policy init` is currently:

- the deterministic setup command for explicit repo policy scaffolding
- non-interactive and non-certifying: it does not review existing dependencies
  or generate active reviewed families
- template-backed: it writes the shipped `barbican.toml`,
  `reviewed-targets.toml`, and dependency-review README templates when absent
- conservative with existing files: regular files are preserved, existing
  `barbican.toml` is validated, and symlinks or wrong-type scaffold paths fail
  closed
- adoption-guidance oriented: successful output points operators to the manual
  adoption guide before `pin-check` / `verify`

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
- `pin-check` validates that every active `review_record` path actually exists
  before the family declaration is trusted
- `pin-check` checks exact resolved `Cargo.lock` parity plus any configured
  exact direct manifest requirements
- `pin-check` validates `allowed_surfaces` manifest integrity, but does not
  inspect live metadata surfaces
- `assess` suppresses matching reviewed `build-rs`, `proc-macro`, and
  `native-sys` execution-surface signals from elevated-risk findings, while
  rendering them in `Allowed policy exceptions:`
- `assess` validates the matching family `review_record` exists before trusting
  an applicable allowance
- review-record checks validate a non-symlink file exists at the configured
  path; they do not authenticate or parse the record content, so reviewers must
  inspect reviewed-target changes and their cited records together
- release-age-aware commands honour matching `allowed_age_exceptions` from the
  same reviewed family only when the referenced `resolved` target carries
  `checksum_sha256` and the family `review_record` exists
- `age`, `age-lock`, `resolve`, and `assess` compare that reviewed digest
  against crates.io's published checksum metadata; `inspect` and `gatehouse
  candidate` also verify downloaded tarball bytes through the inspect path
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
- `pin-check` remains read-only and local-only; it does not fetch from the
  network during enforcement
- when a structured `checksum_sha256` is present, `pin-check` fails closed on
  checksum drift even if the resolved version still matches
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
