# Integration

How a consumer repo adopts cargo-barbican.

> The core Rust reviewed-target flow now exists end-to-end.

## Prerequisites

`cargo barbican audit` delegates to `cargo-deny` and (depending on
`[delegates]` in `barbican.toml`) `cargo-audit`. Install both with a pinned,
`--locked` install before relying on `audit`, following the same
review-then-pin dogma cargo-barbican asks of its own dependents:

```bash
cargo install --locked cargo-deny@0.19.6 cargo-audit@0.22.1
```

Review each tool's own release before pinning it, the same way you would
review any other dependency. Both tools are also the first review records a
consumer repo typically writes — see the manual onboarding guide
([adoption.md](adoption.md)) and step 3 below.

If a required delegate is missing from `PATH`, `cargo barbican audit` detects
this before delegating and fails closed, naming the tool and the exact install
command — for example `FAIL cargo-deny: not found on PATH; install with
cargo install --locked cargo-deny@0.19.6` — then exits non-zero rather than silently
skipping the check. `cargo-audit` is only required when it is the configured
lockfile scanner, so a `cargo-deny`-only setup does not force it to be
installed. If a delegate is installed but its run fails, `audit` surfaces the
delegate's exit status and a stderr excerpt instead of a confusing JSON-parse
error.

## Optional nextest runner

To use process-isolated tests, first review and install the consumer's exact
cargo-nextest version, then set both `[verify] test_runner = "nextest"` and
`nextest_version` in `barbican.toml`. Keep the tool's install feature set in
its review record and bootstrap. For Barbican's reviewed test-tool example:

```bash
cargo install --locked --no-default-features cargo-nextest@0.9.146
```

A version check does not prove binary provenance. Gate-time verification never
installs or updates tools. Check custom-harness compatibility, shared resources
and default-member doctest policy before switching. See
[configuration](configuration.md#verify) for the mixed-doctest restriction.
Generated scaffolds retain cargo-test; add the reviewed nextest bootstrap to an
existing CI workflow explicitly when opting in.

## Policy checks without build/test

Run fresh policy independently of expensive Rust execution:

```bash
cargo barbican gatehouse policy-check
```

This checks toolchain conformance, direct inventory coverage, audit and strict
reviewed pins, including completed records and exact Git identities. It requires
an active reviewed family, even where standalone `pin check` would skip. Valid
selected-runner configuration still applies, but this route does not require
nextest installed. Actual `verify` still checks and executes its selected runner.

A consumer may then run `cargo barbican verify`, or reuse independently valid
locked verification results. That reuse must bind Rust sources, resources and
fixtures, toolchain, dependencies, configuration and the pinned Barbican binary.
Policy PASS does not certify cached artefacts. Rerun policy for current advisory
and exception decisions; no stored PASS or cache protocol is supplied here.
Scratch, tool caches and advisory databases may update; workspace manifests,
lockfile and review policy remain unchanged. This is not an executable sandbox.

`gatehouse pre-release` remains the full release gate and generated CI default.
See [the command contract](../functional/cli.md) for exact scope and tokens.

## Consumer flow

1. Install:

   ```bash
   cargo install --locked --git https://github.com/Rob-Morris/cargo-barbican --tag v0.34.0
   ```

2. Create the policy scaffold in the consumer repo:

   ```bash
   cargo barbican policy init --toolchain 1.95.0
   ```

   Choose the exact channel for the consumer repo; the example is not a
   universal recommendation. This creates `rust-toolchain.toml` from that
   explicit choice with rustup's `minimal` profile (reported in the action
   output), plus the policy files in the current template set:
   `barbican.toml`, `deny.toml`, `reviewed-targets.toml`, and
   `docs/dependency-reviews/README.md`. It preserves existing regular files,
   reports issues, and does not review or certify existing dependencies.

   `cargo barbican policy init --toolchain 1.95.0 --ci github` additionally emits a ready-to-run
   `.github/workflows/barbican.yml` enforcement gate (it fails closed rather
   than overwriting an existing workflow at that path) and points at the shipped
   client-side pre-commit hook. See [ci.md](ci.md) for both.

   If you need to adopt manually, check out the same cargo-barbican branch, then
   copy the available templates:

   ```bash
   git clone https://github.com/Rob-Morris/cargo-barbican /tmp/cargo-barbican
   cd /tmp/cargo-barbican
   git checkout main

   cp templates/barbican.toml /path/to/consumer/barbican.toml
   cp templates/deny.toml /path/to/consumer/deny.toml
   cp templates/reviewed-targets.toml /path/to/consumer/reviewed-targets.toml
   mkdir -p /path/to/consumer/docs/dependency-reviews
   cp templates/dependency-reviews/README.md /path/to/consumer/docs/dependency-reviews/README.md
   ```

   If the consumer repo already has a `deny.toml`, keep it and review the
   shipped template manually. `policy init` creates `deny.toml` only when it is
   absent. The template carries bans/sources posture only; Barbican forces
   `[advisories]` at runtime during `audit`.

3. Follow the manual onboarding guide:

   - [adoption.md](adoption.md)

   A new project without `Cargo.lock` starts with the
   [first-lockfile recipe](adoption.md#starting-a-new-project): policy/toolchain
   setup, `resolve`, inventory and review scaffolds, completed human review,
   then the pre-release gate. Resolution does not approve the graph or invent a
   historical comparison baseline.

   In short, write the first inherited review records:
   - `cargo-barbican` itself, as the tool install
   - `cargo-audit` and `cargo-deny`, as prerequisite tooling

   Then add active reviewed families to `reviewed-targets.toml` only for
   dependencies that have been deliberately reviewed. The template starts as
   scaffolding; it does not certify the existing dependency graph by itself.

4. Run the smoke checks:

   ```bash
   cargo barbican gatehouse pre-release
   ```

   `gatehouse pre-release` first proves exact toolchain conformance, enforces
   the direct-dependency inventory coverage floor, then runs `audit` and
   `verify`; `verify` reuses the default `pin check` gate before locked
   build/test execution. `audit` and `verify` stay separate commands because
   audit also depends on the changing advisory landscape, so scheduled audit
   runs remain necessary — see
   [ci.md](ci.md). The reviewed-target gate also
   expects each active family to point at a real checked-in review record. For
   crates.io reviewed families, prefer the structured `resolved` form in
   `reviewed-targets.toml` so `pin check` can verify both the reviewed version
   and the reviewed tarball `checksum_sha256` against `Cargo.lock`.
   Intentional too-fresh exceptions can be recorded under
   `allowed_age_exceptions`, but only for exact crates already present in the
   same family `resolved` map with `checksum_sha256`.
   Reviewed advisory findings can be recorded under `allowed_advisories` with
   the `RUSTSEC-*` id and a `review_by` re-review deadline; `audit` accepts
   them only while the bound resolved target, checksum, review record, and
   deadline still hold. Configure `[delegates]` in `barbican.toml` to choose
   the advisory scanner and delegated `cargo-deny` checks.

5. Update the consumer repo's `AGENTS.md` so dependency-gate instructions
   point at `cargo barbican` instead of a manual process.

6. Wire the gates into CI. `cargo barbican policy init --ci github` emits a
   ready-to-run `.github/workflows/barbican.yml` gate, and the shipped
   `templates/hooks/pre-commit` hook (`pin check` + `inventory --enforce`)
   installs via `git config core.hooksPath` or a copy into
   `.git/hooks/pre-commit` for fast local feedback. See [ci.md](ci.md) for the
   worked GitHub Actions example, which gates belong on pull requests versus
   scheduled runs, and the hook install instructions.

## Versioning and re-sync

During the insiders window, consumers install from the immutable release tag.
Template files still include a synced version header so copied policy
files can be compared against the cargo-barbican repo version they came from.
Only the version line is common to every template; the review-record template
is the strictest, telling you not to edit the copy directly:

```text
# Synced from cargo-barbican v0.34.0
# Edit upstream and re-sync; do not edit this file directly.
```

The policy files you are meant to tailor — `barbican.toml` and
`reviewed-targets.toml` — instead carry a header inviting local edits after
copying.

When cargo-barbican releases a new version, the consumer:

1. Re-runs the copy step from the updated immutable tag.
2. Reviews the diff.
3. Updates the tool-install review record to cite the new version.

There is no automatic sync mechanism today. Re-sync is deliberate and reviewed.

## Exact Git sources

Exact reviewed Git dependencies use the existing `pin add` / `pin check`,
inventory, audit and verification workflow. See the
[Git source guide](git-sources.md) for the tagged policy
schema, full-commit requirement, per-package review, source-bound allowances,
manual intake and advisory/build-input limitations. Registry age/advisory
exceptions never authorise Git targets; cargo-deny permission remains separate.


### Migrating PR evidence after gate failure

Upgrade to v0.33.0 or later before adding `toolchain check` to a consumer workflow.
Generate the intended workflow in a disposable consumer directory, or use
`policy init --ci github`'s existing-file refusal/reprint; it never overwrites
your workflow. Review the complete gate job in [CI](ci.md), preserving custom
steps, reviewed pins, permissions and the separate scheduled audit.

Replace the old combined `Age-lock and assess` step with both independent steps
and their complete readiness predicates. Include setup IDs, fresh post-gate
conformance, exact-base availability and the outcome summary. Copying only
`!cancelled()` is insufficient: it would allow evidence after unusable setup or
rejected executable controls. Keep the authoritative gate and every evidence
command blocking. Branch protection remains operator-owned.
