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

## Consumer flow

1. Install:

   ```bash
   cargo install --locked --git https://github.com/Rob-Morris/cargo-barbican --tag v0.26.0
   ```

2. Create the policy scaffold in the consumer repo:

   ```bash
   cargo barbican policy init
   ```

   This creates the policy files that exist in the current template set:
   `barbican.toml`, `deny.toml`, `reviewed-targets.toml`, and
   `docs/dependency-reviews/README.md`. It preserves existing regular files,
   reports issues, and does not review or certify existing dependencies.

   `cargo barbican policy init --ci github` additionally emits a ready-to-run
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

   `gatehouse pre-release` first enforces the direct-dependency inventory
   coverage floor, then runs `audit` and `verify`; `verify` reuses the default
   `pin check` gate before locked build/test execution. `audit` and `verify` stay
   separate commands: `verify`'s verdict is a deterministic function of the
   repo, while `audit`'s verdict also depends on the advisory landscape at run
   time, so the two are scheduled differently in CI — see
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
# Synced from cargo-barbican v0.26.0
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
