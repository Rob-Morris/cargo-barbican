# Integration

How a consumer repo adopts cargo-barbican.

> The core Rust reviewed-target flow now exists end-to-end.

## Prerequisites

Install a rustup-managed Rust environment with `rustup`, `cargo`, `rustc` and
`rustdoc` on PATH. `cargo install --git ... --locked` compiles Barbican and its
locked dependencies from source; allow build time and disk space for that
bootstrap. Choose/preinstall the consumer's exact compiler separately.

Review the release, source, build options and install identity of each tool,
including Barbican itself, before installing it. Tool-install records are
separate from graph-family records. First-principles review is the default;
inherit only matching, explicitly trusted prior evidence.

Install only what `[delegates]` in `barbican.toml` selects. For the default
cargo-deny scanner/checks:

```bash
cargo install --locked cargo-deny@0.19.6
```

When cargo-audit is selected as scanner (or both scanners are selected):

```bash
cargo install --locked cargo-audit@0.22.1
```

Cargo-deny is also needed when its non-advisory check groups are configured.
These are this release's reviewed examples; an adopter owns its tool trust
choices. Optional nextest has its own setup below; the advisory hook requires
none of these scanners or a hook framework.

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

Follow [Adoption](adoption.md) for the ordered new/existing project journey.
Install this release using its immutable identity:

```bash
cargo install --locked --git https://github.com/Rob-Morris/cargo-barbican --tag v0.35.0 cargo-barbican
```

Init preserves regular policy/process/template files and completed records.
Optional hook copying and CI generation remain separate choices. See
[CI](ci.md) for activation, required checks and scheduled audit.

## Manual template adoption

From any consumer repository, obtain the source matching the installed
release into a scratch area. This does not assume an upstream checkout:

```sh
barbican_source=$(mktemp -d)
git clone --depth 1 --branch v0.35.0 \
  https://github.com/Rob-Morris/cargo-barbican "$barbican_source/upstream"
# Review templates in "$barbican_source/upstream/templates" before copying.
```

Create the missing files only: `barbican.toml`, `deny.toml`,
`reviewed-targets.toml`, `docs/dependency-reviews/README.md`, and
`docs/dependency-reviews/record-template.md` from the corresponding template
paths. Use exclusive creation (for example shell `set -C` plus redirection)
for an absent destination. Compare any existing files and merge desired changes
manually. Never copy over local policy, completed records or custom process.
The shipped deny template includes `[advisories]`; Barbican forces disclosure
and neutralises native ignores at runtime. Choose `rust-toolchain.toml`
explicitly; templates cannot decide a compiler for the consumer.

The independent [manual hook recipe](ci.md#pre-commit-hook) uses this same
matching-tag scratch checkout. Remove the scratch directory after reviewing
and copying desired files.

## Versioning and re-sync

Every shipped template carries `Synced from cargo-barbican v0.35.0` provenance.
The process README and record template are consumer-owned and may be tailored.
On upgrade, install the reviewed immutable release, obtain its templates in a
scratch checkout as above, and review diffs before merging desired changes.
Rerun init to add missing outputs; it preserves existing regular files and
modes, so presence is not a claim of completeness or current upstream parity.
Update the tool-install review with the actual version/build decision. Existing
completed dependency reviews are not invalidated by a template upgrade.

Generated documentation references use the compiled package version's tag.
They are navigation, not binary attestation. An unpublished ordinary-version
candidate may have no tag yet: use those paths in its matching local source
checkout. A prerelease prints a labelled development/main link which may
differ from the build. There is no runtime URL probe or silent fallback, and
release install/CI pins remain immutable.

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
