# Adopting Cargo-Barbican

This guide is for an existing Rust repository adopting cargo-barbican as a
dependency policy gate.

`cargo barbican policy init` creates policy scaffolding. It does not review,
approve, or certify the dependencies already in the repository.

## 1. Create The Policy Scaffold

From the consumer repository root:

```bash
cargo barbican policy init
```

The command creates missing scaffold files:

- `barbican.toml`
- `reviewed-targets.toml`
- `docs/dependency-reviews/`
- `docs/dependency-reviews/README.md`

Scaffold items are created independently in dependency order. For example,
dependency-review docs may still be created while a malformed existing
`reviewed-targets.toml` is reported as blocked.

Existing regular files are preserved. Wrong-type scaffold paths, including
symlinks at scaffold locations or existing scaffold ancestors, fail closed and
must be resolved manually.

For Windows, see the project-level
[Platform Support](../architecture/overview.md#platform-support) posture before
relying on scaffold path-containment guarantees.

Review `barbican.toml` before enforcing the policy. It is explicit repo policy,
not hidden runtime default state.

## 2. Review Current Dependencies

Treat the existing dependency graph as inventory to review, not as already
trusted state.

For each dependency family you want to bring under reviewed-target policy:

1. Identify the direct manifest requirement and resolved `Cargo.lock` version.
2. Confirm the crates.io checksum from `Cargo.lock` for registry artefacts.
3. Review relevant risk signals, including release age, source, build scripts,
   proc macros, native linking, and advisory status.
4. Write a checked-in review record under `docs/dependency-reviews/`.
5. Add the reviewed family to `reviewed-targets.toml`.

Use structured crates.io `resolved` entries with `checksum_sha256` wherever
possible so `pin-check` can reconcile the reviewed artefact against
`Cargo.lock`.

## 3. Check Reviewed-Target Policy

After adding reviewed families and records:

```bash
cargo barbican pin-check
```

`pin-check` is local-only and read-only. It verifies that active reviewed
families point at real review records and match the current manifests and
`Cargo.lock`.

## 4. Run The Enforcement Gate

When reviewed-target policy is ready:

```bash
cargo barbican verify
```

`verify` fails closed when `reviewed-targets.toml` is absent or not a regular
file. It runs the reviewed-target gate before locked build/test verification.

## Manual Template Adoption

If `policy init` is not available, copy the templates from the pinned
cargo-barbican version instead. Review the copied files before committing them.

```bash
cp templates/barbican.toml /path/to/consumer/barbican.toml
cp templates/reviewed-targets.toml /path/to/consumer/reviewed-targets.toml
mkdir -p /path/to/consumer/docs/dependency-reviews
cp templates/dependency-reviews/README.md /path/to/consumer/docs/dependency-reviews/README.md
```
