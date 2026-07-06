# DD-003: The `pin` Command Namespace

DD-002 is reserved for the in-flight IOC-as-gated-surface design.

## Context

The post-adoption hardening batch added an offline reviewed-family scaffolder.
Its natural name, `pin add`, introduced a `pin` subcommand namespace beside the
existing flat `pin-check` command. That left the reviewed-target surface split
across two grammars: `pin add` (namespaced verb) and `pin-check` (hyphenated
compound), even though both operate on the same policy object — the pinned
reviewed-target set in `reviewed-targets.toml`.

DD-001 established the calibration for renames: cargo-barbican is pre-release,
the only installed copies are local pinned checkouts under our control, and
there is no shipped muscle memory to protect. A clean rename remains available
at its cheapest moment.

## Decision

Adopt `pin` as the command namespace for reviewed-target pin operations, with
the maintainer's direction:

| Command | Operation | Mutates |
| --- | --- | --- |
| `pin add <crate>[@version]` | scaffold a reviewed family + review-record stub from `Cargo.lock` | yes |
| `pin check [--config …]` | enforce active reviewed families against manifests and `Cargo.lock` | no |

`pin-check` is renamed to `pin check` with no compatibility alias. Behaviour,
flags, output tokens (`Pin check: PASS` / `Pin check: FAIL`), and the
skip-on-absent / skip-on-empty diagnostic semantics are unchanged; only the
invocation grammar moves.

`verify` continues to reuse the same enforcement seam internally and is not
renamed: it is an execution gate over multiple steps, not a pin operation.

## Alternatives Considered

- **Keep `pin-check` beside `pin add`.** Rejected. Two grammars for one policy
  object is reader-hostile, and every future pin operation would deepen the
  fork. The asymmetry was flagged during implementation review and the
  maintainer chose the rename.
- **`pin-add` (flat, hyphenated).** Rejected. It preserves symmetry with the
  old name by doubling down on the compound grammar, and reads worse as the
  namespace grows (`pin-add`, `pin-check`, `pin-remove`, …). A namespace keeps
  each verb one word.
- **A compatibility alias for `pin-check`.** Rejected under DD-001's
  calibration: pre-release, no external consumers, and an alias would ship the
  confusion this decision removes.

## Consequences

- The subcommand surface changes, a route-map hard stop; this DD records the
  user-directed approval, exactly as DD-001 did for the `pick`/`resolve`/
  `update` vocabulary.
- All command references move to `pin check` in the living docs
  (`docs/functional/cli.md`, `docs/user/commands.md`, `docs/user/adoption.md`,
  `docs/user/integration.md`, `docs/contributor/*`,
  `docs/architecture/overview.md`, README, shipped templates) and in tool
  output that names the command. Historical records (changelogs, dated
  dependency reviews, DD-001) keep the names that were true when written.
- Future pin operations (for example a `pin remove` or `pin refresh`) have an
  obvious home and grammar.
