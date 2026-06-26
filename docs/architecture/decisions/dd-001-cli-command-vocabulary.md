# DD-001: CLI Command Vocabulary For Resolution, Lockfile Generation, And Updates

## Context

cargo-barbican's mission is to be one gate for what enters a repo's dependency
graph. Two friction points observed while an external agent adopted a new
dependency (`portable-pty`) through a pinned barbican copy show the current
command surface ceding the front of that funnel:

1. The agent dropped to raw `cargo info` to discover the latest version,
   because every barbican candidate command (`age`, `inspect`,
   `gatehouse candidate`, today's `resolve`) requires an exact `crate@version`
   and barbican has no version-discovery affordance. Forming the spec required
   leaving the gate.
2. The agent dropped to raw `cargo generate-lockfile` to materialise
   `Cargo.lock` after editing `Cargo.toml` to add the new dependency, because
   today's `resolve` only re-pins an *already-locked* dependency
   (`cargo update --workspace -p <id> --precise <version>`) and there is no
   barbican command that resolves the whole graph from the manifests.

Separately, the existing `resolve` command is mis-named. In dependency-tooling
vocabulary, "resolution" is the resolver turning manifest constraints into a
concrete locked graph. The command does not do that — it performs a targeted
re-pin of one dependency already in the graph. It borrows the resolver's word
for what Cargo itself calls `update`.

cargo-barbican is pre-release. There are no external consumers; the only
installed copy is a local pinned checkout under our control, with no shipped
muscle memory to protect. The backwards-compatibility override in the design
calibration does not fire, so a clean rename is available at its cheapest
moment.

## Decision

Adopt a three-verb vocabulary that mirrors Cargo's own conceptual split and
closes both holes. Each verb names exactly one operation; no word means two
things.

| Command | Operation | Cargo analogue | Mutates |
| --- | --- | --- | --- |
| `pick` *(new)* | constraint/range → one concrete version, policy-aware | resolver query | no |
| `resolve` *(new meaning; word reclaimed)* | current manifests → (re)write `Cargo.lock` under policy | `cargo generate-lockfile` | yes |
| `update` *(renamed from `resolve`)* | re-pin one existing locked dependency to an exact version | `cargo update -p --precise` | yes |

- **`pick`** is read-only discovery. Given a range or bare crate name, it
  returns the single version barbican would pin: the newest match that is
  non-yanked and satisfies the release-age gate, which may not be the absolute
  latest. Output is an exact `crate@version` line plus age/yank annotations. It
  feeds `inspect` / `gatehouse candidate`; it neither assesses nor mutates. The
  read (choose a version) and the gate (assess an exact version) stay separate
  and composable.
- **`resolve`** (reclaimed) owns whole-graph lockfile resolution. It wraps
  `cargo generate-lockfile`, applies the release-age gate to newly selected
  crates.io versions, and fails closed rather than leaving a too-fresh
  selection on disk. It is the mutating counterpart to `age-lock` (the read
  that audits new lockfile selections) and the missing middle of the adoption
  flow: edit manifest → `resolve` → review record → reviewed-targets entry.
- **`update`** is today's targeted re-pin command, renamed. Behaviour is
  unchanged.

A related grammar decision keeps the CLI spec surface coherent: barbican
candidate specs accept an optional leading `=` (`crate@=1.2.3` ≡
`crate@1.2.3`). In a CLI version literal, `=1.2.3` unambiguously means exactly
1.2.3, and `=` is the exact-pin idiom users carry over from Cargo manifests and
barbican's own `reviewed-targets.toml`. The manifest-requirement parser
(`parse_exact_version_requirement`) continues to *require* `=`, because in a
Cargo requirement expression bare `1.2.3` means `^1.2.3` (a range). The two
parsers serve different grammars and both remain individually correct; only the
CLI literal grammar gains tolerance.

## Alternatives Considered

- **Keep `resolve` as the re-pin command; name the new discovery command
  `resolve-version`.** Rejected. `resolve` / `resolve-version` differ by a
  suffix but are opposite in kind (mutate vs read) — a reader-hostile
  near-collision. It also leaves the re-pin command mis-named.
- **Give `resolve` to the new read (discovery) command; rename re-pin →
  `update`.** Rejected. "Resolve" is the most load-bearing mutation verb in the
  domain — the resolver writes the lock. Spending it on a read while the actual
  whole-graph lockfile mutation (the operation the agent hand-rolled with
  `cargo generate-lockfile`) stays nameless wastes the best name on the wrong
  operation.
- **Accept ranges directly on the existing candidate commands, collapsing to a
  version internally.** Rejected. It makes the gate's input time- and
  registry-state-dependent (same command, different day, different assessed
  version), fights the deliberate-pin and release-age discipline, and pulls
  semver range resolution into every candidate command. Discovery and the gate
  stay as separate, composable commands instead.
- **Defer; rely on raw `cargo info` / `cargo generate-lockfile`.** Rejected.
  That is the status quo that produced the friction and cedes the front of the
  funnel — the exact thing barbican exists to own.

## Consequences

- Three honest verbs that mirror Cargo (`generate-lockfile` ≙ `resolve`,
  `update --precise` ≙ `update`) and read unambiguously.
- **`pick` requires new capability.** A library function to select a version
  from a range, plus a `CratesIoClient` method to list a crate's published
  versions (with a pure response parser in the library and the concrete HTTP in
  the binary). Range matching uses the `semver` crate (decided) — a new
  direct dependency. Per the repo invariants this is a hard stop: a
  first-principles dependency-review record under `docs/dependency-reviews/`
  must be written, and a `reviewed-targets.toml` entry added, *before* the
  dependency lands. This is a gating prerequisite for `pick`, not an
  afterthought.
- **New `resolve` adds barbican-owned lockfile mutation.** The dogfooding rule
  (run mutating commands via the built binary, not `cargo run --locked`)
  applies, exactly as it does for today's `resolve` (now `update`).
- **The rename and additions change the subcommand surface**, a route-map hard
  stop. This DD is the recorded, user-directed approval for that change. It
  touches `docs/functional/cli.md`, `docs/user/commands.md`,
  `docs/architecture/overview.md`, the `docs/contributor/agents.md`
  current-state list, `docs/contributor/process.md` (the `resolve` invocation
  example), and the changelog/version bundle.
- **Future direction (out of scope here).** A `gatehouse adopt <crate@version>`
  workflow could orchestrate manifest pin → `resolve` → a drafted review record
  (pre-filled from the candidate dossier, carrying the checksum already
  computed during inspection) → reviewed-targets entry, leaving a human to
  approve and run `pin-check` / `verify`. The new `resolve` is the reusable,
  policy-gated mutation beneath such a workflow. Recorded as motivation; not
  part of this decision.
