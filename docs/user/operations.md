# Operations

Day-2 operations for a repo that has already adopted cargo-barbican: what to
do when `audit` fails, how to run routine updates, how reviewed families live
and retire, how to upgrade cargo-barbican itself, and how to grow coverage on
a large existing project.

This guide assumes the adoption steps in [adoption.md](adoption.md) are done
and the gates from [integration.md](integration.md) are wired in. Command
syntax and per-command reference live in [commands.md](commands.md); the exact
behaviour contract is [../functional/cli.md](../functional/cli.md).

## When `audit` Fails

`audit`'s verdict depends on the advisory landscape at the moment it runs, so
a new RustSec advisory can flip it from PASS to FAIL with no repo change at
all. A failing `audit` is routine operations, not an emergency signal that the
repo regressed.

### 1. Read the finding's remediation hint

Each unreviewed or expired finding with patched-version ranges carries a
read-only remediation hint. The hint classifies the fix:

- **Direct, non-exact requirement** — the vulnerable crate is a direct
  dependency whose manifest requirement can admit a patched version. The hint
  gives a `cargo barbican update <crate>@<version>` template plus a pointer to
  `pick` for selecting a patched release.
- **Direct, exact `=` pin** — a lockfile-only update cannot move an exact
  pin, so the hint reports a manifest edit: raise the `=` requirement in
  `Cargo.toml` yourself, then run `cargo barbican resolve`.
- **Transitive, provably uncapped** — no resolved parent's declared
  requirement excludes the patched range, so the vulnerable crate itself can
  move with a lockfile-only `cargo barbican update`.
- **Transitive, provably capped** — one or more parents' declared
  requirements exclude every patched version. The hint names each blocking
  parent and its requirement, for example
  `capped by plist@1.9.0 (requires ^0.39)`, and directs the fix at the
  blocker: a manifest edit when the blocker is exact-pinned, an `update` of
  the blocker otherwise. Bumping the vulnerable crate directly cannot work
  until the blocker moves.
- **Indeterminate** — when the requirement-edge analysis cannot decide
  (pre-release comparators, unparseable requirements, missing metadata), the
  hint keeps a conservative nearest-parent suggestion rather than guessing.

In `--format json` output these appear as the stable remediation kinds
`direct-pinned-edit`, `direct-update`, `transitive-update`, and
`transitive-bump`, with `blockers` listing each capping parent. See the
[CLI contract](../functional/cli.md) for the full schema.

Hints are best-effort enrichment and never mutate the repo. Verify every hint
with a dry run before applying it.

### 2. Preview, then apply

```bash
cargo barbican update --dry-run vulnerable-crate@1.2.4
cargo barbican update vulnerable-crate@1.2.4
```

The dry run performs the update in a temporary workspace and prints a lockfile
diff preview; check that the diff moves only what you expect. `update` runs
the release-age gate on the requested version and rechecks newly selected
crates.io versions afterwards, so a patched release published within the
minimum-age window fails the update. When the fix is urgent enough to accept a
too-fresh release, record a reviewed release-age exception under the family's
`allowed_age_exceptions` as described in
[adoption.md](adoption.md#2-review-current-dependencies) — do not lower the
global age policy for one incident.

### 3. Re-pin the affected reviewed family

If the updated crate is covered by an active reviewed family, `pin check` now
fails by design: the lockfile moved away from the exact version and checksum
the family recorded. Treat the bump as a re-review of that family:

1. Read the new resolved version and `checksum` from `Cargo.lock`.
2. Update the family's `resolved` entry (and `direct` entry, if the crate is
   an exact-pinned direct dependency) in `reviewed-targets.toml`.
3. Update the family's review record — see
   [Reviewed-Family Lifecycle](#reviewed-family-lifecycle) for what a
   mechanical re-pin needs versus a genuine re-review.

`pin add` cannot do this for you: it fails closed when the crate is already
covered by an existing family. Re-pinning an existing family is a deliberate
manual edit.

### 4. Close the loop

```bash
cargo barbican gatehouse pre-release
```

`audit` should now report the finding resolved; `verify` confirms the repo
still builds and tests under the re-pinned policy.

### When no patched release is adoptable

Sometimes there is no patched release, or the patched range is capped by a
parent you cannot move yet, or the advisory is informational and accepted
risk. The governed path is a reviewed advisory exception:

```bash
cargo barbican pin exception vulnerable-crate@1.2.3 RUSTSEC-2026-0001
```

`pin exception` scaffolds a checksum-bound acceptance: a family stub (when the
crate is not yet covered) plus an `allowed_advisories` entry binding the
advisory to the exact resolved crate, with a `review_by` re-review deadline —
30 days from today by default, overridable with `--review-by YYYY-MM-DD`.
Complete the review-record stub before treating the exception as active;
`audit` honours it only while the resolved version and checksum still match,
the review record is completed, and the deadline has not passed. Once `review_by`
expires, `audit` fails the exception again and forces a re-decision.

When the crate is already covered by an active family, the command refuses to
rewrite the existing family block and instead prints the exact
`allowed_advisories` fragment to add manually, plus the review record to
update.

Never reach for a native `deny.toml` or `.cargo/audit.toml` ignore instead.
`audit` neutralises native advisory ignores regardless of configuration — it
generates a max-disclosure runtime `cargo-deny` config and reports the ignores
according to `delegates.unmanaged_delegated_policy`, failing them outright
under `deny`. An ungoverned ignore has no owner, no checksum binding, and no
deadline; the governed exception has all three, and `inventory` tracks each
exception's expiry status (active, soon-to-expire within 30 days, expired, or
stale) without running the scanners.

## Routine Update Cadence

Run a periodic update pass — weekly or fortnightly works well with the default
seven-day release-age window — assembled from the existing surfaces. From a
clean checkout:

1. **Pick a target per direct dependency.** For each direct dependency you
   want to move, discover the newest policy-compliant version:

   ```bash
   cargo barbican pick serde
   cargo barbican pick toml@^1
   ```

   `pick` drops yanked versions, pre-releases, semver-incompatible versions,
   and versions below the release-age policy, and prints an exact
   `crate@version`.

2. **Preview and apply.**

   ```bash
   cargo barbican update --dry-run serde@1.0.230 toml@1.1.3
   cargo barbican update serde@1.0.230 toml@1.1.3
   ```

3. **Check what the resolver dragged in.** With the changes still uncommitted,
   both commands baseline against `HEAD` by default:

   ```bash
   cargo barbican age-lock
   cargo barbican assess
   ```

   `age-lock` catches too-fresh transitive selections; `assess` classifies
   the whole diff and flags new non-crates.io sources, yanked selections,
   native `-sys` crates, and new or changed `build.rs` / proc-macro surfaces.
   For non-git baselines (generated or staged flows), see
   [Comparing Against Non-Git Baselines](commands.md#comparing-against-non-git-baselines).

4. **Re-pin affected families.** Update `resolved` (and `direct`) entries and
   review records for any reviewed family the update moved, as in
   [step 3 above](#3-re-pin-the-affected-reviewed-family).

5. **Run the gates before committing.**

   ```bash
   cargo barbican gatehouse pre-release
   ```

Schedule `audit` independently of this cadence as well — its verdict can
change without any repo change. See [ci.md](ci.md) for the scheduled-run
pattern.

### Dependabot and Renovate bumps

A bot bump of a crate covered by a reviewed family fails `pin check` by
design; that mismatch is the gate working, not a false positive. Review the
bumped version as you would any update, then re-pin the family before merging.
The full treatment is in
[Reviewing A Dependency PR](commands.md#reviewing-a-dependency-pr). For crates
not covered by any family, the bot's PR still goes through `age-lock`,
`assess`, `audit`, and `verify` like any other dependency PR.

## Reviewed-Family Lifecycle

A family (see the [glossary](commands.md#glossary)) is **active** by being
present in `reviewed-targets.toml`. There is no status flag: every
`[[rust.families]]` entry is enforced by `pin check` and `verify`, and
retiring a family means removing its entry. The review record the family
points at must exist as long as the family is active.

### Updating a family for a new version

Two distinct cases, distinguished by what changed:

- **Mechanical re-pin.** The new version introduces no new execution surface
  and no other elevated-risk finding — `assess` reports the diff as routine
  after the update. Update the family's `resolved` version and
  `checksum_sha256` from `Cargo.lock`, the `direct` pin if configured, and
  append the new version, date, and commands run to the existing review
  record (or write a short successor record citing the old one under
  `Inheritance`).
- **Genuine re-review.** `assess` flags a new or changed `build.rs`,
  proc-macro, or native `-sys` surface in the newly selected packages, or the
  release otherwise changes the trust posture (new upstream maintainer, new
  transitive graph shape). Re-review the release properly — `inspect` on the
  exact version supplies the evidence — and record the outcome. A newly
  reviewed execution surface must also be declared under the family's
  `allowed_surfaces` before `assess` treats it as an allowed exception rather
  than an elevated-risk finding.

### Retiring or superseding a family

- **Retiring** — the dependency left the graph. Remove the family entry from
  `reviewed-targets.toml`. Leave the review record checked in: records under
  `docs/dependency-reviews/` are audit history, not live policy, and they
  answer "what did we review and when" long after the crate is gone.
- **Superseding** — a new review replaces an old one (a major-version
  re-review, or a regrouping of crates into different families). Add the new
  family with its new record, remove the old family entry, and cite the old
  record from the new one's `Inheritance` section. Old records stay put.

`verify` fails closed when no active family remains, so never retire the last
family without either replacing it or consciously stepping back from the
`verify` gate. Run `pin check` after every edit to `reviewed-targets.toml`.

## Upgrading Cargo-Barbican Itself

cargo-barbican is itself a pinned, reviewed tool in the consumer repo. When a
new version ships:

1. **Review, then reinstall pinned.** Check
   [docs/CHANGELOG.md](../CHANGELOG.md) in the cargo-barbican repo for what
   changed, then reinstall with the same pinned `--locked` install used at
   adoption (see [integration.md](integration.md#consumer-flow)), and update
   the tool-install review record to cite the new version.
2. **Re-sync templates.** Template files carry a `Synced from cargo-barbican
   vX.Y.Z` header. Re-copy the templates from the new version, review the
   diff against your local policy files, and apply what belongs. There is no
   automatic sync; the workflow is
   [integration.md](integration.md#versioning-and-re-sync).
3. **Check for new config keys.** Release notes and the template diff show
   any new `barbican.toml` keys or sections. Every config section falls back
   to a built-in default when absent, so an existing `barbican.toml` keeps
   working under a newer cargo-barbican without edits — new keys are opt-in
   policy, not silent breakage. Adopt them deliberately: the template header
   marks defaults you have not yet made explicit repo policy.
4. **Re-run the gate.** `gatehouse pre-release` after the upgrade confirms the
   new version reads your existing policy the way the old one did, including
   the direct-dependency coverage floor.

## Onboarding A Large Existing Project

On a project with hundreds of resolved crates, full coverage on day one is not
realistic — and not required. Partial coverage is a valid interim posture:
`verify` needs at least one active reviewed family to run at all, `pin check`
enforces exactly the families you have declared, and `inventory` keeps the
remaining gap visible without failing.

### Triage with inventory

```bash
cargo barbican inventory
```

Read the report as a triage list, not a to-do list to clear in order:

- **Direct dependencies** — the crates you chose. Exact-pin status and
  coverage gaps here matter most.
- **Live execution surfaces** — crates with undeclared `build-rs`,
  proc-macro, or `native-sys` surfaces run code at build or compile time.
  These are the elevated-risk crates to bring under review first, direct or
  not.
- **Non-crates.io sources** — git, path, and alternate-registry entries need
  individual decisions before checksum-bound review is even possible.
- Routine transitive crates with no elevated-risk surface can follow later.

### Group crates into families

A family covers crates that were reviewed together and share one record —
review effort groups naturally, so policy should too. cargo-barbican's own
[`reviewed-targets.toml`](../../reviewed-targets.toml) is the worked pattern:

- a **bootstrap core set** — `serde`, `serde_json`, `thiserror`, `toml`,
  `clap` reviewed as one family, with their derive companions
  (`serde_derive`, `thiserror-impl`, `clap_derive`) in the same family's
  `resolved` map and their proc-macro surfaces declared under
  `allowed_surfaces`;
- a **boundary family per capability** — one family for the HTTP boundary
  (`ureq`), one for time handling (`time`), one per meaningful trust
  boundary, so a bump in one boundary re-reviews only that record;
- **tool-install records** — `cargo-deny`, `cargo-audit`, and cargo-barbican
  itself get review records even though they are not lockfile entries.

Keep a crate's proc-macro or `-sys` companions in the same family as their
parent: `allowed_surfaces` and `allowed_age_exceptions` can only reference
crates in the same family's `resolved` map.

### A suggested milestone order

1. **Scaffold and tooling.** `policy init`, then review records for
   cargo-barbican, `cargo-deny`, and `cargo-audit` — the first records a
   consumer repo writes ([integration.md](integration.md)).
2. **First family, gates on.** Bring one well-understood direct family under
   review (`pin add` scaffolds the stub; complete the record). `verify` can
   now run, and every later step happens under a working gate.
3. **Elevated-risk surfaces.** Cover every crate `inventory` lists with an
   undeclared live execution surface, declaring reviewed surfaces under
   `allowed_surfaces` as you go.
4. **Remaining direct dependencies.** Family by family, until direct
   coverage is complete.
5. **Advisory steady state.** Run `audit` throughout; use governed
   exceptions ([above](#when-no-patched-release-is-adoptable)) for accepted
   findings rather than deferring the gate itself.
6. **Routine transitives.** Close the long tail as review capacity allows —
   `inventory` tracks the shrinking uncovered list.

Each milestone leaves the repo strictly better gated than the one before; no
step requires finishing the next to be worth committing.
