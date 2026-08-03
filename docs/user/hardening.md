# Hardening The Barbican Gate

How to make the barbican gate hard for coding agents and careless humans to
work around. This guide is for maintainers of a consumer repo who have already
adopted cargo-barbican (see [adoption.md](adoption.md)) and want the gate to
hold up against contributors — human or automated — who are optimising for a
green build rather than for policy integrity.

See [commands.md](commands.md#glossary) for term definitions (gate, family,
reviewed target, and so on) used below.

## The threat model, honestly

Barbican's entire policy surface is plain checked-in text:

- `barbican.toml` — release-age, high-scrutiny, and delegate settings
- `reviewed-targets.toml` — active reviewed families and exact resolved targets
- `docs/dependency-reviews/` — human review records, in markdown
- `deny.toml` — delegated `cargo-deny` posture

Any agent or human with write access to the working tree can edit every one of
these files. Barbican does not — and cannot — stop that. Its tamper-resistance
model is different: **every bypass must leave a visible, reviewable diff in a
checked-in file.** Silent bypasses (repointing a reviewed crate without
touching the lockfile, hiding an advisory behind a native ignore, swapping a
policy file for a symlink) are detected and fail closed. Noisy bypasses
(editing `reviewed-targets.toml` itself) are forced into the diff, where
repo-side controls — code owners, branch protection, human review — decide
whether they land.

The realistic adversary here is not a determined attacker with admin rights on
the repository. It is a coding agent instructed to "make CI pass" that
discovers the fastest route is editing the policy file, or a hurried human who
adds an ignore instead of a review. The hardening job is to make the governed
path easier than the bypass, and to make every bypass visible to a human who
did not write it.

## What barbican already blocks

These mitigations are active in the shipped gates today. They matter because
each one closes a route that would otherwise let a dependency change dodge the
diff:

- **Lockfile doppelgaengers for reviewed crates.** `pin check` requires every
  `Cargo.lock` entry whose name matches a reviewed crate to be crates.io
  sourced. A second locked entry for the same name from a git, path, or
  alternate-registry source is a blocking mismatch even when a clean crates.io
  entry at the reviewed version sits right next to it.
- **Checksumless lockfile siblings.** For checksum-bound reviewed targets, a
  matching-version `Cargo.lock` entry with no checksum fails the check — even
  if another entry for the same name and version carries the expected
  checksum. A checksum-less entry cannot stand in for the reviewed artefact.
- **`[patch]` tables targeting reviewed crates, including the rename form.**
  A manifest `[patch]` entry (under any registry key) that targets a reviewed
  crate fails closed, and the detection resolves the
  `alias = { package = "real-crate", ... }` rename form to the real package
  name, so aliasing the patch does not hide it.
- **Repo-root `.cargo/config.toml` source overrides.** While any reviewed
  family is active, the mere presence of a `[source]` table, a config-defined
  `[patch]` table, or a top-level `paths` override in the repo-root
  `.cargo/config.toml` (or legacy `.cargo/config`) fails `pin check` — each of
  these can repoint a reviewed crate away from crates.io, or substitute local
  source code for it, without any change to `Cargo.toml` or `Cargo.lock`.
- **Ungoverned advisory ignores are neutralised during `audit`.** `audit`
  never runs `cargo-deny` against your `deny.toml` directly: it generates a
  runtime config that forces the `[advisories]` section with an empty `ignore`
  list and strips graph-exclusion keys, so a `deny.toml` ignore cannot
  suppress a finding. `cargo-audit` is run away from the repo root against an
  explicit lockfile path, so `.cargo/audit.toml` ignores do not apply either —
  and if the scanner's runtime settings still report an ignore, that is itself
  a failure. Native ignores found in `deny.toml` / `.cargo/audit.toml` are
  always rendered in the report. An ID is marked governed only when every
  current occurrence is accepted by active Barbican governance; under
  `delegates.unmanaged_delegated_policy = "deny"`, any remaining unmanaged ID
  fails the audit. Adding a native ignore cannot turn a Barbican failure into
  a pass.
- **Advisory acceptance is checksum-bound and expires.** The only way to
  accept an advisory finding is an `allowed_advisories` entry in a reviewed
  family. Parsing rejects the entry unless the crate is in the same family's
  `resolved` map with a `checksum_sha256`; `audit` honours the exception only
  while the bound target matches the current `Cargo.lock`, the family's review
  record is completed, and the `review_by` deadline has not passed. An
  expired exception is a failing finding again.
- **Symlinked policy files are refused.** `barbican.toml`,
  `reviewed-targets.toml`, `deny.toml`, `.cargo/audit.toml`, and the repo-root
  cargo config are all read through a loader that refuses symlinks, and a
  review record only satisfies the gate when it is a regular file. Pointing a
  policy path at content outside the repo does not work.
- **`verify` fails closed without policy.** Deleting `reviewed-targets.toml`,
  or emptying it of active families, does not turn the gate off: `verify`
  refuses to run build/test verification without at least one active reviewed
  family, and it re-runs the full `pin check` gate first.

## What barbican leaves to process

The honest residual gaps — routes the tool does not close, which the
repo-side recipe below exists to cover:

- **Hierarchical cargo config outside the repo root is not inspected.** A
  `.cargo/config.toml` in a parent directory, or in `$CARGO_HOME`, can carry
  the same `[source]`/`[patch]`/`paths` overrides and is not read by
  `pin check`. This is machine state, not repo state — it cannot be gated by
  a diff. CI running on clean, ephemeral runners is the mitigation.
- **`[replace]` manifest tables are not detected.** The deprecated `[replace]`
  mechanism can repoint a crate like `[patch]` can, and barbican does not yet
  look for it. It does still show up as a manifest diff a reviewer can see.
- **Crates outside reviewed families are not gated deterministically.**
  `pin check` and `verify` enforce only what `reviewed-targets.toml` covers.
  A new transitive crate in an unreviewed family enters the lockfile without
  a deterministic block; `assess`, `inventory`, and release-age checks in
  `update`/`resolve` observe it, but coverage of the graph is a review
  decision, not an automatic guarantee.
- **The policy files themselves are editable.** By design. The control on
  that edit is the diff — which is only a control if a human other than the
  author must approve it. That is the next section.

## Repo-side hardening recipe

### 1. Put the policy surface under CODEOWNERS

Require a policy owner's approval on every file an agent would need to touch
to weaken the gate. A worked GitHub example (`.github/CODEOWNERS`):

```text
# Dependency-policy surface: any change requires a policy owner's review.
/barbican.toml                            @your-org/dependency-policy
/reviewed-targets.toml                    @your-org/dependency-policy
/deny.toml                                @your-org/dependency-policy
/docs/dependency-reviews/                 @your-org/dependency-policy
/.cargo/                                  @your-org/dependency-policy
/.github/CODEOWNERS                       @your-org/dependency-policy
/.github/workflows/dependency-policy.yml  @your-org/dependency-policy
```

Notes on the entries:

- `/.cargo/` is on the list because a repo-root cargo config can repoint
  sources; `pin check` fails closed on the dangerous keys, but the file's
  diff should still reach a policy owner.
- The CI workflow file and `CODEOWNERS` itself are on the list because
  weakening either is equivalent to weakening the gate.
- `Cargo.toml` and `Cargo.lock` are deliberately absent: they change with
  routine work, and gating them on a small owner group creates pressure to
  rubber-stamp. The barbican gates in CI are the control on those files.

CODEOWNERS only enforces anything when branch protection requires code-owner
review — on its own it is a suggestion.

### 2. Branch protection with required CI

Configure the default branch so that pull requests are the only way in, a
code-owner review is required, and the CI checks that run
`cargo barbican gatehouse pre-release` are **required status checks**. See [ci.md](ci.md)
for the worked workflow, including why `audit` also runs on a schedule.
Required checks must be marked required in the branch-protection settings —
a workflow that merely runs is advisory.

### 3. Review policy-file diffs with `cargo barbican review`

`cargo barbican review` renders exactly the policy-relevant diff — root and
member `Cargo.toml` files, `Cargo.lock`, `barbican.toml`, `deny.toml`,
`reviewed-targets.toml`, and the review records — with a checklist above it.
Use it as the reviewer's lens on any pull request that touches the policy
surface, so a one-line change to `reviewed-targets.toml` buried in a large
diff is not missed.

### 4. Keep policy changes in dedicated commits

A commit that changes `reviewed-targets.toml` or a review record should
change nothing else. Mixed commits are where policy edits hide: a reviewer
approving a feature diff should never be implicitly approving a new advisory
exception. This is convention, not tooling — write it into your contributor
docs and hold review to it.

## Instructions for coding agents in consumer repos

Paste this into the consumer repo's `AGENTS.md` or `CLAUDE.md` (adjust
command examples to taste):

```markdown
## Dependency policy (cargo-barbican)

This repo gates its dependency graph with cargo-barbican. Use barbican
surfaces for every dependency change — never raw cargo mutations:

- Choose versions with `cargo barbican pick <crate>@<range>` and check exact
  candidates with `cargo barbican inspect <crate>@<version>`.
- Bump resolved versions with `cargo barbican update <crate>@<version>`
  (preview with `--dry-run`). After editing manifests, regenerate the
  lockfile with `cargo barbican resolve`. Do not run `cargo add` or
  `cargo update`, and do not hand-edit `Cargo.lock`.
- Bring a crate under reviewed-target policy with
  `cargo barbican pin add <crate>`.
- Accept an advisory finding only with
  `cargo barbican pin exception <crate> <RUSTSEC-id>`. A matching
  `deny.toml` or `.cargo/audit.toml` ignore may coexist for direct-tool use,
  but it is neutralised by `cargo barbican audit` and supplies no authority.
- Never edit `barbican.toml`, `reviewed-targets.toml`, `deny.toml`, or
  anything under `docs/dependency-reviews/` on your own initiative. These
  files record human policy decisions. If a task requires a policy change,
  stop and ask; only make the edit after an explicit human decision, and
  record that decision in the matching review record under
  `docs/dependency-reviews/`.
- The scaffolds `pin add` and `pin exception` create are stubs, not
  completed reviews — a human reviewer completes the record.

Before finishing any dependency change, run `cargo barbican pin check` and
`cargo barbican audit`, and fix findings through the surfaces above rather
than by weakening policy files.
```

## The enforcement truth

Stated plainly: everything that runs on a contributor's machine is advisory.
The pre-commit hook from [ci.md](ci.md#pre-commit-hook) is worth having for
fast feedback, but `git commit --no-verify` skips it, and coding agents skip
hooks routinely — sometimes by instruction, sometimes by habit. Local
`gatehouse pre-release` runs prove the change is clean; they do not enforce
anything.

The only gate an agent cannot skip is server-side: a required CI status check
on a protected branch, backed by code-owner review of the policy surface.
That combination is what turns barbican's "every bypass leaves a diff" model
into an actual control — the diff exists, a human who did not write it must
approve it, and the gates re-run on infrastructure the author does not
control. If you configure nothing else from this guide, configure that.
