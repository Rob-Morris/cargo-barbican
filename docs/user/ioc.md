# Exact IOC Review

`ioc check` answers one question: do the requested original sources have complete
declared indicator-of-compromise coverage, with findings absent or every match
covered by a current exact reviewed allowance? Unreviewed findings block. It
never builds or executes candidate code. A pass is not dependency adoption, tool acceptance or a
claim that the source is benign.

## Inspect sources

Choose exactly one explicit source selector:

```bash
cargo-barbican ioc check serde@1.0.228 --output inspection.json
cargo-barbican ioc check --git https://github.com/owner/repository \
  --rev FULL_40_HEX_COMMIT --package package-name --output inspection.json
cargo-barbican ioc check --lockfile Cargo.lock --format json --output locked.json
```

Replace example names and revisions with the exact intended source. Direct
`cargo-barbican` starts without Cargo workspace discovery or compiler probes.
Ordinary `cargo barbican` first invokes the caller's Cargo executable.

`--output` exclusively creates canonical JSON even when stdout uses the default
text format. It refuses an existing destination or unsafe path. Diagnostics go
to stderr. Original archive checksums, exact Git trees, source scope, input and
scanned file/byte counts, raw findings and effective decisions remain distinct.
Incomplete evidence is a nonzero result, never an empty clean scan.

The lockfile selector includes **every identified external locked source**,
including dev, optional and inactive-target versions. Source-less local/path
entries are listed outside scope: a lockfile cannot identify their original
bytes or prove they are workspace members. This is not the active compilation
graph or a scan of mutable application code. Unsupported registries and
ambiguous Git package locations make requested coverage incomplete. No lockfile
is generated or repaired.

The maintained detector matches literal tokens on the declared build-script,
proc-macro and native-source surface. Comments and string literals can match.
Top-level test/example/bench exclusions and Git package/workspace input scope
are explicit; it does not infer runtime reachability or prove maliciousness.
Each finding binds an exact original source, file bytes, rule, scope semantics
and the complete occurrence set. A partial occurrence set cannot be approved.

## Review and attach repository authority

The origin is the explicit global `--repo ROOT`, or an unambiguous filesystem
ancestor containing `barbican.toml` or `reviewed-targets.toml`. The inspected
source, report or lockfile location cannot choose authority. With no origin,
check uses default no-allowance policy and portable review still works. Pin
exception publication requires an origin and existing policy; it never runs
policy init implicitly.

For one unambiguous source in the saved report:

```bash
cargo-barbican --repo /absolute/consumer pin exception --ioc \
  --inspection inspection.json --review-record docs/dependency-reviews/ioc.md
```

This creates only a **PENDING** Markdown record and displays a grant fragment.
It does not write policy authority. The path is explicit, relative to the
repository, and must be a safe new regular file. To prepare portable rationale
without selecting authority, use:

```bash
cargo-barbican ioc review --inspection inspection.json --review-record review.md
```

For multiple sources, `ioc review` and `tool exception` use
`--package NAME@VERSION`. `pin exception --ioc` instead takes the package as a
positional argument, for example `pin exception serde@1.0.228 --ioc ...`.
Use the displayed `--source-id` when name/version is ambiguous across registry
or Git origins. Repeat exact `--path RELATIVE_PATH` and `--rule RULE_ID` to
select a subset.
Unmatched or ambiguous selectors refuse; no wildcard grants exist.

Read the original source and every selected occurrence. Complete the record's
versioned machine block: reviewer label, UTC completion timestamp, conclusion
(`expected-behaviour` or `false-positive`) and substantive rationale/evidence.
Keep its source/finding bindings intact. After completing every review field,
remove the separate `BARBICAN-REVIEW-PENDING` marker outside the machine block
as well. Leaving that marker makes the record
unusable even when the machine block is complete. Humans and authorised agents
use the same record format; structural completion does not authenticate authorship or
prove the review's quality. `unresolved`, `rejected` and `pending` grant nothing.
An optional `review_by_utc` deadline is enforced; no arbitrary expiry is added.
The authoring option `--review-by YYYY-MM-DD` means the end of that UTC date and
must match an already completed record when publishing it.

Then explicitly attach the completed record:

```bash
cargo-barbican --repo /absolute/consumer pin exception --ioc \
  --inspection inspection.json --record docs/dependency-reviews/ioc.md
```

Publication revalidates original bytes and findings. Retain the verified source
cache or recollect the exact report if original inputs are unavailable. A
self-consistent JSON report alone is not source authority. The reference is an
independent `[[rust.ioc_records]]` entry in `reviewed-targets.toml`; it does not
create an active family, pin a dependency or permit Cargo Git sources. Changed
records invalidate their current digest references. Conflicting references are
reported for explicit review rather than silently overwritten.

## Exact tool authority

A repository source allowance does not transfer to a tool subject. From its
blocked or pending stored review, use the exact tool authority owner:

```bash
cargo-barbican tool exception REVIEW_ID --ioc --standalone \
  --review-record cargo-tools/reviews/source-ioc.md
cargo-barbican tool exception REVIEW_ID --ioc --standalone \
  --record cargo-tools/reviews/source-ioc.md
```

The first command scaffolds; complete the record before the second. A tool
record is relative to the originating repository, or to the captured private
data-store root in standalone mode. It is never relative to cwd or to
`policy.toml`. Output identifies the resolved destination. Keep the same
`--repo`, `--data-dir` and `--cache-dir` context across operations.

A tool IOC grant additionally binds the exact Subject and base origin policy.
Recollect the tool review after changing policy. Personal acceptance and any
separate repository approval remain required. Independent checksum, coverage,
yank, age, advisory, licence, source and execution-surface obligations are not
waived by an IOC record. See [reviewed Cargo tools](cargo-tools.md).

## Composition and revocation

`inspect` and Gatehouse candidate dossiers use the same detector and exact
allowances but preserve their broader risk verdict: an approved IOC alone does
not make a build-bearing crate routine-safe. To add the narrow locked-source
check to an existing repository workflow explicitly:

```bash
cargo-barbican gatehouse policy-check --ioc
cargo-barbican gatehouse pre-release --ioc
```

It runs after conformance and before build/test execution. Existing defaults and
`verify` do not silently acquire a new source-fetching gate.

Raw findings remain adverse knowledge after an allowance. New findings or
interrupted collection can block older cached tool evidence. Removal, changed
record bytes, changed policy/source/scope semantics or an elapsed explicit
deadline withdraws applicability, including cached and continuing tool use.
Revalidating saved source bytes does not refresh mutable source observations or
old assessment timestamps. Complete coverage means the declared heuristic scope
was evaluated, not that the package is safe in every use.
