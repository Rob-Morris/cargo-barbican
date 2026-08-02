# Configuration Reference

This is the authoritative user-facing reference for cargo-barbican's two
policy files: `barbican.toml` (behaviour policy) and `reviewed-targets.toml`
(reviewed dependency families). Both live at the consumer repo root. It also
covers how the CLI `--min-age-days` override and the delegated `deny.toml`
boundary interact with them.

`cargo barbican policy init` scaffolds both files from the shipped templates.
For the adoption sequence around them, see [adoption.md](adoption.md). For
per-command usage, see [commands.md](commands.md); for exact behaviour
contracts, see [../functional/cli.md](../functional/cli.md).

## `barbican.toml`

`barbican.toml` configures release-age policy, elevated-risk assessment
toggles, and delegated-tool behaviour. Every key has a built-in default, so
the file is optional in the strict sense — but `policy init` creates it
deliberately, because explicit checked-in policy is easier to review than
implicit defaults.

Loading rules:

- **Absent file** — every key takes its built-in default (the values listed
  below). No error.
- **Empty file** — identical to the absent case: all defaults apply.
- **Partial file** — any omitted section or key takes its default; you only
  write the keys you change.
- **Unknown keys** — rejected. A misspelt key is a parse error, not a
  silently ignored no-op, so a typo cannot quietly weaken policy.
- **Wrong-type path** — a `barbican.toml` that is a symlink, directory, or
  other non-regular file is an error; cargo-barbican refuses to read policy
  through symlinks.

### `[release_age]`

| Key | Type | Default | Valid values |
| --- | --- | --- | --- |
| `minimum_days` | integer | `7` | `0` to `365000` inclusive |

The minimum number of days a crates.io release must have existed before
release-age-aware commands (`age`, `age-lock`, `pick`, `resolve`, `update`,
`assess`, `inspect`, `gatehouse candidate`) accept it. A value above `365000`
fails validation — the cap catches nonsense values (for example a timestamp
pasted where a day count belongs) rather than expressing a meaningful policy
ceiling.

```toml
[release_age]
minimum_days = 14
```

The invocation-scoped `--min-age-days` CLI flag overrides this key for a
single command run; see [Interactions](#interactions).

### `[high_scrutiny]`

Six boolean keys. **All default to `true`.**

| Key | Default | Elevated-risk finding it enables in `assess` |
| --- | --- | --- |
| `new_direct_dependencies` | `true` | Any new direct dependency added across workspace `Cargo.toml` manifests. |
| `non_crates_io_direct_dependencies` | `true` | A new direct dependency whose source is not crates.io (git, path, alternate registry). |
| `non_crates_io_source_changes` | `true` | A `Cargo.lock` package source changing to a non-crates.io source. |
| `build_rs_changes` | `true` | New or changed `build.rs` build-script surfaces in newly selected packages. |
| `proc_macro_changes` | `true` | New or changed proc-macro surfaces in newly selected packages. |
| `native_sys_crates` | `true` | Newly introduced native `-sys` crates. |

These keys govern `cargo barbican assess` classification only. Each key is a
per-category switch: when a category is enabled and `assess` detects a
matching item, the report gains an `elevated-risk` finding for that category,
which fails the default `--policy-mode strict` run. When a key is `false`,
detected items in that category are **still detected and rendered in the
report** — the toggle only stops the category from counting as an
elevated-risk finding, so disabling a key changes classification and exit
code, never visibility.

Two scope notes:

- Blocking findings (age violations, yanked versions, checksum drift,
  release-age-exception artefact mismatches, required-inspection failures)
  are not governed by `[high_scrutiny]` and always block.
- `cargo barbican inspect` is not governed by these keys. Its high-scrutiny
  indicator scan over build-time and proc-macro-relevant sources is fixed,
  and its surface classification (`build.rs`, proc-macro, native `-sys` /
  FFI surfaces are `elevated-risk` unless covered by a reviewed
  `allowed_surfaces` allowance) does not consult `[high_scrutiny]`. The keys
  configure the post-change assessment gate, not the pre-add evidence
  commands.

Set a key to `false` only as a deliberate, reviewed policy decision — for
example a repo that adds direct dependencies frequently under a separate
review process might disable `new_direct_dependencies` while keeping the
non-crates.io and execution-surface categories on.

```toml
[high_scrutiny]
new_direct_dependencies = true
non_crates_io_direct_dependencies = true
non_crates_io_source_changes = true
build_rs_changes = true
proc_macro_changes = true
native_sys_crates = true
```

### `[delegates]`

Configures how `cargo barbican audit` drives the delegated scanners and how
it treats native advisory suppression it finds in their config files.

| Key | Default | Valid values |
| --- | --- | --- |
| `unmanaged_delegated_policy` | `"warn"` | `"warn"`, `"deny"`, `"allow"` |
| `advisories.lockfile_scanner` | `"cargo-deny"` | `"cargo-deny"`, `"cargo-audit"`, `"both"` |
| `cargo_deny.checks` | `["advisories", "bans", "sources"]` | array drawn from `"advisories"`, `"bans"`, `"sources"`, `"licenses"` |

**`unmanaged_delegated_policy`** controls how `audit` reports native advisory
ignores found in a checked-in `deny.toml` (`[advisories] ignore`) or
`.cargo/audit.toml`. Those ignores are **always neutralised** at runtime —
this key never re-enables them; it controls reporting only:

- `"warn"` (default) — report each native ignore as a warning; the verdict
  is unaffected.
- `"deny"` — any native delegated advisory ignore fails `audit`. Use this to
  force every advisory acceptance through the governed
  `allowed_advisories` path in `reviewed-targets.toml`.
- `"allow"` — native ignores are still neutralised and rendered, without the
  warning posture.

**`advisories.lockfile_scanner`** selects which structured scanner(s) `audit`
runs and reconciles for lockfile advisory findings: `cargo-deny`,
`cargo-audit`, or `both`. Whichever is configured must be installed for
`audit` to succeed.

**`cargo_deny.checks`** lists the `cargo-deny` check groups `audit` runs.
Validation fails closed on:

- an **empty** list — `delegates.cargo_deny.checks must not be empty`;
- **duplicate** entries;
- a list that omits `"advisories"` while `advisories.lockfile_scanner` is
  `"cargo-deny"` or `"both"` — the scanner that owns advisory evidence must
  actually run the advisories check.

`"licenses"` is valid but not in the default set; add it when the repo wants
`cargo-deny` licence checking under the same `audit` invocation.

```toml
[delegates]
unmanaged_delegated_policy = "deny"

[delegates.advisories]
lockfile_scanner = "both"

[delegates.cargo_deny]
checks = ["advisories", "bans", "sources", "licenses"]
```

### Worked examples

Absent or empty `barbican.toml` — the effective policy is exactly:

```toml
[release_age]
minimum_days = 7

[high_scrutiny]
new_direct_dependencies = true
non_crates_io_direct_dependencies = true
non_crates_io_source_changes = true
build_rs_changes = true
proc_macro_changes = true
native_sys_crates = true

[delegates]
unmanaged_delegated_policy = "warn"

[delegates.advisories]
lockfile_scanner = "cargo-deny"

[delegates.cargo_deny]
checks = ["advisories", "bans", "sources"]
```

Minimal override — everything else keeps its default:

```toml
[release_age]
minimum_days = 30
```

Stricter posture — longer quarantine, no ungoverned advisory ignores,
`cargo-audit` cross-check:

```toml
[release_age]
minimum_days = 14

[delegates]
unmanaged_delegated_policy = "deny"

[delegates.advisories]
lockfile_scanner = "both"
```

## `reviewed-targets.toml`

`reviewed-targets.toml` is the repo-root manifest of **reviewed dependency
families**: groups of crates that were deliberately reviewed together, backed
by one checked-in review record, and pinned to exact `Cargo.lock` targets.
`pin check` and `verify` enforce it; `assess`, `inspect`, `audit`, and the
release-age-aware commands honour the exceptions it declares.

Loading rules:

- **Absent file** — no reviewed-target policy is configured. Standalone
  `pin check` skips successfully; `verify` fails closed, because build/test
  execution requires explicit reviewed-target policy. `inventory` reports
  the absence as a state, not an error.
- **Present with no families** (the scaffolded `[rust]` header only) — same
  gate behaviour as absent: `pin check` skips, `verify` fails closed.
- **Malformed file, symlink, or wrong-type path** — fails closed for every
  command that reads it.

### What "active" means

A family is **active** by being present: every `[[rust.families]]` entry in
the file is an active family. There is no status flag, date window, or
enable key — deactivating a family means deleting (or never adding) its
entry. Mechanically, activity has two consequences:

- `pin check` enforces the family's `direct`, `resolved`, checksum, and
  allowance constraints against the current manifests and `Cargo.lock`, and
  requires the family's `review_record` path to exist as a regular
  non-symlink file.
- The family's allowances (`allowed_surfaces`, `allowed_age_exceptions`,
  `allowed_advisories`) become candidates for honouring — each is honoured
  only when its additional binding conditions (below) also hold, the review
  record's existence being the common one.

The gate verifies the record file exists; it does not authenticate or parse
the record's content. Reviewers must inspect changes to
`reviewed-targets.toml` and the cited record together.

### Family schema

Each family is one `[[rust.families]]` table:

| Key | Required | Meaning |
| --- | --- | --- |
| `name` | yes | Stable family label used in review records and tooling output. Must be non-empty and unique across the file. |
| `review_record` | yes | Repo-relative path to the checked-in Markdown review record that activated the family. Must be a relative path with no `..` traversal. |
| `[rust.families.direct]` | no | Exact manifest requirements for direct crates, including the leading `=` (for example `serde = "=1.0.228"`). Non-exact requirements fail parsing. |
| `[rust.families.resolved]` | yes, non-empty | Exact `Cargo.lock` targets; see below. |
| `[rust.families.allowed_surfaces]` | no | Reviewed execution surfaces per crate. |
| `[rust.families.allowed_age_exceptions]` | no | Reviewed release-age exceptions per crate. |
| `[rust.families.allowed_advisories]` | no | Reviewed advisory exceptions per crate. |

#### `resolved` — version-only vs structured form

Each `resolved` entry maps a crate name to an exact `Cargo.lock` target, in
one of two forms:

```toml
[rust.families.resolved]
# structured crates.io form — preferred
serde = { version = "1.0.228", checksum_sha256 = "9a8e94ea7f378bd32cbbd37198a4a91436180c5bb472411e48b5ec2e2124ae9e" }
# version-only string form — accepted, weaker
companion-crate = "0.4.5"
```

Both forms require the resolved version to match `Cargo.lock` exactly, and
both require **every** `Cargo.lock` entry sharing the crate's name to be
crates.io sourced — a git, path, alternate-registry, or sourceless entry is
a blocking mismatch even when a sibling entry for the same name and version
is a clean crates.io match.

Only the structured form additionally binds the reviewed artefact digest:
`pin check` reconciles `checksum_sha256` against the resolved `Cargo.lock`
checksum chain, so a same-version crates.io re-publish with different bytes
is caught. A matching-version lockfile entry with **no** checksum is itself
a mismatch under the structured form, not treated as absent. Prefer the
structured form; the version-only form pins a version label, not an
artefact. The structured form is also a prerequisite for
`allowed_age_exceptions` and `allowed_advisories` on that crate.

`checksum_sha256` is the lowercase 64-hex SHA-256 of the published `.crate`
tarball — the same digest `Cargo.lock` records and `pin add` copies from it.

#### `allowed_surfaces`

Reviewed execution-surface allowances, per crate:

```toml
[rust.families.allowed_surfaces]
serde_derive = ["proc-macro"]
```

Valid surface values are `"build-rs"`, `"proc-macro"`, and `"native-sys"`.
The crate must already be present in the **same family's** `resolved` map,
and an empty surface list is rejected. When the family's review record
exists, a matching allowance lets `assess` suppress the corresponding
execution-surface elevated-risk signal, rendering the allowance in an
`Allowed policy exceptions:` section instead. `inspect` does not consult
allowances: it reports its fail-closed verdict regardless, so recording an
allowance changes what the repo intake gate admits, not what `inspect`
prints. `pin check` validates that every allowance references a crate in the
same family's `resolved` map.

#### `allowed_age_exceptions`

Reviewed acceptance of a too-fresh release, per crate:

```toml
[rust.families.allowed_age_exceptions]
some-crate = "1.2.3"
```

The value is the exact version and must equal the same family's `resolved`
entry version, and that `resolved` entry must be the structured form with
`checksum_sha256`. Release-age-aware commands honour the exception only
when the family review record is completed **and** the fetched crates.io checksum
matches the reviewed checksum: metadata-only commands (`age`, `age-lock`,
`resolve`, `update`, `assess`) compare crates.io's published
checksum metadata; inspect-backed commands (`inspect`,
`gatehouse candidate`) also verify downloaded tarball bytes. The exception
can only allow a too-fresh release — yanked releases and checksum
mismatches remain blocking.

A completed review record is a regular, non-symlink, non-empty file with the
`BARBICAN-REVIEW-PENDING` scaffold marker removed.

#### `allowed_advisories`

Governed, expiring acceptance of RustSec advisory findings, per crate:

```toml
[rust.families.allowed_advisories]
some-crate = [{ id = "RUSTSEC-2026-0001", review_by = "2026-12-31" }]
```

Each entry binds one advisory `id` (strictly `RUSTSEC-YYYY-NNNN` form) to a
`review_by` re-review deadline (`YYYY-MM-DD`). The crate must be present in
the same family's `resolved` map with `checksum_sha256`; duplicate advisory
entries for the same crate are rejected.

`cargo barbican audit` honours the exception only while all of these hold:

- the resolved target and checksum still match the current `Cargo.lock`;
- the family's review record is completed;
- `review_by` has not passed — an expired exception fails `audit` again,
  by design: acceptance is bounded, not permanent.

`cargo barbican inventory` reports each configured exception's expiry status
without running the scanners: `active`, `soon-to-expire` (`review_by`
within 30 days), `expired`, or `stale` (the exception's `crate@version` is
no longer in the current `Cargo.lock`).

`cargo barbican pin exception <crate> <RUSTSEC-id>...` scaffolds this
structure — including the review-record stub — with a default `review_by`
30 days from today, overridable with `--review-by`.

### Worked example

A realistic file with two families (adapted from this repo's own
`reviewed-targets.toml`), showing structured resolved entries, proc-macro
surface allowances, a release-age exception, and a bounded advisory
exception:

```toml
[rust]

[[rust.families]]
name = "serde-core-set-2026-05-25"
review_record = "docs/dependency-reviews/2026-05-25-serde-core-set.md"

[rust.families.direct]
serde = "=1.0.228"
serde_json = "=1.0.149"

[rust.families.resolved]
serde = { version = "1.0.228", checksum_sha256 = "9a8e94ea7f378bd32cbbd37198a4a91436180c5bb472411e48b5ec2e2124ae9e" }
serde_json = { version = "1.0.149", checksum_sha256 = "83fc039473c5595ace860d8c4fafa220ff474b3fc6bfdb4293327f1a37e94d86" }
serde_derive = { version = "1.0.228", checksum_sha256 = "d540f220d3187173da220f885ab66608367b6574e925011a9353e4badda91d79" }

[rust.families.allowed_surfaces]
serde_derive = ["proc-macro"]

[[rust.families]]
name = "fast-log-boundary-2026-07-10"
review_record = "docs/dependency-reviews/2026-07-10-fast-log-1.7.7.md"

[rust.families.direct]
fast_log = "=1.7.7"

[rust.families.resolved]
fast_log = { version = "1.7.7", checksum_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }

# Reviewed acceptance of a release younger than release-age policy.
[rust.families.allowed_age_exceptions]
fast_log = "1.7.7"

# Bounded acceptance of an advisory finding, re-reviewed by the deadline.
[rust.families.allowed_advisories]
fast_log = [{ id = "RUSTSEC-2026-0042", review_by = "2026-08-15" }]
```

Prefer `cargo barbican pin add <crate>` and
`cargo barbican pin exception <crate> <advisory-id>` over hand-authoring
family blocks — they copy the resolved version and checksum from
`Cargo.lock` and create the matching review-record stub. See
[commands.md](commands.md).

## Interactions

### `--min-age-days` CLI override

Release-age-aware commands resolve the effective minimum in this order:

1. `--min-age-days N` on the command line, when present;
2. otherwise `[release_age].minimum_days` from `barbican.toml`;
3. otherwise the built-in default of `7`.

The flag is invocation-scoped: it overrides the configured minimum for that
one command run and is not remembered. Reviewed `allowed_age_exceptions`
are honoured through the same shared release-age path regardless of which
source supplied the minimum.

### `deny.toml` delegation boundary

`cargo barbican audit` splits the checked-in `deny.toml` along a firm line:

- **`[advisories]` is forced at runtime.** `audit` never uses a checked-in
  `[advisories]` section. It generates a runtime `cargo-deny` config that
  forces `ignore = []`, `yanked = "deny"`, `unmaintained = "all"`, and
  `unsound = "all"`, and strips graph-exclusion keys that could hide
  advisories (user `targets`/`features` graph scope is preserved). Barbican
  then reconciles the complete finding set against `allowed_advisories`
  exceptions and owns the pass/fail verdict itself. Adding `[advisories]`
  ignores to `deny.toml` therefore cannot weaken the gate — those native
  ignores are neutralised and reported per
  `delegates.unmanaged_delegated_policy`. The same neutralise-and-report
  treatment applies to `.cargo/audit.toml` ignores when `cargo-audit` is
  the configured scanner.
- **`[bans]` and `[sources]` (and `[licenses]`, when enabled) are trusted
  as checked in.** The runtime config preserves the repo's non-advisory
  posture from `deny.toml`; when no `deny.toml` exists, `audit` falls back
  to a generated default base. This is why the `policy init` scaffold's
  `deny.toml` carries bans/sources posture only and deliberately contains
  no `[advisories]` section.

`inventory` reports this boundary without running the scanners: the
configured scanner, checks, unmanaged-ignore policy, any native advisory
ignores found, and whether non-advisory posture would come from a
checked-in `deny.toml` or the generated default base.
