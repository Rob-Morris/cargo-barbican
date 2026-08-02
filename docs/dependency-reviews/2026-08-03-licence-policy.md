# Dependency Review: deny.toml licence policy

## Summary

- Date: 2026-08-03
- Reviewer: Rob Morris
- Scope: declare a `[licenses]` policy in the repo-root `deny.toml` so cargo-barbican enforces licence checking on its own dependency graph

## Classification

- Routine or elevated-risk: elevated-risk
- Reason:
  - repo policy change to `deny.toml`, which the canary treats as elevated-risk regardless of outcome
  - the change activates a previously inactive gate, so it alters what `cargo barbican audit` blocks on

## Targets

- `deny.toml` -> new `[licenses]` table with an explicit `allow` list and `unused-allowed-license = "warn"`

No crate versions change. `Cargo.lock` and both crate manifests are untouched.

## Inheritance

- Upstream record: none
- Trust model match: n/a
- Deltas from upstream: n/a — first-principles review. The prior `deny.toml`
  baseline inherited from undertask carried no `[licenses]` table, so there is
  no upstream licence policy to inherit.

## Reviewed Target Set

- Active family name: n/a
- `reviewed-targets.toml` updated: no

This record activates a cargo-deny policy check, not a reviewed dependency
family. No `reviewed-targets.toml` entry is created or changed.

## Release Age

- Minimum policy: 7 days
- Observed publish date / age: n/a — no dependency is added, updated, or removed
- Pass / fail: n/a

## Advisory Review

- Sources checked: n/a for a licence-policy change; the advisories check is
  unaffected and continues to run
- Findings: none

## Source / Upstream Review

Enumerated every licence expression in the resolved graph under
`--all-features` and derived the minimal allow list — each entry is required by
at least one crate, so an unused entry becomes a signal to re-review rather
than dead permissiveness.

Entries and why each is required:

| Licence | Required by | Notes |
|---|---|---|
| `MIT` | the bulk of the graph | satisfies most `MIT OR Apache-2.0` expressions |
| `Apache-2.0` | `ring` | its `Apache-2.0 AND ISC` needs both halves |
| `ISC` | `rustls-webpki`, `untrusted`, `ring` | sole licence for the first two |
| `Unicode-3.0` | `unicode-ident` | `(MIT OR Apache-2.0) AND Unicode-3.0` |
| `BSD-3-Clause` | `subtle` | sole licence, no alternative offered |
| `CDLA-Permissive-2.0` | `webpki-roots` | sole licence, no alternative offered |

All six are OSI-approved permissive licences. No copyleft licence (GPL, LGPL,
AGPL, MPL) is accepted, and none appears in the current graph.

Deliberately **not** allowed, because each is only ever offered as one arm of an
`OR` expression already satisfied by `MIT` or `Apache-2.0`: `0BSD` (`adler2`),
`Zlib` (`miniz_oxide`), `Unlicense` (`memchr`), and
`Apache-2.0 WITH LLVM-exception` (`wasi`). Keeping them out holds the allow list
to what the graph genuinely requires.

`filetime` and `version_check` declare the deprecated `MIT/Apache-2.0` slash
form; cargo-deny parses it as a disjunction and both resolve to `MIT`.

## Commands Run

```bash
cargo metadata --format-version 1 --all-features
cargo deny check licenses
cargo run --locked --bin cargo-barbican -- audit
sh scripts/verify.sh
```

## Outcome

- Installed / updated: `deny.toml` gained a `[licenses]` table; no dependency change
- Verification:
  - `cargo deny check licenses` returned `licenses ok` (exit 0)
  - `cargo barbican audit` now reports
    `cargo-deny licenses check: enforced (deny.toml declares a [licenses] policy)`,
    where it previously reported
    `skipped (no [licenses] policy in deny.toml)`
  - `sh scripts/verify.sh` passed

## Follow-ups

- A new dependency introducing a licence outside the allow list will fail
  `audit` closed. That is intended: the fix is a first-principles review of the
  new licence and an explicit record, not a silent allow-list append.
- `unused-allowed-license = "warn"` surfaces entries that stop being required;
  treat a warning as a prompt to drop the entry and record why.
