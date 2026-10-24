<!-- Synced from cargo-barbican v0.35.0; consumer-owned process: tailor locally and review upstream diffs on upgrade. -->

# Dependency Review Records

This directory contains checked-in records for deliberate dependency updates
and dependency-tool installs.

These files answer:

- what exact versions were reviewed
- whether the change was routine or elevated-risk
- whether the release-age gate was satisfied
- what advisory and source checks were run
- what was finally installed or updated
- whether an active reviewed family was pinned for later execution gating

## When to add a record

Create a new file here when you do any of the following:

- explicit Rust dependency updates
- dependency-tool installs used by the repo workflow, such as `cargo-deny`
- top-level `Cargo.toml` or policy changes that materially expand trust
- any dependency change classified as elevated-risk

## Naming

Use:

```text
YYYY-MM-DD-short-subject.md
```

## Active reviewed families

If a dependency family needs checked-pin enforcement before build or test
execution, record that active family in the repo-root `reviewed-targets.toml`.

For the first Rust-only contract, each active family entry carries:

- `name` — stable family label
- `review_record` — checked-in Markdown record that activated the family
- optional `direct` — exact manifest requirements for direct crates, including
  the leading `=`
- `resolved` — exact `Cargo.lock` targets; for crates.io reviewed artefacts the
  preferred form is `{ version = "...", checksum_sha256 = "..." }`
- optional `allowed_surfaces` — reviewed `build-rs`, `proc-macro`, or
  `native-sys` execution surfaces for crates already present in the same
  `resolved` map
- optional `allowed_age_exceptions` — reviewed release-age exceptions for exact
  crates already present in the same `resolved` map with `checksum_sha256`
- optional `allowed_advisories` — reviewed `RUSTSEC-*` advisory exceptions with
  a `review_by` deadline, for exact crates already present in the same
  `resolved` map with `checksum_sha256`

The gate requires the configured `review_record` path to resolve to a
completed review: a regular non-symlink file that is non-empty and no longer
carries the scaffold marker `BARBICAN-REVIEW-PENDING`. `pin add` and
`pin exception` write that marker into every review-record stub they scaffold,
so `pin check` (and, for advisory exceptions, `audit`) fails a family until a
reviewer completes the record and deletes the marker line — a freshly
scaffolded stub cannot silently satisfy its own gate. Beyond that emptiness and
marker check the gate does not authenticate or parse the record content;
reviewers must still inspect changes to `reviewed-targets.toml` and the cited
record together.

When a crates.io family carries `checksum_sha256`, `pin check` reconciles that
digest against the resolved `Cargo.lock` checksum chain as part of the local
execution gate.

When a reviewed family carries `allowed_surfaces`, `assess` can suppress the
matching execution-surface elevated-risk signal while still rendering the
reviewed exception in an `Allowed policy exceptions:` section. The family
`review_record` is the evidence path for those allowances.

When a reviewed family carries `allowed_age_exceptions`, release-age-aware
commands can allow a matching too-fresh exact `crate@version` only if the
family `review_record` exists and the fetched crates.io checksum matches the
reviewed `resolved.checksum_sha256`. Metadata-only commands compare against
crates.io's published checksum metadata; inspect-backed commands also verify
downloaded tarball bytes. Yanked releases and checksum mismatches remain
blocking.

`inspect` can supply evidence for a review record, but it does not by itself
activate an entry in `reviewed-targets.toml`.

## Required sections

Each record should include:

1. `Summary`
2. `Classification`
3. `Targets`
4. `Inheritance` (prior art, if any — see the note below)
5. `Reviewed Target Set` when the review activates or changes a family in `reviewed-targets.toml`
6. `Release Age`
7. `Advisory Review`
8. `Source / Upstream Review`
9. `Commands Run`
10. `Outcome`
11. `Follow-ups`

The `Inheritance` section records prior art when it exists — an earlier
internal review or a trusted upstream policy the decision builds on. It is not
a prerequisite: an adopter reviewing a crate from first principles, with no
predecessor policy, leaves those fields blank or records `none —
first-principles review`. Most records outside an organisation with an existing
review corpus are first-principles.

## Starting a record

Copy [record-template.md](record-template.md), or use `cargo barbican pin add`
/ `pin exception` to compose source-aware facts from the lockfile. Both start
unapproved. Complete evidence and the decision before removing the pending
marker; removing a marker alone does not make a review authentic.

The eleven headings guide people, not a Markdown policy parser. Git stubs may
append source-specific details and advisory stubs include advisory facts.
For first-principles reviews, record no inheritance; for tool installs, mark
inapplicable graph-family/resolve fields as not applicable and document the
actual tool source, version, build options and trust decision independently.
Do not cite this README or the reusable template as a completed review record.

This process and the sibling template are consumer-owned: tailor them to your
team. Init preserves existing regular files and completed evidence. On upgrade,
review upstream diffs from the matching release rather than replacing local
content. Provenance identifies the starting point; it neither pins the binary
nor invalidates a completed review.

Upstream guidance: [adoption](https://github.com/Rob-Morris/cargo-barbican/blob/v0.35.0/docs/user/adoption.md).
