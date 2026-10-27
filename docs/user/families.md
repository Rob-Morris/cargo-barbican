# Manage Reviewed Families

A family groups deliberately reviewed package identities and optional grants
under one named policy entry and review record. Related names do not imply
trust, and family membership gives a new package no execution, age, advisory
or source permission.

Start by discovering the exact configured name and inspecting its scope:

```bash
cargo barbican pin list
cargo barbican pin show 'serialization'
```

The list names selectable families, member counts, review-record content state,
shared review scope and available manifest/lock parity. The detail view includes
exact registry checksums or Git URL/commit identities, direct intent and declared
grants/deadlines. These are diagnostic views, not enforcement verdicts. Missing
or malformed optional lock facts are explicitly unavailable; a missing, empty
or PENDING record does not make a diagnostic view fail or become approved.

Use the exact case-sensitive family name. For a name that looks like an option:

```bash
cargo barbican pin show -- '--help'
cargo barbican pin add --family='--help' serde_derive
```

The end-of-options marker and the equals form keep names distinct from options.
Generated shell suggestions also quote names with spaces, quotes or shell
metacharacters. Views add no metadata/scanner/network/build/test work after
ordinary Cargo workspace discovery; they are not a sandbox around rustup.

## Add Deliberately Selected Members

```bash
cargo barbican pin add --family='serialization' serde_derive serde_json
```

This adds facts from the current `Cargo.lock` to one **existing** family. It
does not infer a group, create a misspelled family, transfer ownership or update
an existing identity. Without `--family`, `pin add <crate>` retains its existing
single-crate/new-family behaviour. Several crates require `--family`.

The complete batch must be valid before any write. New crates.io members need
a checksum; Git members need an admitted credential-free URL and matching full
requested/resolved commit. Every same-name lockfile sibling must agree. A
version argument cannot hide a different source/version/checksum. Duplicate or
foreign-family requests reject the batch. See [Git sources](git-sources.md).

Existing compatible direct-only intent is retained. New registry direct fences
are added only when current declarations are uniformly exact, including aliases
and workspace inheritance; otherwise output explains that only resolved facts
were added. Manifests, existing grants and their deadlines are not rewritten.
New members receive no grants or inherited approval.

Full matching existing members are reported as already present. Mixed batches
add only new members. An all-present batch succeeds without writes, even with
missing/read-only/PENDING evidence or an editor-unsupported valid policy layout.
It still needs real matching source/lock facts, rejects conflicts, and neither
completes review nor proves the independent gates pass.

## Review the Expanded Scope

An actual addition appends one unfinished review section and makes the existing
record PENDING **before** publishing the policy change. Existing history and
markers are preserved. If families share the normalised record path, all of
them reopen together; list/show and the write result name that scope. No record
is silently split or retargeted. Missing, empty, read-only, unsafe or aliased
records refuse active extension rather than being repaired automatically.

Gather the relevant source, advisory and execution-surface evidence, inspect
the policy/record diff, and complete the appended human review. Only then remove
the pending marker deliberately. Existing operator-owned review/branch controls
remain necessary: content completion is not authenticated approval.

```bash
cargo barbican pin show 'serialization'
cargo barbican pin check
cargo barbican gatehouse policy-check
# Run the full execution gate only after the dependency execution is accepted:
cargo barbican gatehouse pre-release
```

Record completion satisfies only the existing review-record condition. Source,
checksum, direct coverage, advisory and toolchain checks retain their current
owners; release-age and assessment remain their separate commands. Neither
diagnostic success nor an addition grants a universal PASS. See
[hardening](hardening.md) for the exact enforced and observational boundaries.

## Unsupported Layouts and Interrupted Publication

The editor supports normal explicit family blocks and the registry/Git member
subtables produced by `pin add`, including repeated extensions. It preserves
unrelated text. Valid but unsupported hand-authored layouts produce a labelled
non-applying proposal and fail without writes. Follow that proposal only as
manual pending-first work; it is not a complete replacement policy.

The command snapshots its inputs and checks path/type/identity/configuration
changes. It writes PENDING evidence before one complete policy replacement.
This is not a transaction across files or protection from a hostile local race.
If a later write fails, evidence can remain PENDING and policy publication may
be uncertain. Inspect the diff, run `pin show` and `pin check`, and resubmit only
appropriate work. Never remove markers or delete shared evidence to recover an
I/O failure. Repeating an all-present request does not deduplicate a previous
record-only append.

Use `pin refresh` for changed existing registry identities. Source migration,
family rename/remove/merge and record repair remain deliberate manual work.
