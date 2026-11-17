# DD-006: Reviewed Cargo Tool Inputs and Native Installation

## Context

Single-crate inspection and a synthetic dependency-project dossier do not
represent a binary crate's actual install graph. Installing a candidate to
discover whether it is trustworthy executes its build-time code too early.
Native tracking also does not establish personal approval, repository authority
or which executable a consumer actually selects.

## Decision

Provide independently composable `tool review`, `accept`, `install`,
`installation-check` and `admission-check` operations. Gatehouse remains the
workflow composition layer. The pure domain owns exact source/selection/graph/
effective-input/evaluator identity and eligibility; binary effects explicitly
pass the verified candidate graph and originating policy to existing inspection
and audit owners. No candidate-provided policy or unrelated family grant can
approve a tool.

Review sources and the real native normal/build graph before candidate
execution. Both crates.io archives and immutable exact Git sources are supported
within explicitly qualified layouts and evaluator tuples. Missing/unusable
upstream locks produce visible derived provenance and a complete effective lock
that must be reviewed before unchanged native installation.

Use ordinary Cargo and normal installation roots with a verified public
`--path` stage and public directory source replacement where needed. Record the
resulting path-backed Cargo tracking honestly and preserve original registry/
Git provenance independently. Never rewrite Cargo's private ledger/cache to
manufacture upstream tracking or silently change source modes.

Keep evidence, completed human assessment, local personal acceptance, optional
repository approval, all installed outputs and actual consumer selection
separate. Refresh online for new operations by default. Explicit short-lived
cached operations retain policy/expiry/adverse checks; unchanged continuing use
has its own exact context. Durable source knowledge separates API, inspection
and advisory channels and keeps incomplete/contradictory observations blocking.

### Review and install progress

The executable starts an operation-scoped stderr worker after validation and
signal registration. The work owners publish fixed phases and numeric counts
to one latest snapshot with one pending wake-up. The worker formats and writes
through an owned duplicate of stderr with the shared state unlocked. Stopping
the scope discards queued work and allows one previously claimed line to finish.
This keeps blocked progress I/O off the cancellation and publication paths.
The controlled-process owner retains its existing native Cargo stream capture
and process-group supervision. The installer checks the artefacts and current
authority before publishing a binding. Injected API callers use a
disabled progress handle.

## Alternatives Considered

- A synthetic library wrapper omits binary-only dependencies and build contexts.
- Installing to inspect executes candidate build code before approval.
- A managed private install root or custom publisher replaces normal Cargo
  semantics and adds operational burden without proving input provenance.
- Private Cargo-cache/ledger mutation couples correctness to internal storage
  and misrepresents native tracking.
- Requiring Cargo's ledger to retain original source identity on every route
  excludes a public qualified path handoff. The maintainer accepted the visible
  tracking/interoperability tradeoff with independent provenance binding.
- One combined approval obscures the distinction between reusable evidence,
  personal execution authority and repository governance.

## Consequences

Users complete review before native build code runs, then receive independently
checkable installation and selection identities. Barbican can review a new
Barbican release only through a separate already trusted checker that survives
replacement. Native update tools may not infer upstream identity from path
tracking; future review uses Barbican's independent record.

The guarantee is static correspondence under a cooperating one-writer model.
Accepted generators remain native execution. Partial publication retains
diagnostics and never claims rollback or a complete installation. Unsupported
hosts, graph protocols, source layouts and first selected shims refuse.
Reproducible builds, hostile concurrent writers and general confinement remain
outside this decision.


## Exact tool exception authoring

Pure `cargo_tool` selects one typed registry finding and validates completion;
binary `tool_intake::exception_authoring` owns confined JSON publication and
comment-preserving configuration edits. The static command does not capture
an evaluator or rerun scanners. Age and assigned-advisory authoring reuses the
existing `ToolException` authority schema and eligibility rules; IOC retains
its separate source-revalidation and record-reference owner.

Pending scaffolds carry exact subject/package/checksum/base-policy bindings,
finite explicit expiry and a zero completion-time sentinel. Only explicit
publication of an unreferenced draft derives completion metadata. Active
records validate unchanged or refuse; retries preserve completed metadata.
The live authority file is finalised before its reference is published, with
captured full configuration, referenced bytes, current policy/time and
cancellation guards. The base hash excludes references for bootstrap, while
full policy identity includes validated grants. These are guarded sequential
writes, not a cross-file transaction; a failure may retain an unreferenced
completed record. Fresh review, assessment and acceptance remain separate.
