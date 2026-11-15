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
