# DD-004: Reviewed Registry Pin Refresh

## Context

Pin drift is an intentional enforcement failure after a dependency move.
`pin add` creates coverage and refuses an existing family; hand-copying
checksums into an existing family made governed recovery unnecessarily awkward.
Existing grant text derives its binding from the family's resolved identity,
so updating that identity while retaining grants would transfer permission.

## Decision

Add `pin refresh <crate>[@version]...` as an offline primitive over existing
registry families. It copies lockfile facts, updates qualifying existing direct
pins, withdraws the changed targets' surface/age/advisory grants and reopens
their existing durable records as PENDING. Preserve untouched identities and
history. Both old and current targets must be crates.io; Git migration/refresh
remains outside this slice.

Prepare one aggregate policy replacement and one append per confined shared
record. Reject protected input/output collisions and ambiguous filesystem aliases.
Write all PENDING records before the single policy replacement. Failure can
retain safe PENDING history; no multi-file transaction is claimed. Preserve
source text through bounded edits and independently expected typed equality.

Add `gatehouse re-pin` as fixed composition: required explicit baseline,
nonempty previous-target parity and newly selected current identity for each
target, then canonical age-lock and strict assessment before refresh. Share
invocation-local release memoisation. Evidence never removes PENDING or
renews permissions.

## Alternatives Considered

- A flag on `pin add` mixes creating coverage with changing reviewed intent.
- Retaining grants would transfer their bindings to a changed artefact.
- Updating pins before evidence leaves avoidable mutations on failed workflows.
- Whole-file TOML serialisation damages policy reviewability; a general editor
  dependency/framework is unnecessary for the bounded source layout.
- A transaction manager would promise more than needed; safe retained PENDING
  and one policy publication provide the required failure direction.

## Consequences

Human completion and any replacement grants remain explicit policy decisions.
Registry-only refresh is intentionally narrower than supported Git intake.
Unsupported layouts/source transitions and checksum-only automatic moves route
to deliberate manual recovery. The existing atomic writer now creates private
exclusive temporary files before content and preserves destination permissions.
The feature introduces no dependency, bot exemption or workflow registry.
