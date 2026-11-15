# DD-002: Exact Reviewed IOC Findings

## Context

Literal process/network tokens provide useful static review evidence but do not
prove maliciousness. A package-level aggregate blocker cannot distinguish a
reviewed expected operation from another unresolved finding. Registry and exact
Git source custody, repository policy and exact tool-subject authority also have
different meanings that must not be merged.

## Decision

One pure `ioc` owner defines maintained rules, declared heuristic scope, bounded
original-byte occurrences, stable exact source/file/rule identities, portable
review records and adjudication. Registry and Git adapters supply verified
original inputs. Missing or truncated coverage is independent from a finding's
reviewed disposition. No executable pattern engine is introduced.

`ioc check` independently checks exact registry, exact Git or explicit lockfile
external-source sets without Cargo discovery. `ioc review` only scaffolds
portable PENDING rationale. `pin exception --ioc` and `tool exception --ioc`
attach their respective current authority, using the same review model.
Repository IOC references are independent of active families so pre-add review
does not falsely adopt or pin a package. Tool grants additionally bind exact
Subject/base policy and do not replace acceptance or repository admission.

Completed records bind full exact findings, including every occurrence, with an
optional explicit review deadline. Current record bytes, source/rule/scope and
origin policy are revalidated. Raw adverse observations are retained and shared
across standalone checks and tool lifecycle decisions. An allowance accounts
for exact IOC causes only; checksum, coverage and unrelated policy failures
remain independent blockers.

Gatehouse composes locked-source checking only through explicit `--ioc`.
Existing inspect retains its broader risk verdict and verify retains its current
responsibilities. Locked-source coverage includes inactive external versions
and labels source-less entries outside scope; it does not claim a compilation
graph or mutable workspace-code coverage.

## Alternatives Considered

- Crate-wide ignores lose per-file/rule accountability and can cover new hits.
- Treating all textual hits as unconditionally malicious makes exact justified
  review impossible while overstating detector knowledge.
- Making general inspect the new narrow gate would mix IOC decisions with its
  independent age and elevated execution-risk exit semantics.
- Adding metadata resolution to lock-source inspection would introduce candidate
  configuration and evaluator requirements without improving that named scope.
- Copying a completed review into a tool grant without current record reads
  would obscure revocation and transfer authority unintentionally.

## Consequences

The same immutable finding can be explained once and deliberately referenced by
separate authorities. Source reports remain inspectable after acceptance, and
new findings require new decisions. More complete source/custody evidence may
still fail for an unsupported layout or bounded resource limit. A passing IOC
check is a scoped policy result, never a benignness proof or permission to run
candidate code.

See [the user workflow](../../user/ioc.md) and
[the CLI contract](../../functional/cli.md#ioc-source-inspection-and-reviewed-findings).
