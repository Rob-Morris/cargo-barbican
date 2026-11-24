# Hosted release-consumer token qualification

## Summary

25 November 2026. User explicitly approved deploying the independently reviewed
inert token proof to the existing public rehearsal, its isolated underware-gg
fork and a separate private fixture. All four actual contexts passed on both
Ubuntu22.04 and ARM64 macOS15 (eight native hosted jobs). This gate passed
before enabling the new generated checker-download default.

## Classification / Targets / Inheritance

Elevated-risk bootstrap boundary; first-principles execution qualification of
the exact CLI/release/provenance interface already source-reviewed in
[the input review](2026-11-25-attested-release-inputs.md). No new tool, Rust
dependency, policy exception, signing authority or candidate execution.

Fixed upstream cli/cli2.100.0 source45437bc7eeeb3359bbfddd1742f79de7652fd3e2;
archive gh_2.100.0_macOS_arm64.zip SHA256
45f9a62da2f6e641a7fad57e2ce39656dfd7ef331372d80a2a2aed65abb01642.
The proof verifies signed release filename/digest/source plus exact provenance
SAN/ref/source/signer/issuer/hosted/numeric repository/owner IDs. It never
extracts or executes the archive. Trusted preinstalled hosted gh supplies the
verifier; local2.100.0 is the first tested baseline. Hosted exact gh version was
not printed; compatible required flags/result schema were observed working.
A version number is not tool provenance.

## Release Age / Advisory Review

The fixed upstream release is established (3 September 2026), previously
reviewed as inert data and trusted verifier source. No crate age/advisory
exception changes. The deliberately outdated serde declaration exists only as
metadata to elicit a real Dependabot PR; neither old nor new fixture dependency
is built/installed/executed by this workflow. Dependabot manages its own remote
resolution; no fixture package is admitted into Barbican's graph.

## Observed witnesses

| Context | Actual event/actor/visibility | Run (attempt1) |
| --- | --- | --- |
| Public | workflow_dispatch, Rob-Morris, private=false | [45509482802](https://github.com/Rob-Morris/barbican-admission-rehearsal/actions/runs/45509482802) |
| Fork PR2 | pull_request, Rob-Morris, head.repo.fork=true | [45509755658](https://github.com/Rob-Morris/barbican-admission-rehearsal/actions/runs/45509755658) |
| Dependabot PR1 | pull_request, dependabot[bot], private=false | [45509567063](https://github.com/Rob-Morris/barbican-admission-rehearsal/actions/runs/45509567063) |
| Private | workflow_dispatch, Rob-Morris, private=true | Run45509691668, URL retained in Brain/private fixture |

Each emitted an actual PASS plus matching context lines on both hosts. Job
permissions are contents:read, with no PAT, OIDC, attestation/write privilege or
user secret. Only fixed public upstream requests were made. The source is
`.github/workflows/qualify-release-consumer.yml`, allowlisted to the isolated
fixture footprint; no checkout occurs. Existing protected admission controller
and tags were preserved.

## Commands Run / Source Custody

Reviewed workflow and inert metadata copied to the approved isolated fixture;
ordinary/private dispatch, genuine fork PR and genuine Dependabot PR; read-only
run/actor/log queries. Full masked logs and compact context receipts retained
in owned temporary evidence and Brain. Workflow SHA256:
`96d0e39c5f2c6de8cdf43161c9896cbecc9588d121fa307a5725dfb8400fb2a9`.

## Outcome / Follow-ups

The pre-default token/transport gate passes for these observed contexts. This
is not the supported installer/action consuming a newly signed Barbican release,
Node24 producer-action execution, minimum-host Barbican payload qualification,
immutable publication or a provider's full compiler/scanner approval. Those
remain separate producer/publication acceptance gates. No fixture/repository
or verification bypass was added to the shipped installer. Consumer source
installation remains explicit. Retire temporary bot triggers/PRs after retaining
evidence; preserve existing rehearsal state and the reusable inert workflow.
