# Dependency Review: Zlib permissive licence refinement

## Summary

4 November 2026; first-principles scoped policy refinement for zlib-rs 0.6.8, required by pgp 0.21.0 through flate2 despite disabled default features. Written before any deny.toml change.

## Classification

Elevated-risk policy change. Preserve the permissive-only stance; no copyleft waiver.

## Targets

Zlib-only zlib-rs 0.6.8 archive SHA256 `b268e58e7c693d7c271f93ffc4ba3b380412554231c85bf61ca7af91042a4112`; deliberate addition of `Zlib` to repository licence allow list.

## Inheritance

First-principles actual LICENSE review, independently read on 4 November. The [original licence policy](2026-08-03-licence-policy.md) omitted Zlib because previous packages offered another allowed arm, not because its terms were incompatible.

## Reviewed Target Set

Exact package governed by [public verifier review](2026-11-04-embedded-public-verifier.md); policy integration belongs to root manifest/policy owner.

## Release Age

Published 15 September 2026; older than seven days; non-yanked in 3 November index receipt. Archive digest reverified 4 November.

## Advisory Review

No zlib-rs finding in cited 3 November snapshot; full verifier graph has separately governed findings. This licence record does not suppress advisories.

## Source / Upstream Review

Actual source LICENSE permits commercial use, alteration and redistribution. Requires accurate origin, plainly marked modified versions and retained notice. No source disclosure, copyleft, relinking or downstream licensing obligation. Compatible with the repository permissive stance. Preserve the upstream source notice and identify any modifications. No zlib-rs source modification is proposed.

## Commands Run

Read downloaded exact source LICENSE; independently verified source archive SHA256; read prior repository licence policy.

## Outcome

Accept the explicit minimal Zlib allow-list refinement for this required graph. No unrelated licence changes.

## Follow-ups

Root integration must run the canonical licence gate and retain/remove allowance deliberately if the graph changes.
