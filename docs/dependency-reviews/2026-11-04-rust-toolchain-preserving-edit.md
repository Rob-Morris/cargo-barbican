# Dependency Review: preserving Rust toolchain channel edit

## Summary

2026-11-04, Astra: first-principles review of a narrow preserving edit using the existing pinned TOML parser. No new dependency or package refresh.

## Classification

Routine source reuse with a guarded configuration-publication boundary owned separately by the binary.

## Targets

Existing toml1.1.2+spec-1.1.0 and serde_spanned1.1.1; unchanged exact source/checksum/features under the existing reviewed family.

## Inheritance

Existing parser provenance remains inherited from its checked-in record. This review covers the additional source-span use, not a new parser-clearance claim.

## Reviewed Target Set

No new target, execution-surface or exception. No toml_edit dependency is added.

## Release Age

Existing exact reviewed versions unchanged; no age exception.

## Advisory Review

Existing integration audit remains applicable; no new graph.

## Source / Upstream Review

Read toml's public Spanned re-export, deserialisation/parser span transport and serde_spanned's byte-range contract. Rather than reserialising the whole document, parse toolchain.channel as Spanned<String>, replace only its checked UTF-8 source range with a validated exact-stable quoted value, reparse and compare to the original semantic tree with only channel changed. Every unrelated source byte is retained. Existing missing/invalid channel shapes refuse; filesystem absence/creation/publication is separate. No general TOML editor or text-pattern substitution is introduced.

The alternative toml_edit0.25.13+spec-1.1.0 parse/display source/features were inspected. A new preserving document tree is unnecessary for this single existing scalar edit; source spans avoid another dependency while providing stronger byte preservation of unrelated content.

## Commands Run

Focused pure tests include Unicode before channel, comments/unrelated fields, standard/dotted/inline tables, quoted keys, literal/basic/multiline values, missing/nonstring/duplicate channel, no-op and unsupported release refusal. Semantic reparse verifies the result in every supported case.

## Outcome

Observed preserving edits pass; no dependency changes. Not a publication, activation, compatibility or admission proof.

## Follow-ups

The binary must separately capture/recheck canonical pin/legacy shadow, permissions and external changes before publication. This pure function does not enforce those filesystem preconditions.
