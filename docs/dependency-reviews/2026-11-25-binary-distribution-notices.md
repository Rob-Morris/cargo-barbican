# Binary distribution notice review

## Summary

25 November 2026. Distribution texts for the unchanged locked graph and trusted
Rust1.95.0 standard library. Accepting a licence in cargo-deny is not delivery
of its required notices. No dependency version or policy exception changes.

## Classification

Elevated-risk distribution boundary. Aggregate the complete locked package set
(including build-only/platform alternatives conservatively), exact declared
licences and available original copyright/licence/notice texts. Refuse missing
text unless a reviewed exact-version supplement exists. This is a bounded
notice assembly review, not a general licence inference service.

## Targets / Inheritance

First-principles packaging of existing reviewed packages. Most sources ship
licence files. Two workspace packages use the root MIT licence. Supplemental
texts in distribution/licenses are fixed by sha256.json:

- bitfields/bitfields-impl1.0.3: exact upstream MIT LICENSE at published
  vcs a3c3d994c87c4f9cab566b3bbb5eb9bd1b2a9a98, blob
  1d50f3bc9ec1074e07d0df492c34621e4141b66b, Gregory Gaines2024.
- crc24 0.1.6: published manifest declares MIT/Apache-2.0; select Apache-2.0
  and retain manifest authors (Sebastian Gesemann). Full standard Apache text
  matches the already reviewed sha2 package's LICENSE-APACHE.
- maintained rpgpie0.12.0: preserved README/source SPDX declaration MIT OR
  Apache-2.0 and Heiko Schaefer attribution; select Apache-2.0. Do not alter
  the guarded vendor tree merely to add distribution material.
- cx4480.1.1: published manifest declares BSD-3-Clause; upstream exact vcs
  58785c9ea154f646d03ccec4185f0a1ffa1c67e5 also omits LICENSE. Reproduce the
  standard declared BSD-3-Clause terms with **all** packaged source copyright
  declarations from macros.rs and curve/montgomery.rs. No invented year or
  copyright assignment to the current maintainer. The README's upstream
  derivations remain included as attribution evidence.
- Rust1.95.0: complete original COPYRIGHT-library.html from the already trusted
  installed toolchain, including standard-library in-tree and third-party
  texts/LLVM exceptions. Preserve its HTML source verbatim in the text bundle.
  Its version and exact hash are a guard against silent reuse after Rust bumps.

## Release Age / Advisory Review

No new dependency code or executable is installed. Existing package, verifier,
Rust and exception reviews retain their authority and deadlines. Text-only
supplements grant no additional execution/admission authority.

## Source / Upstream Review

Cargo's locked offline metadata enumerated225 packages;7 lack top-level licence
files: the2 workspace packages and the5 packages covered above. Inspected exact
packaged manifests, README/source declarations, original text files and Rust's
standard-library inventory. Native linkage inspection must refuse unexpected
linked libraries: GNU libc/libgcc and macOS system libraries are runtime
requirements, not payloads being redistributed. No compiler/scanner binary is
included. The assembler keeps per-package names/versions, declared licence,
source identity, authors, original text filenames and supplemental provenance.

## Commands Run

Locked offline cargo metadata; static licence-file inventory; exact-ref public
GitHub tree/blob reads; local SHA256 inventories. No new upstream code executed.

## Outcome / Follow-ups

Use the bounded exact-version supplements and fail missing/changed text. Keep
notices in every final release and installed root. New dependencies, Rust bumps
or linked native libraries require notice review alongside source review.
