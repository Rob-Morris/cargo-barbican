<!--
SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
SPDX-License-Identifier: MIT OR Apache-2.0
-->

# rpgpie 🦀️🔐🥧

An [OpenPGP](https://openpgp.dev/book/) library based on [rPGP](https://github.com/rpgp/rpgp/). rpgpie is an experimental wrapping API that adds OpenPGP semantics handling on top of the rPGP library.

Central goals of rpgpie include simplicity ✨, collaboration 🤝 and fun 🥳.

## Objectives of rpgpie

More concretely, rpgpie currently has the following objectives:

- Serve as a foundation for the [rsop](https://crates.io/crates/rsop) implementation of [stateless OpenPGP (SOP)](https://datatracker.ietf.org/doc/draft-dkg-openpgp-stateless-cli/).
- Explore the semantics specified in [draft-gallagher-openpgp-signatures](https://datatracker.ietf.org/doc/draft-gallagher-openpgp-signatures/).
- Apply the terminology and conceptual framing of the ["OpenPGP for application developers"](https://openpgp.dev/) documentation.
- Apply a basic policy to rPGP (e.g. to limit acceptance of algorithms over time).
- Experiment with API design and abstractions for application developers who are not deep experts in OpenPGP.

## Limitations and non-objectives

rpgpie does not currently process messages in an efficient, streaming manner. Messages that are too large to be conveniently processed in RAM can currently not be handled with rpgpie.

The rpgpie API currently limits itself to using certificates (also known as "OpenPGP public keys") and TSKs (also known as "OpenPGP secret/private keys") as they are.
Updating or altering certificates or TSKs is currently out of scope.

Error handling is not currently well-elaborated.

API stability is not a focus in the current phase of development.

## Technical Details

rpgpie implements some higher-order OpenPGP facilities:

- **Certificate-level**:

    - OpenPGP semantics on the certificate level, to check for expiration or revocation of certificates on their components.
    - Enumerating component keys that are appropriate for specific purposes (such as creating data signatures, or encrypting messages).
    - ["Merging"](https://openpgp.dev/book/adv/certificates.html#merging) of the information in variants of one certificate.

- **Message-level**:

    - Generate/validate data signatures,
    - Encrypt/decrypt messages.
    - Apply a policy for acceptable cryptographic mechanisms.

## Warning, early-stage project!

rpgpie is in a relatively early stage of development. Use with caution!

In particular:

- Its interface will undergo regular changes, as development continues (the API is also still decidedly incomplete).
- OpenPGP semantics are notoriously underspecified. It's not (yet) fully clear what exact semantics a library like this needs to implement to achieve the best user-facing outcomes.
- Some of the implemented business logic is not currently optimized for efficiency, and may be noticeably slower than it should be.
