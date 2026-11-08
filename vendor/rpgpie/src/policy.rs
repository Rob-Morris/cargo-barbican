// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Policy decisions in rpgpie.
//!
//! These include:
//! - Algorithm preferences.
//! - Which algorithms do we accept, for specific operations, depending on context?
//!
//! rpgpie currently couples policy limitations to signature creation timestamps:
//! Obsolete cryptographic mechanisms are considered valid for signatures that show a sufficiently
//! old creation time.
//!
//! This approach represents a tradeoff:
//!
//! - The upside is that old OpenPGP artifacts can be cryptographically validated and used
//!   seamlessly.
//! - The downside is that an attacker may trick users with weak, new (or newly modified) artifacts
//!   that show "old" signature creation timestamps.

use pgp::{
    crypto::{
        aead::{AeadAlgorithm, ChunkSize},
        hash::HashAlgorithm,
        public_key::PublicKeyAlgorithm,
        sym::SymmetricKeyAlgorithm,
    },
    types::{CompressionAlgorithm, EcdhPublicParams, PublicParams, Timestamp},
};

/// FIXME: where should this go? -> upstream to rpgp?
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Seipd {
    SEIPD1,
    SEIPD2,
}

/// Preferred symmetric-key algorithms (in descending order of preference)
pub const PREFERRED_SEIPD_MECHANISMS: &[Seipd] = &[Seipd::SEIPD2, Seipd::SEIPD1];

/// FIXME: what's a good default?
pub const AEAD_CHUNK_SIZE: ChunkSize = ChunkSize::C16KiB;

/// Preferred symmetric-key algorithms (in descending order of preference)
pub const PREFERRED_SYMMETRIC_KEY_ALGORITHMS: &[SymmetricKeyAlgorithm] = &[
    SymmetricKeyAlgorithm::AES256,
    SymmetricKeyAlgorithm::AES192,
    SymmetricKeyAlgorithm::AES128,
];

/// Preferred AEAD algorithms (in descending order of preference)
pub const PREFERRED_AEAD_ALGORITHMS: &[(SymmetricKeyAlgorithm, AeadAlgorithm)] = &[
    (SymmetricKeyAlgorithm::AES256, AeadAlgorithm::Ocb),
    (SymmetricKeyAlgorithm::AES192, AeadAlgorithm::Ocb),
    (SymmetricKeyAlgorithm::AES128, AeadAlgorithm::Ocb),
    (SymmetricKeyAlgorithm::AES256, AeadAlgorithm::Eax),
    (SymmetricKeyAlgorithm::AES192, AeadAlgorithm::Eax),
    (SymmetricKeyAlgorithm::AES128, AeadAlgorithm::Eax),
];

/// Preferred hash algorithms (in descending order of preference)
pub const PREFERRED_HASH_ALGORITHMS: &[HashAlgorithm] = &[
    HashAlgorithm::Sha512,
    HashAlgorithm::Sha384,
    HashAlgorithm::Sha256,
];

/// Preferred hash algorithms for new V6 keys (in descending order of preference)
pub const PREFERRED_HASH_ALGORITHMS_V6: &[HashAlgorithm] = &[
    HashAlgorithm::Sha512,
    HashAlgorithm::Sha3_512,
    HashAlgorithm::Sha384,
    HashAlgorithm::Sha256,
    HashAlgorithm::Sha3_256,
];

/// Hash algorithms that we accept for ECDH encryption
const ACCEPTABLE_HASH_ALGORITHMS_ECDH: &[HashAlgorithm] = &[
    HashAlgorithm::Sha512,
    HashAlgorithm::Sha384,
    HashAlgorithm::Sha256,
];

/// Preferred compression algorithms (in descending order of preference)
pub const PREFERRED_COMPRESSION_ALGORITHMS: &[CompressionAlgorithm] = &[];

/// How many layers deep are we willing to unpack into a message?
pub const MAX_RECURSION: usize = 10;

/// Cutoff time for MD5 hash acceptance: January 1, 2010 12:00:00 AM (GMT)
const MD5_REJECT_AFTER: u32 = 1262304000;

/// Cutoff time for SHA1 hash acceptance in data signatures: January 1, 2014 12:00:00 AM (GMT)
/// (See https://csrc.nist.gov/projects/hash-functions)
const SHA1_FOR_DATA_REJECT_AFTER: u32 = 1388534400;

/// Cutoff time for SHA1 hash acceptance: February 1, 2023 12:00:00 AM (GMT)
const SHA1_REJECT_AFTER: u32 = 1675209600;

/// Cutoff time for RSA <2k bits acceptance: January 1, 2014 12:00:00 AM (GMT)
/// (e.g. NIST guidance was to drop RSA 1k after 2013).
const RSA_UNDER_2K_REJECT_AFTER: u32 = 1388534400;

const RSA_UNDER_2K_CUTOFF_BIT_SIZE: usize = 2048;

/// Cutoff time for validation and creation of DSA signatures: February 3, 2023 12:00:00 AM (GMT)
/// See https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
const DSA_REJECT_AFTER: u32 = 1675382400;

/// Returns our policy about the general acceptability of a `PublicParams` at a reference time.
pub(crate) fn acceptable_pk_algorithm(pp: &PublicParams, reference: Timestamp) -> bool {
    if let PublicParams::RSA(rsa) = pp {
        use rsa::traits::PublicKeyParts;

        // The bits() function accounts for leading zero bits
        let rsa_bits = rsa.key.n().bits();

        // Reject RSA with key size under 2048 bit, after 31.12.2013
        if rsa_bits < RSA_UNDER_2K_CUTOFF_BIT_SIZE
            && reference.as_secs() > RSA_UNDER_2K_REJECT_AFTER
        {
            return false;
        }
    }

    if let PublicParams::DSA { .. } = pp {
        // Reject DSA after 03.02.2023
        if reference.as_secs() > DSA_REJECT_AFTER {
            return false;
        }
    }

    true
}

/// Returns our policy about a `HashAlgorithm` at a reference time.
///
/// Note that we reject SHA-1 at different dates, depending on whether it is used for data
/// signatures or structural signatures.
pub(crate) fn acceptable_hash_algorithm(
    hash_algo: HashAlgorithm,
    reference: Timestamp,
    data_signature: bool,
) -> bool {
    // #![allow(clippy::match_like_matches_macro)]
    match hash_algo {
        // Consider MD5 signatures invalid if they claim to have been made after the cutoff
        // timestamp.
        HashAlgorithm::Md5 => {
            // only return "true" for legacy signatures, false for new ones
            MD5_REJECT_AFTER > reference.as_secs()
        }

        // Consider SHA1 signatures invalid if they claim to have been made after the cutoff
        // timestamp.
        HashAlgorithm::Sha1 => {
            // only return "true" for legacy signatures, false for new ones

            match data_signature {
                true => SHA1_FOR_DATA_REJECT_AFTER > reference.as_secs(),
                false => SHA1_REJECT_AFTER > reference.as_secs(),
            }
        }

        HashAlgorithm::Ripemd160 => {
            // FIXME: reject RIPEMD160 (RFC 9580) [starting when?]
            true
        }

        _ => true,
    }
}

/// Return our policy about acceptable encryption mechanisms.
///
/// Note that encryption happens "now", by definition, so we're not allowing historical algorithms
/// (which we may still allow for decryption of historical data).
pub(crate) fn accept_for_encryption(pp: &PublicParams) -> bool {
    match pp {
        PublicParams::ECDH(
            EcdhPublicParams::Curve25519Legacy { hash, alg_sym, .. }
            | EcdhPublicParams::P256 { hash, alg_sym, .. }
            | EcdhPublicParams::P384 { hash, alg_sym, .. }
            | EcdhPublicParams::P521 { hash, alg_sym, .. },
        ) => {
            if !ACCEPTABLE_HASH_ALGORITHMS_ECDH.contains(hash) {
                return false;
            }
            if !PREFERRED_SYMMETRIC_KEY_ALGORITHMS.contains(alg_sym) {
                return false;
            }

            true
        }
        _ => true,
    }
}

/// Return our policy about acceptable public key mechanisms for signatures.
///
/// This policy applies validation of existing signatures based on their (claimed) creation time,
/// and to issuing new signatures.
pub(crate) fn accept_for_signatures(pk_alg: PublicKeyAlgorithm, reference: Timestamp) -> bool {
    if pk_alg == PublicKeyAlgorithm::DSA {
        // Only allow DSA signatures until the cutoff date (03.02.2023)
        reference.as_secs() <= DSA_REJECT_AFTER
    } else {
        true
    }
}
