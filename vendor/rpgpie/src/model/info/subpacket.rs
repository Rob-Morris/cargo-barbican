// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Helper functions for subpacket handling

use pgp::packet::{SubpacketData, SubpacketType};

/// A (rather arbitrary) scheme for ordering subpacket output by "relevance"
pub(crate) fn prio(d: &SubpacketData) -> usize {
    match d {
        SubpacketData::SignatureCreationTime(_) => 1,
        SubpacketData::SignatureExpirationTime(_) => 2,

        SubpacketData::IsPrimary(_) => 4,

        SubpacketData::KeyFlags(_) => 5,
        SubpacketData::KeyExpirationTime(_) => 6,

        SubpacketData::RevocationReason(_, _) => 9,

        SubpacketData::IssuerFingerprint(_) => 10,
        SubpacketData::IssuerKeyId(_) => 11,

        SubpacketData::EmbeddedSignature(_) => 12,

        SubpacketData::Features(_) => 19,
        SubpacketData::PreferredAeadAlgorithms(_) => 20,
        SubpacketData::PreferredSymmetricAlgorithms(_) => 21,
        SubpacketData::PreferredHashAlgorithms(_) => 22,
        SubpacketData::PreferredCompressionAlgorithms(_) => 23,
        SubpacketData::PreferredKeyServer(_) => 24,
        SubpacketData::PreferredEncryptionModes(_) => 25,
        SubpacketData::KeyServerPreferences(_) => 26,

        SubpacketData::PolicyURI(_) => 30,

        SubpacketData::TrustSignature(_, _) => 40,
        SubpacketData::RegularExpression(_) => 41,

        SubpacketData::Revocable(_) => 50,
        SubpacketData::ExportableCertification(_) => 51,

        SubpacketData::RevocationKey(_) => 52,
        SubpacketData::SignersUserID(_) => 53,
        SubpacketData::IntendedRecipientFingerprint(_) => 54,
        SubpacketData::SignatureTarget(_, _, _) => 55,

        SubpacketData::Notation(_) => 90,

        _ => 99,
    }
}

pub(crate) fn typ_to_name(typ: SubpacketType) -> &'static str {
    match typ {
        SubpacketType::SignatureCreationTime => "Signature creation",
        SubpacketType::KeyExpirationTime => "Key expiration",
        SubpacketType::SignatureExpirationTime => "Signature expiration",
        SubpacketType::PreferredSymmetricAlgorithms => "Pref symmetric",
        SubpacketType::PreferredHashAlgorithms => "Pref hash",
        SubpacketType::PreferredCompressionAlgorithms => "Pref compression",
        SubpacketType::PreferredAead => "Pref AEAD",
        SubpacketType::PreferredKeyServer => "Pref keyserver",
        SubpacketType::IssuerKeyId => "Issuer Key ID",
        SubpacketType::IssuerFingerprint => "Issuer fingerprint",
        SubpacketType::PrimaryUserId => "Primary User ID",
        SubpacketType::KeyServerPreferences => "Key server preferences",
        SubpacketType::KeyFlags => "Key flags",
        SubpacketType::Features => "Features",
        SubpacketType::EmbeddedSignature => "Embedded signature",
        SubpacketType::Notation => "Notation",
        SubpacketType::RevocationReason => "Reason for Revocation",
        SubpacketType::PolicyURI => "Policy URI",
        SubpacketType::TrustSignature => "Trust Signature",
        SubpacketType::RegularExpression => "Regular Expression",
        SubpacketType::Revocable => "Revocable",
        SubpacketType::ExportableCertification => "Exportable Certification",
        SubpacketType::RevocationKey => "Revocation key",
        SubpacketType::SignersUserID => "Signer's User ID",
        SubpacketType::IntendedRecipientFingerprint => "Intended Recipient Fingerprint",
        SubpacketType::SignatureTarget => "Signature Target",

        _ => "TODO",
    }
}
