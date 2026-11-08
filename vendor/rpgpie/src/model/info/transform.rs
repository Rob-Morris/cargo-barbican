// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Helper functions for producing `info` data structures

use std::time::SystemTime;

use chrono::{DateTime, TimeDelta, Utc};
use hex::ToHex;
use pgp::{
    composed::{SignedPublicKey, SignedPublicSubKey},
    packet::{KeyFlags, Signature, SignatureVersionSpecific, Subpacket, SubpacketData},
    types::{KeyDetails, SignedUser, SignedUserAttribute},
};

use crate::{
    certificate::Certificate,
    model::info::{
        CertInfo,
        KeyInfo,
        SigInfo,
        SubpacketInfo,
        UserAttributeInfo,
        UserInfo,
        subpacket,
    },
    util::algo_name,
};

impl From<&Certificate> for CertInfo {
    fn from(value: &Certificate) -> Self {
        cert_to_info(value, true)
    }
}

pub(crate) fn sig_to_info(
    sig: &Signature,
    key_creation: DateTime<Utc>,
    ordered: bool,
) -> Option<SigInfo> {
    let conf = sig.config()?;
    let created = conf.created()?;
    let sig_created: DateTime<Utc> = SystemTime::from(created).into();

    let legacy_issuer = match conf.version_specific {
        SignatureVersionSpecific::V2 { issuer_key_id, .. }
        | SignatureVersionSpecific::V3 { issuer_key_id, .. } => Some(issuer_key_id.encode_hex()),
        _ => None,
    };

    let si = SigInfo {
        typ: conf.typ,
        hash_algo: conf.hash_alg.to_string(),
        public_key_algo: format!("{:?}", conf.pub_alg),
        version: conf.version().into(),
        created: SystemTime::from(created).into(),
        legacy_issuer,
        hashed: subpackets_to_info(&conf.hashed_subpackets, key_creation, sig_created, ordered),
        unhashed: subpackets_to_info(
            &conf.unhashed_subpackets,
            key_creation,
            sig_created,
            ordered,
        ),
    };

    Some(si)
}

pub(crate) fn primary_key_info(spk: &SignedPublicKey, ordered: bool) -> KeyInfo {
    KeyInfo {
        fingerprint: spk.fingerprint().to_string(),
        created: SystemTime::from(spk.created_at()).into(),
        algorithm: algo_name(spk.primary_key.public_params()),
        version: spk.primary_key.version().into(),
        revocations: spk
            .details
            .revocation_signatures
            .iter()
            .flat_map(|s| sig_to_info(s, SystemTime::from(spk.created_at()).into(), ordered))
            .collect(),
        signatures: spk
            .details
            .direct_signatures
            .iter()
            .flat_map(|s| sig_to_info(s, SystemTime::from(spk.created_at()).into(), ordered))
            .collect(),
    }
}

pub(crate) fn subkey_key_info(sk: &SignedPublicSubKey, ordered: bool) -> KeyInfo {
    KeyInfo {
        fingerprint: sk.fingerprint().to_string(),
        created: SystemTime::from(sk.created_at()).into(),
        algorithm: algo_name(sk.public_params()),
        version: sk.version().into(),
        revocations: vec![],
        signatures: sk
            .signatures
            .iter()
            .flat_map(|s| sig_to_info(s, SystemTime::from(sk.created_at()).into(), ordered))
            .collect(),
    }
}

pub(crate) fn user_info(
    su: &SignedUser,
    primary_created: DateTime<Utc>,
    ordered: bool,
) -> UserInfo {
    UserInfo {
        id: String::from_utf8_lossy(su.id.id()).into(),
        signatures: su
            .signatures
            .iter()
            .flat_map(|s| sig_to_info(s, primary_created, ordered))
            .collect(),
    }
}

pub(crate) fn user_attribute_info(
    sua: &SignedUserAttribute,
    primary_created: DateTime<Utc>,
    ordered: bool,
) -> UserAttributeInfo {
    UserAttributeInfo {
        id: format!("{:?}", sua.attr.typ()), // TODO: what should go here?
        signatures: sua
            .signatures
            .iter()
            .flat_map(|s| sig_to_info(s, primary_created, ordered))
            .collect(),
    }
}

pub(crate) fn cert_to_info(cert: &Certificate, ordered: bool) -> CertInfo {
    let spk = cert.spk();

    let primary = primary_key_info(spk, ordered);

    let subkeys: Vec<_> = spk
        .public_subkeys
        .iter()
        .map(|sk| subkey_key_info(sk, ordered))
        .collect();

    let users: Vec<_> = spk
        .details
        .users
        .iter()
        .map(|su| user_info(su, SystemTime::from(spk.created_at()).into(), ordered))
        .collect();

    let user_attributes: Vec<_> = spk
        .details
        .user_attributes
        .iter()
        .map(|sua| user_attribute_info(sua, SystemTime::from(spk.created_at()).into(), ordered))
        .collect();

    CertInfo {
        primary,
        subkeys,
        users,
        user_attributes,
    }
}

fn subpackets_to_info(
    subpackets: &[Subpacket],
    key_creation: DateTime<Utc>,
    signature_creation: DateTime<Utc>,
    ordered: bool,
) -> Vec<SubpacketInfo> {
    let mut subpackets = subpackets.to_vec();

    if ordered {
        subpackets.sort_by_key(|a| subpacket::prio(&a.data));
    }

    subpackets
        .iter()
        .map(|sp| {
            let value = format_sp_data(&sp.data, key_creation, signature_creation);
            SubpacketInfo {
                typ: sp.typ(),
                value,
                critical: sp.is_critical,
            }
        })
        .collect()
}

pub(crate) fn format_sp_data(
    sp_data: &SubpacketData,
    key_creation: DateTime<Utc>, // relevant primary or subkey creation time for this sp
    signature_creation: DateTime<Utc>, // relevant primary or subkey creation time for this sp
) -> String {
    match sp_data {
        SubpacketData::SignatureCreationTime(created) => {
            let created: DateTime<Utc> = SystemTime::from(*created).into();
            format!("{created}")
        }
        SubpacketData::KeyExpirationTime(duration) => {
            let d: chrono::Duration = TimeDelta::seconds(duration.as_secs() as i64);
            let exp = key_creation + d;

            format!("{} (key creation +{}d)", exp, d.num_days())
        }
        SubpacketData::SignatureExpirationTime(duration) => {
            let d: chrono::Duration = TimeDelta::seconds(duration.as_secs() as i64);
            let exp = signature_creation + d;

            format!("{} (signature creation +{}d)", exp, d.num_days())
        }

        SubpacketData::PreferredSymmetricAlgorithms(algs) => algs
            .iter()
            .map(|a| format!("{a:?}"))
            .collect::<Vec<String>>()
            .join(", "),
        SubpacketData::PreferredHashAlgorithms(algs) => algs
            .iter()
            .map(|a| format!("{a:?}"))
            .collect::<Vec<String>>()
            .join(", "),
        SubpacketData::PreferredCompressionAlgorithms(algs) => algs
            .iter()
            .map(|a| format!("{a:?}"))
            .collect::<Vec<String>>()
            .join(", "),
        SubpacketData::PreferredAeadAlgorithms(algs) => algs
            .iter()
            .map(|a| format!("{a:?}"))
            .collect::<Vec<String>>()
            .join(", "),
        SubpacketData::PreferredKeyServer(server) => server.to_string(),
        SubpacketData::IssuerKeyId(keyid) => keyid.encode_hex::<String>(),
        SubpacketData::IssuerFingerprint(fp) => format!("{fp:?}"),

        SubpacketData::IsPrimary(primary) => format!("{primary}"),
        SubpacketData::KeyServerPreferences(pref) => {
            let pref = if pref[0] & 0x80 != 0 { "no-modify" } else { "" };
            pref.to_string()
        }

        SubpacketData::KeyFlags(flags) => key_flags_to_string(flags).join(", "),

        SubpacketData::Features(feat) => {
            let mut f = Vec::new();

            if feat.seipd_v1() {
                f.push("SEIPDv1")
            }
            if feat.seipd_v2() {
                f.push("SEIPDv2")
            }

            f.join(", ").to_string()
        }

        SubpacketData::EmbeddedSignature(s) => {
            if let (Some(typ), Some(created)) = (s.typ(), s.created()) {
                format!("{typ:?}, {created:?}")
            } else {
                "Unknown".to_string()
            }
        }

        SubpacketData::Notation(n) => format!(
            "{:?}: {}",
            String::from_utf8_lossy(&n.name),
            if n.readable {
                format!("{:?}", String::from_utf8_lossy(&n.value))
            } else {
                n.value.encode_hex()
            }
        ),

        SubpacketData::RevocationReason(code, bytes) => {
            format!("{:?} {:?}", code, String::from_utf8_lossy(bytes))
        }

        SubpacketData::PolicyURI(uri) => uri.to_string(),

        SubpacketData::TrustSignature(depth, amount) => {
            format!("{amount} (depth: {depth})")
        }
        SubpacketData::RegularExpression(regex) => String::from_utf8_lossy(regex).to_string(),

        SubpacketData::Revocable(revocable) => revocable.to_string(),
        SubpacketData::ExportableCertification(exportable) => exportable.to_string(),

        SubpacketData::RevocationKey(key) => format!("{key:?}"),
        SubpacketData::SignersUserID(signer) => String::from_utf8_lossy(signer).to_string(),

        SubpacketData::IntendedRecipientFingerprint(fp) => fp.to_string(),
        SubpacketData::SignatureTarget(pk, hash, bytes) => {
            format!("{bytes:02x?} ({pk:?}, {hash})")
        }

        d => format!("{d:?}"), // TODO: break apart type and value
    }
}

pub(crate) fn key_flags_to_string(flags: &KeyFlags) -> Vec<String> {
    let mut f = Vec::new();

    if flags.certify() {
        f.push("Certify".to_string())
    }

    if flags.encrypt_comms() || flags.encrypt_storage() {
        f.push("Encrypt".to_string())
    }

    if flags.sign() {
        f.push("Sign".to_string())
    }

    if flags.authentication() {
        f.push("Auth".to_string())
    }

    if flags.shared() {
        f.push("Shared".to_string())
    }

    if flags.group() {
        f.push("Group".to_string())
    }

    if flags.adsk() {
        f.push("ADSK".to_string())
    }

    if flags.timestamping() {
        f.push("Timestamp".to_string())
    }

    f
}
