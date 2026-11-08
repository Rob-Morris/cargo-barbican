// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The "info" data model represents more or less "raw" OpenPGP data,
//! with very minimal interpretation.

use chrono::{DateTime, Utc};

pub(crate) mod print;
pub(crate) mod subpacket;
pub(crate) mod transform;

#[derive(Debug)]
pub(crate) struct CertInfo {
    pub(crate) primary: KeyInfo,
    pub(crate) subkeys: Vec<KeyInfo>,
    pub(crate) users: Vec<UserInfo>,
    pub(crate) user_attributes: Vec<UserAttributeInfo>,
}

#[derive(Debug)]
pub(crate) struct KeyInfo {
    pub(crate) fingerprint: String,
    pub(crate) created: DateTime<Utc>,
    pub(crate) algorithm: String,
    pub(crate) version: u8,
    pub(crate) revocations: Vec<SigInfo>,
    pub(crate) signatures: Vec<SigInfo>,
}

#[derive(Debug)]
pub(crate) struct UserInfo {
    pub(crate) id: String,
    pub(crate) signatures: Vec<SigInfo>,
}

#[derive(Debug)]
pub(crate) struct UserAttributeInfo {
    pub(crate) id: String, // TODO: what should be in this?
    pub(crate) signatures: Vec<SigInfo>,
}

#[derive(Debug, Clone)]
pub(crate) struct SigInfo {
    pub(crate) typ: pgp::packet::SignatureType,

    pub(crate) hash_algo: String,
    pub(crate) public_key_algo: String,
    pub(crate) version: u8,
    pub(crate) created: DateTime<Utc>, /* redundant with signature creation time subpacket for
                                        * v4+ (but necessary for v2/v3) */
    pub(crate) legacy_issuer: Option<String>, // issuer KeyID for v2/v3 signatures
    pub(crate) hashed: Vec<SubpacketInfo>,
    pub(crate) unhashed: Vec<SubpacketInfo>,
}

#[derive(Debug, Clone)]
pub(crate) struct SubpacketInfo {
    pub(crate) typ: pgp::packet::SubpacketType,

    // TODO: break out a "remark" field, or similar? (e.g. for key expiration?)
    // -> .. or do key expiration math elsewhere?
    pub(crate) value: String,

    pub(crate) critical: bool,
}
