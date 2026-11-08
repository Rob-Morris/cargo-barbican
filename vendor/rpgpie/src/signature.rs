// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Handling of OpenPGP signatures.

use std::{borrow::Cow, io};

use pgp::{
    composed::{Deserializable, DetachedSignature},
    packet::{Packet, RevocationCode, Signature, SignatureConfig, SignatureType, SubpacketData},
    ser::Serialize,
    types::{Fingerprint, Timestamp},
};

use crate::{
    Error,
    certificate::Certificate,
    policy::{accept_for_signatures, acceptable_hash_algorithm},
};

/// Models a signature that was found to be cryptographically valid.
///
/// - `sig`: The validated signature
/// - `component`: Fingerprint of the component key that validated the signature
/// - `certs`: Candidate certs that contain `component` (with metadata that allows data signing)
pub struct Verified<'c, 's> {
    pub sig: Cow<'s, Signature>,
    pub component: Fingerprint,
    pub certs: Vec<&'c Certificate>,
}

fn is_data_type(typ: Option<SignatureType>) -> bool {
    matches!(typ, Some(SignatureType::Binary) | Some(SignatureType::Text))
}

pub(crate) fn is_revocation_type(typ: SignatureType) -> bool {
    matches!(
        typ,
        SignatureType::KeyRevocation
            | SignatureType::CertRevocation
            | SignatureType::SubkeyRevocation
    )
}

pub(crate) fn is_revocation(sig: &Signature) -> bool {
    if let Some(typ) = sig.typ() {
        is_revocation_type(typ)
    } else {
        false
    }
}

/// Checks for explicitly "soft" reason codes.
/// In all other cases, we consider a revocation to be "hard".
fn is_soft_revocation_reason(reason: Option<&RevocationCode>) -> bool {
    matches!(
        reason,
        Some(RevocationCode::KeyRetired)
            | Some(RevocationCode::CertUserIdInvalid)
            | Some(RevocationCode::KeySuperseded)
    )
}

pub(crate) fn is_hard_revocation(sig: &Signature) -> bool {
    if is_revocation(sig) {
        // this is a revocation, but is it a hard revocation?
        !is_soft_revocation_reason(sig.revocation_reason_code())
    } else {
        // this signature is not a revocation
        false
    }
}

/// Does this signature contain unknown critical subpackets or notations?
fn unknown_critical(config: &SignatureConfig) -> bool {
    for sp in &config.hashed_subpackets {
        if sp.is_critical
            && let SubpacketData::Notation(_notation) = &sp.data
        {
            // Unknown critical notation (by default)
            // FIXME: how would an application use critical notations? initialize rpgpie with a
            // good-list?
            return true;
        }
    }

    false
}

/// Check if a signature meets our basic acceptability criteria, in particular regarding the
/// cryptographic primitives it uses.
///
/// In particular, signatures are rejected when they use weak cryptographic mechanisms.
/// Acceptability of algorithms is based on the (claimed) signature creation time:
///
/// - MD5 hashes are considered broken effective January 1, 2010.
/// - SHA-1 hashes for data signatures are considered broken effective January 1, 2014;
/// - SHA-1 hashes for other signature types are considered broken effective February 1, 2023.
/// - DSA signatures are considered unacceptable starting February 3, 2023.
///
/// From a caller's point of view, rpgpie handles signatures that use rejected mechanisms as though
/// they didn't exist, or as though they were cryptographically invalid.
///
/// Rejecting signatures that are technically correct, but use questionable primitives, is a
/// defensive tradeoff: We consider such signatures either attacks or grave mistakes, when they
/// self-report to have been created at a relatively late point in time.
///
/// These additional formal checks are applied:
/// - Rejects signatures that have no creation time stamp set in the hashed area
/// - Rejects signatures that contain unknown critical subpackets
pub fn signature_acceptable(sig: &Signature) -> bool {
    let Some(sig_creation_time) = sig.created() else {
        return false;
    };

    let Some(config) = sig.config() else {
        return false;
    };

    // Unknown critical elements invalidate a signature
    if unknown_critical(config) {
        return false;
    }

    // reject signature if our policy rejects the hash algorithm at signature creation time
    if !acceptable_hash_algorithm(config.hash_alg, sig_creation_time, is_data_type(sig.typ())) {
        return false;
    }

    // reject signature if our policy rejects the signature's public key algorithm at creation time
    if !accept_for_signatures(config.pub_alg, sig_creation_time) {
        return false;
    }

    true
}

/// True for signatures that have a creation time at or after `reference`.
///
/// This is useful to check that a signature doesn't claim to have been created before they key
/// that supposedly issued the signature.
pub(crate) fn not_older_than(sig: &Signature, key_created: Timestamp) -> bool {
    sig.created()
        .is_some_and(|sig_created| sig_created >= key_created)
}

/// True for signatures that have a creation time at or before `reference`.
///
/// This is useful to check that a signature is "active" at `reference`, and not "from the future".
fn not_newer_than(sig: &Signature, reference: Timestamp) -> bool {
    sig.created()
        .is_some_and(|sig_created| sig_created <= reference)
}

/// How long is `sig` valid?
///
/// Some(dt): valid until `dt`
/// None: unlimited validity
///
/// NOTE: Also returns `None` if `sig` has no creation time.
pub(crate) fn signature_validity_expiration(sig: &Signature) -> Option<Timestamp> {
    let Some(sig_creation) = sig.created() else {
        // This is an error case, but we don't handle it here.
        // Callers are expected to handle it independently of this fn.
        return None;
    };

    if let Some(sig_expiration) = sig.signature_expiration_time() {
        if sig_expiration.as_secs() != 0 {
            Some(Timestamp::from_secs(
                sig_creation.as_secs() + sig_expiration.as_secs(),
            ))
        } else {
            None
        }
    } else {
        None
    }
}

/// Read a list of Signatures from an input
pub fn load<R: io::Read>(source: &mut R) -> Result<Vec<Signature>, Error> {
    let (iter, _header) = DetachedSignature::from_reader_many(source)?;

    let mut sigs = vec![];

    for res in iter {
        match res {
            Ok(sig) => sigs.push(sig.signature),
            Err(e) => return Err(Error::Message(format!("Bad data: {e:?}"))),
        }
    }

    Ok(sigs)
}

/// Write a list of Signatures to an output
pub fn save(
    signatures: &[Signature],
    armored: bool,
    mut sink: &mut dyn io::Write,
) -> Result<(), Error> {
    if armored {
        // Only emit armor checksum if any of the signatures is pre-v6
        let armor_checksum = signatures.iter().any(|sig| u8::from(sig.version()) < 6);

        let packets: Vec<_> = signatures.iter().map(|s| Packet::from(s.clone())).collect();

        pgp::armor::write(
            &packets,
            pgp::armor::BlockType::Signature,
            &mut sink,
            None,
            armor_checksum,
        )?;
    } else {
        for s in signatures {
            let p = Packet::from(s.clone());
            p.to_writer(&mut sink)?;
        }
    }

    Ok(())
}

#[derive(Debug)]
pub(crate) struct SigStack<'inner> {
    hard: Vec<&'inner Signature>,
    soft: Vec<&'inner Signature>,
    regular: Vec<&'inner Signature>,

    #[allow(dead_code)]
    invalid: Vec<&'inner Signature>,

    #[allow(dead_code)]
    third_party: Vec<&'inner Signature>,
}

impl<'a> FromIterator<&'a Signature> for SigStack<'a> {
    fn from_iter<T: IntoIterator<Item = &'a Signature>>(iter: T) -> Self {
        let mut hard = vec![];
        let mut soft = vec![];
        let mut regular = vec![];
        let mut invalid = vec![];
        let third_party = vec![];

        // FIXME: pre-process?
        // - Different Enum variants based on hard-revoked vs. not?
        // - Sort signatures by creation time?
        // - Calculate time spans for validity of the component?

        for sig in iter.into_iter() {
            if is_hard_revocation(sig) {
                hard.push(sig)
            } else if is_revocation(sig) {
                soft.push(sig)
            } else if signature_acceptable(sig) {
                regular.push(sig)
            } else {
                invalid.push(sig)

                // FIXME: handle third party sigs
            }
        }

        // sort `regular` by signature creation time
        regular.sort_by(|a, b| {
            a.created()
                .map(Timestamp::as_secs)
                .cmp(&b.created().map(Timestamp::as_secs))
        });

        Self {
            hard,
            soft,
            regular,
            invalid,
            third_party,
        }
    }
}

impl<'a> SigStack<'a> {
    /// Get the currently active signature in this stack at a reference time.
    pub(crate) fn active_at(
        &self,
        reference: Timestamp,
        key_creation: Timestamp,
    ) -> Option<&'a Signature> {
        log::debug!("search active_at: {reference:?}");

        // If there is any hard revocation, it is always active.
        // (If there are multiple hard revocations, picking a specific one seems pointless)
        if let Some(&hard) = self.hard.first() {
            log::debug!(
                " found hard: {}",
                hard.created()
                    .map(|dt| format!("{dt:?}"))
                    .unwrap_or("<no creation time>".to_string())
            );
            return Some(hard);
        }

        /// Replace content of `cur` with `s`, if `s` was created later
        fn replace_if_newer<'a>(cur: &mut Option<&'a Signature>, s: &'a Signature) {
            if let Some(cur) = cur {
                if let Some(sig_created) = s.created()
                    && let Some(cur_created) = cur.created()
                    && cur_created < sig_created
                {
                    *cur = s;
                }
            } else {
                *cur = Some(s);
            }
        }

        // If any soft revocations exist that are created <= `reference`, we return the latest of
        // them.
        let mut latest_soft: Option<&Signature> = None;
        self.soft
            .iter()
            .filter(|&&s| {
                // signature creation time before issuer `key_creation` is invalid
                not_older_than(s, key_creation)
            })
            .filter(|&&s| {
                // only consider signatures that were created at or before the reference time
                not_newer_than(s, reference)
            })
            .for_each(|s| {
                // replace "latest_soft" with any newer soft revocation
                replace_if_newer(&mut latest_soft, s);
            });

        if let Some(latest_soft) = latest_soft {
            log::debug!(
                " found soft: {}",
                latest_soft
                    .created()
                    .map(|dt| format!("{dt:?}"))
                    .unwrap_or("<no creation time>".to_string())
            );
            return Some(latest_soft);
        }

        // We're willing to accept "regular signatures" up to the current timestamp ("now").
        //
        // This can be needed in cases of certificate minimization, where we have no historical
        // signatures available. In such cases, in OpenPGP semantics, the intent of the certificate
        // holder is assumed to be that their newest self-certification should also specify the
        // component's properties at earlier points in time.
        let now = Timestamp::now();

        // Otherwise we return the latest regular signature, if any
        let mut latest_before_reference: Option<&Signature> = None;
        let mut latest_before_now: Option<&Signature> = None;

        self.regular
            .iter()
            .filter(|&&s| {
                // signature creation time before issuer `key_creation` is invalid
                not_older_than(s, key_creation)
            })
            .filter(|&&s| {
                // only consider signatures that were created at or before "now"
                not_newer_than(s, now)
            })
            .filter(|s| {
                if let Some(expired) = signature_validity_expiration(s) {
                    // only consider signatures whose validity doesn't end before the reference time
                    expired > reference
                } else {
                    true
                }
            })
            .for_each(|s| {
                // the `regular` signatures are ordered, we use this to pick either the
                // newest signature from before the `reference` time, or from before `now`

                if let Some(c) = s.created() {
                    if c <= reference {
                        // replace "latest" with any newer Signatures that we didn't filter out
                        // above
                        replace_if_newer(&mut latest_before_reference, s);
                    } else {
                        replace_if_newer(&mut latest_before_now, s);
                    }
                }
            });

        let latest = match (latest_before_reference, latest_before_now) {
            (Some(before_reference), _) => Some(before_reference),
            (_, before_now) => before_now,
        };

        if let Some(latest) = latest {
            log::debug!(
                " latest regular: {}",
                latest
                    .created()
                    .map(|dt| format!("{dt:?}"))
                    .unwrap_or("<no creation time>".to_string())
            );
        }

        latest
    }
}

/// Checks if two signature packets contain the same cryptographic signature.
///
/// This type of equality usually means: the signature has been made over the same data, with the
/// same key material.
///
/// Two otherwise equivalent signature packets are equal in the sense of this function if they
/// differ only in packet framing and/or unhashed subpackets.
pub(crate) fn signature_bytes_eq(a: &Signature, b: &Signature) -> bool {
    if let (Some(sb1), Some(sb2)) = (a.signature(), b.signature()) {
        sb1 == sb2
    } else {
        // rpgp doesn't know about the inner details of this signature, so we can only do a
        // bitwise comparison
        a == b
    }
}

/// Merge additional signature information from `updates` into `target`.
///
/// - Entirely missing signatures are added verbatim.
/// - For signatures that already exist in target, according to `signature_bytes_eq`, any additional
///   unhashed subpackets from `updates` are merged into the pre-existing signature.
pub(crate) fn merge_signatures(target: &mut Vec<Signature>, updates: Vec<Signature>) {
    for upd in updates {
        if let Some(orig) = target.iter_mut().find(|s| signature_bytes_eq(s, &upd)) {
            // We have a signature with these signature bytes already
            // -> merge unhashed area content from `upd` into `orig`
            merge_unhashed(orig, &upd);
        } else {
            // target doesn't have these signature bytes yet
            target.push(upd); // FIXME: ordering?
        }
    }
}

/// Merge additional unhashed subpackets from `source` into `target`, if any
pub(crate) fn merge_unhashed(target: &mut Signature, source: &Signature) {
    let mut inserts = Vec::new();

    if let (Some(c1), Some(c2)) = (target.config(), source.config()) {
        for (n, sub) in c2.unhashed_subpackets.iter().enumerate() {
            if !c1.unhashed_subpackets.contains(sub) {
                inserts.push((n, sub.clone()));
            }
        }
    }

    for (pos, sp) in inserts {
        // try to insert the subpacket at the same position as in `source`
        let _ = target.unhashed_subpacket_insert(pos, sp); // FIXME: error handling
    }
}
