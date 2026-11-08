// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Handling of "primary user id" semantics (especially for v4 certificates)

use pgp::{
    composed::SignedKeyDetails,
    packet::Signature,
    types::{SignedUser, Timestamp},
};

use crate::{signature, signature::SigStack};

/// from a set of user ids, pick the one with the "newest" self-signature
fn pick_by_newest_sig<'a>(users: &'_ [(&'a SignedUser, &'a Signature)]) -> Option<&'a SignedUser> {
    let mut newest: Option<(&'a SignedUser, &'a Signature)> = None;

    for (su, sig) in users {
        match newest {
            None => newest = Some((su, sig)),
            Some((_, stored)) => {
                if stored.created() < sig.created() {
                    newest = Some((su, sig))
                }
            }
        }
    }

    newest.map(|(su, _)| su)
}

/// Return primary User ID:
///
/// We prefer the User ID with the most recent self-signature.
///
/// Either from among all User IDs that are marked "primary".
/// Or from among all User IDs if none are marked "primary".
///
/// (Note: we don't implement looking up the primary User ID at a reference time!)
pub(crate) fn primary_user_id(
    details: &SignedKeyDetails,
    reference: Timestamp,
    key_creation: Timestamp,
) -> Option<&SignedUser> {
    // Find all User IDs that have a non-revoked active signature
    let candidates: Vec<_> = details
        .users
        .iter()
        .map(|su| {
            let stack = SigStack::from_iter(&su.signatures);
            (su, stack.active_at(reference, key_creation))
        })
        .filter_map(|(su, sig)| match (su, sig) {
            (u, Some(sig)) => Some((u, sig)),
            (_, None) => None,
        })
        .filter(|(_, sig)| !signature::is_revocation(sig))
        .collect();

    // TODO: also filter out expired user ids?

    // find all that are marked as primary user ids
    let primary: Vec<_> = candidates
        .clone()
        .into_iter()
        .filter(|(_, s)| s.is_primary())
        .collect();

    if !primary.is_empty() {
        // pick the "primary" with the newest self-sig (based on the signature at "reference")
        pick_by_newest_sig(&primary)
    } else {
        // pick the "candidate" with the newest self-sig (based on the signature at "reference")
        pick_by_newest_sig(&candidates)
    }
}

/// Returns the latest signature of the primary User ID.
/// None, if no primary User ID or binding signature for it are found.
pub(crate) fn primary_user_id_binding_at(
    details: &SignedKeyDetails,
    reference: Timestamp,
    key_creation: Timestamp,
) -> Option<&Signature> {
    primary_user_id(details, reference, key_creation).and_then(|uid| {
        SigStack::from_iter(uid.signatures.iter()).active_at(reference, key_creation)
    })
}
