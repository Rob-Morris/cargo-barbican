// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Utility functionality to look up and verify the issuers of signatures

use std::collections::HashMap;

use pgp::{
    packet::{PublicKey, Signature, SignatureType, UserId},
    types::{Fingerprint, KeyDetails, KeyId, Tag, Timestamp},
};

use crate::certificate::Checked;

/// A generic lookup helper to find certificates by [`Fingerprint`] or [`KeyId`].
///
/// An index can be created (in different ways) over a set of [`Checked`] certificates, with each
/// certificate getting indexed for any number of [`Fingerprint`]s or [`KeyId`]s, depending on the
/// lookup use case.
///
/// The main use case for this is to find the issuer of a [`Signature`], based on the Issuer
/// Fingerprint or Issuer KeyId subpackets in the Signature.
///
/// The current indexing options are:
///
/// - `index_as_certifier`, which indexes every certificate by its primary key (if it carries the
///   key flag for issuing third-party certifications),
/// - `index_as_data_signer`, which indexes every certificate by the fingerprint/keyid of each
///   component key that has the "data signatures" key flag enable.
pub struct CertificateIndex<'a> {
    /// A list of [`Checked`] per [`Fingerprint`].
    ///
    /// This robustly handles multiple `Checked` per `Fingerprint` (which can occur for collisions,
    /// especially with Fingerprints that use weaker hashes, but also e.g. when component keys are
    /// re-used in different certificates)
    by_fp: HashMap<Fingerprint, Vec<&'a Checked>>,

    /// A list of [`Checked`] per [`KeyId`].
    ///
    /// This robustly handles potential duplicate [`KeyId`]s (which can occur due to collisions,
    /// or because a component key is reused in different certificates).
    by_keyid: HashMap<KeyId, Vec<&'a Checked>>,
}

impl<'a> CertificateIndex<'a> {
    /// Initialize a lookup structure for all certificates in `checked` by the primary key's
    /// identity.
    ///
    /// The lookup index is seeded with the primary key's fingerprint and key id.
    /// This is useful for looking up the issuer of third-party certifying signatures.
    pub fn index_as_certifier(checked: &'a [Checked]) -> Self {
        let index_primary = |cert: &Checked| vec![(cert.fingerprint().clone(), cert.key_id())];

        Self::initialize_index(checked, &index_primary)
    }

    /// Initialize a lookup structure for all certificates in `checked`, used as data signers.
    ///
    /// The lookup index is seeded with the fingerprint and key id of all component keys that
    /// carry the key flag for *data signatures*.
    pub fn index_as_data_signer(checked: &'a [Checked]) -> Self {
        let now = Timestamp::now();

        let index_data_signers = |cert: &Checked| {
            // collect data verifiers, not required to be valid at any particular time
            cert.component_keys()
                .filter(|sckp| {
                    // TODO: also include component keys that are now soft revoked, but previously
                    //       carried the "data signature" key flag?

                    // does this component key have the "data signature" key flag right now?
                    sckp.key_flags_at(now)
                        .map(|flag| flag.sign())
                        .unwrap_or(false)
                })
                .map(|sckp| (sckp.fingerprint(), sckp.legacy_key_id()))
                .collect()
        };

        Self::initialize_index(checked, &index_data_signers)
    }

    /// Generic setup of a `CertificateIndex`
    fn initialize_index(
        checked: &'a [Checked],
        indexer: &dyn Fn(&Checked) -> Vec<(Fingerprint, KeyId)>,
    ) -> Self {
        let mut by_fp = HashMap::new();
        let mut by_keyid = HashMap::new();

        for c in checked {
            for (fp, key_id) in indexer(c) {
                // store for lookup by fingerprint
                let values = by_fp.entry(fp).or_insert(vec![]);
                values.push(c);

                // store for lookup by keyid
                let values = by_keyid.entry(key_id).or_insert(vec![]);
                values.push(c);
            }
        }

        Self { by_fp, by_keyid }
    }

    /// Look up a set of certificates by [`Fingerprint`]
    pub fn lookup_fingerprint(&self, fp: &Fingerprint) -> &[&'a Checked] {
        self.by_fp.get(fp).map_or(&[], |v| v)
    }

    /// Look up a set of certificates by [`Key Id`]
    pub fn lookup_keyid(&self, keyid: &KeyId) -> &[&'a Checked] {
        self.by_keyid.get(keyid).map_or(&[], |v| v)
    }
}

/// A helper for dealing with third-party certification signatures.
///
/// An instance of [`CertifierLookup`] is based on a set of certificates, and can efficiently find
/// and verify the issuer of third-party signatures within that set (or determine that the signer is
/// unknown).
///
/// [`CertifierLookup`] handles two types of third-party signatures:
///
/// - User ID certifications,
/// - Direct key signatures (issued over the primary key).
pub struct CertifierLookup<'a> {
    index: CertificateIndex<'a>,
}

impl<'a> CertifierLookup<'a> {
    /// Initialize a lookup structure for all certificates in `checked`.
    ///
    /// This allows efficient lookup of certificates by both [`Fingerprint`] and [`KeyId`], of the
    /// primary key.
    pub fn new(checked: &'a [Checked]) -> Self {
        let index = CertificateIndex::index_as_certifier(checked);
        Self { index }
    }

    /// Find a cryptographically valid signer for `sig` as a third-party certification over
    /// `signee` and `user_id`.
    ///
    /// If a signer is found, a reference to it is returned, otherwise None.
    pub fn find_userid_signer(
        &self,
        sig: &Signature,
        signee: &PublicKey,
        user_id: &UserId,
    ) -> Option<&'a Checked> {
        // Helper closure: verify signature as user id certification
        let verify = |signee: &PublicKey, signer: &PublicKey| {
            sig.verify_third_party_certification(signee, signer, Tag::UserId, user_id)
                .is_ok()
        };

        self.find_signer(sig, signee, &verify)
    }

    /// Find a cryptographically valid signer for `sig` as a third-party direct key signature over
    /// `signee`.
    ///
    /// If a signer is found, a reference to it is returned, otherwise None.
    pub fn find_direct_key_signer(
        &self,
        sig: &Signature,
        signee: &PublicKey,
    ) -> Option<&'a Checked> {
        // Helper closure: verify signature as third-party direct certification
        let verify = |signee: &PublicKey, signer: &PublicKey| {
            sig.verify_key_third_party(signee, signer).is_ok()
        };

        self.find_signer(sig, signee, &verify)
    }

    /// Find possible signers, based on the Issuer Fingerprint and Issuer Key Id Subpackets in `sig`
    fn candidates(&self, sig: &Signature) -> Vec<&'a Checked> {
        // Possible optimization:
        // Remember (e.g. by HashSet of primary fingerprint), which possible signers we already
        // tried and didn't get a positive check result for, and don't try those again.
        //
        // This would save time if there are many issuer/issuer fingerprint subpackets that don't
        // verify as ok.

        let mut cand = Vec::new();

        // Try to find the signer by Issuer Fingerprint subpacket
        for fp in sig.issuer_fingerprint() {
            for &c in self.index.lookup_fingerprint(fp) {
                cand.push(c);
            }
        }

        // Try to find the signer by Issuer KeyId subpacket
        for keyid in sig.issuer_key_id() {
            for &c in self.index.lookup_keyid(keyid) {
                cand.push(c);
            }
        }

        cand
    }

    /// Generic signer lookup, used for both user id certifications and direct key signatures.
    fn find_signer(
        &self,
        sig: &Signature,
        signee: &PublicKey,
        verify: &dyn Fn(&PublicKey, &PublicKey) -> bool,
    ) -> Option<&'a Checked> {
        self.candidates(sig)
            .into_iter()
            .find(|&c| verify(signee, &c.as_signed_public_key().primary_key))
    }

    /// Filter the third-party user id certifying signatures in `signatures` by policy, as well as
    /// temporal and cryptographic validity, and group them by signer certificate.
    ///
    /// This bulk processing function is useful to process the output of
    /// [`Checked::user_id_third_party_certifications`].
    pub fn valid_userid_certifications(
        &self,
        signatures: &[&'a Signature],
        target: &Checked,
        target_user: &UserId,
        reference_time: Timestamp,
    ) -> Vec<(&'a Checked, Vec<&'a Signature>)> {
        // We only handle (some) certification signature types
        const FILTER: &[Option<SignatureType>] = &[
            Some(SignatureType::CertPositive),
            Some(SignatureType::CertGeneric),
            Some(SignatureType::CertCasual),
            Some(SignatureType::CertRevocation),
        ];

        let lookup = |sig| {
            self.find_userid_signer(sig, &target.as_signed_public_key().primary_key, target_user)
        };

        Self::collect_third_party(signatures, reference_time, Box::new(lookup), FILTER)
    }

    /// Filter the third-party direct key signatures in `signatures` by policy, as well as
    /// temporal and cryptographic validity, and group them by signer certificate.
    ///
    /// This bulk processing function is useful to process the output of
    /// [`Checked::direct_third_party_certifications`].
    pub fn valid_direct_signatures(
        &self,
        signatures: &[&'a Signature],
        target: &Checked,
        reference_time: Timestamp,
    ) -> Vec<(&'a Checked, Vec<&'a Signature>)> {
        // We only handle third-party direct key signatures (and their revocations) here
        const FILTER: &[Option<SignatureType>] = &[Some(SignatureType::Key)];

        let lookup =
            |sig| self.find_direct_key_signer(sig, &target.as_signed_public_key().primary_key);

        Self::collect_third_party(signatures, reference_time, Box::new(lookup), FILTER)
    }

    /// Filters a set of `signatures` for semantical validity, looks up their signers, and returns
    /// all valid third-party certifications grouped by signer.
    fn collect_third_party(
        signatures: &[&'a Signature],
        reference_time: Timestamp,
        lookup: Box<impl Fn(&'a Signature) -> Option<&'a Checked>>,
        sigtype_filter: &[Option<SignatureType>],
    ) -> Vec<(&'a Checked, Vec<&'a Signature>)> {
        let mut map = HashMap::new();

        for &sig in signatures {
            if !sigtype_filter.contains(&sig.typ()) {
                continue;
            }

            // Policy check - is the signature using acceptable algorithms?
            if !crate::signature::signature_acceptable(sig) {
                continue;
            }

            let Some(sig_created) = sig.created() else {
                continue;
            };

            // Filter out if signature creation time is after reference_time
            if sig_created > reference_time {
                log::trace!("skipping signature from the future {:?}", sig);
                continue;
            }

            // Filter out if signature has an expiration time that is before reference_time
            if let Some(exp) = sig.signature_expiration_time()
                && exp.as_secs() != 0
            {
                let expires = Timestamp::from_secs(sig_created.as_secs() + exp.as_secs());

                if expires <= reference_time {
                    log::trace!("skipping expired sig {:?}", sig);
                    continue;
                }
            }

            // Find the signer that has made this signature, if any.
            // This includes a check for cryptographic validity of the signature.
            let Some(signer) = lookup(sig) else {
                // We found no signer, go to the next signature
                continue;
            };

            log::debug!("  found signer: {:?}", signer.fingerprint());

            // TODO: check that the signer's primary has key flag `0x01`

            // Ignore signature if signer is invalid at its creation time
            if !signer.primary_valid_at(sig_created).unwrap_or(false) {
                continue;
            }

            // Ignore signature if signer is invalid at reference time.
            // (NOTE: this disagrees with s-w cert_expired, cert_revoked_soft)
            if !signer.primary_valid_at(reference_time).unwrap_or(false) {
                continue;
            }

            // Store this signature in map
            // let signer_cert = to_certificate(signer);
            let entry: &mut (&Checked, Vec<&Signature>) =
                map.entry(signer.fingerprint()).or_insert((signer, vec![]));
            entry.1.push(sig);
        }

        map.into_values().collect()
    }
}
