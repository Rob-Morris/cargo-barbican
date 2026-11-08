// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::time::SystemTime;

use pgp::{
    composed::{SignedKeyDetails, SignedPublicKey, SignedPublicSubKey},
    crypto::{aead::AeadAlgorithm, hash::HashAlgorithm, sym::SymmetricKeyAlgorithm},
    packet::{Features, Signature, SubpacketData, SubpacketType, UserId},
    types::{
        Duration,
        Fingerprint,
        KeyDetails,
        KeyId,
        KeyVersion,
        SignedUser,
        SignedUserAttribute,
        Tag,
        Timestamp,
    },
};

use crate::{
    Error,
    certificate::{Certificate, SignatureVerifier},
    key::{ComponentKeyPub, SignedComponentKeyPub},
    policy,
    primary_userid::primary_user_id_binding_at,
    signature,
    signature::SigStack,
    util,
};

/// A layer on top of [Certificate] that filters out any signatures that we don't consider valid.
///
/// A `Checked` certificate only contains Signatures that have been verified to be cryptographically
/// correct.
/// See <https://openpgp.dev/book/verification.html#when-are-signatures-valid>
///
/// This is a precondition for signatures being considered fully valid, but by itself insufficient.
///
/// Note: The checked representation currently removes all third-party signatures
/// (because they can't be cryptographically checked in the context of looking at an individual
/// certificate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checked {
    /// Unfiltered view of the SignedPublicKey that this Checked was created from
    original: SignedPublicKey,

    /// Checked and filtered representation of the original SignedPublicKey
    cspk: SignedPublicKey,

    /// Cached value for efficient third-party fp checks
    primary_fingerprint: Fingerprint,

    /// Cached value for efficient third-party fp checks
    primary_key_id: KeyId,
}

impl Checked {
    /// Produce a `Checked` view onto a `Certificate`.
    ///
    /// This operation checks all self-signatures for cryptographic validity, as well as
    /// conformance to policy.
    ///
    /// Third party signatures are not currently handled.
    pub fn new(cert: Certificate) -> Self {
        // Make a copy of all parts of the SignedPublicKey and drop all signatures that:
        // - are not cryptographically correct
        // - don't pass our policy checks (`signature_acceptable`)

        // TODO: store bad self-sigs and third-party sigs in a separate place

        // TODO: go look for any (valid/correct) hard revocations for the full cert,
        // and encode the result in a simple "cert is hard revoked" flag:
        //
        // -> any user id binding that claims to be primary
        // -> or direct signatures on the primary

        // TODO: Which parts of validity checking can/should be moved to [SigStack]?

        let original = cert.spk;

        // primary
        let primary = original.primary_key.clone();
        let primary_created = primary.created_at();

        // details
        let revocation_signatures: Vec<_> = original
            .details
            .revocation_signatures
            .iter()
            .filter(|s| signature::signature_acceptable(s)) // FIXME: could this filter out any important revocations?
            .filter(|s| signature::not_older_than(s, primary_created))
            .filter(|s| s.verify_key(&original.primary_key).is_ok())
            .cloned()
            .collect();

        let direct_signatures: Vec<_> = original
            .details
            .direct_signatures
            .iter()
            .filter(|s| signature::signature_acceptable(s))
            .filter(|s| signature::not_older_than(s, primary_created))
            .filter(|s| s.verify_key(&original.primary_key).is_ok())
            .cloned()
            .collect();

        let users: Vec<SignedUser> = original
            .details
            .users
            .iter()
            .map(|su| {
                let id = su.id.clone();
                let signatures = su
                    .signatures
                    .iter()
                    .filter(|s| signature::signature_acceptable(s))
                    .filter(|s| signature::not_older_than(s, primary_created))
                    .filter(|s| s.verify_certification(&primary, Tag::UserId, &id).is_ok())
                    .cloned()
                    .collect();

                SignedUser { id, signatures }
            })
            .collect();

        let user_attributes: Vec<SignedUserAttribute> = original
            .details
            .user_attributes
            .iter()
            .map(|sua| {
                let attr = sua.attr.clone();
                let signatures = sua
                    .signatures
                    .iter()
                    .filter(|s| signature::signature_acceptable(s))
                    .filter(|s| signature::not_older_than(s, primary_created))
                    .filter(|s| {
                        s.verify_certification(&primary, Tag::UserAttribute, &attr)
                            .is_ok()
                    })
                    .cloned()
                    .collect();

                SignedUserAttribute { attr, signatures }
            })
            .collect();

        let details = SignedKeyDetails {
            revocation_signatures,
            direct_signatures,
            users,
            user_attributes,
        };

        // subkeys
        let subkeys = original
            .public_subkeys
            .iter()
            .map(|sk| {
                let key = sk.key.clone();
                let signatures = sk
                    .signatures
                    .iter()
                    .filter(|s| signature::signature_acceptable(s))
                    .filter(|s| signature::not_older_than(s, primary_created))
                    .filter(|s| {
                        if let Err(e) = s.verify_subkey_binding(&original.primary_key, &key) {
                            log::warn!("Ignoring bad key binding signature {s:#?}: {e:?}");
                            return false;
                        }

                        // If there is an embedded back signature, we reject the entire signature if the back signature is cryptographically invalid
                        for embedded in s
                            .config()
                            .map(|c| &c.hashed_subpackets)
                            .into_iter()
                            .flatten()
                            .filter(|sp| sp.typ() == SubpacketType::EmbeddedSignature)
                        {
                            match &embedded.data {
                                SubpacketData::EmbeddedSignature(backsig) => {
                                    if !signature::signature_acceptable(backsig) {
                                        log::warn!(
                                            "Ignoring signature because of unacceptable embedded signature {backsig:#?}"
                                        );

                                        return false;
                                    }

                                    // FIXME: reject if signature creation time is before subkey creation time

                                    if let Err(e) =
                                        backsig.verify_primary_key_binding(
                                            &key,
                                            &original.primary_key,
                                        )
                                    {
                                        log::warn!(
                                            "Ignoring signature because embedded signature doesn't verify as correct {backsig:#?}: {e:?}"
                                        );

                                        return false;
                                    }
                                }
                                _ => unreachable!("no other subpacket types should come up, here"),
                            }
                        }

                        true
                    })
                    .cloned()
                    .collect();
                SignedPublicSubKey { key, signatures }
            })
            .collect();

        // combine
        let cspk = SignedPublicKey::new(primary, details, subkeys);

        log::debug!("Checked cert: {cspk:#?}");

        let primary_key_id = original.primary_key.legacy_key_id();
        let primary_fingerprint = original.primary_key.fingerprint();

        Self {
            original,
            cspk,
            primary_key_id,
            primary_fingerprint,
        }
    }

    // --- basic accessors

    /// The checked subset of the underlying SignedPublicKey.
    ///
    /// This contains only self-signatures that are cryptographically verified, and considered
    /// valid by our policy.
    pub fn as_signed_public_key(&self) -> &SignedPublicKey {
        &self.cspk
    }

    /// The fingerprint of this Certificate
    pub fn fingerprint(&self) -> &Fingerprint {
        &self.primary_fingerprint
    }

    /// The key id of this Certificate
    pub fn key_id(&self) -> KeyId {
        self.primary_key_id
    }

    /// Get the creation time of the certificate (the creation time of the primary key)
    pub fn primary_creation_time(&self) -> Timestamp {
        self.cspk.primary_key.created_at()
    }

    /// The primary key of this `Checked`
    pub(crate) fn primary_key(&self) -> SignedComponentKeyPub {
        let mut sigs: Vec<_> = self.cspk.details.revocation_signatures.clone();
        sigs.append(&mut self.cspk.details.direct_signatures.clone());

        SignedComponentKeyPub::Primary((self.cspk.clone(), sigs))
    }

    /// An iterator over all subkeys of this `Checked`
    pub(crate) fn subkeys(&self) -> impl Iterator<Item = SignedComponentKeyPub> + '_ {
        self.cspk.public_subkeys.iter().map(|spsk| {
            SignedComponentKeyPub::Subkey((
                spsk.clone(),
                self.cspk.details.direct_signatures.clone(),
            ))
        })
    }

    /// An iterator over the primary and all subkeys of this `Checked`
    pub(crate) fn component_keys(&self) -> impl Iterator<Item = SignedComponentKeyPub> + '_ {
        std::iter::once(self.primary_key()).chain(self.subkeys())
    }

    /// List all User IDs
    pub fn user_ids(&self) -> &[SignedUser] {
        &self.cspk.details.users
    }

    /// List all User Attributes
    pub fn user_attributes(&self) -> &[SignedUserAttribute] {
        &self.cspk.details.user_attributes
    }

    // --- semantics functionality

    /// Return the primary User ID
    pub fn primary_user_id(&self) -> Option<&SignedUser> {
        let now = Timestamp::now();

        crate::primary_userid::primary_user_id(
            &self.cspk.details,
            now,
            self.primary_creation_time(),
        )
    }

    /// Get the active direct key signature at `reference`.
    fn active_dks_at(&self, reference: Timestamp) -> Option<&Signature> {
        // combine direct_signatures+revocation_signatures
        SigStack::from_iter(
            self.cspk
                .details
                .direct_signatures
                .iter()
                .chain(self.cspk.details.revocation_signatures.iter()),
        )
        .active_at(reference, self.primary_creation_time())
    }

    /// Find the active metadata-bearing signature for the certificate.
    ///
    /// For v6 certificates, this is the active direct key self-signature.
    ///
    /// For earlier certificate versions, it is usually the active self-signature of the
    /// primary user id. However, a direct key self-signature can be used as well.
    /// If both types of self-signature exist, this will pick the one with the later creation time.
    pub fn active_certificate_self_signature_at(&self, reference: Timestamp) -> Option<&Signature> {
        match self.cspk.version() {
            KeyVersion::V2 | KeyVersion::V3 | KeyVersion::V4 => {
                let uid_binding = primary_user_id_binding_at(
                    &self.cspk.details,
                    reference,
                    self.primary_creation_time(),
                );
                let direct_sig = self.active_dks_at(reference);

                match (uid_binding, direct_sig) {
                    (None, None) => None,
                    (Some(a), None) | (None, Some(a)) => Some(a),
                    (Some(a), Some(b)) => Some(util::newer(a, b)),
                }
            }

            KeyVersion::V6 => self.active_dks_at(reference),

            _ => None,
        }
    }

    /// Return key expiration "duration" of the primary key.
    ///
    /// If the `Duration` is `None`, or if it is "zero", the key doesn't expire.
    fn primary_expiration_duration(&self, reference: Timestamp) -> Option<Duration> {
        self.active_certificate_self_signature_at(reference)
            .and_then(Signature::key_expiration_time)
    }

    /// Return expiration time of the primary key, or `None` if the key doesn't expire
    fn primary_expiration_time(&self, reference: Timestamp) -> Option<Timestamp> {
        self.primary_expiration_duration(reference)
            // if the value is zero, we don't have a key expiration
            .filter(|d| d.as_secs() != 0)
            .map(|d| self.cspk.primary_key.created_at().as_secs() + d.as_secs())
            .map(Timestamp::from_secs)
    }

    /// Is the primary key (and thus the certificate as a whole) valid at `reference` time?
    ///
    /// The primary is invalid if it is expired, revoked, or has no acceptable binding
    /// self-signature.
    ///
    /// It is also invalid it its public key algorithm is considered insufficient at the reference
    /// time.
    pub fn primary_valid_at(&self, reference: Timestamp) -> Result<bool, Error> {
        log::debug!(
            "checking primary key validity at {:?}",
            SystemTime::from(reference)
        );

        // It's not ok if `reference` is before key creation time
        if reference < self.primary_creation_time() {
            log::debug!(" reference time predates primary key creation");
            return Ok(false);
        }

        // If the primary is using an insufficiently strong public key algorithm
        // (i.e. unacceptable at the reference time), we reject its use
        let pp = self.cspk.primary_key.public_params();
        if !policy::acceptable_pk_algorithm(pp, reference) {
            log::debug!(" primary key uses unacceptable public parameters {pp:?}");
            return Ok(false);
        }

        if let Some(expiration) = self.primary_expiration_time(reference)
            && expiration <= reference
        {
            log::debug!(" primary key expired {expiration:?}");
            return Ok(false);
        }

        // Check that a valid primary user id binding or dks exist at the reference time.
        // (This includes checking that the binding signatures use an acceptable public key
        // algorithm.)
        let Some(active) = self.active_certificate_self_signature_at(reference) else {
            log::debug!(" no valid primary key binding");
            return Ok(false);
        };

        // Is the primary revoked at the reference time?
        if signature::is_revocation(active) {
            log::debug!(" primary key is revoked");
            return Ok(false);
        }

        log::debug!(" primary key is valid");
        Ok(true)
    }

    /// Is the full certificate revoked at `reference` time?
    ///
    /// This takes into account the semantics of hard and soft revocation.
    pub fn revoked_at(&self, reference: Timestamp) -> bool {
        let Some(active) = self.active_certificate_self_signature_at(reference) else {
            log::debug!(" no valid primary key binding");
            return false;
        };

        signature::is_revocation(active)
    }

    // --- preferences/features metadata lookup

    /// The preferred `SymmetricKeyAlgorithm` setting for this certificate
    pub fn preferred_symmetric_key_algo(
        &self,
        reference: Timestamp,
    ) -> Option<&[SymmetricKeyAlgorithm]> {
        self.active_certificate_self_signature_at(reference)
            .map(Signature::preferred_symmetric_algs)
    }

    /// The preferred `AeadAlgorithm` setting for this certificate
    pub fn preferred_aead_algo(
        &self,
        reference: Timestamp,
    ) -> Option<&[(SymmetricKeyAlgorithm, AeadAlgorithm)]> {
        self.active_certificate_self_signature_at(reference)
            .map(Signature::preferred_aead_algs)
    }

    /// The preferred `HashAlgorithm` setting for this certificate
    pub fn preferred_hash_algo(&self, reference: Timestamp) -> Option<&[HashAlgorithm]> {
        self.active_certificate_self_signature_at(reference)
            .map(Signature::preferred_hash_algs)
    }

    /// The `Features` setting of this Certificate
    pub fn features(&self, reference: Timestamp) -> Option<&Features> {
        self.active_certificate_self_signature_at(reference)
            .and_then(Signature::features)
    }

    // --- component key selectors

    /// List all valid subkeys at the reference time.
    pub fn valid_subkeys_at(&self, reference: Timestamp) -> Vec<ComponentKeyPub> {
        // If the primary key is invalid, there are no valid subkeys
        if matches!(self.primary_valid_at(reference), Err(_) | Ok(false)) {
            return vec![];
        }

        // Filter based on validity
        self.subkeys()
            .filter(|sckp| policy::acceptable_pk_algorithm(sckp.public_params(), reference))
            .filter(|sckp| sckp.is_component_subkey_valid_at(reference))
            .map(Into::into)
            .collect()
    }

    /// A baseline set of generically valid component keys.
    ///
    /// No component keys are returned if the certificate as a whole in invalid.
    /// Individual component keys are returned if they are validly bound, and use a public key
    /// mechanism that we accept at the reference time.
    ///
    /// This function is intended for further filtering by callers, to limit component keys more
    /// specifically for concrete use cases.
    fn valid_component_keys_at(&self, reference: Timestamp) -> Vec<SignedComponentKeyPub> {
        // If the primary key is invalid, there are no valid subkeys
        if matches!(self.primary_valid_at(reference), Err(_) | Ok(false)) {
            return vec![];
        }

        // Filter based on validity
        self.component_keys()
            .filter(|sckp| policy::acceptable_pk_algorithm(sckp.public_params(), reference))
            .filter(|sckp| sckp.is_component_subkey_valid_at(reference))
            .collect()
    }

    /// List all valid component keys that are encryption capable.
    ///
    /// The resulting set of [ComponentKeyPub] can be used to encrypt data.
    pub fn valid_encryption_capable_component_keys(&self) -> Vec<ComponentKeyPub> {
        let reference = Timestamp::now();

        self.valid_component_keys_at(reference)
            .into_iter()
            .filter(|sckp| sckp.valid_encryption_algo())
            .filter(|sckp| sckp.is_encryption_capable(reference))
            .map(Into::into)
            .collect()
    }

    /// Get a set of [SignatureVerifier] objects, one for each valid component key that is
    /// appropriate to use for data signatures.
    ///
    /// This includes a check that the binding signature must have an embedded back signature
    /// (we have a `Checked`, so we can assume that if a back signature exists at all, it is
    /// acceptable).
    pub fn valid_signing_capable_component_keys_at(
        &self,
        reference: Timestamp,
    ) -> Vec<SignatureVerifier> {
        log::debug!("valid_signing_capable_component_keys_at {reference:?}");

        self.valid_component_keys_at(reference)
            .into_iter()
            .filter(|sckp| sckp.is_signing_capable(reference))
            .filter(|sckp| sckp.has_valid_backsig_at(reference, self.primary_creation_time()))
            .map(ComponentKeyPub::from)
            .map(|ckey| SignatureVerifier::new(ckey, self.cspk.primary_key.created_at()))
            .collect()
    }

    /// Get a set of [ComponentKeyPub] objects, one for each valid component key that is
    /// appropriate to use for authentication.
    pub fn valid_authentication_capable_component_keys(
        &self,
        reference: Timestamp,
    ) -> Vec<ComponentKeyPub> {
        self.valid_component_keys_at(reference)
            .into_iter()
            .filter(|sckp| sckp.is_authentication_capable(reference))
            .map(Into::into)
            .collect()
    }

    // --- third party signature helpers

    /// Was this signature potentially issued by a third party?
    ///
    /// This checks if any issuer key id or fingerprint subpacket matches the primary key id or
    /// fingerprint of `self`.
    fn maybe_third_party(&self, s: &Signature) -> bool {
        let mut maybe_third_party = false;

        let issuers = s.issuer_key_id();
        if !issuers.is_empty() && issuers.into_iter().any(|x| x != &self.primary_key_id) {
            maybe_third_party = true
        };

        let issuer_fps = s.issuer_fingerprint();
        if !issuer_fps.is_empty()
            && issuer_fps
                .into_iter()
                .any(|x| x != &self.primary_fingerprint)
        {
            maybe_third_party = true
        };

        maybe_third_party
    }

    /// Get all third-party certifications for all User IDs
    pub fn user_id_third_party_certifications(&self) -> Vec<(UserId, Vec<&Signature>)> {
        let mut res = vec![];

        for su in &self.original.details.users {
            let id = su.id.clone();
            let sigs = su
                .signatures
                .iter()
                .filter(|s| self.maybe_third_party(s))
                .collect();

            res.push((id, sigs));
        }

        res
    }

    pub fn direct_third_party_certifications(&self) -> Vec<&Signature> {
        self.original
            .details
            .direct_signatures
            .iter()
            .chain(&self.original.details.revocation_signatures)
            .filter(|s| self.maybe_third_party(s))
            .collect()
    }
}

impl From<Certificate> for Checked {
    fn from(value: Certificate) -> Self {
        Checked::new(value)
    }
}

impl From<Checked> for Certificate {
    fn from(value: Checked) -> Self {
        value.cspk.into()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::time::SystemTime;

    use chrono::DateTime;
    use pgp::types::Timestamp;

    use crate::certificate::Checked;

    fn load_cert(filename: &str) -> Checked {
        let mut read = std::fs::File::open(filename).expect("open");
        let c = crate::certificate::Certificate::load(&mut read).expect("load");

        assert_eq!(c.len(), 1);

        Checked::from(c.into_iter().next().expect("asserted"))
    }

    fn expiration_at(c: &Checked, at: &str) -> Timestamp {
        let rfc3339 = DateTime::parse_from_rfc3339(at).expect("parse at");

        let time: SystemTime = rfc3339.into();
        c.primary_expiration_time(time.try_into().expect("time fits in u32"))
            .expect("some")
    }

    #[test]
    fn test_dsa() {
        // This certificate uses a DSA primary (which is used for all self-signatures).
        //
        // Note that we consider DSA invalid from February 3, 2023 forward (see [policy]).
        //
        // Thus, self-signatures that are newer than this cutoff are ignored -
        // so the self-signature on the primary User ID from 2024-06-03 is considered invalid,
        // and the key is considered expired at 2024-06-07T19:57:03Z.
        let checked = load_cert("tests/608B00ABE1DAA3501C5FF91AE58271326F9F4937");

        // --- validity of the primary ---

        // key is not revoked
        assert!(
            !checked.revoked_at(
                SystemTime::from(
                    DateTime::parse_from_rfc3339("2025-01-01T23:59:00Z").expect("parse date")
                )
                .try_into()
                .expect("time fits in u32"),
            )
        );

        // valid at 2020-01-01T23:59:00Z
        assert!(
            checked
                .primary_valid_at(
                    SystemTime::from(
                        DateTime::parse_from_rfc3339("2020-01-01T23:59:00Z").expect("parse date")
                    )
                    .try_into()
                    .expect("time fits in u32"),
                )
                .expect("primary_valid_at")
        );

        let exp = expiration_at(&checked, "2020-01-01T23:59:00Z");
        assert_eq!(
            exp,
            SystemTime::from(
                DateTime::parse_from_rfc3339("2020-08-03T13:32:24Z").expect("parse date")
            )
            .try_into()
            .expect("time fits in u32"),
        );

        let exp = expiration_at(&checked, "2021-01-01T23:59:00Z");
        assert_eq!(
            exp,
            SystemTime::from(
                DateTime::parse_from_rfc3339("2022-07-06T17:06:34Z").expect("parse date")
            )
            .try_into()
            .expect("time fits in u32"),
        );

        let exp = expiration_at(&checked, "2024-01-01T23:59:00Z");
        assert_eq!(
            exp,
            SystemTime::from(
                DateTime::parse_from_rfc3339("2024-06-07T19:57:03Z").expect("parse date")
            )
            .try_into()
            .expect("time fits in u32"),
        );

        // not valid at 2024-07-01T23:59:00Z
        assert!(
            !checked
                .primary_valid_at(
                    SystemTime::from(
                        DateTime::parse_from_rfc3339("2024-07-01T23:59:00Z").expect("parse date")
                    )
                    .try_into()
                    .expect("time fits in u32"),
                )
                .expect("primary_valid_at")
        );

        // --- encryption subkey ---

        let enc = checked.valid_encryption_capable_component_keys();
        assert_eq!(enc.len(), 0);

        // TODO: if we had a [valid_encryption_capable_component_keys_at] fn, we could test for
        //  - historical validity of the old ElGamal encryption key, and
        //  - the switch to the RSA encryption key on 2017-08-02.

        // --- signature component key (the primary key) ---
        let sig = checked.valid_signing_capable_component_keys_at(
            SystemTime::from(
                DateTime::parse_from_rfc3339("2022-07-01T23:59:00Z").expect("parse date"),
            )
            .try_into()
            .expect("time fits in u32"),
        );
        assert_eq!(sig.len(), 1);

        let sig = checked.valid_signing_capable_component_keys_at(
            SystemTime::from(
                DateTime::parse_from_rfc3339("2024-07-01T23:59:00Z").expect("parse date"),
            )
            .try_into()
            .expect("time fits in u32"),
        );
        assert_eq!(sig.len(), 0);
    }
}
