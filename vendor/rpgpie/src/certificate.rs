// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wrapper types and logic for certificates, aka OpenPGP public keys ("transferable public keys").

use std::io;

use pgp::{
    armor,
    composed::{
        ArmorOptions,
        CleartextSignedMessage,
        Deserializable,
        PublicOrSecret,
        SignedPublicKey,
    },
    packet::Signature,
    ser::Serialize,
    types::{Fingerprint, KeyDetails, KeyVersion, Timestamp},
};

pub use crate::checked::Checked;
use crate::{
    Error,
    key::{ComponentKeyPub, SignedComponentKeyPub},
    signature,
    tsk::Tsk,
};

/// A "certificate," also known as an "OpenPGP public key."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    pub(crate) spk: SignedPublicKey,
}

impl From<SignedPublicKey> for Certificate {
    fn from(spk: SignedPublicKey) -> Self {
        Self { spk }
    }
}

impl From<Certificate> for SignedPublicKey {
    fn from(cert: Certificate) -> Self {
        cert.spk
    }
}

impl TryFrom<&[u8]> for Certificate {
    type Error = Error;

    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        let (spk, _) = SignedPublicKey::from_reader_single(input)?;
        Ok(Self { spk })
    }
}

impl TryFrom<&Certificate> for Vec<u8> {
    type Error = Error;

    fn try_from(value: &Certificate) -> Result<Self, Self::Error> {
        Ok(value.spk().to_bytes()?)
    }
}

impl From<Tsk> for Certificate {
    fn from(value: Tsk) -> Self {
        Certificate::from(SignedPublicKey::from(value.ssk))
    }
}

impl Certificate {
    /// The fingerprint of this certificate (i.e. the fingerprint of its primary key)
    pub fn fingerprint(&self) -> Fingerprint {
        self.spk.primary_key.fingerprint()
    }

    /// Load a set of `Certificate`s from a source.
    ///
    /// The source data may be armored or binary.
    pub fn load<R: io::Read>(source: &mut R) -> Result<Vec<Certificate>, Error> {
        let mut certs = vec![];

        let (parsed, _headers) = PublicOrSecret::from_reader_many(source)?;

        for res in parsed {
            match res {
                Ok(pos) => {
                    let cert = match pos {
                        PublicOrSecret::Public(spk) => spk.into(),
                        PublicOrSecret::Secret(_ssk) => {
                            return Err(Error::Message(
                                "Expected Certificate(s), got TSK".to_string(),
                            ));
                        }
                    };

                    certs.push(cert);
                }
                Err(_) => log::warn!("Bad data {res:?}"),
            }
        }

        if certs.is_empty() {
            Err(Error::Message("No certificates found".to_string()))
        } else {
            Ok(certs)
        }
    }

    /// Save this Certificate to a writer
    pub fn save(&self, armored: bool, sink: &mut dyn io::Write) -> Result<(), Error> {
        Self::save_all([self], armored, sink)
    }

    /// Save a set of Certificates to a writer
    pub fn save_all<'a>(
        certs: impl IntoIterator<Item = &'a Self>,
        armored: bool,
        mut sink: &mut dyn io::Write,
    ) -> Result<(), Error> {
        if armored {
            let spks: Vec<_> = certs.into_iter().map(|c| c.spk()).collect();

            // Only emit armor checksum if any of the keys is pre-v6
            let armor_checksum = spks.iter().any(|spk| spk.version() < KeyVersion::V6);

            armor::write(
                &spks,
                armor::BlockType::PublicKey,
                &mut sink,
                ArmorOptions::default().headers,
                armor_checksum,
            )?;
        } else {
            for c in certs {
                c.spk().to_writer(&mut sink)?;
            }
        }

        Ok(())
    }

    /// Access to inner rPGP object
    pub(crate) fn spk(&self) -> &SignedPublicKey {
        &self.spk
    }

    /// Mutable access to inner rPGP object
    pub(crate) fn spk_mut(&mut self) -> &mut SignedPublicKey {
        &mut self.spk
    }

    fn primary(&self) -> SignedComponentKeyPub {
        SignedComponentKeyPub::Primary((
            self.spk.clone(),
            self.spk.details.direct_signatures.clone(), // FIXME: plus revocations?
        ))
    }

    fn subkeys(&self) -> impl Iterator<Item = SignedComponentKeyPub> + '_ {
        self.spk.public_subkeys.iter().map(|spsk| {
            SignedComponentKeyPub::Subkey((
                spsk.clone(),
                self.spk.details.direct_signatures.clone(), // FIXME: plus revocations?
            ))
        })
    }

    fn component_keys(&self) -> impl Iterator<Item = SignedComponentKeyPub> + '_ {
        std::iter::once(self.primary()).chain(self.subkeys())
    }

    /// Get list of all validation-capable component keys.
    ///
    /// This fn is intended to signal only *potential* use for validation
    /// It is *very* lenient in what it lists. It only checks for key flags, but doesn't check
    /// for validity in any way (e.g. it doesn't check for a correct subkey binding signature).
    pub(crate) fn validation_capable_component_keys(
        &self,
    ) -> impl Iterator<Item = SignedComponentKeyPub> + '_ {
        let now = Timestamp::now();

        self.component_keys()
            .filter(move |sckp| sckp.clone().is_signing_capable(now))
    }

    /// Get list of all decryption-capable component keys.
    ///
    /// This fn is intended to signal potential use for *decryption*, not encryption!
    /// It is *very* lenient in what it lists. It only checks for key flags, but doesn't check
    /// for validity in any way (e.g. it doesn't check for a correct subkey binding signature).
    ///
    /// NOTE: Checking for decryption capable subkeys on a certificate is intended for use with
    /// hardware-backed key material.
    pub fn decryption_capable_component_keys(&self) -> impl Iterator<Item = ComponentKeyPub> + '_ {
        let now = Timestamp::now();

        // FIXME: filter out unknown notations

        self.component_keys()
            .filter(move |sckp| sckp.clone().is_encryption_capable(now))
            .map(ComponentKeyPub::from)
    }
}

/// Verify data signatures
#[derive(Debug)]
pub struct SignatureVerifier {
    ckey: ComponentKeyPub,
    primary_creation: Timestamp,
}

impl SignatureVerifier {
    /// Create a `SignatureVerifier` from a [`ComponentKeyPub`] and the creation time of the
    /// associated primary key (used to validate temporal validity of signatures)
    pub(crate) fn new(ckey: ComponentKeyPub, primary_creation: Timestamp) -> Self {
        Self {
            ckey,
            primary_creation,
        }
    }

    /// Check temporal validity of `sig`.
    ///
    /// Returns an error if:
    ///
    /// - The creation time of `sig` predates the creation of the signing component key or primary.
    /// - The creation time of `sig` is in the future.
    pub(crate) fn temporal_validity(&self, sig: &Signature) -> Result<(), Error> {
        let Some(created) = sig.created() else {
            // this should not happen
            return Err(Error::Message(
                "Missing signature creation time".to_string(),
            ));
        };

        // reject if signature timestamp is before ckey or primary creation time
        if created < self.primary_creation || created < self.ckey.created_at() {
            return Err(Error::Message(
                "Data signature predates key creation".to_string(),
            ));
        }

        // reject if signature creation is in the future
        if created > Timestamp::now() {
            return Err(Error::Message("Data signature from the future".to_string()));
        }

        Ok(())
    }

    /// Verify a data signature
    ///
    /// Performs rpgpie policy checks (see [`crate::signature::signature_acceptable`]), and
    /// rejects signatures if the cryptographic mechanisms are insufficient, and checks temporal
    /// validity.
    pub fn verify(&self, signature: &Signature, data: &[u8]) -> Result<(), Error> {
        self.temporal_validity(signature)?;

        self.ckey.verify(signature, data)
    }

    /// Verify a cleartext data signature
    ///
    /// Performs rpgpie policy checks (see [`crate::signature::signature_acceptable`]), and
    /// rejects signatures if the cryptographic mechanisms are insufficient, and checks temporal
    /// validity.
    pub fn verify_csf(&self, csf: &CleartextSignedMessage) -> Result<Signature, Error> {
        // A CSF can contain multiple signatures. This call to `CleartextSignedMessage::verify`
        // returns the first cryptographically valid signature that is found.
        let sig = csf.verify(&self.ckey)?;

        // policy check
        if !signature::signature_acceptable(sig) {
            return Err(Error::Message(
                "Signature doesn't satisfy our policy".to_string(),
            ));
        }

        // reject signature if it's temporally invalid
        self.temporal_validity(sig)?;

        Ok(sig.clone())
    }

    /// Return the underlying component public key for this verifier
    pub fn as_componentkey(&self) -> &ComponentKeyPub {
        &self.ckey
    }
}
