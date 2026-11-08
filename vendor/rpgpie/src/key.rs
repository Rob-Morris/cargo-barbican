// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Handling of component keys. A component key is an individual "primary key" or "subkey."
//!
//! NOTE: This module is particularly experimental, the API may change drastically.
//! (This current implementation does a lot of cloning and is limited to read-only operations.)

use std::fmt::{Debug, Formatter};

use pgp::{
    composed::{
        RawSessionKey,
        SignedPublicKey,
        SignedPublicSubKey,
        SignedSecretKey,
        SignedSecretSubKey,
    },
    crypto::{hash::HashAlgorithm, public_key::PublicKeyAlgorithm, sym::SymmetricKeyAlgorithm},
    packet::{
        KeyFlags,
        PublicKeyEncryptedSessionKey,
        Signature,
        SignatureConfig,
        SignatureType,
        Subpacket,
        SubpacketData,
    },
    types::{
        EncryptionKey,
        EskType,
        Fingerprint,
        KeyDetails,
        KeyId,
        KeyVersion,
        Password,
        PkeskBytes,
        PkeskVersion,
        PublicParams,
        SignatureBytes,
        SigningKey,
        Timestamp,
        VerifyingKey,
    },
};
use rand::{Rng, thread_rng};
use rand_core::CryptoRng;

use crate::{
    Error,
    message::SignatureMode,
    primary_userid::primary_user_id_binding_at,
    signature,
    signature::SigStack,
};

/// A public component key (either a public primary key, or a public subkey).
///
/// NOTE: This component key representation consists of only the raw public key packet data,
/// without the context of binding signatures
#[derive(Debug, Clone)]
pub enum ComponentKeyPub {
    Primary(pgp::packet::PublicKey),
    Subkey(pgp::packet::PublicSubkey),
}

impl KeyDetails for ComponentKeyPub {
    fn version(&self) -> KeyVersion {
        match self {
            ComponentKeyPub::Primary(pri) => pri.version(),
            ComponentKeyPub::Subkey(sub) => sub.version(),
        }
    }

    fn fingerprint(&self) -> Fingerprint {
        match self {
            ComponentKeyPub::Primary(pri) => pri.fingerprint(),
            ComponentKeyPub::Subkey(sub) => sub.fingerprint(),
        }
    }

    fn legacy_key_id(&self) -> KeyId {
        match self {
            ComponentKeyPub::Primary(pri) => pri.legacy_key_id(),
            ComponentKeyPub::Subkey(sub) => sub.legacy_key_id(),
        }
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        match self {
            ComponentKeyPub::Primary(pri) => pri.algorithm(),
            ComponentKeyPub::Subkey(sub) => sub.algorithm(),
        }
    }

    fn created_at(&self) -> Timestamp {
        match self {
            ComponentKeyPub::Primary(pri) => pri.created_at(),
            ComponentKeyPub::Subkey(sub) => sub.created_at(),
        }
    }

    fn legacy_v3_expiration_days(&self) -> Option<u16> {
        match self {
            ComponentKeyPub::Primary(pri) => pri.legacy_v3_expiration_days(),
            ComponentKeyPub::Subkey(sub) => sub.legacy_v3_expiration_days(),
        }
    }

    fn public_params(&self) -> &PublicParams {
        match self {
            ComponentKeyPub::Primary(pri) => pri.public_params(),
            ComponentKeyPub::Subkey(sub) => sub.public_params(),
        }
    }
}

impl EncryptionKey for ComponentKeyPub {
    fn encrypt<R: CryptoRng + Rng>(
        &self,
        rng: R,
        plain: &[u8],
        typ: EskType,
    ) -> pgp::errors::Result<PkeskBytes> {
        match self {
            ComponentKeyPub::Primary(pri) => pri.encrypt(rng, plain, typ),
            ComponentKeyPub::Subkey(sub) => sub.encrypt(rng, plain, typ),
        }
    }
}

impl VerifyingKey for ComponentKeyPub {
    fn verify(
        &self,
        hash: HashAlgorithm,
        data: &[u8],
        sig: &SignatureBytes,
    ) -> pgp::errors::Result<()> {
        match self {
            ComponentKeyPub::Primary(pri) => pri.verify(hash, data, sig),
            ComponentKeyPub::Subkey(sub) => sub.verify(hash, data, sig),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum SignedComponentKeyPub {
    // We store a copy of all primary-related signatures, to have an owned copy that can be
    // borrowed as a SigStack. FIXME: do this better?
    Primary((SignedPublicKey, Vec<Signature>)),

    // key, dks stack
    Subkey((SignedPublicSubKey, Vec<Signature>)),
}

impl KeyDetails for SignedComponentKeyPub {
    fn version(&self) -> KeyVersion {
        match self {
            SignedComponentKeyPub::Primary((p, _)) => p.version(),
            SignedComponentKeyPub::Subkey((s, _)) => s.version(),
        }
    }

    fn fingerprint(&self) -> Fingerprint {
        match self {
            SignedComponentKeyPub::Primary((p, _)) => p.fingerprint(),
            SignedComponentKeyPub::Subkey((s, _)) => s.fingerprint(),
        }
    }

    fn legacy_key_id(&self) -> KeyId {
        match self {
            SignedComponentKeyPub::Primary((p, _)) => p.legacy_key_id(),
            SignedComponentKeyPub::Subkey((s, _)) => s.legacy_key_id(),
        }
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        match self {
            SignedComponentKeyPub::Primary((p, _)) => p.algorithm(),
            SignedComponentKeyPub::Subkey((s, _)) => s.algorithm(),
        }
    }

    fn created_at(&self) -> Timestamp {
        match self {
            SignedComponentKeyPub::Primary((p, _)) => p.created_at(),
            SignedComponentKeyPub::Subkey((s, _)) => s.created_at(),
        }
    }

    fn legacy_v3_expiration_days(&self) -> Option<u16> {
        match self {
            SignedComponentKeyPub::Primary((p, _)) => p.legacy_v3_expiration_days(),
            SignedComponentKeyPub::Subkey((s, _)) => s.legacy_v3_expiration_days(),
        }
    }
    fn public_params(&self) -> &PublicParams {
        match self {
            SignedComponentKeyPub::Primary((p, _)) => p.public_params(),
            SignedComponentKeyPub::Subkey((s, _)) => s.public_params(),
        }
    }
}

impl VerifyingKey for SignedComponentKeyPub {
    fn verify(
        &self,
        hash: HashAlgorithm,
        data: &[u8],
        sig: &SignatureBytes,
    ) -> pgp::errors::Result<()> {
        match self {
            SignedComponentKeyPub::Primary((p, _)) => VerifyingKey::verify(p, hash, data, sig),
            SignedComponentKeyPub::Subkey((s, _)) => VerifyingKey::verify(s, hash, data, sig),
        }
    }
}

impl From<SignedComponentKeyPub> for ComponentKeyPub {
    fn from(value: SignedComponentKeyPub) -> ComponentKeyPub {
        match value {
            SignedComponentKeyPub::Subkey(sk) => ComponentKeyPub::Subkey(sk.0.key),
            SignedComponentKeyPub::Primary((pk, _)) => ComponentKeyPub::Primary(pk.primary_key),
        }
    }
}

/// A component key with private key material (either a secret primary key, or a secret subkey).
///
/// NOTE: This component key representation consists of only the raw secret key packet data,
/// without the context of binding signatures
pub enum ComponentKeyPriv {
    Primary(pgp::packet::SecretKey),
    Subkey(pgp::packet::SecretSubkey),
}

impl From<SignedComponentKeySec> for ComponentKeyPriv {
    fn from(value: SignedComponentKeySec) -> Self {
        match value {
            SignedComponentKeySec::Primary(ssk) => ComponentKeyPriv::Primary(ssk.primary_key),
            SignedComponentKeySec::Subkey((sssk, _)) => ComponentKeyPriv::Subkey(sssk.key),
        }
    }
}

impl KeyDetails for ComponentKeyPriv {
    fn version(&self) -> KeyVersion {
        match self {
            Self::Primary(p) => p.version(),
            Self::Subkey(s) => s.version(),
        }
    }

    fn fingerprint(&self) -> Fingerprint {
        match self {
            Self::Primary(p) => p.fingerprint(),
            Self::Subkey(s) => s.fingerprint(),
        }
    }

    fn legacy_key_id(&self) -> KeyId {
        match self {
            Self::Primary(p) => p.legacy_key_id(),
            Self::Subkey(s) => s.legacy_key_id(),
        }
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        match self {
            Self::Primary(p) => p.algorithm(),
            Self::Subkey(s) => s.algorithm(),
        }
    }

    fn created_at(&self) -> Timestamp {
        match self {
            ComponentKeyPriv::Primary(pri) => pri.public_key().created_at(),
            ComponentKeyPriv::Subkey(sub) => sub.public_key().created_at(),
        }
    }

    fn legacy_v3_expiration_days(&self) -> Option<u16> {
        match self {
            ComponentKeyPriv::Primary(pri) => pri.public_key().legacy_v3_expiration_days(),
            ComponentKeyPriv::Subkey(sub) => sub.public_key().legacy_v3_expiration_days(),
        }
    }

    fn public_params(&self) -> &PublicParams {
        match self {
            ComponentKeyPriv::Primary(pri) => pri.public_key().public_params(),
            ComponentKeyPriv::Subkey(sub) => sub.public_key().public_params(),
        }
    }
}

impl Debug for ComponentKeyPriv {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Primary(p) => p.fmt(f),
            Self::Subkey(s) => s.fmt(f),
        }
    }
}

impl VerifyingKey for ComponentKeyPriv {
    fn verify(
        &self,
        hash: HashAlgorithm,
        data: &[u8],
        sig: &SignatureBytes,
    ) -> pgp::errors::Result<()> {
        match self {
            ComponentKeyPriv::Primary(pri) => pri.public_key().verify(hash, data, sig),
            ComponentKeyPriv::Subkey(sub) => sub.public_key().verify(hash, data, sig),
        }
    }
}

impl SigningKey for ComponentKeyPriv {
    fn sign(
        &self,
        key_pw: &Password,
        hash: HashAlgorithm,
        data: &[u8],
    ) -> pgp::errors::Result<SignatureBytes> {
        match self {
            ComponentKeyPriv::Primary(p) => SigningKey::sign(p, key_pw, hash, data),
            ComponentKeyPriv::Subkey(s) => SigningKey::sign(s, key_pw, hash, data),
        }
    }

    fn hash_alg(&self) -> HashAlgorithm {
        match self {
            ComponentKeyPriv::Primary(p) => p.hash_alg(),
            ComponentKeyPriv::Subkey(s) => s.hash_alg(),
        }
    }
}

impl ComponentKeyPriv {
    pub fn sign_data(
        &self,
        data: &[u8],
        sig_mode: SignatureMode,
        key_pw: &Password,
        hash_algorithm: HashAlgorithm,
    ) -> Result<Signature, Error> {
        // FIXME: upstream this functionality?

        let rng = thread_rng();

        let typ = match sig_mode {
            SignatureMode::Text => SignatureType::Text,
            SignatureMode::Binary => SignatureType::Binary,
        };

        let mut config = match self.version() {
            KeyVersion::V4 => SignatureConfig::v4(typ, self.algorithm(), hash_algorithm),
            KeyVersion::V6 => SignatureConfig::v6(rng, typ, self.algorithm(), hash_algorithm)?,
            v => {
                return Err(Error::Message(format!("unsupported key version: {:?}", v)));
            }
        };

        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::IssuerFingerprint(self.fingerprint()))?,
            Subpacket::critical(SubpacketData::SignatureCreationTime(Timestamp::now()))?,
        ];

        if self.version() < KeyVersion::V6 {
            config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::IssuerKeyId(
                self.legacy_key_id(),
            ))?];
        }

        let signature = config.sign(self, key_pw, data)?;

        Ok(signature)
    }

    pub(crate) fn is_locked(&self) -> bool {
        match self {
            Self::Primary(sk) => sk.secret_params().is_encrypted(),
            Self::Subkey(ssk) => ssk.secret_params().is_encrypted(),
        }
    }

    pub(crate) fn remove_password(&mut self, pw: &Password) -> Result<(), Error> {
        match self {
            Self::Primary(sk) => Ok(sk.remove_password(pw)?),
            Self::Subkey(ssk) => Ok(ssk.remove_password(pw)?),
        }
    }

    pub fn decrypt_session_key(
        &self,
        pkesk: &PublicKeyEncryptedSessionKey,
        key_pw: &Password,
    ) -> Result<pgp::composed::PlainSessionKey, Error> {
        let typ = match pkesk.version() {
            PkeskVersion::V3 => pgp::types::EskType::V3_4,
            PkeskVersion::V6 => pgp::types::EskType::V6,
            v => return Err(Error::Message(format!("Unsupported PKESK version {v:?}"))),
        };

        match self {
            ComponentKeyPriv::Primary(sk) => {
                let sk = sk.unlock(key_pw, |pub_params, priv_key| {
                    priv_key.decrypt(pub_params, pkesk.values()?, typ, &sk.public_key())
                })??;

                Ok(sk)
            }
            ComponentKeyPriv::Subkey(ssk) => {
                let sk = ssk.unlock(key_pw, |pub_params, priv_key| {
                    priv_key.decrypt(pub_params, pkesk.values()?, typ, &ssk.public_key())
                })??;

                Ok(sk)
            }
        }
    }
}

/// Either a secret primary key, or a secret subkey.
/// This enum serves as a convenience wrapper around both cases.
///
/// The component key is stored combined with the context of its binding signature(s)
#[derive(Clone)]
pub(crate) enum SignedComponentKeySec {
    Primary(SignedSecretKey),
    Subkey((SignedSecretSubKey, Option<Signature>)), // key, dks
}

impl Debug for SignedComponentKeySec {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SignedComponentKeySec::Primary(p) => p.fmt(f),
            SignedComponentKeySec::Subkey(s) => s.fmt(f),
        }
    }
}

impl KeyDetails for SignedComponentKeySec {
    fn version(&self) -> KeyVersion {
        match self {
            SignedComponentKeySec::Primary(p) => p.version(),
            SignedComponentKeySec::Subkey((s, _)) => s.version(),
        }
    }

    fn fingerprint(&self) -> Fingerprint {
        match self {
            SignedComponentKeySec::Primary(p) => p.fingerprint(),
            SignedComponentKeySec::Subkey((s, _)) => s.fingerprint(),
        }
    }

    fn legacy_key_id(&self) -> KeyId {
        match self {
            SignedComponentKeySec::Primary(p) => p.legacy_key_id(),
            SignedComponentKeySec::Subkey((s, _)) => s.legacy_key_id(),
        }
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        match self {
            SignedComponentKeySec::Primary(p) => p.algorithm(),
            SignedComponentKeySec::Subkey((s, _)) => s.algorithm(),
        }
    }

    fn created_at(&self) -> Timestamp {
        match self {
            SignedComponentKeySec::Primary(p) => p.primary_key.public_key().created_at(),
            SignedComponentKeySec::Subkey((s, _)) => s.key.public_key().created_at(),
        }
    }

    fn legacy_v3_expiration_days(&self) -> Option<u16> {
        match self {
            SignedComponentKeySec::Primary(p) => {
                p.primary_key.public_key().legacy_v3_expiration_days()
            }
            SignedComponentKeySec::Subkey((s, _)) => s.key.public_key().legacy_v3_expiration_days(),
        }
    }

    fn public_params(&self) -> &PublicParams {
        match self {
            SignedComponentKeySec::Primary(p) => p.primary_key.public_key().public_params(),
            SignedComponentKeySec::Subkey((s, _)) => s.key.public_key().public_params(),
        }
    }
}

impl VerifyingKey for SignedComponentKeySec {
    fn verify(
        &self,
        hash: HashAlgorithm,
        data: &[u8],
        sig: &SignatureBytes,
    ) -> pgp::errors::Result<()> {
        match self {
            SignedComponentKeySec::Primary(p) => p.public_key().verify(hash, data, sig),
            SignedComponentKeySec::Subkey((s, _)) => s.public_key().verify(hash, data, sig),
        }
    }
}

pub(crate) enum KeyFlagMatch {
    Sign,
    Enc,
    Auth,
}

impl SignedComponentKeySec {
    fn match_flag(sig: &Signature, check: KeyFlagMatch) -> bool {
        let flags = sig.key_flags();
        match check {
            KeyFlagMatch::Sign => flags.sign(),
            KeyFlagMatch::Auth => flags.authentication(),
            KeyFlagMatch::Enc => flags.encrypt_comms() | flags.encrypt_storage(),
        }
    }

    pub(crate) fn has_key_flag(&self, check: KeyFlagMatch, key_creation: Timestamp) -> bool {
        match self {
            SignedComponentKeySec::Primary(ssk) => {
                // FIXME: DRY

                let now = Timestamp::now();

                if let Some(binding) = primary_user_id_binding_at(&ssk.details, now, key_creation) {
                    Self::match_flag(binding, check)
                } else if let Some(dks) = SigStack::from_iter(
                    ssk.details
                        .direct_signatures
                        .iter()
                        .chain(ssk.details.revocation_signatures.iter()),
                )
                .active_at(now, key_creation)
                {
                    // also consider direct signatures
                    Self::match_flag(dks, check)
                } else {
                    false
                }
            }
            SignedComponentKeySec::Subkey((sssk, _)) => {
                let stack = SigStack::from_iter(sssk.signatures.iter());
                if let Some(sig) =
                    stack.active_at(Timestamp::now(), sssk.key.public_key().created_at())
                {
                    Self::match_flag(sig, check)
                } else {
                    false
                }
            }
        }
    }
}

impl From<&SignedComponentKeySec> for ComponentKeyPriv {
    fn from(value: &SignedComponentKeySec) -> Self {
        match value {
            SignedComponentKeySec::Primary(ssk) => {
                ComponentKeyPriv::Primary(ssk.primary_key.clone())
            }
            SignedComponentKeySec::Subkey((sssk, _)) => ComponentKeyPriv::Subkey(sssk.key.clone()),
        }
    }
}

impl SignedComponentKeyPub {
    /// This fn is intended for use on signing-capable component keys.
    /// It returns "false" is a subkey is not validly "backward-bound" to the primary.
    ///
    /// Note that this only checks the metadata, not the cryptographic signature as such. Embedded
    /// back signatures are cryptographically checked during creation of `Checked` instances.
    pub(crate) fn has_valid_backsig_at(
        &self,
        reference: Timestamp,
        primary_key_creation: Timestamp,
    ) -> bool {
        match self {
            SignedComponentKeyPub::Subkey(sssk) => {
                // If a subkey binding signature has no embedded back signature,
                // the subkey is not reasonably bound to the certificate for signing

                let Some(binding) = SigStack::from_iter(sssk.0.signatures.iter())
                    .active_at(reference, primary_key_creation)
                else {
                    // we don't have any binding at the reference time
                    return false;
                };

                let Some(backsig) = binding.embedded_signature() else {
                    // the binding includes no embedded back signature
                    return false;
                };

                let Some(creation) = backsig.created() else {
                    // A signature with unset creation time is invalid
                    return false;
                };

                if creation < primary_key_creation {
                    log::trace!("backsig is older than primary key creation");
                    return false;
                }

                // If the signature expires before the reference time, the signature is invalid
                // FIXME: do we allow signature expiration here?
                if let Some(sig_exp) = signature::signature_validity_expiration(backsig)
                    && sig_exp < reference
                {
                    log::trace!("signature is expired");
                    return false;
                }

                true
            }

            // A primary doesn't need a backsig to be "validly bound"
            SignedComponentKeyPub::Primary(_) => true,
        }
    }

    /// This fn presupposes that the primary is valid at the reference time
    pub(crate) fn is_component_subkey_valid_at(&self, reference: Timestamp) -> bool {
        match &self {
            SignedComponentKeyPub::Subkey(sk) => Self::is_subkey_valid_at(&sk.0, reference),
            SignedComponentKeyPub::Primary(_) => true,
        }
    }

    fn is_subkey_valid_at(spsk: &SignedPublicSubKey, reference: Timestamp) -> bool {
        let stack = SigStack::from_iter(spsk.signatures.iter());
        let Some(sig) = stack.active_at(reference, spsk.created_at()) else {
            log::trace!("no active sig");
            return false;
        };

        // is the binding signature a revocation?
        if signature::is_revocation(sig) {
            log::trace!("active is revocation");
            return false;
        }

        // If the key expires and expiration is before the reference time, the signature is invalid
        if let Some(key_exp) = sig.key_expiration_time()
            && key_exp.as_secs() != 0
            && (u64::from(spsk.created_at().as_secs()) + u64::from(key_exp.as_secs()) <= u64::from(reference.as_secs()))
        {
            return false;
        }

        true
    }

    /// Are we willing to encrypt to the algorithm/ECDH parameters of self?
    pub(crate) fn valid_encryption_algo(&self) -> bool {
        crate::policy::accept_for_encryption(self.public_params())
    }

    /// Find KeyFlags subpacket in hashed area, return first occurrence (if any)
    fn key_flag_subpacket(sig: &Signature) -> Option<KeyFlags> {
        let config = sig.config()?;

        config.hashed_subpackets.iter().find_map(|p| match &p.data {
            SubpacketData::KeyFlags(d) => Some(d.clone()),
            _ => None,
        })
    }

    pub(crate) fn key_flags_at(&self, reference: Timestamp) -> Option<KeyFlags> {
        match self {
            SignedComponentKeyPub::Primary((spk, dks)) => {
                // We favor the dks for the primary
                if let Some(dks) =
                    SigStack::from_iter(dks.iter()).active_at(reference, self.created_at())
                {
                    if let Some(kf) = Self::key_flag_subpacket(dks) {
                        return Some(kf);
                    }
                } else if let Some(prim_bind) =
                    primary_user_id_binding_at(&spk.details, reference, self.created_at())
                    && let Some(kf) = Self::key_flag_subpacket(prim_bind)
                {
                    return Some(kf);
                }

                None
            }
            SignedComponentKeyPub::Subkey((spsk, _)) => SigStack::from_iter(spsk.signatures.iter())
                .active_at(reference, spsk.created_at())
                .and_then(Self::key_flag_subpacket),
        }
    }

    pub(crate) fn is_encryption_capable(&self, reference: Timestamp) -> bool {
        if let Some(kf) = self.key_flags_at(reference) {
            return kf.encrypt_comms() || kf.encrypt_storage();
        }

        false
    }

    pub(crate) fn is_signing_capable(&self, reference: Timestamp) -> bool {
        if let Some(kf) = self.key_flags_at(reference) {
            return kf.sign();
        }

        false
    }

    pub(crate) fn is_authentication_capable(&self, reference: Timestamp) -> bool {
        if let Some(kf) = self.key_flags_at(reference) {
            return kf.authentication();
        }

        false
    }
}

impl ComponentKeyPub {
    pub fn pkesk_from_session_key_v3<R: CryptoRng + Rng>(
        &self,
        rng: &mut R,
        session_key: &[u8],
        alg: SymmetricKeyAlgorithm,
    ) -> Result<PublicKeyEncryptedSessionKey, Error> {
        match &self {
            Self::Primary(pk) => Ok(PublicKeyEncryptedSessionKey::from_session_key_v3(
                rng,
                &RawSessionKey::from(session_key),
                alg,
                pk,
            )?),
            Self::Subkey(psk) => Ok(PublicKeyEncryptedSessionKey::from_session_key_v3(
                rng,
                &RawSessionKey::from(session_key),
                alg,
                psk,
            )?),
        }
    }

    pub fn pkesk_from_session_key_v6<R: CryptoRng + Rng>(
        &self,
        rng: &mut R,
        session_key: &[u8],
    ) -> Result<PublicKeyEncryptedSessionKey, Error> {
        match &self {
            Self::Primary(pk) => Ok(PublicKeyEncryptedSessionKey::from_session_key_v6(
                rng,
                &RawSessionKey::from(session_key),
                pk,
            )?),
            Self::Subkey(psk) => Ok(PublicKeyEncryptedSessionKey::from_session_key_v6(
                rng,
                &RawSessionKey::from(session_key),
                psk,
            )?),
        }
    }

    /// Verify cryptographic signature, and perform rpgpie policy checks:
    ///
    /// Checks acceptability of the hash and signing algorithms at signature creation time,
    /// as well as plausibility checks of the involved timestamps.
    ///
    /// (Also see [`crate::signature::signature_acceptable`]).
    pub fn verify(&self, s: &Signature, payload: &[u8]) -> Result<(), Error> {
        // policy check on s
        if !signature::signature_acceptable(s) {
            return Err(Error::Message(
                "Signature doesn't satisfy our policy".to_string(),
            ));
        }

        match self {
            ComponentKeyPub::Primary(pri) => Ok(s.verify(pri, payload)?),
            ComponentKeyPub::Subkey(sub) => Ok(s.verify(sub, payload)?),
        }
    }
}
