// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wrapper types and logic around OpenPGP private keys, aka TSKs ("transferable secret keys").

use std::{
    fmt::{Debug, Formatter},
    io,
};

use pgp::{
    composed::{
        CleartextSignedMessage,
        Deserializable,
        EncryptionCaps,
        KeyType,
        PublicOrSecret,
        SecretKeyParamsBuilder,
        SignedPublicKey,
        SignedSecretKey,
        SubkeyParamsBuilder,
    },
    crypto::{hash::HashAlgorithm, public_key::PublicKeyAlgorithm},
    packet::Signature,
    ser::Serialize,
    types::{
        Fingerprint,
        KeyDetails,
        KeyId,
        KeyVersion,
        Password,
        PublicParams,
        SignatureBytes,
        SigningKey,
        Timestamp,
    },
};
use rand::thread_rng;

use crate::{
    Error,
    certificate::{Certificate, Checked},
    key::{ComponentKeyPriv, ComponentKeyPub, KeyFlagMatch, SignedComponentKeySec},
    message::SignatureMode,
    policy::{
        PREFERRED_AEAD_ALGORITHMS,
        PREFERRED_COMPRESSION_ALGORITHMS,
        PREFERRED_HASH_ALGORITHMS,
        PREFERRED_HASH_ALGORITHMS_V6,
        PREFERRED_SYMMETRIC_KEY_ALGORITHMS,
    },
    signature::SigStack,
};

/// A "transferable secret key (TSK)," also known as an "OpenPGP private/secret key."
#[derive(Clone)]
pub struct Tsk {
    pub(crate) ssk: SignedSecretKey,

    /// keep a "checked" version of the ssk, to find valid component keys on
    pub(crate) checked: Checked,
}

impl TryFrom<&[u8]> for Tsk {
    type Error = Error;

    fn try_from(input: &[u8]) -> Result<Self, Self::Error> {
        let (ssk, _) = SignedSecretKey::from_reader_single(input)?;
        Ok(ssk.into())
    }
}

impl From<SignedSecretKey> for Tsk {
    fn from(ssk: SignedSecretKey) -> Self {
        let spk = SignedPublicKey::from(ssk.clone());
        let checked = Certificate::from(spk).into();

        Self { ssk, checked }
    }
}

/// A signer that's based on a private component key that is marked as capable of producing data
/// signatures.
pub struct DataSigner {
    pub(crate) key: ComponentKeyPriv,
}

impl KeyDetails for DataSigner {
    fn version(&self) -> KeyVersion {
        self.key.version()
    }

    fn fingerprint(&self) -> Fingerprint {
        self.key.fingerprint()
    }

    fn legacy_key_id(&self) -> KeyId {
        self.key.legacy_key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.key.algorithm()
    }

    fn created_at(&self) -> Timestamp {
        self.key.created_at()
    }

    fn legacy_v3_expiration_days(&self) -> Option<u16> {
        self.key.legacy_v3_expiration_days()
    }

    fn public_params(&self) -> &PublicParams {
        self.key.public_params()
    }
}

impl Debug for DataSigner {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.key.fmt(f)
    }
}

impl SigningKey for DataSigner {
    fn sign(
        &self,
        key_pw: &Password,
        hash: HashAlgorithm,
        data: &[u8],
    ) -> pgp::errors::Result<SignatureBytes> {
        self.key.sign(key_pw, hash, data)
    }

    fn hash_alg(&self) -> HashAlgorithm {
        self.key.hash_alg()
    }
}

impl DataSigner {
    /// Takes some raw data as input, and produces a detached data Signature packet
    pub fn sign_data(
        &self,
        data: &[u8],
        sig_mode: SignatureMode,
        key_pw: &Password,
        hash_algo: HashAlgorithm,
    ) -> Result<Signature, Error> {
        self.key.sign_data(data, sig_mode, key_pw, hash_algo)
    }

    /// Takes a message as input, and produces a cleartext signed message
    pub fn sign_csf(&self, body: &str, key_pw: &Password) -> Result<CleartextSignedMessage, Error> {
        match &self.key {
            // FIXME: DRY?
            ComponentKeyPriv::Primary(sk) => Ok(CleartextSignedMessage::sign(
                thread_rng(),
                body,
                sk,
                key_pw,
            )?),
            ComponentKeyPriv::Subkey(ssk) => Ok(CleartextSignedMessage::sign(
                thread_rng(),
                body,
                ssk,
                key_pw,
            )?),
        }
    }

    /// The fingerprint of the underlying component private key
    pub fn fingerprint(&self) -> Fingerprint {
        self.key.fingerprint()
    }
}

impl Tsk {
    /// Load a set of `Tsk`s from a source.
    ///
    /// The source data may be armored or binary.
    pub fn load<R: io::Read>(read: &mut R) -> Result<Vec<Tsk>, Error> {
        let (keys, _headers) = PublicOrSecret::from_reader_many(read)?;

        let mut tsk = vec![];

        for res in keys {
            match res {
                Ok(pos) => match pos {
                    PublicOrSecret::Public(spk) => {
                        log::warn!("Bad data {spk:?}");
                    }
                    PublicOrSecret::Secret(ssk) => {
                        tsk.push(ssk.into());
                    }
                },
                Err(_) => log::warn!("Bad data {res:?}"),
            }
        }

        if tsk.is_empty() {
            Err(Error::Message("No TSKs found".to_string()))
        } else {
            Ok(tsk)
        }
    }

    /// Save this Tsk to a writer
    pub fn save(&self, armored: bool, sink: &mut dyn io::Write) -> Result<(), Error> {
        Self::save_all([self], armored, sink)
    }

    /// Save a set of Certificates to a writer
    pub fn save_all<'a>(
        tsks: impl IntoIterator<Item = &'a Self>,
        armored: bool,
        mut sink: &mut dyn io::Write,
    ) -> Result<(), Error> {
        if armored {
            let ssks: Vec<_> = tsks.into_iter().map(|tsk| &tsk.ssk).collect();

            // Only emit armor checksum if any of the keys is pre-v6
            let armor_checksum = ssks.iter().any(|ssk| ssk.version() < KeyVersion::V6);

            pgp::armor::write(
                &ssks,
                pgp::armor::BlockType::PrivateKey,
                &mut sink,
                None,
                armor_checksum,
            )?;
        } else {
            for tsk in tsks {
                tsk.ssk.to_writer(&mut sink)?;
            }
        }

        Ok(())
    }

    /// FIXME: remove this from the API again?
    pub fn key(&self) -> &SignedSecretKey {
        &self.ssk
    }

    pub fn generate(
        key_version: KeyVersion,
        key_type_primary: KeyType,
        key_type_encrypt: impl Into<Option<KeyType>>,
        primary_user_id: Option<String>,
        secondary_user_ids: Vec<String>,
        key_password: Option<&'_ Password>,
    ) -> Result<Self, Error> {
        let mut rng = thread_rng();

        let subkeys = if let Some(key_type_encrypt) = key_type_encrypt.into() {
            vec![
                SubkeyParamsBuilder::default()
                    .version(key_version)
                    .key_type(key_type_encrypt)
                    .can_encrypt(EncryptionCaps::All)
                    .build()?,
            ]
        } else {
            vec![]
        };

        // In V6 keys we add newer hash algorithms to the preferences (Sha3)
        let pref_hash = if key_version == KeyVersion::V6 {
            PREFERRED_HASH_ALGORITHMS_V6.into()
        } else {
            PREFERRED_HASH_ALGORITHMS.into()
        };

        let mut key_params = SecretKeyParamsBuilder::default();
        key_params
            .version(key_version)
            .key_type(key_type_primary)
            .can_certify(true)
            .can_sign(true)
            .preferred_symmetric_algorithms(PREFERRED_SYMMETRIC_KEY_ALGORITHMS.into())
            .preferred_hash_algorithms(pref_hash)
            .preferred_compression_algorithms(PREFERRED_COMPRESSION_ALGORITHMS.into())
            .preferred_aead_algorithms(PREFERRED_AEAD_ALGORITHMS.into())
            .user_ids(secondary_user_ids)
            .subkeys(subkeys);

        if key_version == KeyVersion::V6 {
            key_params.feature_seipd_v2(true);
        }

        if let Some(primary_user_id) = primary_user_id {
            key_params.primary_user_id(primary_user_id);
        }

        let secret_key_params = key_params.build()?;
        let mut signed_secret_key = secret_key_params.generate(&mut rng)?;

        if let Some(key_password) = key_password {
            signed_secret_key
                .primary_key
                .set_password(&mut rng, key_password)?;

            for sk in &mut signed_secret_key.secret_subkeys {
                sk.key.set_password(&mut rng, key_password)?;
            }
        };

        Ok(signed_secret_key.into())
    }

    fn get_matching_secret_key(&self, ckp: &ComponentKeyPub) -> Option<ComponentKeyPriv> {
        match ckp {
            ComponentKeyPub::Primary(pri) => {
                let sk = &self.ssk.primary_key;

                if pri.fingerprint() == sk.fingerprint() {
                    // FIXME: compare more efficiently?
                    Some(ComponentKeyPriv::Primary(sk.clone()))
                } else {
                    None
                }
            }

            ComponentKeyPub::Subkey(sub) => {
                for sssk in &self.ssk.secret_subkeys {
                    // FIXME: compare more efficiently?
                    if sub.fingerprint() == sssk.fingerprint() {
                        return Some(ComponentKeyPriv::Subkey(sssk.key.clone()));
                    }
                }

                // Found no match
                None
            }
        }
    }

    /// Get list of all *valid* signing capable component keys
    /// (this fn is specific to *signing*, not validation: it uses "now" as its reference time and
    /// is thus stricter)
    pub fn signing_capable_component_keys(&self) -> impl Iterator<Item = DataSigner> + '_ {
        let now = Timestamp::now();
        let sv = self.checked.valid_signing_capable_component_keys_at(now);

        let mut ds = vec![];

        for ckp in sv.iter().map(|sv| sv.as_componentkey()) {
            // Find associated secret key packet
            let key = self.get_matching_secret_key(ckp);

            if let Some(key) = key {
                ds.push(DataSigner { key });
            } else {
                log::warn!(
                    "signing_capable_component_keys: failed to find secret key packet for {:?}",
                    ckp.fingerprint()
                );
            }
        }

        ds.into_iter()
    }

    fn sec_components(&self) -> Vec<SignedComponentKeySec> {
        let x = SignedComponentKeySec::Primary(self.ssk.clone());
        let mut v = vec![x];

        let now = Timestamp::now();

        self.ssk.secret_subkeys.iter().for_each(|sssk| {
            let dks = SigStack::from_iter(self.ssk.details.direct_signatures.iter())
                .active_at(now, self.ssk.primary_key.public_key().created_at());

            let x = SignedComponentKeySec::Subkey((sssk.clone(), dks.cloned()));
            v.push(x);
        });

        v
    }

    /// Get all component secret keys that have a "signing capable" key flag.
    ///
    /// NOTE: this function doesn't cryptographically verify self-signatures, it's not safe to use
    /// on potentially attacker-controlled Tsks.
    pub fn signing_keys_sec(&self) -> Vec<ComponentKeyPriv> {
        // FIXME: filter out revoked subkeys

        self.sec_components()
            .iter()
            .filter(|x| {
                x.has_key_flag(
                    KeyFlagMatch::Sign,
                    self.ssk.primary_key.public_key().created_at(),
                )
            })
            .map(Into::into)
            .collect()
    }

    /// Get all component secret keys that have an "encryption capable" key flag.
    ///
    /// NOTE: this function doesn't cryptographically verify self-signatures, it's not safe to use
    /// on potentially attacker-controlled Tsks.
    pub fn decryption_keys_sec(&self) -> Vec<ComponentKeyPriv> {
        // This should actually not filter out revoked subkeys - we may still want to decrypt with
        // them!

        // FIXME: filter out unknown notations

        self.sec_components()
            .iter()
            .filter(|x| {
                x.has_key_flag(
                    KeyFlagMatch::Enc,
                    self.ssk.primary_key.public_key().created_at(),
                )
            })
            .map(Into::into)
            .collect()
    }

    /// Get all component secret keys that have an "authentication capable" key flag.
    ///
    /// NOTE: this function doesn't cryptographically verify self-signatures, it's not safe to use
    /// on potentially attacker-controlled Tsks.
    pub fn auth_keys_sec(&self) -> Vec<ComponentKeyPriv> {
        // FIXME: filter out revoked subkeys

        self.sec_components()
            .iter()
            .filter(|x| {
                x.has_key_flag(
                    KeyFlagMatch::Auth,
                    self.ssk.primary_key.public_key().created_at(),
                )
            })
            .map(Into::into)
            .collect()
    }

    pub fn as_signed_secret_key(&self) -> &SignedSecretKey {
        &self.ssk
    }
}
