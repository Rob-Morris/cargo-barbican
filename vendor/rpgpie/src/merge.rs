// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! OpenPGP certificates can be updated by "merging" new information into them.
//!
//! An update can consist of a [Certificate], or a bare revocation signature.
//! This module offers the type [CertificateInfo] to handle certificate update information,
//! and contains the business logic for certificate merging.

use std::{
    fs::File,
    io::{BufReader, Cursor, Read},
    mem,
    path::Path,
};

use pgp::{
    armor::Dearmor,
    composed::{Deserializable, SignedPublicKey, SignedSecretSubKey},
    packet::{Packet, PacketParser, Signature},
    types::KeyDetails,
};

use crate::{
    Error,
    certificate::{Certificate, Checked},
    signature::merge_signatures,
    tsk::Tsk,
    util::{canonicalize, verify_signature},
};

/// Information about a certificate, for use in a merge operation.
///
/// Contains either:
/// - a full certificate (aka OpenPGP public key), or
/// - a "revocation certificate" (i.e. a bare signature packet) that can apply to a certificate.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum CertificateInfo {
    Cert(Certificate),
    Revocation(Signature),
}

impl CertificateInfo {
    pub fn from_file(path: &Path) -> Result<Self, Error> {
        Self::from_reader(&mut File::open(path)?)
    }

    pub fn from_reader<R: Read>(mut reader: R) -> Result<Self, Error> {
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;

        Self::from_data(&data)
    }

    pub fn from_data(data: &[u8]) -> Result<Self, Error> {
        // Try if we parse `data` as a SignedPublicKey

        // FIXME: error if data contains more than one object

        if let Ok((spk, _)) = SignedPublicKey::from_reader_single(BufReader::new(Cursor::new(data)))
        {
            return Ok(CertificateInfo::Cert(spk.into()));
        }

        let rev = Self::parse_as_revocation_sig(data)?;
        Ok(CertificateInfo::Revocation(rev))
    }

    /// Try to parse `data` as a revocation signature (aka a "revocation certificate")
    fn parse_as_revocation_sig(data: &[u8]) -> Result<Signature, Error> {
        fn detect_armor(byte: u8) -> bool {
            byte & 0x80 == 0
        }

        // Detect armor
        let armored = match data.first() {
            Some(byte) => detect_armor(*byte),
            None => return Err(Error::Message("Not content found in data".to_string())),
        };

        let buf = BufReader::new(Cursor::new(data));

        // Create a packet parser for data
        let mut pp: Box<dyn Iterator<Item = pgp::errors::Result<Packet>> + '_> = if armored {
            let dearmor = Dearmor::new(buf);
            Box::new(PacketParser::new(BufReader::new(dearmor)))
        } else {
            Box::new(PacketParser::new(buf))
        };

        // Check if we find a (single) revocation signature in `data`
        match pp.next() {
            Some(Ok(Packet::Signature(sig))) => {
                if pp.next().is_some() {
                    // If this packet parser contains more packets, that's not ok
                    return Err(Error::Message("found more than one packet".to_string()));
                }

                // TODO: check the signature more closely (must be a revocation signature)

                Ok(sig)
            }
            res => Err(Error::Message(format!("Unexpected input data: {res:?}"))),
        }
    }
}

impl Certificate {
    /// Merge a list of updates into this Certificate.
    ///
    /// Updates can consist of different versions of this certificate, or "revocation certificates".
    ///
    /// Note: This merge function only does relatively minimal checks for validity of input data:
    ///
    /// - When merging in a Certificate it checks that the primary key's fingerprint matches between
    ///   the original certificate and the update.
    /// - When merging in a revocation signature, a cryptographic verification of the signature is
    ///   performed against the primary key.
    ///
    /// All other connections (subkey binding signatures, and any other self-signatures) are not
    /// currently validated.
    ///
    /// The main focus of this function is deduplication of components and signatures.
    /// All other validations are defined as out-of-scope, and need to be performed separately, if
    /// required.
    ///
    /// Also note: No special ordering is currently imposed within each set of components (subkeys,
    /// users, user attributes), or among the set of signatures associated with each component.
    ///
    /// That said, this function does not alter the ordering of elements in the original
    /// certificate if `updates` contains no additional information.
    pub fn merge(&mut self, updates: Vec<CertificateInfo>) {
        let merged = self;

        for update in updates {
            match update {
                CertificateInfo::Cert(update) => merged.merge_cert(update),
                CertificateInfo::Revocation(rev) => {
                    // Borrow the SPK to (potentially) merge the revocation signature into
                    let spk = merged.spk_mut();

                    if !spk.details.revocation_signatures.contains(&rev) {
                        // Merge the revocation into spk

                        // TODO: This might add a duplicate signature that differs only in framing
                        //       or unhashed subpackets

                        // Verify that the revocation fits with the primary key of the target
                        if verify_signature(&rev, &spk.primary_key) {
                            spk.details.revocation_signatures.push(rev)

                            // TODO: we could opt to not verify the signature here, and instead
                            // compare issuer fingerprint or issuer claims.
                            // That would work even for signatures that we can't verify.
                            // But at the risk of merging in signatures that aren't meaningfully
                            // related to this certificate.

                            // Maybe using hashed issuer fingerprint/issuer subpackets as an
                            // alternate signal to merge would be good?

                            // (Only checking for these subpackets would not work for anonymous
                            // revocation signatures that don't contain the issuer's identity.
                            // Is that a thing?)
                        } else {
                            log::info!(
                                "revocation signature {:#?} doesn't verify correctly against {:?}",
                                rev,
                                spk.fingerprint()
                            );
                        }

                        // TODO: Do we need to alternatively verify the revocation signature
                        //       against other components? The (primary) user id?!
                    }
                }
            };
        }

        // canonicalize
        let spk = merged.spk_mut();
        canonicalize(spk);
    }

    /// Merge the contents of the certificate `update` into `self`
    fn merge_cert(&mut self, update: Certificate) {
        // Switch to SPK representation for this operation
        let orig = self.spk_mut();
        let update: SignedPublicKey = update.into();

        // If the cert in "update" has a different primary fingerprint, we ignore its contents
        if orig.fingerprint() != update.fingerprint() {
            return; // early return
        }

        // Merge any additional information (components, signatures, signature subpackets)
        // from "update" into "orig"

        // Direct key signatures
        merge_signatures(
            &mut orig.details.direct_signatures,
            update.details.direct_signatures,
        );

        // Revocation signatures
        merge_signatures(
            &mut orig.details.revocation_signatures,
            update.details.revocation_signatures,
        );

        // Subkeys (and their signatures)
        for sk_update in update.public_subkeys {
            // Does `orig` have a subkey with this fingerprint already?
            if let Some(spsk) = orig
                .public_subkeys
                .iter_mut()
                .find(|sk| sk.fingerprint() == sk_update.fingerprint())
            {
                // Yes, check if additional signatures exist in update, and merge those into orig
                merge_signatures(&mut spsk.signatures, sk_update.signatures);
            } else {
                // No, add the subkey

                // FIXME: ordering?
                orig.public_subkeys.push(sk_update);
            }
        }

        // user ids (and their signatures)
        for uid in update.details.users {
            // Does `orig` have a userid with the same "id" value already?
            if let Some(su) = orig
                .details
                .users
                .iter_mut()
                .find(|x| x.id.id() == uid.id.id())
            {
                // Yes, check if additional signatures exist in update, and merge those into orig
                merge_signatures(&mut su.signatures, uid.signatures);
            } else {
                // No, add the userid

                // FIXME: ordering?
                orig.details.users.push(uid);
            }
        }

        // user attributes (and their signatures)
        for attr in update.details.user_attributes {
            // Does `orig` have a user attribute that compares as equal, already?
            if let Some(sua) = orig
                .details
                .user_attributes
                .iter_mut()
                .find(|x| x.attr == attr.attr)
            {
                // Yes, check if additional signatures exist in update, and merge those into orig
                merge_signatures(&mut sua.signatures, attr.signatures);
            } else {
                // No, add the user attribute

                // FIXME: ordering?
                orig.details.user_attributes.push(attr);
            }
        }
    }
}

impl Tsk {
    pub fn merge(&mut self, updates: Vec<CertificateInfo>) {
        let mut cert: Certificate = self.clone().into();
        cert.merge(updates);

        // Fully merged public key view.
        // This needs to be combined with the Secret Key Packets from self.ssk
        let spk: SignedPublicKey = cert.into();

        // Replace details completely from new view
        self.ssk.details = spk.details;

        // Remove all old subkey information from self, ...
        self.ssk.public_subkeys = Vec::new();
        // ... but keep the secret subkey packets around for reuse
        let old_secret_subkeys = mem::take(&mut self.ssk.secret_subkeys);

        for subkey in spk.public_subkeys {
            match old_secret_subkeys
                .iter()
                .find(|secret_subkey| secret_subkey.fingerprint() == subkey.fingerprint())
            {
                None => {
                    self.ssk.public_subkeys.push(subkey);
                }
                Some(secret_subkey) => self.ssk.secret_subkeys.push(SignedSecretSubKey {
                    key: secret_subkey.key.clone(),
                    signatures: subkey.signatures,
                }),
            }
        }

        // update the Checked in self
        self.checked = Checked::new(SignedPublicKey::from(self.ssk.clone()).into());
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
#[allow(clippy::panic)]
mod tests {
    use std::path::PathBuf;

    use pgp::{
        composed::KeyType,
        crypto::ecc_curve::ECCCurve,
        packet::{Notation, Signature, Subpacket, SubpacketData},
        types::{KeyId, KeyVersion, Password, Tag},
    };

    use crate::{certificate::Certificate, merge::CertificateInfo, tsk::Tsk};

    #[test]
    /// Test case "TestMergeAddSig" from Hockeypuck
    fn test_merge_add_sig() {
        let id: [u8; 8] = hex::decode("62aea01d67640fb5")
            .expect("hex")
            .try_into()
            .expect("8 byte");
        let expected_issuer = KeyId::from(id);

        let has_expected_sig = |s: &[Signature]| {
            s.iter()
                .any(|s| s.issuer_key_id().contains(&&expected_issuer))
        };

        // load certs, do minor consistency checking

        let CertificateInfo::Cert(alice_unsigned) =
            CertificateInfo::from_file(&PathBuf::from("tests/merge/hockeypuck/alice_unsigned.asc"))
                .expect("load")
        else {
            panic!("unexpected CertificateInfo variant");
        };

        assert!(!has_expected_sig(
            &alice_unsigned.spk().details.users[0].signatures
        ));

        let CertificateInfo::Cert(alice_signed) =
            CertificateInfo::from_file(&PathBuf::from("tests/merge/hockeypuck/alice_signed.asc"))
                .expect("load")
        else {
            panic!("unexpected CertificateInfo variant");
        };

        assert!(has_expected_sig(
            &alice_signed.spk().details.users[0].signatures
        ));

        // merge, check that result contains the new certification signature

        let mut merged = alice_unsigned;
        merged.merge_cert(alice_signed);

        assert_eq!(merged.spk().details.users[0].signatures.len(), 2);
        assert!(has_expected_sig(&merged.spk().details.users[0].signatures));
    }

    #[test]
    /// Test case "TestResolveRootSignatures" from Hockeypuck
    fn test_merge_rev_1() {
        let CertificateInfo::Cert(key) =
            CertificateInfo::from_file(&PathBuf::from("tests/merge/hockeypuck/test-key.asc"))
                .expect("load")
        else {
            panic!("unexpected CertificateInfo variant");
        };

        assert!(key.spk().details.revocation_signatures.is_empty());

        let revoked = CertificateInfo::from_file(&PathBuf::from(
            "tests/merge/hockeypuck/test-key-revoked.asc",
        ))
        .expect("load");

        let mut merged = key;
        merged.merge(vec![revoked]);

        assert_eq!(merged.spk().details.revocation_signatures.len(), 1);
    }

    #[test]
    /// Test case "TestMergeRevocationSig" from Hockeypuck
    fn test_merge_rev_2() {
        let CertificateInfo::Cert(key) =
            CertificateInfo::from_file(&PathBuf::from("tests/merge/hockeypuck/test-key.asc"))
                .expect("load")
        else {
            panic!("unexpected CertificateInfo variant");
        };

        assert!(key.spk().details.revocation_signatures.is_empty());

        let rev = CertificateInfo::from_file(&PathBuf::from(
            "tests/merge/hockeypuck/test-key-revoke.asc",
        ))
        .expect("load");

        let mut merged = key;
        merged.merge(vec![rev]);

        assert_eq!(merged.spk().details.revocation_signatures.len(), 1);
    }

    #[test]
    /// Test case "TestMergeWrongRevocationSig" from Hockeypuck
    /// (slight variation: this reuses the alice cert and a non-matched revocation)
    fn test_merge_rev_3() {
        let CertificateInfo::Cert(key) =
            CertificateInfo::from_file(&PathBuf::from("tests/merge/hockeypuck/alice_unsigned.asc"))
                .expect("load")
        else {
            panic!("unexpected CertificateInfo variant");
        };

        assert!(key.spk().details.revocation_signatures.is_empty());

        let rev = CertificateInfo::from_file(&PathBuf::from(
            "tests/merge/hockeypuck/test-key-revoke.asc", // mismatched!
        ))
        .expect("load");

        let mut merged = key;
        merged.merge(vec![rev]);
        assert!(merged.spk().details.revocation_signatures.is_empty());
    }

    #[test]
    fn tsk_merge_unchanged() {
        let tsk = Tsk::generate(
            KeyVersion::V4,
            KeyType::Ed25519Legacy,
            Some(KeyType::ECDH(ECCCurve::Curve25519Legacy)),
            Some("alice".into()),
            vec![],
            None,
        )
        .expect("generate");

        let cert: Certificate = tsk.clone().into();

        let mut tsk_merged = tsk.clone();
        tsk_merged.merge(vec![CertificateInfo::Cert(cert)]);

        // merging in a cert view shouldn't change anything
        assert_eq!(tsk.ssk, tsk_merged.ssk);
    }

    #[test]
    fn tsk_merge_new_uid_self_sig() {
        let tsk = Tsk::generate(
            KeyVersion::V4,
            KeyType::Ed25519Legacy,
            Some(KeyType::ECDH(ECCCurve::Curve25519Legacy)),
            Some("alice".into()),
            vec![],
            None,
        )
        .expect("generate");

        let mut cert: Certificate = tsk.clone().into();

        // add a new signature to the first user id in `cert`
        let sig = &cert.spk.details.users[0].signatures[0];
        let mut config = sig.config().expect("signature config").clone();

        config.hashed_subpackets.push(
            Subpacket::regular(SubpacketData::Notation(Notation {
                readable: true,
                value: "hello".into(),
                name: "world".into(),
            }))
            .expect("subpacket"),
        );

        let sig = config
            .sign_certification(
                &tsk.ssk.primary_key,
                tsk.ssk.primary_key.public_key(),
                &Password::empty(),
                Tag::UserId,
                &cert.spk.details.users[0].id,
            )
            .expect("sign");

        cert.spk.details.users[0].signatures.push(sig);

        // merge extended cert into tsk
        let mut tsk_merged = tsk.clone();
        tsk_merged.merge(vec![CertificateInfo::Cert(cert)]);

        // old tsk and new tsk should differ
        assert_ne!(tsk.ssk, tsk_merged.ssk);

        // new tsk should have two signatures on the user id
        assert_eq!(tsk_merged.ssk.details.users[0].signatures.len(), 2);
    }

    #[test]
    fn tsk_merge_new_subkey_self_sig() {
        let tsk = Tsk::generate(
            KeyVersion::V4,
            KeyType::Ed25519Legacy,
            Some(KeyType::ECDH(ECCCurve::Curve25519Legacy)),
            Some("alice".into()),
            vec![],
            None,
        )
        .expect("generate");

        let mut cert: Certificate = tsk.clone().into();

        // add a new signature to the first user id in `cert`
        let sig = &cert.spk.public_subkeys[0].signatures[0];
        let mut config = sig.config().expect("signature config").clone();

        config.hashed_subpackets.push(
            Subpacket::regular(SubpacketData::Notation(Notation {
                readable: true,
                value: "hello".into(),
                name: "world".into(),
            }))
            .expect("subpacket"),
        );

        let sig = config
            .sign_subkey_binding(
                &tsk.ssk.primary_key,
                tsk.ssk.primary_key.public_key(),
                &Password::empty(),
                &cert.spk.public_subkeys[0].key,
            )
            .expect("sign");

        cert.spk.public_subkeys[0].signatures.push(sig);

        // merge extended cert into tsk
        let mut tsk_merged = tsk.clone();
        tsk_merged.merge(vec![CertificateInfo::Cert(cert)]);

        // old tsk and new tsk should differ
        assert_ne!(tsk.ssk, tsk_merged.ssk);

        // new tsk should have two signatures on the subkey
        assert_eq!(tsk_merged.ssk.secret_subkeys[0].signatures.len(), 2);
    }
}
