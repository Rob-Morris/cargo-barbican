// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Handling of OpenPGP messages.

use std::{
    borrow::Cow,
    io::{Read, Write},
};

use pgp::{
    composed::{
        ArmorOptions,
        DecryptionOptions,
        Edata,
        Encryption,
        Esk,
        Message,
        MessageBuilder,
        PlainSessionKey,
        SignedSecretKey,
        TheRing,
        VerificationResult,
        decrypt_session_key_with_password,
    },
    crypto::{
        aead::{AeadAlgorithm, ChunkSize},
        sym::SymmetricKeyAlgorithm,
    },
    packet::{Features, ProtectedDataConfig, SymEncryptedProtectedDataConfig},
    types::{KeyDetails, KeyVersion, Password, SigningKey, StringToKey, Timestamp, VerifyingKey},
};
use rand::{CryptoRng, Rng};
use zeroize::Zeroizing;

use crate::{
    Error,
    certificate::{Certificate, Checked},
    key::{ComponentKeyPub, SignedComponentKeyPub},
    message,
    policy::Seipd,
    signature::Verified,
    tsk::Tsk,
    util::{pick_signers, pqc_picker},
};

/// Result of decrypting and/or verifying the signatures of a message with [unpack].
///
/// Depending on the format of the processed message, this result contains:
/// - The cleartext of the message.
/// - The session key, if the message was encrypted.
/// - A list of signatures that were found to be valid.
pub struct MessageResult<'c, 's> {
    pub validated: Vec<Verified<'c, 's>>,

    pub session_key: Option<(u8, Vec<u8>)>,
    pub cleartext: Vec<u8>,

    /// How this message was encrypted (if at all)
    pub encryption_mode: EncryptionMode,
}

pub enum EncryptionMode {
    Unencrypted,
    Sed,
    Seipdv1,
    GnupgAead,
    Seipdv2,
}

/// Process an existing message: Decrypt message, and/or verify signatures.
///
/// This function handles messages that are encrypted, signed or both.
///
/// More specifically: OpenPGP messages may consist of layers of encryption, signing and
/// compression. This function processes arbitrary combinations of these layers, up to a maximum
/// layering depth.
///
/// The return value encodes (to some degree) the properties the message:
///
/// - It returns the cleartext of the message, and
/// - A list of the signatures on the message that were found to be valid (if any).
///
/// **Decryption**
///
/// Decryption can be attempted using two distinct mechanisms:
///
/// 1. Using a private OpenPGP component key provided via `decryptor`. The OpenPGP component key may
///    optionally be protected with a passphrase. Unlocking such protected keys will be attempted
///    with the passphrases provided in `key_passwords` (if any).
///
/// 2. A symmetric key, represented by a passphrase, in `skesk_passwords` (OpenPGP messages can be
///    encrypted to a recipient who is not using an OpenPGP key, with this method).
///
/// **Signature verification**
///
/// If the message has been signed, signatures will be verified against the certificates in
/// `verifier`. Any correct signatures will be reported in the `MessageResult`.
///
/// **Compression layers**
///
/// If the message has compression layers, they will be unpacked, silently.
pub fn unpack<'c, 's>(
    mut msg: Message,
    decryptors: Vec<&SignedSecretKey>,
    dec_pws: Vec<&Password>,
    skesk_passwords: Vec<&Password>,
    session_keys: &[(SymmetricKeyAlgorithm, &[u8])],
    verifier: &'c [Certificate],
) -> Result<MessageResult<'c, 's>, Error> {
    if msg.is_compressed() {
        msg = msg.decompress()?;
    }

    // FIXME: handle v6 session keys
    // FIXME: handle multiple session keys usefully somehow?
    let session_keys: Vec<PlainSessionKey> = session_keys
        .iter()
        .map(|(algo, key)| PlainSessionKey::V3_4 {
            key: (*key).into(),
            sym_alg: *algo,
        })
        .collect();

    // stores the session key, if any existed and could be decrypted
    let mut sk = None;

    // store how the message was encrypted
    let mut encryption_mode = EncryptionMode::Unencrypted;

    if msg.is_encrypted() {
        let Message::Encrypted {
            esk: esks, edata, ..
        } = &msg
        else {
            return Err(Error::Message(
                "Inconsistent encryption state of message".to_string(),
            ));
        };

        if !session_keys.is_empty() {
            sk = Some(session_keys[0].clone());

            if session_keys.len() > 1 {
                // warn that multiple session keys are not supported
                log::warn!("Multiple session keys are not supported, trying the first one")
            }
        }

        encryption_mode = match edata {
            Edata::SymEncryptedData { .. } => EncryptionMode::Sed,
            Edata::SymEncryptedProtectedData { reader } => match reader.config() {
                ProtectedDataConfig::Seipd(config) => match config {
                    SymEncryptedProtectedDataConfig::V1 => EncryptionMode::Seipdv1,
                    SymEncryptedProtectedDataConfig::V2 { .. } => EncryptionMode::Seipdv2,
                },
                ProtectedDataConfig::GnupgAead(_) => {
                    return Err(Error::Message("Inconsistent encrypted data".to_string()));
                }
            },
            Edata::GnupgAeadData { .. } => EncryptionMode::GnupgAead,
        };

        // remember if we tried to unlock any secret key packet
        let mut tried_locked_decryptor = false;

        for esk in esks {
            match esk {
                Esk::PublicKeyEncryptedSessionKey(pkesk) => {
                    for ssk in &decryptors {
                        let pws = if !dec_pws.is_empty() {
                            dec_pws.as_slice()
                        } else {
                            &[&Password::empty()]
                        };

                        for pw in pws {
                            let tsk = Tsk::from((*ssk).clone());
                            for cks in tsk.decryption_keys_sec() {
                                if cks.is_locked() {
                                    tried_locked_decryptor = true;
                                }

                                if let Ok(s) = cks.decrypt_session_key(pkesk, pw) {
                                    sk = Some(s);
                                    break;
                                }
                            }
                        }
                    }
                }
                Esk::SymKeyEncryptedSessionKey(skesk) => {
                    for pw in &skesk_passwords {
                        if let Ok(session_key) = decrypt_session_key_with_password(skesk, pw) {
                            // For v4 SKESK, there is some concern if decryption yields a correct
                            // SessionKey, because there's not much integrity protection.
                            //
                            // However, if rPGP returns Ok, then the decrypted algorithm and key
                            // length passed a plausibility check, so we assume the SessionKey
                            // is not random junk, but indeed valid.

                            sk = Some(session_key);
                            break;
                        }
                    }
                }
            }
        }

        match &sk {
            Some(sk) => {
                // decrypt the message
                let ring = TheRing {
                    session_keys: vec![sk.clone()],
                    decrypt_options: DecryptionOptions::new().enable_gnupg_aead(),
                    ..Default::default()
                };
                msg = msg.decrypt_the_ring(ring, true)?.0;
            }
            None => {
                if tried_locked_decryptor {
                    // FIXME: return CantUnlock (but for which primary?)
                    return Err(Error::Message(
                        "Couldn't unlock secret key packet".to_string(),
                    ));
                } else {
                    // FIXME: add specialized error type
                    return Err(Error::Message("Couldn't decrypt message".to_string()));
                }
            }
        }
    }

    // we are willing to strip away a few layers of compression
    let mut i = 0;
    while msg.is_compressed() && i < 3 {
        msg = msg.decompress()?;

        i += 1;
    }

    let cleartext = msg.as_data_vec()?;

    // Signature verification in streaming mode:
    //
    // In this first step, we pass in all component keys that could possibly be validation-capable.
    //
    // We don't know signature creation times here, so we can't check for actual validity of
    // verifiers at signature creation time. We filter for that in a next step, further down.
    let mut verifiers: Vec<(SignedComponentKeyPub, &Certificate)> = vec![];
    for vcert in verifier {
        vcert
            .validation_capable_component_keys()
            .for_each(|v| verifiers.push((v, vcert)));
    }

    let keys: Vec<_> = verifiers
        .iter()
        .map(|(sck, _)| sck as &dyn VerifyingKey)
        .collect();

    let verification_result = msg.verify_nested(keys.as_ref())?;

    // - do policy checks:
    //   * signature_acceptable
    //   * valid_signing_capable_component_keys_at
    let validations: Vec<Verified> = verification_result
        .into_iter()
        .zip(verifiers.iter())
        .filter(|(vr, _)| {
            if let VerificationResult::Valid(sig) = &vr {
                crate::signature::signature_acceptable(sig)
            } else {
                false
            }
        })
        .filter(|(vr, (sck, cert))| {
            if let VerificationResult::Valid(sig) = &vr {
                if let Some(created) = sig.created() {
                    // reject signatures "from the future"
                    if created > Timestamp::now() {
                        return false;
                    }

                    let checked = Checked::from((*cert).clone());
                    let valid = checked.valid_signing_capable_component_keys_at(created);

                    // FIXME: compare by raw keys, not fingerprint
                    // FIXME: efficient lookup?
                    valid
                        .iter()
                        .any(|sv| sv.as_componentkey().fingerprint() == sck.fingerprint())
                } else {
                    false
                }
            } else {
                false
            }
        })
        .map(|(vr, (sckp, cert))| {
            let VerificationResult::Valid(sig) = vr else {
                unreachable!("checked")
            };

            let ckp: ComponentKeyPub = sckp.clone().into();

            Verified {
                sig: Cow::Owned(sig),
                component: ckp.fingerprint(),
                certs: vec![cert],
            }
        })
        .collect();

    // FIXME: deduplicate validations?

    let mr = MessageResult {
        cleartext,
        session_key: sk.and_then(|sk| match &sk {
            PlainSessionKey::V3_4 { key, sym_alg } => {
                Some(((*sym_alg).into(), key.as_ref().to_vec()))
            }
            _ => None,
        }),
        validated: validations,
        encryption_mode,
    };

    Ok(mr)
}

/// Configuration for encryption, either as SeipdV1 or SeipdV2
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum EncryptionMechanism {
    SeipdV1(SymmetricKeyAlgorithm),
    SeipdV2(AeadAlgorithm, SymmetricKeyAlgorithm),
}

/// Mode for data signatures: Signature over binary data or over normalized text data.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SignatureMode {
    /// Produce SignatureType::Binary
    Binary,

    /// Produce SignatureType::Text over normalized payload
    Text,
}

/// SOP-style inline-sign operation
pub fn inline_sign<R: Read, W: Write>(
    source: R,
    sink: W,
    signers: &[Tsk],
    signers_passwords: &[Password],
    signature_mode: SignatureMode,
    armor: bool,
) -> Result<(), Error> {
    let data_signers = pick_signers(signers, signers_passwords)?;

    let all_v6 = !data_signers.iter().any(|s| s.version() != KeyVersion::V6);

    let mut builder = MessageBuilder::from_reader("", source);

    for ds in &data_signers {
        builder.sign(ds, Password::empty(), ds.hash_alg());
    }

    if signature_mode == SignatureMode::Text {
        builder.sign_text();
    }

    let rng = rand::thread_rng();
    if armor {
        let armor_options = ArmorOptions {
            headers: None,
            include_checksum: !all_v6,
        };

        builder.to_armored_writer(rng, armor_options, sink)?;
    } else {
        builder.to_writer(rng, sink)?;
    }

    Ok(())
}

/// Encrypt (and optionally sign) a message.
///
/// NOTE: `source` is expected to contain raw data, not an OpenPGP Message
///
/// `seipd`, if set, may override internal preference calculations,
/// and is applied for SKESK-only encryption.
//
// TODO: set  recipient primary as intended recipient?
#[allow(clippy::too_many_arguments)]
pub fn encrypt(
    seipd: Option<Seipd>,
    recipients: Vec<Certificate>,
    skesk_passwords: Vec<&Password>,
    signers: Vec<Tsk>,
    signers_passwords: &[&Password],
    source: &mut (dyn Read + Send + Sync),
    signature_mode: SignatureMode,
    mut sink: &mut (dyn std::io::Write + Send + Sync),
    armor: bool,
) -> Result<(Zeroizing<Vec<u8>>, Option<SymmetricKeyAlgorithm>), Error> {
    let mut rng = rand::thread_rng();

    let checked: Vec<Checked> = recipients.iter().map(|c| c.clone().into()).collect();

    // --- algorithm prefs calculations ---
    let now = Timestamp::now();

    let mut symmetric_algorithms_pref = crate::policy::PREFERRED_SYMMETRIC_KEY_ALGORITHMS.to_vec();
    let mut aead_algorithms_pref = crate::policy::PREFERRED_AEAD_ALGORITHMS.to_vec();
    let mut seipd_pref = crate::policy::PREFERRED_SEIPD_MECHANISMS.to_vec();

    for ccert in checked {
        // Handle recipient symmetric algorithm preferences, if any
        // (calculate intersection with our defaults)
        if let Some(p) = ccert.preferred_symmetric_key_algo(now) {
            symmetric_algorithms_pref.retain(|a| p.contains(a));
        }

        // Handle recipient aead preferences, if any
        // (calculate intersection with our defaults)
        if let Some(p) = ccert.preferred_aead_algo(now) {
            aead_algorithms_pref.retain(|a| p.contains(a));
        }

        // Handle SEIPD preferences, if any
        // (calculate intersection with our defaults)
        if let Some(feat) = ccert.features(now) {
            fn contains(feat: &Features, seipd: Seipd) -> bool {
                match seipd {
                    Seipd::SEIPD1 => feat.seipd_v1(),
                    Seipd::SEIPD2 => feat.seipd_v2(),
                }
            }

            seipd_pref.retain(|a| contains(feat, *a));
        } else {
            // if there's no features setting, we only do SeipdV1
            seipd_pref = vec![Seipd::SEIPD1]
        }
    }

    let mechanism = if !recipients.is_empty() {
        // If we have recipients, we choose the Seipd version purely based on their preferences
        let seipd = *seipd_pref.first().unwrap_or(&Seipd::SEIPD1);
        match seipd {
            Seipd::SEIPD1 => {
                let symmetric_algo = symmetric_algorithms_pref
                    .first()
                    .cloned()
                    .unwrap_or(SymmetricKeyAlgorithm::default());

                message::EncryptionMechanism::SeipdV1(symmetric_algo)
            }
            Seipd::SEIPD2 => {
                let aead_algo = aead_algorithms_pref
                    .first()
                    .unwrap_or(&(SymmetricKeyAlgorithm::AES128, AeadAlgorithm::Ocb));

                message::EncryptionMechanism::SeipdV2(aead_algo.1, aead_algo.0)
            }
        }
    } else {
        // If we have no recipients, choose seipd1 vs. seipd2 based on the `seipd` parameter,
        // or default to seipd1
        match seipd.unwrap_or(Seipd::SEIPD1) {
            Seipd::SEIPD1 => EncryptionMechanism::SeipdV1(SymmetricKeyAlgorithm::default()),
            Seipd::SEIPD2 => {
                EncryptionMechanism::SeipdV2(AeadAlgorithm::Ocb, SymmetricKeyAlgorithm::default())
            }
        }
    };

    // --- actual message generation / encryption ---

    let mut builder = MessageBuilder::from_reader("", source);

    if matches!(signature_mode, SignatureMode::Text) {
        builder.sign_text();
    }

    let session_key;
    let sym_alg;

    match mechanism {
        EncryptionMechanism::SeipdV1(sym) => {
            let mut all_v6 = true;

            let mut builder = builder.seipd_v1(&mut rng, sym);
            session_key = builder.session_key().clone();
            sym_alg = Some(sym);

            for cert in &recipients {
                let mut encrypted = false;

                let ccert: Checked = cert.clone().into();

                let enc = ccert.valid_encryption_capable_component_keys();

                for key in pqc_picker(enc) {
                    if builder.encrypt_to_key(&mut rng, &key).is_ok() {
                        encrypted = true;

                        if key.version() < KeyVersion::V6 {
                            all_v6 = false;
                        }
                    }
                }

                if !encrypted {
                    // Can be mapped to sop::errors::Error::CertCannotEncrypt in rsop
                    return Err(Error::InvalidPrimary);
                }
            }

            for pw in skesk_passwords {
                builder.encrypt_with_password(StringToKey::new_default(&mut rng), pw)?;
            }

            sign_and_write(
                &mut rng,
                builder,
                signers,
                signers_passwords,
                &mut sink,
                armor,
                !all_v6, // produce CRC24 if not all encryption keys are v6
            )?;
        }
        EncryptionMechanism::SeipdV2(aead, sym) => {
            let mut builder = builder.seipd_v2(&mut rng, sym, aead, ChunkSize::default());
            session_key = builder.session_key().clone();
            sym_alg = None;

            for cert in &recipients {
                let mut encrypted = false;

                let ccert: Checked = cert.clone().into();

                let enc = ccert.valid_encryption_capable_component_keys();

                for key in pqc_picker(enc) {
                    if builder.encrypt_to_key(&mut rng, &key).is_ok() {
                        encrypted = true;
                    }
                }

                if !encrypted {
                    return Err(Error::NotEncryptionCapable(cert.fingerprint()));
                }
            }

            for pw in skesk_passwords {
                // "If much less memory is available, a uniformly safe option is Argon2id with
                // t=3 iterations, p=4 lanes, m=2^(16) (64 MiB of RAM),
                // 128-bit salt, and 256-bit tag size. This is the SECOND RECOMMENDED option."

                // FIXME: move these settings up to rPGP, as part of a convenience constructor?
                let s2k = StringToKey::new_argon2(&mut rng, 3, 4, 16);

                builder.encrypt_with_password(&mut rng, s2k, pw)?;
            }

            sign_and_write(
                &mut rng,
                builder,
                signers,
                signers_passwords,
                &mut sink,
                armor,
                false, // no CRC24 for seipdv2
            )?;
        }
    };

    Ok((session_key.as_ref().to_vec().into(), sym_alg))
}

fn sign_and_write<R: Read, RAND: CryptoRng + Rng, E: Encryption>(
    rng: &mut RAND,
    builder: MessageBuilder<R, E>,
    signers: Vec<Tsk>,
    signers_passwords: &[&Password],
    sink: &mut (dyn std::io::Write + Send + Sync),
    armor: bool,
    armor_crc: bool,
) -> Result<(), Error> {
    // Ownership shuffle. TODO: cleanup.
    let pws: Vec<_> = signers_passwords
        .iter()
        .map(|pw| Password::from(pw.read().as_slice()))
        .collect();

    let dss = pick_signers(&signers, &pws)?;

    let mut builder = builder;
    for ds in &dss {
        let hash_algorithm = ds.hash_alg();
        builder.sign(ds, Password::empty(), hash_algorithm);
    }

    if armor {
        // Don't emit crc24 for modern messages:
        // - seipdv2 encryption
        // - seipdv1 encryption to v6 keys only
        //
        // This ignores properties of the signing layer (if any).
        // Reasoning: If the encryption layer is modern, then legacy implementations
        // cannot reach the signature layer.
        // Modern signatures on a legacy encryption layer are not considered enough reason to
        // omit the crc24 checksum.
        let armor_options = ArmorOptions {
            headers: None,
            include_checksum: armor_crc,
        };

        builder.to_armored_writer(rng, armor_options, sink)?;
    } else {
        builder.to_writer(rng, sink)?;
    }

    Ok(())
}
