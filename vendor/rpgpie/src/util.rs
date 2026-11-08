// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use pgp::{
    composed::SignedPublicKey,
    crypto::ecc_curve::ECCCurve,
    packet::{PublicKey, Signature},
    types::{EcdsaPublicParams, EddsaLegacyPublicParams, KeyDetails, Password, PublicParams},
};
use rsa::signature::digest::DynDigest;

use crate::{
    Error,
    certificate::Certificate,
    key::ComponentKeyPub,
    model::info::{print::print_cert_info, transform::cert_to_info},
    signature::{merge_unhashed, signature_bytes_eq},
    tsk::{DataSigner, Tsk},
};

/// Pick the signature with the newer creation time, if creation time differs
pub(crate) fn newer<'a>(a: &'a Signature, b: &'a Signature) -> &'a Signature {
    if a.created() > b.created() { a } else { b }
}

/// Produce a human-readable name for the public key algorithm in a PublicParams
pub(crate) fn algo_name(pp: &PublicParams) -> String {
    match pp {
        PublicParams::RSA(key) => {
            use rsa::traits::PublicKeyParts;
            format!("RSA({})", key.key.n().to_bytes_be().len() * 8)
        }
        PublicParams::DSA(key) => {
            format!("DSA({})", key.key.y().to_bytes_be().len() * 8)
        }
        PublicParams::Elgamal(_) => "Elgamal".to_string(),

        PublicParams::ECDH(params) => {
            format!("ECDH/{}", params.curve().name())
        }

        PublicParams::ECDSA(params) => {
            let curve = match params {
                EcdsaPublicParams::P256 { .. } => ECCCurve::P256,
                EcdsaPublicParams::P384 { .. } => ECCCurve::P384,
                EcdsaPublicParams::P521 { .. } => ECCCurve::P521,
                EcdsaPublicParams::Secp256k1 { .. } => ECCCurve::Secp256k1,
                EcdsaPublicParams::Unsupported { curve, .. } => curve.clone(),
            };

            format!("ECDSA/{}", curve.name())
        }

        PublicParams::EdDSALegacy(EddsaLegacyPublicParams::Ed25519 { .. }) => {
            "EdDSA/Curve25519".to_string()
        }

        PublicParams::Ed25519(_) => "Ed25519".to_string(),
        PublicParams::X25519(_) => "X25519".to_string(),
        PublicParams::Ed448(_) => "Ed448".to_string(),
        PublicParams::X448(_) => "X448".to_string(),

        #[cfg(feature = "pqc")]
        PublicParams::MlKem768X25519(_) => "ML-KEM-768+X25519".to_string(),
        #[cfg(feature = "pqc")]
        PublicParams::MlKem1024X448(_) => "ML-KEM-1024+X448".to_string(),
        #[cfg(feature = "pqc")]
        PublicParams::MlDsa65Ed25519(_) => "ML-DSA-65+Ed25519".to_string(),
        #[cfg(feature = "pqc")]
        PublicParams::MlDsa87Ed448(_) => "ML-DSA-87+Ed448".to_string(),
        #[cfg(feature = "pqc")]
        PublicParams::SlhDsaShake128s(_) => "SLH-DSA-SHAKE-128s".to_string(),
        #[cfg(feature = "pqc")]
        PublicParams::SlhDsaShake128f(_) => "SLH-DSA-SHAKE-128f".to_string(),
        #[cfg(feature = "pqc")]
        PublicParams::SlhDsaShake256s(_) => "SLH-DSA-SHAKE-256s".to_string(),

        _ => format!("{pp:?}"),
    }
}

/// Print human-readable information about a Certificate
///
/// FIXME: This will probably not remain in the public API in this form.
pub fn print_cert(cert: &Certificate, verbose: bool, ordered: bool) {
    let ci = cert_to_info(cert, ordered);
    print_cert_info(&ci, verbose, ordered);
}

/// Check if `sig` is a valid direct/revocation signature over `public`
pub(crate) fn verify_signature(sig: &Signature, public: &PublicKey) -> bool {
    sig.verify_key(public).is_ok()
}

/// Flatten duplicates in a set of signatures:
/// Remove duplicate instances of the same signature, but merge
/// unhashed subpackets into the unified signature.
fn dedup(sigs: &mut Vec<Signature>) {
    /// Returns the pos of a signature that can be removed as a duplicate.
    /// None, if no duplicate is found.
    fn dedup_inner(sigs: &mut [Signature]) -> Option<usize> {
        for pos in 0..sigs.len() {
            for check in pos + 1..sigs.len() {
                if signature_bytes_eq(&sigs[pos], &sigs[check]) {
                    // merge unhashed packets from check into pos
                    let chk = sigs[check].clone();
                    merge_unhashed(&mut sigs[pos], &chk);

                    return Some(check);
                }
            }
        }
        None
    }

    while let Some(pos) = dedup_inner(sigs) {
        sigs.remove(pos);
    }
}

/// Drop/unify duplicate signatures
pub fn canonicalize(spk: &mut SignedPublicKey) {
    // - drop duplicate signatures
    dedup(&mut spk.details.revocation_signatures);
    dedup(&mut spk.details.direct_signatures);
    for sk in &mut spk.public_subkeys {
        dedup(&mut sk.signatures);
    }
    for user in &mut spk.details.users {
        dedup(&mut user.signatures);
    }
    for ua in &mut spk.details.user_attributes {
        dedup(&mut ua.signatures);
    }

    // TODO?
    // - check that non-revocation signatures satisfy our policy?
    // - verify self-signatures?
}

/// Selects a subset of a set of keys:
///
/// - Only the pqc keys, if any exist in the set.
/// - All non-pqc keys, otherwise.
pub(crate) fn pqc_picker(keys: Vec<ComponentKeyPub>) -> Vec<ComponentKeyPub> {
    let has_pqc = keys.iter().any(|k| k.algorithm().is_pqc());

    if has_pqc {
        // collect all pqc keys
        keys.into_iter()
            .filter(|k| k.algorithm().is_pqc())
            .collect()
    } else {
        // collect all non-pqc keys
        keys.into_iter()
            .filter(|k| !k.algorithm().is_pqc())
            .collect()
    }
}

/// Returns unlocked DataSigners
pub(crate) fn pick_signers(tsks: &[Tsk], pws: &[Password]) -> Result<Vec<DataSigner>, Error> {
    let mut data_signers = Vec::new();

    for tsk in tsks {
        // True if any signing key has been added
        let mut added_any = false;

        // True if any unlocking attempt failed
        let mut unlock_failed = false;

        'signers: for mut ds in tsk.signing_capable_component_keys() {
            if !ds.key.is_locked() {
                data_signers.push(ds);
                added_any = true;
            } else {
                // Try to remove the password locking on this copy of the key packet.
                // This is ok because the key packet received from `signing_capable_component_keys`
                // is a clone that only we have. Thus, we can't accidentally unlock a
                // key packet that someone else relies on to stay locked.
                for pw in pws {
                    if ds.key.remove_password(pw).is_ok() {
                        data_signers.push(ds);

                        added_any = true;
                        continue 'signers;
                    } else {
                        unlock_failed = true;
                    }
                }
            }
        }

        if !added_any {
            return if unlock_failed {
                // If we added no signing key, and failed to unlock, we error about unlocking
                Err(Error::CantUnlock(tsk.key().fingerprint()))
            } else {
                // If we added no signing key, but didn't fail to unlock, we error about
                // capabilities
                Err(Error::NotSigningCapable(tsk.key().fingerprint()))
            };
        }
    }

    Ok(data_signers)
}

// TODO: this is a copy from rpgp, remove again after upstreaming detached signature handling
pub(crate) fn match_signer(sig: &Signature, key: &impl KeyDetails) -> bool {
    let issuer_key_ids = sig.issuer_key_id();
    let issuer_fps = sig.issuer_fingerprint();

    // Does any issuer or issuer fingerprint subpacket match the identity of `sig`?
    issuer_key_ids
        .iter()
        .any(|&key_id| key_id == &key.legacy_key_id())
        || issuer_fps.iter().any(|&fp| fp == &key.fingerprint())
}

/// FIXME: this is a copy from rpgp, remove again!
pub(crate) struct NormalizingHasher {
    hasher: Box<dyn DynDigest + Send>,
    text_mode: bool,
    last_was_cr: bool,
}

impl NormalizingHasher {
    pub(crate) fn new(hasher: Box<dyn DynDigest + Send>, text_mode: bool) -> Self {
        Self {
            hasher,
            text_mode,
            last_was_cr: false,
        }
    }

    pub(crate) fn done(mut self) -> Box<dyn DynDigest + Send> {
        if self.text_mode && self.last_was_cr {
            self.hasher.update(b"\n")
        }

        self.hasher
    }

    pub(crate) fn hash_buf(&mut self, buffer: &[u8]) {
        if buffer.is_empty() {
            return;
        }

        if !self.text_mode {
            self.hasher.update(buffer);
        } else {
            let mut buf = buffer;

            if self.last_was_cr {
                // detect and handle a LF that follows a CR
                // (it should not be normalized)
                if buf[0] == b'\n' {
                    self.hasher.update(b"\n");
                    buf = &buf[1..];
                }

                self.last_was_cr = false;
            }

            while !buf.is_empty() {
                match buf
                    .iter()
                    .enumerate()
                    .find(|&(_, &c)| c == b'\r' || c == b'\n')
                {
                    None => {
                        // no line endings in sight, just hash the data
                        self.hasher.update(buf);
                        buf = &[]
                    }

                    Some((pos, _)) => {
                        // consume all bytes before line-break-related position

                        self.hasher.update(&buf[..pos]);
                        buf = &buf[pos..];

                        // handle this line-break related context
                        let only_one = buf.len() == 1;
                        match (buf[0], only_one) {
                            (b'\n', _) => {
                                self.hasher.update(b"\r\n");
                                buf = &buf[1..];
                            }
                            (b'\r', false) => {
                                // we are guaranteed to have at least two bytes
                                if buf[1] == b'\n' {
                                    // there was a '\n' in the stream, we consume it as well
                                    self.hasher.update(b"\r\n");
                                    buf = &buf[2..];
                                } else {
                                    // this was a lone '\r', we don't normalize it
                                    self.hasher.update(b"\r");
                                    buf = &buf[1..];
                                }
                            }
                            (b'\r', true) => {
                                // this one '\r' was the last thing in the buffer
                                self.hasher.update(b"\r");
                                buf = &[];

                                // remember that the last character was a CR.
                                // if the next character is a LF, we want to *not* normalize it
                                self.last_was_cr = true;
                            }
                            _ => unreachable!("buf.position gave us either a '\n or a '\r'"),
                        }
                    }
                }
            }
        }
    }
}
