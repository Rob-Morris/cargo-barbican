// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Produce and verify detached signatures

use std::{borrow::Cow, io::Read};

use pgp::{
    packet::{
        Signature,
        SignatureConfig,
        SignatureType,
        SignatureVersion,
        SignatureVersionSpecific,
        Subpacket,
        SubpacketData,
    },
    types::{KeyDetails, KeyVersion, Password, SigningKey, Timestamp, VerifyingKey},
};
use rand::thread_rng;

use crate::{
    Error,
    PW_EMPTY,
    certificate::{Certificate, SignatureVerifier},
    checked::Checked,
    message::SignatureMode,
    signature::{Verified, signature_acceptable},
    tsk::Tsk,
    util,
    util::NormalizingHasher,
};

/// Produce a hash digest for each SignatureConfig.
///
/// If a digest can not be produced, then None is returned in its place, so that the output order
/// matches the `configs` vector exactly.
fn hash_data_signatures<R: Read>(
    mut data: R,
    configs: &[&SignatureConfig],
) -> Result<Vec<Option<Box<[u8]>>>, Error> {
    let mut hashers: Vec<(&SignatureConfig, Option<NormalizingHasher>)> = Vec::new();

    for config in configs {
        if let Ok(mut hasher) = config.hash_alg.new_hasher() {
            // For v6: initialize hasher with salt
            if let SignatureVersionSpecific::V6 { salt } = &config.version_specific {
                hasher.update(salt);
            }

            let text_mode = config.typ == SignatureType::Text;
            let norm = NormalizingHasher::new(hasher, text_mode);

            hashers.push((config, Some(norm)));
        } else {
            hashers.push((config, None));
        }
    }

    // Stream the payload into each hasher
    let mut payload = [0u8; 8192];
    while let read = data.read(&mut payload)?
        && read > 0
    {
        hashers.iter_mut().for_each(|(_, norm)| {
            if let Some(norm) = norm {
                norm.hash_buf(&payload[..read]);
            }
        });
    }

    // Hash the signature config and trailer into each hasher
    let mut digests = Vec::new();

    for (config, norm) in hashers {
        let Some(norm) = norm else {
            digests.push(None);
            continue;
        };

        let mut hasher = norm.done();

        let len = config.hash_signature_data(&mut hasher)?;
        hasher.update(&config.trailer(len)?);

        digests.push(Some(hasher.finalize()));
    }

    Ok(digests)
}

/// SOP-style verification of detached signatures.
///
/// Outputs a list of successfully verified signatures, combined with the fingerprint of the
/// component key that verified the signature, and a list of certificates that contain this
/// component key (marked as valid for issuing data signatures).
///
/// <https://www.ietf.org/archive/id/draft-dkg-openpgp-stateless-cli-16.html#name-verify-verify-detached-sign>
pub fn verify<'c, 's, R: Read>(
    data: R,
    sigs: &'s [Signature],
    certs: &'c [Certificate],
) -> Result<Vec<Verified<'c, 's>>, Error> {
    let checked: Vec<_> = certs
        .iter()
        .map(|cert| (Checked::from(cert.clone()), cert))
        .collect();

    // Mapping from signature to a set of candidate verifier keys
    // (could be multiple e.g. if a signature shows multiple issuers)
    #[allow(clippy::type_complexity)]
    let mut matched: Vec<(
        &Signature,
        &SignatureConfig,
        Vec<(SignatureVerifier, &Certificate)>,
    )> = Vec::new();

    // TODO: make a separate map of certificates that a verifier is validly linked to?!

    // Pre-match verifiers per signature
    for sig in sigs {
        let Some(config) = sig.config() else {
            continue;
        };

        let Some(created) = sig.created() else {
            continue;
        };

        if ![SignatureType::Binary, SignatureType::Text].contains(&config.typ) {
            continue;
        }

        let mut verifiers: Vec<(SignatureVerifier, &Certificate)> = Vec::new();

        for (ccert, cert) in &checked {
            // Check validity for signature verification at signature creation time.
            for verifier in ccert.valid_signing_capable_component_keys_at(created) {
                if util::match_signer(sig, verifier.as_componentkey()) {
                    // Only store one verifier per unique fingerprint.
                    // TODO: deal with multiple certs that contain the same component key?!
                    if verifiers.iter().all(|(v, _)| {
                        v.as_componentkey().fingerprint()
                            != verifier.as_componentkey().fingerprint()
                    }) {
                        verifiers.push((verifier, *cert));
                    }
                }
            }
        }

        if !verifiers.is_empty() {
            matched.push((sig, config, verifiers));
        }
    }

    let configs: Vec<_> = matched.iter().map(|(_, config, ..)| *config).collect();
    let hashes = hash_data_signatures(data, &configs)?;

    // Check 2 byte prefix and verify signature bytes
    let mut verifications = Vec::new();

    for ((sig, _, verifiers), digest) in matched.iter().zip(hashes.iter()) {
        // rpgpie policy check
        if !signature_acceptable(sig) {
            continue;
        }

        let Some(config) = sig.config() else { continue };

        let Some(digest) = digest else { continue };

        {
            // DRY: copy of rPGP check_signature_hash_strength
            if config.pub_alg.is_pqc() {
                let Some(digest_size) = config.hash_alg.digest_size() else {
                    continue;
                };

                // PQC signatures must use hash algorithms with digest size >= 256 bits
                if digest_size * 8 < 256 {
                    continue;
                }
            }
        }

        for verifier in verifiers {
            // rpgpie semantics check (SignatureVerifier::temporal_validity)
            if verifier.0.temporal_validity(sig).is_err() {
                continue;
            }

            {
                // DRY: copy of rPGP check_signature_key_version_alignment
                if config.version() == SignatureVersion::V6
                    && verifier.0.as_componentkey().version() != KeyVersion::V6
                {
                    continue;
                }
                if verifier.0.as_componentkey().version() == KeyVersion::V6
                    && config.version() != SignatureVersion::V6
                {
                    continue;
                }
            }

            if digest.len() < 2 {
                // This should never happen
                continue;
            }

            if sig.signed_hash_value() != Some([digest[0], digest[1]]) {
                continue;
            }

            let Some(config) = sig.config() else {
                continue;
            };
            let Some(sig_bytes) = sig.signature() else {
                continue;
            };

            let key = &verifier.0.as_componentkey();
            if VerifyingKey::verify(key, config.hash_alg, digest, sig_bytes).is_ok() {
                let v = Verified {
                    sig: Cow::Borrowed(sig),
                    component: key.fingerprint(),

                    // TODO: handle multiple certs that contain the component key
                    certs: vec![verifier.1],
                };

                verifications.push(v);
            }
        }
    }

    Ok(verifications)
}

/// SOP-style creation of detached signatures.
///
/// Fails if no signature can be produced with any entry of `tsks` for any reason
/// (e.g.: no signing capable component key, or password unlocking failed).
///
/// <https://www.ietf.org/archive/id/draft-dkg-openpgp-stateless-cli-16.html#name-sign-create-detached-signat>
//
// TODO: factor out an inner function that signs based on a set of key packets
pub fn sign<R: Read>(
    data: R,
    tsks: &[Tsk],
    pws: &[Password],
    mode: SignatureMode,
) -> Result<Vec<Signature>, Error> {
    let mut rng = thread_rng();

    let mode = match mode {
        SignatureMode::Binary => SignatureType::Binary,
        SignatureMode::Text => SignatureType::Text,
    };

    let data_signers = util::pick_signers(tsks, pws)?;

    let mut configs = Vec::new();
    for ds in &data_signers {
        let mut config = SignatureConfig::from_key(&mut rng, &ds.key, mode)?;

        // Set subpackets
        config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::IssuerFingerprint(ds.fingerprint()))?,
            Subpacket::critical(SubpacketData::SignatureCreationTime(Timestamp::now()))?,
        ];

        if ds.version() < KeyVersion::V6 {
            config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::IssuerKeyId(
                ds.legacy_key_id(),
            ))?];
        }

        configs.push(config);
    }

    let hashes = hash_data_signatures(data, &configs.iter().collect::<Vec<_>>())?;

    let mut sigs = Vec::new();
    for ((ds, config), digest) in data_signers.iter().zip(configs.iter()).zip(hashes.iter()) {
        let Some(digest) = digest else { continue };

        let signed_hash_value = [digest[0], digest[1]];
        let raw_sig = ds.sign(&PW_EMPTY, config.hash_alg, digest)?;

        let signature = Signature::from_config(config.clone(), signed_hash_value, raw_sig)?;

        sigs.push(signature);
    }

    Ok(sigs)
}
