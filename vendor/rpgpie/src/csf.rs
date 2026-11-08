// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cleartext signature handling

use std::{
    borrow::Cow,
    io::{Read, Write},
};

use pgp::{
    composed::CleartextSignedMessage,
    packet::Signature,
    types::{KeyDetails, Password, SigningKey, Timestamp},
};

use crate::{
    Error,
    PW_EMPTY,
    certificate::Certificate,
    checked::Checked,
    message::SignatureMode,
    signature::Verified,
    tsk::{DataSigner, Tsk},
    util,
};

/// SOP-style verification of a cleartext signed message
pub fn verify<W: Write, R: Fn(&Signature) -> bool>(
    csf: CleartextSignedMessage,
    mut sink: W,
    retain_sig: R,
    certs: &[Certificate],
) -> Result<Vec<Verified<'_, '_>>, Error> {
    let now = Timestamp::now();

    let mut verified = Vec::new();

    for c in certs {
        let cc: Checked = c.clone().into();
        let verifiers = cc.valid_signing_capable_component_keys_at(now);

        for v in verifiers {
            if let Ok(sig) = v.verify_csf(&csf)
                && retain_sig(&sig)
            {
                verified.push(Verified {
                    sig: Cow::Owned(sig),
                    component: v.as_componentkey().fingerprint(),

                    // FIXME: unify multiple certs with the same primary fingerprint
                    certs: vec![c],
                });
            }
        }
    }

    if !verified.is_empty() {
        sink.write_all(csf.signed_text().as_bytes())?;
    }

    Ok(verified)
}

/// SOP-style generation of a cleartext signed message
pub fn sign<R: Read>(
    input: R,
    tsks: &[Tsk],
    pws: &[Password],
) -> Result<CleartextSignedMessage, Error> {
    let data_signers = util::pick_signers(tsks, pws)?;

    sign_internal(input, data_signers)
}

pub(crate) fn sign_internal<R: Read>(
    mut input: R,
    data_signers: Vec<DataSigner>,
) -> Result<CleartextSignedMessage, Error> {
    let mut data = vec![];
    input.read_to_end(&mut data)?;

    let signers = |text: &str| -> Result<Vec<Signature>, pgp::errors::Error> {
        let mut sigs: Vec<Signature> = vec![];

        for ds in data_signers {
            let sig = ds
                .sign_data(
                    text.as_bytes(),
                    SignatureMode::Text,
                    &PW_EMPTY,
                    ds.hash_alg(),
                )
                .map_err(|e| pgp::errors::Error::Message {
                    message: format!("Couldn't sign: {e}"),
                    backtrace: None,
                })?;
            sigs.push(sig);
        }

        Ok(sigs)
    };

    let text = std::str::from_utf8(&data)?;

    Ok(CleartextSignedMessage::new_many(text, signers)?)
}
