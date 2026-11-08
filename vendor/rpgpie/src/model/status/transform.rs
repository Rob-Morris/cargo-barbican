// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Helper functions for producing `status` data structures

use std::time::SystemTime;

use chrono::{DateTime, Utc};
use pgp::{
    packet::{Signature, SubpacketData},
    types::{KeyDetails, Timestamp},
};

use crate::{
    certificate::Checked,
    model::{
        info::transform::{
            key_flags_to_string,
            primary_key_info,
            subkey_key_info,
            user_attribute_info,
            user_info,
        },
        status::{CertStatus, Status},
    },
    signature,
    signature::SigStack,
};

pub(crate) fn to_cert_status(checked: &Checked) -> CertStatus {
    // Checked view of the certificate as SPK.
    let spk = checked.as_signed_public_key();

    fn get_active_sig(signatures: &[Signature], key_creation: Timestamp) -> Option<&Signature> {
        let stack = SigStack::from_iter(signatures);
        stack.active_at(Timestamp::now(), key_creation)
    }

    fn key_flags(s: &Signature) -> Option<Vec<String>> {
        let conf = s.config()?;

        // Key flags, if any
        conf.hashed_subpackets
            .iter()
            .filter_map(|sp| {
                if let SubpacketData::KeyFlags(flags) = &sp.data {
                    Some(flags)
                } else {
                    None
                }
            })
            .next()
            .map(key_flags_to_string)
    }

    let (status, flags) =
        if let Some(sig) = checked.active_certificate_self_signature_at(Timestamp::now()) {
            (
                to_sig_status(sig, spk.primary_key.created_at()),
                key_flags(sig),
            )
        } else {
            (
                Status::Invalid {
                    context: "no active signature".to_string(),
                },
                None,
            )
        };

    let primary = (primary_key_info(spk, true), status, flags);

    let subkeys = spk
        .public_subkeys
        .iter()
        .map(|sk| {
            let (status, flags) = if let Some(sig) = get_active_sig(&sk.signatures, sk.created_at())
            {
                (to_sig_status(sig, sk.created_at()), key_flags(sig))
            } else {
                (
                    Status::Invalid {
                        context: "no active signature".to_string(),
                    },
                    None,
                )
            };

            (subkey_key_info(sk, true), status, flags)
        })
        .collect();

    let users = spk
        .details
        .users
        .iter()
        .map(|su| {
            let ui = user_info(
                su,
                SystemTime::from(spk.primary_key.created_at()).into(),
                true,
            );
            let primary;

            let status = if let Some(sig) =
                get_active_sig(&su.signatures, checked.primary_creation_time())
            {
                primary = sig.is_primary();

                to_sig_status(sig, spk.primary_key.created_at())
            } else {
                primary = false;

                Status::Invalid {
                    context: "no active signature".to_string(),
                }
            };

            (ui, status, primary)
        })
        .collect();

    let user_attributes = spk
        .details
        .user_attributes
        .iter()
        .map(|sua| {
            let uai = user_attribute_info(
                sua,
                SystemTime::from(spk.primary_key.created_at()).into(),
                true,
            );
            let primary;

            let status = if let Some(sig) =
                get_active_sig(&sua.signatures, checked.primary_creation_time())
            {
                primary = sig.is_primary();
                to_sig_status(sig, spk.primary_key.created_at())
            } else {
                primary = false;
                Status::Invalid {
                    context: "no active signature".to_string(),
                }
            };

            (uai, status, primary)
        })
        .collect();

    CertStatus {
        primary,
        subkeys,
        users,
        user_attributes,
    }
}

fn to_sig_status(s: &Signature, key_creation: Timestamp) -> Status {
    let Some(conf) = s.config() else {
        return Status::Invalid {
            context: "missing signature config".to_string(),
        };
    };

    let Some(sig_created) = conf.created() else {
        return Status::Invalid {
            context: "missing signature creation time".to_string(),
        };
    };

    let now: DateTime<Utc> = SystemTime::now().into();

    // Status: expired or revoked?
    let exp = if let Some(key_exp) = s.key_expiration_time() {
        if key_exp.as_secs() != 0 {
            let expiry = key_creation.as_secs() + key_exp.as_secs();
            Some(SystemTime::from(Timestamp::from_secs(expiry)).into())
        } else {
            None
        }
    } else {
        None
    };

    if signature::is_revocation(s) {
        let reason = match (s.revocation_reason_code(), s.revocation_reason_string()) {
            (Some(code), Some(reason)) => {
                format!("{:?} {:?}", code, String::from_utf8_lossy(reason))
            }
            (None, None) => "Reason for revocation is unset".to_string(),
            _ => "??".to_string(), // this should never happen
        };

        if signature::is_hard_revocation(s) {
            Status::RevokedHard {
                time: SystemTime::from(sig_created).into(),
                reason,
            }
        } else {
            Status::RevokedSoft {
                time: SystemTime::from(sig_created).into(),
                reason,
            }
        }
    } else if let Some(exp) = exp {
        if exp > now {
            Status::Valid { expires: Some(exp) }
        } else {
            Status::Expired { time: exp }
        }
    } else {
        Status::Valid { expires: None }
    }
}
