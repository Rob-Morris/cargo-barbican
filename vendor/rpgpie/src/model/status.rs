// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Determine and output the validity status of a certificate and its components.
//!
//! This module is related to the [crate::model::info] module, and builds on it:
//!
//! - `info` models and inspects raw certificate content, without interpreting or checking validity,
//! - `status` models certificate content with a focus on validity, while checking cryptographic
//!   validity of the involved self-signatures.

pub(crate) mod transform;

use std::fmt::{Display, Formatter};

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::model::info::{KeyInfo, UserAttributeInfo, UserInfo};

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Valid {
        /// if `expires` is `None`, the component is valid indefinitely
        #[serde(skip_serializing_if = "Option::is_none")]
        expires: Option<DateTime<Utc>>,
    },

    Expired {
        time: DateTime<Utc>,
    },
    RevokedSoft {
        time: DateTime<Utc>,
        reason: String,
    },
    RevokedHard {
        time: DateTime<Utc>,
        reason: String,
    },
    Invalid {
        context: String,
    },
}

impl Status {
    pub fn is_valid(&self) -> bool {
        matches!(self, Status::Valid { .. })
    }

    pub fn is_revoked(&self) -> bool {
        matches!(
            self,
            Status::RevokedSoft { .. } | Status::RevokedHard { .. }
        )
    }
}

impl Display for Status {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Status::Valid { expires: None } => write!(f, "✅ Active (no expiration)"),
            Status::Valid { expires: Some(exp) } => write!(f, "✅ Active, expires {exp}"),

            Status::Expired { time } => write!(f, "🚫 Expired {time}"),

            Status::RevokedSoft { time, reason: msg } => {
                write!(f, "🚫 Revoked (soft) {time}: {msg}")
            }
            Status::RevokedHard { time, reason: msg } => {
                write!(f, "🚫 Revoked (hard) {time}: {msg}")
            }

            Status::Invalid { context } => write!(f, "🚫 Invalid: {context}"),
        }
    }
}

/// Similar to a [CertInfo], but with a [Status] object for each component.
///
/// In addition, [CertStatus] starts from a *checked* certificate, so it's a filtered view that
/// drops elements of the certificate that don't satisfy our policy, or are not cryptographically
/// valid.
#[derive(Debug)]
pub(crate) struct CertStatus {
    // key information, validity status, key flags (if set in dks)
    pub(crate) primary: (KeyInfo, Status, Option<Vec<String>>),

    // key information, validity status, key flags (if set)
    pub(crate) subkeys: Vec<(KeyInfo, Status, Option<Vec<String>>)>,

    // user id information, validity status, "primary user id" flag
    pub(crate) users: Vec<(UserInfo, Status, bool)>,

    // user attr information, validity status, "primary user id" flag
    pub(crate) user_attributes: Vec<(UserAttributeInfo, Status, bool)>,
}
