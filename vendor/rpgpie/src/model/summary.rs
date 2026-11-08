// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{
    fmt::{Display, Formatter},
    ops::Not,
};

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::model::status::CertStatus;
pub use crate::model::status::Status;

/// This is a representation of a certificate's status that is easy to output,
/// both in human-readable and in machine-readable formats.
#[derive(Debug, Serialize)]
pub struct CertStatusSummary {
    pub primary: ComponentKeySummary,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub subkeys: Vec<ComponentKeySummary>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub user_ids: Vec<UserIdSummary>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub user_attributes: Vec<UserAttributeSummary>,
}

/// Metadata about an individual component key
#[derive(Debug, Serialize)]
pub struct ComponentKeySummary {
    pub fingerprint: String,
    pub version: u8,
    pub created: DateTime<Utc>,
    pub algorithm: String,
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_flags: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct UserIdSummary {
    pub id: String,
    #[serde(skip_serializing_if = "<&bool>::not")]
    pub primary: bool,
    pub status: Status,
}

#[derive(Debug, Serialize)]
pub struct UserAttributeSummary {
    pub id: String,
    #[serde(skip_serializing_if = "<&bool>::not")]
    pub primary: bool,
    pub status: Status,
}

impl From<CertStatus> for CertStatusSummary {
    fn from(value: CertStatus) -> Self {
        let primary = ComponentKeySummary {
            fingerprint: value.primary.0.fingerprint,
            version: value.primary.0.version,
            created: value.primary.0.created,
            algorithm: value.primary.0.algorithm,
            status: value.primary.1,
            key_flags: value.primary.2,
        };

        let mut subkeys = vec![];
        for (ki, status, key_flags) in value.subkeys {
            let sk = ComponentKeySummary {
                fingerprint: ki.fingerprint,
                version: ki.version,
                created: ki.created,
                algorithm: ki.algorithm,
                status,
                key_flags,
            };

            subkeys.push(sk);
        }

        let mut user_ids = vec![];
        for (uid, status, primary) in value.users {
            user_ids.push(UserIdSummary {
                id: uid.id,
                primary,
                status,
            });
        }

        let mut user_attributes = vec![];
        for (ua, status, primary) in value.user_attributes {
            user_attributes.push(UserAttributeSummary {
                id: ua.id,
                primary,
                status,
            });
        }

        CertStatusSummary {
            primary,
            subkeys,
            user_ids,
            user_attributes,
        }
    }
}

impl Display for &CertStatusSummary {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "🔐 {} v{} {}",
            self.primary.algorithm, self.primary.version, self.primary.fingerprint
        )?;
        writeln!(f, "  ⏱️ Created {}", self.primary.created)?;
        writeln!(f, "  {}", self.primary.status)?;

        if let Some(key_flags) = &self.primary.key_flags {
            writeln!(f, "  🏴 Key flags: {}", key_flags.join(", "))?;
        }

        // TODO: mix in primary user id metadata for v4, here?

        writeln!(f)?;

        for subkey in &self.subkeys {
            writeln!(
                f,
                "  🔑 {} v{} {}",
                subkey.algorithm, subkey.version, subkey.fingerprint
            )?;
            writeln!(f, "    ⏱️ Created {}", subkey.created)?;
            writeln!(f, "    {}", subkey.status)?;

            if let Some(key_flags) = &subkey.key_flags {
                writeln!(f, "    🏴 Key flags: {}", key_flags.join(", "))?;
            }

            writeln!(f)?;
        }

        for user in &self.user_ids {
            // show primary user id flag, if set
            let pri = if user.primary { " (primary)" } else { "" };

            writeln!(f, "  🪪 ID {:?}{pri}", user.id)?;
            writeln!(f, "    {}", user.status)?;

            writeln!(f)?;
        }

        for ua in &self.user_attributes {
            writeln!(f, "  🪪 ATTR [{}]", ua.id)?;
            writeln!(f, "    {}", ua.status)?;

            writeln!(f)?;
        }

        Ok(())
    }
}
