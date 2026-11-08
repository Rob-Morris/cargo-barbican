// SPDX-FileCopyrightText: Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! # rpgpie 🦀️🔐🥧
//!
//! rpgpie is an experimental higher level [OpenPGP](https://www.rfc-editor.org/rfc/rfc9850)
//! library based on [rPGP](https://github.com/rpgp/rpgp).
//!
//! It exposes a convenient API for some simple common OpenPGP operations.
//!
//! rpgpie implements semantics for OpenPGP expiration and revocation mechanisms, key flags,
//! and applies some amount of policy (to limit reliance on obsolete algorithms).
//!
//! Main goals of rpgpie include simplicity and collaboration 🥳.
//!
//! ## "OpenPGP for application developers"
//!
//! rpgpie aims to apply the terminology outlined in the
//! ["OpenPGP for application developers"](https://openpgp.dev/) documentation.
//!
//! ## Stateless OpenPGP (SOP)
//!
//! See [rsop](https://crates.io/crates/rsop) for a
//! [stateless OpenPGP (SOP)](https://datatracker.ietf.org/doc/draft-dkg-openpgp-stateless-cli/)
//! tool based on rpgpie.

use std::sync::LazyLock;

use pgp::types::{Fingerprint, Password};

pub mod certificate;
mod checked;
pub mod csf;
pub mod detached;
pub mod key;
pub mod lookup;
pub mod merge;
pub mod message;
pub mod model;
pub mod policy;
mod primary_userid;
pub mod signature;
pub mod tsk;
pub mod util;

/// rpgpie version, via Cargo.toml
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Version of the rPGP dependency we built against
pub const RPGP_VERSION: &str = pgp::VERSION;

pub(crate) static PW_EMPTY: LazyLock<Password> = LazyLock::new(Password::empty);

/// Error type for this crate
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("rPGP error: {0}")]
    Rpgp(#[from] pgp::errors::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Internal error: {0}")]
    Message(String),

    #[error("Primary key invalid: No valid binding signature found")]
    InvalidPrimary,

    #[error("No valid component keys for data signing found in {0}")]
    NotSigningCapable(Fingerprint),

    #[error("No valid component keys for encryption found in {0}")]
    NotEncryptionCapable(Fingerprint),

    #[error("Failed to unlock a component key of {0}")]
    CantUnlock(Fingerprint),

    #[error("UTF8 error")]
    Utf8Error,
}

impl From<pgp::composed::SubkeyParamsBuilderError> for Error {
    fn from(value: pgp::composed::SubkeyParamsBuilderError) -> Self {
        Error::Message(format!("SubkeyParamsBuilderError: {value}"))
    }
}

impl From<pgp::composed::SecretKeyParamsBuilderError> for Error {
    fn from(value: pgp::composed::SecretKeyParamsBuilderError) -> Self {
        Error::Message(format!("SecretKeyParamsBuilderError: {value}"))
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(_: std::str::Utf8Error) -> Self {
        Error::Utf8Error
    }
}
