//! Bounded, data-only Rust distribution inspection. Parsing does not authenticate inputs.
mod archive;
mod decode;
mod manifest;
mod native_metadata;
mod pin_edit;
mod repository_selection;

pub use archive::{ArchiveInventory, EntryKind, ExpectedEntry, SelectionInventory, inspect_tar};
pub(crate) use decode::GzipReader;
pub use decode::inspect_archive;
pub use manifest::{
    ArchiveEncodings, ArchiveIdentity, Encoding, Manifest, PackageSourceMetadata, Profile,
    Selection, SelectionRequest,
};
pub use native_metadata::{
    check_rustup_config, check_rustup_default_assignment, check_rustup_default_restoration,
    check_rustup_manifest, rustup_default, rustup_manifest_projection,
};
pub use pin_edit::replace_channel;
pub use repository_selection::parse_repository_selection;

use crate::Sha256Digest;
use sha2::{Digest, Sha256};
use std::io;

pub const MAX_COMPRESSED_BYTES: u64 = 1024 * 1024 * 1024;
pub const MAX_EXPANDED_BYTES: u64 = 8 * 1024 * 1024 * 1024;
pub const MAX_SELECTION_BYTES: u64 = 32 * 1024 * 1024 * 1024;
pub const MAX_ENTRIES: usize = 200_000;
pub const MAX_PATH_BYTES: usize = 4096;
pub const MAX_METADATA_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_DECODER_MEMORY_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum DistributionError {
    #[error("invalid or unsupported Rust distribution: {0}")]
    Invalid(String),
    #[error("Rust distribution I/O: {0}")]
    Io(#[from] io::Error),
}
fn invalid(message: impl Into<String>) -> DistributionError {
    DistributionError::Invalid(message.into())
}
fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::try_from(format!("{:x}", Sha256::digest(bytes)).as_str()).expect("SHA256 hex")
}
fn path(value: &str) -> Result<(), DistributionError> {
    if value.is_empty()
        || value.len() > MAX_PATH_BYTES
        || value
            .bytes()
            .any(|b| b < 32 || b == 127 || b == b'\\' || b == b':')
        || value
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..")
    {
        return Err(invalid("non-canonical or oversized relative path"));
    }
    Ok(())
}

pub use native_metadata::{rustup_configured_host, rustup_directory_overrides};
