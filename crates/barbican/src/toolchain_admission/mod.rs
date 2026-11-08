//! Pure, versioned toolchain records. Parsing is not authentication or approval.
//! Effects adapters supply authenticated original bytes and checked archive inventories;
//! persisted records are compared with those reconstructed facts before eligibility.
mod advisory_source;
mod eligibility;
mod evidence;
mod identity;
mod source_inventory;

pub use advisory_source::*;
pub use eligibility::*;
pub use evidence::*;
pub use identity::*;
pub use source_inventory::*;

use crate::Sha256Digest;
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

pub const SCHEMA_VERSION: u32 = 1;
pub const MAX_RECORD_BYTES: usize = 8 * 1024 * 1024;
pub const MAPPING_VERSION: &str = "rust-installer-mapping-v1";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct AdmissionError(pub String);
pub type Result<T> = std::result::Result<T, AdmissionError>;

pub fn parse_record<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    require(bytes.len() <= MAX_RECORD_BYTES, "record byte limit")?;
    serde_json::from_slice(bytes).map_err(|e| AdmissionError(e.to_string()))
}

pub fn digest_bytes(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::try_from(format!("{:x}", Sha256::digest(bytes))).expect("SHA-256 hex")
}

pub fn digest_reader(
    mut reader: impl std::io::Read,
    limit: u64,
) -> std::io::Result<(Sha256Digest, u64)> {
    let mut hash = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 32768];
    loop {
        let take = limit
            .saturating_sub(total)
            .saturating_add(1)
            .min(buffer.len() as u64) as usize;
        let count = reader.read(&mut buffer[..take])?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .filter(|n| *n <= limit)
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "digest byte limit")
            })?;
        hash.update(&buffer[..count]);
    }
    Ok((
        Sha256Digest::try_from(format!("{:x}", hash.finalize())).expect("SHA-256 hex"),
        total,
    ))
}

// Protocol v1: domain length (u64 BE) + domain + complete UTF-8 JSON.
// Only fixed-field structs and canonically sorted collections enter this function.
fn record_id(domain: &str, record: &impl Serialize) -> Result<Sha256Digest> {
    let mut hash = Sha256::new();
    hash.update((domain.len() as u64).to_be_bytes());
    hash.update(domain.as_bytes());
    struct HashWriter<'a>(&'a mut Sha256);
    impl std::io::Write for HashWriter<'_> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(HashWriter(&mut hash), record)
        .map_err(|e| AdmissionError(e.to_string()))?;
    Ok(Sha256Digest::try_from(format!("{hash:x}", hash = hash.finalize())).expect("SHA-256 hex"))
}

fn require(ok: bool, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(AdmissionError(message.to_owned()))
    }
}
fn text(value: &str) -> Result<()> {
    require(
        !value.trim().is_empty() && value.len() <= 4096 && !value.chars().any(char::is_control),
        "blank, oversized or control-bearing field",
    )
}
fn timestamp(value: i64) -> Result<()> {
    require(
        value >= 0 && time::OffsetDateTime::from_unix_timestamp(value).is_ok(),
        "invalid UTC timestamp",
    )
}
fn version(value: u32) -> Result<()> {
    require(value == SCHEMA_VERSION, "unsupported record schema")
}

#[cfg(test)]
mod tests;
