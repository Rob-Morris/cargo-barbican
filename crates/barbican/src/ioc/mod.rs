mod model;
mod review;
mod roles;
mod scan;

pub use model::*;
pub use review::*;
pub use roles::*;
pub use scan::*;

pub const SCHEMA_VERSION: u32 = 1;
pub const MAX_REPORT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_FINDINGS: usize = 10_000;
pub const MAX_OCCURRENCES: usize = 20_000;
pub const MAX_SNIPPET_BYTES: usize = 160;
pub const SEMANTICS: &str = "barbican-build-source-literals-v1";
pub const GIT_SEMANTICS: &str = "barbican-git-repository-build-source-literals-v1";

pub fn digest(bytes: &[u8]) -> crate::Sha256Digest {
    use sha2::{Digest, Sha256};
    crate::Sha256Digest::try_from(format!("{:x}", Sha256::digest(bytes))).expect("SHA256 encoding")
}

pub fn digest_checked(
    bytes: &[u8],
    check: &mut dyn FnMut() -> Result<(), String>,
) -> Result<crate::Sha256Digest, String> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    check()?;
    for chunk in bytes.chunks(64 * 1024) {
        check()?;
        hasher.update(chunk);
    }
    Ok(crate::Sha256Digest::try_from(format!("{:x}", hasher.finalize())).expect("SHA256 encoding"))
}

pub fn canonical_digest(value: &impl serde::Serialize) -> Result<crate::Sha256Digest, String> {
    Ok(digest(
        &serde_json::to_vec(value).map_err(|e| e.to_string())?,
    ))
}

pub fn relative_path(path: &str) -> Result<(), String> {
    if path.is_empty()
        || path.len() > 4096
        || path.contains('\\')
        || path.chars().any(char::is_control)
        || path.split('/').count() > 128
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err("IOC path must be a bounded canonical relative path".into());
    }
    Ok(())
}

pub fn encode_bounded<T: serde::Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, String> {
    encode_with_limit(value, false)
}

pub fn encode_pretty_bounded<T: serde::Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, String> {
    encode_with_limit(value, true)
}

fn encode_with_limit<T: serde::Serialize + ?Sized>(
    value: &T,
    pretty: bool,
) -> Result<Vec<u8>, String> {
    struct Bounded(Vec<u8>);
    impl std::io::Write for Bounded {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self
                .0
                .len()
                .checked_add(bytes.len())
                .is_none_or(|size| size > MAX_REPORT_BYTES)
            {
                return Err(std::io::Error::other("IOC output exceeds 8 MiB"));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut output = Bounded(Vec::new());
    if pretty {
        serde_json::to_writer_pretty(&mut output, value)
    } else {
        serde_json::to_writer(&mut output, value)
    }
    .map_err(|e| e.to_string())?;
    Ok(output.0)
}

#[cfg(test)]
mod tests;
