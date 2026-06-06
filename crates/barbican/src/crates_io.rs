use serde::Deserialize;
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::{ExactCrateSpec, Sha256Digest};

pub trait CratesIoClient {
    fn fetch_release(&self, spec: &ExactCrateSpec) -> Result<CrateRelease, CratesIoClientError>;

    fn fetch_release_tarball(
        &self,
        _spec: &ExactCrateSpec,
    ) -> Result<Vec<u8>, CratesIoClientError> {
        Err(CratesIoClientError::NotSupported)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrateRelease {
    pub checksum_sha256_hex: Sha256Digest,
    pub published_at_raw: String,
    pub published_at: OffsetDateTime,
    pub yanked: bool,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CratesIoClientError {
    #[error("crates.io returned HTTP {status_code} for version metadata")]
    HttpStatus { status_code: u16 },
    #[error("crates.io returned HTTP {status_code} for crate tarball download")]
    TarballHttpStatus { status_code: u16 },
    #[error("unable to reach crates.io ({reason})")]
    Transport { reason: String },
    #[error("crate tarball downloads are not supported")]
    NotSupported,
    #[error("unexpected crates.io response shape ({detail})")]
    InvalidResponse { detail: String },
}

pub fn parse_version_response_body(body: &str) -> Result<CrateRelease, CratesIoClientError> {
    let response: CratesIoVersionResponse =
        serde_json::from_str(body).map_err(|source| CratesIoClientError::InvalidResponse {
            detail: source.to_string(),
        })?;

    response.into_release()
}

#[derive(Debug, Deserialize)]
struct CratesIoVersionResponse {
    version: CratesIoVersion,
}

impl CratesIoVersionResponse {
    fn into_release(self) -> Result<CrateRelease, CratesIoClientError> {
        let published_at =
            OffsetDateTime::parse(&self.version.created_at, &Rfc3339).map_err(|source| {
                CratesIoClientError::InvalidResponse {
                    detail: source.to_string(),
                }
            })?;

        let checksum_sha256_hex =
            Sha256Digest::try_from(self.version.checksum.as_str()).map_err(|_| {
                CratesIoClientError::InvalidResponse {
                    detail: "version.checksum is not a valid SHA-256 digest".to_owned(),
                }
            })?;

        Ok(CrateRelease {
            checksum_sha256_hex,
            published_at_raw: self.version.created_at,
            published_at,
            yanked: self.version.yanked,
        })
    }
}

#[derive(Debug, Deserialize)]
struct CratesIoVersion {
    checksum: String,
    created_at: String,
    yanked: bool,
}

#[cfg(test)]
mod tests {
    use super::{CratesIoClientError, parse_version_response_body};

    #[test]
    fn parses_version_metadata() {
        let release = parse_version_response_body(
            r#"{"version":{"checksum":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","created_at":"2026-05-01T00:00:00Z","yanked":true}}"#,
        )
        .expect("response should parse");

        assert_eq!(
            release.checksum_sha256_hex.as_str(),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        assert_eq!(release.published_at_raw, "2026-05-01T00:00:00Z");
        assert!(release.yanked);
    }

    #[test]
    fn invalid_timestamps_fail_as_response_shape_errors() {
        let error = parse_version_response_body(
            r#"{"version":{"checksum":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","created_at":"not-a-timestamp","yanked":false}}"#,
        )
        .expect_err("invalid timestamps should fail");

        assert!(matches!(error, CratesIoClientError::InvalidResponse { .. }));
    }

    #[test]
    fn invalid_checksums_fail_as_response_shape_errors() {
        let error = parse_version_response_body(
            r#"{"version":{"checksum":"abc123","created_at":"2026-05-01T00:00:00Z","yanked":false}}"#,
        )
        .expect_err("invalid checksums should fail");

        assert!(matches!(error, CratesIoClientError::InvalidResponse { .. }));
    }

    #[test]
    fn missing_yanked_fails_as_response_shape_error() {
        let error = parse_version_response_body(
            r#"{"version":{"checksum":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","created_at":"2026-05-01T00:00:00Z"}}"#,
        )
        .expect_err("missing yanked field should fail");

        assert!(matches!(error, CratesIoClientError::InvalidResponse { .. }));
    }
}
