use serde::Deserialize;
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::{ExactCrateSpec, Sha256Digest};

pub trait CratesIoClient {
    fn fetch_release(&self, spec: &ExactCrateSpec) -> Result<CrateRelease, CratesIoClientError>;

    fn fetch_versions(&self, _crate_name: &str) -> Result<Vec<VersionInfo>, CratesIoClientError> {
        Err(CratesIoClientError::NotSupported)
    }

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionInfo {
    pub num: String,
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
    #[error("operation not supported by this client")]
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

pub fn parse_versions_response_body(body: &str) -> Result<Vec<VersionInfo>, CratesIoClientError> {
    let response: CratesIoVersionsResponse =
        serde_json::from_str(body).map_err(|source| CratesIoClientError::InvalidResponse {
            detail: source.to_string(),
        })?;

    response
        .versions
        .into_iter()
        .map(CratesIoVersion::into_version_info)
        .collect()
}

#[derive(Debug, Deserialize)]
struct CratesIoVersionResponse {
    version: CratesIoVersion,
}

impl CratesIoVersionResponse {
    fn into_release(self) -> Result<CrateRelease, CratesIoClientError> {
        let version = self.version.into_version_info()?;

        Ok(CrateRelease {
            checksum_sha256_hex: version.checksum_sha256_hex,
            published_at_raw: version.published_at_raw,
            published_at: version.published_at,
            yanked: version.yanked,
        })
    }
}

#[derive(Debug, Deserialize)]
struct CratesIoVersionsResponse {
    versions: Vec<CratesIoVersion>,
}

#[derive(Debug, Deserialize)]
struct CratesIoVersion {
    num: String,
    checksum: String,
    created_at: String,
    yanked: bool,
}

impl CratesIoVersion {
    fn into_version_info(self) -> Result<VersionInfo, CratesIoClientError> {
        let published_at = OffsetDateTime::parse(&self.created_at, &Rfc3339).map_err(|source| {
            CratesIoClientError::InvalidResponse {
                detail: source.to_string(),
            }
        })?;

        let checksum_sha256_hex = Sha256Digest::try_from(self.checksum.as_str()).map_err(|_| {
            CratesIoClientError::InvalidResponse {
                detail: "version.checksum is not a valid SHA-256 digest".to_owned(),
            }
        })?;

        Ok(VersionInfo {
            num: self.num,
            checksum_sha256_hex,
            published_at_raw: self.created_at,
            published_at,
            yanked: self.yanked,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{CratesIoClientError, parse_version_response_body, parse_versions_response_body};

    #[test]
    fn parses_version_metadata() {
        let release = parse_version_response_body(
            r#"{"version":{"num":"1.0.0","checksum":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","created_at":"2026-05-01T00:00:00Z","yanked":true}}"#,
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
    fn parses_versions_metadata() {
        let versions = parse_versions_response_body(
            r#"{"versions":[{"num":"1.0.1","checksum":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","created_at":"2026-05-02T00:00:00Z","yanked":false},{"num":"1.0.0","checksum":"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789","created_at":"2026-05-01T00:00:00Z","yanked":true}]}"#,
        )
        .expect("response should parse");

        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].num, "1.0.1");
        assert_eq!(
            versions[0].checksum_sha256_hex.as_str(),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        assert_eq!(versions[0].published_at_raw, "2026-05-02T00:00:00Z");
        assert!(!versions[0].yanked);
        assert_eq!(versions[1].num, "1.0.0");
        assert!(versions[1].yanked);
    }

    #[test]
    fn invalid_timestamps_fail_as_response_shape_errors() {
        let error = parse_version_response_body(
            r#"{"version":{"num":"1.0.0","checksum":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","created_at":"not-a-timestamp","yanked":false}}"#,
        )
        .expect_err("invalid timestamps should fail");

        assert!(matches!(error, CratesIoClientError::InvalidResponse { .. }));
    }

    #[test]
    fn invalid_checksums_fail_as_response_shape_errors() {
        let error = parse_version_response_body(
            r#"{"version":{"num":"1.0.0","checksum":"abc123","created_at":"2026-05-01T00:00:00Z","yanked":false}}"#,
        )
        .expect_err("invalid checksums should fail");

        assert!(matches!(error, CratesIoClientError::InvalidResponse { .. }));
    }

    #[test]
    fn missing_yanked_fails_as_response_shape_error() {
        let error = parse_version_response_body(
            r#"{"version":{"num":"1.0.0","checksum":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","created_at":"2026-05-01T00:00:00Z"}}"#,
        )
        .expect_err("missing yanked field should fail");

        assert!(matches!(error, CratesIoClientError::InvalidResponse { .. }));
    }
}
