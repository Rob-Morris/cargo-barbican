use std::time::Duration;

use barbican::{
    CrateRelease, CratesIoClient, CratesIoClientError, ExactCrateSpec, VersionInfo,
    parse_version_response_body, parse_versions_response_body,
};
use ureq::Agent;

const USER_AGENT: &str = concat!("cargo-barbican/", env!("CARGO_PKG_VERSION"));
pub const DEFAULT_CRATES_IO_BASE_URL: &str = "https://crates.io";
pub const CRATES_IO_BASE_URL_ENV: &str = "CARGO_BARBICAN_CRATES_IO_BASE_URL";
const MAX_TARBALL_BYTES: u64 = 128 * 1024 * 1024;

pub struct UreqCratesIoClient {
    agent: Agent,
    base_url: String,
}

impl UreqCratesIoClient {
    pub fn new(base_url: String) -> Self {
        let base_url = base_url.trim_end_matches('/').to_owned();
        let config = Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(20)))
            .http_status_as_error(false)
            .https_only(base_url.to_ascii_lowercase().starts_with("https://"))
            .build();

        Self {
            agent: config.into(),
            base_url,
        }
    }

    fn version_url(&self, spec: &ExactCrateSpec) -> String {
        format!(
            "{}/api/v1/crates/{}/{}",
            self.base_url,
            spec.crate_name(),
            spec.version()
        )
    }

    fn versions_url(&self, crate_name: &str) -> String {
        format!("{}/api/v1/crates/{crate_name}", self.base_url)
    }

    fn tarball_url(&self, spec: &ExactCrateSpec) -> String {
        format!(
            "{}/api/v1/crates/{}/{}/download",
            self.base_url,
            spec.crate_name(),
            spec.version()
        )
    }
    fn read_checked(
        &self,
        url: String,
        limit: u64,
        archive: bool,
        check: &mut dyn FnMut() -> Result<(), String>,
    ) -> Result<Vec<u8>, CratesIoClientError> {
        use std::io::Read;
        let transport = |reason: String| CratesIoClientError::Transport { reason };
        check().map_err(transport)?;
        let mut response = self
            .agent
            .get(url)
            .header("User-Agent", USER_AGENT)
            .call()
            .map_err(|e| transport(e.to_string()))?;
        if response.status().is_client_error() || response.status().is_server_error() {
            let status_code = response.status().as_u16();
            return Err(if archive {
                CratesIoClientError::TarballHttpStatus { status_code }
            } else {
                CratesIoClientError::HttpStatus { status_code }
            });
        }
        let mut reader = response.body_mut().as_reader();
        let mut bytes = Vec::new();
        let mut chunk = [0; 64 * 1024];
        loop {
            check().map_err(transport)?;
            let count = reader
                .read(&mut chunk)
                .map_err(|e| transport(e.to_string()))?;
            if count == 0 {
                break;
            }
            if bytes.len() as u64 + count as u64 > limit {
                return Err(transport(
                    "crates.io response exceeds bounded source size".into(),
                ));
            }
            bytes.extend_from_slice(&chunk[..count]);
        }
        Ok(bytes)
    }
    pub(crate) fn fetch_release_observed(
        &self,
        spec: &ExactCrateSpec,
        mut check: impl FnMut() -> Result<(), String>,
    ) -> Result<(CrateRelease, u64), CratesIoClientError> {
        let bytes =
            self.read_checked(self.version_url(spec), 8 * 1024 * 1024, false, &mut check)?;
        parse_observed_release(spec, &bytes)
    }
    pub(crate) fn fetch_tarball_checked(
        &self,
        spec: &ExactCrateSpec,
        mut check: impl FnMut() -> Result<(), String>,
    ) -> Result<Vec<u8>, CratesIoClientError> {
        self.read_checked(self.tarball_url(spec), MAX_TARBALL_BYTES, true, &mut check)
    }
}

fn parse_observed_release(
    spec: &ExactCrateSpec,
    bytes: &[u8],
) -> Result<(CrateRelease, u64), CratesIoClientError> {
    let text = std::str::from_utf8(bytes).map_err(|e| CratesIoClientError::InvalidResponse {
        detail: e.to_string(),
    })?;
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| CratesIoClientError::InvalidResponse {
            detail: e.to_string(),
        })?;
    if value
        .pointer("/version/crate")
        .and_then(serde_json::Value::as_str)
        != Some(spec.crate_name())
        || value
            .pointer("/version/num")
            .and_then(serde_json::Value::as_str)
            != Some(spec.version())
    {
        return Err(CratesIoClientError::InvalidResponse {
            detail: "release response identity differs from requested exact source".into(),
        });
    }
    let updated = value
        .pointer("/version/updated_at")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| CratesIoClientError::InvalidResponse {
            detail: "mutable release observation has no authenticated source update time".into(),
        })?;
    let revision = barbican::tool_inputs::source_version_timestamp(updated)
        .map_err(|detail| CratesIoClientError::InvalidResponse { detail })?;
    Ok((parse_version_response_body(text)?, revision))
}

impl CratesIoClient for UreqCratesIoClient {
    fn fetch_release(&self, spec: &ExactCrateSpec) -> Result<CrateRelease, CratesIoClientError> {
        let bytes =
            self.read_checked(self.version_url(spec), 8 * 1024 * 1024, false, &mut || {
                Ok(())
            })?;
        let text =
            std::str::from_utf8(&bytes).map_err(|e| CratesIoClientError::InvalidResponse {
                detail: e.to_string(),
            })?;
        parse_version_response_body(text)
    }

    fn fetch_versions(&self, crate_name: &str) -> Result<Vec<VersionInfo>, CratesIoClientError> {
        let mut response = self
            .agent
            .get(self.versions_url(crate_name))
            .header("User-Agent", USER_AGENT)
            .call()
            .map_err(|error| CratesIoClientError::Transport {
                reason: error.to_string(),
            })?;

        if response.status().is_client_error() || response.status().is_server_error() {
            return Err(CratesIoClientError::HttpStatus {
                status_code: response.status().as_u16(),
            });
        }

        let body = response.body_mut().read_to_string().map_err(|error| {
            CratesIoClientError::Transport {
                reason: error.to_string(),
            }
        })?;

        parse_versions_response_body(&body)
    }

    fn fetch_release_tarball(&self, spec: &ExactCrateSpec) -> Result<Vec<u8>, CratesIoClientError> {
        self.fetch_tarball_checked(spec, || Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_CRATES_IO_BASE_URL, UreqCratesIoClient};
    #[test]
    fn observed_release_requires_exact_response_identity_and_source_mutation_time() {
        let spec = "fixture@1.0.0".parse().unwrap();
        let valid = serde_json::json!({"version":{"crate":"fixture","num":"1.0.0","checksum":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","created_at":"2026-05-01T00:00:00Z","updated_at":"2026-05-02T00:00:00Z","yanked":true}});
        let parse = |value: &serde_json::Value| {
            super::parse_observed_release(&spec, &serde_json::to_vec(value).unwrap())
        };
        let (release, version) = parse(&valid).unwrap();
        assert!(release.yanked);
        assert_eq!(
            version,
            barbican::tool_inputs::source_version_timestamp("2026-05-02T00:00:00Z").unwrap()
        );
        for (field, wrong) in [
            ("crate", "other"),
            ("num", "2.0.0"),
            ("updated_at", "not a timestamp"),
        ] {
            let mut value = valid.clone();
            value["version"][field] = wrong.into();
            assert!(parse(&value).is_err());
            value["version"].as_object_mut().unwrap().remove(field);
            assert!(parse(&value).is_err());
        }
    }

    #[test]
    fn https_base_enforces_https_only_transport() {
        for base_url in [DEFAULT_CRATES_IO_BASE_URL, "HTTPS://example.invalid"] {
            let client = UreqCratesIoClient::new(base_url.to_owned());

            assert!(
                client.agent.config().https_only(),
                "HTTPS base URLs must reject plain-HTTP redirect targets"
            );
        }
    }

    #[test]
    fn loopback_http_base_preserves_local_test_transport() {
        let client = UreqCratesIoClient::new("http://127.0.0.1:8080".to_owned());

        assert!(
            !client.agent.config().https_only(),
            "the validated loopback HTTP test seam must remain usable"
        );
    }
}
