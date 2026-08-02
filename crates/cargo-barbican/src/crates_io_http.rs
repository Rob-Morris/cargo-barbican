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
}

impl CratesIoClient for UreqCratesIoClient {
    fn fetch_release(&self, spec: &ExactCrateSpec) -> Result<CrateRelease, CratesIoClientError> {
        let mut response = self
            .agent
            .get(self.version_url(spec))
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

        parse_version_response_body(&body)
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
        let mut response = self
            .agent
            .get(self.tarball_url(spec))
            .header("User-Agent", USER_AGENT)
            .call()
            .map_err(|error| CratesIoClientError::Transport {
                reason: error.to_string(),
            })?;

        if response.status().is_client_error() || response.status().is_server_error() {
            return Err(CratesIoClientError::TarballHttpStatus {
                status_code: response.status().as_u16(),
            });
        }

        response
            .body_mut()
            .with_config()
            .limit(MAX_TARBALL_BYTES)
            .read_to_vec()
            .map_err(|error| CratesIoClientError::Transport {
                reason: error.to_string(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_CRATES_IO_BASE_URL, UreqCratesIoClient};

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
