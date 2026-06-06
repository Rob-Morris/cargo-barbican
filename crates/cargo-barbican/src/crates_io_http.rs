use std::time::Duration;

use barbican::{
    CrateRelease, CratesIoClient, CratesIoClientError, ExactCrateSpec, parse_version_response_body,
};
use ureq::Agent;

const USER_AGENT: &str = concat!("cargo-barbican/", env!("CARGO_PKG_VERSION"));
pub const DEFAULT_CRATES_IO_BASE_URL: &str = "https://crates.io";
pub const CRATES_IO_BASE_URL_ENV: &str = "CARGO_BARBICAN_CRATES_IO_BASE_URL";

pub struct UreqCratesIoClient {
    agent: Agent,
    base_url: String,
}

impl UreqCratesIoClient {
    pub fn new(base_url: String) -> Self {
        let config = Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(20)))
            .http_status_as_error(false)
            .build();

        Self {
            agent: config.into(),
            base_url,
        }
    }

    fn version_url(&self, spec: &ExactCrateSpec) -> String {
        format!(
            "{}/api/v1/crates/{}/{}",
            self.base_url.trim_end_matches('/'),
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
}
