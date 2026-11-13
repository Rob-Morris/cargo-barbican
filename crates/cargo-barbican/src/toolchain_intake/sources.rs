use super::store::PrivateStore;
use std::path::{Path, PathBuf};
use std::time::Duration;
use ureq::Agent;

pub(super) const MAX_SOURCE_BYTES: u64 = 8 * 1024 * 1024;
const USER_AGENT: &str = concat!("cargo-barbican/", env!("CARGO_PKG_VERSION"));

pub(super) struct Sources {
    agent: Agent,
    #[cfg(test)]
    fixture: Option<std::collections::BTreeMap<String, Vec<u8>>>,
}
impl Sources {
    pub fn new() -> Self {
        let config = Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(300)))
            .https_only(true)
            .max_redirects(0)
            .build();
        Self {
            agent: config.into(),
            #[cfg(test)]
            fixture: None,
        }
    }

    #[cfg(test)]
    pub fn fixture(responses: std::collections::BTreeMap<String, Vec<u8>>) -> Self {
        let mut sources = Self::new();
        sources.fixture = Some(responses);
        sources
    }

    pub fn fetch(&self, url: &str) -> Result<Vec<u8>, String> {
        official_url(url)?;
        #[cfg(test)]
        if let Some(fixture) = &self.fixture {
            return fixture
                .get(url)
                .cloned()
                .ok_or_else(|| format!("missing fixture source {url}"));
        }
        let mut response = self
            .agent
            .get(url)
            .header("User-Agent", USER_AGENT)
            .call()
            .map_err(|e| format!("required source {url} retrieval failed: {e}"))?;
        if response.status().as_u16() != 200 {
            return Err(format!(
                "required source {url} returned unexpected HTTP {}",
                response.status().as_u16()
            ));
        }
        response
            .body_mut()
            .with_config()
            .limit(MAX_SOURCE_BYTES)
            .read_to_vec()
            .map_err(|e| format!("required source {url} body failed: {e}"))
    }

    pub fn cargo_advisories(&self) -> Result<Vec<u8>, String> {
        #[cfg(test)]
        if let Some(fixture) = &self.fixture {
            return fixture
                .get("https://api.github.com/repos/rust-lang/cargo/security-advisories")
                .cloned()
                .ok_or_else(|| "missing fixture Cargo advisories".into());
        }
        let mut advisories = Vec::new();
        for page in 1..=10 {
            let url = format!(
                "https://api.github.com/repos/rust-lang/cargo/security-advisories?per_page=100&page={page}"
            );
            let mut response = self
                .agent
                .get(&url)
                .header("User-Agent", USER_AGENT)
                .call()
                .map_err(|e| e.to_string())?;
            if response.status().as_u16() != 200 {
                return Err("Cargo advisory source returned unexpected HTTP status".into());
            }
            let next = response
                .headers()
                .get("link")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|link| link.contains("rel=\"next\""));
            let bytes = response
                .body_mut()
                .with_config()
                .limit(MAX_SOURCE_BYTES)
                .read_to_vec()
                .map_err(|e| e.to_string())?;
            let entries: Vec<serde_json::Value> = serde_json::from_slice(&bytes)
                .map_err(|e| format!("Cargo advisory response is not an array: {e}"))?;
            if entries.len() > 100 {
                return Err("Cargo advisory page exceeds selected page size".into());
            }
            for entry in &entries {
                let id = entry
                    .get("ghsa_id")
                    .and_then(serde_json::Value::as_str)
                    .ok_or("Cargo advisory missing GHSA identity")?;
                if !id.starts_with("GHSA-")
                    || id.len() != 19
                    || entry
                        .get("description")
                        .and_then(serde_json::Value::as_str)
                        .is_none_or(|s| s.is_empty())
                    || entry
                        .get("vulnerabilities")
                        .and_then(serde_json::Value::as_array)
                        .is_none_or(|v| v.is_empty())
                {
                    return Err("Cargo advisory source schema is incomplete".into());
                }
            }
            advisories.extend(entries);
            if !next {
                let bytes = serde_json::to_vec(&advisories).map_err(|e| e.to_string())?;
                if bytes.len() as u64 > MAX_SOURCE_BYTES {
                    return Err("complete Cargo advisory corpus exceeds source bound".into());
                }
                return Ok(bytes);
            }
        }
        Err("Cargo advisory pagination exceeds qualified bound".into())
    }

    pub fn archive(
        &self,
        url: &str,
        store: &PrivateStore,
        relative: &Path,
    ) -> Result<PathBuf, String> {
        if !url.starts_with("https://static.rust-lang.org/dist/") {
            return Err("archive is outside the official distribution source".into());
        }
        official_url(url)?;
        #[cfg(test)]
        if self.fixture.is_some() {
            return store.publish_stream(
                relative,
                std::io::Cursor::new(self.fetch(url)?),
                barbican::rust_distribution::MAX_COMPRESSED_BYTES,
            );
        }
        let mut response = self
            .agent
            .get(url)
            .header("User-Agent", USER_AGENT)
            .call()
            .map_err(|e| format!("archive {url} retrieval failed: {e}"))?;
        if response.status().as_u16() != 200 {
            return Err(format!(
                "archive {url} returned unexpected HTTP {}",
                response.status().as_u16()
            ));
        }
        let reader = response.body_mut().as_reader();
        store.publish_stream(
            relative,
            reader,
            barbican::rust_distribution::MAX_COMPRESSED_BYTES,
        )
    }
}

fn official_url(url: &str) -> Result<(), String> {
    const PREFIXES: [&str; 9] = [
        "https://static.rust-lang.org/",
        "https://blog.rust-lang.org/",
        "https://raw.githubusercontent.com/rust-lang/",
        "https://api.github.com/repos/rust-lang/",
        "https://raw.githubusercontent.com/RustSec/advisory-db/",
        "https://api.github.com/repos/RustSec/advisory-db/",
        "https://codeload.github.com/RustSec/advisory-db/",
        "https://rust-lang.org/",
        "https://llvm.org/",
    ];
    if !PREFIXES.iter().any(|prefix| url.starts_with(prefix))
        || url.bytes().any(|b| b <= 32 || b == 127 || b == b'\\')
        || url.contains('#')
        || url.contains('?')
        || url.split('/').any(|part| part == ".." || part == ".")
    {
        return Err("source URL is outside the closed official source set".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_transport_refuses_redirects_and_unapproved_authorities() {
        let sources = Sources::new();
        assert!(sources.agent.config().https_only());
        assert_eq!(sources.agent.config().max_redirects(), 0);
        for url in [
            "http://static.rust-lang.org/dist/a",
            "https://static.rust-lang.org.evil/a",
            "https://static.rust-lang.org/../a",
            "https://static.rust-lang.org/a?redirect=evil",
        ] {
            assert!(official_url(url).is_err());
        }
        assert!(official_url("https://static.rust-lang.org/dist/channel-rust-1.99.1.toml").is_ok());
    }
}
