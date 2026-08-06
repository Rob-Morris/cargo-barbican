use std::fmt;
use std::str::FromStr;

use semver::Version;
use thiserror::Error;

use crate::iso_date::parse_iso_date;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactRustToolchainChannel {
    value: String,
    kind: ExactRustToolchainKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ExactRustToolchainKind {
    Release,
    DatedNightly,
}

impl ExactRustToolchainChannel {
    pub fn as_str(&self) -> &str {
        &self.value
    }

    fn accepts_release(&self, release: &str) -> bool {
        match self.kind {
            ExactRustToolchainKind::Release => release == self.value,
            ExactRustToolchainKind::DatedNightly => release.ends_with("-nightly"),
        }
    }
}

impl fmt::Display for ExactRustToolchainChannel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.value)
    }
}

impl FromStr for ExactRustToolchainChannel {
    type Err = RustToolchainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Some(date) = value.strip_prefix("nightly-") {
            validate_nightly_date(date)?;
            return Ok(Self {
                value: value.to_owned(),
                kind: ExactRustToolchainKind::DatedNightly,
            });
        }

        let version = Version::parse(value)
            .map_err(|_| RustToolchainError::FloatingOrUnsupportedChannel(value.to_owned()))?;
        if !version.build.is_empty()
            || (!version.pre.is_empty() && !is_supported_beta_prerelease(version.pre.as_str()))
        {
            return Err(RustToolchainError::FloatingOrUnsupportedChannel(
                value.to_owned(),
            ));
        }

        Ok(Self {
            value: value.to_owned(),
            kind: ExactRustToolchainKind::Release,
        })
    }
}

fn is_supported_beta_prerelease(prerelease: &str) -> bool {
    let mut parts = prerelease.split('.');
    if parts.next() != Some("beta") {
        return false;
    }
    match (parts.next(), parts.next()) {
        (Some(number), None) => {
            !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())
        }
        _ => false,
    }
}

fn validate_nightly_date(value: &str) -> Result<(), RustToolchainError> {
    parse_iso_date(value)
        .map(|_| ())
        .map_err(|_| RustToolchainError::InvalidNightlyDate(value.to_owned()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustToolchainConformance {
    pub host: String,
    pub release: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ToolVerboseVersion {
    release: String,
    host: String,
}

pub fn parse_rust_toolchain_toml(
    text: &str,
) -> Result<ExactRustToolchainChannel, RustToolchainError> {
    let value: toml::Value = toml::from_str(text).map_err(RustToolchainError::Parse)?;
    let root = value.as_table().ok_or(RustToolchainError::ExpectedTable)?;
    let toolchain = root
        .get("toolchain")
        .and_then(toml::Value::as_table)
        .ok_or(RustToolchainError::MissingToolchainTable)?;
    if toolchain.contains_key("path") {
        return Err(RustToolchainError::PathToolchainUnsupported);
    }
    let channel = toolchain
        .get("channel")
        .and_then(toml::Value::as_str)
        .ok_or(RustToolchainError::MissingChannel)?;
    channel.parse()
}

pub fn evaluate_rust_toolchain_conformance(
    pin: &ExactRustToolchainChannel,
    active_toolchain_output: &str,
    cargo_verbose_version: &str,
    rustc_verbose_version: &str,
    rustdoc_verbose_version: &str,
) -> Result<RustToolchainConformance, RustToolchainError> {
    let active = active_toolchain_output
        .split_whitespace()
        .next()
        .ok_or(RustToolchainError::MissingActiveToolchain)?;
    let cargo = parse_verbose_version("cargo", cargo_verbose_version)?;
    let rustc = parse_verbose_version("rustc", rustc_verbose_version)?;
    let rustdoc = parse_verbose_version("rustdoc", rustdoc_verbose_version)?;

    for (tool, facts) in [("cargo", &cargo), ("rustdoc", &rustdoc)] {
        if facts.host != rustc.host {
            return Err(RustToolchainError::ToolHostMismatch {
                tool,
                expected: rustc.host,
                actual: facts.host.clone(),
            });
        }
    }

    let expected_active = format!("{}-{}", pin.as_str(), rustc.host);
    if active != expected_active {
        return Err(RustToolchainError::ActiveToolchainMismatch {
            expected: expected_active,
            actual: active.to_owned(),
        });
    }
    if !pin.accepts_release(&cargo.release) {
        return Err(RustToolchainError::ToolReleaseMismatch {
            tool: "cargo",
            expected: pin.to_string(),
            actual: cargo.release,
        });
    }
    if !pin.accepts_release(&rustc.release) {
        return Err(RustToolchainError::ToolReleaseMismatch {
            tool: "rustc",
            expected: pin.to_string(),
            actual: rustc.release,
        });
    }
    if !pin.accepts_release(&rustdoc.release) {
        return Err(RustToolchainError::ToolReleaseMismatch {
            tool: "rustdoc",
            expected: pin.to_string(),
            actual: rustdoc.release,
        });
    }
    for (tool, facts) in [("cargo", &cargo), ("rustdoc", &rustdoc)] {
        if facts.release != rustc.release {
            return Err(RustToolchainError::ToolchainReleaseMismatch {
                tool,
                expected: rustc.release,
                actual: facts.release.clone(),
            });
        }
    }

    Ok(RustToolchainConformance {
        host: rustc.host,
        release: rustc.release,
    })
}

fn parse_verbose_version(
    tool: &'static str,
    text: &str,
) -> Result<ToolVerboseVersion, RustToolchainError> {
    let release =
        verbose_field(text, "release").ok_or(RustToolchainError::MissingVerboseField {
            tool,
            field: "release",
        })?;
    let host = verbose_field(text, "host").ok_or(RustToolchainError::MissingVerboseField {
        tool,
        field: "host",
    })?;
    Ok(ToolVerboseVersion { release, host })
}

fn verbose_field(text: &str, field: &str) -> Option<String> {
    let prefix = format!("{field}:");
    text.lines()
        .find_map(|line| line.strip_prefix(&prefix).map(str::trim))
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

#[derive(Debug, Error)]
pub enum RustToolchainError {
    #[error("unable to parse rust-toolchain.toml: {0}")]
    Parse(#[source] toml::de::Error),
    #[error("rust-toolchain.toml root must be a TOML table")]
    ExpectedTable,
    #[error("rust-toolchain.toml must contain a [toolchain] table")]
    MissingToolchainTable,
    #[error("rust-toolchain.toml [toolchain].channel must be a string")]
    MissingChannel,
    #[error("path-based Rust toolchains are not portable and are unsupported by the gate")]
    PathToolchainUnsupported,
    #[error(
        "Rust toolchain channel {0:?} is floating or unsupported; use an exact release such as 1.95.0 or a dated nightly such as nightly-2026-04-14"
    )]
    FloatingOrUnsupportedChannel(String),
    #[error("nightly toolchain date {0:?} is invalid; use nightly-YYYY-MM-DD")]
    InvalidNightlyDate(String),
    #[error("rustup did not report an active toolchain")]
    MissingActiveToolchain,
    #[error("active Rust toolchain mismatch: expected {expected}, found {actual}")]
    ActiveToolchainMismatch { expected: String, actual: String },
    #[error("{tool} --version --verbose did not report {field}")]
    MissingVerboseField {
        tool: &'static str,
        field: &'static str,
    },
    #[error("{tool} and rustc host mismatch: rustc reported {expected}, {tool} reported {actual}")]
    ToolHostMismatch {
        tool: &'static str,
        expected: String,
        actual: String,
    },
    #[error(
        "{tool} release mismatch: rust-toolchain.toml pins {expected}, but {tool} reported {actual}"
    )]
    ToolReleaseMismatch {
        tool: &'static str,
        expected: String,
        actual: String,
    },
    #[error(
        "{tool} and rustc release mismatch: rustc reported {expected}, {tool} reported {actual}"
    )]
    ToolchainReleaseMismatch {
        tool: &'static str,
        expected: String,
        actual: String,
    },
}

#[cfg(test)]
mod tests {
    use super::{
        ExactRustToolchainChannel, RustToolchainError, evaluate_rust_toolchain_conformance,
        parse_rust_toolchain_toml,
    };

    const CARGO_VERBOSE: &str = "cargo 1.95.0\nrelease: 1.95.0\nhost: aarch64-apple-darwin\n";
    const RUSTC_VERBOSE: &str = "rustc 1.95.0\nrelease: 1.95.0\nhost: aarch64-apple-darwin\n";
    const RUSTDOC_VERBOSE: &str = "rustdoc 1.95.0\nrelease: 1.95.0\nhost: aarch64-apple-darwin\n";

    #[test]
    fn parses_exact_release_and_dated_nightly_pins() {
        for channel in ["1.95.0", "1.96.0-beta.2", "nightly-2026-04-14"] {
            let parsed = channel
                .parse::<ExactRustToolchainChannel>()
                .expect("exact channel should parse");
            assert_eq!(parsed.as_str(), channel);
        }
    }

    #[test]
    fn rejects_floating_custom_and_undated_nightly_channels() {
        for channel in [
            "stable",
            "beta",
            "nightly",
            "1.95",
            "1.96.0-beta",
            "1.96.0-nightly",
            "custom-toolchain",
            "1.95.0+local",
        ] {
            assert!(channel.parse::<ExactRustToolchainChannel>().is_err());
        }
    }

    #[test]
    fn rejects_invalid_nightly_calendar_dates() {
        for channel in ["nightly-2026-02-30", "nightly-+123-01-01"] {
            let error = channel
                .parse::<ExactRustToolchainChannel>()
                .expect_err("invalid calendar date should fail");
            assert!(matches!(error, RustToolchainError::InvalidNightlyDate(_)));
        }
    }

    #[test]
    fn parses_channel_from_toolchain_toml_without_duplicating_rustup_schema() {
        let pin = parse_rust_toolchain_toml(
            r#"[toolchain]
channel = "1.95.0"
profile = "minimal"
components = ["clippy"]
"#,
        )
        .expect("toolchain config should parse");
        assert_eq!(pin.as_str(), "1.95.0");
    }

    #[test]
    fn rejects_path_toolchains_even_when_a_channel_is_also_present() {
        let error = parse_rust_toolchain_toml(
            r#"[toolchain]
channel = "1.95.0"
path = "/tmp/custom-rust"
"#,
        )
        .expect_err("path toolchain should fail");
        assert!(matches!(
            error,
            RustToolchainError::PathToolchainUnsupported
        ));
    }

    #[test]
    fn accepts_matching_active_toolchain_versions() {
        let pin = "1.95.0"
            .parse::<ExactRustToolchainChannel>()
            .expect("pin should parse");
        let conformance = evaluate_rust_toolchain_conformance(
            &pin,
            "1.95.0-aarch64-apple-darwin (overridden by 'rust-toolchain.toml')\n",
            CARGO_VERBOSE,
            RUSTC_VERBOSE,
            RUSTDOC_VERBOSE,
        )
        .expect("matching toolchain should pass");
        assert_eq!(conformance.host, "aarch64-apple-darwin");
    }

    #[test]
    fn rejects_a_higher_precedence_active_toolchain_override() {
        let pin = "1.95.0"
            .parse::<ExactRustToolchainChannel>()
            .expect("pin should parse");
        let error = evaluate_rust_toolchain_conformance(
            &pin,
            "1.96.0-aarch64-apple-darwin (environment override)\n",
            CARGO_VERBOSE,
            RUSTC_VERBOSE,
            RUSTDOC_VERBOSE,
        )
        .expect_err("active mismatch should fail");
        assert!(matches!(
            error,
            RustToolchainError::ActiveToolchainMismatch { .. }
        ));
    }

    #[test]
    fn rejects_cargo_release_drift() {
        let pin = "1.95.0"
            .parse::<ExactRustToolchainChannel>()
            .expect("pin should parse");
        let error = evaluate_rust_toolchain_conformance(
            &pin,
            "1.95.0-aarch64-apple-darwin\n",
            "cargo 1.96.0\nrelease: 1.96.0\nhost: aarch64-apple-darwin\n",
            RUSTC_VERBOSE,
            RUSTDOC_VERBOSE,
        )
        .expect_err("cargo drift should fail");
        assert!(matches!(
            error,
            RustToolchainError::ToolReleaseMismatch { tool: "cargo", .. }
        ));
    }

    #[test]
    fn rejects_rustc_release_drift() {
        let pin = "1.95.0"
            .parse::<ExactRustToolchainChannel>()
            .expect("pin should parse");
        let error = evaluate_rust_toolchain_conformance(
            &pin,
            "1.95.0-aarch64-apple-darwin\n",
            CARGO_VERBOSE,
            "rustc 1.96.0\nrelease: 1.96.0\nhost: aarch64-apple-darwin\n",
            RUSTDOC_VERBOSE,
        )
        .expect_err("rustc drift should fail");
        assert!(matches!(
            error,
            RustToolchainError::ToolReleaseMismatch { tool: "rustc", .. }
        ));
    }

    #[test]
    fn accepts_matching_dated_nightly_toolchain() {
        let pin = "nightly-2026-04-14"
            .parse::<ExactRustToolchainChannel>()
            .expect("dated nightly should parse");
        let conformance = evaluate_rust_toolchain_conformance(
            &pin,
            "nightly-2026-04-14-aarch64-apple-darwin (overridden by 'rust-toolchain.toml')\n",
            "cargo 1.96.0-nightly\nrelease: 1.96.0-nightly\nhost: aarch64-apple-darwin\n",
            "rustc 1.96.0-nightly\nrelease: 1.96.0-nightly\nhost: aarch64-apple-darwin\n",
            "rustdoc 1.96.0-nightly\nrelease: 1.96.0-nightly\nhost: aarch64-apple-darwin\n",
        )
        .expect("matching nightly toolchain should pass");

        assert_eq!(conformance.release, "1.96.0-nightly");
    }

    #[test]
    fn rejects_a_different_active_dated_nightly() {
        let pin = "nightly-2026-04-14"
            .parse::<ExactRustToolchainChannel>()
            .expect("dated nightly should parse");
        let error = evaluate_rust_toolchain_conformance(
            &pin,
            "nightly-2026-04-15-aarch64-apple-darwin\n",
            "cargo 1.96.0-nightly\nrelease: 1.96.0-nightly\nhost: aarch64-apple-darwin\n",
            "rustc 1.96.0-nightly\nrelease: 1.96.0-nightly\nhost: aarch64-apple-darwin\n",
            "rustdoc 1.96.0-nightly\nrelease: 1.96.0-nightly\nhost: aarch64-apple-darwin\n",
        )
        .expect_err("a different active nightly date should fail");

        assert!(matches!(
            error,
            RustToolchainError::ActiveToolchainMismatch { .. }
        ));
    }

    #[test]
    fn rejects_rustdoc_release_drift() {
        let pin = "1.95.0"
            .parse::<ExactRustToolchainChannel>()
            .expect("pin should parse");
        let error = evaluate_rust_toolchain_conformance(
            &pin,
            "1.95.0-aarch64-apple-darwin\n",
            CARGO_VERBOSE,
            RUSTC_VERBOSE,
            "rustdoc 1.96.0\nrelease: 1.96.0\nhost: aarch64-apple-darwin\n",
        )
        .expect_err("rustdoc drift should fail");
        assert!(matches!(
            error,
            RustToolchainError::ToolReleaseMismatch {
                tool: "rustdoc",
                ..
            }
        ));
    }

    #[test]
    fn rejects_cross_tool_release_drift_within_a_dated_nightly() {
        let pin = "nightly-2026-04-14"
            .parse::<ExactRustToolchainChannel>()
            .expect("dated nightly should parse");

        for (tool, cargo, rustdoc) in [
            (
                "cargo",
                "cargo 1.97.0-nightly\nrelease: 1.97.0-nightly\nhost: aarch64-apple-darwin\n",
                "rustdoc 1.96.0-nightly\nrelease: 1.96.0-nightly\nhost: aarch64-apple-darwin\n",
            ),
            (
                "rustdoc",
                "cargo 1.96.0-nightly\nrelease: 1.96.0-nightly\nhost: aarch64-apple-darwin\n",
                "rustdoc 1.97.0-nightly\nrelease: 1.97.0-nightly\nhost: aarch64-apple-darwin\n",
            ),
        ] {
            let error = evaluate_rust_toolchain_conformance(
                &pin,
                "nightly-2026-04-14-aarch64-apple-darwin\n",
                cargo,
                "rustc 1.96.0-nightly\nrelease: 1.96.0-nightly\nhost: aarch64-apple-darwin\n",
                rustdoc,
            )
            .expect_err("cross-tool nightly drift should fail");

            assert!(matches!(
                error,
                RustToolchainError::ToolchainReleaseMismatch {
                    tool: actual_tool,
                    ..
                } if actual_tool == tool
            ));
        }
    }
}
