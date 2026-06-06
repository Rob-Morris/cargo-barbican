use serde::Deserialize;
use thiserror::Error;

pub const MAXIMUM_RELEASE_AGE_MINIMUM_DAYS: u64 = 365_000;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct BarbicanConfig {
    pub release_age: ReleaseAgeConfig,
    pub high_scrutiny: HighScrutinyConfig,
    pub delegates: DelegatesConfig,
}

impl BarbicanConfig {
    pub fn from_toml_str(text: &str) -> Result<Self, ConfigLoadError> {
        let config: Self = toml::from_str(text).map_err(ConfigLoadError::Parse)?;
        config.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReleaseAgeConfig {
    pub minimum_days: u64,
}

impl Default for ReleaseAgeConfig {
    fn default() -> Self {
        Self { minimum_days: 7 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HighScrutinyConfig {
    pub new_direct_dependencies: bool,
    pub non_crates_io_direct_dependencies: bool,
    pub non_crates_io_source_changes: bool,
    pub build_rs_changes: bool,
    pub proc_macro_changes: bool,
    pub native_sys_crates: bool,
}

impl Default for HighScrutinyConfig {
    fn default() -> Self {
        Self {
            new_direct_dependencies: true,
            non_crates_io_direct_dependencies: true,
            non_crates_io_source_changes: true,
            build_rs_changes: true,
            proc_macro_changes: true,
            native_sys_crates: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DelegatesConfig {}

#[derive(Debug, Error)]
pub enum ConfigLoadError {
    #[error("unable to parse barbican.toml: {0}")]
    Parse(#[source] toml::de::Error),
    #[error(
        "barbican.toml release_age.minimum_days {actual} exceeds the supported maximum of {max}"
    )]
    InvalidMinimumDays { actual: u64, max: u64 },
}

impl BarbicanConfig {
    fn validate(self) -> Result<Self, ConfigLoadError> {
        if self.release_age.minimum_days > MAXIMUM_RELEASE_AGE_MINIMUM_DAYS {
            return Err(ConfigLoadError::InvalidMinimumDays {
                actual: self.release_age.minimum_days,
                max: MAXIMUM_RELEASE_AGE_MINIMUM_DAYS,
            });
        }

        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::{BarbicanConfig, ConfigLoadError};

    #[test]
    fn empty_config_uses_defaults() {
        let config = BarbicanConfig::from_toml_str("").expect("empty config should parse");

        assert_eq!(config.release_age.minimum_days, 7);
        assert!(config.high_scrutiny.new_direct_dependencies);
        assert!(config.high_scrutiny.non_crates_io_direct_dependencies);
        assert!(config.high_scrutiny.non_crates_io_source_changes);
        assert!(config.high_scrutiny.build_rs_changes);
        assert!(config.high_scrutiny.proc_macro_changes);
        assert!(config.high_scrutiny.native_sys_crates);
    }

    #[test]
    fn release_age_section_overrides_default_days() {
        let config = BarbicanConfig::from_toml_str(
            r#"
[release_age]
minimum_days = 21

[high_scrutiny]

[delegates]
"#,
        )
        .expect("config should parse");

        assert_eq!(config.release_age.minimum_days, 21);
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let error = BarbicanConfig::from_toml_str(
            r#"
[release_age]
minimum_days = 7
unexpected = true
"#,
        )
        .expect_err("unknown config keys should fail");

        assert!(matches!(error, ConfigLoadError::Parse(_)));
    }

    #[test]
    fn rejects_unreasonably_large_minimum_days() {
        let error = BarbicanConfig::from_toml_str(
            r#"
[release_age]
minimum_days = 365001
"#,
        )
        .expect_err("excessive minimum_days should fail");

        assert!(matches!(
            error,
            ConfigLoadError::InvalidMinimumDays {
                actual: 365001,
                max: 365000,
            }
        ));
    }
}
