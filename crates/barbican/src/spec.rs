use std::fmt;
use std::str::FromStr;

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExactCrateSpec {
    crate_name: String,
    version: String,
}

impl ExactCrateSpec {
    pub fn from_parts(crate_name: &str, version: &str) -> Result<Self, ExactCrateSpecError> {
        Self::validate(crate_name, version, format!("{crate_name}@{version}"))
    }

    pub fn crate_name(&self) -> &str {
        &self.crate_name
    }

    pub fn version(&self) -> &str {
        &self.version
    }
}

impl fmt::Display for ExactCrateSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}@{}", self.crate_name, self.version)
    }
}

impl FromStr for ExactCrateSpec {
    type Err = ExactCrateSpecError;

    fn from_str(spec: &str) -> Result<Self, Self::Err> {
        if spec.starts_with('-') {
            return Err(ExactCrateSpecError::InvalidShape(spec.to_owned()));
        }

        let Some((crate_name, version)) = spec.rsplit_once('@') else {
            return Err(ExactCrateSpecError::InvalidShape(spec.to_owned()));
        };

        if crate_name.is_empty() || version.is_empty() {
            return Err(ExactCrateSpecError::InvalidShape(spec.to_owned()));
        }

        Self::validate(crate_name, version, spec.to_owned())
    }
}

impl ExactCrateSpec {
    fn validate(
        crate_name: &str,
        version: &str,
        original: String,
    ) -> Result<Self, ExactCrateSpecError> {
        if version
            .chars()
            .any(|character| matches!(character, '^' | '~' | '*' | '<' | '>' | '='))
        {
            return Err(ExactCrateSpecError::VersionRange(original));
        }

        Ok(Self {
            crate_name: crate_name.to_owned(),
            version: version.to_owned(),
        })
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ExactCrateSpecError {
    #[error("Expected exact crate@version spec, got: {0}")]
    InvalidShape(String),
    #[error("Version ranges are not allowed in routine checks: {0}")]
    VersionRange(String),
}

#[cfg(test)]
mod tests {
    use crate::{ExactCrateSpec, ExactCrateSpecError};

    #[test]
    fn parses_valid_exact_specs() {
        let spec = "serde@1.0.228"
            .parse::<ExactCrateSpec>()
            .expect("spec should parse");

        assert_eq!(spec.crate_name(), "serde");
        assert_eq!(spec.version(), "1.0.228");
        assert_eq!(spec.to_string(), "serde@1.0.228");
    }

    #[test]
    fn rejects_specs_without_an_exact_version() {
        let error = "serde"
            .parse::<ExactCrateSpec>()
            .expect_err("spec should fail");

        assert_eq!(error, ExactCrateSpecError::InvalidShape("serde".to_owned()));
    }

    #[test]
    fn rejects_version_ranges() {
        let error = "serde@^1.0.228"
            .parse::<ExactCrateSpec>()
            .expect_err("range specs should fail");

        assert_eq!(
            error,
            ExactCrateSpecError::VersionRange("serde@^1.0.228".to_owned())
        );
    }
}
