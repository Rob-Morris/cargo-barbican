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

    pub fn is_native_sys(&self) -> bool {
        self.crate_name.ends_with("-sys")
    }
}

pub fn parse_exact_version_requirement(
    crate_name: &str,
    requirement: &str,
) -> Result<String, ExactVersionRequirementError> {
    let Some(version) = requirement.strip_prefix('=') else {
        return Err(ExactVersionRequirementError::MissingEquals);
    };

    ExactCrateSpec::from_parts(crate_name, version)
        .map_err(ExactVersionRequirementError::InvalidVersion)?;

    Ok(version.to_owned())
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

        let version = version.strip_prefix('=').unwrap_or(version);

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
        if crate_name.is_empty() || version.is_empty() {
            return Err(ExactCrateSpecError::InvalidShape(original));
        }

        if !is_valid_crate_name(crate_name) {
            return Err(ExactCrateSpecError::InvalidCrateName(original));
        }

        if !is_valid_version(version) {
            return Err(ExactCrateSpecError::VersionRange(original));
        }

        Ok(Self {
            crate_name: crate_name.to_owned(),
            version: version.to_owned(),
        })
    }
}

pub(crate) fn is_valid_crate_name(crate_name: &str) -> bool {
    crate_name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

pub(crate) fn is_valid_version(version: &str) -> bool {
    let mut bytes = version.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };

    first.is_ascii_alphanumeric()
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ExactCrateSpecError {
    #[error("Expected exact crate@version spec, got: {0:?}")]
    InvalidShape(String),
    #[error("Crate names may contain only ASCII letters, numbers, '_' and '-': {0:?}")]
    InvalidCrateName(String),
    #[error("Expected exact crate@version spec; version ranges are not allowed: {0:?}")]
    VersionRange(String),
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ExactVersionRequirementError {
    #[error("exact version requirements must include a leading '='")]
    MissingEquals,
    #[error("invalid exact version requirement: {0:?}")]
    InvalidVersion(#[source] ExactCrateSpecError),
}

#[cfg(test)]
mod tests {
    use crate::{
        ExactCrateSpec, ExactCrateSpecError, ExactVersionRequirementError,
        parse_exact_version_requirement,
    };

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
    fn parses_cli_specs_with_optional_leading_equals() {
        let spec = "serde@=1.0.228"
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
    fn rejects_invalid_crate_names() {
        let error = "foo\"@1.0.0"
            .parse::<ExactCrateSpec>()
            .expect_err("spec should fail");

        assert_eq!(
            error,
            ExactCrateSpecError::InvalidCrateName("foo\"@1.0.0".to_owned())
        );
    }

    #[test]
    fn rejects_version_ranges() {
        for spec in ["serde@^1.0.228", "serde@=^1", "serde@>=1"] {
            let error = spec
                .parse::<ExactCrateSpec>()
                .expect_err("range specs should fail");

            assert_eq!(error, ExactCrateSpecError::VersionRange(spec.to_owned()));
        }
    }

    #[test]
    fn rejects_empty_parts_from_parts() {
        let error = ExactCrateSpec::from_parts("", "1.0.0").expect_err("name should fail");
        assert_eq!(
            error,
            ExactCrateSpecError::InvalidShape("@1.0.0".to_owned())
        );

        let error = ExactCrateSpec::from_parts("serde", "").expect_err("version should fail");
        assert_eq!(
            error,
            ExactCrateSpecError::InvalidShape("serde@".to_owned())
        );
    }

    #[test]
    fn rejects_versions_with_url_path_characters() {
        let error = "serde@1.0.0/../serde"
            .parse::<ExactCrateSpec>()
            .expect_err("version should fail");

        assert_eq!(
            error,
            ExactCrateSpecError::VersionRange("serde@1.0.0/../serde".to_owned())
        );
    }

    #[test]
    fn rejects_versions_with_non_alphanumeric_prefixes() {
        for spec in ["serde@-1.0.0", "serde@+meta", "serde@.1"] {
            let error = spec
                .parse::<ExactCrateSpec>()
                .expect_err("version should fail");

            assert_eq!(error, ExactCrateSpecError::VersionRange(spec.to_owned()));
        }
    }

    #[test]
    fn parses_exact_version_requirements() {
        assert_eq!(
            parse_exact_version_requirement("serde", "=1.0.228").expect("requirement should parse"),
            "1.0.228"
        );
    }

    #[test]
    fn exact_version_requirements_distinguish_missing_equals_from_invalid_version() {
        assert_eq!(
            parse_exact_version_requirement("serde", "^1.0.228")
                .expect_err("requirement should fail"),
            ExactVersionRequirementError::MissingEquals
        );

        assert!(matches!(
            parse_exact_version_requirement("serde", "=^1.0.228")
                .expect_err("requirement should fail"),
            ExactVersionRequirementError::InvalidVersion(ExactCrateSpecError::VersionRange(_))
        ));
    }
}
