use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use thiserror::Error;

use crate::{ExactCrateSpec, Sha256Digest};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReviewedTargets {
    rust_families: Vec<ReviewedRustFamily>,
}

impl ReviewedTargets {
    pub fn rust_families(&self) -> &[ReviewedRustFamily] {
        &self.rust_families
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewedRustFamily {
    name: String,
    review_record: String,
    direct: BTreeMap<String, String>,
    resolved: BTreeMap<String, ReviewedResolvedTarget>,
}

impl ReviewedRustFamily {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn review_record(&self) -> &str {
        &self.review_record
    }

    pub fn direct(&self) -> &BTreeMap<String, String> {
        &self.direct
    }

    pub fn resolved(&self) -> &BTreeMap<String, ReviewedResolvedTarget> {
        &self.resolved
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewedResolvedTarget {
    version: String,
    checksum_sha256: Option<Sha256Digest>,
}

impl ReviewedResolvedTarget {
    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn checksum_sha256(&self) -> Option<&Sha256Digest> {
        self.checksum_sha256.as_ref()
    }

    pub(crate) fn is_satisfied_by(&self, observed: &ObservedResolvedTarget) -> bool {
        let version_matches =
            observed.versions.len() == 1 && observed.versions.contains(self.version());
        let checksum_matches = match self.checksum_sha256() {
            Some(expected_checksum) => observed.checksums_sha256.contains(expected_checksum),
            None => true,
        };

        version_matches && checksum_matches
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct ObservedResolvedTarget {
    pub(crate) versions: BTreeSet<String>,
    pub(crate) checksums_sha256: BTreeSet<Sha256Digest>,
}

pub fn parse_reviewed_targets_toml(text: &str) -> Result<ReviewedTargets, ReviewedTargetsError> {
    let raw: RawReviewedTargets = toml::from_str(text).map_err(ReviewedTargetsError::Parse)?;
    let mut rust_families = Vec::with_capacity(raw.rust.families.len());

    for family in raw.rust.families {
        if family.resolved.is_empty() {
            return Err(ReviewedTargetsError::EmptyResolvedSet {
                family: family.name,
            });
        }

        for (crate_name, requirement) in &family.direct {
            let Some(version) = requirement.strip_prefix('=') else {
                return Err(ReviewedTargetsError::DirectRequirementNotExact {
                    family: family.name.clone(),
                    crate_name: crate_name.clone(),
                    requirement: requirement.clone(),
                });
            };
            ExactCrateSpec::from_parts(crate_name, version).map_err(|source| {
                ReviewedTargetsError::InvalidDirectRequirement {
                    family: family.name.clone(),
                    crate_name: crate_name.clone(),
                    requirement: requirement.clone(),
                    source,
                }
            })?;
        }

        let mut resolved = BTreeMap::new();

        for (crate_name, target) in &family.resolved {
            let (version, checksum_sha256) = match target {
                RawReviewedResolvedTarget::Version(version) => (version.clone(), None),
                RawReviewedResolvedTarget::RegistryArtifact {
                    version,
                    checksum_sha256,
                } => {
                    let digest =
                        Sha256Digest::try_from(checksum_sha256.as_str()).map_err(|_| {
                            ReviewedTargetsError::InvalidResolvedChecksum {
                                family: family.name.clone(),
                                crate_name: crate_name.clone(),
                                checksum: checksum_sha256.clone(),
                            }
                        })?;

                    (version.clone(), Some(digest))
                }
            };

            ExactCrateSpec::from_parts(crate_name, &version).map_err(|source| {
                ReviewedTargetsError::InvalidResolvedVersion {
                    family: family.name.clone(),
                    crate_name: crate_name.clone(),
                    version: version.clone(),
                    source,
                }
            })?;

            resolved.insert(
                crate_name.clone(),
                ReviewedResolvedTarget {
                    version,
                    checksum_sha256,
                },
            );
        }

        rust_families.push(ReviewedRustFamily {
            name: family.name,
            review_record: family.review_record,
            direct: family.direct,
            resolved,
        });
    }

    Ok(ReviewedTargets { rust_families })
}

#[derive(Debug, Error)]
pub enum ReviewedTargetsError {
    #[error("unable to parse reviewed-targets.toml: {0}")]
    Parse(#[source] toml::de::Error),
    #[error("family {family} has no resolved Cargo.lock targets")]
    EmptyResolvedSet { family: String },
    #[error(
        "family {family} direct requirement for {crate_name} must be exact and include a leading '=': {requirement}"
    )]
    DirectRequirementNotExact {
        family: String,
        crate_name: String,
        requirement: String,
    },
    #[error(
        "family {family} direct requirement for {crate_name} is not a valid exact version {requirement}: {source}"
    )]
    InvalidDirectRequirement {
        family: String,
        crate_name: String,
        requirement: String,
        #[source]
        source: crate::ExactCrateSpecError,
    },
    #[error(
        "family {family} resolved Cargo.lock version for {crate_name} is not exact {version}: {source}"
    )]
    InvalidResolvedVersion {
        family: String,
        crate_name: String,
        version: String,
        #[source]
        source: crate::ExactCrateSpecError,
    },
    #[error(
        "family {family} resolved checksum for {crate_name} is not a valid SHA-256 digest: {checksum}"
    )]
    InvalidResolvedChecksum {
        family: String,
        crate_name: String,
        checksum: String,
    },
}

#[derive(Debug, Deserialize, Default)]
struct RawReviewedTargets {
    #[serde(default)]
    rust: RawRustReviewedTargets,
}

#[derive(Debug, Deserialize, Default)]
struct RawRustReviewedTargets {
    #[serde(default)]
    families: Vec<RawReviewedRustFamily>,
}

#[derive(Debug, Deserialize)]
struct RawReviewedRustFamily {
    name: String,
    review_record: String,
    #[serde(default)]
    direct: BTreeMap<String, String>,
    #[serde(default)]
    resolved: BTreeMap<String, RawReviewedResolvedTarget>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawReviewedResolvedTarget {
    Version(String),
    RegistryArtifact {
        version: String,
        checksum_sha256: String,
    },
}

#[cfg(test)]
mod tests {
    use super::{ReviewedTargetsError, parse_reviewed_targets_toml};
    use crate::Sha256Digest;

    #[test]
    fn parses_rust_reviewed_families() {
        let targets = parse_reviewed_targets_toml(
            r#"
[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.direct]
serde = "=1.0.228"

[rust.families.resolved]
serde = { version = "1.0.228", checksum_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }
serde_derive = "1.0.228"
"#,
        )
        .expect("reviewed targets should parse");

        assert_eq!(targets.rust_families().len(), 1);
        let family = &targets.rust_families()[0];
        assert_eq!(family.name(), "serde-family");
        assert_eq!(
            family.review_record(),
            "docs/dependency-reviews/2026-05-27-serde.md"
        );
        assert_eq!(family.direct().get("serde"), Some(&"=1.0.228".to_owned()));
        assert_eq!(
            family
                .resolved()
                .get("serde")
                .and_then(|target| target.checksum_sha256().map(Sha256Digest::as_str)),
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        );
        assert_eq!(
            family
                .resolved()
                .get("serde_derive")
                .map(|target| target.version()),
            Some("1.0.228")
        );
        assert_eq!(
            family
                .resolved()
                .get("serde_derive")
                .and_then(|target| target.checksum_sha256()),
            None
        );
    }

    #[test]
    fn rejects_non_exact_direct_requirements() {
        let error = parse_reviewed_targets_toml(
            r#"
[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.direct]
serde = "^1.0.228"

[rust.families.resolved]
serde = "1.0.228"
"#,
        )
        .expect_err("non-exact direct requirement should fail");

        assert!(matches!(
            error,
            ReviewedTargetsError::DirectRequirementNotExact { .. }
        ));
    }

    #[test]
    fn rejects_families_without_resolved_targets() {
        let error = parse_reviewed_targets_toml(
            r#"
[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"
"#,
        )
        .expect_err("families without resolved targets should fail");

        assert!(matches!(
            error,
            ReviewedTargetsError::EmptyResolvedSet { .. }
        ));
    }

    #[test]
    fn rejects_invalid_resolved_checksum() {
        let error = parse_reviewed_targets_toml(
            r#"
[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.resolved]
serde = { version = "1.0.228", checksum_sha256 = "not-a-sha256" }
"#,
        )
        .expect_err("invalid checksum should fail");

        assert!(matches!(
            error,
            ReviewedTargetsError::InvalidResolvedChecksum { .. }
        ));
    }
}
