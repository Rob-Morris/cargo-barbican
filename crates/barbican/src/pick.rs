use semver::{Version, VersionReq};
use thiserror::Error;
use time::OffsetDateTime;

use crate::{
    CrateRelease, ExactCrateSpec, ReleaseAgeOutcome, ReleaseAgeReport, ReviewedReleaseAgeException,
    VersionInfo, evaluate_release_age,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PickSpec {
    crate_name: String,
    requirement: String,
}

impl PickSpec {
    pub fn crate_name(&self) -> &str {
        &self.crate_name
    }

    pub fn requirement(&self) -> &str {
        &self.requirement
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PickSpecError {
    #[error("pick specs must be `crate` or `crate@range`, got: {0:?}")]
    InvalidShape(String),
    #[error("invalid crate name in pick spec: {0:?}")]
    InvalidCrateName(String),
    #[error("invalid semver requirement {requirement:?}: {reason}")]
    InvalidRequirement { requirement: String, reason: String },
}

pub fn parse_pick_spec(input: &str) -> Result<PickSpec, PickSpecError> {
    if input.is_empty() || input.starts_with('-') {
        return Err(PickSpecError::InvalidShape(input.to_owned()));
    }

    let (crate_name, requirement) = match input.rsplit_once('@') {
        Some((crate_name, requirement)) if !crate_name.is_empty() && !requirement.is_empty() => {
            (crate_name, requirement)
        }
        Some(_) => return Err(PickSpecError::InvalidShape(input.to_owned())),
        None => (input, "*"),
    };

    // ExactCrateSpec validates the crate-name character set; the version is a dummy.
    ExactCrateSpec::from_parts(crate_name, "0.0.0")
        .map_err(|_| PickSpecError::InvalidCrateName(input.to_owned()))?;
    VersionReq::parse(requirement).map_err(|source| PickSpecError::InvalidRequirement {
        requirement: requirement.to_owned(),
        reason: source.to_string(),
    })?;

    Ok(PickSpec {
        crate_name: crate_name.to_owned(),
        requirement: requirement.to_owned(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PickSelection {
    selected: ExactCrateSpec,
    release_age: ReleaseAgeReport,
    excluded: Vec<PickExcludedVersion>,
}

impl PickSelection {
    pub fn selected(&self) -> &ExactCrateSpec {
        &self.selected
    }

    pub fn release_age(&self) -> &ReleaseAgeReport {
        &self.release_age
    }

    pub fn excluded(&self) -> &[PickExcludedVersion] {
        &self.excluded
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PickExcludedVersion {
    version: String,
    reason: PickExclusionReason,
}

impl PickExcludedVersion {
    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn reason(&self) -> &PickExclusionReason {
        &self.reason
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PickExclusionReason {
    InvalidSemver(String),
    InvalidExactSpec(String),
    DoesNotMatchRequirement,
    PreRelease,
    Yanked,
    TooFresh,
    ReleaseAgeExceptionArtefactMismatch,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PickError {
    #[error("invalid semver requirement {requirement:?}: {reason}")]
    InvalidRequirement { requirement: String, reason: String },
    #[error("no version satisfied the requirement and policy")]
    NoMatchingVersion { excluded: Vec<PickExcludedVersion> },
}

impl PickError {
    pub fn excluded(&self) -> &[PickExcludedVersion] {
        match self {
            PickError::InvalidRequirement { .. } => &[],
            PickError::NoMatchingVersion { excluded } => excluded,
        }
    }
}

pub fn pick_version(
    crate_name: &str,
    requirement: &str,
    versions: &[VersionInfo],
    minimum_days: u64,
    now: OffsetDateTime,
    release_age_exceptions: &[ReviewedReleaseAgeException],
) -> Result<PickSelection, PickError> {
    let requirement =
        VersionReq::parse(requirement).map_err(|source| PickError::InvalidRequirement {
            requirement: requirement.to_owned(),
            reason: source.to_string(),
        })?;
    let mut candidates = Vec::new();
    let mut excluded = Vec::new();

    for version in versions {
        let parsed = match Version::parse(&version.num) {
            Ok(parsed) => parsed,
            Err(source) => {
                excluded.push(PickExcludedVersion {
                    version: version.num.clone(),
                    reason: PickExclusionReason::InvalidSemver(source.to_string()),
                });
                continue;
            }
        };

        if !parsed.pre.is_empty() {
            excluded.push(PickExcludedVersion {
                version: version.num.clone(),
                reason: PickExclusionReason::PreRelease,
            });
            continue;
        }

        if !requirement.matches(&parsed) {
            excluded.push(PickExcludedVersion {
                version: version.num.clone(),
                reason: PickExclusionReason::DoesNotMatchRequirement,
            });
            continue;
        }

        if version.yanked {
            excluded.push(PickExcludedVersion {
                version: version.num.clone(),
                reason: PickExclusionReason::Yanked,
            });
            continue;
        }

        let spec = match ExactCrateSpec::from_parts(crate_name, &version.num) {
            Ok(spec) => spec,
            Err(source) => {
                excluded.push(PickExcludedVersion {
                    version: version.num.clone(),
                    reason: PickExclusionReason::InvalidExactSpec(source.to_string()),
                });
                continue;
            }
        };
        let release = CrateRelease {
            checksum_sha256_hex: version.checksum_sha256_hex.clone(),
            published_at_raw: version.published_at_raw.clone(),
            published_at: version.published_at,
            yanked: version.yanked,
        };
        let exception = release_age_exceptions
            .iter()
            .find(|exception| exception.spec() == &spec);
        let release_age = evaluate_release_age(spec.clone(), release, now, minimum_days, exception);

        match release_age.outcome() {
            ReleaseAgeOutcome::Allowed | ReleaseAgeOutcome::AllowedByException { .. } => {
                candidates.push((parsed, spec, release_age));
            }
            ReleaseAgeOutcome::TooFresh => excluded.push(PickExcludedVersion {
                version: version.num.clone(),
                reason: PickExclusionReason::TooFresh,
            }),
            ReleaseAgeOutcome::Yanked => {
                unreachable!("yanked filtered before evaluate_release_age");
            }
            ReleaseAgeOutcome::ExceptionArtefactMismatch { .. } => {
                excluded.push(PickExcludedVersion {
                    version: version.num.clone(),
                    reason: PickExclusionReason::ReleaseAgeExceptionArtefactMismatch,
                });
            }
        }
    }

    candidates.sort_by(|(left, _, _), (right, _, _)| left.cmp(right));
    let Some((_, selected, release_age)) = candidates.pop() else {
        return Err(PickError::NoMatchingVersion { excluded });
    };

    Ok(PickSelection {
        selected,
        release_age,
        excluded,
    })
}

#[cfg(test)]
mod tests {
    use time::OffsetDateTime;

    use crate::{
        PickError, PickExclusionReason, ReleaseAgeOutcome, Sha256Digest, VersionInfo,
        parse_pick_spec, pick_version,
    };

    fn version(num: &str, published_at: &str, yanked: bool) -> VersionInfo {
        VersionInfo {
            num: num.to_owned(),
            checksum_sha256_hex: Sha256Digest::try_from(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            )
            .expect("checksum should parse"),
            published_at_raw: published_at.to_owned(),
            published_at: OffsetDateTime::parse(
                published_at,
                &time::format_description::well_known::Rfc3339,
            )
            .expect("timestamp should parse"),
            yanked,
        }
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_590_969_600).expect("timestamp should parse")
    }

    #[test]
    fn parses_pick_specs_with_optional_range() {
        let spec = parse_pick_spec("serde").expect("spec should parse");
        assert_eq!(spec.crate_name(), "serde");
        assert_eq!(spec.requirement(), "*");

        let spec = parse_pick_spec("serde@^1.0").expect("spec should parse");
        assert_eq!(spec.crate_name(), "serde");
        assert_eq!(spec.requirement(), "^1.0");
    }

    #[test]
    fn rejects_invalid_pick_specs() {
        assert!(parse_pick_spec("").is_err());
        assert!(parse_pick_spec("-serde").is_err());
        assert!(parse_pick_spec("bad/name@1").is_err());
        assert!(parse_pick_spec("serde@").is_err());
        assert!(parse_pick_spec("serde@not a range").is_err());
    }

    #[test]
    fn picks_newest_matching_non_yanked_non_prerelease_old_enough_version() {
        let versions = vec![
            version("2.0.0", "2020-05-01T00:00:00Z", false),
            version("1.5.0", "2020-05-01T00:00:00Z", false),
            version("1.6.0-alpha.1", "2020-05-01T00:00:00Z", false),
            version("1.4.0", "2020-05-01T00:00:00Z", true),
            version("1.7.0", "2020-05-30T00:00:00Z", false),
        ];

        let selection =
            pick_version("serde", "^1", &versions, 7, now(), &[]).expect("version should select");

        assert_eq!(selection.selected().to_string(), "serde@1.5.0");
        assert_eq!(selection.excluded().len(), 4);
        assert!(
            selection
                .excluded()
                .iter()
                .any(|excluded| excluded.version() == "2.0.0"
                    && excluded.reason() == &PickExclusionReason::DoesNotMatchRequirement)
        );
        assert!(
            selection
                .excluded()
                .iter()
                .any(|excluded| excluded.version() == "1.6.0-alpha.1"
                    && excluded.reason() == &PickExclusionReason::PreRelease)
        );
        assert!(
            selection
                .excluded()
                .iter()
                .any(|excluded| excluded.version() == "1.4.0"
                    && excluded.reason() == &PickExclusionReason::Yanked)
        );
        assert!(
            selection
                .excluded()
                .iter()
                .any(|excluded| excluded.version() == "1.7.0"
                    && excluded.reason() == &PickExclusionReason::TooFresh)
        );
    }

    #[test]
    fn reports_no_matching_version_when_policy_excludes_every_candidate() {
        let versions = vec![version("1.0.0", "2020-05-30T00:00:00Z", false)];
        let error = pick_version("serde", "^1", &versions, 7, now(), &[])
            .expect_err("selection should fail");

        assert!(matches!(error, PickError::NoMatchingVersion { .. }));
        assert_eq!(error.excluded()[0].reason(), &PickExclusionReason::TooFresh);
    }

    #[test]
    fn review_exception_can_allow_too_fresh_selection() {
        let versions = vec![version("1.0.0", "2020-05-30T00:00:00Z", false)];
        let policy = r#"
[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/serde.md"

[rust.families.resolved]
serde = { version = "1.0.0", checksum_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }

[rust.families.allowed_age_exceptions]
serde = "1.0.0"
"#;
        let reviewed_targets =
            crate::parse_reviewed_targets_toml(policy).expect("policy should parse");
        let exception = reviewed_targets.release_age_exceptions();

        let selection = pick_version("serde", "^1", &versions, 7, now(), &exception)
            .expect("exception should allow selection");

        assert_eq!(selection.selected().to_string(), "serde@1.0.0");
        assert!(matches!(
            selection.release_age().outcome(),
            ReleaseAgeOutcome::AllowedByException { .. }
        ));
    }
}
