use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Component;

use serde::Deserialize;
use thiserror::Error;
use time::{Date, Month};

use crate::{
    ExactCrateSpec, ExactVersionRequirementError, Sha256Digest, parse_exact_version_requirement,
};

const RUSTSEC_ID_LEN: usize = 17;
const ISO_DATE_LEN: usize = 10;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReviewedTargets {
    rust_families: Vec<ReviewedRustFamily>,
}

impl ReviewedTargets {
    pub fn rust_families(&self) -> &[ReviewedRustFamily] {
        &self.rust_families
    }

    pub fn execution_surface_allowances(&self) -> Vec<ReviewedExecutionSurfaceAllowance> {
        self.rust_families
            .iter()
            .flat_map(ReviewedRustFamily::execution_surface_allowances)
            .collect()
    }

    pub fn release_age_exceptions(&self) -> Vec<ReviewedReleaseAgeException> {
        self.rust_families
            .iter()
            .flat_map(ReviewedRustFamily::release_age_exceptions)
            .collect()
    }

    /// Returns raw configured advisory exceptions with no resolved-target,
    /// review-record, or expiry binding applied.
    ///
    /// Callers must enforce resolved-target match, review-record success, and
    /// `review_by` expiry before using these exceptions to suppress findings.
    pub fn advisory_exceptions(&self) -> Vec<ReviewedAdvisoryException> {
        self.rust_families
            .iter()
            .flat_map(ReviewedRustFamily::advisory_exceptions)
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewedRustFamily {
    name: String,
    review_record: String,
    direct: BTreeMap<String, String>,
    resolved: BTreeMap<String, ReviewedResolvedTarget>,
    allowed_surfaces: BTreeMap<String, BTreeSet<ExecutionSurfaceKind>>,
    allowed_age_exceptions: BTreeMap<String, String>,
    allowed_advisories: BTreeMap<String, Vec<ReviewedAdvisory>>,
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

    pub fn allowed_surfaces(&self) -> &BTreeMap<String, BTreeSet<ExecutionSurfaceKind>> {
        &self.allowed_surfaces
    }

    pub fn allowed_age_exceptions(&self) -> &BTreeMap<String, String> {
        &self.allowed_age_exceptions
    }

    pub fn allowed_advisories(&self) -> &BTreeMap<String, Vec<ReviewedAdvisory>> {
        &self.allowed_advisories
    }

    pub(crate) fn execution_surface_allowances(&self) -> Vec<ReviewedExecutionSurfaceAllowance> {
        self.allowed_surfaces
            .iter()
            .flat_map(|(crate_name, surfaces)| {
                let target = self
                    .resolved
                    .get(crate_name)
                    .expect("parse_reviewed_targets_toml validates allowance targets");
                surfaces
                    .iter()
                    .map(|surface| ReviewedExecutionSurfaceAllowance {
                        spec: ExactCrateSpec::from_parts(crate_name, target.version())
                            .expect("parse_reviewed_targets_toml validates exact specs"),
                        surface: *surface,
                        family: self.name.clone(),
                        review_record: self.review_record.clone(),
                    })
            })
            .collect()
    }

    fn release_age_exceptions(&self) -> Vec<ReviewedReleaseAgeException> {
        self.allowed_age_exceptions
            .iter()
            .map(|(crate_name, version)| {
                let target = self
                    .resolved
                    .get(crate_name)
                    .expect("parse_reviewed_targets_toml validates age exception targets");
                ReviewedReleaseAgeException {
                    spec: ExactCrateSpec::from_parts(crate_name, version)
                        .expect("parse_reviewed_targets_toml validates exact specs"),
                    checksum_sha256: target
                        .checksum_sha256()
                        .expect("parse_reviewed_targets_toml validates age exception checksums")
                        .clone(),
                    family: self.name.clone(),
                    review_record: self.review_record.clone(),
                }
            })
            .collect()
    }

    /// Returns raw configured advisory exceptions with no resolved-target,
    /// review-record, or expiry binding applied.
    ///
    /// Callers must enforce resolved-target match, review-record success, and
    /// `review_by` expiry before using these exceptions to suppress findings.
    pub fn advisory_exceptions(&self) -> Vec<ReviewedAdvisoryException> {
        self.allowed_advisories
            .iter()
            .flat_map(|(crate_name, advisories)| {
                let target = self
                    .resolved
                    .get(crate_name)
                    .expect("parse_reviewed_targets_toml validates advisory targets");
                advisories.iter().map(|advisory| ReviewedAdvisoryException {
                    advisory_id: advisory.id.clone(),
                    spec: ExactCrateSpec::from_parts(crate_name, target.version())
                        .expect("parse_reviewed_targets_toml validates exact specs"),
                    checksum_sha256: target
                        .checksum_sha256()
                        .expect("parse_reviewed_targets_toml validates advisory checksums")
                        .clone(),
                    review_by: advisory.review_by,
                    family: self.name.clone(),
                    review_record: self.review_record.clone(),
                })
            })
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExecutionSurfaceKind {
    BuildRs,
    ProcMacro,
    NativeSys,
}

impl ExecutionSurfaceKind {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "build-rs" => Some(Self::BuildRs),
            "proc-macro" => Some(Self::ProcMacro),
            "native-sys" => Some(Self::NativeSys),
            _ => None,
        }
    }
}

impl fmt::Display for ExecutionSurfaceKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BuildRs => write!(formatter, "build-rs"),
            Self::ProcMacro => write!(formatter, "proc-macro"),
            Self::NativeSys => write!(formatter, "native-sys"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReviewedExecutionSurfaceAllowance {
    spec: ExactCrateSpec,
    surface: ExecutionSurfaceKind,
    family: String,
    review_record: String,
}

impl ReviewedExecutionSurfaceAllowance {
    pub fn spec(&self) -> &ExactCrateSpec {
        &self.spec
    }

    pub fn surface(&self) -> ExecutionSurfaceKind {
        self.surface
    }

    pub fn family(&self) -> &str {
        &self.family
    }

    pub fn review_record(&self) -> &str {
        &self.review_record
    }
}

impl fmt::Display for ReviewedExecutionSurfaceAllowance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} {} allowed by reviewed family {} ({})",
            self.spec, self.surface, self.family, self.review_record
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReviewedReleaseAgeException {
    spec: ExactCrateSpec,
    checksum_sha256: Sha256Digest,
    family: String,
    review_record: String,
}

impl ReviewedReleaseAgeException {
    pub fn spec(&self) -> &ExactCrateSpec {
        &self.spec
    }

    pub fn checksum_sha256(&self) -> &Sha256Digest {
        &self.checksum_sha256
    }

    pub fn family(&self) -> &str {
        &self.family
    }

    pub fn review_record(&self) -> &str {
        &self.review_record
    }
}

impl fmt::Display for ReviewedReleaseAgeException {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} release age allowed by reviewed family {} ({})",
            self.spec, self.family, self.review_record
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RustSecAdvisoryId(String);

impl RustSecAdvisoryId {
    pub fn parse(value: &str) -> Result<Self, RustSecAdvisoryIdError> {
        let bytes = value.as_bytes();
        let valid = bytes.len() == RUSTSEC_ID_LEN
            && &bytes[0..8] == b"RUSTSEC-"
            && bytes[8..12].iter().all(u8::is_ascii_digit)
            && bytes[12] == b'-'
            && bytes[13..17].iter().all(u8::is_ascii_digit);

        if valid {
            Ok(Self(value.to_owned()))
        } else {
            Err(RustSecAdvisoryIdError)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RustSecAdvisoryId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("expected RustSec advisory ID in RUSTSEC-YYYY-NNNN form")]
pub struct RustSecAdvisoryIdError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewedAdvisory {
    id: RustSecAdvisoryId,
    review_by: Date,
}

impl ReviewedAdvisory {
    pub fn id(&self) -> &RustSecAdvisoryId {
        &self.id
    }

    pub fn review_by(&self) -> Date {
        self.review_by
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReviewedAdvisoryException {
    advisory_id: RustSecAdvisoryId,
    spec: ExactCrateSpec,
    checksum_sha256: Sha256Digest,
    review_by: Date,
    family: String,
    review_record: String,
}

impl ReviewedAdvisoryException {
    pub fn advisory_id(&self) -> &RustSecAdvisoryId {
        &self.advisory_id
    }

    pub fn spec(&self) -> &ExactCrateSpec {
        &self.spec
    }

    pub fn checksum_sha256(&self) -> &Sha256Digest {
        &self.checksum_sha256
    }

    pub fn review_by(&self) -> Date {
        self.review_by
    }

    pub fn family(&self) -> &str {
        &self.family
    }

    pub fn review_record(&self) -> &str {
        &self.review_record
    }
}

impl fmt::Display for ReviewedAdvisoryException {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} {} accepted by reviewed family {} ({}), review by {}",
            self.spec, self.advisory_id, self.family, self.review_record, self.review_by
        )
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
            Some(expected_checksum) => {
                observed.checksums_sha256.len() == 1
                    && observed.checksums_sha256.contains(expected_checksum)
            }
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
    let mut family_names = BTreeSet::new();
    let mut advisory_bindings: BTreeMap<(RustSecAdvisoryId, ExactCrateSpec), String> =
        BTreeMap::new();

    for family in raw.rust.families {
        if reviewed_target_string_is_blank_or_control(&family.name) {
            return Err(ReviewedTargetsError::InvalidFamilyName {
                family: family.name,
            });
        }

        if reviewed_target_string_is_blank_or_control(&family.review_record) {
            return Err(ReviewedTargetsError::InvalidReviewRecord {
                family: family.name,
                review_record: family.review_record,
            });
        }

        if !family_names.insert(family.name.clone()) {
            return Err(ReviewedTargetsError::DuplicateFamilyName {
                family: family.name,
            });
        }

        if review_record_path_is_unsafe(&family.review_record) {
            return Err(ReviewedTargetsError::UnsafeReviewRecordPath {
                family: family.name,
                review_record: family.review_record,
            });
        }

        if family.resolved.is_empty() {
            return Err(ReviewedTargetsError::EmptyResolvedSet {
                family: family.name,
            });
        }

        for (crate_name, requirement) in &family.direct {
            match parse_exact_version_requirement(crate_name, requirement) {
                Ok(_) => {}
                Err(ExactVersionRequirementError::MissingEquals) => {
                    return Err(ReviewedTargetsError::DirectRequirementNotExact {
                        family: family.name.clone(),
                        crate_name: crate_name.clone(),
                        requirement: requirement.clone(),
                    });
                }
                Err(ExactVersionRequirementError::InvalidVersion(source)) => {
                    return Err(ReviewedTargetsError::InvalidDirectRequirement {
                        family: family.name.clone(),
                        crate_name: crate_name.clone(),
                        requirement: requirement.clone(),
                        source,
                    });
                }
            }
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

        let mut allowed_surfaces = BTreeMap::new();
        for (crate_name, raw_surfaces) in family.allowed_surfaces {
            if !resolved.contains_key(&crate_name) {
                return Err(ReviewedTargetsError::AllowedSurfaceTargetMissing {
                    family: family.name.clone(),
                    crate_name,
                });
            }
            if raw_surfaces.is_empty() {
                return Err(ReviewedTargetsError::EmptyAllowedSurfaces {
                    family: family.name.clone(),
                    crate_name,
                });
            }

            let mut surfaces = BTreeSet::new();
            for raw_surface in raw_surfaces {
                let surface = ExecutionSurfaceKind::parse(&raw_surface).ok_or_else(|| {
                    ReviewedTargetsError::InvalidAllowedSurface {
                        family: family.name.clone(),
                        crate_name: crate_name.clone(),
                        surface: raw_surface,
                    }
                })?;
                surfaces.insert(surface);
            }

            allowed_surfaces.insert(crate_name, surfaces);
        }

        let mut allowed_age_exceptions = BTreeMap::new();
        for (crate_name, version) in family.allowed_age_exceptions {
            let Some(target) = resolved.get(&crate_name) else {
                return Err(ReviewedTargetsError::AllowedAgeExceptionTargetMissing {
                    family: family.name.clone(),
                    crate_name,
                });
            };
            if target.checksum_sha256().is_none() {
                return Err(ReviewedTargetsError::AllowedAgeExceptionChecksumMissing {
                    family: family.name.clone(),
                    crate_name,
                });
            }
            if target.version() != version {
                return Err(ReviewedTargetsError::AllowedAgeExceptionVersionMismatch {
                    family: family.name.clone(),
                    crate_name,
                    exception_version: version,
                    resolved_version: target.version().to_owned(),
                });
            }

            allowed_age_exceptions.insert(crate_name, version);
        }

        let mut allowed_advisories = BTreeMap::new();
        for (crate_name, raw_advisories) in family.allowed_advisories {
            let Some(target) = resolved.get(&crate_name) else {
                return Err(ReviewedTargetsError::AllowedAdvisoryTargetMissing {
                    family: family.name.clone(),
                    crate_name,
                });
            };
            if raw_advisories.is_empty() {
                return Err(ReviewedTargetsError::EmptyAllowedAdvisories {
                    family: family.name.clone(),
                    crate_name,
                });
            }
            if target.checksum_sha256().is_none() {
                return Err(ReviewedTargetsError::AllowedAdvisoryChecksumMissing {
                    family: family.name.clone(),
                    crate_name,
                });
            }

            let mut advisories = Vec::with_capacity(raw_advisories.len());
            let mut advisory_ids = BTreeSet::new();
            for raw_advisory in raw_advisories {
                let id = RustSecAdvisoryId::parse(&raw_advisory.id).map_err(|source| {
                    ReviewedTargetsError::InvalidAllowedAdvisoryId {
                        family: family.name.clone(),
                        crate_name: crate_name.clone(),
                        advisory_id: raw_advisory.id.clone(),
                        source,
                    }
                })?;
                if !advisory_ids.insert(id.clone()) {
                    return Err(ReviewedTargetsError::DuplicateAllowedAdvisory {
                        family: family.name.clone(),
                        crate_name: crate_name.clone(),
                        advisory_id: id,
                    });
                }
                let spec = ExactCrateSpec::from_parts(&crate_name, target.version())
                    .expect("parse_reviewed_targets_toml validates exact specs");
                if let Some(existing_family) =
                    advisory_bindings.insert((id.clone(), spec.clone()), family.name.clone())
                {
                    return Err(ReviewedTargetsError::DuplicateAllowedAdvisoryBinding {
                        advisory_id: id,
                        spec,
                        first_family: existing_family,
                        second_family: family.name.clone(),
                    });
                }
                let review_by = parse_iso_date(&raw_advisory.review_by).map_err(|source| {
                    ReviewedTargetsError::InvalidAllowedAdvisoryReviewBy {
                        family: family.name.clone(),
                        crate_name: crate_name.clone(),
                        advisory_id: raw_advisory.id.clone(),
                        review_by: raw_advisory.review_by.clone(),
                        source,
                    }
                })?;

                advisories.push(ReviewedAdvisory { id, review_by });
            }

            allowed_advisories.insert(crate_name, advisories);
        }

        rust_families.push(ReviewedRustFamily {
            name: family.name,
            review_record: family.review_record,
            direct: family.direct,
            resolved,
            allowed_surfaces,
            allowed_age_exceptions,
            allowed_advisories,
        });
    }

    Ok(ReviewedTargets { rust_families })
}

fn parse_iso_date(value: &str) -> Result<Date, IsoDateError> {
    let bytes = value.as_bytes();
    if bytes.len() != ISO_DATE_LEN
        || !bytes[0..4].iter().all(u8::is_ascii_digit)
        || bytes[4] != b'-'
        || !bytes[5..7].iter().all(u8::is_ascii_digit)
        || bytes[7] != b'-'
        || !bytes[8..10].iter().all(u8::is_ascii_digit)
    {
        return Err(IsoDateError);
    }

    let year = value[0..4].parse::<i32>().map_err(|_| IsoDateError)?;
    let month_number = value[5..7].parse::<u8>().map_err(|_| IsoDateError)?;
    let day = value[8..10].parse::<u8>().map_err(|_| IsoDateError)?;
    let month = Month::try_from(month_number).map_err(|_| IsoDateError)?;

    Date::from_calendar_date(year, month, day).map_err(|_| IsoDateError)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("expected ISO date in YYYY-MM-DD form")]
pub struct IsoDateError;

fn review_record_path_is_unsafe(path: &str) -> bool {
    std::path::Path::new(path)
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::RootDir))
}

fn reviewed_target_string_is_blank_or_control(value: &str) -> bool {
    value.trim().is_empty() || value.chars().any(is_terminal_control_char)
}

fn is_terminal_control_char(character: char) -> bool {
    matches!(
        character,
        '\u{0000}'..='\u{001f}'
            | '\u{007f}'
            | '\u{0080}'..='\u{009f}'
            | '\u{061c}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200d}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'
            | '\u{2066}'..='\u{2069}'
            | '\u{fff9}'..='\u{fffb}'
            | '\u{feff}'
    )
}

#[derive(Debug, Error)]
pub enum ReviewedTargetsError {
    #[error("unable to parse reviewed-targets.toml: {0}")]
    Parse(#[source] toml::de::Error),
    #[error("reviewed family name must not be empty or contain control characters: {family:?}")]
    InvalidFamilyName { family: String },
    #[error(
        "family {family:?} review_record must not be empty or contain control characters: {review_record:?}"
    )]
    InvalidReviewRecord {
        family: String,
        review_record: String,
    },
    #[error("family {family:?} has no resolved Cargo.lock targets")]
    EmptyResolvedSet { family: String },
    #[error("reviewed family names must be unique: {family:?}")]
    DuplicateFamilyName { family: String },
    #[error(
        "family {family:?} direct requirement for {crate_name:?} must be exact and include a leading '=': {requirement:?}"
    )]
    DirectRequirementNotExact {
        family: String,
        crate_name: String,
        requirement: String,
    },
    #[error(
        "family {family:?} direct requirement for {crate_name:?} is not a valid exact version {requirement:?}: {source}"
    )]
    InvalidDirectRequirement {
        family: String,
        crate_name: String,
        requirement: String,
        #[source]
        source: crate::ExactCrateSpecError,
    },
    #[error(
        "family {family:?} resolved Cargo.lock version for {crate_name:?} is not exact {version:?}: {source}"
    )]
    InvalidResolvedVersion {
        family: String,
        crate_name: String,
        version: String,
        #[source]
        source: crate::ExactCrateSpecError,
    },
    #[error(
        "family {family:?} resolved checksum for {crate_name:?} is not a valid SHA-256 digest: {checksum:?}"
    )]
    InvalidResolvedChecksum {
        family: String,
        crate_name: String,
        checksum: String,
    },
    #[error(
        "family {family:?} review_record path must be relative and stay inside the repo: {review_record:?}"
    )]
    UnsafeReviewRecordPath {
        family: String,
        review_record: String,
    },
    #[error("family {family:?} allowed_surfaces entry for {crate_name:?} is empty")]
    EmptyAllowedSurfaces { family: String, crate_name: String },
    #[error(
        "family {family:?} allowed_surfaces entry for {crate_name:?} references a crate absent from the same resolved map"
    )]
    AllowedSurfaceTargetMissing { family: String, crate_name: String },
    #[error(
        "family {family:?} allowed_surfaces entry for {crate_name:?} has unknown surface {surface:?}"
    )]
    InvalidAllowedSurface {
        family: String,
        crate_name: String,
        surface: String,
    },
    #[error(
        "family {family:?} allowed_age_exceptions entry for {crate_name:?} references a crate absent from the same resolved map"
    )]
    AllowedAgeExceptionTargetMissing { family: String, crate_name: String },
    #[error(
        "family {family:?} allowed_age_exceptions entry for {crate_name:?} requires the resolved target to carry checksum_sha256"
    )]
    AllowedAgeExceptionChecksumMissing { family: String, crate_name: String },
    #[error(
        "family {family:?} allowed_age_exceptions entry for {crate_name:?} version {exception_version:?} does not match resolved version {resolved_version:?}"
    )]
    AllowedAgeExceptionVersionMismatch {
        family: String,
        crate_name: String,
        exception_version: String,
        resolved_version: String,
    },
    #[error("family {family:?} allowed_advisories entry for {crate_name:?} is empty")]
    EmptyAllowedAdvisories { family: String, crate_name: String },
    #[error(
        "family {family:?} allowed_advisories entry for {crate_name:?} contains duplicate advisory {advisory_id}"
    )]
    DuplicateAllowedAdvisory {
        family: String,
        crate_name: String,
        advisory_id: RustSecAdvisoryId,
    },
    #[error(
        "allowed_advisories binding for {spec} {advisory_id} must be owned by one reviewed family; found {first_family:?} and {second_family:?}"
    )]
    DuplicateAllowedAdvisoryBinding {
        advisory_id: RustSecAdvisoryId,
        spec: ExactCrateSpec,
        first_family: String,
        second_family: String,
    },
    #[error(
        "family {family:?} allowed_advisories entry for {crate_name:?} references a crate absent from the same resolved map"
    )]
    AllowedAdvisoryTargetMissing { family: String, crate_name: String },
    #[error(
        "family {family:?} allowed_advisories entry for {crate_name:?} requires the resolved target to carry checksum_sha256"
    )]
    AllowedAdvisoryChecksumMissing { family: String, crate_name: String },
    #[error(
        "family {family:?} allowed_advisories entry for {crate_name:?} has invalid advisory id {advisory_id:?}: {source}"
    )]
    InvalidAllowedAdvisoryId {
        family: String,
        crate_name: String,
        advisory_id: String,
        #[source]
        source: RustSecAdvisoryIdError,
    },
    #[error(
        "family {family:?} allowed_advisories entry for {crate_name:?} advisory {advisory_id:?} has invalid review_by date {review_by:?}: {source}"
    )]
    InvalidAllowedAdvisoryReviewBy {
        family: String,
        crate_name: String,
        advisory_id: String,
        review_by: String,
        #[source]
        source: IsoDateError,
    },
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawReviewedTargets {
    #[serde(default)]
    rust: RawRustReviewedTargets,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawRustReviewedTargets {
    #[serde(default)]
    families: Vec<RawReviewedRustFamily>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawReviewedRustFamily {
    name: String,
    review_record: String,
    #[serde(default)]
    direct: BTreeMap<String, String>,
    #[serde(default)]
    resolved: BTreeMap<String, RawReviewedResolvedTarget>,
    #[serde(default)]
    allowed_surfaces: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    allowed_age_exceptions: BTreeMap<String, String>,
    #[serde(default)]
    allowed_advisories: BTreeMap<String, Vec<RawReviewedAdvisory>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawReviewedAdvisory {
    id: String,
    review_by: String,
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
    use super::{ExecutionSurfaceKind, ReviewedTargetsError, parse_reviewed_targets_toml};
    use crate::Sha256Digest;
    use time::{Date, Month};

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

[rust.families.allowed_surfaces]
serde = ["build-rs", "proc-macro", "build-rs"]

[rust.families.allowed_age_exceptions]
serde = "1.0.228"

[rust.families.allowed_advisories]
serde = [
  { id = "RUSTSEC-2026-0001", review_by = "2026-09-21" },
]
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
        assert_eq!(
            family
                .allowed_surfaces()
                .get("serde")
                .expect("allowance should parse")
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            vec![
                ExecutionSurfaceKind::BuildRs,
                ExecutionSurfaceKind::ProcMacro
            ]
        );
        let allowances = targets.execution_surface_allowances();
        assert_eq!(allowances.len(), 2);
        assert_eq!(allowances[0].spec().to_string(), "serde@1.0.228");
        assert_eq!(allowances[0].family(), "serde-family");
        assert_eq!(
            allowances[0].review_record(),
            "docs/dependency-reviews/2026-05-27-serde.md"
        );
        let age_exceptions = targets.release_age_exceptions();
        assert_eq!(age_exceptions.len(), 1);
        assert_eq!(age_exceptions[0].spec().to_string(), "serde@1.0.228");
        assert_eq!(
            age_exceptions[0].checksum_sha256().as_str(),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        assert_eq!(age_exceptions[0].family(), "serde-family");
        assert_eq!(
            age_exceptions[0].review_record(),
            "docs/dependency-reviews/2026-05-27-serde.md"
        );
        let advisories = family
            .allowed_advisories()
            .get("serde")
            .expect("advisory exception should parse");
        assert_eq!(advisories.len(), 1);
        assert_eq!(advisories[0].id().as_str(), "RUSTSEC-2026-0001");
        assert_eq!(
            advisories[0].review_by(),
            Date::from_calendar_date(2026, Month::September, 21)
                .expect("test date should be valid")
        );
        let advisory_exceptions = targets.advisory_exceptions();
        assert_eq!(advisory_exceptions.len(), 1);
        assert_eq!(
            advisory_exceptions[0].advisory_id().as_str(),
            "RUSTSEC-2026-0001"
        );
        assert_eq!(advisory_exceptions[0].spec().to_string(), "serde@1.0.228");
        assert_eq!(
            advisory_exceptions[0].checksum_sha256().as_str(),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        assert_eq!(
            advisory_exceptions[0].review_by(),
            Date::from_calendar_date(2026, Month::September, 21)
                .expect("test date should be valid")
        );
        assert_eq!(advisory_exceptions[0].family(), "serde-family");
        assert_eq!(
            advisory_exceptions[0].review_record(),
            "docs/dependency-reviews/2026-05-27-serde.md"
        );
        assert_eq!(
            advisory_exceptions[0].to_string(),
            "serde@1.0.228 RUSTSEC-2026-0001 accepted by reviewed family serde-family (docs/dependency-reviews/2026-05-27-serde.md), review by 2026-09-21"
        );
    }

    #[test]
    fn execution_surface_kind_strings_round_trip() {
        for kind in [
            ExecutionSurfaceKind::BuildRs,
            ExecutionSurfaceKind::ProcMacro,
            ExecutionSurfaceKind::NativeSys,
        ] {
            assert_eq!(
                ExecutionSurfaceKind::parse(&kind.to_string()).expect("kind should parse"),
                kind
            );
        }
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
    fn rejects_invalid_exact_direct_requirements() {
        let error = parse_reviewed_targets_toml(
            r#"
[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.direct]
serde = "=^1.0.228"

[rust.families.resolved]
serde = "1.0.228"
"#,
        )
        .expect_err("invalid exact direct requirement should fail");

        assert!(matches!(
            error,
            ReviewedTargetsError::InvalidDirectRequirement { .. }
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
    fn rejects_duplicate_family_names() {
        let error = parse_reviewed_targets_toml(
            r#"
[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/serde-a.md"

[rust.families.resolved]
serde = "1.0.228"

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/serde-b.md"

[rust.families.resolved]
serde_json = "1.0.145"
"#,
        )
        .expect_err("duplicate family names should fail");

        assert!(matches!(
            error,
            ReviewedTargetsError::DuplicateFamilyName { family } if family == "serde-family"
        ));
    }

    #[test]
    fn rejects_review_record_paths_outside_the_repo() {
        for review_record in [
            "../docs/dependency-reviews/native.md",
            "/tmp/native.md",
            "docs/../native.md",
        ] {
            let error = parse_reviewed_targets_toml(&format!(
                r#"
[rust]

[[rust.families]]
name = "native-family"
review_record = "{review_record}"

[rust.families.resolved]
native-sys = "1.2.3"
"#
            ))
            .expect_err("unsafe review record path should fail");

            assert!(matches!(
                error,
                ReviewedTargetsError::UnsafeReviewRecordPath { .. }
            ));
        }
    }

    #[test]
    fn allows_printable_family_and_review_record_strings() {
        let targets = parse_reviewed_targets_toml(
            r#"
[rust]

[[rust.families]]
name = "ffi family 2026-06-21"
review_record = "docs/dependency-reviews/ffi family 2026-06-21.md"

[rust.families.resolved]
native-sys = "1.2.3"
"#,
        )
        .expect("printable family and review record strings should parse");

        let family = &targets.rust_families()[0];
        assert_eq!(family.name(), "ffi family 2026-06-21");
        assert_eq!(
            family.review_record(),
            "docs/dependency-reviews/ffi family 2026-06-21.md"
        );
    }

    #[test]
    fn rejects_blank_family_names_and_review_records() {
        let family_error = parse_reviewed_targets_toml(
            r#"
[rust]

[[rust.families]]
name = "   "
review_record = "docs/dependency-reviews/native.md"

[rust.families.resolved]
native-sys = "1.2.3"
"#,
        )
        .expect_err("blank family names should fail");

        assert!(matches!(
            family_error,
            ReviewedTargetsError::InvalidFamilyName { .. }
        ));

        let review_record_error = parse_reviewed_targets_toml(
            r#"
[rust]

[[rust.families]]
name = "native-family"
review_record = "   "

[rust.families.resolved]
native-sys = "1.2.3"
"#,
        )
        .expect_err("blank review records should fail");

        assert!(matches!(
            review_record_error,
            ReviewedTargetsError::InvalidReviewRecord { .. }
        ));
    }

    #[test]
    fn rejects_control_characters_in_family_names_and_review_records() {
        for character in [
            "\\u0000", "\\n", "\\u001f", "\\u007f", "\\u0080", "\\u009f", "\\u200b", "\\u2028",
            "\\u2029", "\\u202e", "\\u200f", "\\u2060",
        ] {
            let family_error = parse_reviewed_targets_toml(&format!(
                r#"
[rust]

[[rust.families]]
name = "native{character}family"
review_record = "docs/dependency-reviews/native.md"

[rust.families.resolved]
native-sys = "1.2.3"
"#
            ))
            .expect_err("control characters in family names should fail");

            assert!(matches!(
                family_error,
                ReviewedTargetsError::InvalidFamilyName { .. }
            ));

            let review_record_error = parse_reviewed_targets_toml(&format!(
                r#"
[rust]

[[rust.families]]
name = "native-family"
review_record = "docs/dependency-reviews/native{character}.md"

[rust.families.resolved]
native-sys = "1.2.3"
"#
            ))
            .expect_err("control characters in review records should fail");

            assert!(matches!(
                review_record_error,
                ReviewedTargetsError::InvalidReviewRecord { .. }
            ));
        }
    }

    #[test]
    fn reviewed_target_errors_escape_toml_sourced_fields() {
        let error = parse_reviewed_targets_toml(
            r#"
[rust]

[[rust.families]]
name = "native-family"
review_record = "docs/dependency-reviews/native.md"

[rust.families.resolved]
native-sys = "1.2.3"

[rust.families.allowed_surfaces]
"native-sys" = ["\u001b]0;pwned\u0007"]
"#,
        )
        .expect_err("invalid surface should fail");
        let message = error.to_string();
        assert!(!message.contains('\u{001b}'));
        assert!(!message.contains('\u{0007}'));
        assert!(message.contains("\\u{1b}]0;pwned\\u{7}"), "{message}");

        let error = parse_reviewed_targets_toml(
            r#"
[rust]

[[rust.families]]
name = "native-family"
review_record = "docs/dependency-reviews/native.md"

[rust.families.resolved]
"native\u001b-sys" = "1.2.3"
"#,
        )
        .expect_err("invalid crate name should fail");
        let message = error.to_string();
        assert!(!message.contains('\u{001b}'));
        assert!(message.contains("native\\u{1b}-sys"), "{message}");

        let error = parse_reviewed_targets_toml(
            r#"
[rust]

[[rust.families]]
name = "native-family"
review_record = "docs/dependency-reviews/native.md"

[rust.families.direct]
serde = "=\u001b1.0.228"

[rust.families.resolved]
serde = "1.0.228"
"#,
        )
        .expect_err("invalid exact requirement should fail");
        let message = error.to_string();
        assert!(!message.contains('\u{001b}'));
        assert!(message.contains("=\\u{1b}1.0.228"), "{message}");

        let error = parse_reviewed_targets_toml(
            r#"
[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/serde.md"

[rust.families.resolved]
serde = { version = "1.0.228", checksum_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }

[rust.families.allowed_advisories]
serde = [
  { id = "RUSTSEC-2026-\u001b001", review_by = "2026-09-21" },
]
"#,
        )
        .expect_err("invalid advisory id should fail");
        let message = error.to_string();
        assert!(!message.contains('\u{001b}'));
        assert!(message.contains("RUSTSEC-2026-\\u{1b}001"), "{message}");
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

    #[test]
    fn rejects_unknown_allowed_surface_identifiers() {
        let error = parse_reviewed_targets_toml(
            r#"
[rust]

[[rust.families]]
name = "native-family"
review_record = "docs/dependency-reviews/2026-05-27-native.md"

[rust.families.resolved]
native-sys = "1.2.3"

[rust.families.allowed_surfaces]
native-sys = ["ffi"]
"#,
        )
        .expect_err("unknown allowed surface should fail");

        assert!(matches!(
            error,
            ReviewedTargetsError::InvalidAllowedSurface { .. }
        ));
    }

    #[test]
    fn rejects_empty_allowed_surface_lists() {
        let error = parse_reviewed_targets_toml(
            r#"
[rust]

[[rust.families]]
name = "native-family"
review_record = "docs/dependency-reviews/2026-05-27-native.md"

[rust.families.resolved]
native-sys = "1.2.3"

[rust.families.allowed_surfaces]
native-sys = []
"#,
        )
        .expect_err("empty allowed surface list should fail");

        assert!(matches!(
            error,
            ReviewedTargetsError::EmptyAllowedSurfaces { .. }
        ));
    }

    #[test]
    fn rejects_allowed_surface_targets_absent_from_resolved_map() {
        let error = parse_reviewed_targets_toml(
            r#"
[rust]

[[rust.families]]
name = "native-family"
review_record = "docs/dependency-reviews/2026-05-27-native.md"

[rust.families.resolved]
other = "1.2.3"

[rust.families.allowed_surfaces]
native-sys = ["native-sys"]
"#,
        )
        .expect_err("allowance target outside resolved map should fail");

        assert!(matches!(
            error,
            ReviewedTargetsError::AllowedSurfaceTargetMissing { .. }
        ));
    }

    #[test]
    fn rejects_allowed_age_exception_targets_absent_from_resolved_map() {
        let error = parse_reviewed_targets_toml(
            r#"
[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.resolved]
serde = { version = "1.0.228", checksum_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }

[rust.families.allowed_age_exceptions]
other = "1.0.0"
"#,
        )
        .expect_err("age exception target outside resolved map should fail");

        assert!(matches!(
            error,
            ReviewedTargetsError::AllowedAgeExceptionTargetMissing { .. }
        ));
    }

    #[test]
    fn rejects_allowed_age_exception_targets_without_resolved_checksums() {
        let error = parse_reviewed_targets_toml(
            r#"
[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.resolved]
serde = "1.0.228"

[rust.families.allowed_age_exceptions]
serde = "1.0.228"
"#,
        )
        .expect_err("age exception target without checksum should fail");

        assert!(matches!(
            error,
            ReviewedTargetsError::AllowedAgeExceptionChecksumMissing { .. }
        ));
    }

    #[test]
    fn rejects_allowed_age_exception_version_mismatches() {
        let error = parse_reviewed_targets_toml(
            r#"
[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.resolved]
serde = { version = "1.0.228", checksum_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }

[rust.families.allowed_age_exceptions]
serde = "1.0.227"
"#,
        )
        .expect_err("age exception version mismatch should fail");

        assert!(matches!(
            error,
            ReviewedTargetsError::AllowedAgeExceptionVersionMismatch { .. }
        ));
    }

    #[test]
    fn allows_transitive_age_exception_targets_in_resolved_map() {
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
serde_derive = { version = "1.0.228", checksum_sha256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789" }

[rust.families.allowed_age_exceptions]
serde_derive = "1.0.228"
"#,
        )
        .expect("transitive age exception target should parse");

        let exceptions = targets.release_age_exceptions();
        assert_eq!(exceptions.len(), 1);
        assert_eq!(exceptions[0].spec().to_string(), "serde_derive@1.0.228");
    }

    #[test]
    fn rejects_empty_allowed_advisory_lists() {
        let error = parse_reviewed_targets_toml(
            r#"
[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.resolved]
serde = { version = "1.0.228", checksum_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }

[rust.families.allowed_advisories]
serde = []
"#,
        )
        .expect_err("empty advisory list should fail");

        assert!(matches!(
            error,
            ReviewedTargetsError::EmptyAllowedAdvisories { .. }
        ));
    }

    #[test]
    fn rejects_allowed_advisory_targets_absent_from_resolved_map() {
        let error = parse_reviewed_targets_toml(
            r#"
[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.resolved]
serde = { version = "1.0.228", checksum_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }

[rust.families.allowed_advisories]
other = [
  { id = "RUSTSEC-2026-0001", review_by = "2026-09-21" },
]
"#,
        )
        .expect_err("advisory target outside resolved map should fail");

        assert!(matches!(
            error,
            ReviewedTargetsError::AllowedAdvisoryTargetMissing { .. }
        ));
    }

    #[test]
    fn rejects_allowed_advisory_targets_without_resolved_checksums() {
        let error = parse_reviewed_targets_toml(
            r#"
[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.resolved]
serde = "1.0.228"

[rust.families.allowed_advisories]
serde = [
  { id = "RUSTSEC-2026-0001", review_by = "2026-09-21" },
]
"#,
        )
        .expect_err("advisory target without checksum should fail");

        assert!(matches!(
            error,
            ReviewedTargetsError::AllowedAdvisoryChecksumMissing { .. }
        ));
    }

    #[test]
    fn rejects_invalid_rustsec_advisory_ids() {
        for advisory_id in [
            "RUSTSEC-2026-001",
            "RUSTSEC-26-0001",
            "CVE-2026-0001",
            "RUSTSEC-2026-ABCD",
        ] {
            let error = parse_reviewed_targets_toml(&format!(
                r#"
[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.resolved]
serde = {{ version = "1.0.228", checksum_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }}

[rust.families.allowed_advisories]
serde = [
  {{ id = "{advisory_id}", review_by = "2026-09-21" }},
]
"#
            ))
            .expect_err("invalid RustSec advisory ID should fail");

            assert!(matches!(
                error,
                ReviewedTargetsError::InvalidAllowedAdvisoryId { .. }
            ));
        }
    }

    #[test]
    fn rejects_duplicate_allowed_advisories_for_the_same_crate() {
        let error = parse_reviewed_targets_toml(
            r#"
[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.resolved]
serde = { version = "1.0.228", checksum_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }

[rust.families.allowed_advisories]
serde = [
  { id = "RUSTSEC-2026-0001", review_by = "2026-09-21" },
  { id = "RUSTSEC-2026-0001", review_by = "2027-01-01" },
]
"#,
        )
        .expect_err("duplicate advisory IDs for one crate should fail");

        assert!(matches!(
            error,
            ReviewedTargetsError::DuplicateAllowedAdvisory {
                family,
                crate_name,
                advisory_id,
            } if family == "serde-family"
                && crate_name == "serde"
                && advisory_id.as_str() == "RUSTSEC-2026-0001"
        ));
    }

    #[test]
    fn allows_same_advisory_for_different_resolved_crates() {
        let targets = parse_reviewed_targets_toml(
            r#"
[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.resolved]
serde = { version = "1.0.228", checksum_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }
serde_derive = { version = "1.0.228", checksum_sha256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789" }

[rust.families.allowed_advisories]
serde = [
  { id = "RUSTSEC-2026-0001", review_by = "2026-09-21" },
]
serde_derive = [
  { id = "RUSTSEC-2026-0001", review_by = "2026-09-21" },
]
"#,
        )
        .expect("same advisory may affect multiple crates");

        assert_eq!(targets.advisory_exceptions().len(), 2);
    }

    #[test]
    fn rejects_invalid_advisory_review_by_dates() {
        for review_by in ["2026-02-30", "2026-2-03", "20260203", "not-a-date"] {
            let error = parse_reviewed_targets_toml(&format!(
                r#"
[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.resolved]
serde = {{ version = "1.0.228", checksum_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }}

[rust.families.allowed_advisories]
serde = [
  {{ id = "RUSTSEC-2026-0001", review_by = "{review_by}" }},
]
"#
            ))
            .expect_err("invalid review_by date should fail");

            assert!(matches!(
                error,
                ReviewedTargetsError::InvalidAllowedAdvisoryReviewBy { .. }
            ));
        }
    }

    #[test]
    fn rejects_advisory_entries_missing_required_fields() {
        for entry in [
            r#"{ review_by = "2026-09-21" }"#,
            r#"{ id = "RUSTSEC-2026-0001" }"#,
            r#"{ id = "RUSTSEC-2026-0001", review_by = "2026-09-21", note = "extra" }"#,
        ] {
            let error = parse_reviewed_targets_toml(&format!(
                r#"
[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.resolved]
serde = {{ version = "1.0.228", checksum_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }}

[rust.families.allowed_advisories]
serde = [
  {entry},
]
"#
            ))
            .expect_err("missing or unknown advisory fields should fail");

            assert!(matches!(error, ReviewedTargetsError::Parse(_)));
        }
    }

    #[test]
    fn rejects_unknown_reviewed_target_fields() {
        let error = parse_reviewed_targets_toml(
            r#"
[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"
allowed_advisory = "typo"

[rust.families.resolved]
serde = { version = "1.0.228", checksum_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }
"#,
        )
        .expect_err("unknown reviewed-target fields should fail");

        assert!(matches!(error, ReviewedTargetsError::Parse(_)));
    }

    #[test]
    fn allows_transitive_advisory_targets_in_resolved_map() {
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
serde_derive = { version = "1.0.228", checksum_sha256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789" }

[rust.families.allowed_advisories]
serde_derive = [
  { id = "RUSTSEC-2026-0001", review_by = "2026-09-21" },
]
"#,
        )
        .expect("transitive advisory target should parse");

        let exceptions = targets.advisory_exceptions();
        assert_eq!(exceptions.len(), 1);
        assert_eq!(exceptions[0].spec().to_string(), "serde_derive@1.0.228");
        assert_eq!(exceptions[0].advisory_id().as_str(), "RUSTSEC-2026-0001");
    }
}
