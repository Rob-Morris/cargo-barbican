//! Library for Rust supply-chain hardening.
//!
//! Provides primitives the `cargo-barbican` binary composes into subcommands:
//! crates.io release-age checks, `Cargo.lock` diffing, policy assessment.
//!
//! See `docs/architecture/overview.md` in the repo root for the design brief.
pub mod assessment;
pub mod config;
pub mod crates_io;
pub mod inspect;
pub mod lockfile;
pub mod manifest;
pub mod metadata;
pub mod release_age;
pub mod spec;

pub use assessment::{
    InspectionFailure, NonCratesIoSourceChange, ReleaseAgeViolation, RustAssessmentClassification,
    RustAssessmentFinding, RustAssessmentFindingCategory, RustAssessmentFindingSeverity,
    RustAssessmentReport, assess_rust_update, assess_rust_update_at,
};
pub use config::{
    BarbicanConfig, ConfigLoadError, DelegatesConfig, HighScrutinyConfig,
    MAXIMUM_RELEASE_AGE_MINIMUM_DAYS, ReleaseAgeConfig,
};
pub use crates_io::{
    CrateRelease, CratesIoClient, CratesIoClientError, parse_version_response_body,
};
pub use inspect::{
    CrateVcsInfo, IocHit, RustInspectReport, inspect_published_crate, inspect_published_crate_at,
};
pub use lockfile::{
    CRATES_IO_SOURCE, LockedPackage, Lockfile, LockfileError, added_crates_io_specs, parse_lockfile,
};
pub use manifest::{
    CargoDependencySourceKind, CargoManifestDependency, CargoManifestError,
    parse_manifest_dependencies,
};
pub use metadata::{
    CargoMetadata, CargoMetadataError, MetadataPackageSurfaces, package_surfaces,
    parse_cargo_metadata, select_package_id,
};
pub use release_age::{
    ReleaseAgeOutcome, ReleaseAgeReport, check_release_age, check_release_age_at,
    evaluate_release_age, format_age,
};
pub use spec::{ExactCrateSpec, ExactCrateSpecError};
