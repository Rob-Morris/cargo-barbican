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
pub mod inventory;
pub mod lockfile;
pub mod manifest;
pub mod metadata;
pub mod pin_check;
pub mod release_age;
pub mod reviewed_targets;
pub mod sha256;
pub mod spec;

pub use assessment::{
    InspectionFailure, LockedChecksumDrift, NonCratesIoSourceChange,
    ReleaseAgeExceptionArtefactMismatch, ReleaseAgeViolation, RustAssessmentClassification,
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
pub use inventory::{
    Inventory, InventoryDeclaredSurface, InventoryDirectDependency, InventoryDirectRequirements,
    InventoryGap, InventoryNonCratesIoSource, InventoryResolvedCrate, InventoryReviewedFamily,
    InventoryRollup, ReviewRecordFact, WorkspacePackageIdentity, build_inventory,
};
pub use lockfile::{
    CRATES_IO_SOURCE, LockedChecksumChange, LockedPackage, Lockfile, LockfileError,
    added_crates_io_specs, changed_crates_io_checksums, parse_lockfile,
};
pub use manifest::{
    CargoDependencySourceKind, CargoManifestDependency, CargoManifestDirectRequirement,
    CargoManifestError, CargoManifestPackage, parse_manifest_dependencies,
    parse_manifest_direct_requirements, parse_manifest_package_identity,
    parse_workspace_dependency_requirements, parse_workspace_member_glob_roots,
    parse_workspace_member_manifest_paths, parse_workspace_package_version,
};
pub use metadata::{
    CargoMetadata, CargoMetadataError, MetadataPackageSurfaces, package_surfaces,
    parse_cargo_metadata, select_package_id,
};
pub use pin_check::{
    ObservedDirectDependency, ReviewedDirectDependencyCheck, ReviewedResolvedDependencyCheck,
    RustReviewedFamilyReport, RustReviewedTargetsReport, check_reviewed_rust_targets,
};
pub use release_age::{
    ReleaseAgeOutcome, ReleaseAgeReport, check_release_age, check_release_age_at,
    evaluate_release_age, format_age,
};
pub use reviewed_targets::{
    ExecutionSurfaceKind, ReviewedExecutionSurfaceAllowance, ReviewedReleaseAgeException,
    ReviewedResolvedTarget, ReviewedRustFamily, ReviewedTargets, ReviewedTargetsError,
    parse_reviewed_targets_toml,
};
pub use sha256::{Sha256Digest, Sha256DigestError};
pub use spec::{
    ExactCrateSpec, ExactCrateSpecError, ExactVersionRequirementError,
    parse_exact_version_requirement,
};
pub use time::OffsetDateTime;
