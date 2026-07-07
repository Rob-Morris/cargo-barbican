//! Library for Rust supply-chain hardening.
//!
//! Provides primitives the `cargo-barbican` binary composes into subcommands:
//! crates.io release-age checks, `Cargo.lock` diffing, policy assessment.
//!
//! See `docs/architecture/overview.md` in the repo root for the design brief.
pub mod advisory;
pub mod assessment;
pub mod cargo_config;
pub mod config;
pub mod crates_io;
pub mod deny_config;
pub mod inspect;
pub mod inventory;
pub mod lockfile;
pub mod manifest;
pub mod metadata;
pub mod pick;
pub mod pin_check;
pub mod release_age;
pub mod reviewed_targets;
pub mod scaffold;
pub mod sha256;
pub mod spec;

pub use advisory::{
    AdvisoryAuditCompletenessFailure, AdvisoryAuditOutcome, AdvisoryDisposition, AdvisoryFinding,
    AdvisoryFindingDetails, AdvisoryFindingId, AdvisoryParseError, AdvisoryReconciliationReport,
    CargoAuditAdvisoryReport, CargoDenyAdvisoryReport, CargoDenyNoAdvisoryDiagnostic,
    CargoDenySummaryCount, evaluate_advisory_audit, parse_cargo_audit_json,
    parse_cargo_deny_json_lines, reconcile_advisory_findings,
};
pub use assessment::{
    InspectionFailure, LockedChecksumDrift, NonCratesIoSourceChange,
    ReleaseAgeExceptionArtefactMismatch, ReleaseAgeViolation, RustAssessmentClassification,
    RustAssessmentFinding, RustAssessmentFindingCategory, RustAssessmentFindingSeverity,
    RustAssessmentReport, assess_rust_update_at,
};
pub use cargo_config::{CargoConfigError, cargo_config_source_override_key};
pub use config::{
    AdvisoryDelegatesConfig, BarbicanConfig, CargoDenyCheck, CargoDenyDelegatesConfig,
    ConfigLoadError, DelegatesConfig, HighScrutinyConfig, LockfileAdvisoryScanner,
    MAXIMUM_RELEASE_AGE_MINIMUM_DAYS, ReleaseAgeConfig, UnmanagedDelegatedPolicyMode,
};
pub use crates_io::{
    CrateRelease, CratesIoClient, CratesIoClientError, VersionInfo, parse_version_response_body,
    parse_versions_response_body,
};
pub use deny_config::{
    CargoDenyRuntimeConfigError, advisory_ignores_from_toml, generate_cargo_deny_runtime_config,
};
pub use inspect::{CrateVcsInfo, IocHit, RustInspectReport, inspect_published_crate_at};
pub use inventory::{
    GraphSurfaces, INVENTORY_ADVISORY_SOON_TO_EXPIRE_DAYS, Inventory, InventoryAdvisoryException,
    InventoryAdvisoryExceptionStatus, InventoryDeclaredSurface, InventoryDirectDependency,
    InventoryDirectRequirements, InventoryGap, InventoryLiveSurface, InventoryNonCratesIoSource,
    InventoryResolvedCrate, InventoryReviewedFamily, InventoryRollup, ReviewRecordFact,
    WorkspacePackageIdentity, build_graph_surfaces, build_inventory,
};
pub use lockfile::{
    CRATES_IO_SOURCE, LockedChecksumChange, LockedPackage, Lockfile, LockfileError,
    added_crates_io_specs, changed_crates_io_checksums, parse_lockfile,
};
pub use manifest::{
    CargoDependencySourceKind, CargoManifestDependency, CargoManifestDirectRequirement,
    CargoManifestError, CargoManifestPackage, parse_manifest_dependencies,
    parse_manifest_direct_requirements, parse_manifest_package_identity,
    parse_manifest_patched_crate_names, parse_workspace_dependency_requirements,
    parse_workspace_member_glob_roots, parse_workspace_member_manifest_paths,
    parse_workspace_package_version,
};
pub use metadata::{
    CargoMetadata, CargoMetadataError, MetadataDependencyPath, MetadataPackageSurfaces,
    package_surfaces, parse_cargo_metadata, select_package_id, shortest_workspace_dependency_path,
};
pub use pick::{
    PickError, PickExcludedVersion, PickExclusionReason, PickSelection, PickSpec, PickSpecError,
    parse_pick_spec, pick_version,
};
pub use pin_check::{
    ObservedDirectDependency, PatchedReviewedCrate, ReviewedAdvisoryExceptionBinding,
    ReviewedDirectDependencyCheck, ReviewedResolvedDependencyCheck, RustReviewedFamilyReport,
    RustReviewedTargetsReport, check_reviewed_rust_targets, patched_reviewed_crates,
};
pub use release_age::{
    ReleaseAgeGateVerdict, ReleaseAgeOutcome, ReleaseAgeReport, check_release_age_at,
    classify_release_age_gate, evaluate_release_age, format_age,
};
pub use reviewed_targets::{
    ExecutionSurfaceKind, IsoDateError, ReviewedAdvisoryException,
    ReviewedExecutionSurfaceAllowance, ReviewedReleaseAgeException, ReviewedResolvedTarget,
    ReviewedRustFamily, ReviewedTargets, ReviewedTargetsError, RustSecAdvisoryId,
    RustSecAdvisoryIdError, format_iso_date, parse_reviewed_targets_toml,
};
pub use scaffold::{
    PinAddPlan, PinAddRejection, PinAddTarget, PinAddTargetError, compose_pin_family_stub,
    compose_pin_review_record, parse_pin_add_target, pin_family_name, pin_review_record_path,
    plan_pin_add,
};
pub use sha256::{Sha256Digest, Sha256DigestError};
pub use spec::{
    ExactCrateSpec, ExactCrateSpecError, ExactVersionRequirementError,
    is_native_sys_execution_surface, parse_exact_version_requirement,
};
pub use time::{Date, OffsetDateTime};
