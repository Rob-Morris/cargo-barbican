use std::collections::{BTreeMap, BTreeSet};

use crate::metadata::metadata_packages;
use crate::{
    CargoDependencySourceKind, CargoManifestDirectRequirement, ExactCrateSpec,
    ExecutionSurfaceKind, Lockfile, MetadataPackageSurfaces, RustReviewedTargetsReport,
    Sha256Digest, parse_exact_version_requirement,
};
use time::{Duration, OffsetDateTime};

pub const INVENTORY_ADVISORY_SOON_TO_EXPIRE_DAYS: i64 = 30;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inventory {
    policy_configured: bool,
    direct_dependencies: Vec<InventoryDirectDependency>,
    resolved_crates_io: Vec<InventoryResolvedCrate>,
    non_crates_io_sources: Vec<InventoryNonCratesIoSource>,
    reviewed_families: Vec<InventoryReviewedFamily>,
    advisory_exceptions: Vec<InventoryAdvisoryException>,
    declared_surfaces: Vec<InventoryDeclaredSurface>,
    live_surfaces: Option<Vec<InventoryLiveSurface>>,
    gaps: Vec<InventoryGap>,
}

impl Inventory {
    pub fn policy_configured(&self) -> bool {
        self.policy_configured
    }

    pub fn direct_dependencies(&self) -> &[InventoryDirectDependency] {
        &self.direct_dependencies
    }

    pub fn resolved_crates_io(&self) -> &[InventoryResolvedCrate] {
        &self.resolved_crates_io
    }

    pub fn non_crates_io_sources(&self) -> &[InventoryNonCratesIoSource] {
        &self.non_crates_io_sources
    }

    pub fn reviewed_families(&self) -> &[InventoryReviewedFamily] {
        &self.reviewed_families
    }

    pub fn advisory_exceptions(&self) -> &[InventoryAdvisoryException] {
        &self.advisory_exceptions
    }

    pub fn declared_surfaces(&self) -> &[InventoryDeclaredSurface] {
        &self.declared_surfaces
    }

    pub fn live_surfaces(&self) -> Option<&[InventoryLiveSurface]> {
        self.live_surfaces.as_deref()
    }

    pub fn gaps(&self) -> &[InventoryGap] {
        &self.gaps
    }

    pub fn observational_findings(&self) -> Vec<&InventoryGap> {
        self.gaps
            .iter()
            .filter(|gap| !gap.is_policy_relative())
            .collect()
    }

    pub fn policy_coverage_gaps(&self) -> Vec<&InventoryGap> {
        self.gaps
            .iter()
            .filter(|gap| gap.is_policy_relative())
            .collect()
    }

    pub fn rollup(&self) -> InventoryRollup {
        InventoryRollup {
            direct_dependencies: self.direct_dependencies.len(),
            resolved_crates_io: self.resolved_crates_io.len(),
            non_crates_io_sources: self.non_crates_io_sources.len(),
            reviewed_families: self.reviewed_families.len(),
            declared_surfaces: self.declared_surfaces.len(),
            observational_findings: self
                .gaps
                .iter()
                .filter(|gap| !gap.is_policy_relative())
                .count(),
            policy_coverage_gaps: self
                .gaps
                .iter()
                .filter(|gap| gap.is_policy_relative())
                .count(),
            gaps: self.gaps.len(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InventoryRollup {
    pub direct_dependencies: usize,
    pub resolved_crates_io: usize,
    pub non_crates_io_sources: usize,
    pub reviewed_families: usize,
    pub declared_surfaces: usize,
    pub observational_findings: usize,
    pub policy_coverage_gaps: usize,
    pub gaps: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryDirectDependency {
    manifest_path: String,
    section: String,
    name: String,
    source_kind: CargoDependencySourceKind,
    effective_source_kind: CargoDependencySourceKind,
    version_requirement: Option<String>,
    inherited: bool,
    exact_pinned: bool,
}

impl InventoryDirectDependency {
    pub fn manifest_path(&self) -> &str {
        &self.manifest_path
    }

    pub fn section(&self) -> &str {
        &self.section
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn source_kind(&self) -> CargoDependencySourceKind {
        self.source_kind
    }

    pub fn effective_source_kind(&self) -> CargoDependencySourceKind {
        self.effective_source_kind
    }

    pub fn version_requirement(&self) -> Option<&str> {
        self.version_requirement.as_deref()
    }

    pub fn inherited(&self) -> bool {
        self.inherited
    }

    pub fn exact_pinned(&self) -> bool {
        self.exact_pinned
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryResolvedCrate {
    spec: ExactCrateSpec,
    checksum: Option<Sha256Digest>,
}

impl InventoryResolvedCrate {
    pub fn spec(&self) -> &ExactCrateSpec {
        &self.spec
    }

    pub fn checksum(&self) -> Option<&Sha256Digest> {
        self.checksum.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryNonCratesIoSource {
    name: String,
    version: String,
    source: Option<String>,
}

impl InventoryNonCratesIoSource {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn source(&self) -> Option<&str> {
        self.source.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryReviewedFamily {
    name: String,
    review_record: String,
    review_record_exists: bool,
    direct_count: usize,
    resolved_count: usize,
}

impl InventoryReviewedFamily {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn review_record(&self) -> &str {
        &self.review_record
    }

    pub fn review_record_exists(&self) -> bool {
        self.review_record_exists
    }

    pub fn direct_count(&self) -> usize {
        self.direct_count
    }

    pub fn resolved_count(&self) -> usize {
        self.resolved_count
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InventoryAdvisoryExceptionStatus {
    Active,
    SoonToExpire,
    Expired,
    Stale,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryAdvisoryException {
    advisory_id: String,
    spec: ExactCrateSpec,
    family: String,
    review_record: String,
    review_by: time::Date,
    status: InventoryAdvisoryExceptionStatus,
    resolved_target_matches: bool,
    review_record_exists: bool,
}

impl InventoryAdvisoryException {
    pub fn advisory_id(&self) -> &str {
        &self.advisory_id
    }

    pub fn spec(&self) -> &ExactCrateSpec {
        &self.spec
    }

    pub fn family(&self) -> &str {
        &self.family
    }

    pub fn review_record(&self) -> &str {
        &self.review_record
    }

    pub fn review_by(&self) -> time::Date {
        self.review_by
    }

    pub fn status(&self) -> InventoryAdvisoryExceptionStatus {
        self.status
    }

    pub fn resolved_target_matches(&self) -> bool {
        self.resolved_target_matches
    }

    pub fn review_record_exists(&self) -> bool {
        self.review_record_exists
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryDeclaredSurface {
    family: String,
    spec: ExactCrateSpec,
    surface: ExecutionSurfaceKind,
}

impl InventoryDeclaredSurface {
    pub fn family(&self) -> &str {
        &self.family
    }

    pub fn spec(&self) -> &ExactCrateSpec {
        &self.spec
    }

    pub fn surface(&self) -> ExecutionSurfaceKind {
        self.surface
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryLiveSurface {
    spec: ExactCrateSpec,
    surface: ExecutionSurfaceKind,
    declared: bool,
}

impl InventoryLiveSurface {
    pub fn spec(&self) -> &ExactCrateSpec {
        &self.spec
    }

    pub fn surface(&self) -> ExecutionSurfaceKind {
        self.surface
    }

    pub fn declared(&self) -> bool {
        self.declared
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InventoryGap {
    MissingReviewRecord {
        family: String,
        review_record: String,
    },
    UncoveredResolvedCrate {
        spec: ExactCrateSpec,
    },
    NonExactDirectPin {
        manifest_path: String,
        section: String,
        name: String,
        requirement: Option<String>,
        inherited: bool,
    },
    NonCratesIoSource {
        name: String,
        version: String,
        source: Option<String>,
    },
    UndeclaredExecutionSurface {
        spec: ExactCrateSpec,
        surface: ExecutionSurfaceKind,
        policy_configured: bool,
    },
}

impl InventoryGap {
    pub fn is_policy_relative(&self) -> bool {
        match self {
            Self::MissingReviewRecord { .. } | Self::UncoveredResolvedCrate { .. } => true,
            Self::UndeclaredExecutionSurface {
                policy_configured, ..
            } => *policy_configured,
            Self::NonExactDirectPin { .. } | Self::NonCratesIoSource { .. } => false,
        }
    }
}

impl InventoryNonCratesIoSource {
    fn as_gap(&self) -> InventoryGap {
        InventoryGap::NonCratesIoSource {
            name: self.name.clone(),
            version: self.version.clone(),
            source: self.source.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewRecordFact {
    family_name: String,
    review_record: String,
    exists: bool,
}

impl ReviewRecordFact {
    pub fn new(family_name: String, review_record: String, exists: bool) -> Self {
        Self {
            family_name,
            review_record,
            exists,
        }
    }

    pub fn family_name(&self) -> &str {
        &self.family_name
    }

    pub fn review_record(&self) -> &str {
        &self.review_record
    }

    pub fn exists(&self) -> bool {
        self.exists
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphSurfaces {
    surfaces: BTreeMap<ExactCrateSpec, MetadataPackageSurfaces>,
}

impl GraphSurfaces {
    pub fn surfaces(&self) -> impl Iterator<Item = (&ExactCrateSpec, &MetadataPackageSurfaces)> {
        self.surfaces.iter()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct InventoryDirectRequirements<'a> {
    manifest: &'a [CargoManifestDirectRequirement],
    workspace: &'a [CargoManifestDirectRequirement],
}

impl<'a> InventoryDirectRequirements<'a> {
    pub fn new(
        manifest: &'a [CargoManifestDirectRequirement],
        workspace: &'a [CargoManifestDirectRequirement],
    ) -> Self {
        Self {
            manifest,
            workspace,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct WorkspacePackageIdentity {
    name: String,
    version: String,
}

impl WorkspacePackageIdentity {
    pub fn new(name: String, version: String) -> Self {
        Self { name, version }
    }
}

pub fn build_inventory(
    lockfile: &Lockfile,
    direct_requirements: InventoryDirectRequirements<'_>,
    workspace_packages: &BTreeSet<WorkspacePackageIdentity>,
    reviewed_report: Option<&RustReviewedTargetsReport>,
    review_record_facts: &[ReviewRecordFact],
    now: OffsetDateTime,
    surfaces: Option<&GraphSurfaces>,
) -> Inventory {
    let workspace_requirements_by_name = direct_requirements
        .workspace
        .iter()
        .map(|dependency| (dependency.name(), dependency))
        .collect::<BTreeMap<_, _>>();
    let review_facts_by_family = review_record_facts
        .iter()
        .map(|fact| (fact.family_name(), fact))
        .collect::<BTreeMap<_, _>>();

    let mut gaps = Vec::new();
    let mut direct_dependencies = Vec::new();
    for dependency in direct_requirements.manifest {
        let inherited_dependency =
            if dependency.source_kind() == CargoDependencySourceKind::Workspace {
                workspace_requirements_by_name
                    .get(dependency.name())
                    .copied()
            } else {
                None
            };
        let effective_requirement = inherited_dependency
            .and_then(|root_dependency| root_dependency.version_requirement())
            .or_else(|| dependency.version_requirement())
            .map(str::to_owned);
        let effective_source_kind = inherited_dependency
            .map(|root_dependency| root_dependency.source_kind())
            .unwrap_or_else(|| dependency.source_kind());
        let exact_pinned = effective_requirement.as_deref().is_some_and(|requirement| {
            parse_exact_version_requirement(dependency.name(), requirement).is_ok()
        });
        let inherited = inherited_dependency.is_some();

        if effective_source_kind.requires_exact_pin() && !exact_pinned {
            gaps.push(InventoryGap::NonExactDirectPin {
                manifest_path: dependency.manifest_path().to_owned(),
                section: dependency.section().to_owned(),
                name: dependency.name().to_owned(),
                requirement: effective_requirement.clone(),
                inherited,
            });
        }

        direct_dependencies.push(InventoryDirectDependency {
            manifest_path: dependency.manifest_path().to_owned(),
            section: dependency.section().to_owned(),
            name: dependency.name().to_owned(),
            source_kind: dependency.source_kind(),
            effective_source_kind,
            version_requirement: effective_requirement,
            inherited,
            exact_pinned,
        });
    }
    direct_dependencies.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.manifest_path.cmp(&right.manifest_path))
            .then_with(|| left.section.cmp(&right.section))
    });

    let mut covered_specs = BTreeSet::new();
    let mut reviewed_families = Vec::new();
    let mut declared_surfaces = Vec::new();
    let mut declared_surface_keys = BTreeSet::new();

    let mut advisory_exceptions = Vec::new();

    if let Some(reviewed_report) = reviewed_report {
        for family in reviewed_report.families() {
            let record_fact = review_facts_by_family.get(family.name()).copied();
            let review_record_exists = record_fact.is_some_and(ReviewRecordFact::exists);
            if !review_record_exists {
                gaps.push(InventoryGap::MissingReviewRecord {
                    family: family.name().to_owned(),
                    review_record: family.review_record().to_owned(),
                });
            }

            for check in family.resolved_checks() {
                covered_specs.insert(
                    ExactCrateSpec::from_parts(
                        check.crate_name(),
                        check.expected_target().version(),
                    )
                    .expect("parse_reviewed_targets_toml validates exact specs"),
                );
            }
            reviewed_families.push(InventoryReviewedFamily {
                name: family.name().to_owned(),
                review_record: family.review_record().to_owned(),
                review_record_exists,
                direct_count: family.direct_checks().len(),
                resolved_count: family.resolved_checks().len(),
            });

            advisory_exceptions.extend(family.advisory_exception_bindings().into_iter().map(
                |binding| {
                    let exception = binding.exception();
                    InventoryAdvisoryException {
                        advisory_id: exception.advisory_id().to_string(),
                        spec: exception.spec().clone(),
                        family: exception.family().to_owned(),
                        review_record: exception.review_record().to_owned(),
                        review_by: exception.review_by(),
                        status: advisory_exception_status(
                            binding.resolved_target_present(),
                            exception.review_by(),
                            now,
                        ),
                        resolved_target_matches: binding.resolved_target_matches(),
                        review_record_exists,
                    }
                },
            ));
        }
        declared_surfaces.extend(
            reviewed_report
                .execution_surface_allowances()
                .into_iter()
                .map(|allowance| InventoryDeclaredSurface {
                    family: allowance.family().to_owned(),
                    spec: allowance.spec().clone(),
                    surface: allowance.surface(),
                }),
        );
    }
    for surface in &declared_surfaces {
        declared_surface_keys.insert((surface.spec.clone(), surface.surface));
    }

    let mut resolved_crates_io = Vec::new();
    let mut non_crates_io_sources = Vec::new();
    for package in lockfile.packages() {
        if package.is_crates_io() {
            let resolved = InventoryResolvedCrate {
                spec: package.exact_spec().clone(),
                checksum: package.checksum().cloned(),
            };
            if reviewed_report.is_some() && !covered_specs.contains(resolved.spec()) {
                gaps.push(InventoryGap::UncoveredResolvedCrate {
                    spec: resolved.spec().clone(),
                });
            }
            resolved_crates_io.push(resolved);
        } else {
            let is_known_workspace_member = package.source.is_none()
                && workspace_packages.contains(&WorkspacePackageIdentity::new(
                    package.name.clone(),
                    package.version.clone(),
                ));
            if is_known_workspace_member {
                continue;
            }

            let entry = non_crates_io_source_from_package(package);
            gaps.push(entry.as_gap());
            non_crates_io_sources.push(entry);
        }
    }
    resolved_crates_io.sort_by(|left, right| left.spec.cmp(&right.spec));
    non_crates_io_sources.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.version.cmp(&right.version))
    });
    declared_surfaces.sort_by(|left, right| {
        left.spec
            .cmp(&right.spec)
            .then_with(|| left.surface.cmp(&right.surface))
            .then_with(|| left.family.cmp(&right.family))
    });
    let live_surfaces = surfaces.map(|surfaces| {
        let mut live_surfaces = Vec::new();
        for (spec, package_surfaces) in surfaces.surfaces() {
            let mut surface_kinds = package_surfaces.surface_kinds();
            if spec.is_native_sys() && !surface_kinds.contains(&ExecutionSurfaceKind::NativeSys) {
                surface_kinds.push(ExecutionSurfaceKind::NativeSys);
            }
            for surface in surface_kinds {
                let declared = declared_surface_keys.contains(&(spec.clone(), surface));
                if !declared {
                    gaps.push(InventoryGap::UndeclaredExecutionSurface {
                        spec: spec.clone(),
                        surface,
                        policy_configured: reviewed_report.is_some(),
                    });
                }
                live_surfaces.push(InventoryLiveSurface {
                    spec: spec.clone(),
                    surface,
                    declared,
                });
            }
        }
        live_surfaces.sort_by(|left, right| {
            left.spec
                .cmp(&right.spec)
                .then_with(|| left.surface.cmp(&right.surface))
        });
        live_surfaces
    });

    Inventory {
        policy_configured: reviewed_report.is_some(),
        direct_dependencies,
        resolved_crates_io,
        non_crates_io_sources,
        reviewed_families,
        advisory_exceptions,
        declared_surfaces,
        live_surfaces,
        gaps,
    }
}

fn advisory_exception_status(
    resolved_target_present: bool,
    review_by: time::Date,
    now: OffsetDateTime,
) -> InventoryAdvisoryExceptionStatus {
    if !resolved_target_present {
        return InventoryAdvisoryExceptionStatus::Stale;
    }

    let today = now.date();
    if review_by < today {
        InventoryAdvisoryExceptionStatus::Expired
    } else if review_by <= today + Duration::days(INVENTORY_ADVISORY_SOON_TO_EXPIRE_DAYS) {
        InventoryAdvisoryExceptionStatus::SoonToExpire
    } else {
        InventoryAdvisoryExceptionStatus::Active
    }
}

pub fn build_graph_surfaces(
    metadata: &crate::CargoMetadata,
) -> Result<GraphSurfaces, crate::ExactCrateSpecError> {
    let mut surfaces = BTreeMap::new();
    for package in metadata_packages(metadata) {
        if package.is_workspace_member {
            continue;
        }

        let spec = ExactCrateSpec::from_parts(package.name, package.version)?;
        surfaces
            .entry(spec)
            .and_modify(|existing: &mut MetadataPackageSurfaces| {
                existing.union_with(&package.surfaces);
            })
            .or_insert(package.surfaces);
    }

    Ok(GraphSurfaces { surfaces })
}

fn non_crates_io_source_from_package(package: &crate::LockedPackage) -> InventoryNonCratesIoSource {
    InventoryNonCratesIoSource {
        name: package.name.clone(),
        version: package.version.clone(),
        source: package.source.clone(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use crate::{
        InventoryAdvisoryExceptionStatus, InventoryDirectRequirements, InventoryGap,
        ReviewRecordFact, WorkspacePackageIdentity, build_graph_surfaces, build_inventory,
        check_reviewed_rust_targets, parse_cargo_metadata, parse_lockfile,
        parse_manifest_direct_requirements, parse_reviewed_targets_toml,
    };
    use time::OffsetDateTime;

    fn inventory_now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_820_908_800).expect("fixed timestamp is valid")
    }

    #[test]
    fn builds_inventory_with_policy_gaps_and_rollups() {
        let lockfile = parse_lockfile(
            r#"
[[package]]
name = "covered"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

[[package]]
name = "uncovered"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "1111111111111111111111111111111111111111111111111111111111111111"

[[package]]
name = "git-crate"
version = "0.1.0"
source = "git+https://example.invalid/repo"
"#,
        )
        .expect("lockfile should parse");
        let requirements = parse_manifest_direct_requirements(
            "Cargo.toml",
            r#"
[dependencies]
covered = "=1.0.0"
uncovered = "2"
git-crate = { git = "https://example.invalid/repo", version = "=0.1.0" }
"#,
        )
        .expect("manifest should parse")
        .into_iter()
        .collect::<Vec<_>>();
        let reviewed_targets = parse_reviewed_targets_toml(
            r#"
[rust]

[[rust.families]]
name = "covered-family"
review_record = "docs/dependency-reviews/covered.md"

[rust.families.direct]
covered = "=1.0.0"

[rust.families.resolved]
covered = { version = "1.0.0", checksum_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }
"#,
        )
        .expect("reviewed targets should parse");
        let reviewed_report =
            check_reviewed_rust_targets(&reviewed_targets, &requirements, &lockfile);

        let inventory = build_inventory(
            &lockfile,
            InventoryDirectRequirements::new(&requirements, &[]),
            &BTreeSet::new(),
            Some(&reviewed_report),
            &[ReviewRecordFact::new(
                "covered-family".to_owned(),
                "docs/dependency-reviews/covered.md".to_owned(),
                false,
            )],
            inventory_now(),
            None,
        );

        assert_eq!(inventory.rollup().direct_dependencies, 3);
        assert_eq!(inventory.rollup().resolved_crates_io, 2);
        assert_eq!(inventory.rollup().non_crates_io_sources, 1);
        assert_eq!(inventory.rollup().observational_findings, 2);
        assert_eq!(inventory.rollup().policy_coverage_gaps, 2);
        assert_eq!(inventory.rollup().gaps, 4);
        assert!(inventory.gaps().iter().any(|gap| {
            matches!(gap, InventoryGap::MissingReviewRecord { family, .. } if family == "covered-family")
        }));
        assert!(inventory.gaps().iter().any(|gap| {
            matches!(gap, InventoryGap::UncoveredResolvedCrate { spec } if spec.to_string() == "uncovered@2.0.0")
        }));
        assert!(inventory.gaps().iter().any(|gap| {
            matches!(gap, InventoryGap::NonExactDirectPin { name, .. } if name == "uncovered")
        }));
        assert!(inventory.gaps().iter().any(|gap| {
            matches!(gap, InventoryGap::NonCratesIoSource { name, .. } if name == "git-crate")
        }));
        assert_eq!(
            inventory
                .gaps()
                .iter()
                .filter(|gap| {
                    matches!(gap, InventoryGap::NonCratesIoSource { name, .. } if name == "git-crate")
                })
                .count(),
            1
        );
    }

    #[test]
    fn inherited_workspace_dependencies_use_root_requirements() {
        let lockfile = parse_lockfile(
            r#"
[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
"#,
        )
        .expect("lockfile should parse");
        let member_requirements = parse_manifest_direct_requirements(
            "crates/app/Cargo.toml",
            r#"
[dependencies]
serde = { workspace = true }
"#,
        )
        .expect("manifest should parse")
        .into_iter()
        .collect::<Vec<_>>();
        let workspace_requirements = parse_manifest_direct_requirements(
            "Cargo.toml",
            r#"
[dependencies]
serde = "=1.0.228"
"#,
        )
        .expect("manifest should parse")
        .into_iter()
        .collect::<Vec<_>>();

        let inventory = build_inventory(
            &lockfile,
            InventoryDirectRequirements::new(&member_requirements, &workspace_requirements),
            &BTreeSet::new(),
            None,
            &[],
            inventory_now(),
            None,
        );

        let dependency = inventory
            .direct_dependencies()
            .iter()
            .find(|dependency| dependency.name() == "serde")
            .expect("dependency should exist");
        assert!(dependency.inherited());
        assert!(dependency.exact_pinned());
        assert_eq!(dependency.version_requirement(), Some("=1.0.228"));
        assert!(!inventory.gaps().iter().any(|gap| {
            matches!(gap, InventoryGap::NonExactDirectPin { name, .. } if name == "serde")
        }));
    }

    #[test]
    fn exact_pin_gaps_apply_to_alternate_registry_but_not_git_or_path() {
        let lockfile = parse_lockfile(
            r#"
[[package]]
name = "alt"
version = "1.0.0"
source = "registry+https://example.invalid/index"

[[package]]
name = "git-crate"
version = "0.1.0"
source = "git+https://example.invalid/repo"

[[package]]
name = "path-crate"
version = "0.1.0"
"#,
        )
        .expect("lockfile should parse");
        let requirements = parse_manifest_direct_requirements(
            "Cargo.toml",
            r#"
[dependencies]
alt = { version = "1", registry = "internal" }
git-crate = { git = "https://example.invalid/repo", version = "0.1" }
path-crate = { path = "crates/path-crate" }
"#,
        )
        .expect("manifest should parse")
        .into_iter()
        .collect::<Vec<_>>();

        let inventory = build_inventory(
            &lockfile,
            InventoryDirectRequirements::new(&requirements, &[]),
            &BTreeSet::new(),
            None,
            &[],
            inventory_now(),
            None,
        );

        assert!(inventory.gaps().iter().any(|gap| {
            matches!(gap, InventoryGap::NonExactDirectPin { name, .. } if name == "alt")
        }));
        assert!(!inventory.gaps().iter().any(|gap| {
            matches!(gap, InventoryGap::NonExactDirectPin { name, .. } if name == "git-crate")
        }));
        assert!(!inventory.gaps().iter().any(|gap| {
            matches!(gap, InventoryGap::NonExactDirectPin { name, .. } if name == "path-crate")
        }));
    }

    #[test]
    fn workspace_members_are_not_non_crates_io_sources() {
        let lockfile = parse_lockfile(
            r#"
[[package]]
name = "app"
version = "0.1.0"

[[package]]
name = "app"
version = "0.2.0"

[[package]]
name = "app"
version = "0.1.0"
source = "git+https://example.invalid/app"

[[package]]
name = "git-crate"
version = "0.1.0"
source = "git+https://example.invalid/git-crate"
"#,
        )
        .expect("lockfile should parse");
        let workspace_packages = BTreeSet::from([WorkspacePackageIdentity::new(
            "app".to_owned(),
            "0.1.0".to_owned(),
        )]);

        let inventory = build_inventory(
            &lockfile,
            InventoryDirectRequirements::new(&[], &[]),
            &workspace_packages,
            None,
            &[],
            inventory_now(),
            None,
        );

        assert!(!inventory.non_crates_io_sources().iter().any(|source| {
            source.name() == "app" && source.version() == "0.1.0" && source.source().is_none()
        }));
        assert!(
            inventory
                .non_crates_io_sources()
                .iter()
                .any(|source| { source.name() == "app" && source.version() == "0.2.0" })
        );
        assert!(inventory.non_crates_io_sources().iter().any(|source| {
            source.name() == "app"
                && source.version() == "0.1.0"
                && source.source() == Some("git+https://example.invalid/app")
        }));
        assert!(inventory.non_crates_io_sources().iter().any(|source| {
            source.name() == "git-crate"
                && source.version() == "0.1.0"
                && source.source() == Some("git+https://example.invalid/git-crate")
        }));
        assert!(!inventory.gaps().iter().any(|gap| {
            matches!(gap, InventoryGap::NonCratesIoSource { name, version, source } if name == "app" && version == "0.1.0" && source.is_none())
        }));
        assert!(inventory.gaps().iter().any(|gap| {
            matches!(gap, InventoryGap::NonCratesIoSource { name, version, .. } if name == "app" && version == "0.2.0")
        }));
        assert!(inventory.gaps().iter().any(|gap| {
            matches!(gap, InventoryGap::NonCratesIoSource { name, version, source } if name == "app" && version == "0.1.0" && source.as_deref() == Some("git+https://example.invalid/app"))
        }));
        assert!(inventory.gaps().iter().any(|gap| {
            matches!(gap, InventoryGap::NonCratesIoSource { name, version, source } if name == "git-crate" && version == "0.1.0" && source.as_deref() == Some("git+https://example.invalid/git-crate"))
        }));
    }

    #[test]
    fn builds_graph_surfaces_in_one_package_pass() {
        let metadata = parse_cargo_metadata(
            r#"{
  "packages": [
    {
      "name": "build-crate",
      "id": "registry+https://github.com/rust-lang/crates.io-index#build-crate@1.0.0",
      "version": "1.0.0",
      "targets": [{"kind": ["custom-build"]}]
    },
    {
      "name": "derive-crate",
      "id": "registry+https://github.com/rust-lang/crates.io-index#derive-crate@1.0.0",
      "version": "1.0.0",
      "targets": [{"kind": ["proc-macro"]}]
    },
    {
      "name": "native-crate",
      "id": "registry+https://github.com/rust-lang/crates.io-index#native-crate@1.0.0",
      "version": "1.0.0",
      "links": "native",
      "targets": []
    },
    {
      "name": "foo",
      "id": "path+file:///workspace/foo#foo@0.1.0",
      "version": "0.1.0",
      "targets": []
    },
    {
      "name": "workspace-build",
      "id": "path+file:///workspace/workspace-build#workspace-build@0.1.0",
      "version": "0.1.0",
      "targets": [{"kind": ["custom-build"]}]
    },
    {
      "name": "foo",
      "id": "git+https://example.invalid/foo#foo@0.1.0",
      "version": "0.1.0",
      "targets": [{"kind": ["custom-build"]}]
    },
    {
      "name": "shadow",
      "id": "git+https://example.invalid/shadow-a#shadow@1.0.0",
      "version": "1.0.0",
      "targets": [{"kind": ["custom-build"]}]
    },
    {
      "name": "shadow",
      "id": "git+https://example.invalid/shadow-b#shadow@1.0.0",
      "version": "1.0.0",
      "targets": [{"kind": ["proc-macro"]}]
    }
  ],
  "workspace_members": [
    "path+file:///workspace/foo#foo@0.1.0",
    "path+file:///workspace/workspace-build#workspace-build@0.1.0"
  ],
  "resolve": {"nodes": []}
}"#,
        )
        .expect("metadata should parse");

        let surfaces = build_graph_surfaces(&metadata).expect("surfaces should build");
        let observed = surfaces
            .surfaces()
            .map(|(spec, surfaces)| {
                (
                    spec.to_string(),
                    surfaces.has_build_rs,
                    surfaces.is_proc_macro,
                    surfaces.has_native_links,
                )
            })
            .collect::<Vec<_>>();

        assert!(
            !observed
                .iter()
                .any(|(spec, ..)| spec == "workspace-build@0.1.0")
        );
        assert_eq!(
            observed,
            vec![
                ("build-crate@1.0.0".to_owned(), true, false, false),
                ("derive-crate@1.0.0".to_owned(), false, true, false),
                ("foo@0.1.0".to_owned(), true, false, false),
                ("native-crate@1.0.0".to_owned(), false, false, true),
                ("shadow@1.0.0".to_owned(), true, true, false),
            ]
        );
    }

    #[test]
    fn live_execution_surfaces_are_cross_referenced_against_declarations() {
        let lockfile = parse_lockfile(
            r#"
[[package]]
name = "covered"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

[[package]]
name = "uncovered"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "1111111111111111111111111111111111111111111111111111111111111111"

[[package]]
name = "native"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "2222222222222222222222222222222222222222222222222222222222222222"

[[package]]
name = "foo"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "3333333333333333333333333333333333333333333333333333333333333333"

[[package]]
name = "multi"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "5555555555555555555555555555555555555555555555555555555555555555"

[[package]]
name = "ffi-sys"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "6666666666666666666666666666666666666666666666666666666666666666"
"#,
        )
        .expect("lockfile should parse");
        let reviewed_targets = parse_reviewed_targets_toml(
            r#"
[rust]

[[rust.families]]
name = "covered-family"
review_record = "docs/dependency-reviews/covered.md"

[rust.families.direct]
covered = "=1.0.0"

[rust.families.resolved]
covered = { version = "1.0.0", checksum_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }

[rust.families.allowed_surfaces]
covered = ["build-rs"]

[[rust.families]]
name = "versioned-family"
review_record = "docs/dependency-reviews/versioned.md"

[rust.families.direct]
foo = "=1.0.0"

[rust.families.resolved]
foo = { version = "1.0.0", checksum_sha256 = "4444444444444444444444444444444444444444444444444444444444444444" }

[rust.families.allowed_surfaces]
foo = ["build-rs"]

[[rust.families]]
name = "multi-family"
review_record = "docs/dependency-reviews/multi.md"

[rust.families.direct]
multi = "=1.0.0"

[rust.families.resolved]
multi = { version = "1.0.0", checksum_sha256 = "5555555555555555555555555555555555555555555555555555555555555555" }

[rust.families.allowed_surfaces]
multi = ["build-rs"]
"#,
        )
        .expect("reviewed targets should parse");
        let metadata = parse_cargo_metadata(
            r#"{
  "packages": [
    {
      "name": "covered",
      "id": "registry+https://github.com/rust-lang/crates.io-index#covered@1.0.0",
      "version": "1.0.0",
      "targets": [{"kind": ["custom-build"]}]
    },
    {
      "name": "uncovered",
      "id": "registry+https://github.com/rust-lang/crates.io-index#uncovered@1.0.0",
      "version": "1.0.0",
      "targets": [{"kind": ["proc-macro"]}]
    },
    {
      "name": "native",
      "id": "registry+https://github.com/rust-lang/crates.io-index#native@1.0.0",
      "version": "1.0.0",
      "links": "native",
      "targets": []
    },
    {
      "name": "foo",
      "id": "registry+https://github.com/rust-lang/crates.io-index#foo@2.0.0",
      "version": "2.0.0",
      "targets": [{"kind": ["custom-build"]}]
    },
    {
      "name": "multi",
      "id": "registry+https://github.com/rust-lang/crates.io-index#multi@1.0.0",
      "version": "1.0.0",
      "targets": [{"kind": ["custom-build"]}, {"kind": ["proc-macro"]}]
    },
    {
      "name": "ffi-sys",
      "id": "registry+https://github.com/rust-lang/crates.io-index#ffi-sys@1.0.0",
      "version": "1.0.0",
      "targets": []
    }
  ],
  "workspace_members": [],
  "resolve": {"nodes": []}
}"#,
        )
        .expect("metadata should parse");
        let graph_surfaces = build_graph_surfaces(&metadata).expect("surfaces should build");
        let reviewed_report = check_reviewed_rust_targets(&reviewed_targets, &[], &lockfile);

        let inventory = build_inventory(
            &lockfile,
            InventoryDirectRequirements::new(&[], &[]),
            &BTreeSet::new(),
            Some(&reviewed_report),
            &[
                ReviewRecordFact::new(
                    "covered-family".to_owned(),
                    "docs/dependency-reviews/covered.md".to_owned(),
                    true,
                ),
                ReviewRecordFact::new(
                    "versioned-family".to_owned(),
                    "docs/dependency-reviews/versioned.md".to_owned(),
                    true,
                ),
                ReviewRecordFact::new(
                    "multi-family".to_owned(),
                    "docs/dependency-reviews/multi.md".to_owned(),
                    true,
                ),
            ],
            inventory_now(),
            Some(&graph_surfaces),
        );

        let live_surfaces = inventory.live_surfaces().expect("surfaces collected");
        assert!(live_surfaces.iter().any(|surface| {
            surface.spec().to_string() == "covered@1.0.0" && surface.declared()
        }));
        assert!(live_surfaces.iter().any(|surface| {
            surface.spec().to_string() == "uncovered@1.0.0" && !surface.declared()
        }));
        assert!(live_surfaces.iter().any(|surface| {
            surface.spec().to_string() == "native@1.0.0"
                && surface.surface() == crate::ExecutionSurfaceKind::NativeSys
                && !surface.declared()
        }));
        assert!(live_surfaces.iter().any(|surface| {
            surface.spec().to_string() == "foo@2.0.0"
                && surface.surface() == crate::ExecutionSurfaceKind::BuildRs
                && !surface.declared()
        }));
        assert!(live_surfaces.iter().any(|surface| {
            surface.spec().to_string() == "multi@1.0.0"
                && surface.surface() == crate::ExecutionSurfaceKind::BuildRs
                && surface.declared()
        }));
        assert!(live_surfaces.iter().any(|surface| {
            surface.spec().to_string() == "multi@1.0.0"
                && surface.surface() == crate::ExecutionSurfaceKind::ProcMacro
                && !surface.declared()
        }));
        assert!(live_surfaces.iter().any(|surface| {
            surface.spec().to_string() == "ffi-sys@1.0.0"
                && surface.surface() == crate::ExecutionSurfaceKind::NativeSys
                && !surface.declared()
        }));
        assert!(!inventory.gaps().iter().any(|gap| {
            matches!(gap, InventoryGap::UndeclaredExecutionSurface { spec, .. }
                if spec.to_string() == "covered@1.0.0")
        }));
        assert!(inventory.gaps().iter().any(|gap| {
            matches!(gap, InventoryGap::UndeclaredExecutionSurface { spec, surface, policy_configured }
                if spec.to_string() == "uncovered@1.0.0"
                    && *surface == crate::ExecutionSurfaceKind::ProcMacro
                    && *policy_configured)
        }));
        assert!(inventory.gaps().iter().any(|gap| {
            matches!(gap, InventoryGap::UndeclaredExecutionSurface { spec, surface, policy_configured }
                if spec.to_string() == "native@1.0.0"
                    && *surface == crate::ExecutionSurfaceKind::NativeSys
                    && *policy_configured)
        }));
        assert!(inventory.gaps().iter().any(|gap| {
            matches!(gap, InventoryGap::UndeclaredExecutionSurface { spec, surface, policy_configured }
                if spec.to_string() == "foo@2.0.0"
                    && *surface == crate::ExecutionSurfaceKind::BuildRs
                    && *policy_configured)
        }));
        assert!(!inventory.gaps().iter().any(|gap| {
            matches!(gap, InventoryGap::UndeclaredExecutionSurface { spec, surface, .. }
                if spec.to_string() == "multi@1.0.0"
                    && *surface == crate::ExecutionSurfaceKind::BuildRs)
        }));
        assert!(inventory.gaps().iter().any(|gap| {
            matches!(gap, InventoryGap::UndeclaredExecutionSurface { spec, surface, policy_configured }
                if spec.to_string() == "multi@1.0.0"
                    && *surface == crate::ExecutionSurfaceKind::ProcMacro
                    && *policy_configured)
        }));
        assert!(inventory.gaps().iter().any(|gap| {
            matches!(gap, InventoryGap::UndeclaredExecutionSurface { spec, surface, policy_configured }
                if spec.to_string() == "ffi-sys@1.0.0"
                    && *surface == crate::ExecutionSurfaceKind::NativeSys
                    && *policy_configured)
        }));
    }

    #[test]
    fn advisory_exceptions_report_binding_and_expiry_status() {
        let lockfile = parse_lockfile(
            r#"
[[package]]
name = "active"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

[[package]]
name = "soon"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

[[package]]
name = "boundary-soon"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "1212121212121212121212121212121212121212121212121212121212121212"

[[package]]
name = "boundary-active"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "3434343434343434343434343434343434343434343434343434343434343434"

[[package]]
name = "expired"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

[[package]]
name = "mismatch"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

[[package]]
name = "missing-record"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
"#,
        )
        .expect("lockfile should parse");
        let reviewed_targets = parse_reviewed_targets_toml(
            r#"
[rust]

[[rust.families]]
name = "existing-family"
review_record = "docs/dependency-reviews/existing.md"

[rust.families.resolved]
active = { version = "1.0.0", checksum_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
soon = { version = "1.0.0", checksum_sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }
boundary-soon = { version = "1.0.0", checksum_sha256 = "1212121212121212121212121212121212121212121212121212121212121212" }
boundary-active = { version = "1.0.0", checksum_sha256 = "3434343434343434343434343434343434343434343434343434343434343434" }
expired = { version = "1.0.0", checksum_sha256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" }
stale = { version = "1.0.0", checksum_sha256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" }
mismatch = { version = "1.0.0", checksum_sha256 = "9999999999999999999999999999999999999999999999999999999999999999" }

[rust.families.allowed_advisories]
active = [{ id = "RUSTSEC-2027-0001", review_by = "2027-11-01" }]
soon = [{ id = "RUSTSEC-2027-0002", review_by = "2027-10-01" }]
boundary-soon = [{ id = "RUSTSEC-2027-0007", review_by = "2027-10-14" }]
boundary-active = [{ id = "RUSTSEC-2027-0008", review_by = "2027-10-15" }]
expired = [{ id = "RUSTSEC-2027-0003", review_by = "2027-09-13" }]
stale = [{ id = "RUSTSEC-2027-0004", review_by = "2027-11-01" }]
mismatch = [{ id = "RUSTSEC-2027-0005", review_by = "2027-11-01" }]

[[rust.families]]
name = "missing-family"
review_record = "docs/dependency-reviews/missing.md"

[rust.families.resolved]
missing-record = { version = "1.0.0", checksum_sha256 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" }

[rust.families.allowed_advisories]
missing-record = [{ id = "RUSTSEC-2027-0006", review_by = "2027-11-01" }]
"#,
        )
        .expect("reviewed targets should parse");
        let reviewed_report = check_reviewed_rust_targets(&reviewed_targets, &[], &lockfile);

        let inventory = build_inventory(
            &lockfile,
            InventoryDirectRequirements::new(&[], &[]),
            &BTreeSet::new(),
            Some(&reviewed_report),
            &[
                ReviewRecordFact::new(
                    "existing-family".to_owned(),
                    "docs/dependency-reviews/existing.md".to_owned(),
                    true,
                ),
                ReviewRecordFact::new(
                    "missing-family".to_owned(),
                    "docs/dependency-reviews/missing.md".to_owned(),
                    false,
                ),
            ],
            inventory_now(),
            None,
        );

        assert_advisory_inventory(
            &inventory,
            "RUSTSEC-2027-0001",
            InventoryAdvisoryExceptionStatus::Active,
            true,
            true,
        );
        assert_advisory_inventory(
            &inventory,
            "RUSTSEC-2027-0002",
            InventoryAdvisoryExceptionStatus::SoonToExpire,
            true,
            true,
        );
        assert_advisory_inventory(
            &inventory,
            "RUSTSEC-2027-0007",
            InventoryAdvisoryExceptionStatus::SoonToExpire,
            true,
            true,
        );
        assert_advisory_inventory(
            &inventory,
            "RUSTSEC-2027-0008",
            InventoryAdvisoryExceptionStatus::Active,
            true,
            true,
        );
        assert_advisory_inventory(
            &inventory,
            "RUSTSEC-2027-0003",
            InventoryAdvisoryExceptionStatus::Expired,
            true,
            true,
        );
        assert_advisory_inventory(
            &inventory,
            "RUSTSEC-2027-0004",
            InventoryAdvisoryExceptionStatus::Stale,
            false,
            true,
        );
        assert_advisory_inventory(
            &inventory,
            "RUSTSEC-2027-0005",
            InventoryAdvisoryExceptionStatus::Active,
            false,
            true,
        );
        assert_advisory_inventory(
            &inventory,
            "RUSTSEC-2027-0006",
            InventoryAdvisoryExceptionStatus::Active,
            true,
            false,
        );
    }

    fn assert_advisory_inventory(
        inventory: &crate::Inventory,
        advisory_id: &str,
        status: InventoryAdvisoryExceptionStatus,
        resolved_target_matches: bool,
        review_record_exists: bool,
    ) {
        let exception = inventory
            .advisory_exceptions()
            .iter()
            .find(|exception| exception.advisory_id() == advisory_id)
            .expect("advisory exception should be reported");
        assert_eq!(exception.status(), status);
        assert_eq!(exception.resolved_target_matches(), resolved_target_matches);
        assert_eq!(exception.review_record_exists(), review_record_exists);
    }

    #[test]
    fn build_graph_surfaces_rejects_invalid_metadata_specs() {
        let metadata = parse_cargo_metadata(
            r#"{
  "packages": [
    {
      "name": "",
      "id": "registry+https://github.com/rust-lang/crates.io-index#invalid@1.0.0",
      "version": "1.0.0",
      "targets": [{"kind": ["custom-build"]}]
    }
  ],
  "workspace_members": [],
  "resolve": {"nodes": []}
}"#,
        )
        .expect("metadata should parse");

        assert!(build_graph_surfaces(&metadata).is_err());
    }
}
