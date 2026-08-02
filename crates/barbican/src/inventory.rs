use std::collections::{BTreeMap, BTreeSet};

use crate::metadata::{metadata_packages, workspace_direct_dependencies};
use crate::review_record::ReviewRecordStatus;
use crate::{
    CargoDependencySourceKind, CargoManifestDirectRequirement, ExactCrateSpec,
    ExecutionSurfaceKind, Lockfile, MetadataDirectDependency, MetadataPackageSurfaces,
    RustReviewedTargetsReport, Sha256Digest, parse_exact_version_requirement,
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
    resolved_direct_dependencies: Option<Vec<MetadataDirectDependency>>,
    graph_facts_error: Option<String>,
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

    /// The `inventory --enforce` coverage floor: the pure pass/fail decision
    /// over already-computed inventory facts. The floor fails closed when no
    /// reviewed-target policy is configured, exact direct-dependency facts
    /// could not be collected, any crates.io direct dependency lacks active
    /// reviewed-family coverage, or any external-source direct dependency is
    /// present. Enforcement of undeclared execution surfaces is a documented
    /// follow-up: surfaces stay observationally reported here and are not
    /// gated (see docs/functional/cli.md).
    pub fn coverage_floor(&self) -> InventoryCoverageFloor {
        let uncovered_specs = self
            .gaps
            .iter()
            .filter_map(|gap| match gap {
                InventoryGap::UncoveredResolvedCrate { spec } => Some(spec),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        let mut uncovered_direct_dependencies = Vec::new();
        let mut external_non_crates_io_direct_dependencies = Vec::new();

        for dependency in self.resolved_direct_dependencies.iter().flatten() {
            if dependency.is_workspace_member() {
                continue;
            }
            if dependency.is_crates_io() {
                if uncovered_specs.contains(dependency.spec()) {
                    uncovered_direct_dependencies.push(dependency.spec().clone());
                }
            } else {
                external_non_crates_io_direct_dependencies
                    .push(InventoryNonCratesIoSource::from(dependency));
            }
        }

        InventoryCoverageFloor {
            policy_configured: self.policy_configured,
            graph_facts_collected: self.resolved_direct_dependencies.is_some(),
            graph_facts_error: self.graph_facts_error.clone(),
            uncovered_direct_dependencies,
            external_non_crates_io_direct_dependencies,
        }
    }

    /// Domain-owned readiness classification for gate and report consumers.
    /// Categories are exclusive: direct coverage failures belong to the
    /// coverage floor, while the remaining gaps are enforced, observational,
    /// or unclassified when graph facts cannot establish the distinction.
    pub fn readiness_summary(&self) -> InventoryReadinessSummary {
        let coverage_floor = self.coverage_floor();
        let uncovered_direct = coverage_floor
            .uncovered_direct_dependencies()
            .iter()
            .collect::<BTreeSet<_>>();
        let external_direct = coverage_floor
            .external_non_crates_io_direct_dependencies()
            .iter()
            .map(|source| (source.name(), source.version(), source.source()))
            .collect::<BTreeSet<_>>();
        let mut unclassified_uncovered_crates_io = 0;
        let mut unclassified_non_crates_io_sources = 0;
        let mut uncovered_transitive_crates_io = 0;
        let mut undeclared_execution_surfaces = 0;
        let mut incomplete_review_records = 0;
        let mut other_observational_findings = 0;

        for gap in &self.gaps {
            match gap {
                InventoryGap::UncoveredResolvedCrate { .. }
                    if !coverage_floor.graph_facts_collected() =>
                {
                    unclassified_uncovered_crates_io += 1;
                }
                InventoryGap::UncoveredResolvedCrate { spec }
                    if !uncovered_direct.contains(spec) =>
                {
                    uncovered_transitive_crates_io += 1;
                }
                InventoryGap::UncoveredResolvedCrate { .. } => {}
                InventoryGap::UndeclaredExecutionSurface { .. } => {
                    undeclared_execution_surfaces += 1;
                }
                InventoryGap::IncompleteReviewRecord { .. } => {
                    incomplete_review_records += 1;
                }
                InventoryGap::NonExactDirectPin { .. } => {
                    other_observational_findings += 1;
                }
                InventoryGap::NonCratesIoSource { .. }
                    if !coverage_floor.graph_facts_collected() =>
                {
                    unclassified_non_crates_io_sources += 1;
                }
                InventoryGap::NonCratesIoSource {
                    name,
                    version,
                    source,
                } if !external_direct.contains(&(
                    name.as_str(),
                    version.as_str(),
                    source.as_deref(),
                )) =>
                {
                    other_observational_findings += 1;
                }
                InventoryGap::NonCratesIoSource { .. } => {}
            }
        }

        InventoryReadinessSummary {
            coverage_floor,
            unclassified_uncovered_crates_io,
            unclassified_non_crates_io_sources,
            uncovered_transitive_crates_io,
            undeclared_execution_surfaces,
            incomplete_review_records,
            other_observational_findings,
        }
    }
}

/// The decision produced by [`Inventory::coverage_floor`]. `passed` is the
/// gate; the offending crates let the binary name each one and teach the fix.
/// It fails closed on an uncovered crates.io direct dependency and on any
/// external (git / alternate-registry / external-path) direct dependency,
/// which a crates.io reviewed family cannot cover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryCoverageFloor {
    policy_configured: bool,
    graph_facts_collected: bool,
    graph_facts_error: Option<String>,
    uncovered_direct_dependencies: Vec<ExactCrateSpec>,
    external_non_crates_io_direct_dependencies: Vec<InventoryNonCratesIoSource>,
}

impl InventoryCoverageFloor {
    pub fn passed(&self) -> bool {
        self.policy_configured
            && self.graph_facts_collected
            && self.uncovered_direct_dependencies.is_empty()
            && self.external_non_crates_io_direct_dependencies.is_empty()
    }

    pub fn policy_configured(&self) -> bool {
        self.policy_configured
    }

    pub fn graph_facts_collected(&self) -> bool {
        self.graph_facts_collected
    }

    pub fn graph_facts_error(&self) -> Option<&str> {
        self.graph_facts_error.as_deref()
    }

    pub fn uncovered_direct_dependencies(&self) -> &[ExactCrateSpec] {
        &self.uncovered_direct_dependencies
    }

    pub fn external_non_crates_io_direct_dependencies(&self) -> &[InventoryNonCratesIoSource] {
        &self.external_non_crates_io_direct_dependencies
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryReadinessSummary {
    coverage_floor: InventoryCoverageFloor,
    unclassified_uncovered_crates_io: usize,
    unclassified_non_crates_io_sources: usize,
    uncovered_transitive_crates_io: usize,
    undeclared_execution_surfaces: usize,
    incomplete_review_records: usize,
    other_observational_findings: usize,
}

impl InventoryReadinessSummary {
    pub fn coverage_floor(&self) -> &InventoryCoverageFloor {
        &self.coverage_floor
    }

    pub fn unclassified_uncovered_crates_io(&self) -> usize {
        self.unclassified_uncovered_crates_io
    }

    pub fn unclassified_non_crates_io_sources(&self) -> usize {
        self.unclassified_non_crates_io_sources
    }

    pub fn uncovered_transitive_crates_io(&self) -> usize {
        self.uncovered_transitive_crates_io
    }

    pub fn undeclared_execution_surfaces(&self) -> usize {
        self.undeclared_execution_surfaces
    }

    pub fn incomplete_review_records(&self) -> usize {
        self.incomplete_review_records
    }

    pub fn other_observational_findings(&self) -> usize {
        self.other_observational_findings
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
    fn from_spec_and_source(spec: &ExactCrateSpec, source: Option<&str>) -> Self {
        Self {
            name: spec.crate_name().to_owned(),
            version: spec.version().to_owned(),
            source: source.map(str::to_owned),
        }
    }

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

impl From<&MetadataDirectDependency> for InventoryNonCratesIoSource {
    fn from(dependency: &MetadataDirectDependency) -> Self {
        Self::from_spec_and_source(dependency.spec(), dependency.source())
    }
}

impl From<&crate::LockedPackage> for InventoryNonCratesIoSource {
    fn from(package: &crate::LockedPackage) -> Self {
        Self::from_spec_and_source(package.exact_spec(), package.source.as_deref())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryReviewedFamily {
    name: String,
    review_record: String,
    review_record_completed: bool,
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

    pub fn review_record_completed(&self) -> bool {
        self.review_record_completed
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
    review_record_completed: bool,
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

    pub fn review_record_completed(&self) -> bool {
        self.review_record_completed
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
    IncompleteReviewRecord {
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
            Self::IncompleteReviewRecord { .. } | Self::UncoveredResolvedCrate { .. } => true,
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
    status: ReviewRecordStatus,
}

impl ReviewRecordFact {
    pub fn new(family_name: String, review_record: String, status: ReviewRecordStatus) -> Self {
        Self {
            family_name,
            review_record,
            status,
        }
    }

    pub fn family_name(&self) -> &str {
        &self.family_name
    }

    pub fn review_record(&self) -> &str {
        &self.review_record
    }

    pub fn status(&self) -> ReviewRecordStatus {
        self.status
    }

    /// True only for a completed record. A missing, empty, or scaffold-stub
    /// record fails closed, so an unfinished scaffold cannot satisfy the gate.
    pub fn is_satisfied(&self) -> bool {
        self.status.is_satisfied()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryGraphFacts {
    surfaces: Result<BTreeMap<ExactCrateSpec, MetadataPackageSurfaces>, String>,
    direct_dependencies: Result<Vec<MetadataDirectDependency>, String>,
}

impl InventoryGraphFacts {
    pub fn unavailable(reason: String) -> Self {
        Self {
            surfaces: Err(reason.clone()),
            direct_dependencies: Err(reason),
        }
    }

    pub fn surfaces(
        &self,
    ) -> Option<impl Iterator<Item = (&ExactCrateSpec, &MetadataPackageSurfaces)>> {
        self.surfaces.as_ref().ok().map(BTreeMap::iter)
    }

    pub fn surface_error(&self) -> Option<&str> {
        self.surfaces.as_ref().err().map(String::as_str)
    }

    pub fn direct_dependencies(&self) -> Option<&[MetadataDirectDependency]> {
        self.direct_dependencies.as_deref().ok()
    }

    pub fn direct_dependency_error(&self) -> Option<&str> {
        self.direct_dependencies.as_ref().err().map(String::as_str)
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
    graph_facts: Option<&InventoryGraphFacts>,
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
            let review_record_completed = record_fact.is_some_and(ReviewRecordFact::is_satisfied);
            if !review_record_completed {
                gaps.push(InventoryGap::IncompleteReviewRecord {
                    family: family.name().to_owned(),
                    review_record: family.review_record().to_owned(),
                });
            }

            for check in family.resolved_checks() {
                covered_specs.insert(check.expected_target().spec().clone());
            }
            reviewed_families.push(InventoryReviewedFamily {
                name: family.name().to_owned(),
                review_record: family.review_record().to_owned(),
                review_record_completed,
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
                        review_record_completed,
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

            let entry = InventoryNonCratesIoSource::from(package);
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
    let live_surfaces = graph_facts.and_then(|graph_facts| {
        let surfaces = graph_facts.surfaces()?;
        let mut live_surfaces = Vec::new();
        for (spec, package_surfaces) in surfaces {
            for surface in package_surfaces.surface_kinds(spec) {
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
        Some(live_surfaces)
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
        resolved_direct_dependencies: graph_facts
            .and_then(InventoryGraphFacts::direct_dependencies)
            .map(<[_]>::to_vec),
        graph_facts_error: graph_facts
            .and_then(InventoryGraphFacts::direct_dependency_error)
            .map(str::to_owned),
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

pub fn build_inventory_graph_facts(
    metadata: &crate::CargoMetadata,
    lockfile: &Lockfile,
) -> Result<InventoryGraphFacts, crate::CargoMetadataError> {
    let mut surfaces = BTreeMap::new();
    for package in metadata_packages(metadata) {
        if package.is_workspace_member {
            continue;
        }

        let spec = ExactCrateSpec::from_parts(package.name, package.version).map_err(|source| {
            crate::CargoMetadataError::InvalidPackageSpec {
                package_id: format!("{}@{}", package.name, package.version),
                source,
            }
        })?;
        surfaces
            .entry(spec)
            .and_modify(|existing: &mut MetadataPackageSurfaces| {
                existing.union_with(&package.surfaces);
            })
            .or_insert(package.surfaces);
    }

    Ok(InventoryGraphFacts {
        surfaces: Ok(surfaces),
        direct_dependencies: workspace_direct_dependencies(metadata, lockfile)
            .map_err(|error| error.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use crate::{
        InventoryAdvisoryExceptionStatus, InventoryDirectRequirements, InventoryGap,
        ReviewRecordFact, ReviewRecordStatus, WorkspacePackageIdentity, build_inventory,
        build_inventory_graph_facts, check_reviewed_rust_targets, parse_cargo_metadata,
        parse_lockfile, parse_manifest_direct_requirements, parse_reviewed_targets_toml,
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
                ReviewRecordStatus::Missing,
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
        let readiness = inventory.readiness_summary();
        assert_eq!(readiness.unclassified_uncovered_crates_io(), 1);
        assert_eq!(readiness.unclassified_non_crates_io_sources(), 1);
        assert_eq!(readiness.uncovered_transitive_crates_io(), 0);
        assert_eq!(readiness.undeclared_execution_surfaces(), 0);
        assert_eq!(readiness.incomplete_review_records(), 1);
        assert_eq!(readiness.other_observational_findings(), 1);
        assert!(inventory.gaps().iter().any(|gap| {
            matches!(gap, InventoryGap::IncompleteReviewRecord { family, .. } if family == "covered-family")
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
    fn coverage_floor_passes_when_every_direct_dependency_is_covered() {
        let lockfile = parse_lockfile(
            r#"
[[package]]
name = "root"
version = "0.1.0"
dependencies = ["covered"]

[[package]]
name = "covered"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

[[package]]
name = "transitive"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "1111111111111111111111111111111111111111111111111111111111111111"
"#,
        )
        .expect("lockfile should parse");
        let requirements = parse_manifest_direct_requirements(
            "Cargo.toml",
            r#"
[dependencies]
covered = "=1.0.0"
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
        let metadata = parse_cargo_metadata(
            r#"{
  "packages": [
    {"name":"root","id":"path+file:///repo#root@0.1.0","version":"0.1.0","source":null,"targets":[],"dependencies":[{"name":"covered","req":"=1.0.0","kind":null,"optional":false,"source":"registry+https://github.com/rust-lang/crates.io-index"}]},
    {"name":"covered","id":"registry+https://github.com/rust-lang/crates.io-index#covered@1.0.0","version":"1.0.0","source":"registry+https://github.com/rust-lang/crates.io-index","targets":[]},
    {"name":"transitive","id":"registry+https://github.com/rust-lang/crates.io-index#transitive@2.0.0","version":"2.0.0","source":"registry+https://github.com/rust-lang/crates.io-index","targets":[]}
  ],
  "workspace_members": ["path+file:///repo#root@0.1.0"],
  "resolve": {"nodes":[
    {"id":"path+file:///repo#root@0.1.0","deps":[
      {"name":"covered","pkg":"registry+https://github.com/rust-lang/crates.io-index#covered@1.0.0"}
    ]},
    {"id":"registry+https://github.com/rust-lang/crates.io-index#covered@1.0.0","deps":[{"name":"transitive","pkg":"registry+https://github.com/rust-lang/crates.io-index#transitive@2.0.0"}]},
    {"id":"registry+https://github.com/rust-lang/crates.io-index#transitive@2.0.0","deps":[]}
  ]}
}"#,
        )
        .expect("metadata should parse");
        let graph_facts =
            build_inventory_graph_facts(&metadata, &lockfile).expect("graph facts should build");

        let inventory = build_inventory(
            &lockfile,
            InventoryDirectRequirements::new(&requirements, &[]),
            &BTreeSet::from([WorkspacePackageIdentity::new(
                "root".to_owned(),
                "0.1.0".to_owned(),
            )]),
            Some(&reviewed_report),
            &[ReviewRecordFact::new(
                "covered-family".to_owned(),
                "docs/dependency-reviews/covered.md".to_owned(),
                ReviewRecordStatus::Completed,
            )],
            inventory_now(),
            Some(&graph_facts),
        );

        let floor = inventory.coverage_floor();
        assert!(floor.passed());
        assert!(floor.uncovered_direct_dependencies().is_empty());
        let readiness = inventory.readiness_summary();
        assert_eq!(readiness.unclassified_uncovered_crates_io(), 0);
        assert_eq!(readiness.unclassified_non_crates_io_sources(), 0);
        assert_eq!(readiness.uncovered_transitive_crates_io(), 1);
        assert_eq!(readiness.incomplete_review_records(), 0);
        assert_eq!(readiness.other_observational_findings(), 0);
        // The uncovered transitive crate is a resolved-graph gap but not a
        // direct dependency, so the floor leaves it observational.
        assert!(inventory.gaps().iter().any(|gap| {
            matches!(gap, InventoryGap::UncoveredResolvedCrate { spec } if spec.to_string() == "transitive@2.0.0")
        }));
    }

    #[test]
    fn coverage_floor_fails_naming_each_uncovered_direct_dependency() {
        let lockfile = parse_lockfile(
            r#"
[[package]]
name = "root"
version = "0.1.0"
dependencies = ["covered", "sneaky"]

[[package]]
name = "covered"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

[[package]]
name = "sneaky"
version = "3.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "2222222222222222222222222222222222222222222222222222222222222222"
"#,
        )
        .expect("lockfile should parse");
        let requirements = parse_manifest_direct_requirements(
            "Cargo.toml",
            r#"
[dependencies]
covered = "=1.0.0"
sneaky = "=3.0.0"
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
        let metadata = parse_cargo_metadata(
            r#"{
  "packages": [
    {"name":"root","id":"path+file:///repo#root@0.1.0","version":"0.1.0","source":null,"targets":[],"dependencies":[{"name":"covered","req":"=1.0.0","kind":null,"optional":false,"source":"registry+https://github.com/rust-lang/crates.io-index"},{"name":"sneaky","req":"=3.0.0","kind":null,"optional":false,"source":"registry+https://github.com/rust-lang/crates.io-index"}]},
    {"name":"covered","id":"registry+https://github.com/rust-lang/crates.io-index#covered@1.0.0","version":"1.0.0","source":"registry+https://github.com/rust-lang/crates.io-index","targets":[]},
    {"name":"sneaky","id":"registry+https://github.com/rust-lang/crates.io-index#sneaky@3.0.0","version":"3.0.0","source":"registry+https://github.com/rust-lang/crates.io-index","targets":[]}
  ],
  "workspace_members": ["path+file:///repo#root@0.1.0"],
  "resolve": {"nodes":[
    {"id":"path+file:///repo#root@0.1.0","deps":[
      {"name":"covered","pkg":"registry+https://github.com/rust-lang/crates.io-index#covered@1.0.0"},
      {"name":"sneaky","pkg":"registry+https://github.com/rust-lang/crates.io-index#sneaky@3.0.0"}
    ]},
    {"id":"registry+https://github.com/rust-lang/crates.io-index#covered@1.0.0","deps":[]},
    {"id":"registry+https://github.com/rust-lang/crates.io-index#sneaky@3.0.0","deps":[]}
  ]}
}"#,
        )
        .expect("metadata should parse");
        let graph_facts =
            build_inventory_graph_facts(&metadata, &lockfile).expect("graph facts should build");

        let inventory = build_inventory(
            &lockfile,
            InventoryDirectRequirements::new(&requirements, &[]),
            &BTreeSet::new(),
            Some(&reviewed_report),
            &[ReviewRecordFact::new(
                "covered-family".to_owned(),
                "docs/dependency-reviews/covered.md".to_owned(),
                ReviewRecordStatus::Completed,
            )],
            inventory_now(),
            Some(&graph_facts),
        );

        let floor = inventory.coverage_floor();
        assert!(!floor.passed());
        let uncovered = floor
            .uncovered_direct_dependencies()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        assert_eq!(uncovered, vec!["sneaky@3.0.0".to_owned()]);
        let readiness = inventory.readiness_summary();
        assert_eq!(readiness.uncovered_transitive_crates_io(), 0);
    }

    #[test]
    fn coverage_floor_fails_closed_when_no_policy_is_configured() {
        let lockfile = parse_lockfile(
            r#"
[[package]]
name = "anything"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
"#,
        )
        .expect("lockfile should parse");
        let requirements = parse_manifest_direct_requirements(
            "Cargo.toml",
            r#"
[dependencies]
anything = "=1.0.0"
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

        let floor = inventory.coverage_floor();
        assert!(!floor.passed());
        assert!(!floor.policy_configured());
        // No policy means no resolved-coverage gaps are computed, so the
        // floor must fail closed on the missing policy rather than on an
        // empty uncovered set.
        assert!(floor.uncovered_direct_dependencies().is_empty());
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

        let lockfile = parse_lockfile(
            r#"
[[package]]
name = "foo"
version = "0.1.0"

[[package]]
name = "workspace-build"
version = "0.1.0"
"#,
        )
        .expect("workspace lockfile should parse");
        let surfaces =
            build_inventory_graph_facts(&metadata, &lockfile).expect("graph facts should build");
        let observed = surfaces
            .surfaces()
            .expect("surface facts should be available")
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
        let graph_surfaces =
            build_inventory_graph_facts(&metadata, &lockfile).expect("graph facts should build");
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
                    ReviewRecordStatus::Completed,
                ),
                ReviewRecordFact::new(
                    "versioned-family".to_owned(),
                    "docs/dependency-reviews/versioned.md".to_owned(),
                    ReviewRecordStatus::Completed,
                ),
                ReviewRecordFact::new(
                    "multi-family".to_owned(),
                    "docs/dependency-reviews/multi.md".to_owned(),
                    ReviewRecordStatus::Completed,
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
        assert_eq!(
            inventory
                .readiness_summary()
                .undeclared_execution_surfaces(),
            5
        );
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
stale-expired = { version = "1.0.0", checksum_sha256 = "5656565656565656565656565656565656565656565656565656565656565656" }
mismatch = { version = "1.0.0", checksum_sha256 = "9999999999999999999999999999999999999999999999999999999999999999" }

[rust.families.allowed_advisories]
active = [{ id = "RUSTSEC-2027-0001", review_by = "2027-11-01" }]
soon = [{ id = "RUSTSEC-2027-0002", review_by = "2027-10-01" }]
boundary-soon = [{ id = "RUSTSEC-2027-0007", review_by = "2027-10-14" }]
boundary-active = [{ id = "RUSTSEC-2027-0008", review_by = "2027-10-15" }]
expired = [{ id = "RUSTSEC-2027-0003", review_by = "2027-09-13" }]
stale = [{ id = "RUSTSEC-2027-0004", review_by = "2027-11-01" }]
stale-expired = [{ id = "RUSTSEC-2027-0009", review_by = "2027-09-13" }]
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
                    ReviewRecordStatus::Completed,
                ),
                ReviewRecordFact::new(
                    "missing-family".to_owned(),
                    "docs/dependency-reviews/missing.md".to_owned(),
                    ReviewRecordStatus::Missing,
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
            "RUSTSEC-2027-0009",
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
        review_record_completed: bool,
    ) {
        let exception = inventory
            .advisory_exceptions()
            .iter()
            .find(|exception| exception.advisory_id() == advisory_id)
            .expect("advisory exception should be reported");
        assert_eq!(exception.status(), status);
        assert_eq!(exception.resolved_target_matches(), resolved_target_matches);
        assert_eq!(exception.review_record_completed(), review_record_completed);
    }

    #[test]
    fn build_inventory_graph_facts_rejects_invalid_metadata_specs() {
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

        let lockfile = parse_lockfile("").expect("empty lockfile should parse");
        assert!(build_inventory_graph_facts(&metadata, &lockfile).is_err());
    }

    #[test]
    fn graph_facts_preserve_surfaces_when_direct_resolution_fails() {
        let metadata = parse_cargo_metadata(
            r#"{
  "packages": [
    {"name":"root","id":"path+file:///repo#root@0.1.0","version":"0.1.0","source":null,"manifest_path":"/repo/Cargo.toml","targets":[],"dependencies":[
      {"name":"builder","req":"^2","kind":null,"optional":false,"source":"registry+https://github.com/rust-lang/crates.io-index"}
    ]},
    {"name":"builder","id":"registry+https://github.com/rust-lang/crates.io-index#builder@1.0.0","version":"1.0.0","source":"registry+https://github.com/rust-lang/crates.io-index","targets":[{"kind":["custom-build"]}]}
  ],
  "workspace_members":["path+file:///repo#root@0.1.0"],
  "resolve":{"nodes":[]}
}"#,
        )
        .expect("metadata should parse");
        let lockfile = parse_lockfile(
            r#"
version = 4

[[package]]
name = "root"
version = "0.1.0"
dependencies = ["builder"]

[[package]]
name = "builder"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
        )
        .expect("lockfile should parse");

        let facts = build_inventory_graph_facts(&metadata, &lockfile)
            .expect("surface facts should remain available");

        assert_eq!(facts.surfaces().expect("surfaces should exist").count(), 1);
        assert!(facts.direct_dependencies().is_none());
        assert!(
            facts
                .direct_dependency_error()
                .is_some_and(|error| error.contains("builder"))
        );
    }
}
