use std::collections::{BTreeMap, BTreeSet};

use crate::{
    CargoDependencySourceKind, CargoManifestDirectRequirement, ExactCrateSpec,
    ExecutionSurfaceKind, Lockfile, ReviewedTargets, Sha256Digest, parse_exact_version_requirement,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inventory {
    policy_configured: bool,
    direct_dependencies: Vec<InventoryDirectDependency>,
    resolved_crates_io: Vec<InventoryResolvedCrate>,
    non_crates_io_sources: Vec<InventoryNonCratesIoSource>,
    reviewed_families: Vec<InventoryReviewedFamily>,
    declared_surfaces: Vec<InventoryDeclaredSurface>,
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

    pub fn declared_surfaces(&self) -> &[InventoryDeclaredSurface] {
        &self.declared_surfaces
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
}

impl InventoryGap {
    pub fn is_policy_relative(&self) -> bool {
        matches!(
            self,
            Self::MissingReviewRecord { .. } | Self::UncoveredResolvedCrate { .. }
        )
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
    reviewed_targets: Option<&ReviewedTargets>,
    review_record_facts: &[ReviewRecordFact],
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

    if let Some(reviewed_targets) = reviewed_targets {
        for family in reviewed_targets.rust_families() {
            let record_fact = review_facts_by_family.get(family.name()).copied();
            let review_record_exists = record_fact.is_some_and(ReviewRecordFact::exists);
            if !review_record_exists {
                gaps.push(InventoryGap::MissingReviewRecord {
                    family: family.name().to_owned(),
                    review_record: family.review_record().to_owned(),
                });
            }

            for (crate_name, target) in family.resolved() {
                covered_specs.insert(
                    ExactCrateSpec::from_parts(crate_name, target.version())
                        .expect("parse_reviewed_targets_toml validates exact specs"),
                );
            }
            reviewed_families.push(InventoryReviewedFamily {
                name: family.name().to_owned(),
                review_record: family.review_record().to_owned(),
                review_record_exists,
                direct_count: family.direct().len(),
                resolved_count: family.resolved().len(),
            });
        }
        declared_surfaces.extend(
            reviewed_targets
                .execution_surface_allowances()
                .into_iter()
                .map(|allowance| InventoryDeclaredSurface {
                    family: allowance.family().to_owned(),
                    spec: allowance.spec().clone(),
                    surface: allowance.surface(),
                }),
        );
    }

    let mut resolved_crates_io = Vec::new();
    let mut non_crates_io_sources = Vec::new();
    for package in lockfile.packages() {
        if package.is_crates_io() {
            let resolved = InventoryResolvedCrate {
                spec: package.exact_spec().clone(),
                checksum: package.checksum().cloned(),
            };
            if reviewed_targets.is_some() && !covered_specs.contains(resolved.spec()) {
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

    Inventory {
        policy_configured: reviewed_targets.is_some(),
        direct_dependencies,
        resolved_crates_io,
        non_crates_io_sources,
        reviewed_families,
        declared_surfaces,
        gaps,
    }
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
        InventoryDirectRequirements, InventoryGap, ReviewRecordFact, WorkspacePackageIdentity,
        build_inventory, parse_lockfile, parse_manifest_direct_requirements,
        parse_reviewed_targets_toml,
    };

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

        let inventory = build_inventory(
            &lockfile,
            InventoryDirectRequirements::new(&requirements, &[]),
            &BTreeSet::new(),
            Some(&reviewed_targets),
            &[ReviewRecordFact::new(
                "covered-family".to_owned(),
                "docs/dependency-reviews/covered.md".to_owned(),
                false,
            )],
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
}
