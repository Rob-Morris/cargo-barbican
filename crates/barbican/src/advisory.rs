use std::collections::BTreeMap;

use thiserror::Error;
use time::OffsetDateTime;

use crate::{
    CargoDenyCheck, CargoDependencySourceKind, CargoManifestDirectRequirement, ExactCrateSpec,
    ExactCrateSpecError, LockfileAdvisoryScanner, MetadataDependencyPath, MetadataRequirementEdge,
    ReviewedAdvisoryException, RustSecAdvisoryId, parse_exact_version_requirement,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvisoryFinding {
    advisory_id: AdvisoryFindingId,
    package: ExactCrateSpec,
    details: AdvisoryFindingDetails,
}

impl AdvisoryFinding {
    pub fn new(advisory_id: AdvisoryFindingId, package: ExactCrateSpec) -> Self {
        Self {
            advisory_id,
            package,
            details: AdvisoryFindingDetails::default(),
        }
    }

    pub fn advisory_id(&self) -> &AdvisoryFindingId {
        &self.advisory_id
    }

    pub fn package(&self) -> &ExactCrateSpec {
        &self.package
    }

    pub fn details(&self) -> &AdvisoryFindingDetails {
        &self.details
    }

    fn merge_missing_details_from(&mut self, other: &Self) {
        self.details.merge_missing_from(&other.details);
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdvisoryFindingDetails {
    title: Option<String>,
    severity: Option<String>,
    cvss: Option<String>,
    informational: Option<String>,
    patched_versions: Vec<String>,
}

impl AdvisoryFindingDetails {
    pub fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }

    pub fn severity(&self) -> Option<&str> {
        self.severity.as_deref()
    }

    pub fn cvss(&self) -> Option<&str> {
        self.cvss.as_deref()
    }

    pub fn informational(&self) -> Option<&str> {
        self.informational.as_deref()
    }

    pub fn patched_versions(&self) -> &[String] {
        &self.patched_versions
    }

    pub fn risk_label(&self) -> Option<&str> {
        self.severity()
            .or_else(|| self.informational())
            .or_else(|| self.cvss())
    }

    fn merge_missing_from(&mut self, other: &Self) {
        if self.title.is_none() {
            self.title.clone_from(&other.title);
        }
        if self.severity.is_none() {
            self.severity.clone_from(&other.severity);
        }
        if self.cvss.is_none() {
            self.cvss.clone_from(&other.cvss);
        }
        if self.informational.is_none() {
            self.informational.clone_from(&other.informational);
        }
        if self.patched_versions.is_empty() {
            self.patched_versions.clone_from(&other.patched_versions);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct AdvisoryFindingKey {
    advisory_id: AdvisoryFindingId,
    package: ExactCrateSpec,
}

impl From<&AdvisoryFinding> for AdvisoryFindingKey {
    fn from(finding: &AdvisoryFinding) -> Self {
        Self {
            advisory_id: finding.advisory_id.clone(),
            package: finding.package.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum AdvisoryFindingId {
    RustSec(RustSecAdvisoryId),
    Unnormalised(String),
}

impl AdvisoryFindingId {
    pub fn parse(value: &str) -> Self {
        RustSecAdvisoryId::parse(value)
            .map_or_else(|_| Self::Unnormalised(value.to_owned()), Self::RustSec)
    }

    fn matches_reviewed(&self, reviewed: &RustSecAdvisoryId) -> bool {
        matches!(self, Self::RustSec(id) if id == reviewed)
    }
}

impl std::fmt::Display for AdvisoryFindingId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RustSec(id) => write!(formatter, "{id}"),
            Self::Unnormalised(id) => write!(formatter, "{id}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoDenyAdvisoryReport {
    findings: Vec<AdvisoryFinding>,
    summary_counts: Vec<CargoDenySummaryCount>,
    no_advisory_diagnostics: Vec<CargoDenyNoAdvisoryDiagnostic>,
}

impl CargoDenyAdvisoryReport {
    pub fn findings(&self) -> &[AdvisoryFinding] {
        &self.findings
    }

    pub fn summary_counts(&self) -> &[CargoDenySummaryCount] {
        &self.summary_counts
    }

    pub fn non_advisory_error_counts(&self) -> Vec<&CargoDenySummaryCount> {
        self.summary_counts
            .iter()
            .filter(|count| {
                count.check() != CargoDenyCheck::Advisories.as_str() && count.errors() > 0
            })
            .collect()
    }

    pub fn no_advisory_diagnostics(&self) -> &[CargoDenyNoAdvisoryDiagnostic] {
        &self.no_advisory_diagnostics
    }

    fn summary_count_for(&self, check: CargoDenyCheck) -> Option<&CargoDenySummaryCount> {
        self.summary_counts
            .iter()
            .find(|count| count.check() == check.as_str())
    }

    fn has_unenumerated_advisory_errors(&self) -> bool {
        self.summary_count_for(CargoDenyCheck::Advisories)
            .is_some_and(|count| count.errors() > 0)
            && self.findings.is_empty()
            && self
                .no_advisory_diagnostics
                .iter()
                .all(CargoDenyNoAdvisoryDiagnostic::is_known_benign)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoDenySummaryCount {
    check: String,
    errors: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoDenyNoAdvisoryDiagnostic {
    line: usize,
    severity: Option<String>,
    code: Option<String>,
}

impl CargoDenyNoAdvisoryDiagnostic {
    pub fn line(&self) -> usize {
        self.line
    }

    pub fn severity(&self) -> Option<&str> {
        self.severity.as_deref()
    }

    pub fn code(&self) -> Option<&str> {
        self.code.as_deref()
    }

    fn is_known_benign(&self) -> bool {
        matches!(self.severity(), Some("warning" | "note" | "help"))
    }
}

impl CargoDenySummaryCount {
    pub fn check(&self) -> &str {
        &self.check
    }

    pub fn errors(&self) -> u64 {
        self.errors
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoAuditAdvisoryReport {
    findings: Vec<AdvisoryFinding>,
    settings_ignore: Vec<String>,
    idless_warnings: usize,
}

impl CargoAuditAdvisoryReport {
    pub fn findings(&self) -> &[AdvisoryFinding] {
        &self.findings
    }

    pub fn settings_ignore(&self) -> &[String] {
        &self.settings_ignore
    }

    pub fn idless_warnings(&self) -> usize {
        self.idless_warnings
    }
}

/// Whether a semver requirement can resolve to any release in the advisory's
/// patched set. Decided exactly, by interval arithmetic: every Cargo
/// requirement op describes a contiguous release interval, a comma
/// requirement is an interval intersection, and a patched list is an
/// interval union — so overlap is decidable without probing versions.
/// Pre-release comparators and unparseable requirements are `Indeterminate`
/// rather than guessed, because semver pre-release matching is not
/// interval-shaped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PatchedOverlap {
    AdmitsPatched,
    ExcludesPatched,
    Indeterminate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct VersionTriple {
    major: u64,
    minor: u64,
    patch: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VersionBound {
    version: VersionTriple,
    inclusive: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VersionInterval {
    lower: VersionBound,
    upper: Option<VersionBound>,
}

impl VersionInterval {
    fn all() -> Self {
        Self {
            lower: VersionBound {
                version: VersionTriple {
                    major: 0,
                    minor: 0,
                    patch: 0,
                },
                inclusive: true,
            },
            upper: None,
        }
    }

    fn intersect(self, other: Self) -> Option<Self> {
        let lower = if (other.lower.version, !other.lower.inclusive)
            > (self.lower.version, !self.lower.inclusive)
        {
            other.lower
        } else {
            self.lower
        };
        let upper = match (self.upper, other.upper) {
            (None, None) => None,
            (Some(upper), None) | (None, Some(upper)) => Some(upper),
            (Some(left), Some(right)) => {
                if (left.version, left.inclusive) < (right.version, right.inclusive) {
                    Some(left)
                } else {
                    Some(right)
                }
            }
        };

        match upper {
            None => Some(Self { lower, upper }),
            Some(bound) => {
                let non_empty = lower.version < bound.version
                    || (lower.version == bound.version && lower.inclusive && bound.inclusive);
                non_empty.then_some(Self { lower, upper })
            }
        }
    }
}

fn comparator_interval(comparator: &semver::Comparator) -> Option<VersionInterval> {
    if !comparator.pre.is_empty() {
        return None;
    }

    let major = comparator.major;
    let minor = comparator.minor;
    let patch = comparator.patch;
    let base = VersionTriple {
        major,
        minor: minor.unwrap_or(0),
        patch: patch.unwrap_or(0),
    };
    let next_major = VersionTriple {
        major: major.checked_add(1)?,
        minor: 0,
        patch: 0,
    };
    let next_minor = minor.map(|minor| {
        Some(VersionTriple {
            major,
            minor: minor.checked_add(1)?,
            patch: 0,
        })
    });
    let next_patch = patch.map(|patch| {
        Some(VersionTriple {
            major,
            minor: minor.unwrap_or(0),
            patch: patch.checked_add(1)?,
        })
    });

    let inclusive_from = |version| VersionBound {
        version,
        inclusive: true,
    };
    let exclusive_to = |version| VersionBound {
        version,
        inclusive: false,
    };
    let bounded = |lower, upper| VersionInterval {
        lower,
        upper: Some(upper),
    };
    let unbounded = |lower| VersionInterval { lower, upper: None };

    // Cargo requirement semantics per op, over release versions only:
    // partial comparators (`=1.2`, `>1`, `<=1.2`) cover the whole omitted
    // component range, exactly as the semver crate matches them.
    Some(match comparator.op {
        semver::Op::Exact => match (minor, patch) {
            (Some(_), Some(_)) => bounded(
                inclusive_from(base),
                VersionBound {
                    version: base,
                    inclusive: true,
                },
            ),
            (Some(_), None) => bounded(inclusive_from(base), exclusive_to(next_minor??)),
            (None, _) => bounded(inclusive_from(base), exclusive_to(next_major)),
        },
        semver::Op::Greater => match (minor, patch) {
            (Some(_), Some(_)) => VersionInterval {
                lower: VersionBound {
                    version: base,
                    inclusive: false,
                },
                upper: None,
            },
            (Some(_), None) => unbounded(inclusive_from(next_minor??)),
            (None, _) => unbounded(inclusive_from(next_major)),
        },
        semver::Op::GreaterEq => unbounded(inclusive_from(base)),
        semver::Op::Less => bounded(
            inclusive_from(VersionTriple {
                major: 0,
                minor: 0,
                patch: 0,
            }),
            exclusive_to(base),
        ),
        semver::Op::LessEq => match (minor, patch) {
            (Some(_), Some(_)) => bounded(
                inclusive_from(VersionTriple {
                    major: 0,
                    minor: 0,
                    patch: 0,
                }),
                VersionBound {
                    version: base,
                    inclusive: true,
                },
            ),
            (Some(_), None) => bounded(
                inclusive_from(VersionTriple {
                    major: 0,
                    minor: 0,
                    patch: 0,
                }),
                exclusive_to(next_minor??),
            ),
            (None, _) => bounded(
                inclusive_from(VersionTriple {
                    major: 0,
                    minor: 0,
                    patch: 0,
                }),
                exclusive_to(next_major),
            ),
        },
        semver::Op::Tilde => match (minor, patch) {
            (Some(_), _) => bounded(inclusive_from(base), exclusive_to(next_minor??)),
            (None, _) => bounded(inclusive_from(base), exclusive_to(next_major)),
        },
        semver::Op::Caret => {
            let upper = if major > 0 || minor.is_none() {
                next_major
            } else if base.minor > 0 || patch.is_none() {
                VersionTriple {
                    major,
                    minor: base.minor.checked_add(1)?,
                    patch: 0,
                }
            } else {
                next_patch??
            };
            bounded(inclusive_from(base), exclusive_to(upper))
        }
        semver::Op::Wildcard => match minor {
            Some(_) => bounded(inclusive_from(base), exclusive_to(next_minor??)),
            None => bounded(inclusive_from(base), exclusive_to(next_major)),
        },
        _ => return None,
    })
}

fn requirement_interval(requirement: &str) -> Option<VersionInterval> {
    let parsed = semver::VersionReq::parse(requirement).ok()?;
    let mut interval = VersionInterval::all();
    for comparator in &parsed.comparators {
        interval = interval.intersect(comparator_interval(comparator)?)?;
    }

    Some(interval)
}

fn requirement_patched_overlap(requirement: &str, patched_versions: &[String]) -> PatchedOverlap {
    let Some(parsed) = semver::VersionReq::parse(requirement)
        .ok()
        .filter(|parsed| {
            parsed
                .comparators
                .iter()
                .all(|comparator| comparator.pre.is_empty())
        })
    else {
        return PatchedOverlap::Indeterminate;
    };
    let mut requirement_interval_value = VersionInterval::all();
    for comparator in &parsed.comparators {
        let Some(interval) = comparator_interval(comparator) else {
            return PatchedOverlap::Indeterminate;
        };
        match requirement_interval_value.intersect(interval) {
            Some(intersection) => requirement_interval_value = intersection,
            // A self-contradictory requirement admits nothing, patched or
            // otherwise; that is exclusion, not uncertainty.
            None => return PatchedOverlap::ExcludesPatched,
        }
    }

    let mut any_overlap = false;
    for patched in patched_versions {
        let Some(patched_interval) = requirement_interval(patched) else {
            return PatchedOverlap::Indeterminate;
        };
        if requirement_interval_value
            .intersect(patched_interval)
            .is_some()
        {
            any_overlap = true;
        }
    }

    if any_overlap {
        PatchedOverlap::AdmitsPatched
    } else {
        PatchedOverlap::ExcludesPatched
    }
}

/// One resolved parent whose declared requirement provably cannot reach any
/// patched release of the vulnerable crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvisoryRemediationBlocker {
    parent: ExactCrateSpec,
    requirement: String,
}

impl AdvisoryRemediationBlocker {
    pub fn parent(&self) -> &ExactCrateSpec {
        &self.parent
    }

    pub fn requirement(&self) -> &str {
        &self.requirement
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvisoryRemediation {
    kind: AdvisoryRemediationKind,
    patched_versions: Vec<String>,
    target_crate: String,
    nearest_parent: Option<String>,
    command_hint: Option<String>,
    blockers: Option<Vec<AdvisoryRemediationBlocker>>,
}

impl AdvisoryRemediation {
    pub fn kind(&self) -> AdvisoryRemediationKind {
        self.kind
    }

    pub fn patched_versions(&self) -> &[String] {
        &self.patched_versions
    }

    pub fn target_crate(&self) -> &str {
        &self.target_crate
    }

    pub fn nearest_parent(&self) -> Option<&str> {
        self.nearest_parent.as_deref()
    }

    pub fn command_hint(&self) -> Option<&str> {
        self.command_hint.as_deref()
    }

    /// `None` when the requirement-edge analysis could not run or was
    /// indeterminate; `Some(&[])` when it ran and proved no parent caps the
    /// patched range; non-empty when the named parents provably cap it.
    pub fn blockers(&self) -> Option<&[AdvisoryRemediationBlocker]> {
        self.blockers.as_deref()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvisoryRemediationKind {
    DirectPinnedEdit,
    DirectUpdate,
    TransitiveUpdate,
    TransitiveBump,
}

impl AdvisoryRemediationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DirectPinnedEdit => "direct-pinned-edit",
            Self::DirectUpdate => "direct-update",
            Self::TransitiveUpdate => "transitive-update",
            Self::TransitiveBump => "transitive-bump",
        }
    }
}

pub fn advisory_remediation(
    finding: &AdvisoryFinding,
    manifest_requirements: &[CargoManifestDirectRequirement],
    workspace_requirements: &[CargoManifestDirectRequirement],
    dependency_path: Option<&MetadataDependencyPath>,
    requirement_edges: Option<&[MetadataRequirementEdge]>,
) -> Option<AdvisoryRemediation> {
    let patched_versions = finding.details().patched_versions();
    if patched_versions.is_empty() {
        return None;
    }

    let crate_name = finding.package().crate_name();
    let edges = requirement_edges.filter(|edges| !edges.is_empty());

    // The resolve graph is version-precise and rename-resolved, so when
    // requirement edges are available they outrank manifest-name matching: a
    // workspace-member edge onto this exact package *is* the direct case.
    let member_edges = edges
        .map(|edges| {
            edges
                .iter()
                .filter(|edge| edge.parent_is_workspace_member())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let is_direct;
    let exact_pinned;
    if !member_edges.is_empty() {
        is_direct = true;
        let known_member_requirements = member_edges
            .iter()
            .filter_map(|edge| edge.requirement())
            .collect::<Vec<_>>();
        exact_pinned = if known_member_requirements.is_empty() {
            direct_requirement_summary(
                finding.package(),
                manifest_requirements,
                workspace_requirements,
            )
            .is_some_and(|summary| summary.exact_pinned)
        } else {
            known_member_requirements
                .iter()
                .any(|requirement| parse_exact_version_requirement(crate_name, requirement).is_ok())
        };
    } else if edges.is_some() {
        is_direct = false;
        exact_pinned = false;
    } else {
        let summary = direct_requirement_summary(
            finding.package(),
            manifest_requirements,
            workspace_requirements,
        );
        is_direct = summary.is_some();
        exact_pinned = summary.is_some_and(|summary| summary.exact_pinned);
    }

    if is_direct {
        if exact_pinned {
            return Some(AdvisoryRemediation {
                kind: AdvisoryRemediationKind::DirectPinnedEdit,
                patched_versions: patched_versions.to_vec(),
                target_crate: crate_name.to_owned(),
                nearest_parent: None,
                command_hint: None,
                blockers: None,
            });
        }

        return Some(AdvisoryRemediation {
            kind: AdvisoryRemediationKind::DirectUpdate,
            patched_versions: patched_versions.to_vec(),
            target_crate: crate_name.to_owned(),
            nearest_parent: None,
            command_hint: Some(format!("cargo barbican update {crate_name}@<version>")),
            blockers: None,
        });
    }

    let nearest_parent = dependency_path
        .and_then(|path| nearest_parent_crate(path, finding.package()))
        .map(str::to_owned);

    if let Some(edges) = edges {
        match analyse_requirement_edges(edges, patched_versions) {
            RequirementEdgeAnalysis::Capped(blockers) => {
                let primary = blockers
                    .iter()
                    .position(|blocker| {
                        Some(blocker.parent().crate_name()) == nearest_parent.as_deref()
                    })
                    .unwrap_or(0);
                let primary_crate = blockers[primary].parent().crate_name().to_owned();
                let primary_pinned = direct_requirement_summary(
                    blockers[primary].parent(),
                    manifest_requirements,
                    workspace_requirements,
                )
                .is_some_and(|summary| summary.exact_pinned);
                let command_hint = (!primary_pinned)
                    .then(|| format!("cargo barbican update {primary_crate}@<version>"));
                return Some(AdvisoryRemediation {
                    kind: AdvisoryRemediationKind::TransitiveBump,
                    patched_versions: patched_versions.to_vec(),
                    target_crate: primary_crate,
                    nearest_parent,
                    command_hint,
                    blockers: Some(blockers),
                });
            }
            RequirementEdgeAnalysis::Uncapped => {
                return Some(AdvisoryRemediation {
                    kind: AdvisoryRemediationKind::TransitiveUpdate,
                    patched_versions: patched_versions.to_vec(),
                    target_crate: crate_name.to_owned(),
                    nearest_parent,
                    command_hint: Some(format!("cargo barbican update {crate_name}@<version>")),
                    blockers: Some(Vec::new()),
                });
            }
            RequirementEdgeAnalysis::Indeterminate => {}
        }
    }

    let target_crate = nearest_parent
        .clone()
        .unwrap_or_else(|| crate_name.to_owned());
    let command_hint = nearest_parent
        .as_ref()
        .map(|parent| format!("cargo barbican update {parent}@<version>"));
    Some(AdvisoryRemediation {
        kind: AdvisoryRemediationKind::TransitiveBump,
        patched_versions: patched_versions.to_vec(),
        target_crate,
        nearest_parent,
        command_hint,
        blockers: None,
    })
}

enum RequirementEdgeAnalysis {
    Capped(Vec<AdvisoryRemediationBlocker>),
    Uncapped,
    Indeterminate,
}

/// A parent is a blocker when *any* of its declared requirements on the
/// vulnerable crate excludes every patched range: that declaration will keep
/// a vulnerable copy resolved no matter what else moves. Proving the crate
/// bumpable in place requires every edge to determinately admit a patched
/// release.
fn analyse_requirement_edges(
    edges: &[MetadataRequirementEdge],
    patched_versions: &[String],
) -> RequirementEdgeAnalysis {
    let mut blockers: Vec<AdvisoryRemediationBlocker> = Vec::new();
    let mut indeterminate = false;
    for edge in edges {
        let Some(requirement) = edge.requirement() else {
            indeterminate = true;
            continue;
        };
        match requirement_patched_overlap(requirement, patched_versions) {
            PatchedOverlap::ExcludesPatched => {
                if !blockers
                    .iter()
                    .any(|blocker| blocker.parent() == edge.parent())
                {
                    blockers.push(AdvisoryRemediationBlocker {
                        parent: edge.parent().clone(),
                        requirement: requirement.to_owned(),
                    });
                }
            }
            PatchedOverlap::AdmitsPatched => {}
            PatchedOverlap::Indeterminate => indeterminate = true,
        }
    }

    if !blockers.is_empty() {
        RequirementEdgeAnalysis::Capped(blockers)
    } else if indeterminate {
        RequirementEdgeAnalysis::Indeterminate
    } else {
        RequirementEdgeAnalysis::Uncapped
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirectRequirementSummary {
    exact_pinned: bool,
}

/// A manifest requirement only makes the *finding* direct when it can admit
/// the finding's resolved version. Matching by crate name alone classified a
/// capped transitive duplicate (for example a vulnerable `hashbrown 0.12`
/// beside a safe direct `hashbrown = "0.15"`) as direct, steering the
/// remediation at the already-safe copy.
fn direct_requirement_summary(
    package: &ExactCrateSpec,
    manifest_requirements: &[CargoManifestDirectRequirement],
    workspace_requirements: &[CargoManifestDirectRequirement],
) -> Option<DirectRequirementSummary> {
    let resolved_version = semver::Version::parse(package.version()).ok()?;
    let matching = manifest_requirements
        .iter()
        .filter(|requirement| requirement.name() == package.crate_name());

    let mut found = false;
    let mut exact_pinned = false;
    for requirement in matching {
        let Some(version_requirement) =
            effective_direct_requirement(requirement, workspace_requirements)
        else {
            continue;
        };
        let Ok(parsed_requirement) = semver::VersionReq::parse(version_requirement) else {
            continue;
        };
        if !parsed_requirement.matches(&resolved_version) {
            continue;
        }
        found = true;
        if parse_exact_version_requirement(package.crate_name(), version_requirement).is_ok() {
            exact_pinned = true;
        }
    }

    found.then_some(DirectRequirementSummary { exact_pinned })
}

fn effective_direct_requirement<'a>(
    requirement: &'a CargoManifestDirectRequirement,
    workspace_requirements: &'a [CargoManifestDirectRequirement],
) -> Option<&'a str> {
    if requirement.source_kind() == CargoDependencySourceKind::Workspace {
        workspace_requirements
            .iter()
            .find(|workspace| workspace.name() == requirement.name())
            .and_then(CargoManifestDirectRequirement::version_requirement)
            .or_else(|| requirement.version_requirement())
    } else {
        requirement.version_requirement()
    }
}

fn nearest_parent_crate<'a>(
    path: &'a MetadataDependencyPath,
    target: &ExactCrateSpec,
) -> Option<&'a str> {
    let packages = path.packages();
    if packages.last() != Some(target) || packages.len() < 3 {
        return None;
    }

    packages
        .get(packages.len() - 2)
        .map(ExactCrateSpec::crate_name)
}

pub fn parse_cargo_deny_json_lines(
    text: &str,
) -> Result<CargoDenyAdvisoryReport, AdvisoryParseError> {
    let mut findings = BTreeMap::new();
    let mut summary_counts = Vec::new();
    let mut no_advisory_diagnostics = Vec::new();
    let mut saw_summary = false;

    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }

        let value: serde_json::Value =
            serde_json::from_str(line).map_err(|source| AdvisoryParseError::JsonLine {
                line: index + 1,
                source,
            })?;
        let record_type = value
            .get("type")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| AdvisoryParseError::CargoDenyShape {
                reason: format!("line {} missing type", index + 1),
            })?;
        if saw_summary {
            return Err(AdvisoryParseError::CargoDenyShape {
                reason: format!("line {} follows terminal summary record", index + 1),
            });
        }

        match record_type {
            "summary" => {
                summary_counts = parse_cargo_deny_summary(index + 1, &value)?;
                saw_summary = true;
            }
            "diagnostic" => collect_cargo_deny_diagnostic(
                index + 1,
                &value,
                &mut findings,
                &mut no_advisory_diagnostics,
            )?,
            _ => {}
        }
    }

    if !saw_summary {
        return Err(AdvisoryParseError::CargoDenyMissingSummary);
    }

    Ok(CargoDenyAdvisoryReport {
        findings: findings.into_values().collect(),
        summary_counts,
        no_advisory_diagnostics,
    })
}

fn parse_cargo_deny_summary(
    line: usize,
    value: &serde_json::Value,
) -> Result<Vec<CargoDenySummaryCount>, AdvisoryParseError> {
    let fields = value
        .get("fields")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| AdvisoryParseError::CargoDenyShape {
            reason: format!("summary line {line} missing fields"),
        })?;
    fields
        .iter()
        .map(|(check, counts)| {
            let counts = counts
                .as_object()
                .ok_or_else(|| AdvisoryParseError::CargoDenyShape {
                    reason: format!("summary line {line} {check} is not an object"),
                })?;
            let errors = counts
                .get("errors")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| AdvisoryParseError::CargoDenyShape {
                    reason: format!("summary line {line} {check}.errors missing or invalid"),
                })?;
            Ok(CargoDenySummaryCount {
                check: check.to_owned(),
                errors,
            })
        })
        .collect()
}

fn collect_cargo_deny_diagnostic(
    line: usize,
    value: &serde_json::Value,
    findings: &mut BTreeMap<AdvisoryFindingKey, AdvisoryFinding>,
    no_advisory_diagnostics: &mut Vec<CargoDenyNoAdvisoryDiagnostic>,
) -> Result<(), AdvisoryParseError> {
    let fields = value
        .get("fields")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| AdvisoryParseError::CargoDenyShape {
            reason: format!("diagnostic line {line} missing fields"),
        })?;
    let Some(advisory) = fields.get("advisory") else {
        no_advisory_diagnostics.push(CargoDenyNoAdvisoryDiagnostic {
            line,
            severity: fields
                .get("severity")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            code: fields
                .get("code")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
        });
        return Ok(());
    };
    let advisory_id = advisory
        .get("id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| AdvisoryParseError::CargoDenyShape {
            reason: format!("diagnostic line {line} advisory missing id"),
        })?;
    let graphs = fields
        .get("graphs")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| AdvisoryParseError::CargoDenyShape {
            reason: format!("diagnostic line {line} advisory missing graphs"),
        })?;
    if graphs.is_empty() {
        return Err(AdvisoryParseError::CargoDenyShape {
            reason: format!("diagnostic line {line} advisory present but graphs empty"),
        });
    }

    for graph in graphs {
        let krate = graph
            .get("Krate")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| AdvisoryParseError::CargoDenyShape {
                reason: format!("diagnostic line {line} graph missing Krate"),
            })?;
        let name = krate
            .get("name")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| AdvisoryParseError::CargoDenyShape {
                reason: format!("diagnostic line {line} Krate missing name"),
            })?;
        let version = krate
            .get("version")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| AdvisoryParseError::CargoDenyShape {
                reason: format!("diagnostic line {line} Krate missing version"),
            })?;

        insert_finding(findings, finding_from_parts(advisory_id, name, version)?);
    }

    Ok(())
}

pub fn parse_cargo_audit_json(text: &str) -> Result<CargoAuditAdvisoryReport, AdvisoryParseError> {
    let raw: serde_json::Value =
        serde_json::from_str(text).map_err(AdvisoryParseError::CargoAuditJson)?;
    let vulnerabilities = raw
        .get("vulnerabilities")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| AdvisoryParseError::CargoAuditShape {
            reason: "missing vulnerabilities object".to_owned(),
        })?;
    let list = vulnerabilities
        .get("list")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| AdvisoryParseError::CargoAuditShape {
            reason: "missing vulnerabilities.list array".to_owned(),
        })?;
    let settings = raw
        .get("settings")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| AdvisoryParseError::CargoAuditShape {
            reason: "missing settings object".to_owned(),
        })?;
    let ignore = settings
        .get("ignore")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| AdvisoryParseError::CargoAuditShape {
            reason: "missing settings.ignore array".to_owned(),
        })?;
    let warnings = raw
        .get("warnings")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| AdvisoryParseError::CargoAuditShape {
            reason: "missing warnings object".to_owned(),
        })?;
    let mut findings = BTreeMap::new();
    let mut idless_warnings = 0;

    for vulnerability in list {
        let Some(finding) = cargo_audit_finding(
            vulnerability,
            "vulnerabilities.list entry",
            MissingAdvisory::Error,
        )?
        else {
            continue;
        };
        insert_finding(&mut findings, finding);
    }
    for (kind, entries) in warnings {
        let entries = entries
            .as_array()
            .ok_or_else(|| AdvisoryParseError::CargoAuditShape {
                reason: format!("warnings.{kind} is not an array"),
            })?;
        for entry in entries {
            if entry.get("advisory").is_none_or(serde_json::Value::is_null) {
                idless_warnings += 1;
            }
            let Some(finding) = cargo_audit_finding(
                entry,
                &format!("warnings.{kind} entry"),
                MissingAdvisory::Skip,
            )?
            else {
                continue;
            };
            insert_finding(&mut findings, finding);
        }
    }
    let settings_ignore = ignore
        .iter()
        .map(|ignored| {
            ignored
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| AdvisoryParseError::CargoAuditShape {
                    reason: "settings.ignore entry is not a string".to_owned(),
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(CargoAuditAdvisoryReport {
        findings: findings.into_values().collect(),
        settings_ignore,
        idless_warnings,
    })
}

fn cargo_audit_finding(
    value: &serde_json::Value,
    context: &str,
    missing_advisory: MissingAdvisory,
) -> Result<Option<AdvisoryFinding>, AdvisoryParseError> {
    let entry = value
        .as_object()
        .ok_or_else(|| AdvisoryParseError::CargoAuditShape {
            reason: format!("{context} is not an object"),
        })?;
    let Some(advisory) = entry.get("advisory").filter(|advisory| !advisory.is_null()) else {
        return match missing_advisory {
            MissingAdvisory::Skip => Ok(None),
            MissingAdvisory::Error => Err(AdvisoryParseError::CargoAuditShape {
                reason: format!("{context} advisory missing id"),
            }),
        };
    };
    let advisory = advisory
        .as_object()
        .ok_or_else(|| AdvisoryParseError::CargoAuditShape {
            reason: format!("{context} advisory is not an object"),
        })?;
    let advisory_id = advisory
        .get("id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| AdvisoryParseError::CargoAuditShape {
            reason: format!("{context} advisory missing id"),
        })?;
    let details = cargo_audit_finding_details(entry, advisory)?;
    let package = entry
        .get("package")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| AdvisoryParseError::CargoAuditShape {
            reason: format!("{context} missing package object"),
        })?;
    let name = package
        .get("name")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| AdvisoryParseError::CargoAuditShape {
            reason: format!("{context} package missing name"),
        })?;
    let version = package
        .get("version")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| AdvisoryParseError::CargoAuditShape {
            reason: format!("{context} package missing version"),
        })?;

    let mut finding = finding_from_parts(advisory_id, name, version)?;
    finding.details = details;

    Ok(Some(finding))
}

fn cargo_audit_finding_details(
    entry: &serde_json::Map<String, serde_json::Value>,
    advisory: &serde_json::Map<String, serde_json::Value>,
) -> Result<AdvisoryFindingDetails, AdvisoryParseError> {
    let title = optional_string(advisory, "title");
    let severity =
        optional_string(advisory, "severity").or_else(|| optional_string(entry, "severity"));
    let informational = optional_string(advisory, "informational");
    let cvss = advisory.get("cvss").and_then(cvss_value);
    let patched_versions = entry
        .get("versions")
        .and_then(serde_json::Value::as_object)
        .and_then(|versions| versions.get("patched"))
        .map(parse_patched_versions)
        .transpose()?
        .unwrap_or_default();

    Ok(AdvisoryFindingDetails {
        title,
        severity,
        cvss,
        informational,
        patched_versions,
    })
}

fn optional_string(
    fields: &serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> Option<String> {
    fields
        .get(name)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

fn cvss_value(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(value) => Some(value.clone()),
        serde_json::Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn parse_patched_versions(value: &serde_json::Value) -> Result<Vec<String>, AdvisoryParseError> {
    let patched = value
        .as_array()
        .ok_or_else(|| AdvisoryParseError::CargoAuditShape {
            reason: "versions.patched is not an array".to_owned(),
        })?;
    patched
        .iter()
        .map(|version| {
            version
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| AdvisoryParseError::CargoAuditShape {
                    reason: "versions.patched entry is not a string".to_owned(),
                })
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MissingAdvisory {
    Error,
    Skip,
}

fn finding_from_parts(
    advisory_id: &str,
    crate_name: &str,
    version: &str,
) -> Result<AdvisoryFinding, AdvisoryParseError> {
    Ok(AdvisoryFinding {
        advisory_id: AdvisoryFindingId::parse(advisory_id),
        package: ExactCrateSpec::from_parts(crate_name, version)
            .map_err(AdvisoryParseError::InvalidPackageSpec)?,
        details: AdvisoryFindingDetails::default(),
    })
}

fn insert_finding(
    findings: &mut BTreeMap<AdvisoryFindingKey, AdvisoryFinding>,
    finding: AdvisoryFinding,
) {
    findings
        .entry(AdvisoryFindingKey::from(&finding))
        .and_modify(|existing| existing.merge_missing_details_from(&finding))
        .or_insert(finding);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvisoryReconciliationReport {
    dispositions: Vec<AdvisoryDisposition>,
}

impl AdvisoryReconciliationReport {
    pub fn dispositions(&self) -> &[AdvisoryDisposition] {
        &self.dispositions
    }

    pub fn accepted_exceptions(&self) -> Vec<&ReviewedAdvisoryException> {
        self.dispositions
            .iter()
            .filter_map(AdvisoryDisposition::accepted_exception)
            .collect()
    }

    pub fn is_success(&self) -> bool {
        self.dispositions
            .iter()
            .all(|disposition| matches!(disposition, AdvisoryDisposition::Accepted { .. }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdvisoryDisposition {
    Accepted {
        finding: AdvisoryFinding,
        exception: ReviewedAdvisoryException,
    },
    Expired {
        finding: AdvisoryFinding,
        exception: ReviewedAdvisoryException,
    },
    Unreviewed {
        finding: AdvisoryFinding,
    },
}

impl AdvisoryDisposition {
    pub fn finding(&self) -> &AdvisoryFinding {
        match self {
            Self::Accepted { finding, .. }
            | Self::Expired { finding, .. }
            | Self::Unreviewed { finding } => finding,
        }
    }

    pub fn accepted_exception(&self) -> Option<&ReviewedAdvisoryException> {
        match self {
            Self::Accepted { exception, .. } => Some(exception),
            Self::Expired { .. } | Self::Unreviewed { .. } => None,
        }
    }
}

pub fn reconcile_advisory_findings(
    findings: &[AdvisoryFinding],
    exceptions: &[&ReviewedAdvisoryException],
    now: OffsetDateTime,
) -> AdvisoryReconciliationReport {
    let now_date = now.date();
    let dispositions = findings
        .iter()
        .cloned()
        .map(|finding| {
            // First-match is deterministic because reviewed-targets parsing
            // rejects duplicate (RustSec advisory id, exact crate spec) bindings.
            let exception = exceptions.iter().find(|exception| {
                finding
                    .advisory_id()
                    .matches_reviewed(exception.advisory_id())
                    && finding.package() == exception.spec()
            });

            match exception {
                Some(exception) if exception.review_by() >= now_date => {
                    AdvisoryDisposition::Accepted {
                        finding,
                        exception: (*exception).clone(),
                    }
                }
                Some(exception) => AdvisoryDisposition::Expired {
                    finding,
                    exception: (*exception).clone(),
                },
                None => AdvisoryDisposition::Unreviewed { finding },
            }
        })
        .collect();

    AdvisoryReconciliationReport { dispositions }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvisoryAuditOutcome {
    reconciliation: AdvisoryReconciliationReport,
    completeness_failures: Vec<AdvisoryAuditCompletenessFailure>,
    cargo_deny_no_advisory_errors: Vec<CargoDenyNoAdvisoryDiagnostic>,
    cargo_deny_non_advisory_errors: Vec<CargoDenySummaryCount>,
    cargo_audit_settings_ignore: Vec<String>,
    cargo_audit_idless_warnings: usize,
}

impl AdvisoryAuditOutcome {
    pub fn reconciliation(&self) -> &AdvisoryReconciliationReport {
        &self.reconciliation
    }

    pub fn accepted_exceptions(&self) -> Vec<&ReviewedAdvisoryException> {
        self.reconciliation.accepted_exceptions()
    }

    pub fn completeness_failures(&self) -> &[AdvisoryAuditCompletenessFailure] {
        &self.completeness_failures
    }

    pub fn cargo_deny_no_advisory_errors(&self) -> &[CargoDenyNoAdvisoryDiagnostic] {
        &self.cargo_deny_no_advisory_errors
    }

    pub fn cargo_deny_non_advisory_errors(&self) -> &[CargoDenySummaryCount] {
        &self.cargo_deny_non_advisory_errors
    }

    pub fn cargo_audit_settings_ignore(&self) -> &[String] {
        &self.cargo_audit_settings_ignore
    }

    pub fn cargo_audit_idless_warnings(&self) -> usize {
        self.cargo_audit_idless_warnings
    }

    pub fn is_success(&self) -> bool {
        self.reconciliation.is_success()
            && self.completeness_failures.is_empty()
            && self.cargo_deny_no_advisory_errors.is_empty()
            && self.cargo_deny_non_advisory_errors.is_empty()
            && self.cargo_audit_settings_ignore.is_empty()
            && self.cargo_audit_idless_warnings == 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdvisoryAuditCompletenessFailure {
    MissingCargoDenyReport,
    MissingCargoAuditReport,
    MissingCargoDenySummaryCheck { check: CargoDenyCheck },
    CargoDenyAdvisoryErrorsUnenumerated,
}

pub fn evaluate_advisory_audit(
    scanner: LockfileAdvisoryScanner,
    cargo_deny_checks: &[CargoDenyCheck],
    cargo_deny_report: Option<&CargoDenyAdvisoryReport>,
    cargo_audit_report: Option<&CargoAuditAdvisoryReport>,
    exceptions: &[&ReviewedAdvisoryException],
    now: OffsetDateTime,
) -> AdvisoryAuditOutcome {
    let mut findings = BTreeMap::new();
    let mut completeness_failures = Vec::new();
    let mut cargo_deny_no_advisory_errors = Vec::new();
    let mut cargo_deny_non_advisory_errors = Vec::new();
    let mut cargo_audit_settings_ignore = Vec::new();
    let mut cargo_audit_idless_warnings = 0;

    if !cargo_deny_checks.is_empty() {
        match cargo_deny_report {
            Some(report) => {
                for finding in report.findings() {
                    insert_finding(&mut findings, finding.clone());
                }
                cargo_deny_no_advisory_errors.extend(
                    report
                        .no_advisory_diagnostics()
                        .iter()
                        .filter(|diagnostic| !diagnostic.is_known_benign())
                        .cloned(),
                );
                cargo_deny_non_advisory_errors
                    .extend(report.non_advisory_error_counts().into_iter().cloned());
                if report.has_unenumerated_advisory_errors() {
                    completeness_failures.push(
                        AdvisoryAuditCompletenessFailure::CargoDenyAdvisoryErrorsUnenumerated,
                    );
                }
                for check in cargo_deny_checks {
                    if report.summary_count_for(*check).is_none() {
                        completeness_failures.push(
                            AdvisoryAuditCompletenessFailure::MissingCargoDenySummaryCheck {
                                check: *check,
                            },
                        );
                    }
                }
            }
            None => {
                completeness_failures.push(AdvisoryAuditCompletenessFailure::MissingCargoDenyReport)
            }
        }
    }
    if matches!(
        scanner,
        LockfileAdvisoryScanner::CargoAudit | LockfileAdvisoryScanner::Both
    ) {
        match cargo_audit_report {
            Some(report) => {
                for finding in report.findings() {
                    insert_finding(&mut findings, finding.clone());
                }
                cargo_audit_settings_ignore.extend(report.settings_ignore().iter().cloned());
                cargo_audit_idless_warnings += report.idless_warnings();
            }
            None => completeness_failures
                .push(AdvisoryAuditCompletenessFailure::MissingCargoAuditReport),
        }
    }

    let findings = findings.into_values().collect::<Vec<_>>();
    AdvisoryAuditOutcome {
        reconciliation: reconcile_advisory_findings(&findings, exceptions, now),
        completeness_failures,
        cargo_deny_no_advisory_errors,
        cargo_deny_non_advisory_errors,
        cargo_audit_settings_ignore,
        cargo_audit_idless_warnings,
    }
}

#[derive(Debug, Error)]
pub enum AdvisoryParseError {
    #[error("unable to parse cargo-deny JSON line {line}: {source}")]
    JsonLine {
        line: usize,
        #[source]
        source: serde_json::Error,
    },
    #[error("cargo-deny JSON output is incomplete: missing terminal summary record")]
    CargoDenyMissingSummary,
    #[error("cargo-deny JSON output has unsupported shape: {reason}")]
    CargoDenyShape { reason: String },
    #[error("unable to parse cargo-audit JSON: {0}")]
    CargoAuditJson(#[source] serde_json::Error),
    #[error("cargo-audit JSON output has unsupported shape: {reason}")]
    CargoAuditShape { reason: String },
    #[error("scanner advisory package is not an exact crate spec: {0}")]
    InvalidPackageSpec(#[source] ExactCrateSpecError),
}

#[cfg(test)]
mod tests {
    use super::{
        AdvisoryAuditCompletenessFailure, AdvisoryAuditOutcome, AdvisoryDisposition,
        AdvisoryFinding, AdvisoryFindingId, AdvisoryRemediationKind, advisory_remediation,
        evaluate_advisory_audit, parse_cargo_audit_json, parse_cargo_deny_json_lines,
        reconcile_advisory_findings,
    };
    use crate::{
        CargoAuditAdvisoryReport, CargoDenyAdvisoryReport, CargoDenyCheck, ExactCrateSpec,
        LockfileAdvisoryScanner, ReviewedAdvisoryException, ReviewedTargetsError,
        parse_cargo_metadata, parse_manifest_direct_requirements, parse_reviewed_targets_toml,
        parse_workspace_dependency_requirements, shortest_workspace_dependency_path,
    };
    use time::{Date, Month, OffsetDateTime};

    const CHECKSUM: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const CARGO_AUDIT_CLEAN: &str =
        include_str!("../tests/fixtures/advisory/cargo-audit-clean.json");
    const CARGO_AUDIT_WITH_FINDINGS: &str =
        include_str!("../tests/fixtures/advisory/cargo-audit-findings.json");
    const CARGO_DENY_CLEAN: &str =
        include_str!("../tests/fixtures/advisory/cargo-deny-clean.jsonl");
    const CARGO_DENY_BANS_FINDING: &str =
        include_str!("../tests/fixtures/advisory/cargo-deny-bans-finding.jsonl");
    const CARGO_DENY_WITH_FINDINGS: &str =
        include_str!("../tests/fixtures/advisory/cargo-deny-findings.jsonl");

    #[test]
    fn remediation_targets_nearest_parent_for_transitive_findings() {
        let finding = remediation_finding();
        let manifest_requirements = direct_requirements("[dependencies]\nplist = \"1.9\"\n");
        let path = dependency_path_to_quick_xml();

        let remediation =
            advisory_remediation(&finding, &manifest_requirements, &[], Some(&path), None)
                .expect("patched transitive finding should have remediation");

        assert_eq!(remediation.kind(), AdvisoryRemediationKind::TransitiveBump);
        assert_eq!(remediation.target_crate(), "plist");
        assert_eq!(remediation.nearest_parent(), Some("plist"));
        assert_eq!(
            remediation.command_hint(),
            Some("cargo barbican update plist@<version>")
        );
        assert_eq!(remediation.patched_versions(), &[">=0.41.0".to_owned()]);
    }

    #[test]
    fn remediation_does_not_treat_workspace_root_as_transitive_parent() {
        let finding = remediation_finding_for("serde", "1.0.228", ">=1.0.229");
        let path = dependency_path_to_direct_serde();

        let remediation = advisory_remediation(&finding, &[], &[], Some(&path), None)
            .expect("patched finding should have generic transitive remediation");

        assert_eq!(remediation.kind(), AdvisoryRemediationKind::TransitiveBump);
        assert_eq!(remediation.target_crate(), "serde");
        assert_eq!(remediation.nearest_parent(), None);
        assert_eq!(remediation.command_hint(), None);
    }

    #[test]
    fn remediation_keeps_direct_exact_pins_as_manifest_edits() {
        let finding = remediation_finding_for("tauri", "2.11.2", ">=2.11.5");
        let manifest_requirements = direct_requirements("[dependencies]\ntauri = \"=2.11.2\"\n");

        let remediation = advisory_remediation(&finding, &manifest_requirements, &[], None, None)
            .expect("patched direct finding should have remediation");

        assert_eq!(
            remediation.kind(),
            AdvisoryRemediationKind::DirectPinnedEdit
        );
        assert_eq!(remediation.target_crate(), "tauri");
        assert_eq!(remediation.command_hint(), None);
    }

    #[test]
    fn remediation_treats_workspace_inherited_exact_pins_as_pinned() {
        let finding = remediation_finding_for("tauri", "2.11.2", ">=2.11.5");
        let manifest_requirements =
            direct_requirements("[dependencies]\ntauri = { workspace = true }\n");
        let workspace_requirements =
            workspace_requirements("[workspace.dependencies]\ntauri = \"=2.11.2\"\n");

        let remediation = advisory_remediation(
            &finding,
            &manifest_requirements,
            &workspace_requirements,
            None,
            None,
        )
        .expect("patched direct finding should have remediation");

        assert_eq!(
            remediation.kind(),
            AdvisoryRemediationKind::DirectPinnedEdit
        );
        assert_eq!(remediation.command_hint(), None);
    }

    #[test]
    fn remediation_suggests_update_for_direct_unpinned_findings() {
        let finding = remediation_finding_for("serde", "1.0.228", ">=1.0.229");
        let manifest_requirements = direct_requirements("[dependencies]\nserde = \"1\"\n");

        let remediation = advisory_remediation(&finding, &manifest_requirements, &[], None, None)
            .expect("patched direct finding should have remediation");

        assert_eq!(remediation.kind(), AdvisoryRemediationKind::DirectUpdate);
        assert_eq!(remediation.target_crate(), "serde");
        assert_eq!(
            remediation.command_hint(),
            Some("cargo barbican update serde@<version>")
        );
    }

    #[test]
    fn requirement_patched_overlap_decides_interval_overlap_exactly() {
        use super::{PatchedOverlap, requirement_patched_overlap};

        let cases: &[(&str, &[&str], PatchedOverlap)] = &[
            ("^0.39", &[">=0.40.0"], PatchedOverlap::ExcludesPatched),
            ("^0.39", &[">=0.39.5"], PatchedOverlap::AdmitsPatched),
            ("1", &[">=1.0.229"], PatchedOverlap::AdmitsPatched),
            ("=1.9.0", &[">=1.9.1"], PatchedOverlap::ExcludesPatched),
            ("~1.2", &[">=1.3.0"], PatchedOverlap::ExcludesPatched),
            (">1.2", &[">=1.3.0"], PatchedOverlap::AdmitsPatched),
            ("0.39.*", &[">=0.40.0"], PatchedOverlap::ExcludesPatched),
            ("*", &[">=0.40.0"], PatchedOverlap::AdmitsPatched),
            (
                ">=0.8, <0.9",
                &[">=0.8.26, <0.9.0", ">=1.0.3"],
                PatchedOverlap::AdmitsPatched,
            ),
            (
                ">=0.8, <0.8.26",
                &[">=0.8.26, <0.9.0", ">=1.0.3"],
                PatchedOverlap::ExcludesPatched,
            ),
            ("^0.0.3", &[">=0.0.4"], PatchedOverlap::ExcludesPatched),
            ("<=1.2", &[">=1.3.0"], PatchedOverlap::ExcludesPatched),
            ("1.0.0-alpha", &[">=1.0.0"], PatchedOverlap::Indeterminate),
            ("not-a-req", &[">=1.0.0"], PatchedOverlap::Indeterminate),
            ("^1", &["also-not-a-range"], PatchedOverlap::Indeterminate),
        ];
        for (requirement, patched, expected) in cases {
            let patched = patched
                .iter()
                .map(|range| (*range).to_owned())
                .collect::<Vec<_>>();
            assert_eq!(
                requirement_patched_overlap(requirement, &patched),
                *expected,
                "requirement {requirement:?} against {patched:?}"
            );
        }
    }

    #[test]
    fn remediation_names_the_provable_blocker_from_requirement_edges() {
        let finding = remediation_finding();
        let edges = quick_xml_requirement_edges("^0.39");
        let path = dependency_path_to_quick_xml();

        let remediation = advisory_remediation(&finding, &[], &[], Some(&path), Some(&edges))
            .expect("capped transitive finding should have remediation");

        assert_eq!(remediation.kind(), AdvisoryRemediationKind::TransitiveBump);
        assert_eq!(remediation.target_crate(), "plist");
        let blockers = remediation
            .blockers()
            .expect("blocker analysis should have completed");
        assert_eq!(blockers.len(), 1);
        assert_eq!(blockers[0].parent().to_string(), "plist@1.9.0");
        assert_eq!(blockers[0].requirement(), "^0.39");
        assert_eq!(
            remediation.command_hint(),
            Some("cargo barbican update plist@<version>")
        );
    }

    #[test]
    fn remediation_suggests_a_lockfile_update_when_no_parent_caps_the_patched_range() {
        let finding = remediation_finding_for("quick-xml", "0.39.4", ">=0.39.5");
        let edges = quick_xml_requirement_edges("^0.39");
        let path = dependency_path_to_quick_xml();

        let remediation = advisory_remediation(&finding, &[], &[], Some(&path), Some(&edges))
            .expect("uncapped transitive finding should have remediation");

        assert_eq!(
            remediation.kind(),
            AdvisoryRemediationKind::TransitiveUpdate
        );
        assert_eq!(remediation.target_crate(), "quick-xml");
        assert_eq!(remediation.blockers(), Some(&[][..]));
        assert_eq!(
            remediation.command_hint(),
            Some("cargo barbican update quick-xml@<version>")
        );
    }

    #[test]
    fn remediation_prefers_an_off_path_blocker_over_the_nearest_parent() {
        let finding = remediation_finding();
        let metadata = parse_cargo_metadata(
            r#"{
  "packages": [
    {"name": "root", "version": "0.1.0", "id": "path+file:///repo#root@0.1.0", "targets": [],
     "dependencies": [
       {"name": "plist", "req": ">=0.1"},
       {"name": "other-parent", "req": ">=0.1"}
     ]},
    {"name": "plist", "version": "1.9.0", "id": "registry+https://github.com/rust-lang/crates.io-index#plist@1.9.0", "targets": [],
     "dependencies": [{"name": "quick-xml", "req": ">=0.39"}]},
    {"name": "other-parent", "version": "0.5.0", "id": "registry+https://github.com/rust-lang/crates.io-index#other-parent@0.5.0", "targets": [],
     "dependencies": [{"name": "quick-xml", "req": "^0.39"}]},
    {"name": "quick-xml", "version": "0.39.4", "id": "registry+https://github.com/rust-lang/crates.io-index#quick-xml@0.39.4", "targets": []}
  ],
  "workspace_members": ["path+file:///repo#root@0.1.0"],
  "resolve": {
    "nodes": [
      {"id": "path+file:///repo#root@0.1.0", "deps": [
        {"name": "plist", "pkg": "registry+https://github.com/rust-lang/crates.io-index#plist@1.9.0"},
        {"name": "other_parent", "pkg": "registry+https://github.com/rust-lang/crates.io-index#other-parent@0.5.0"}
      ]},
      {"id": "registry+https://github.com/rust-lang/crates.io-index#plist@1.9.0", "deps": [
        {"name": "quick_xml", "pkg": "registry+https://github.com/rust-lang/crates.io-index#quick-xml@0.39.4"}
      ]},
      {"id": "registry+https://github.com/rust-lang/crates.io-index#other-parent@0.5.0", "deps": [
        {"name": "quick_xml", "pkg": "registry+https://github.com/rust-lang/crates.io-index#quick-xml@0.39.4"}
      ]},
      {"id": "registry+https://github.com/rust-lang/crates.io-index#quick-xml@0.39.4", "deps": []}
    ]
  }
}"#,
        )
        .expect("metadata should parse");
        let target = ExactCrateSpec::from_parts("quick-xml", "0.39.4").expect("spec should parse");
        let edges =
            crate::requirement_edges_onto(&metadata, &target).expect("edges should collect");
        let path = shortest_workspace_dependency_path(&metadata, &target)
            .expect("path lookup should succeed")
            .expect("path should exist");

        let remediation = advisory_remediation(&finding, &[], &[], Some(&path), Some(&edges))
            .expect("capped transitive finding should have remediation");

        assert_eq!(remediation.kind(), AdvisoryRemediationKind::TransitiveBump);
        // The nearest parent on the shortest path admits the patched range;
        // the true cap is the off-path parent.
        assert_eq!(remediation.target_crate(), "other-parent");
        let blockers = remediation.blockers().expect("analysis should complete");
        assert_eq!(blockers.len(), 1);
        assert_eq!(blockers[0].parent().to_string(), "other-parent@0.5.0");
    }

    #[test]
    fn remediation_classifies_direct_findings_from_workspace_member_edges() {
        let finding = remediation_finding_for("tauri", "2.11.2", ">=2.11.5");
        let metadata = parse_cargo_metadata(
            r#"{
  "packages": [
    {"name": "root", "version": "0.1.0", "id": "path+file:///repo#root@0.1.0", "targets": [],
     "dependencies": [{"name": "tauri", "req": "=2.11.2"}]},
    {"name": "tauri", "version": "2.11.2", "id": "registry+https://github.com/rust-lang/crates.io-index#tauri@2.11.2", "targets": []}
  ],
  "workspace_members": ["path+file:///repo#root@0.1.0"],
  "resolve": {
    "nodes": [
      {"id": "path+file:///repo#root@0.1.0", "deps": [
        {"name": "tauri", "pkg": "registry+https://github.com/rust-lang/crates.io-index#tauri@2.11.2"}
      ]},
      {"id": "registry+https://github.com/rust-lang/crates.io-index#tauri@2.11.2", "deps": []}
    ]
  }
}"#,
        )
        .expect("metadata should parse");
        let target = ExactCrateSpec::from_parts("tauri", "2.11.2").expect("spec should parse");
        let edges =
            crate::requirement_edges_onto(&metadata, &target).expect("edges should collect");

        // No manifest requirements supplied at all: the member edge alone
        // classifies the finding, immune to rename and dev-dependency
        // blindness in manifest-name matching.
        let remediation = advisory_remediation(&finding, &[], &[], None, Some(&edges))
            .expect("direct finding should have remediation");

        assert_eq!(
            remediation.kind(),
            AdvisoryRemediationKind::DirectPinnedEdit
        );
        assert_eq!(remediation.target_crate(), "tauri");
    }

    #[test]
    fn remediation_hedges_when_a_requirement_edge_is_indeterminate() {
        let finding = remediation_finding();
        let metadata = parse_cargo_metadata(
            r#"{
  "packages": [
    {"name": "root", "version": "0.1.0", "id": "path+file:///repo#root@0.1.0", "targets": []},
    {"name": "plist", "version": "1.9.0", "id": "registry+https://github.com/rust-lang/crates.io-index#plist@1.9.0", "targets": []},
    {"name": "quick-xml", "version": "0.39.4", "id": "registry+https://github.com/rust-lang/crates.io-index#quick-xml@0.39.4", "targets": []}
  ],
  "workspace_members": ["path+file:///repo#root@0.1.0"],
  "resolve": {
    "nodes": [
      {"id": "path+file:///repo#root@0.1.0", "deps": [
        {"name": "plist", "pkg": "registry+https://github.com/rust-lang/crates.io-index#plist@1.9.0"}
      ]},
      {"id": "registry+https://github.com/rust-lang/crates.io-index#plist@1.9.0", "deps": [
        {"name": "quick_xml", "pkg": "registry+https://github.com/rust-lang/crates.io-index#quick-xml@0.39.4"}
      ]},
      {"id": "registry+https://github.com/rust-lang/crates.io-index#quick-xml@0.39.4", "deps": []}
    ]
  }
}"#,
        )
        .expect("metadata should parse");
        let target = ExactCrateSpec::from_parts("quick-xml", "0.39.4").expect("spec should parse");
        let edges =
            crate::requirement_edges_onto(&metadata, &target).expect("edges should collect");
        let path = dependency_path_to_quick_xml();

        let remediation = advisory_remediation(&finding, &[], &[], Some(&path), Some(&edges))
            .expect("finding should keep the hedged remediation");

        assert_eq!(remediation.kind(), AdvisoryRemediationKind::TransitiveBump);
        assert_eq!(remediation.blockers(), None);
        assert_eq!(remediation.nearest_parent(), Some("plist"));
    }

    fn quick_xml_requirement_edges(plist_requirement: &str) -> Vec<crate::MetadataRequirementEdge> {
        let metadata = parse_cargo_metadata(&format!(
            r#"{{
  "packages": [
    {{"name": "root", "version": "0.1.0", "id": "path+file:///repo#root@0.1.0", "targets": [],
     "dependencies": [{{"name": "plist", "req": "^1.9"}}]}},
    {{"name": "plist", "version": "1.9.0", "id": "registry+https://github.com/rust-lang/crates.io-index#plist@1.9.0", "targets": [],
     "dependencies": [{{"name": "quick-xml", "req": "{plist_requirement}"}}]}},
    {{"name": "quick-xml", "version": "0.39.4", "id": "registry+https://github.com/rust-lang/crates.io-index#quick-xml@0.39.4", "targets": []}}
  ],
  "workspace_members": ["path+file:///repo#root@0.1.0"],
  "resolve": {{
    "nodes": [
      {{"id": "path+file:///repo#root@0.1.0", "deps": [
        {{"name": "plist", "pkg": "registry+https://github.com/rust-lang/crates.io-index#plist@1.9.0"}}
      ]}},
      {{"id": "registry+https://github.com/rust-lang/crates.io-index#plist@1.9.0", "deps": [
        {{"name": "quick_xml", "pkg": "registry+https://github.com/rust-lang/crates.io-index#quick-xml@0.39.4"}}
      ]}},
      {{"id": "registry+https://github.com/rust-lang/crates.io-index#quick-xml@0.39.4", "deps": []}}
    ]
  }}
}}"#,
        ))
        .expect("metadata should parse");
        let target = ExactCrateSpec::from_parts("quick-xml", "0.39.4").expect("spec should parse");

        crate::requirement_edges_onto(&metadata, &target).expect("edges should collect")
    }

    #[test]
    fn remediation_treats_version_mismatched_direct_requirement_as_transitive() {
        let finding = remediation_finding();
        let manifest_requirements = direct_requirements("[dependencies]\nquick-xml = \"0.41\"\n");
        let path = dependency_path_to_quick_xml();

        let remediation =
            advisory_remediation(&finding, &manifest_requirements, &[], Some(&path), None)
                .expect("patched transitive duplicate should have remediation");

        assert_eq!(remediation.kind(), AdvisoryRemediationKind::TransitiveBump);
        assert_eq!(remediation.target_crate(), "plist");
        assert_eq!(remediation.nearest_parent(), Some("plist"));
    }

    #[test]
    fn remediation_ignores_exact_pin_of_a_different_version() {
        let finding = remediation_finding_for("serde", "1.0.228", ">=1.0.229");
        let manifest_requirements = direct_requirements("[dependencies]\nserde = \"=1.0.300\"\n");

        let remediation = advisory_remediation(&finding, &manifest_requirements, &[], None, None)
            .expect("patched finding should have remediation");

        assert_eq!(remediation.kind(), AdvisoryRemediationKind::TransitiveBump);
        assert_eq!(remediation.target_crate(), "serde");
        assert_eq!(remediation.command_hint(), None);
    }

    #[test]
    fn remediation_is_absent_without_patched_versions() {
        let finding = AdvisoryFinding::new(
            AdvisoryFindingId::parse("RUSTSEC-2026-0001"),
            ExactCrateSpec::from_parts("serde", "1.0.228").expect("spec should parse"),
        );
        let manifest_requirements = direct_requirements("[dependencies]\nserde = \"1\"\n");

        assert!(advisory_remediation(&finding, &manifest_requirements, &[], None, None).is_none());
    }

    #[test]
    fn parses_cargo_deny_json_advisory_diagnostics() {
        let report = parse_cargo_deny_json_lines(
            r#"{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"RUSTSEC-2026-0001"},"graphs":[{"Krate":{"name":"serde","version":"1.0.228"}}]}}
{"type":"summary","fields":{"advisories":{"errors":1,"warnings":0,"helps":0,"notes":0}}}
"#
        )
        .expect("cargo-deny output should parse");

        assert_eq!(report.findings().len(), 1);
        assert_eq!(report.summary_counts().len(), 1);
        assert_eq!(report.summary_counts()[0].check(), "advisories");
        assert_eq!(report.summary_counts()[0].errors(), 1);
        assert_eq!(
            report.findings()[0].advisory_id().to_string(),
            "RUSTSEC-2026-0001"
        );
        assert_eq!(report.findings()[0].package().to_string(), "serde@1.0.228");
    }

    #[test]
    fn parses_cargo_audit_cvss_from_string_and_number_and_uses_it_as_risk_fallback() {
        for cvss_json in [r#""9.8""#, "9.8"] {
            let report = parse_cargo_audit_json(&format!(
                r#"{{
  "vulnerabilities": {{
    "found": true,
    "count": 1,
    "list": [
      {{
        "advisory": {{ "id": "RUSTSEC-2026-0001", "cvss": {cvss_json} }},
        "package": {{ "name": "serde", "version": "1.0.228" }},
        "versions": {{ "patched": [], "unaffected": [] }}
      }}
    ]
  }},
  "settings": {{ "ignore": [] }},
  "warnings": {{}}
}}"#,
            ))
            .expect("cargo-audit output should parse");

            let details = report.findings()[0].details();
            assert_eq!(details.cvss(), Some("9.8"));
            assert_eq!(details.severity(), None);
            assert_eq!(
                details.risk_label(),
                Some("9.8"),
                "risk label should fall back to cvss when severity and informational are absent"
            );
        }
    }

    #[test]
    fn parses_cargo_audit_json_advisories_and_settings_ignore() {
        let report = parse_cargo_audit_json(
            r#"{
  "vulnerabilities": {
    "found": true,
    "count": 1,
    "list": [
      {
        "advisory": {
          "id": "RUSTSEC-2026-0001",
          "title": "extra scanner metadata",
          "severity": "high"
        },
        "package": { "name": "serde", "version": "1.0.228" },
        "versions": { "patched": [">=1.0.229"], "unaffected": [] }
      }
    ]
  },
  "settings": { "ignore": ["RUSTSEC-2025-0001"], "target_arch": null },
  "warnings": {}
}"#,
        )
        .expect("cargo-audit output should parse");

        assert_eq!(report.findings().len(), 1);
        assert_eq!(
            report.findings()[0].advisory_id().to_string(),
            "RUSTSEC-2026-0001"
        );
        assert_eq!(report.findings()[0].package().to_string(), "serde@1.0.228");
        assert_eq!(
            report.findings()[0].details().title(),
            Some("extra scanner metadata")
        );
        assert_eq!(report.findings()[0].details().risk_label(), Some("high"));
        assert_eq!(
            report.findings()[0].details().patched_versions(),
            &[">=1.0.229".to_owned()]
        );
        assert_eq!(report.settings_ignore(), &["RUSTSEC-2025-0001".to_owned()]);
    }

    #[test]
    fn cargo_audit_merges_duplicate_findings_without_dropping_remediation_details() {
        let report = parse_cargo_audit_json(
            r#"{
  "vulnerabilities": {
    "found": true,
    "count": 1,
    "list": [
      {
        "advisory": {
          "id": "RUSTSEC-2026-0001",
          "title": "vulnerable parser"
        },
        "package": { "name": "serde", "version": "1.0.228" },
        "versions": { "patched": [">=1.0.229"], "unaffected": [] }
      }
    ]
  },
  "settings": { "ignore": [] },
  "warnings": {
    "unmaintained": [
      {
        "advisory": {
          "id": "RUSTSEC-2026-0001",
          "informational": "unmaintained"
        },
        "package": { "name": "serde", "version": "1.0.228" },
        "versions": { "patched": [], "unaffected": [] }
      }
    ]
  }
}"#,
        )
        .expect("cargo-audit output should parse");

        assert_eq!(report.findings().len(), 1);
        assert_eq!(
            report.findings()[0].details().title(),
            Some("vulnerable parser")
        );
        assert_eq!(
            report.findings()[0].details().risk_label(),
            Some("unmaintained")
        );
        assert_eq!(
            report.findings()[0].details().patched_versions(),
            &[">=1.0.229".to_owned()]
        );
    }

    #[test]
    fn cargo_deny_requires_terminal_summary_record() {
        let error = parse_cargo_deny_json_lines(
            r#"{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"RUSTSEC-2026-0001"},"graphs":[{"Krate":{"name":"serde","version":"1.0.228"}}]}}"#,
        )
        .expect_err("truncated cargo-deny output should fail");

        assert!(error.to_string().contains("missing terminal summary"));
    }

    #[test]
    fn cargo_deny_requires_summary_to_be_terminal_record() {
        let error = parse_cargo_deny_json_lines(
            r#"{"type":"summary","fields":{}}
{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"RUSTSEC-2026-0001"},"graphs":[{"Krate":{"name":"serde","version":"1.0.228"}}]}}
"#,
        )
        .expect_err("records after the summary should fail closed");

        assert!(error.to_string().contains("follows terminal summary"));
    }

    #[test]
    fn parses_clean_empty_scanner_outputs_as_empty_findings() {
        let deny_report = parse_cargo_deny_json_lines(r#"{"type":"summary","fields":{}}"#)
            .expect("cargo-deny summary-only output is a complete clean report");
        let audit_report = parse_cargo_audit_json(
            r#"{
  "vulnerabilities": { "found": false, "count": 0, "list": [] },
  "settings": {
    "target_arch": [],
    "target_os": [],
    "severity": null,
    "ignore": [],
    "informational_warnings": ["unmaintained", "unsound", "notice"]
  },
  "warnings": {}
}"#,
        )
        .expect("cargo-audit complete empty output should parse");

        assert!(deny_report.findings().is_empty());
        assert!(audit_report.findings().is_empty());
        assert!(audit_report.settings_ignore().is_empty());
    }

    #[test]
    fn parses_real_clean_scanner_fixtures() {
        let deny_report = parse_cargo_deny_json_lines(CARGO_DENY_CLEAN)
            .expect("real cargo-deny clean fixture should parse");
        let audit_report =
            parse_cargo_audit_json(CARGO_AUDIT_CLEAN).expect("real cargo-audit clean fixture");

        assert!(deny_report.findings().is_empty());
        assert!(audit_report.findings().is_empty());
        assert!(audit_report.settings_ignore().is_empty());
    }

    #[test]
    fn parses_real_advisory_scanner_fixtures() {
        let deny_report = parse_cargo_deny_json_lines(CARGO_DENY_WITH_FINDINGS)
            .expect("real cargo-deny advisory fixture should parse");
        let audit_report = parse_cargo_audit_json(CARGO_AUDIT_WITH_FINDINGS)
            .expect("real cargo-audit advisory fixture should parse");

        assert_eq!(deny_report.findings().len(), 2);
        assert_eq!(
            deny_report
                .findings()
                .iter()
                .map(|finding| (
                    finding.advisory_id().to_string(),
                    finding.package().to_string()
                ))
                .collect::<Vec<_>>(),
            vec![
                ("RUSTSEC-2021-0145".to_owned(), "atty@0.2.14".to_owned()),
                ("RUSTSEC-2024-0375".to_owned(), "atty@0.2.14".to_owned()),
            ]
        );
        assert_eq!(audit_report.findings().len(), 3);
        assert_eq!(
            audit_report
                .findings()
                .iter()
                .map(|finding| (
                    finding.advisory_id().to_string(),
                    finding.package().to_string()
                ))
                .collect::<Vec<_>>(),
            vec![
                ("RUSTSEC-2021-0145".to_owned(), "atty@0.2.14".to_owned()),
                (
                    "RUSTSEC-2023-0018".to_owned(),
                    "remove_dir_all@0.5.3".to_owned()
                ),
                ("RUSTSEC-2024-0375".to_owned(), "atty@0.2.14".to_owned()),
            ]
        );
        assert!(audit_report.settings_ignore().is_empty());
    }

    #[test]
    fn parses_real_cargo_deny_non_advisory_summary_errors() {
        let report = parse_cargo_deny_json_lines(CARGO_DENY_BANS_FINDING)
            .expect("real cargo-deny bans fixture should parse");

        assert!(report.findings().is_empty());
        assert_eq!(
            report
                .summary_counts()
                .iter()
                .map(|count| (count.check().to_owned(), count.errors()))
                .collect::<Vec<_>>(),
            vec![("advisories".to_owned(), 3), ("bans".to_owned(), 1)]
        );
        assert_eq!(
            report
                .non_advisory_error_counts()
                .iter()
                .map(|count| (count.check().to_owned(), count.errors()))
                .collect::<Vec<_>>(),
            vec![("bans".to_owned(), 1)]
        );
    }

    #[test]
    fn cargo_audit_requires_complete_top_level_object() {
        let error = parse_cargo_audit_json(r#"{"vulnerabilities":{"list":[]}}"#)
            .expect_err("truncated cargo-audit output should fail");

        assert!(error.to_string().contains("unsupported shape"));
        assert!(error.to_string().contains("missing settings object"));
    }

    #[test]
    fn cargo_audit_rejects_non_string_settings_ignore_entries() {
        let error = parse_cargo_audit_json(
            r#"{
  "vulnerabilities": { "found": false, "count": 0, "list": [] },
  "settings": { "ignore": [42] },
  "warnings": {}
}"#,
        )
        .expect_err("non-string ignore entries should fail closed");

        assert!(error.to_string().contains("settings.ignore entry"));
    }

    #[test]
    fn cargo_audit_warning_advisories_are_findings() {
        let report = parse_cargo_audit_json(
            r#"{
  "database": { "advisory-count": 1138 },
  "lockfile": { "dependency-count": 2 },
  "settings": {
    "target_arch": [],
    "target_os": [],
    "severity": null,
    "ignore": [],
    "informational_warnings": ["unmaintained", "unsound", "notice"]
  },
  "vulnerabilities": { "found": false, "count": 0, "list": [] },
  "warnings": {
    "unmaintained": [
      {
        "kind": "unmaintained",
        "package": {
          "name": "atty",
          "version": "0.2.14",
          "source": "registry+https://github.com/rust-lang/crates.io-index",
          "checksum": "d9b39be18770d11421cdb1b9947a45dd3f37e93092cbf377614828a319d5fee8"
        },
        "advisory": {
          "id": "RUSTSEC-2024-0375",
          "package": "atty",
          "title": "`atty` is unmaintained",
          "informational": "unmaintained"
        },
        "versions": { "patched": [], "unaffected": [] }
      }
    ],
    "yanked": [
      {
        "kind": "yanked",
        "package": { "name": "gone", "version": "1.2.3" }
      }
    ]
  }
}"#,
        )
        .expect("cargo-audit warnings should parse");
        let reconciled = reconcile_advisory_findings(report.findings(), &[], fixed_now());

        assert_eq!(report.findings().len(), 1);
        assert_eq!(report.idless_warnings(), 1);
        assert_eq!(
            report.findings()[0].advisory_id().to_string(),
            "RUSTSEC-2024-0375"
        );
        assert_eq!(report.findings()[0].package().to_string(), "atty@0.2.14");
        assert!(matches!(
            reconciled.dispositions()[0],
            AdvisoryDisposition::Unreviewed { .. }
        ));
    }

    #[test]
    fn cargo_audit_malformed_advisory_warnings_fail_closed() {
        for advisory in [r#"{}"#, r#"{"id": 123}"#] {
            let error = parse_cargo_audit_json(&format!(
                r#"{{
  "vulnerabilities": {{ "found": false, "count": 0, "list": [] }},
  "settings": {{ "ignore": [] }},
  "warnings": {{
    "unmaintained": [
      {{
        "kind": "unmaintained",
        "package": {{ "name": "atty", "version": "0.2.14" }},
        "advisory": {advisory}
      }}
    ]
  }}
}}"#
            ))
            .expect_err("malformed advisory-bearing warning should fail closed");

            assert!(error.to_string().contains("advisory missing id"));
        }
    }

    #[test]
    fn cargo_deny_unrecognised_advisory_shape_fails_closed() {
        let error = parse_cargo_deny_json_lines(
            r#"{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"RUSTSEC-2026-0001"},"graphs":[{"Krate":{"name":"serde"}}]}}
{"type":"summary","fields":{}}
"#,
        )
        .expect_err("unsupported shape should fail");

        assert!(error.to_string().contains("unsupported shape"));
    }

    #[test]
    fn cargo_deny_rejects_advisory_diagnostics_with_empty_graphs() {
        let error = parse_cargo_deny_json_lines(
            r#"{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"RUSTSEC-2026-0001"},"graphs":[]}}
{"type":"summary","fields":{}}
"#,
        )
        .expect_err("known advisory with no graph evidence must fail closed");

        assert!(error.to_string().contains("graphs empty"));
    }

    #[test]
    fn cargo_deny_skips_non_advisory_diagnostics_and_keeps_advisories() {
        let report = parse_cargo_deny_json_lines(
            r#"{"type":"diagnostic","fields":{"code":"source-not-allowed","message":"source policy finding"}}
{"type":"diagnostic","fields":{"code":"unmaintained","advisory":{"id":"RUSTSEC-2024-0375"},"graphs":[{"Krate":{"name":"atty","version":"0.2.14"}}]}}
{"type":"summary","fields":{}}
"#,
        )
        .expect("mixed cargo-deny output should parse");

        assert_eq!(report.findings().len(), 1);
        assert_eq!(
            report.findings()[0].advisory_id().to_string(),
            "RUSTSEC-2024-0375"
        );
        assert_eq!(report.findings()[0].package().to_string(), "atty@0.2.14");
    }

    #[test]
    fn cargo_deny_collects_multiple_graphs_and_deduplicates_findings() {
        let report = parse_cargo_deny_json_lines(
            r#"{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"RUSTSEC-2026-0001"},"graphs":[{"Krate":{"name":"serde","version":"1.0.228"}},{"Krate":{"name":"serde","version":"1.0.228"}},{"Krate":{"name":"toml","version":"0.8.0"}}]}}
{"type":"summary","fields":{}}
"#,
        )
        .expect("multi-graph cargo-deny advisory should parse");

        assert_eq!(report.findings().len(), 2);
        assert_eq!(report.findings()[0].package().to_string(), "serde@1.0.228");
        assert_eq!(report.findings()[1].package().to_string(), "toml@0.8.0");
    }

    #[test]
    fn unparseable_advisory_ids_are_not_dropped_and_reconcile_unreviewed() {
        let report = parse_cargo_deny_json_lines(
            r#"{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"GHSA-0000"},"graphs":[{"Krate":{"name":"serde","version":"1.0.228"}}]}}
{"type":"summary","fields":{}}
"#,
        )
        .expect("finding should still parse");
        let reconciled = reconcile_advisory_findings(report.findings(), &[], fixed_now());

        assert!(matches!(
            report.findings()[0].advisory_id(),
            AdvisoryFindingId::Unnormalised(id) if id == "GHSA-0000"
        ));
        assert!(matches!(
            reconciled.dispositions()[0],
            AdvisoryDisposition::Unreviewed { .. }
        ));
        assert!(!reconciled.is_success());
    }

    #[test]
    fn reconciles_accepted_unreviewed_and_expired_dispositions() {
        let targets = reviewed_targets_with_advisories();
        let exceptions = targets.advisory_exceptions();
        let exception_refs = exceptions.iter().collect::<Vec<_>>();
        let findings = parse_cargo_deny_json_lines(
            r#"{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"RUSTSEC-2026-0001"},"graphs":[{"Krate":{"name":"serde","version":"1.0.228"}}]}}
{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"RUSTSEC-2026-0002"},"graphs":[{"Krate":{"name":"serde","version":"1.0.228"}}]}}
{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"RUSTSEC-2026-0003"},"graphs":[{"Krate":{"name":"serde","version":"1.0.228"}}]}}
{"type":"summary","fields":{}}
"#,
        )
        .expect("findings should parse");

        let report = reconcile_advisory_findings(findings.findings(), &exception_refs, fixed_now());

        assert!(matches!(
            report.dispositions()[0],
            AdvisoryDisposition::Accepted { .. }
        ));
        assert!(matches!(
            report.dispositions()[1],
            AdvisoryDisposition::Expired { .. }
        ));
        assert!(matches!(
            report.dispositions()[2],
            AdvisoryDisposition::Unreviewed { .. }
        ));
        assert!(!report.is_success());
    }

    #[test]
    fn accepts_exception_on_exact_review_by_boundary() {
        let targets = reviewed_targets_with_advisories();
        let exceptions = targets.advisory_exceptions();
        let exception_refs = exceptions.iter().collect::<Vec<_>>();
        let findings = parse_cargo_deny_json_lines(
            r#"{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"RUSTSEC-2026-0001"},"graphs":[{"Krate":{"name":"serde","version":"1.0.228"}}]}}
{"type":"summary","fields":{}}
"#,
        )
        .expect("findings should parse");
        let boundary = Date::from_calendar_date(2026, Month::December, 31)
            .expect("date should parse")
            .midnight()
            .assume_utc();

        let report = reconcile_advisory_findings(findings.findings(), &exception_refs, boundary);

        assert!(matches!(
            report.dispositions()[0],
            AdvisoryDisposition::Accepted { .. }
        ));
        assert!(report.is_success());
    }

    #[test]
    fn exact_scanner_versions_match_reviewed_specs() {
        let targets = reviewed_targets_with_advisories();
        let exceptions = targets.advisory_exceptions();
        let exception_refs = exceptions.iter().collect::<Vec<_>>();
        let findings = parse_cargo_deny_json_lines(
            r#"{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"RUSTSEC-2026-0001"},"graphs":[{"Krate":{"name":"serde","version":"1.0.228"}}]}}
{"type":"summary","fields":{}}
"#,
        )
        .expect("findings should parse");

        let report = reconcile_advisory_findings(findings.findings(), &exception_refs, fixed_now());

        assert!(matches!(
            report.dispositions()[0],
            AdvisoryDisposition::Accepted { .. }
        ));
        assert!(report.is_success());
    }

    #[test]
    fn verdict_fails_on_any_unreviewed_or_expired_disposition() {
        let targets = reviewed_targets_with_advisories();
        let exceptions = targets.advisory_exceptions();
        let exception_refs = exceptions.iter().collect::<Vec<_>>();
        let accepted_finding = parse_cargo_deny_json_lines(
            r#"{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"RUSTSEC-2026-0001"},"graphs":[{"Krate":{"name":"serde","version":"1.0.228"}}]}}
{"type":"summary","fields":{}}
"#,
        )
        .expect("findings should parse");
        let mixed_findings = parse_cargo_deny_json_lines(
            r#"{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"RUSTSEC-2026-0001"},"graphs":[{"Krate":{"name":"serde","version":"1.0.228"}}]}}
{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"RUSTSEC-2026-0003"},"graphs":[{"Krate":{"name":"serde","version":"1.0.228"}}]}}
{"type":"summary","fields":{}}
"#,
        )
        .expect("findings should parse");

        assert!(
            reconcile_advisory_findings(accepted_finding.findings(), &exception_refs, fixed_now())
                .is_success()
        );
        assert!(
            !reconcile_advisory_findings(mixed_findings.findings(), &exception_refs, fixed_now())
                .is_success()
        );
    }

    #[test]
    fn audit_outcome_passes_when_all_findings_are_accepted() {
        let targets = reviewed_targets_with_advisories();
        let exceptions = targets.advisory_exceptions();
        let exception_refs = exceptions.iter().collect::<Vec<_>>();
        let deny_report = parse_cargo_deny_json_lines(
            r#"{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"RUSTSEC-2026-0001"},"graphs":[{"Krate":{"name":"serde","version":"1.0.228"}}]}}
{"type":"summary","fields":{"advisories":{"errors":1,"warnings":0,"helps":0,"notes":0}}}
"#,
        )
        .expect("findings should parse");

        let outcome = evaluate_deny(&deny_report, &exception_refs, fixed_now());

        assert!(outcome.is_success());
        assert_eq!(outcome.accepted_exceptions().len(), 1);
        assert!(outcome.cargo_deny_non_advisory_errors().is_empty());
    }

    #[test]
    fn audit_outcome_fails_on_unreviewed_findings() {
        let deny_report = parse_cargo_deny_json_lines(
            r#"{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"RUSTSEC-2026-0003"},"graphs":[{"Krate":{"name":"serde","version":"1.0.228"}}]}}
{"type":"summary","fields":{"advisories":{"errors":1,"warnings":0,"helps":0,"notes":0}}}
"#,
        )
        .expect("finding should parse");

        let outcome = evaluate_deny(&deny_report, &[], fixed_now());

        assert!(!outcome.is_success());
        assert!(matches!(
            outcome.reconciliation().dispositions()[0],
            AdvisoryDisposition::Unreviewed { .. }
        ));
    }

    #[test]
    fn audit_outcome_fails_on_expired_findings_but_accepts_boundary_date() {
        let targets = reviewed_targets_with_advisories();
        let exceptions = targets.advisory_exceptions();
        let exception_refs = exceptions.iter().collect::<Vec<_>>();
        let accepted = parse_cargo_deny_json_lines(
            r#"{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"RUSTSEC-2026-0001"},"graphs":[{"Krate":{"name":"serde","version":"1.0.228"}}]}}
{"type":"summary","fields":{"advisories":{"errors":1,"warnings":0,"helps":0,"notes":0}}}
"#,
        )
        .expect("finding should parse");
        let expired = parse_cargo_deny_json_lines(
            r#"{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"RUSTSEC-2026-0002"},"graphs":[{"Krate":{"name":"serde","version":"1.0.228"}}]}}
{"type":"summary","fields":{"advisories":{"errors":1,"warnings":0,"helps":0,"notes":0}}}
"#,
        )
        .expect("finding should parse");
        let boundary = Date::from_calendar_date(2026, Month::December, 31)
            .expect("date should parse")
            .midnight()
            .assume_utc();

        assert!(evaluate_deny(&accepted, &exception_refs, boundary).is_success());
        let outcome = evaluate_deny(&expired, &exception_refs, fixed_now());

        assert!(!outcome.is_success());
        assert!(matches!(
            outcome.reconciliation().dispositions()[0],
            AdvisoryDisposition::Expired { .. }
        ));
    }

    #[test]
    fn audit_outcome_fails_on_non_advisory_cargo_deny_errors() {
        let targets = reviewed_targets_with_advisories();
        let exceptions = targets.advisory_exceptions();
        let exception_refs = exceptions.iter().collect::<Vec<_>>();
        let deny_report = parse_cargo_deny_json_lines(
            r#"{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"RUSTSEC-2026-0001"},"graphs":[{"Krate":{"name":"serde","version":"1.0.228"}}]}}
{"type":"summary","fields":{"advisories":{"errors":1,"warnings":0,"helps":0,"notes":0},"bans":{"errors":1,"warnings":0,"helps":0,"notes":0}}}
"#,
        )
        .expect("finding should parse");

        let outcome = evaluate_advisory_audit(
            LockfileAdvisoryScanner::CargoDeny,
            &[CargoDenyCheck::Advisories, CargoDenyCheck::Bans],
            Some(&deny_report),
            None,
            &exception_refs,
            fixed_now(),
        );

        assert!(!outcome.is_success());
        assert!(outcome.reconciliation().is_success());
        assert_eq!(
            outcome
                .cargo_deny_non_advisory_errors()
                .iter()
                .map(|count| (count.check().to_owned(), count.errors()))
                .collect::<Vec<_>>(),
            vec![("bans".to_owned(), 1)]
        );
    }

    #[test]
    fn audit_outcome_fails_on_cargo_deny_error_diagnostic_without_advisory_id() {
        let targets = reviewed_targets_with_advisories();
        let exceptions = targets.advisory_exceptions();
        let exception_refs = exceptions.iter().collect::<Vec<_>>();
        let deny_report = parse_cargo_deny_json_lines(
            r#"{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"RUSTSEC-2026-0001"},"graphs":[{"Krate":{"name":"serde","version":"1.0.228"}}]}}
{"type":"diagnostic","fields":{"code":"yanked","message":"crate is yanked","severity":"error"}}
{"type":"summary","fields":{"advisories":{"errors":2,"warnings":0,"helps":0,"notes":0}}}
"#,
        )
        .expect("cargo-deny output should parse");

        let outcome = evaluate_deny(&deny_report, &exception_refs, fixed_now());

        assert!(!outcome.is_success());
        assert!(outcome.reconciliation().is_success());
        assert_eq!(outcome.cargo_deny_no_advisory_errors().len(), 1);
        assert_eq!(
            outcome.cargo_deny_no_advisory_errors()[0].code(),
            Some("yanked")
        );
    }

    #[test]
    fn audit_outcome_allows_known_benign_cargo_deny_diagnostics_without_advisory_id() {
        let deny_report = parse_cargo_deny_json_lines(
            r#"{"type":"diagnostic","fields":{"code":"context","message":"warning only","severity":"warning"}}
{"type":"diagnostic","fields":{"code":"context","message":"note only","severity":"note"}}
{"type":"diagnostic","fields":{"code":"context","message":"help only","severity":"help"}}
{"type":"summary","fields":{"advisories":{"errors":0,"warnings":1,"helps":1,"notes":1}}}
"#,
        )
        .expect("cargo-deny output should parse");

        let outcome = evaluate_deny(&deny_report, &[], fixed_now());

        assert!(outcome.is_success());
        assert!(outcome.cargo_deny_no_advisory_errors().is_empty());
    }

    #[test]
    fn audit_outcome_fails_when_expected_scanner_reports_are_absent() {
        let outcome = evaluate_advisory_audit(
            LockfileAdvisoryScanner::Both,
            &[CargoDenyCheck::Advisories],
            None,
            None,
            &[],
            fixed_now(),
        );

        assert!(!outcome.is_success());
        assert_eq!(
            outcome.completeness_failures(),
            &[
                AdvisoryAuditCompletenessFailure::MissingCargoDenyReport,
                AdvisoryAuditCompletenessFailure::MissingCargoAuditReport,
            ]
        );
    }

    #[test]
    fn audit_outcome_fails_when_configured_cargo_deny_check_is_missing_from_summary() {
        let deny_report = parse_cargo_deny_json_lines(
            r#"{"type":"summary","fields":{"advisories":{"errors":0,"warnings":0,"helps":0,"notes":0}}}
"#,
        )
        .expect("cargo-deny output should parse");

        let outcome = evaluate_advisory_audit(
            LockfileAdvisoryScanner::CargoDeny,
            &[CargoDenyCheck::Advisories, CargoDenyCheck::Bans],
            Some(&deny_report),
            None,
            &[],
            fixed_now(),
        );

        assert!(!outcome.is_success());
        assert_eq!(
            outcome.completeness_failures(),
            &[
                AdvisoryAuditCompletenessFailure::MissingCargoDenySummaryCheck {
                    check: CargoDenyCheck::Bans,
                }
            ]
        );
    }

    #[test]
    fn audit_outcome_fails_when_cargo_deny_advisory_errors_are_unenumerated() {
        let deny_report = parse_cargo_deny_json_lines(
            r#"{"type":"summary","fields":{"advisories":{"errors":1,"warnings":0,"helps":0,"notes":0}}}
"#,
        )
        .expect("cargo-deny output should parse");

        let outcome = evaluate_advisory_audit(
            LockfileAdvisoryScanner::CargoDeny,
            &[CargoDenyCheck::Advisories],
            Some(&deny_report),
            None,
            &[],
            fixed_now(),
        );

        assert!(!outcome.is_success());
        assert_eq!(
            outcome.completeness_failures(),
            &[AdvisoryAuditCompletenessFailure::CargoDenyAdvisoryErrorsUnenumerated]
        );
    }

    #[test]
    fn audit_outcome_still_fails_cargo_deny_bans_when_cargo_audit_scans_advisories() {
        let deny_report = parse_cargo_deny_json_lines(
            r#"{"type":"diagnostic","fields":{"code":"banned","message":"crate is banned","severity":"error"}}
{"type":"summary","fields":{"bans":{"errors":1,"warnings":0,"helps":0,"notes":0}}}
"#,
        )
        .expect("cargo-deny output should parse");
        let audit_report = parse_cargo_audit_json(
            r#"{
  "vulnerabilities": { "found": false, "count": 0, "list": [] },
  "settings": { "ignore": [] },
  "warnings": {}
}"#,
        )
        .expect("cargo-audit output should parse");

        let outcome = evaluate_advisory_audit(
            LockfileAdvisoryScanner::CargoAudit,
            &[CargoDenyCheck::Bans],
            Some(&deny_report),
            Some(&audit_report),
            &[],
            fixed_now(),
        );

        assert!(!outcome.is_success());
        assert_eq!(outcome.cargo_deny_no_advisory_errors().len(), 1);
        assert_eq!(
            outcome
                .cargo_deny_non_advisory_errors()
                .iter()
                .map(|count| (count.check().to_owned(), count.errors()))
                .collect::<Vec<_>>(),
            vec![("bans".to_owned(), 1)]
        );
    }

    #[test]
    fn audit_outcome_uses_cargo_audit_findings_when_cargo_deny_is_clean() {
        let deny_report = parse_cargo_deny_json_lines(
            r#"{"type":"summary","fields":{"bans":{"errors":0,"warnings":0,"helps":0,"notes":0}}}
"#,
        )
        .expect("cargo-deny output should parse");
        let audit_report = parse_cargo_audit_json(
            r#"{
  "vulnerabilities": {
    "found": true,
    "count": 1,
    "list": [
      {
        "advisory": { "id": "RUSTSEC-2026-0003" },
        "package": { "name": "serde", "version": "1.0.228" }
      }
    ]
  },
  "settings": { "ignore": [] },
  "warnings": {}
}"#,
        )
        .expect("cargo-audit output should parse");

        let outcome = evaluate_advisory_audit(
            LockfileAdvisoryScanner::CargoAudit,
            &[CargoDenyCheck::Bans],
            Some(&deny_report),
            Some(&audit_report),
            &[],
            fixed_now(),
        );

        assert!(!outcome.is_success());
        assert!(outcome.cargo_deny_no_advisory_errors().is_empty());
        assert!(outcome.cargo_deny_non_advisory_errors().is_empty());
        assert!(matches!(
            outcome.reconciliation().dispositions()[0],
            AdvisoryDisposition::Unreviewed { .. }
        ));
    }

    #[test]
    fn audit_outcome_fails_on_cargo_audit_ignored_settings() {
        let audit_report = parse_cargo_audit_json(
            r#"{
  "vulnerabilities": { "found": false, "count": 0, "list": [] },
  "settings": { "ignore": ["RUSTSEC-2026-0001"] },
  "warnings": {}
}"#,
        )
        .expect("cargo-audit output should parse");

        let outcome = evaluate_audit(&audit_report, &[], fixed_now());

        assert!(!outcome.is_success());
        assert_eq!(
            outcome.cargo_audit_settings_ignore(),
            &["RUSTSEC-2026-0001".to_owned()]
        );
    }

    #[test]
    fn audit_outcome_fails_on_cargo_audit_idless_warnings() {
        let audit_report = parse_cargo_audit_json(
            r#"{
  "vulnerabilities": { "found": false, "count": 0, "list": [] },
  "settings": { "ignore": [] },
  "warnings": {
    "yanked": [
      { "kind": "yanked", "package": { "name": "gone", "version": "1.2.3" } }
    ]
  }
}"#,
        )
        .expect("cargo-audit output should parse");

        let outcome = evaluate_audit(&audit_report, &[], fixed_now());

        assert!(!outcome.is_success());
        assert_eq!(outcome.cargo_audit_idless_warnings(), 1);
    }

    #[test]
    fn audit_outcome_fails_on_non_yanked_cargo_audit_idless_warnings() {
        let audit_report = parse_cargo_audit_json(
            r#"{
  "vulnerabilities": { "found": false, "count": 0, "list": [] },
  "settings": { "ignore": [] },
  "warnings": {
    "future-warning": [
      { "kind": "future-warning", "package": { "name": "gone", "version": "1.2.3" } }
    ]
  }
}"#,
        )
        .expect("cargo-audit output should parse");

        let outcome = evaluate_audit(&audit_report, &[], fixed_now());

        assert!(!outcome.is_success());
        assert_eq!(outcome.cargo_audit_idless_warnings(), 1);
    }

    #[test]
    fn audit_outcome_counts_null_advisory_warnings_as_idless() {
        let audit_report = parse_cargo_audit_json(
            r#"{
  "vulnerabilities": { "found": false, "count": 0, "list": [] },
  "settings": { "ignore": [] },
  "warnings": {
    "future-warning": [
      { "advisory": null, "package": { "name": "gone", "version": "1.2.3" } }
    ]
  }
}"#,
        )
        .expect("cargo-audit output should parse");

        let outcome = evaluate_audit(&audit_report, &[], fixed_now());

        assert!(!outcome.is_success());
        assert_eq!(outcome.cargo_audit_idless_warnings(), 1);
    }

    #[test]
    fn audit_outcome_deduplicates_findings_across_scanners() {
        let targets = reviewed_targets_with_advisories();
        let exceptions = targets.advisory_exceptions();
        let exception_refs = exceptions.iter().collect::<Vec<_>>();
        let deny_report = parse_cargo_deny_json_lines(
            r#"{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"RUSTSEC-2026-0001"},"graphs":[{"Krate":{"name":"serde","version":"1.0.228"}}]}}
{"type":"summary","fields":{"advisories":{"errors":1,"warnings":0,"helps":0,"notes":0}}}
"#,
        )
        .expect("cargo-deny output should parse");
        let audit_report = parse_cargo_audit_json(
            r#"{
  "vulnerabilities": {
    "found": true,
    "count": 1,
    "list": [
      {
        "advisory": { "id": "RUSTSEC-2026-0001" },
        "package": { "name": "serde", "version": "1.0.228" }
      }
    ]
  },
  "settings": { "ignore": [] },
  "warnings": {}
}"#,
        )
        .expect("cargo-audit output should parse");

        let outcome = evaluate_advisory_audit(
            LockfileAdvisoryScanner::Both,
            &[CargoDenyCheck::Advisories],
            Some(&deny_report),
            Some(&audit_report),
            &exception_refs,
            fixed_now(),
        );

        assert!(outcome.is_success());
        assert_eq!(outcome.reconciliation().dispositions().len(), 1);
    }

    #[test]
    fn audit_outcome_keeps_cargo_audit_details_when_cargo_deny_reports_same_finding_first() {
        let deny_report = parse_cargo_deny_json_lines(
            r#"{"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"RUSTSEC-2026-0003"},"graphs":[{"Krate":{"name":"serde","version":"1.0.228"}}]}}
{"type":"summary","fields":{"advisories":{"errors":1,"warnings":0,"helps":0,"notes":0}}}
"#,
        )
        .expect("cargo-deny output should parse");
        let audit_report = parse_cargo_audit_json(
            r#"{
  "vulnerabilities": {
    "found": true,
    "count": 1,
    "list": [
      {
        "advisory": {
          "id": "RUSTSEC-2026-0003",
          "title": "vulnerable parser",
          "severity": "high"
        },
        "package": { "name": "serde", "version": "1.0.228" },
        "versions": { "patched": [">=1.0.229"], "unaffected": [] }
      }
    ]
  },
  "settings": { "ignore": [] },
  "warnings": {}
}"#,
        )
        .expect("cargo-audit output should parse");

        let outcome = evaluate_advisory_audit(
            LockfileAdvisoryScanner::Both,
            &[CargoDenyCheck::Advisories],
            Some(&deny_report),
            Some(&audit_report),
            &[],
            fixed_now(),
        );

        assert!(!outcome.is_success());
        assert_eq!(outcome.reconciliation().dispositions().len(), 1);
        let AdvisoryDisposition::Unreviewed { finding } =
            &outcome.reconciliation().dispositions()[0]
        else {
            panic!("merged finding should remain unreviewed");
        };
        assert_eq!(finding.details().title(), Some("vulnerable parser"));
        assert_eq!(finding.details().risk_label(), Some("high"));
        assert_eq!(
            finding.details().patched_versions(),
            &[">=1.0.229".to_owned()]
        );
    }

    #[test]
    fn rejects_cross_family_duplicate_advisory_bindings() {
        let error = parse_reviewed_targets_toml(&format!(
            r#"[rust]

[[rust.families]]
name = "first"
review_record = "docs/dependency-reviews/first.md"

[rust.families.resolved]
serde = {{ version = "1.0.228", checksum_sha256 = "{CHECKSUM}" }}

[rust.families.allowed_advisories]
serde = [
  {{ id = "RUSTSEC-2026-0001", review_by = "2026-09-21" }},
]

[[rust.families]]
name = "second"
review_record = "docs/dependency-reviews/second.md"

[rust.families.resolved]
serde = {{ version = "1.0.228", checksum_sha256 = "{CHECKSUM}" }}

[rust.families.allowed_advisories]
serde = [
  {{ id = "RUSTSEC-2026-0001", review_by = "2026-10-21" }},
]
"#
        ))
        .expect_err("duplicate advisory binding should fail");

        assert!(matches!(
            error,
            ReviewedTargetsError::DuplicateAllowedAdvisoryBinding { .. }
        ));
    }

    #[test]
    fn allows_cross_family_advisory_bindings_for_different_versions() {
        let targets = parse_reviewed_targets_toml(&format!(
            r#"[rust]

[[rust.families]]
name = "first"
review_record = "docs/dependency-reviews/first.md"

[rust.families.resolved]
serde = {{ version = "1.0.228", checksum_sha256 = "{CHECKSUM}" }}

[rust.families.allowed_advisories]
serde = [
  {{ id = "RUSTSEC-2026-0001", review_by = "2026-09-21" }},
]

[[rust.families]]
name = "second"
review_record = "docs/dependency-reviews/second.md"

[rust.families.resolved]
serde = {{ version = "1.0.229", checksum_sha256 = "{CHECKSUM}" }}

[rust.families.allowed_advisories]
serde = [
  {{ id = "RUSTSEC-2026-0001", review_by = "2026-10-21" }},
]
"#
        ))
        .expect("different-version advisory bindings should parse");

        assert_eq!(targets.advisory_exceptions().len(), 2);
    }

    fn reviewed_targets_with_advisories() -> crate::ReviewedTargets {
        parse_reviewed_targets_toml(&format!(
            r#"[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/serde.md"

[rust.families.resolved]
serde = {{ version = "1.0.228", checksum_sha256 = "{CHECKSUM}" }}

[rust.families.allowed_advisories]
serde = [
  {{ id = "RUSTSEC-2026-0001", review_by = "2026-12-31" }},
  {{ id = "RUSTSEC-2026-0002", review_by = "2025-12-31" }},
]
"#
        ))
        .expect("reviewed targets should parse")
    }

    fn evaluate_deny(
        report: &CargoDenyAdvisoryReport,
        exceptions: &[&ReviewedAdvisoryException],
        now: OffsetDateTime,
    ) -> AdvisoryAuditOutcome {
        evaluate_advisory_audit(
            LockfileAdvisoryScanner::CargoDeny,
            &[CargoDenyCheck::Advisories],
            Some(report),
            None,
            exceptions,
            now,
        )
    }

    fn evaluate_audit(
        report: &CargoAuditAdvisoryReport,
        exceptions: &[&ReviewedAdvisoryException],
        now: OffsetDateTime,
    ) -> AdvisoryAuditOutcome {
        evaluate_advisory_audit(
            LockfileAdvisoryScanner::CargoAudit,
            &[],
            None,
            Some(report),
            exceptions,
            now,
        )
    }

    fn remediation_finding() -> AdvisoryFinding {
        remediation_finding_for("quick-xml", "0.39.4", ">=0.41.0")
    }

    fn remediation_finding_for(
        crate_name: &str,
        version: &str,
        patched_range: &str,
    ) -> AdvisoryFinding {
        let report = parse_cargo_audit_json(&format!(
            r#"{{
  "database": {{ "advisory-count": 1 }},
  "lockfile": {{ "dependency-count": 1 }},
  "settings": {{
    "target_arch": [],
    "target_os": [],
    "severity": null,
    "ignore": [],
    "informational_warnings": []
  }},
  "vulnerabilities": {{
    "found": true,
    "count": 1,
    "list": [
      {{
        "package": {{
          "name": "{crate_name}",
          "version": "{version}",
          "source": "registry+https://github.com/rust-lang/crates.io-index",
          "checksum": "00"
        }},
        "advisory": {{
          "id": "RUSTSEC-2026-0001",
          "package": "{crate_name}",
          "title": "vulnerable parser",
          "severity": "high",
          "versions": {{ "patched": ["{patched_range}"] }}
        }},
        "versions": {{ "patched": ["{patched_range}"] }}
      }}
    ]
  }},
  "warnings": {{}}
}}"#
        ))
        .expect("cargo audit fixture should parse");

        report.findings()[0].clone()
    }

    fn direct_requirements(text: &str) -> Vec<crate::CargoManifestDirectRequirement> {
        parse_manifest_direct_requirements("Cargo.toml", text)
            .expect("manifest should parse")
            .into_iter()
            .collect()
    }

    fn workspace_requirements(text: &str) -> Vec<crate::CargoManifestDirectRequirement> {
        parse_workspace_dependency_requirements("Cargo.toml", text)
            .expect("workspace manifest should parse")
            .into_iter()
            .collect()
    }

    fn dependency_path_to_quick_xml() -> crate::MetadataDependencyPath {
        let metadata = parse_cargo_metadata(
            r#"{
  "packages": [
    {
      "name": "root",
      "version": "0.1.0",
      "id": "path+file:///repo#root@0.1.0",
      "targets": []
    },
    {
      "name": "plist",
      "version": "1.9.0",
      "id": "registry+https://github.com/rust-lang/crates.io-index#plist@1.9.0",
      "targets": []
    },
    {
      "name": "quick-xml",
      "version": "0.39.4",
      "id": "registry+https://github.com/rust-lang/crates.io-index#quick-xml@0.39.4",
      "targets": []
    }
  ],
  "workspace_members": ["path+file:///repo#root@0.1.0"],
  "resolve": {
    "nodes": [
      {
        "id": "path+file:///repo#root@0.1.0",
        "deps": [
          {
            "name": "plist",
            "pkg": "registry+https://github.com/rust-lang/crates.io-index#plist@1.9.0"
          }
        ]
      },
      {
        "id": "registry+https://github.com/rust-lang/crates.io-index#plist@1.9.0",
        "deps": [
          {
            "name": "quick_xml",
            "pkg": "registry+https://github.com/rust-lang/crates.io-index#quick-xml@0.39.4"
          }
        ]
      },
      {
        "id": "registry+https://github.com/rust-lang/crates.io-index#quick-xml@0.39.4",
        "deps": []
      }
    ]
  }
}"#,
        )
        .expect("metadata should parse");
        let target = ExactCrateSpec::from_parts("quick-xml", "0.39.4").expect("spec should parse");

        shortest_workspace_dependency_path(&metadata, &target)
            .expect("path lookup should succeed")
            .expect("path should exist")
    }

    fn dependency_path_to_direct_serde() -> crate::MetadataDependencyPath {
        let metadata = parse_cargo_metadata(
            r#"{
  "packages": [
    {
      "name": "root",
      "version": "0.1.0",
      "id": "path+file:///repo#root@0.1.0",
      "targets": []
    },
    {
      "name": "serde",
      "version": "1.0.228",
      "id": "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228",
      "targets": []
    }
  ],
  "workspace_members": ["path+file:///repo#root@0.1.0"],
  "resolve": {
    "nodes": [
      {
        "id": "path+file:///repo#root@0.1.0",
        "deps": [
          {
            "name": "serde_alias",
            "pkg": "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228"
          }
        ]
      },
      {
        "id": "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228",
        "deps": []
      }
    ]
  }
}"#,
        )
        .expect("metadata should parse");
        let target = ExactCrateSpec::from_parts("serde", "1.0.228").expect("spec should parse");

        shortest_workspace_dependency_path(&metadata, &target)
            .expect("path lookup should succeed")
            .expect("path should exist")
    }

    fn fixed_now() -> OffsetDateTime {
        Date::from_calendar_date(2026, Month::June, 24)
            .expect("date should parse")
            .midnight()
            .assume_utc()
    }
}
