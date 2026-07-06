use std::collections::HashSet;
use std::fmt;

use time::OffsetDateTime;

use crate::reviewed_targets::ExecutionSurfaceKind;
use crate::{
    CargoManifestDependency, CargoMetadata, CratesIoClient, ExactCrateSpec, HighScrutinyConfig,
    Lockfile, ReleaseAgeOutcome, ReviewedExecutionSurfaceAllowance, ReviewedReleaseAgeException,
    Sha256Digest, changed_crates_io_checksums, check_release_age_at,
    is_native_sys_execution_surface, package_surfaces,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustAssessmentClassification {
    RoutineSafe,
    ElevatedRisk,
    PolicyViolating,
}

impl fmt::Display for RustAssessmentClassification {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RoutineSafe => write!(formatter, "routine-safe"),
            Self::ElevatedRisk => write!(formatter, "elevated-risk"),
            Self::PolicyViolating => write!(formatter, "policy-violating"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustAssessmentFindingSeverity {
    Blocking,
    Elevated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustAssessmentFindingCategory {
    NewDirectDependencies,
    NonCratesIoDirectDependencies,
    AgeViolations,
    YankedVersions,
    ReleaseAgeExceptionArtefactMismatches,
    LockedChecksumDrifts,
    NonCratesIoSourceChanges,
    NativeSysCrates,
    BuildRsSurfaces,
    ProcMacroSurfaces,
    InspectionFailures,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RustAssessmentFinding {
    severity: RustAssessmentFindingSeverity,
    category: RustAssessmentFindingCategory,
}

impl RustAssessmentFinding {
    fn blocking(category: RustAssessmentFindingCategory) -> Self {
        Self {
            severity: RustAssessmentFindingSeverity::Blocking,
            category,
        }
    }

    fn elevated(category: RustAssessmentFindingCategory) -> Self {
        Self {
            severity: RustAssessmentFindingSeverity::Elevated,
            category,
        }
    }

    pub fn severity(&self) -> RustAssessmentFindingSeverity {
        self.severity
    }

    pub fn category(&self) -> RustAssessmentFindingCategory {
        self.category
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReleaseAgeViolation {
    spec: ExactCrateSpec,
    age_seconds: i64,
}

impl ReleaseAgeViolation {
    fn new(spec: ExactCrateSpec, age_seconds: i64) -> Self {
        Self { spec, age_seconds }
    }

    pub fn spec(&self) -> &ExactCrateSpec {
        &self.spec
    }

    pub fn age_seconds(&self) -> i64 {
        self.age_seconds
    }
}

impl fmt::Display for ReleaseAgeViolation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} ({} old)",
            self.spec,
            crate::format_age(self.age_seconds)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NonCratesIoSourceChange {
    spec: ExactCrateSpec,
    source: String,
}

impl NonCratesIoSourceChange {
    fn new(spec: ExactCrateSpec, source: String) -> Self {
        Self { spec, source }
    }

    pub fn spec(&self) -> &ExactCrateSpec {
        &self.spec
    }

    pub fn source(&self) -> &str {
        &self.source
    }
}

impl fmt::Display for NonCratesIoSourceChange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} source={}", self.spec, self.source)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LockedChecksumDrift {
    spec: ExactCrateSpec,
    base_checksum: Sha256Digest,
    current_checksum: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReleaseAgeExceptionArtefactMismatch {
    spec: ExactCrateSpec,
    family: String,
    review_record: String,
    expected: Sha256Digest,
    found: Sha256Digest,
}

impl ReleaseAgeExceptionArtefactMismatch {
    fn new(
        spec: ExactCrateSpec,
        family: String,
        review_record: String,
        expected: Sha256Digest,
        found: Sha256Digest,
    ) -> Self {
        Self {
            spec,
            family,
            review_record,
            expected,
            found,
        }
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

    pub fn expected(&self) -> &Sha256Digest {
        &self.expected
    }

    pub fn found(&self) -> &Sha256Digest {
        &self.found
    }
}

impl fmt::Display for ReleaseAgeExceptionArtefactMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} release-age exception artefact mismatch for family {} ({}): expected {}, found {}",
            self.spec, self.family, self.review_record, self.expected, self.found
        )
    }
}

impl LockedChecksumDrift {
    fn new(
        spec: ExactCrateSpec,
        base_checksum: Sha256Digest,
        current_checksum: Sha256Digest,
    ) -> Self {
        Self {
            spec,
            base_checksum,
            current_checksum,
        }
    }

    pub fn spec(&self) -> &ExactCrateSpec {
        &self.spec
    }

    pub fn base_checksum(&self) -> &Sha256Digest {
        &self.base_checksum
    }

    pub fn current_checksum(&self) -> &Sha256Digest {
        &self.current_checksum
    }
}

impl fmt::Display for LockedChecksumDrift {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} checksum drift: {} -> {}",
            self.spec, self.base_checksum, self.current_checksum
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct InspectionFailure {
    spec: ExactCrateSpec,
    detail: String,
}

impl InspectionFailure {
    fn new(spec: ExactCrateSpec, detail: String) -> Self {
        Self { spec, detail }
    }

    pub fn spec(&self) -> &ExactCrateSpec {
        &self.spec
    }

    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for InspectionFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.spec, self.detail)
    }
}

/// A single detected item from a Rust dependency-update assessment.
///
/// Every item is recorded regardless of the `HighScrutinyConfig` toggles: the
/// per-category accessors on `RustAssessmentReport` always report the full
/// detected set, so the "Rust Assessment" detail block never hides what was
/// found. Only [`RustAssessmentReport::classification`] and the aggregated
/// [`RustAssessmentReport::findings`] apply the high-scrutiny gate, and that
/// gate is applied once, at construction, rather than at every accessor call.
///
/// Declaration order matches the fixed rendering order of the blocking, then
/// elevated, finding sections: adding a new gate means adding one variant
/// here and one push site in [`assess_rust_update_at`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum RustAssessmentItem {
    AgeViolation(ReleaseAgeViolation),
    YankedVersion(ExactCrateSpec),
    ReleaseAgeExceptionArtefactMismatch(ReleaseAgeExceptionArtefactMismatch),
    LockedChecksumDrift(LockedChecksumDrift),
    InspectionFailure(InspectionFailure),
    NewDirectDependency(CargoManifestDependency),
    NonCratesIoSourceChange(NonCratesIoSourceChange),
    NativeSysCrate(ExactCrateSpec),
    BuildRsSurface(ExactCrateSpec),
    ProcMacroSurface(ExactCrateSpec),
}

impl RustAssessmentItem {
    fn category(&self) -> RustAssessmentFindingCategory {
        match self {
            Self::AgeViolation(_) => RustAssessmentFindingCategory::AgeViolations,
            Self::YankedVersion(_) => RustAssessmentFindingCategory::YankedVersions,
            Self::ReleaseAgeExceptionArtefactMismatch(_) => {
                RustAssessmentFindingCategory::ReleaseAgeExceptionArtefactMismatches
            }
            Self::LockedChecksumDrift(_) => RustAssessmentFindingCategory::LockedChecksumDrifts,
            Self::InspectionFailure(_) => RustAssessmentFindingCategory::InspectionFailures,
            Self::NewDirectDependency(_) => RustAssessmentFindingCategory::NewDirectDependencies,
            Self::NonCratesIoSourceChange(_) => {
                RustAssessmentFindingCategory::NonCratesIoSourceChanges
            }
            Self::NativeSysCrate(_) => RustAssessmentFindingCategory::NativeSysCrates,
            Self::BuildRsSurface(_) => RustAssessmentFindingCategory::BuildRsSurfaces,
            Self::ProcMacroSurface(_) => RustAssessmentFindingCategory::ProcMacroSurfaces,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustAssessmentReport {
    newly_selected_lock_entries: usize,
    newly_introduced_crate_names: usize,
    items: Vec<RustAssessmentItem>,
    allowed_execution_surfaces: Vec<ReviewedExecutionSurfaceAllowance>,
    allowed_release_age_exceptions: Vec<ReviewedReleaseAgeException>,
    findings: Vec<RustAssessmentFinding>,
}

impl RustAssessmentReport {
    fn new(
        newly_selected_lock_entries: usize,
        newly_introduced_crate_names: usize,
        items: Vec<RustAssessmentItem>,
        allowed_execution_surfaces: Vec<ReviewedExecutionSurfaceAllowance>,
        allowed_release_age_exceptions: Vec<ReviewedReleaseAgeException>,
        high_scrutiny: &HighScrutinyConfig,
    ) -> Self {
        let findings = aggregate_findings(&items, high_scrutiny);

        Self {
            newly_selected_lock_entries,
            newly_introduced_crate_names,
            items,
            allowed_execution_surfaces,
            allowed_release_age_exceptions,
            findings,
        }
    }

    pub fn classification(&self) -> RustAssessmentClassification {
        if self
            .findings
            .iter()
            .any(|finding| finding.severity == RustAssessmentFindingSeverity::Blocking)
        {
            RustAssessmentClassification::PolicyViolating
        } else if !self.findings.is_empty() {
            RustAssessmentClassification::ElevatedRisk
        } else {
            RustAssessmentClassification::RoutineSafe
        }
    }

    pub fn newly_selected_lock_entries(&self) -> usize {
        self.newly_selected_lock_entries
    }

    pub fn newly_introduced_crate_names(&self) -> usize {
        self.newly_introduced_crate_names
    }

    pub fn new_direct_dependencies(&self) -> Vec<&CargoManifestDependency> {
        self.items
            .iter()
            .filter_map(|item| match item {
                RustAssessmentItem::NewDirectDependency(dependency) => Some(dependency),
                _ => None,
            })
            .collect()
    }

    pub fn non_crates_io_direct_dependencies(&self) -> Vec<&CargoManifestDependency> {
        self.new_direct_dependencies()
            .into_iter()
            .filter(|dependency| dependency.source_kind().is_non_crates_io())
            .collect()
    }

    pub fn age_violations(&self) -> Vec<&ReleaseAgeViolation> {
        self.items
            .iter()
            .filter_map(|item| match item {
                RustAssessmentItem::AgeViolation(violation) => Some(violation),
                _ => None,
            })
            .collect()
    }

    pub fn yanked_versions(&self) -> Vec<&ExactCrateSpec> {
        self.items
            .iter()
            .filter_map(|item| match item {
                RustAssessmentItem::YankedVersion(spec) => Some(spec),
                _ => None,
            })
            .collect()
    }

    pub fn release_age_exception_mismatches(&self) -> Vec<&ReleaseAgeExceptionArtefactMismatch> {
        self.items
            .iter()
            .filter_map(|item| match item {
                RustAssessmentItem::ReleaseAgeExceptionArtefactMismatch(mismatch) => Some(mismatch),
                _ => None,
            })
            .collect()
    }

    pub fn locked_checksum_drifts(&self) -> Vec<&LockedChecksumDrift> {
        self.items
            .iter()
            .filter_map(|item| match item {
                RustAssessmentItem::LockedChecksumDrift(drift) => Some(drift),
                _ => None,
            })
            .collect()
    }

    pub fn non_crates_io_source_changes(&self) -> Vec<&NonCratesIoSourceChange> {
        self.items
            .iter()
            .filter_map(|item| match item {
                RustAssessmentItem::NonCratesIoSourceChange(change) => Some(change),
                _ => None,
            })
            .collect()
    }

    pub fn native_sys_crates(&self) -> Vec<&ExactCrateSpec> {
        self.items
            .iter()
            .filter_map(|item| match item {
                RustAssessmentItem::NativeSysCrate(spec) => Some(spec),
                _ => None,
            })
            .collect()
    }

    pub fn build_rs_surfaces(&self) -> Vec<&ExactCrateSpec> {
        self.items
            .iter()
            .filter_map(|item| match item {
                RustAssessmentItem::BuildRsSurface(spec) => Some(spec),
                _ => None,
            })
            .collect()
    }

    pub fn proc_macro_surfaces(&self) -> Vec<&ExactCrateSpec> {
        self.items
            .iter()
            .filter_map(|item| match item {
                RustAssessmentItem::ProcMacroSurface(spec) => Some(spec),
                _ => None,
            })
            .collect()
    }

    pub fn allowed_execution_surfaces(&self) -> &[ReviewedExecutionSurfaceAllowance] {
        &self.allowed_execution_surfaces
    }

    pub fn allowed_release_age_exceptions(&self) -> &[ReviewedReleaseAgeException] {
        &self.allowed_release_age_exceptions
    }

    pub fn inspection_failures(&self) -> Vec<&InspectionFailure> {
        self.items
            .iter()
            .filter_map(|item| match item {
                RustAssessmentItem::InspectionFailure(failure) => Some(failure),
                _ => None,
            })
            .collect()
    }

    pub fn findings(&self) -> &[RustAssessmentFinding] {
        &self.findings
    }
}

/// Aggregates detected items into the coarse per-category findings that drive
/// classification and the blocking/elevated summary sections.
///
/// Blocking categories count whenever their item is present; elevated
/// categories additionally require the matching `high_scrutiny` toggle. This
/// runs once, after every item has been detected, rather than being decided
/// item-by-item at push time, so a category either counts in full or not at
/// all -- matching the historical behaviour where high-scrutiny toggles are
/// per-category switches, not per-item ones.
fn aggregate_findings(
    items: &[RustAssessmentItem],
    high_scrutiny: &HighScrutinyConfig,
) -> Vec<RustAssessmentFinding> {
    let has = |category: RustAssessmentFindingCategory| {
        items.iter().any(|item| item.category() == category)
    };
    let has_non_crates_io_direct = || {
        items.iter().any(|item| match item {
            RustAssessmentItem::NewDirectDependency(dependency) => {
                dependency.source_kind().is_non_crates_io()
            }
            _ => false,
        })
    };

    let mut findings = Vec::new();

    for category in [
        RustAssessmentFindingCategory::AgeViolations,
        RustAssessmentFindingCategory::YankedVersions,
        RustAssessmentFindingCategory::ReleaseAgeExceptionArtefactMismatches,
        RustAssessmentFindingCategory::LockedChecksumDrifts,
        RustAssessmentFindingCategory::InspectionFailures,
    ] {
        if has(category) {
            findings.push(RustAssessmentFinding::blocking(category));
        }
    }

    if high_scrutiny.new_direct_dependencies
        && has(RustAssessmentFindingCategory::NewDirectDependencies)
    {
        findings.push(RustAssessmentFinding::elevated(
            RustAssessmentFindingCategory::NewDirectDependencies,
        ));
    }
    if high_scrutiny.non_crates_io_direct_dependencies && has_non_crates_io_direct() {
        findings.push(RustAssessmentFinding::elevated(
            RustAssessmentFindingCategory::NonCratesIoDirectDependencies,
        ));
    }
    if high_scrutiny.non_crates_io_source_changes
        && has(RustAssessmentFindingCategory::NonCratesIoSourceChanges)
    {
        findings.push(RustAssessmentFinding::elevated(
            RustAssessmentFindingCategory::NonCratesIoSourceChanges,
        ));
    }
    if high_scrutiny.native_sys_crates && has(RustAssessmentFindingCategory::NativeSysCrates) {
        findings.push(RustAssessmentFinding::elevated(
            RustAssessmentFindingCategory::NativeSysCrates,
        ));
    }
    if high_scrutiny.build_rs_changes && has(RustAssessmentFindingCategory::BuildRsSurfaces) {
        findings.push(RustAssessmentFinding::elevated(
            RustAssessmentFindingCategory::BuildRsSurfaces,
        ));
    }
    if high_scrutiny.proc_macro_changes && has(RustAssessmentFindingCategory::ProcMacroSurfaces) {
        findings.push(RustAssessmentFinding::elevated(
            RustAssessmentFindingCategory::ProcMacroSurfaces,
        ));
    }

    findings
}

/// Assess a Rust dependency update at a fixed timestamp.
///
/// Review-record evidence is not verified here because the library performs no
/// filesystem I/O. The returned classification is computed with matching
/// reviewed execution-surface allowances already applied; callers that trust
/// that classification must verify every `allowed_execution_surfaces()` entry
/// and `allowed_release_age_exceptions()` entry is backed by an existing review
/// record.
pub fn assess_rust_update_at<C>(
    client: &C,
    current_lockfile: &Lockfile,
    base_lockfile: &Lockfile,
    current_direct_dependencies: &[CargoManifestDependency],
    base_direct_dependencies: &[CargoManifestDependency],
    metadata: &CargoMetadata,
    minimum_days: u64,
    high_scrutiny: &HighScrutinyConfig,
    reviewed_execution_surface_allowances: &[ReviewedExecutionSurfaceAllowance],
    reviewed_release_age_exceptions: &[ReviewedReleaseAgeException],
    now: OffsetDateTime,
) -> RustAssessmentReport
where
    C: CratesIoClient + ?Sized,
{
    let added_packages = current_lockfile
        .packages()
        .iter()
        .filter(|package| {
            !base_lockfile
                .packages()
                .iter()
                .any(|base_package| base_package.has_same_identity(package))
        })
        .collect::<Vec<_>>();
    let base_package_names: HashSet<&str> = base_lockfile
        .packages()
        .iter()
        .map(|package| package.name.as_str())
        .collect();
    let newly_introduced_crate_names: HashSet<String> = current_lockfile
        .packages()
        .iter()
        .filter(|package| !base_package_names.contains(package.name.as_str()))
        .map(|package| package.name.clone())
        .collect();
    let current_direct: HashSet<CargoManifestDependency> =
        current_direct_dependencies.iter().cloned().collect();
    let base_direct: HashSet<CargoManifestDependency> =
        base_direct_dependencies.iter().cloned().collect();

    let mut items = current_direct
        .difference(&base_direct)
        .cloned()
        .map(RustAssessmentItem::NewDirectDependency)
        .collect::<Vec<_>>();

    items.extend(
        changed_crates_io_checksums(current_lockfile, base_lockfile)
            .into_iter()
            .map(|change| {
                RustAssessmentItem::LockedChecksumDrift(LockedChecksumDrift::new(
                    change.spec().clone(),
                    change.base_checksum().clone(),
                    change.current_checksum().clone(),
                ))
            }),
    );

    let mut allowed_execution_surfaces = Vec::new();
    let mut allowed_release_age_exceptions = Vec::new();

    for package in &added_packages {
        let spec = package.exact_spec().clone();

        if !package.is_crates_io() {
            items.push(RustAssessmentItem::NonCratesIoSourceChange(
                NonCratesIoSourceChange::new(
                    spec.clone(),
                    package.source.clone().unwrap_or_else(|| "none".to_owned()),
                ),
            ));
        } else {
            let age_exception = reviewed_release_age_exceptions
                .iter()
                .find(|exception| exception.spec() == &spec);
            match check_release_age_at(client, &spec, now, minimum_days, age_exception) {
                Ok(report) => match report.outcome() {
                    ReleaseAgeOutcome::Allowed => {}
                    ReleaseAgeOutcome::AllowedByException { .. } => {
                        let exception =
                            age_exception.expect("matching exception produced allowed outcome");
                        allowed_release_age_exceptions.push(exception.clone());
                    }
                    ReleaseAgeOutcome::TooFresh => {
                        items.push(RustAssessmentItem::AgeViolation(ReleaseAgeViolation::new(
                            spec.clone(),
                            report.age_seconds(),
                        )));
                    }
                    ReleaseAgeOutcome::Yanked => {
                        items.push(RustAssessmentItem::YankedVersion(spec.clone()));
                    }
                    ReleaseAgeOutcome::ExceptionArtefactMismatch {
                        family,
                        review_record,
                        expected,
                        found,
                    } => items.push(RustAssessmentItem::ReleaseAgeExceptionArtefactMismatch(
                        ReleaseAgeExceptionArtefactMismatch::new(
                            spec.clone(),
                            family.clone(),
                            review_record.clone(),
                            expected.clone(),
                            found.clone(),
                        ),
                    )),
                },
                Err(error) => {
                    items.push(RustAssessmentItem::InspectionFailure(
                        InspectionFailure::new(spec.clone(), error.to_string()),
                    ));
                }
            }
        }

        match package_surfaces(metadata, &spec) {
            Ok(surfaces) => {
                if is_native_sys_execution_surface(spec.is_native_sys(), surfaces.has_native_links)
                {
                    push_execution_surface(
                        &spec,
                        ExecutionSurfaceKind::NativeSys,
                        reviewed_execution_surface_allowances,
                        &mut items,
                        &mut allowed_execution_surfaces,
                        RustAssessmentItem::NativeSysCrate,
                    );
                }
                if surfaces.has_build_rs {
                    push_execution_surface(
                        &spec,
                        ExecutionSurfaceKind::BuildRs,
                        reviewed_execution_surface_allowances,
                        &mut items,
                        &mut allowed_execution_surfaces,
                        RustAssessmentItem::BuildRsSurface,
                    );
                }
                if surfaces.is_proc_macro {
                    push_execution_surface(
                        &spec,
                        ExecutionSurfaceKind::ProcMacro,
                        reviewed_execution_surface_allowances,
                        &mut items,
                        &mut allowed_execution_surfaces,
                        RustAssessmentItem::ProcMacroSurface,
                    );
                }
            }
            Err(error) => {
                items.push(RustAssessmentItem::InspectionFailure(
                    InspectionFailure::new(spec, error.to_string()),
                ));
            }
        }
    }

    items.sort();
    allowed_execution_surfaces.sort();
    allowed_release_age_exceptions.sort();

    RustAssessmentReport::new(
        added_packages.len(),
        newly_introduced_crate_names.len(),
        items,
        allowed_execution_surfaces,
        allowed_release_age_exceptions,
        high_scrutiny,
    )
}

fn push_execution_surface(
    spec: &ExactCrateSpec,
    surface: ExecutionSurfaceKind,
    allowances: &[ReviewedExecutionSurfaceAllowance],
    items: &mut Vec<RustAssessmentItem>,
    allowed_surfaces: &mut Vec<ReviewedExecutionSurfaceAllowance>,
    make_item: impl FnOnce(ExactCrateSpec) -> RustAssessmentItem,
) {
    match allowances
        .iter()
        .find(|allowance| allowance.spec() == spec && allowance.surface() == surface)
    {
        Some(allowance) => allowed_surfaces.push(allowance.clone()),
        None => items.push(make_item(spec.clone())),
    }
}

#[cfg(test)]
mod tests {
    use time::OffsetDateTime;

    use crate::{
        CargoManifestDependency, CargoMetadata, CrateRelease, CratesIoClient, CratesIoClientError,
        HighScrutinyConfig, Lockfile, parse_cargo_metadata, parse_lockfile,
        parse_manifest_dependencies,
    };

    use super::{
        RustAssessmentClassification, RustAssessmentFinding, RustAssessmentFindingCategory,
        RustAssessmentFindingSeverity, assess_rust_update_at,
    };

    #[derive(Default)]
    struct FakeCratesIoClient {
        responses: std::collections::HashMap<String, Result<CrateRelease, CratesIoClientError>>,
    }

    impl FakeCratesIoClient {
        fn with_release(mut self, spec: &str, published_at: &str, yanked: bool) -> Self {
            self.responses.insert(
                spec.to_owned(),
                Ok(crate::parse_version_response_body(&format!(
                    r#"{{"version":{{"num":"0.0.0","checksum":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","created_at":"{published_at}","yanked":{yanked}}}}}"#
                ))
                .expect("fake response should parse")),
            );
            self
        }

        fn with_error(mut self, spec: &str, error: CratesIoClientError) -> Self {
            self.responses.insert(spec.to_owned(), Err(error));
            self
        }
    }

    impl CratesIoClient for FakeCratesIoClient {
        fn fetch_release(
            &self,
            spec: &crate::ExactCrateSpec,
        ) -> Result<CrateRelease, CratesIoClientError> {
            self.responses
                .get(&spec.to_string())
                .cloned()
                .expect("missing fake release")
        }
    }

    fn parse_direct_dependencies(text: &str) -> Vec<CargoManifestDependency> {
        parse_manifest_dependencies("crates/demo/Cargo.toml", text)
            .expect("manifest should parse")
            .into_iter()
            .collect()
    }

    fn parse_metadata(text: &str) -> CargoMetadata {
        parse_cargo_metadata(text).expect("metadata should parse")
    }

    fn parse_lock(text: &str) -> Lockfile {
        parse_lockfile(text).expect("lockfile should parse")
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::parse(
            "2026-05-26T00:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .expect("timestamp should parse")
    }

    fn reviewed_allowance(
        crate_name: &str,
        version: &str,
        surface: crate::ExecutionSurfaceKind,
    ) -> crate::ReviewedExecutionSurfaceAllowance {
        let reviewed_targets = crate::parse_reviewed_targets_toml(&format!(
            r#"
[rust]

[[rust.families]]
name = "native-family"
review_record = "docs/dependency-reviews/2026-05-27-native.md"

[rust.families.resolved]
{crate_name} = "{version}"

[rust.families.allowed_surfaces]
{crate_name} = ["{surface}"]
"#
        ))
        .expect("reviewed targets should parse");

        reviewed_targets
            .execution_surface_allowances()
            .into_iter()
            .next()
            .expect("allowance should exist")
    }

    #[test]
    fn reports_routine_safe_when_no_findings_are_present() {
        let report = assess_rust_update_at(
            &FakeCratesIoClient::default(),
            &parse_lock(
                r#"
[[package]]
name = "serde"
version = "1.0.227"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
            ),
            &parse_lock(
                r#"
[[package]]
name = "serde"
version = "1.0.227"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
            ),
            &parse_direct_dependencies("[dependencies]\nserde = \"1\"\n"),
            &parse_direct_dependencies("[dependencies]\nserde = \"1\"\n"),
            &parse_metadata(
                r#"{
  "packages": [
    {
      "name": "serde",
      "id": "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.227",
      "version": "1.0.227",
      "targets": [{"kind": ["lib"]}]
    }
  ],
  "workspace_members": [],
  "resolve": null
}"#,
            ),
            7,
            &HighScrutinyConfig::default(),
            &[],
            &[],
            now(),
        );

        assert_eq!(
            report.classification(),
            RustAssessmentClassification::RoutineSafe
        );
        assert!(report.findings().is_empty());
    }

    #[test]
    fn reports_blocking_and_elevated_rust_findings() {
        let report = assess_rust_update_at(
            &FakeCratesIoClient::default().with_release(
                "demo-sys@1.2.3",
                "2026-05-24T00:00:00Z",
                false,
            ),
            &parse_lock(
                r#"
[[package]]
name = "serde"
version = "1.0.227"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "demo-sys"
version = "1.2.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
            ),
            &parse_lock(
                r#"
[[package]]
name = "serde"
version = "1.0.227"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
            ),
            &parse_direct_dependencies("[dependencies]\ndemo-sys = \"1.2.3\"\n"),
            &parse_direct_dependencies(""),
            &parse_metadata(
                r#"{
  "packages": [
    {
      "name": "demo-sys",
      "id": "registry+https://github.com/rust-lang/crates.io-index#demo-sys@1.2.3",
      "version": "1.2.3",
      "targets": [{"kind": ["custom-build"]}]
    }
  ],
  "workspace_members": [],
  "resolve": null
}"#,
            ),
            7,
            &HighScrutinyConfig::default(),
            &[],
            &[],
            now(),
        );

        assert_eq!(
            report.classification(),
            RustAssessmentClassification::PolicyViolating
        );
        assert_eq!(
            report.findings(),
            &[
                RustAssessmentFinding {
                    severity: RustAssessmentFindingSeverity::Blocking,
                    category: RustAssessmentFindingCategory::AgeViolations,
                },
                RustAssessmentFinding {
                    severity: RustAssessmentFindingSeverity::Elevated,
                    category: RustAssessmentFindingCategory::NewDirectDependencies,
                },
                RustAssessmentFinding {
                    severity: RustAssessmentFindingSeverity::Elevated,
                    category: RustAssessmentFindingCategory::NativeSysCrates,
                },
                RustAssessmentFinding {
                    severity: RustAssessmentFindingSeverity::Elevated,
                    category: RustAssessmentFindingCategory::BuildRsSurfaces,
                },
            ]
        );
    }

    #[test]
    fn checksum_drift_for_existing_locked_package_is_policy_violating() {
        let report = assess_rust_update_at(
            &FakeCratesIoClient::default(),
            &parse_lock(
                r#"
[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
"#,
            ),
            &parse_lock(
                r#"
[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
"#,
            ),
            &parse_direct_dependencies("[dependencies]\nserde = \"1\"\n"),
            &parse_direct_dependencies("[dependencies]\nserde = \"1\"\n"),
            &parse_metadata(r#"{"packages":[],"workspace_members":[],"resolve":null}"#),
            7,
            &HighScrutinyConfig::default(),
            &[],
            &[],
            now(),
        );

        assert_eq!(
            report.classification(),
            RustAssessmentClassification::PolicyViolating
        );
        assert_eq!(report.locked_checksum_drifts().len(), 1);
        assert_eq!(
            report.locked_checksum_drifts()[0].spec().to_string(),
            "serde@1.0.228"
        );
        assert_eq!(
            report.findings(),
            &[RustAssessmentFinding {
                severity: RustAssessmentFindingSeverity::Blocking,
                category: RustAssessmentFindingCategory::LockedChecksumDrifts,
            }]
        );
    }

    #[test]
    fn checksum_backfill_for_existing_locked_package_is_not_drift() {
        let report = assess_rust_update_at(
            &FakeCratesIoClient::default(),
            &parse_lock(
                r#"
[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
"#,
            ),
            &parse_lock(
                r#"
[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
            ),
            &parse_direct_dependencies("[dependencies]\nserde = \"1\"\n"),
            &parse_direct_dependencies("[dependencies]\nserde = \"1\"\n"),
            &parse_metadata(r#"{"packages":[],"workspace_members":[],"resolve":null}"#),
            7,
            &HighScrutinyConfig::default(),
            &[],
            &[],
            now(),
        );

        assert_eq!(
            report.classification(),
            RustAssessmentClassification::RoutineSafe
        );
        assert!(report.locked_checksum_drifts().is_empty());
        assert!(report.findings().is_empty());
    }

    #[test]
    fn allowed_execution_surfaces_do_not_create_elevated_findings() {
        let allowances = vec![
            reviewed_allowance("demo-sys", "1.2.3", crate::ExecutionSurfaceKind::NativeSys),
            reviewed_allowance("demo-sys", "1.2.3", crate::ExecutionSurfaceKind::BuildRs),
            reviewed_allowance("demo-sys", "1.2.3", crate::ExecutionSurfaceKind::ProcMacro),
        ];
        let report = assess_rust_update_at(
            &FakeCratesIoClient::default().with_release(
                "demo-sys@1.2.3",
                "2026-05-01T00:00:00Z",
                false,
            ),
            &parse_lock(
                r#"
[[package]]
name = "demo-sys"
version = "1.2.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
            ),
            &parse_lock(""),
            &parse_direct_dependencies("[dependencies]\ndemo-sys = \"1.2.3\"\n"),
            &parse_direct_dependencies(""),
            &parse_metadata(
                r#"{
  "packages": [
    {
      "name": "demo-sys",
      "id": "registry+https://github.com/rust-lang/crates.io-index#demo-sys@1.2.3",
      "version": "1.2.3",
      "targets": [
        {"kind": ["custom-build"]},
        {"kind": ["proc-macro"]}
      ]
    }
  ],
  "workspace_members": [],
  "resolve": null
}"#,
            ),
            7,
            &HighScrutinyConfig {
                new_direct_dependencies: false,
                ..HighScrutinyConfig::default()
            },
            &allowances,
            &[],
            now(),
        );

        assert_eq!(
            report.classification(),
            RustAssessmentClassification::RoutineSafe
        );
        assert!(report.native_sys_crates().is_empty());
        assert!(report.build_rs_surfaces().is_empty());
        assert!(report.proc_macro_surfaces().is_empty());
        assert_eq!(report.allowed_execution_surfaces().len(), 3);
        assert_eq!(
            report.allowed_execution_surfaces()[0].to_string(),
            "demo-sys@1.2.3 build-rs allowed by reviewed family native-family (docs/dependency-reviews/2026-05-27-native.md)"
        );
    }

    #[test]
    fn path_packages_are_recorded_and_surface_checked() {
        let report = assess_rust_update_at(
            &FakeCratesIoClient::default(),
            &parse_lock(
                r#"
[[package]]
name = "local-build"
version = "0.1.0"
"#,
            ),
            &parse_lock(""),
            &parse_direct_dependencies(
                "[dependencies]\nlocal-build = { path = \"local-build\" }\n",
            ),
            &parse_direct_dependencies(""),
            &parse_metadata(
                r#"{
  "packages": [
    {
      "name": "local-build",
      "id": "path+file:///repo/local-build#0.1.0",
      "version": "0.1.0",
      "targets": [{"kind": ["custom-build"]}]
    }
  ],
  "workspace_members": [],
  "resolve": null
}"#,
            ),
            7,
            &HighScrutinyConfig::default(),
            &[],
            &[],
            now(),
        );

        assert_eq!(
            report.classification(),
            RustAssessmentClassification::ElevatedRisk
        );
        assert_eq!(report.non_crates_io_source_changes().len(), 1);
        assert_eq!(report.non_crates_io_source_changes()[0].source(), "none");
        assert_eq!(
            report.build_rs_surfaces(),
            vec![&crate::ExactCrateSpec::from_parts("local-build", "0.1.0").expect("valid spec")]
        );
    }

    #[test]
    fn release_age_failures_do_not_suppress_surface_detection() {
        let report = assess_rust_update_at(
            &FakeCratesIoClient::default().with_error(
                "demo@1.2.3",
                CratesIoClientError::Transport {
                    reason: "offline".to_owned(),
                },
            ),
            &parse_lock(
                r#"
[[package]]
name = "demo"
version = "1.2.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
            ),
            &parse_lock(""),
            &parse_direct_dependencies("[dependencies]\ndemo = \"1.2.3\"\n"),
            &parse_direct_dependencies(""),
            &parse_metadata(
                r#"{
  "packages": [
    {
      "name": "demo",
      "id": "registry+https://github.com/rust-lang/crates.io-index#demo@1.2.3",
      "version": "1.2.3",
      "targets": [{"kind": ["custom-build"]}]
    }
  ],
  "workspace_members": [],
  "resolve": null
}"#,
            ),
            7,
            &HighScrutinyConfig::default(),
            &[],
            &[],
            now(),
        );

        assert_eq!(
            report.classification(),
            RustAssessmentClassification::PolicyViolating
        );
        assert_eq!(report.inspection_failures().len(), 1);
        assert_eq!(
            report.build_rs_surfaces(),
            vec![&crate::ExactCrateSpec::from_parts("demo", "1.2.3").expect("valid spec")]
        );
    }

    #[test]
    fn metadata_links_mark_native_surface_without_sys_suffix() {
        let report = assess_rust_update_at(
            &FakeCratesIoClient::default().with_release(
                "native-link@1.2.3",
                "2026-05-01T00:00:00Z",
                false,
            ),
            &parse_lock(
                r#"
[[package]]
name = "native-link"
version = "1.2.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
            ),
            &parse_lock(""),
            &parse_direct_dependencies("[dependencies]\nnative-link = \"1.2.3\"\n"),
            &parse_direct_dependencies(""),
            &parse_metadata(
                r#"{
  "packages": [
    {
      "name": "native-link",
      "id": "registry+https://github.com/rust-lang/crates.io-index#native-link@1.2.3",
      "version": "1.2.3",
      "links": "native",
      "targets": [{"kind": ["lib"]}]
    }
  ],
  "workspace_members": [],
  "resolve": null
}"#,
            ),
            7,
            &HighScrutinyConfig {
                new_direct_dependencies: false,
                ..HighScrutinyConfig::default()
            },
            &[],
            &[],
            now(),
        );

        assert_eq!(
            report.classification(),
            RustAssessmentClassification::ElevatedRisk
        );
        assert_eq!(
            report.native_sys_crates(),
            vec![&crate::ExactCrateSpec::from_parts("native-link", "1.2.3").expect("valid spec")]
        );
    }

    #[test]
    fn sys_crate_version_bumps_remain_native_surface_findings() {
        let report = assess_rust_update_at(
            &FakeCratesIoClient::default().with_release(
                "native-sys@1.2.4",
                "2026-05-01T00:00:00Z",
                false,
            ),
            &parse_lock(
                r#"
[[package]]
name = "native-sys"
version = "1.2.4"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
            ),
            &parse_lock(
                r#"
[[package]]
name = "native-sys"
version = "1.2.3"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
            ),
            &parse_direct_dependencies("[dependencies]\nnative-sys = \"1.2.4\"\n"),
            &parse_direct_dependencies("[dependencies]\nnative-sys = \"1.2.3\"\n"),
            &parse_metadata(
                r#"{
  "packages": [
    {
      "name": "native-sys",
      "id": "registry+https://github.com/rust-lang/crates.io-index#native-sys@1.2.4",
      "version": "1.2.4",
      "targets": [{"kind": ["lib"]}]
    }
  ],
  "workspace_members": [],
  "resolve": null
}"#,
            ),
            7,
            &HighScrutinyConfig {
                new_direct_dependencies: false,
                ..HighScrutinyConfig::default()
            },
            &[],
            &[],
            now(),
        );

        assert_eq!(
            report.native_sys_crates(),
            vec![&crate::ExactCrateSpec::from_parts("native-sys", "1.2.4").expect("valid spec")]
        );
    }

    #[test]
    fn allowances_do_not_suppress_different_surface_kinds_or_versions() {
        let allowances = vec![
            reviewed_allowance("demo-sys", "1.2.3", crate::ExecutionSurfaceKind::BuildRs),
            reviewed_allowance("drift-sys", "1.2.3", crate::ExecutionSurfaceKind::NativeSys),
        ];
        let report = assess_rust_update_at(
            &FakeCratesIoClient::default()
                .with_release("demo-sys@1.2.3", "2026-05-01T00:00:00Z", false)
                .with_release("drift-sys@1.2.4", "2026-05-01T00:00:00Z", false),
            &parse_lock(
                r#"
[[package]]
name = "demo-sys"
version = "1.2.3"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "drift-sys"
version = "1.2.4"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
            ),
            &parse_lock(""),
            &parse_direct_dependencies(
                "[dependencies]\ndemo-sys = \"1.2.3\"\ndrift-sys = \"1.2.4\"\n",
            ),
            &parse_direct_dependencies(""),
            &parse_metadata(
                r#"{
  "packages": [
    {
      "name": "demo-sys",
      "id": "registry+https://github.com/rust-lang/crates.io-index#demo-sys@1.2.3",
      "version": "1.2.3",
      "targets": [
        {"kind": ["custom-build"]},
        {"kind": ["proc-macro"]}
      ]
    },
    {
      "name": "drift-sys",
      "id": "registry+https://github.com/rust-lang/crates.io-index#drift-sys@1.2.4",
      "version": "1.2.4",
      "targets": []
    }
  ],
  "workspace_members": [],
  "resolve": null
}"#,
            ),
            7,
            &HighScrutinyConfig {
                new_direct_dependencies: false,
                build_rs_changes: false,
                ..HighScrutinyConfig::default()
            },
            &allowances,
            &[],
            now(),
        );

        assert_eq!(
            report.classification(),
            RustAssessmentClassification::ElevatedRisk
        );
        assert_eq!(
            report.proc_macro_surfaces(),
            vec![&crate::ExactCrateSpec::from_parts("demo-sys", "1.2.3").expect("valid spec")]
        );
        assert_eq!(
            report.native_sys_crates(),
            vec![
                &crate::ExactCrateSpec::from_parts("demo-sys", "1.2.3").expect("valid spec"),
                &crate::ExactCrateSpec::from_parts("drift-sys", "1.2.4").expect("valid spec"),
            ]
        );
        assert_eq!(report.allowed_execution_surfaces().len(), 1);
    }
}
