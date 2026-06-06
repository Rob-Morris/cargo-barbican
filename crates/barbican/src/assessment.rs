use std::collections::HashSet;
use std::fmt;

use time::OffsetDateTime;

use crate::reviewed_targets::ExecutionSurfaceKind;
use crate::{
    CargoManifestDependency, CargoMetadata, CratesIoClient, ExactCrateSpec, HighScrutinyConfig,
    Lockfile, ReleaseAgeOutcome, ReviewedExecutionSurfaceAllowance, Sha256Digest,
    changed_crates_io_checksums, check_release_age_at, package_surfaces,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustAssessmentReport {
    newly_selected_lock_entries: usize,
    newly_introduced_crate_names: usize,
    new_direct_dependencies: Vec<CargoManifestDependency>,
    non_crates_io_direct_dependencies: Vec<CargoManifestDependency>,
    age_violations: Vec<ReleaseAgeViolation>,
    yanked_versions: Vec<ExactCrateSpec>,
    locked_checksum_drifts: Vec<LockedChecksumDrift>,
    non_crates_io_source_changes: Vec<NonCratesIoSourceChange>,
    native_sys_crates: Vec<ExactCrateSpec>,
    build_rs_surfaces: Vec<ExactCrateSpec>,
    proc_macro_surfaces: Vec<ExactCrateSpec>,
    allowed_execution_surfaces: Vec<ReviewedExecutionSurfaceAllowance>,
    inspection_failures: Vec<InspectionFailure>,
    findings: Vec<RustAssessmentFinding>,
}

impl RustAssessmentReport {
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

    pub fn new_direct_dependencies(&self) -> &[CargoManifestDependency] {
        &self.new_direct_dependencies
    }

    pub fn non_crates_io_direct_dependencies(&self) -> &[CargoManifestDependency] {
        &self.non_crates_io_direct_dependencies
    }

    pub fn age_violations(&self) -> &[ReleaseAgeViolation] {
        &self.age_violations
    }

    pub fn yanked_versions(&self) -> &[ExactCrateSpec] {
        &self.yanked_versions
    }

    pub fn locked_checksum_drifts(&self) -> &[LockedChecksumDrift] {
        &self.locked_checksum_drifts
    }

    pub fn non_crates_io_source_changes(&self) -> &[NonCratesIoSourceChange] {
        &self.non_crates_io_source_changes
    }

    pub fn native_sys_crates(&self) -> &[ExactCrateSpec] {
        &self.native_sys_crates
    }

    pub fn build_rs_surfaces(&self) -> &[ExactCrateSpec] {
        &self.build_rs_surfaces
    }

    pub fn proc_macro_surfaces(&self) -> &[ExactCrateSpec] {
        &self.proc_macro_surfaces
    }

    pub fn allowed_execution_surfaces(&self) -> &[ReviewedExecutionSurfaceAllowance] {
        &self.allowed_execution_surfaces
    }

    pub fn inspection_failures(&self) -> &[InspectionFailure] {
        &self.inspection_failures
    }

    pub fn findings(&self) -> &[RustAssessmentFinding] {
        &self.findings
    }
}

pub fn assess_rust_update<C>(
    client: &C,
    current_lockfile: &Lockfile,
    base_lockfile: &Lockfile,
    current_direct_dependencies: &[CargoManifestDependency],
    base_direct_dependencies: &[CargoManifestDependency],
    metadata: &CargoMetadata,
    minimum_days: u64,
    high_scrutiny: &HighScrutinyConfig,
) -> RustAssessmentReport
where
    C: CratesIoClient + ?Sized,
{
    assess_rust_update_at(
        client,
        current_lockfile,
        base_lockfile,
        current_direct_dependencies,
        base_direct_dependencies,
        metadata,
        minimum_days,
        high_scrutiny,
        &[],
        OffsetDateTime::now_utc(),
    )
}

/// Assess a Rust dependency update at a fixed timestamp.
///
/// Review-record evidence is not verified here because the library performs no
/// filesystem I/O. The returned classification is computed with matching
/// reviewed execution-surface allowances already applied; callers that trust
/// that classification must verify every `allowed_execution_surfaces()` entry
/// is backed by an existing review record.
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
    let mut new_direct_dependencies = current_direct
        .difference(&base_direct)
        .cloned()
        .collect::<Vec<_>>();
    let mut non_crates_io_direct_dependencies = current_direct
        .difference(&base_direct)
        .filter(|dependency| dependency.source_kind().is_non_crates_io())
        .cloned()
        .collect::<Vec<_>>();

    let mut age_violations = Vec::new();
    let mut yanked_versions = Vec::new();
    let mut locked_checksum_drifts = changed_crates_io_checksums(current_lockfile, base_lockfile)
        .into_iter()
        .map(|change| {
            LockedChecksumDrift::new(
                change.spec().clone(),
                change.base_checksum().clone(),
                change.current_checksum().clone(),
            )
        })
        .collect::<Vec<_>>();
    let mut non_crates_io_source_changes = Vec::new();
    let mut native_sys_crates = Vec::new();
    let mut build_rs_surfaces = Vec::new();
    let mut proc_macro_surfaces = Vec::new();
    let mut allowed_execution_surfaces = Vec::new();
    let mut inspection_failures = Vec::new();

    for package in &added_packages {
        let spec = package.exact_spec().clone();

        if !package.is_crates_io() {
            non_crates_io_source_changes.push(NonCratesIoSourceChange::new(
                spec.clone(),
                package.source.clone().unwrap_or_else(|| "none".to_owned()),
            ));
        } else {
            match check_release_age_at(client, &spec, now, minimum_days) {
                Ok(report) => match report.outcome() {
                    ReleaseAgeOutcome::Allowed => {}
                    ReleaseAgeOutcome::TooFresh => {
                        age_violations
                            .push(ReleaseAgeViolation::new(spec.clone(), report.age_seconds()));
                    }
                    ReleaseAgeOutcome::Yanked => yanked_versions.push(spec.clone()),
                },
                Err(error) => {
                    inspection_failures
                        .push(InspectionFailure::new(spec.clone(), error.to_string()));
                }
            }
        }

        match package_surfaces(metadata, &spec) {
            Ok(surfaces) => {
                if surfaces.has_native_links || spec.is_native_sys() {
                    push_execution_surface(
                        &spec,
                        ExecutionSurfaceKind::NativeSys,
                        reviewed_execution_surface_allowances,
                        &mut native_sys_crates,
                        &mut allowed_execution_surfaces,
                    );
                }
                if surfaces.has_build_rs {
                    push_execution_surface(
                        &spec,
                        ExecutionSurfaceKind::BuildRs,
                        reviewed_execution_surface_allowances,
                        &mut build_rs_surfaces,
                        &mut allowed_execution_surfaces,
                    );
                }
                if surfaces.is_proc_macro {
                    push_execution_surface(
                        &spec,
                        ExecutionSurfaceKind::ProcMacro,
                        reviewed_execution_surface_allowances,
                        &mut proc_macro_surfaces,
                        &mut allowed_execution_surfaces,
                    );
                }
            }
            Err(error) => {
                inspection_failures.push(InspectionFailure::new(spec, error.to_string()));
            }
        }
    }

    new_direct_dependencies.sort();
    non_crates_io_direct_dependencies.sort();
    age_violations.sort();
    yanked_versions.sort();
    locked_checksum_drifts.sort();
    non_crates_io_source_changes.sort();
    native_sys_crates.sort();
    build_rs_surfaces.sort();
    proc_macro_surfaces.sort();
    allowed_execution_surfaces.sort();
    inspection_failures.sort();

    let mut findings = Vec::new();

    if !age_violations.is_empty() {
        findings.push(RustAssessmentFinding::blocking(
            RustAssessmentFindingCategory::AgeViolations,
        ));
    }
    if !yanked_versions.is_empty() {
        findings.push(RustAssessmentFinding::blocking(
            RustAssessmentFindingCategory::YankedVersions,
        ));
    }
    if !locked_checksum_drifts.is_empty() {
        findings.push(RustAssessmentFinding::blocking(
            RustAssessmentFindingCategory::LockedChecksumDrifts,
        ));
    }
    if !inspection_failures.is_empty() {
        findings.push(RustAssessmentFinding::blocking(
            RustAssessmentFindingCategory::InspectionFailures,
        ));
    }
    if high_scrutiny.new_direct_dependencies && !new_direct_dependencies.is_empty() {
        findings.push(RustAssessmentFinding::elevated(
            RustAssessmentFindingCategory::NewDirectDependencies,
        ));
    }
    if high_scrutiny.non_crates_io_direct_dependencies
        && !non_crates_io_direct_dependencies.is_empty()
    {
        findings.push(RustAssessmentFinding::elevated(
            RustAssessmentFindingCategory::NonCratesIoDirectDependencies,
        ));
    }
    if high_scrutiny.non_crates_io_source_changes && !non_crates_io_source_changes.is_empty() {
        findings.push(RustAssessmentFinding::elevated(
            RustAssessmentFindingCategory::NonCratesIoSourceChanges,
        ));
    }
    if high_scrutiny.native_sys_crates && !native_sys_crates.is_empty() {
        findings.push(RustAssessmentFinding::elevated(
            RustAssessmentFindingCategory::NativeSysCrates,
        ));
    }
    if high_scrutiny.build_rs_changes && !build_rs_surfaces.is_empty() {
        findings.push(RustAssessmentFinding::elevated(
            RustAssessmentFindingCategory::BuildRsSurfaces,
        ));
    }
    if high_scrutiny.proc_macro_changes && !proc_macro_surfaces.is_empty() {
        findings.push(RustAssessmentFinding::elevated(
            RustAssessmentFindingCategory::ProcMacroSurfaces,
        ));
    }

    RustAssessmentReport {
        newly_selected_lock_entries: added_packages.len(),
        newly_introduced_crate_names: newly_introduced_crate_names.len(),
        new_direct_dependencies,
        non_crates_io_direct_dependencies,
        age_violations,
        yanked_versions,
        locked_checksum_drifts,
        non_crates_io_source_changes,
        native_sys_crates,
        build_rs_surfaces,
        proc_macro_surfaces,
        allowed_execution_surfaces,
        inspection_failures,
        findings,
    }
}

fn push_execution_surface(
    spec: &ExactCrateSpec,
    surface: ExecutionSurfaceKind,
    allowances: &[ReviewedExecutionSurfaceAllowance],
    elevated_surfaces: &mut Vec<ExactCrateSpec>,
    allowed_surfaces: &mut Vec<ReviewedExecutionSurfaceAllowance>,
) {
    match allowances
        .iter()
        .find(|allowance| allowance.spec() == spec && allowance.surface() == surface)
    {
        Some(allowance) => allowed_surfaces.push(allowance.clone()),
        None => elevated_surfaces.push(spec.clone()),
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
                    r#"{{"version":{{"checksum":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","created_at":"{published_at}","yanked":{yanked}}}}}"#
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
            &[crate::ExactCrateSpec::from_parts("local-build", "0.1.0").expect("valid spec")]
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
            now(),
        );

        assert_eq!(
            report.classification(),
            RustAssessmentClassification::PolicyViolating
        );
        assert_eq!(report.inspection_failures().len(), 1);
        assert_eq!(
            report.build_rs_surfaces(),
            &[crate::ExactCrateSpec::from_parts("demo", "1.2.3").expect("valid spec")]
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
            now(),
        );

        assert_eq!(
            report.classification(),
            RustAssessmentClassification::ElevatedRisk
        );
        assert_eq!(
            report.native_sys_crates(),
            &[crate::ExactCrateSpec::from_parts("native-link", "1.2.3").expect("valid spec")]
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
            now(),
        );

        assert_eq!(
            report.native_sys_crates(),
            &[crate::ExactCrateSpec::from_parts("native-sys", "1.2.4").expect("valid spec")]
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
            now(),
        );

        assert_eq!(
            report.classification(),
            RustAssessmentClassification::ElevatedRisk
        );
        assert_eq!(
            report.proc_macro_surfaces(),
            &[crate::ExactCrateSpec::from_parts("demo-sys", "1.2.3").expect("valid spec")]
        );
        assert_eq!(
            report.native_sys_crates(),
            &[
                crate::ExactCrateSpec::from_parts("demo-sys", "1.2.3").expect("valid spec"),
                crate::ExactCrateSpec::from_parts("drift-sys", "1.2.4").expect("valid spec"),
            ]
        );
        assert_eq!(report.allowed_execution_surfaces().len(), 1);
    }
}
