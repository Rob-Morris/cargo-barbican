use std::collections::HashSet;
use std::fmt;

use time::OffsetDateTime;

use crate::{
    CargoManifestDependency, CargoMetadata, CratesIoClient, ExactCrateSpec, HighScrutinyConfig,
    Lockfile, ReleaseAgeOutcome, check_release_age_at, package_surfaces,
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
    non_crates_io_source_changes: Vec<NonCratesIoSourceChange>,
    native_sys_crates: Vec<ExactCrateSpec>,
    build_rs_surfaces: Vec<ExactCrateSpec>,
    proc_macro_surfaces: Vec<ExactCrateSpec>,
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
        OffsetDateTime::now_utc(),
    )
}

pub fn assess_rust_update_at<C>(
    client: &C,
    current_lockfile: &Lockfile,
    base_lockfile: &Lockfile,
    current_direct_dependencies: &[CargoManifestDependency],
    base_direct_dependencies: &[CargoManifestDependency],
    metadata: &CargoMetadata,
    minimum_days: u64,
    high_scrutiny: &HighScrutinyConfig,
    now: OffsetDateTime,
) -> RustAssessmentReport
where
    C: CratesIoClient + ?Sized,
{
    let base_packages: HashSet<_> = base_lockfile.packages().iter().collect();
    let added_packages = current_lockfile
        .packages()
        .iter()
        .filter(|package| !base_packages.contains(package))
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
    let mut non_crates_io_source_changes = Vec::new();
    let mut native_sys_crates = Vec::new();
    let mut build_rs_surfaces = Vec::new();
    let mut proc_macro_surfaces = Vec::new();
    let mut inspection_failures = Vec::new();

    for package in &added_packages {
        let spec = package
            .exact_spec()
            .expect("parse_lockfile guarantees exact locked package specs");

        if !package.is_crates_io() {
            if let Some(source) = package.source.as_deref() {
                non_crates_io_source_changes.push(NonCratesIoSourceChange::new(
                    spec.clone(),
                    source.to_owned(),
                ));
            }
            continue;
        }

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
                inspection_failures.push(InspectionFailure::new(spec.clone(), error.to_string()));
                continue;
            }
        }

        match package_surfaces(metadata, &spec) {
            Ok(surfaces) => {
                if newly_introduced_crate_names.contains(spec.crate_name())
                    && spec.crate_name().ends_with("-sys")
                {
                    native_sys_crates.push(spec.clone());
                }
                if surfaces.has_build_rs {
                    build_rs_surfaces.push(spec.clone());
                }
                if surfaces.is_proc_macro {
                    proc_macro_surfaces.push(spec.clone());
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
    non_crates_io_source_changes.sort();
    native_sys_crates.sort();
    build_rs_surfaces.sort();
    proc_macro_surfaces.sort();
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
        non_crates_io_source_changes,
        native_sys_crates,
        build_rs_surfaces,
        proc_macro_surfaces,
        inspection_failures,
        findings,
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
                    r#"{{"version":{{"checksum":"abc123","created_at":"{published_at}","yanked":{yanked}}}}}"#
                ))
                .expect("fake response should parse")),
            );
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
}
