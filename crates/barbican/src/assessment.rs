use std::collections::HashSet;
use std::fmt;

use time::OffsetDateTime;

use crate::{
    CargoManifestDependency, CargoMetadata, CratesIoClient, HighScrutinyConfig, Lockfile,
    ReleaseAgeOutcome, check_release_age_at, package_surfaces,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustAssessmentReport {
    newly_selected_lock_entries: usize,
    newly_introduced_crate_names: usize,
    new_direct_dependencies: Vec<String>,
    non_crates_io_direct_dependencies: Vec<String>,
    age_violations: Vec<String>,
    yanked_versions: Vec<String>,
    non_crates_io_source_changes: Vec<String>,
    native_sys_crates: Vec<String>,
    build_rs_surfaces: Vec<String>,
    proc_macro_surfaces: Vec<String>,
    inspection_failures: Vec<String>,
    blocking_findings: Vec<String>,
    elevated_findings: Vec<String>,
}

impl RustAssessmentReport {
    pub fn classification(&self) -> RustAssessmentClassification {
        if !self.blocking_findings.is_empty() {
            RustAssessmentClassification::PolicyViolating
        } else if !self.elevated_findings.is_empty() {
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

    pub fn new_direct_dependencies(&self) -> &[String] {
        &self.new_direct_dependencies
    }

    pub fn non_crates_io_direct_dependencies(&self) -> &[String] {
        &self.non_crates_io_direct_dependencies
    }

    pub fn age_violations(&self) -> &[String] {
        &self.age_violations
    }

    pub fn yanked_versions(&self) -> &[String] {
        &self.yanked_versions
    }

    pub fn non_crates_io_source_changes(&self) -> &[String] {
        &self.non_crates_io_source_changes
    }

    pub fn native_sys_crates(&self) -> &[String] {
        &self.native_sys_crates
    }

    pub fn build_rs_surfaces(&self) -> &[String] {
        &self.build_rs_surfaces
    }

    pub fn proc_macro_surfaces(&self) -> &[String] {
        &self.proc_macro_surfaces
    }

    pub fn inspection_failures(&self) -> &[String] {
        &self.inspection_failures
    }

    pub fn blocking_findings(&self) -> &[String] {
        &self.blocking_findings
    }

    pub fn elevated_findings(&self) -> &[String] {
        &self.elevated_findings
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
        .map(render_manifest_dependency)
        .collect::<Vec<_>>();
    let mut non_crates_io_direct_dependencies = current_direct
        .difference(&base_direct)
        .filter(|dependency| dependency.source_kind().is_non_crates_io())
        .map(render_manifest_dependency_with_source)
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
        let spec_string = spec.to_string();

        if !package.is_crates_io() {
            if let Some(source) = package.source.as_deref() {
                non_crates_io_source_changes.push(format!("{spec_string} source={source}"));
            }
            continue;
        }

        match check_release_age_at(client, &spec, now, minimum_days) {
            Ok(report) => match report.outcome() {
                ReleaseAgeOutcome::Allowed => {}
                ReleaseAgeOutcome::TooFresh => {
                    age_violations.push(format!(
                        "{spec_string} ({} old)",
                        crate::format_age(report.age_seconds())
                    ));
                }
                ReleaseAgeOutcome::Yanked => yanked_versions.push(spec_string.clone()),
            },
            Err(error) => {
                inspection_failures.push(format!("{spec_string}: {error}"));
                continue;
            }
        }

        match package_surfaces(metadata, &spec) {
            Ok(surfaces) => {
                if newly_introduced_crate_names.contains(spec.crate_name())
                    && spec.crate_name().ends_with("-sys")
                {
                    native_sys_crates.push(spec_string.clone());
                }
                if surfaces.has_build_rs {
                    build_rs_surfaces.push(spec_string.clone());
                }
                if surfaces.is_proc_macro {
                    proc_macro_surfaces.push(spec_string);
                }
            }
            Err(error) => inspection_failures.push(format!("{spec_string}: {error}")),
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

    let mut blocking_findings = Vec::new();
    let mut elevated_findings = Vec::new();

    if !age_violations.is_empty() {
        blocking_findings.push(format!(
            "newly selected crates.io versions below the minimum age: {}",
            age_violations.join(", ")
        ));
    }
    if !yanked_versions.is_empty() {
        blocking_findings.push(format!(
            "newly selected yanked crate versions: {}",
            yanked_versions.join(", ")
        ));
    }
    if !inspection_failures.is_empty() {
        blocking_findings.push(format!(
            "failed to inspect some Rust dependency surfaces: {}",
            inspection_failures.join("; ")
        ));
    }
    if high_scrutiny.new_direct_dependencies && !new_direct_dependencies.is_empty() {
        elevated_findings.push(format!(
            "new direct Rust dependencies added: {}",
            new_direct_dependencies.join(", ")
        ));
    }
    if high_scrutiny.non_crates_io_direct_dependencies
        && !non_crates_io_direct_dependencies.is_empty()
    {
        elevated_findings.push(format!(
            "new non-crates.io direct Rust dependency specs detected: {}",
            non_crates_io_direct_dependencies.join(", ")
        ));
    }
    if high_scrutiny.non_crates_io_source_changes && !non_crates_io_source_changes.is_empty() {
        elevated_findings.push(format!(
            "non-crates.io source changes detected: {}",
            non_crates_io_source_changes.join(", ")
        ));
    }
    if high_scrutiny.native_sys_crates && !native_sys_crates.is_empty() {
        elevated_findings.push(format!(
            "new native -sys crates introduced: {}",
            native_sys_crates.join(", ")
        ));
    }
    if high_scrutiny.build_rs_changes && !build_rs_surfaces.is_empty() {
        elevated_findings.push(format!(
            "new or changed build.rs surface detected: {}",
            build_rs_surfaces.join(", ")
        ));
    }
    if high_scrutiny.proc_macro_changes && !proc_macro_surfaces.is_empty() {
        elevated_findings.push(format!(
            "new or changed proc-macro surface detected: {}",
            proc_macro_surfaces.join(", ")
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
        blocking_findings,
        elevated_findings,
    }
}

fn render_manifest_dependency(dependency: &CargoManifestDependency) -> String {
    format!(
        "{}:{}:{}",
        dependency.manifest_path(),
        dependency.section(),
        dependency.name()
    )
}

fn render_manifest_dependency_with_source(dependency: &CargoManifestDependency) -> String {
    format!(
        "{} ({})",
        render_manifest_dependency(dependency),
        dependency.source_kind()
    )
}

#[cfg(test)]
mod tests {
    use time::OffsetDateTime;

    use crate::{
        CargoManifestDependency, CargoMetadata, CrateRelease, CratesIoClient, CratesIoClientError,
        HighScrutinyConfig, Lockfile, parse_cargo_metadata, parse_lockfile,
        parse_manifest_dependencies,
    };

    use super::{RustAssessmentClassification, assess_rust_update_at};

    #[derive(Default)]
    struct FakeCratesIoClient {
        responses: std::collections::HashMap<String, Result<CrateRelease, CratesIoClientError>>,
    }

    impl FakeCratesIoClient {
        fn with_release(mut self, spec: &str, published_at: &str, yanked: bool) -> Self {
            self.responses.insert(
                spec.to_owned(),
                Ok(crate::parse_version_response_body(&format!(
                    r#"{{"version":{{"created_at":"{published_at}","yanked":{yanked}}}}}"#
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
        assert!(report.blocking_findings().is_empty());
        assert!(report.elevated_findings().is_empty());
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
        assert!(
            report
                .blocking_findings()
                .iter()
                .any(|finding| finding.contains("below the minimum age"))
        );
        assert!(
            report
                .elevated_findings()
                .iter()
                .any(|finding| finding.contains("new direct Rust dependencies added"))
        );
        assert!(
            report
                .elevated_findings()
                .iter()
                .any(|finding| finding.contains("new native -sys crates introduced"))
        );
        assert!(
            report
                .elevated_findings()
                .iter()
                .any(|finding| finding.contains("new or changed build.rs surface detected"))
        );
    }
}
