use std::collections::{BTreeMap, BTreeSet};

use crate::reviewed_targets::ObservedResolvedTarget;
use crate::{
    CargoDependencySourceKind, CargoManifestDirectRequirement, Lockfile, ReviewedAdvisoryException,
    ReviewedExecutionSurfaceAllowance, ReviewedResolvedTarget, ReviewedTargets, Sha256Digest,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustReviewedTargetsReport {
    families: Vec<RustReviewedFamilyReport>,
}

impl RustReviewedTargetsReport {
    pub fn families(&self) -> &[RustReviewedFamilyReport] {
        &self.families
    }

    pub fn is_success(&self) -> bool {
        self.families
            .iter()
            .all(RustReviewedFamilyReport::is_success)
    }

    pub fn is_empty(&self) -> bool {
        self.families.is_empty()
    }

    pub fn execution_surface_allowances(&self) -> Vec<&ReviewedExecutionSurfaceAllowance> {
        self.families
            .iter()
            .flat_map(RustReviewedFamilyReport::execution_surface_allowances)
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustReviewedFamilyReport {
    name: String,
    review_record: String,
    direct_checks: Vec<ReviewedDirectDependencyCheck>,
    resolved_checks: Vec<ReviewedResolvedDependencyCheck>,
    execution_surface_allowances: Vec<ReviewedExecutionSurfaceAllowance>,
    advisory_exceptions: Vec<ReviewedAdvisoryException>,
}

impl RustReviewedFamilyReport {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn review_record(&self) -> &str {
        &self.review_record
    }

    pub fn direct_checks(&self) -> &[ReviewedDirectDependencyCheck] {
        &self.direct_checks
    }

    pub fn resolved_checks(&self) -> &[ReviewedResolvedDependencyCheck] {
        &self.resolved_checks
    }

    pub fn execution_surface_allowances(&self) -> &[ReviewedExecutionSurfaceAllowance] {
        &self.execution_surface_allowances
    }

    /// Returns advisory exceptions whose checksum-bound resolved target matched.
    /// Callers must additionally require review-record success before rendering
    /// or applying the exception as honoured policy. Callers that suppress
    /// advisory findings must also enforce the exception's `review_by` expiry.
    pub fn advisory_exceptions_with_matching_resolved_target(
        &self,
    ) -> Vec<&ReviewedAdvisoryException> {
        self.advisory_exception_bindings()
            .into_iter()
            .filter(|binding| binding.resolved_target_matches())
            .map(|binding| binding.exception())
            .collect()
    }

    /// Returns advisory exceptions with their resolved-target binding state.
    ///
    /// This is derived from the reviewed-targets report, not raw config:
    /// `resolved_target_matches` means the checksum-bound reviewed target
    /// matched the current `Cargo.lock`, while `resolved_target_present` means
    /// the crate@version still appears in the current `Cargo.lock`.
    pub fn advisory_exception_bindings(&self) -> Vec<ReviewedAdvisoryExceptionBinding<'_>> {
        self.advisory_exceptions
            .iter()
            .map(|exception| {
                let resolved_check = self
                    .resolved_checks
                    .iter()
                    .find(|check| check.crate_name() == exception.spec().crate_name())
                    .expect("parse_reviewed_targets_toml validates advisory targets resolve");
                ReviewedAdvisoryExceptionBinding {
                    exception,
                    resolved_target_matches: resolved_check.is_success(),
                    resolved_target_present: resolved_check
                        .actual_versions()
                        .contains(exception.spec().version()),
                }
            })
            .collect()
    }

    pub fn is_success(&self) -> bool {
        self.direct_checks
            .iter()
            .all(ReviewedDirectDependencyCheck::is_success)
            && self
                .resolved_checks
                .iter()
                .all(ReviewedResolvedDependencyCheck::is_success)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReviewedAdvisoryExceptionBinding<'a> {
    exception: &'a ReviewedAdvisoryException,
    resolved_target_matches: bool,
    resolved_target_present: bool,
}

impl<'a> ReviewedAdvisoryExceptionBinding<'a> {
    pub fn exception(&self) -> &'a ReviewedAdvisoryException {
        self.exception
    }

    pub fn resolved_target_matches(&self) -> bool {
        self.resolved_target_matches
    }

    pub fn resolved_target_present(&self) -> bool {
        self.resolved_target_present
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewedDirectDependencyCheck {
    crate_name: String,
    expected_requirement: String,
    observed: Vec<ObservedDirectDependency>,
}

impl ReviewedDirectDependencyCheck {
    pub fn crate_name(&self) -> &str {
        &self.crate_name
    }

    pub fn expected_requirement(&self) -> &str {
        &self.expected_requirement
    }

    pub fn observed(&self) -> &[ObservedDirectDependency] {
        &self.observed
    }

    pub fn is_success(&self) -> bool {
        !self.observed.is_empty()
            && self.observed.iter().all(|entry| {
                entry.source_kind().requires_exact_pin()
                    && entry.version_requirement() == Some(self.expected_requirement.as_str())
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedDirectDependency {
    manifest_path: String,
    section: String,
    source_kind: CargoDependencySourceKind,
    version_requirement: Option<String>,
}

impl ObservedDirectDependency {
    pub fn manifest_path(&self) -> &str {
        &self.manifest_path
    }

    pub fn section(&self) -> &str {
        &self.section
    }

    pub fn source_kind(&self) -> CargoDependencySourceKind {
        self.source_kind
    }

    pub fn version_requirement(&self) -> Option<&str> {
        self.version_requirement.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewedResolvedDependencyCheck {
    crate_name: String,
    expected_target: ReviewedResolvedTarget,
    observed_target: ObservedResolvedTarget,
}

impl ReviewedResolvedDependencyCheck {
    pub fn crate_name(&self) -> &str {
        &self.crate_name
    }

    pub fn expected_target(&self) -> &ReviewedResolvedTarget {
        &self.expected_target
    }

    pub fn actual_versions(&self) -> &BTreeSet<String> {
        &self.observed_target.versions
    }

    pub fn actual_checksums_sha256(&self) -> &BTreeSet<Sha256Digest> {
        &self.observed_target.checksums_sha256
    }

    pub fn is_success(&self) -> bool {
        self.expected_target.is_satisfied_by(&self.observed_target)
    }
}

pub fn check_reviewed_rust_targets(
    reviewed_targets: &ReviewedTargets,
    manifest_requirements: &[CargoManifestDirectRequirement],
    lockfile: &Lockfile,
) -> RustReviewedTargetsReport {
    let direct_by_name = manifest_requirements.iter().fold(
        BTreeMap::<&str, Vec<ObservedDirectDependency>>::new(),
        |mut grouped, dependency| {
            grouped
                .entry(dependency.name())
                .or_default()
                .push(ObservedDirectDependency {
                    manifest_path: dependency.manifest_path().to_owned(),
                    section: dependency.section().to_owned(),
                    source_kind: dependency.source_kind(),
                    version_requirement: dependency.version_requirement().map(str::to_owned),
                });
            grouped
        },
    );

    let observed_lockfile_targets = lockfile.packages().iter().fold(
        BTreeMap::<&str, ObservedResolvedTarget>::new(),
        |mut grouped, package| {
            let observed = grouped.entry(package.name.as_str()).or_default();
            observed.versions.insert(package.version.clone());

            if let Some(checksum) = package.checksum.as_ref() {
                observed.checksums_sha256.insert(checksum.clone());
            }

            grouped
        },
    );

    let families = reviewed_targets
        .rust_families()
        .iter()
        .map(|family| {
            let direct_checks = family
                .direct()
                .iter()
                .map(
                    |(crate_name, expected_requirement)| ReviewedDirectDependencyCheck {
                        crate_name: crate_name.clone(),
                        expected_requirement: expected_requirement.clone(),
                        observed: direct_by_name
                            .get(crate_name.as_str())
                            .cloned()
                            .unwrap_or_default(),
                    },
                )
                .collect::<Vec<_>>();

            let resolved_checks = family
                .resolved()
                .iter()
                .map(
                    |(crate_name, expected_target)| ReviewedResolvedDependencyCheck {
                        crate_name: crate_name.clone(),
                        expected_target: expected_target.clone(),
                        observed_target: observed_lockfile_targets
                            .get(crate_name.as_str())
                            .cloned()
                            .unwrap_or_default(),
                    },
                )
                .collect::<Vec<_>>();

            RustReviewedFamilyReport {
                name: family.name().to_owned(),
                review_record: family.review_record().to_owned(),
                direct_checks,
                resolved_checks,
                execution_surface_allowances: family.execution_surface_allowances(),
                advisory_exceptions: family.advisory_exceptions(),
            }
        })
        .collect();

    RustReviewedTargetsReport { families }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use crate::{
        CargoManifestDirectRequirement, CargoManifestError, Sha256Digest,
        check_reviewed_rust_targets, parse_lockfile, parse_manifest_direct_requirements,
        parse_reviewed_targets_toml,
    };

    fn manifest_requirements(
        text: &str,
    ) -> Result<Vec<CargoManifestDirectRequirement>, CargoManifestError> {
        Ok(parse_manifest_direct_requirements("Cargo.toml", text)?
            .into_iter()
            .collect())
    }

    #[test]
    fn passes_when_direct_and_resolved_targets_match_exactly() {
        let reviewed_targets = parse_reviewed_targets_toml(
            r#"
[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.direct]
serde = "=1.0.228"

[rust.families.resolved]
serde = { version = "1.0.228", checksum_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }
serde_derive = "1.0.228"
"#,
        )
        .expect("reviewed targets should parse");
        let manifest_requirements = manifest_requirements("[dependencies]\nserde = \"=1.0.228\"\n")
            .expect("manifest should parse");
        let lockfile = parse_lockfile(
            r#"
[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

[[package]]
name = "serde_derive"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
        )
        .expect("lockfile should parse");

        let report =
            check_reviewed_rust_targets(&reviewed_targets, &manifest_requirements, &lockfile);

        assert!(report.is_success());
        assert_eq!(report.families().len(), 1);
        assert_eq!(
            report.families()[0].resolved_checks()[0]
                .expected_target()
                .checksum_sha256()
                .map(Sha256Digest::as_str),
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        );
    }

    #[test]
    fn report_carries_reviewed_advisory_exceptions() {
        let reviewed_targets = parse_reviewed_targets_toml(
            r#"
[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.resolved]
serde = { version = "1.0.228", checksum_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }

[rust.families.allowed_advisories]
serde = [
  { id = "RUSTSEC-2026-0001", review_by = "2026-09-21" },
]
"#,
        )
        .expect("reviewed targets should parse");
        let manifest_requirements = manifest_requirements("").expect("manifest should parse");
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

        let report =
            check_reviewed_rust_targets(&reviewed_targets, &manifest_requirements, &lockfile);

        assert!(report.is_success());
        assert_eq!(
            report.families()[0]
                .advisory_exceptions_with_matching_resolved_target()
                .len(),
            1
        );
        assert_eq!(
            report.families()[0].advisory_exceptions_with_matching_resolved_target()[0].to_string(),
            "serde@1.0.228 RUSTSEC-2026-0001 accepted by reviewed family serde-family (docs/dependency-reviews/2026-05-27-serde.md), review by 2026-09-21"
        );
    }

    #[test]
    fn report_exposes_only_advisory_exceptions_with_matching_resolved_targets() {
        let reviewed_targets = parse_reviewed_targets_toml(
            r#"
[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.resolved]
serde = { version = "1.0.228", checksum_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }
syn = { version = "2.0.100", checksum_sha256 = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" }

[rust.families.allowed_advisories]
serde = [
  { id = "RUSTSEC-2026-0001", review_by = "2026-09-21" },
]
syn = [
  { id = "RUSTSEC-2026-0002", review_by = "2026-09-21" },
]
"#,
        )
        .expect("reviewed targets should parse");
        let manifest_requirements = manifest_requirements("").expect("manifest should parse");
        let lockfile = parse_lockfile(
            r#"
[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

[[package]]
name = "syn"
version = "2.0.99"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
"#,
        )
        .expect("lockfile should parse");

        let report =
            check_reviewed_rust_targets(&reviewed_targets, &manifest_requirements, &lockfile);
        let matching = report.families()[0].advisory_exceptions_with_matching_resolved_target();

        assert!(!report.is_success());
        assert_eq!(matching.len(), 1);
        assert_eq!(matching[0].spec().to_string(), "serde@1.0.228");
    }

    #[test]
    fn fails_when_direct_requirement_drifts() {
        let reviewed_targets = parse_reviewed_targets_toml(
            r#"
[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.direct]
serde = "=1.0.228"

[rust.families.resolved]
serde = "1.0.228"
"#,
        )
        .expect("reviewed targets should parse");
        let manifest_requirements = manifest_requirements("[dependencies]\nserde = \"1\"\n")
            .expect("manifest should parse");
        let lockfile = parse_lockfile(
            r#"
[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
        )
        .expect("lockfile should parse");

        let report =
            check_reviewed_rust_targets(&reviewed_targets, &manifest_requirements, &lockfile);

        assert!(!report.is_success());
        assert!(!report.families()[0].direct_checks()[0].is_success());
        assert!(report.families()[0].resolved_checks()[0].is_success());
    }

    #[test]
    fn fails_when_lockfile_versions_drift() {
        let reviewed_targets = parse_reviewed_targets_toml(
            r#"
[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.resolved]
serde = "1.0.228"
"#,
        )
        .expect("reviewed targets should parse");
        let manifest_requirements = manifest_requirements("[dependencies]\nserde = \"=1.0.228\"\n")
            .expect("manifest should parse");
        let lockfile = parse_lockfile(
            r#"
[[package]]
name = "serde"
version = "1.0.227"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
        )
        .expect("lockfile should parse");

        let report =
            check_reviewed_rust_targets(&reviewed_targets, &manifest_requirements, &lockfile);

        assert!(!report.is_success());
        assert_eq!(
            report.families()[0].resolved_checks()[0].actual_versions(),
            &BTreeSet::from(["1.0.227".to_owned(), "1.0.228".to_owned()])
        );
    }

    #[test]
    fn fails_when_lockfile_checksum_drifts() {
        let reviewed_targets = parse_reviewed_targets_toml(
            r#"
[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.resolved]
serde = { version = "1.0.228", checksum_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }
"#,
        )
        .expect("reviewed targets should parse");
        let manifest_requirements = manifest_requirements("[dependencies]\nserde = \"=1.0.228\"\n")
            .expect("manifest should parse");
        let lockfile = parse_lockfile(
            r#"
[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
"#,
        )
        .expect("lockfile should parse");

        let report =
            check_reviewed_rust_targets(&reviewed_targets, &manifest_requirements, &lockfile);

        assert!(!report.is_success());
        assert_eq!(
            report.families()[0].resolved_checks()[0].actual_checksums_sha256(),
            &BTreeSet::from([Sha256Digest::try_from(
                "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            )
            .expect("digest should parse")])
        );
    }

    #[test]
    fn fails_when_reviewed_checksum_is_missing_from_lockfile() {
        let reviewed_targets = parse_reviewed_targets_toml(
            r#"
[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.resolved]
serde = { version = "1.0.228", checksum_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }
"#,
        )
        .expect("reviewed targets should parse");
        let manifest_requirements = manifest_requirements("[dependencies]\nserde = \"=1.0.228\"\n")
            .expect("manifest should parse");
        let lockfile = parse_lockfile(
            r#"
[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
        )
        .expect("lockfile should parse");

        let report =
            check_reviewed_rust_targets(&reviewed_targets, &manifest_requirements, &lockfile);

        assert!(!report.is_success());
        assert!(
            report.families()[0].resolved_checks()[0]
                .actual_checksums_sha256()
                .is_empty()
        );
    }

    #[test]
    fn normalises_checksum_casefold_at_parse_boundaries() {
        let reviewed_targets = parse_reviewed_targets_toml(
            r#"
[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.resolved]
serde = { version = "1.0.228", checksum_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }
"#,
        )
        .expect("reviewed targets should parse");
        let manifest_requirements = manifest_requirements("[dependencies]\nserde = \"=1.0.228\"\n")
            .expect("manifest should parse");
        let lockfile = parse_lockfile(
            r#"
[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
"#,
        )
        .expect("lockfile should parse");

        let report =
            check_reviewed_rust_targets(&reviewed_targets, &manifest_requirements, &lockfile);

        assert!(report.is_success());
    }
}
