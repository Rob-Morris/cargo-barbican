use std::collections::{BTreeMap, BTreeSet};

use crate::inventory::ReviewRecordFact;
use crate::reviewed_targets::ObservedResolvedTarget;
use crate::{
    CargoDependencySourceKind, CargoManifestDirectRequirement, Lockfile, ReviewedAdvisoryException,
    ReviewedExecutionSurfaceAllowance, ReviewedResolvedTarget, ReviewedTargets, Sha256Digest,
};

const NO_SOURCE_LABEL: &str = "(no source: path or workspace member)";

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

    /// The one advisory-exception binding join: an exception is bound (safe to
    /// render or apply as an accepted policy exception) only when its
    /// family's review record actually exists on disk, not merely referenced
    /// in policy. `review_record_facts` carries that record-exists fact per
    /// family, keeping the filesystem check itself in the shell.
    pub fn advisory_exceptions_bound_to_reviewed_records(
        &self,
        review_record_facts: &[ReviewRecordFact],
    ) -> Vec<&ReviewedAdvisoryException> {
        self.families
            .iter()
            .filter(|family| {
                review_record_facts
                    .iter()
                    .any(|fact| fact.family_name() == family.name() && fact.exists())
            })
            .flat_map(RustReviewedFamilyReport::advisory_exceptions_with_matching_resolved_target)
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
    ///
    /// Every exception's crate name is a key of the same family's `resolved`
    /// map (enforced by `parse_reviewed_targets_toml`), and `resolved_checks`
    /// carries one entry per resolved key, so the lookup below always hits in
    /// practice. If it ever did not, both flags fall back to `false` rather
    /// than trusting that invariant with a panic: an exception whose
    /// `Cargo.lock` observation cannot be found must not suppress findings.
    pub fn advisory_exception_bindings(&self) -> Vec<ReviewedAdvisoryExceptionBinding<'_>> {
        let observed_by_crate_name: BTreeMap<&str, &ObservedResolvedTarget> = self
            .resolved_checks
            .iter()
            .map(|check| (check.crate_name(), check.observed_target()))
            .collect();

        self.advisory_exceptions
            .iter()
            .map(|exception| {
                let observed = observed_by_crate_name
                    .get(exception.spec().crate_name())
                    .copied();
                ReviewedAdvisoryExceptionBinding {
                    exception,
                    resolved_target_matches: observed.is_some_and(|observed| {
                        exception.expected_target().is_satisfied_by(observed)
                    }),
                    resolved_target_present: observed.is_some_and(|observed| {
                        observed.versions.contains(exception.spec().version())
                    }),
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

    pub(crate) fn observed_target(&self) -> &ObservedResolvedTarget {
        &self.observed_target
    }

    pub fn actual_versions(&self) -> &BTreeSet<String> {
        &self.observed_target.versions
    }

    pub fn actual_checksums_sha256(&self) -> &BTreeSet<Sha256Digest> {
        &self.observed_target.checksums_sha256
    }

    /// Non-crates.io sources observed for this crate name in `Cargo.lock`,
    /// including `NO_SOURCE_LABEL` for path/workspace members. Non-empty
    /// means at least one locked entry for this crate name did not resolve
    /// from crates.io, regardless of whether another entry matches the
    /// reviewed version/checksum.
    pub fn non_crates_io_sources(&self) -> &BTreeSet<String> {
        &self.observed_target.non_crates_io_sources
    }

    /// True when at least one `Cargo.lock` entry matching this crate name
    /// carries no checksum. Distinct from an absent checksum overall: this
    /// flags a checksum-less entry coexisting with (or standing in for) the
    /// reviewed artefact.
    pub fn has_checksumless_entry(&self) -> bool {
        self.observed_target.has_checksumless_entry
    }

    pub fn is_success(&self) -> bool {
        self.expected_target.is_satisfied_by(&self.observed_target)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PatchedReviewedCrate {
    crate_name: String,
    family: String,
}

impl PatchedReviewedCrate {
    pub fn crate_name(&self) -> &str {
        &self.crate_name
    }

    pub fn family(&self) -> &str {
        &self.family
    }
}

/// Returns reviewed-family crates that a manifest `[patch]` table also
/// targets. `[patch]` repoints an already-reviewed crate name at a different
/// source without touching `Cargo.lock` checksums or `[dependencies]`, so a
/// patched reviewed crate bypasses the resolved-target gate entirely and must
/// fail closed.
pub fn patched_reviewed_crates(
    reviewed_targets: &ReviewedTargets,
    patched_crate_names: &BTreeSet<String>,
) -> Vec<PatchedReviewedCrate> {
    let mut patched = Vec::new();

    for family in reviewed_targets.rust_families() {
        let covered_names = family
            .resolved()
            .keys()
            .chain(family.direct().keys())
            .collect::<BTreeSet<_>>();

        for crate_name in patched_crate_names {
            if covered_names.contains(crate_name) {
                patched.push(PatchedReviewedCrate {
                    crate_name: crate_name.clone(),
                    family: family.name().to_owned(),
                });
            }
        }
    }

    patched
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

            if !package.is_crates_io() {
                observed.non_crates_io_sources.insert(
                    package
                        .source
                        .as_deref()
                        .unwrap_or(NO_SOURCE_LABEL)
                        .to_owned(),
                );
            }

            match package.checksum.as_ref() {
                Some(checksum) => {
                    observed.checksums_sha256.insert(checksum.clone());
                }
                None => observed.has_checksumless_entry = true,
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
                execution_surface_allowances: family.execution_surface_allowances().to_vec(),
                advisory_exceptions: family.advisory_exceptions().to_vec(),
            }
        })
        .collect();

    RustReviewedTargetsReport { families }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use crate::{
        CargoManifestDirectRequirement, CargoManifestError, ReviewRecordFact, Sha256Digest,
        check_reviewed_rust_targets, parse_lockfile, parse_manifest_direct_requirements,
        parse_manifest_patched_crate_names, parse_reviewed_targets_toml, patched_reviewed_crates,
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
    fn advisory_exceptions_are_suppressed_for_families_missing_review_records() {
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

[[rust.families]]
name = "syn-family"
review_record = "docs/dependency-reviews/2026-05-27-syn.md"

[rust.families.resolved]
syn = { version = "2.0.100", checksum_sha256 = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" }

[rust.families.allowed_advisories]
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
version = "2.0.100"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
"#,
        )
        .expect("lockfile should parse");

        let report =
            check_reviewed_rust_targets(&reviewed_targets, &manifest_requirements, &lockfile);
        let review_record_facts = vec![
            ReviewRecordFact::new(
                "serde-family".to_owned(),
                "docs/dependency-reviews/2026-05-27-serde.md".to_owned(),
                true,
            ),
            ReviewRecordFact::new(
                "syn-family".to_owned(),
                "docs/dependency-reviews/2026-05-27-syn.md".to_owned(),
                false,
            ),
        ];

        let bound = report.advisory_exceptions_bound_to_reviewed_records(&review_record_facts);

        assert_eq!(bound.len(), 1);
        assert_eq!(bound[0].spec().to_string(), "serde@1.0.228");
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
    fn fails_when_lockfile_reports_extra_checksum_even_if_expected_is_present() {
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
checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

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
            report.families()[0].resolved_checks()[0].actual_versions(),
            &BTreeSet::from(["1.0.228".to_owned()])
        );
        assert_eq!(
            report.families()[0].resolved_checks()[0].actual_checksums_sha256(),
            &BTreeSet::from([
                Sha256Digest::try_from(
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                )
                .expect("digest should parse"),
                Sha256Digest::try_from(
                    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                )
                .expect("digest should parse"),
            ])
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

    #[test]
    fn fails_when_a_git_doppelgaenger_accompanies_the_reviewed_registry_entry() {
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
        let manifest_requirements = manifest_requirements("").expect("manifest should parse");
        let lockfile = parse_lockfile(
            r#"
[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

[[package]]
name = "serde"
version = "1.0.228"
source = "git+https://attacker.example/serde"
"#,
        )
        .expect("lockfile should parse");

        let report =
            check_reviewed_rust_targets(&reviewed_targets, &manifest_requirements, &lockfile);

        assert!(!report.is_success());
        assert_eq!(
            report.families()[0].resolved_checks()[0].non_crates_io_sources(),
            &BTreeSet::from(["git+https://attacker.example/serde".to_owned()])
        );
    }

    #[test]
    fn fails_when_a_checksumless_git_entry_stands_in_for_a_version_only_reviewed_target() {
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
        let manifest_requirements = manifest_requirements("").expect("manifest should parse");
        let lockfile = parse_lockfile(
            r#"
[[package]]
name = "serde"
version = "1.0.228"
source = "git+https://attacker.example/serde"
"#,
        )
        .expect("lockfile should parse");

        let report =
            check_reviewed_rust_targets(&reviewed_targets, &manifest_requirements, &lockfile);

        assert!(!report.is_success());
        assert_eq!(
            report.families()[0].resolved_checks()[0].non_crates_io_sources(),
            &BTreeSet::from(["git+https://attacker.example/serde".to_owned()])
        );
    }

    #[test]
    fn fails_when_a_crates_io_entry_matching_the_reviewed_checksum_target_has_no_checksum() {
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
        let manifest_requirements = manifest_requirements("").expect("manifest should parse");
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
        assert!(report.families()[0].resolved_checks()[0].has_checksumless_entry());
        assert!(
            report.families()[0].resolved_checks()[0]
                .non_crates_io_sources()
                .is_empty()
        );
    }

    #[test]
    fn fails_when_a_checksumless_crates_io_sibling_accompanies_the_expected_checksum() {
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
        let manifest_requirements = manifest_requirements("").expect("manifest should parse");
        let lockfile = parse_lockfile(
            r#"
[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

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
        assert!(report.families()[0].resolved_checks()[0].has_checksumless_entry());
        assert!(
            report.families()[0].resolved_checks()[0]
                .non_crates_io_sources()
                .is_empty()
        );
    }

    #[test]
    fn passes_for_path_or_workspace_members_labels_missing_source_distinctly() {
        let reviewed_targets = parse_reviewed_targets_toml(
            r#"
[rust]

[[rust.families]]
name = "local-family"
review_record = "docs/dependency-reviews/2026-05-27-local.md"

[rust.families.resolved]
local-crate = "0.1.0"
"#,
        )
        .expect("reviewed targets should parse");
        let manifest_requirements = manifest_requirements("").expect("manifest should parse");
        let lockfile = parse_lockfile(
            r#"
[[package]]
name = "local-crate"
version = "0.1.0"
"#,
        )
        .expect("lockfile should parse");

        let report =
            check_reviewed_rust_targets(&reviewed_targets, &manifest_requirements, &lockfile);

        assert!(!report.is_success());
        assert_eq!(
            report.families()[0].resolved_checks()[0].non_crates_io_sources(),
            &BTreeSet::from(["(no source: path or workspace member)".to_owned()])
        );
    }

    #[test]
    fn patched_reviewed_crates_reports_intersection_with_resolved_and_direct_targets() {
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
        let patched_crate_names =
            parse_manifest_patched_crate_names("Cargo.toml", "[patch.crates-io]\nserde = { git = \"https://example.com/serde.git\" }\nunrelated = { git = \"https://example.com/unrelated.git\" }\n")
                .expect("manifest should parse");

        let patched = patched_reviewed_crates(&reviewed_targets, &patched_crate_names);

        assert_eq!(patched.len(), 1);
        assert_eq!(patched[0].crate_name(), "serde");
        assert_eq!(patched[0].family(), "serde-family");
    }

    #[test]
    fn patched_reviewed_crates_detects_package_rename_form_for_direct_only_coverage() {
        let reviewed_targets = parse_reviewed_targets_toml(
            r#"
[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.direct]
serde = "=1.0.228"

[rust.families.resolved]
serde_derive = "1.0.228"
"#,
        )
        .expect("reviewed targets should parse");
        let patched_crate_names = parse_manifest_patched_crate_names(
            "Cargo.toml",
            r#"[patch.crates-io]
serde-alias = { package = "serde", git = "https://attacker.example/serde" }
"#,
        )
        .expect("manifest should parse");

        let patched = patched_reviewed_crates(&reviewed_targets, &patched_crate_names);

        assert_eq!(patched.len(), 1);
        assert_eq!(patched[0].crate_name(), "serde");
        assert_eq!(patched[0].family(), "serde-family");
    }

    #[test]
    fn patched_reviewed_crates_is_empty_when_no_patch_targets_a_reviewed_crate() {
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
        let patched_crate_names = parse_manifest_patched_crate_names(
            "Cargo.toml",
            "[patch.crates-io]\nunrelated = { git = \"https://example.com/unrelated.git\" }\n",
        )
        .expect("manifest should parse");

        let patched = patched_reviewed_crates(&reviewed_targets, &patched_crate_names);

        assert!(patched.is_empty());
    }
}
