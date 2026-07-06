use std::collections::BTreeMap;
use std::fmt::Write as _;

use thiserror::Error;
use time::Date;

use crate::lockfile::{LockedPackage, Lockfile};
use crate::manifest::CargoManifestDirectRequirement;
use crate::reviewed_targets::{
    RawReviewedResolvedTarget, RawReviewedRustFamily, RawReviewedTargets, RawRustReviewedTargets,
    ReviewedTargets, format_iso_date,
};
use crate::sha256::Sha256Digest;
use crate::spec::{ExactCrateSpec, ExactCrateSpecError, VersionMarker, split_crate_version_spec};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinAddTarget {
    crate_name: String,
    version: Option<String>,
}

impl PinAddTarget {
    pub fn crate_name(&self) -> &str {
        &self.crate_name
    }

    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }
}

pub fn parse_pin_add_target(spec: &str) -> Result<PinAddTarget, PinAddTargetError> {
    let Some(shape) = split_crate_version_spec(spec, VersionMarker::Optional) else {
        return Err(PinAddTargetError::InvalidShape(spec.to_owned()));
    };
    let crate_name = shape.crate_name;
    let version = match shape.version {
        Some(version) => {
            let version = version.strip_prefix('=').unwrap_or(version);
            if version.is_empty() {
                return Err(PinAddTargetError::InvalidShape(spec.to_owned()));
            }
            Some(version)
        }
        None => None,
    };

    ExactCrateSpec::from_parts(crate_name, version.unwrap_or("0.0.0"))
        .map_err(PinAddTargetError::InvalidExactSpec)?;

    Ok(PinAddTarget {
        crate_name: crate_name.to_owned(),
        version: version.map(str::to_owned),
    })
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PinAddTargetError {
    #[error("Expected crate or exact crate@version, got: {0:?}")]
    InvalidShape(String),
    #[error(transparent)]
    InvalidExactSpec(#[from] ExactCrateSpecError),
}

pub fn pin_family_name(crate_name: &str, date: Date) -> String {
    format!("{crate_name}-{}", format_iso_date(date))
}

pub fn pin_review_record_path(records_dir: &str, crate_name: &str, date: Date) -> String {
    format!("{records_dir}/{}-{crate_name}.md", format_iso_date(date))
}

/// Composes the reviewed-targets policy fragment for a scaffolded family by
/// serialising the same raw schema `parse_reviewed_targets_toml` reads back,
/// so the writer and reader cannot drift on shape.
pub fn compose_pin_family_stub(
    family_name: &str,
    review_record: &str,
    spec: &ExactCrateSpec,
    checksum_sha256: Option<&Sha256Digest>,
    direct_requirement: Option<&str>,
) -> String {
    let crate_name = spec.crate_name().to_owned();
    let mut direct = BTreeMap::new();
    if let Some(requirement) = direct_requirement {
        direct.insert(crate_name.clone(), requirement.to_owned());
    }

    let resolved_target = match checksum_sha256 {
        Some(checksum) => RawReviewedResolvedTarget::RegistryArtifact {
            version: spec.version().to_owned(),
            checksum_sha256: checksum.to_string(),
        },
        None => RawReviewedResolvedTarget::Version(spec.version().to_owned()),
    };
    let resolved = BTreeMap::from([(crate_name, resolved_target)]);

    let family = RawReviewedRustFamily {
        name: family_name.to_owned(),
        review_record: review_record.to_owned(),
        direct,
        resolved,
        allowed_surfaces: BTreeMap::new(),
        allowed_age_exceptions: BTreeMap::new(),
        allowed_advisories: BTreeMap::new(),
    };
    let document = RawReviewedTargets {
        rust: RawRustReviewedTargets {
            families: vec![family],
        },
    };

    format!(
        "\n{}",
        toml::to_string(&document).expect("a scaffolded family always serialises to TOML")
    )
}

pub fn compose_pin_review_record(
    spec: &ExactCrateSpec,
    checksum_sha256: Option<&Sha256Digest>,
    from_crates_io: bool,
    family_name: &str,
    direct_requirement: Option<&str>,
    date: Date,
) -> String {
    let crate_name = spec.crate_name();
    let version = spec.version();
    let iso_date = format_iso_date(date);
    let target_source = if from_crates_io {
        "(from `crates.io`)".to_owned()
    } else {
        "(non-crates.io source; record the source manually)".to_owned()
    };
    let resolved_set = match checksum_sha256 {
        Some(checksum) => format!("`{crate_name}` `{version}` (checksum_sha256 `{checksum}`)"),
        None => format!("`{crate_name}` `{version}` (no `Cargo.lock` checksum recorded)"),
    };
    let direct_set = match direct_requirement {
        Some(requirement) => format!(" `{crate_name}` `{requirement}`"),
        None => String::new(),
    };

    let mut record = String::new();
    let _ = write!(
        &mut record,
        "# Dependency Review: {crate_name} {version}

## Summary

- Date: {iso_date}
- Reviewer:
- Scope:

## Classification

- Routine or elevated-risk:
- Reason:

## Targets

- `{crate_name}` -> `{version}` {target_source}

## Inheritance

- Upstream record:
- Trust model match:
- Deltas from upstream:

## Reviewed Target Set

- Active family name: {family_name}
- `reviewed-targets.toml` updated: yes, scaffolded by `cargo barbican pin add`
- Direct reviewed set:{direct_set}
- Resolved reviewed set: {resolved_set}
- Allowed execution surfaces:
- Allowed release-age exceptions:
- Allowed advisory exceptions:

## Release Age

- Minimum policy:
- Observed publish date / age:
- Pass / fail:

## Advisory Review

- Sources checked:
- Findings:

## Source / Upstream Review

- Release notes reviewed:
- `build.rs` / `proc-macro` / `-sys` surfaces:
- Additional notes:

## Commands Run

```bash
# commands
```

## Outcome

- Installed / updated:
- Verification:

## Follow-ups

- Remaining risks or next actions:
"
    );

    record
}

/// Why `plan_pin_add` refused to build a plan. Carries the data needed to
/// render the message; the shell owns the exact wording (including the
/// configured policy file name, which is a binary/CLI concern).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinAddRejection {
    NotInLockfile {
        crate_name: String,
    },
    VersionNotResolved {
        crate_name: String,
        version: String,
        resolved_versions: Vec<String>,
    },
    AmbiguousVersion {
        crate_name: String,
        resolved_versions: Vec<String>,
    },
    AlreadyCovered {
        crate_name: String,
        family: String,
    },
    FamilyAlreadyExists {
        crate_name: String,
        family_name: String,
    },
}

/// The reviewed-family scaffold `pin add` would create, and the offline
/// facts it was built from. The shell only reads inputs, writes the two
/// files this plan already composed, and renders the notes below.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinAddPlan {
    family_name: String,
    review_record: String,
    exact: ExactCrateSpec,
    checksum: Option<Sha256Digest>,
    direct_requirement: Option<String>,
    has_non_conforming_direct_requirement: bool,
    family_stub: String,
    record_stub: String,
}

impl PinAddPlan {
    pub fn family_name(&self) -> &str {
        &self.family_name
    }

    pub fn review_record(&self) -> &str {
        &self.review_record
    }

    pub fn exact(&self) -> &ExactCrateSpec {
        &self.exact
    }

    pub fn checksum(&self) -> Option<&Sha256Digest> {
        self.checksum.as_ref()
    }

    pub fn direct_requirement(&self) -> Option<&str> {
        self.direct_requirement.as_deref()
    }

    /// True when the crate is a direct dependency but its manifest
    /// requirement is not uniformly the exact pin, so no `[rust.families.direct]`
    /// entry was scaffolded even though one might be expected.
    pub fn has_non_conforming_direct_requirement(&self) -> bool {
        self.has_non_conforming_direct_requirement
    }

    pub fn family_stub(&self) -> &str {
        &self.family_stub
    }

    pub fn record_stub(&self) -> &str {
        &self.record_stub
    }
}

/// The one `pin add` decision pipeline: version disambiguation, coverage and
/// collision checks against the existing policy, and direct-requirement
/// computation. Pure and offline; the shell resolves `family_name` and
/// `review_record` (they depend on a binary-side records-directory constant)
/// and owns every filesystem read, write, and rendered message.
pub fn plan_pin_add(
    lockfile: &Lockfile,
    reviewed_targets: &ReviewedTargets,
    manifest_requirements: &[CargoManifestDirectRequirement],
    target: &PinAddTarget,
    family_name: String,
    review_record: String,
    date: Date,
) -> Result<PinAddPlan, PinAddRejection> {
    let matching_packages = lockfile
        .packages()
        .iter()
        .filter(|package| package.name == target.crate_name())
        .collect::<Vec<_>>();
    if matching_packages.is_empty() {
        return Err(PinAddRejection::NotInLockfile {
            crate_name: target.crate_name().to_owned(),
        });
    }

    let package = select_locked_package(&matching_packages, target)?;

    if let Some(family) = family_covering_crate(reviewed_targets, target.crate_name()) {
        return Err(PinAddRejection::AlreadyCovered {
            crate_name: target.crate_name().to_owned(),
            family: family.to_owned(),
        });
    }

    if reviewed_targets
        .rust_families()
        .iter()
        .any(|family| family.name() == family_name)
    {
        return Err(PinAddRejection::FamilyAlreadyExists {
            crate_name: target.crate_name().to_owned(),
            family_name,
        });
    }

    let observed_direct = manifest_requirements
        .iter()
        .filter(|requirement| requirement.name() == package.name)
        .collect::<Vec<_>>();
    let exact = package.exact_spec();
    let direct_requirement = exact_direct_requirement(&observed_direct, exact);
    let has_non_conforming_direct_requirement =
        direct_requirement.is_none() && !observed_direct.is_empty();

    let family_stub = compose_pin_family_stub(
        &family_name,
        &review_record,
        exact,
        package.checksum(),
        direct_requirement.as_deref(),
    );
    let record_stub = compose_pin_review_record(
        exact,
        package.checksum(),
        package.is_crates_io(),
        &family_name,
        direct_requirement.as_deref(),
        date,
    );

    Ok(PinAddPlan {
        family_name,
        review_record,
        exact: exact.clone(),
        checksum: package.checksum().cloned(),
        direct_requirement,
        has_non_conforming_direct_requirement,
        family_stub,
        record_stub,
    })
}

fn select_locked_package<'a>(
    matching_packages: &[&'a LockedPackage],
    target: &PinAddTarget,
) -> Result<&'a LockedPackage, PinAddRejection> {
    match target.version() {
        Some(version) => matching_packages
            .iter()
            .copied()
            .find(|package| package.version == version)
            .ok_or_else(|| PinAddRejection::VersionNotResolved {
                crate_name: target.crate_name().to_owned(),
                version: version.to_owned(),
                resolved_versions: resolved_versions(matching_packages),
            }),
        None => {
            if matching_packages.len() > 1 {
                Err(PinAddRejection::AmbiguousVersion {
                    crate_name: target.crate_name().to_owned(),
                    resolved_versions: resolved_versions(matching_packages),
                })
            } else {
                Ok(matching_packages[0])
            }
        }
    }
}

fn resolved_versions(packages: &[&LockedPackage]) -> Vec<String> {
    packages
        .iter()
        .map(|package| package.version.clone())
        .collect()
}

fn family_covering_crate<'a>(
    reviewed_targets: &'a ReviewedTargets,
    crate_name: &str,
) -> Option<&'a str> {
    reviewed_targets
        .rust_families()
        .iter()
        .find(|family| family.resolved().contains_key(crate_name))
        .map(|family| family.name())
}

fn exact_direct_requirement(
    observed_direct: &[&CargoManifestDirectRequirement],
    exact: &ExactCrateSpec,
) -> Option<String> {
    let exact_requirement = format!("={}", exact.version());
    (!observed_direct.is_empty()
        && observed_direct.iter().all(|requirement| {
            requirement.source_kind().requires_exact_pin()
                && requirement.version_requirement() == Some(exact_requirement.as_str())
        }))
    .then_some(exact_requirement)
}

#[cfg(test)]
mod tests {
    use time::Date;
    use time::Month;

    use crate::sha256::Sha256Digest;
    use crate::{
        ExactCrateSpec, ExactCrateSpecError, format_iso_date, parse_lockfile,
        parse_manifest_direct_requirements, parse_reviewed_targets_toml,
    };

    use super::{
        PinAddRejection, PinAddTargetError, compose_pin_family_stub, compose_pin_review_record,
        parse_pin_add_target, pin_family_name, pin_review_record_path, plan_pin_add,
    };

    fn test_date() -> Date {
        Date::from_calendar_date(2026, Month::July, 2).expect("test date should construct")
    }

    fn test_checksum() -> Sha256Digest {
        Sha256Digest::try_from("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .expect("test checksum should parse")
    }

    #[test]
    fn parses_bare_crate_names_and_exact_specs() {
        let bare = parse_pin_add_target("serde").expect("bare name should parse");
        assert_eq!(bare.crate_name(), "serde");
        assert_eq!(bare.version(), None);

        for spec in ["serde@1.0.228", "serde@=1.0.228"] {
            let exact = parse_pin_add_target(spec).expect("exact spec should parse");
            assert_eq!(exact.crate_name(), "serde");
            assert_eq!(exact.version(), Some("1.0.228"));
        }
    }

    #[test]
    fn rejects_invalid_pin_add_targets() {
        assert_eq!(
            parse_pin_add_target("serde@"),
            Err(PinAddTargetError::InvalidShape("serde@".to_owned()))
        );
        assert_eq!(
            parse_pin_add_target("@1.0.0"),
            Err(PinAddTargetError::InvalidShape("@1.0.0".to_owned()))
        );
        assert_eq!(
            parse_pin_add_target("--flag"),
            Err(PinAddTargetError::InvalidShape("--flag".to_owned()))
        );
        assert_eq!(
            parse_pin_add_target("bad/name"),
            Err(PinAddTargetError::InvalidExactSpec(
                ExactCrateSpecError::InvalidCrateName("bad/name@0.0.0".to_owned())
            ))
        );
        assert_eq!(
            parse_pin_add_target("serde@^1"),
            Err(PinAddTargetError::InvalidExactSpec(
                ExactCrateSpecError::VersionRange("serde@^1".to_owned())
            ))
        );
    }

    #[test]
    fn derives_family_names_and_record_paths_from_the_injected_date() {
        assert_eq!(format_iso_date(test_date()), "2026-07-02");
        assert_eq!(pin_family_name("serde", test_date()), "serde-2026-07-02");
        assert_eq!(
            pin_review_record_path("docs/dependency-reviews", "serde", test_date()),
            "docs/dependency-reviews/2026-07-02-serde.md"
        );
    }

    #[test]
    fn composes_a_checksum_bound_family_stub_that_parses_as_policy() {
        let checksum = test_checksum();
        let spec = ExactCrateSpec::from_parts("serde", "1.0.228").expect("spec should parse");
        let stub = compose_pin_family_stub(
            "serde-2026-07-02",
            "docs/dependency-reviews/2026-07-02-serde.md",
            &spec,
            Some(&checksum),
            Some("=1.0.228"),
        );

        // The stub is generated by serialising the same raw schema
        // `parse_reviewed_targets_toml` deserialises, so the round trip below
        // (rather than a literal string match) is what guards writer/reader
        // drift; the shape assertions below pin the parsed values instead.
        assert!(stub.starts_with('\n'));
        assert!(stub.contains("[[rust.families]]"));

        let parsed = parse_reviewed_targets_toml(&format!("[rust]\n{stub}"))
            .expect("composed stub should parse as reviewed-targets policy");
        let family = &parsed.rust_families()[0];
        assert_eq!(family.name(), "serde-2026-07-02");
        assert_eq!(
            family.review_record(),
            "docs/dependency-reviews/2026-07-02-serde.md"
        );
        assert_eq!(
            family.direct().get("serde").map(String::as_str),
            Some("=1.0.228")
        );
        let resolved = family
            .resolved()
            .get("serde")
            .expect("resolved entry should exist");
        assert_eq!(resolved.version(), "1.0.228");
        assert_eq!(resolved.checksum_sha256(), Some(&checksum));
    }

    #[test]
    fn composes_a_version_only_family_stub_when_no_checksum_exists() {
        let spec = ExactCrateSpec::from_parts("local-crate", "0.1.0").expect("spec should parse");
        let stub = compose_pin_family_stub(
            "local-crate-2026-07-02",
            "docs/dependency-reviews/2026-07-02-local-crate.md",
            &spec,
            None,
            None,
        );

        assert!(stub.contains("local-crate = \"0.1.0\"\n"));
        assert!(!stub.contains("[rust.families.direct]"));
        let parsed = parse_reviewed_targets_toml(&format!("[rust]\n{stub}"))
            .expect("version-only stub should parse as reviewed-targets policy");
        assert!(parsed.rust_families()[0].direct().is_empty());
    }

    #[test]
    fn composes_a_review_record_stub_with_the_required_sections() {
        let checksum = test_checksum();
        let spec = ExactCrateSpec::from_parts("serde", "1.0.228").expect("spec should parse");
        let record = compose_pin_review_record(
            &spec,
            Some(&checksum),
            true,
            "serde-2026-07-02",
            Some("=1.0.228"),
            test_date(),
        );

        assert!(record.starts_with("# Dependency Review: serde 1.0.228\n"));
        for section in [
            "## Summary",
            "## Classification",
            "## Targets",
            "## Inheritance",
            "## Reviewed Target Set",
            "## Release Age",
            "## Advisory Review",
            "## Source / Upstream Review",
            "## Commands Run",
            "## Outcome",
            "## Follow-ups",
        ] {
            assert!(record.contains(section), "record should contain {section}");
        }
        assert!(record.contains("- Date: 2026-07-02"));
        assert!(record.contains("- `serde` -> `1.0.228` (from `crates.io`)"));
        assert!(record.contains("- Active family name: serde-2026-07-02"));
        assert!(record.contains("- Direct reviewed set: `serde` `=1.0.228`"));
        assert!(record.contains(
            "- Resolved reviewed set: `serde` `1.0.228` (checksum_sha256 `0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef`)"
        ));
    }

    #[test]
    fn review_record_stub_marks_non_crates_io_sources_for_manual_completion() {
        let spec = ExactCrateSpec::from_parts("local-crate", "0.1.0").expect("spec should parse");
        let record = compose_pin_review_record(
            &spec,
            None,
            false,
            "local-crate-2026-07-02",
            None,
            test_date(),
        );

        assert!(record.contains(
            "- `local-crate` -> `0.1.0` (non-crates.io source; record the source manually)"
        ));
        assert!(record.contains("(no `Cargo.lock` checksum recorded)"));
    }

    fn empty_reviewed_targets() -> crate::ReviewedTargets {
        parse_reviewed_targets_toml("[rust]\n").expect("empty reviewed targets should parse")
    }

    fn serde_lockfile() -> crate::Lockfile {
        parse_lockfile(
            r#"
[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
"#,
        )
        .expect("lockfile should parse")
    }

    fn direct_requirements(text: &str) -> Vec<crate::CargoManifestDirectRequirement> {
        parse_manifest_direct_requirements("Cargo.toml", text)
            .expect("manifest should parse")
            .into_iter()
            .collect()
    }

    #[test]
    fn plans_a_checksum_bound_family_with_a_matching_direct_requirement() {
        let lockfile = serde_lockfile();
        let reviewed_targets = empty_reviewed_targets();
        let manifest_requirements = direct_requirements("[dependencies]\nserde = \"=1.0.228\"\n");
        let target = parse_pin_add_target("serde").expect("target should parse");

        let plan = plan_pin_add(
            &lockfile,
            &reviewed_targets,
            &manifest_requirements,
            &target,
            "serde-2026-07-02".to_owned(),
            "docs/dependency-reviews/2026-07-02-serde.md".to_owned(),
            test_date(),
        )
        .expect("plan should build");

        assert_eq!(plan.family_name(), "serde-2026-07-02");
        assert_eq!(
            plan.review_record(),
            "docs/dependency-reviews/2026-07-02-serde.md"
        );
        assert_eq!(plan.exact().to_string(), "serde@1.0.228");
        assert_eq!(plan.checksum(), Some(&test_checksum()));
        assert_eq!(plan.direct_requirement(), Some("=1.0.228"));
        assert!(!plan.has_non_conforming_direct_requirement());
        assert!(plan.family_stub().contains("[[rust.families]]"));
        assert!(plan.record_stub().starts_with("# Dependency Review:"));
    }

    #[test]
    fn plan_flags_a_direct_dependency_whose_requirement_is_not_an_exact_pin() {
        let lockfile = serde_lockfile();
        let reviewed_targets = empty_reviewed_targets();
        let manifest_requirements = direct_requirements("[dependencies]\nserde = \"1.0\"\n");
        let target = parse_pin_add_target("serde").expect("target should parse");

        let plan = plan_pin_add(
            &lockfile,
            &reviewed_targets,
            &manifest_requirements,
            &target,
            "serde-2026-07-02".to_owned(),
            "docs/dependency-reviews/2026-07-02-serde.md".to_owned(),
            test_date(),
        )
        .expect("plan should build");

        assert_eq!(plan.direct_requirement(), None);
        assert!(plan.has_non_conforming_direct_requirement());
    }

    #[test]
    fn plan_rejects_a_crate_absent_from_the_lockfile() {
        let lockfile = parse_lockfile("").expect("empty lockfile should parse");
        let reviewed_targets = empty_reviewed_targets();
        let target = parse_pin_add_target("serde").expect("target should parse");

        let rejection = plan_pin_add(
            &lockfile,
            &reviewed_targets,
            &[],
            &target,
            "serde-2026-07-02".to_owned(),
            "docs/dependency-reviews/2026-07-02-serde.md".to_owned(),
            test_date(),
        )
        .expect_err("crate absent from Cargo.lock should be rejected");

        assert_eq!(
            rejection,
            PinAddRejection::NotInLockfile {
                crate_name: "serde".to_owned()
            }
        );
    }

    #[test]
    fn plan_rejects_an_ambiguous_bare_spec_when_multiple_versions_are_resolved() {
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
        let reviewed_targets = empty_reviewed_targets();
        let target = parse_pin_add_target("serde").expect("target should parse");

        let rejection = plan_pin_add(
            &lockfile,
            &reviewed_targets,
            &[],
            &target,
            "serde-2026-07-02".to_owned(),
            "docs/dependency-reviews/2026-07-02-serde.md".to_owned(),
            test_date(),
        )
        .expect_err("ambiguous bare spec should be rejected");

        assert_eq!(
            rejection,
            PinAddRejection::AmbiguousVersion {
                crate_name: "serde".to_owned(),
                resolved_versions: vec!["1.0.227".to_owned(), "1.0.228".to_owned()],
            }
        );
    }

    #[test]
    fn plan_rejects_an_exact_spec_absent_from_the_resolved_versions() {
        let lockfile = serde_lockfile();
        let reviewed_targets = empty_reviewed_targets();
        let target = parse_pin_add_target("serde@9.9.9").expect("target should parse");

        let rejection = plan_pin_add(
            &lockfile,
            &reviewed_targets,
            &[],
            &target,
            "serde-2026-07-02".to_owned(),
            "docs/dependency-reviews/2026-07-02-serde.md".to_owned(),
            test_date(),
        )
        .expect_err("unresolved exact version should be rejected");

        assert_eq!(
            rejection,
            PinAddRejection::VersionNotResolved {
                crate_name: "serde".to_owned(),
                version: "9.9.9".to_owned(),
                resolved_versions: vec!["1.0.228".to_owned()],
            }
        );
    }

    #[test]
    fn plan_rejects_a_crate_already_covered_by_an_existing_family() {
        let lockfile = serde_lockfile();
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
        let target = parse_pin_add_target("serde").expect("target should parse");

        let rejection = plan_pin_add(
            &lockfile,
            &reviewed_targets,
            &[],
            &target,
            "serde-2026-07-02".to_owned(),
            "docs/dependency-reviews/2026-07-02-serde.md".to_owned(),
            test_date(),
        )
        .expect_err("crate already covered by a family should be rejected");

        assert_eq!(
            rejection,
            PinAddRejection::AlreadyCovered {
                crate_name: "serde".to_owned(),
                family: "serde-family".to_owned(),
            }
        );
    }

    #[test]
    fn plan_rejects_a_family_name_collision() {
        let lockfile = serde_lockfile();
        let reviewed_targets = parse_reviewed_targets_toml(
            r#"
[rust]

[[rust.families]]
name = "serde-2026-07-02"
review_record = "docs/dependency-reviews/2026-05-27-other.md"

[rust.families.resolved]
tokio = "1.0.0"
"#,
        )
        .expect("reviewed targets should parse");
        let target = parse_pin_add_target("serde").expect("target should parse");

        let rejection = plan_pin_add(
            &lockfile,
            &reviewed_targets,
            &[],
            &target,
            "serde-2026-07-02".to_owned(),
            "docs/dependency-reviews/2026-07-02-serde.md".to_owned(),
            test_date(),
        )
        .expect_err("colliding family name should be rejected");

        assert_eq!(
            rejection,
            PinAddRejection::FamilyAlreadyExists {
                crate_name: "serde".to_owned(),
                family_name: "serde-2026-07-02".to_owned(),
            }
        );
    }
}
