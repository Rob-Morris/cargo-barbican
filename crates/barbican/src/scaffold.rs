use std::fmt::Write as _;

use thiserror::Error;
use time::Date;

use crate::reviewed_targets::format_iso_date;
use crate::sha256::Sha256Digest;
use crate::spec::{ExactCrateSpec, ExactCrateSpecError};

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
    if spec.starts_with('-') {
        return Err(PinAddTargetError::InvalidShape(spec.to_owned()));
    }

    let (crate_name, version) = match spec.rsplit_once('@') {
        Some((crate_name, version)) => {
            let version = version.strip_prefix('=').unwrap_or(version);
            (crate_name, Some(version))
        }
        None => (spec, None),
    };

    if crate_name.is_empty() || version.is_some_and(str::is_empty) {
        return Err(PinAddTargetError::InvalidShape(spec.to_owned()));
    }
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

pub fn compose_pin_family_stub(
    family_name: &str,
    review_record: &str,
    spec: &ExactCrateSpec,
    checksum_sha256: Option<&Sha256Digest>,
    direct_requirement: Option<&str>,
) -> String {
    let crate_name = spec.crate_name();
    let version = spec.version();
    let direct_section = match direct_requirement {
        Some(requirement) => {
            format!("\n[rust.families.direct]\n{crate_name} = \"{requirement}\"\n")
        }
        None => String::new(),
    };
    let resolved_entry = match checksum_sha256 {
        Some(checksum) => {
            format!(
                "{crate_name} = {{ version = \"{version}\", checksum_sha256 = \"{checksum}\" }}"
            )
        }
        None => format!("{crate_name} = \"{version}\""),
    };

    format!(
        "\n[[rust.families]]\nname = \"{family_name}\"\nreview_record = \"{review_record}\"\n{direct_section}\n[rust.families.resolved]\n{resolved_entry}\n"
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

#[cfg(test)]
mod tests {
    use time::Date;
    use time::Month;

    use crate::sha256::Sha256Digest;
    use crate::{
        ExactCrateSpec, ExactCrateSpecError, format_iso_date, parse_reviewed_targets_toml,
    };

    use super::{
        PinAddTargetError, compose_pin_family_stub, compose_pin_review_record,
        parse_pin_add_target, pin_family_name, pin_review_record_path,
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

        assert_eq!(
            stub,
            "\n[[rust.families]]\nname = \"serde-2026-07-02\"\nreview_record = \"docs/dependency-reviews/2026-07-02-serde.md\"\n\n[rust.families.direct]\nserde = \"=1.0.228\"\n\n[rust.families.resolved]\nserde = { version = \"1.0.228\", checksum_sha256 = \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\" }\n"
        );

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
}
