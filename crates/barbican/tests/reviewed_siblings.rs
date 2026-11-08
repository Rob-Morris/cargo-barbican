use barbican::*;

fn family(name: &str, version: &str, checksum: Option<char>, grants: bool) -> String {
    let target = checksum.map_or_else(
        || format!("\"{version}\""),
        |c| {
            format!(
                "{{ version = \"{version}\", checksum_sha256 = \"{}\" }}",
                c.to_string().repeat(64)
            )
        },
    );
    let mut text = format!(
        "\n[[rust.families]]\nname = \"{name}\"\nreview_record = \"docs/{name}.md\"\n[rust.families.resolved]\nexample = {target}\n"
    );
    if grants {
        text.push_str("[rust.families.allowed_surfaces]\nexample = [\"build-rs\"]\n[rust.families.allowed_age_exceptions]\nexample = \"1.0.0\"\n[rust.families.allowed_advisories]\nexample = [{ id = \"RUSTSEC-2026-0001\", review_by = \"2027-01-01\" }]\n");
    }
    text
}

fn package(version: &str, checksum: Option<char>, source: Option<&str>) -> String {
    let mut text = format!("\n[[package]]\nname = \"example\"\nversion = \"{version}\"\n");
    if let Some(source) = source {
        text.push_str(&format!("source = \"{source}\"\n"));
    }
    if let Some(c) = checksum {
        text.push_str(&format!("checksum = \"{}\"\n", c.to_string().repeat(64)));
    }
    text
}

fn policy() -> ReviewedTargets {
    parse_reviewed_targets_toml(
        &(family("one", "1.0.0", Some('a'), true) + &family("two", "2.0.0", Some('b'), false)),
    )
    .unwrap()
}

fn facts(second: ReviewRecordStatus) -> Vec<ReviewRecordFact> {
    vec![
        ReviewRecordFact::new(
            "one".into(),
            "docs/one.md".into(),
            ReviewRecordStatus::Completed,
        ),
        ReviewRecordFact::new("two".into(), "docs/two.md".into(), second),
    ]
}

#[test]
fn explicitly_reviewed_siblings_pass_without_transferring_grants() {
    let policy = policy();
    let lock = parse_lockfile(
        &(package("1.0.0", Some('a'), Some(CRATES_IO_SOURCE))
            + &package("2.0.0", Some('b'), Some(CRATES_IO_SOURCE))),
    )
    .unwrap();
    let report = check_reviewed_rust_targets(&policy, &[], &lock);
    assert!(report.is_success());
    let granted =
        report.advisory_exceptions_bound_to_reviewed_records(&facts(ReviewRecordStatus::Completed));
    assert_eq!(granted.len(), 1);
    assert_eq!(granted[0].spec().version(), "1.0.0");
    let surfaces = policy.execution_surface_allowances();
    assert!(surfaces[0].matches_package(&lock.packages()[0]));
    assert!(!surfaces[0].matches_package(&lock.packages()[1]));
    assert_eq!(policy.release_age_exceptions()[0].spec().version(), "1.0.0");
    for status in [
        ReviewRecordStatus::Missing,
        ReviewRecordStatus::Empty,
        ReviewRecordStatus::ScaffoldPlaceholder,
    ] {
        assert!(
            report
                .advisory_exceptions_bound_to_reviewed_records(&facts(status))
                .is_empty()
        );
    }
}

#[test]
fn every_observed_and_expected_sibling_is_reconciled_as_an_exact_tuple() {
    let first = package("1.0.0", Some('a'), Some(CRATES_IO_SOURCE));
    let second = package("2.0.0", Some('b'), Some(CRATES_IO_SOURCE));
    let cases = [
        first.clone(),
        second.clone(),
        first.clone() + &second + &package("3.0.0", Some('c'), Some(CRATES_IO_SOURCE)),
        first.clone() + &package("2.0.0", Some('c'), Some(CRATES_IO_SOURCE)),
        first.clone() + &package("2.0.0", None, Some(CRATES_IO_SOURCE)),
        first.clone() + &package("2.0.0", None, None),
        first.clone() + &second + &package("2.0.0", None, None),
        package("1.0.0", Some('b'), Some(CRATES_IO_SOURCE))
            + &package("2.0.0", Some('a'), Some(CRATES_IO_SOURCE)),
        first.clone()
            + &second
            + &package(
                "2.0.0",
                Some('b'),
                Some("registry+https://example.org/index"),
            ),
        first.clone() + &second + &second,
    ];
    for text in cases {
        // A duplicate rejected by the parser is also a closed gate.
        if let Ok(lock) = parse_lockfile(&text) {
            let report = check_reviewed_rust_targets(&policy(), &[], &lock);
            assert!(!report.is_success(), "{text}");
            assert!(
                report
                    .advisory_exceptions_bound_to_reviewed_records(&facts(
                        ReviewRecordStatus::Completed
                    ))
                    .is_empty(),
                "{text}"
            );
        }
    }
}

#[test]
fn weak_or_conflicting_declarations_cannot_dilute_strong_identity() {
    let strong = family("strong", "1.0.0", Some('a'), false);
    let weak = family("weak", "1.0.0", None, false);
    let policy = parse_reviewed_targets_toml(&(strong.clone() + &weak)).unwrap();
    for checksum in [None, Some('b')] {
        let lock = parse_lockfile(&package("1.0.0", checksum, Some(CRATES_IO_SOURCE))).unwrap();
        assert!(!check_reviewed_rust_targets(&policy, &[], &lock).is_success());
    }
    let matching = parse_lockfile(&package("1.0.0", Some('a'), Some(CRATES_IO_SOURCE))).unwrap();
    assert!(check_reviewed_rust_targets(&policy, &[], &matching).is_success());
    let conflict =
        parse_reviewed_targets_toml(&(strong + &family("conflict", "1.0.0", Some('b'), false)))
            .unwrap();
    assert!(!check_reviewed_rust_targets(&conflict, &[], &matching).is_success());
}

#[test]
fn release_age_grant_does_not_transfer_to_another_reviewed_version() {
    let now = OffsetDateTime::from_unix_timestamp(1_820_908_800).unwrap();
    let policy = policy();
    let grants = policy.release_age_exceptions();
    for (version, checksum, allowed) in [
        ("1.0.0", 'a', true),
        ("2.0.0", 'b', false),
        ("1.0.0", 'b', false),
    ] {
        let release = CrateRelease {
            checksum_sha256_hex: Sha256Digest::try_from(checksum.to_string().repeat(64).as_str())
                .unwrap(),
            published_at_raw: "now".into(),
            published_at: now,
            yanked: false,
        };
        let report = evaluate_release_age(
            ExactCrateSpec::from_parts("example", version).unwrap(),
            release,
            now,
            7,
            Some(&grants[0]),
        );
        assert_eq!(
            matches!(
                report.outcome(),
                ReleaseAgeOutcome::AllowedByException { .. }
            ),
            allowed
        );
    }
}

#[test]
fn multiple_resolved_versions_do_not_relax_direct_exact_manifest_rules() {
    let text = family("one", "1.0.0", Some('a'), false)
        + "[rust.families.direct]\nexample = \"=1.0.0\"\n"
        + &family("two", "2.0.0", Some('b'), false);
    let policy = parse_reviewed_targets_toml(&text).unwrap();
    let lock = parse_lockfile(
        &(package("1.0.0", Some('a'), Some(CRATES_IO_SOURCE))
            + &package("2.0.0", Some('b'), Some(CRATES_IO_SOURCE))),
    )
    .unwrap();
    for (requirement, pass) in [("=1.0.0", true), ("1", false), ("=2.0.0", false)] {
        let direct = parse_manifest_direct_requirements(
            "Cargo.toml",
            &format!("[dependencies]\nexample = \"{requirement}\"\n"),
        )
        .unwrap()
        .into_iter()
        .collect::<Vec<_>>();
        assert_eq!(
            check_reviewed_rust_targets(&policy, &direct, &lock).is_success(),
            pass
        );
    }
}
