use barbican::*;

const REV: &str = "901f9946efdaaa289e6b1c5bd56dc67f4b651e51";
const URL: &str = "https://example.org/reviewed.git";

struct MatureRegistry;

impl CratesIoClient for MatureRegistry {
    fn fetch_release(&self, _: &ExactCrateSpec) -> Result<CrateRelease, CratesIoClientError> {
        parse_version_response_body(
            r#"{"version":{"num":"0.1.0","checksum":"0000000000000000000000000000000000000000000000000000000000000000","created_at":"1970-01-01T00:00:00Z","yanked":false}}"#,
        )
    }
}

fn surface_metadata(source: &str) -> CargoMetadata {
    parse_cargo_metadata(&serde_json::json!({
        "packages": [
            {"name":"wrapper","version":"0.1.0","id":format!("{source}#wrapper@0.1.0"),"source":source,"targets":[{"kind":["lib"]}]},
            {"name":"native-sys","version":"0.1.0","id":format!("{source}#native-sys@0.1.0"),"source":source,"links":"native","targets":[{"kind":["custom-build"]}]}
        ],
        "workspace_members":[], "resolve":{"nodes":[]}
    }).to_string()).unwrap()
}

#[test]
fn git_surface_allowances_require_the_exact_locked_and_metadata_source() {
    let reviewed = parse_reviewed_targets_toml(&policy()).unwrap();
    let exact = GitSourceIdentity::new(URL, REV).unwrap().locked_source();
    let other_repository = exact.replace("reviewed.git", "different.git");
    let other_revision = exact.replace(REV, &"1".repeat(40));
    let now = OffsetDateTime::from_unix_timestamp(1_820_908_800).unwrap();
    let empty = parse_lockfile("version=4\n").unwrap();
    for (locked_source, metadata_source, expected_allowed, disagreement) in [
        (exact.as_str(), exact.as_str(), true, false),
        (
            other_repository.as_str(),
            other_repository.as_str(),
            false,
            false,
        ),
        (
            other_revision.as_str(),
            other_revision.as_str(),
            false,
            false,
        ),
        (CRATES_IO_SOURCE, CRATES_IO_SOURCE, false, false),
        (exact.as_str(), other_repository.as_str(), false, true),
    ] {
        let current = lock(locked_source);
        let metadata = surface_metadata(metadata_source);
        let assessment = assess_rust_update_at(
            &MatureRegistry,
            &current,
            &empty,
            &[],
            &[],
            &metadata,
            0,
            &HighScrutinyConfig::default(),
            &reviewed.execution_surface_allowances(),
            &[],
            now,
        );
        assert_eq!(
            assessment.allowed_execution_surfaces().len(),
            if expected_allowed { 2 } else { 0 },
            "lock={locked_source}, metadata={metadata_source}"
        );
        if disagreement {
            assert!(!assessment.inspection_failures().is_empty());
        } else {
            assert!(assessment.inspection_failures().is_empty());
            assert_eq!(
                assessment.build_rs_surfaces().len(),
                usize::from(!expected_allowed)
            );
            assert_eq!(
                assessment.native_sys_crates().len(),
                usize::from(!expected_allowed)
            );
        }
        let graph = build_inventory_graph_facts(&metadata, &current).unwrap();
        let pin_report = check_reviewed_rust_targets(&reviewed, &[], &current);
        let inventory = build_inventory(
            &current,
            InventoryDirectRequirements::new(&[], &[]),
            &std::collections::BTreeSet::new(),
            Some(&pin_report),
            &[ReviewRecordFact::new(
                "upstream".into(),
                "docs/review.md".into(),
                ReviewRecordStatus::Completed,
            )],
            now,
            Some(&graph),
        );
        let surfaces = inventory.live_surfaces().unwrap();
        assert_eq!(surfaces.len(), 2);
        assert!(
            surfaces
                .iter()
                .all(|surface| surface.spec().crate_name() == "native-sys"
                    && surface.source() == Some(metadata_source)
                    && surface.declared() == expected_allowed)
        );
    }
}

fn policy() -> String {
    format!(
        r#"[[rust.families]]
name = "upstream"
review_record = "docs/review.md"
[rust.families.resolved]
wrapper = {{ source = "git", version = "0.1.0", url = "{URL}", rev = "{REV}" }}
native-sys = {{ source = "git", version = "0.1.0", url = "{URL}", rev = "{REV}" }}
[rust.families.allowed_surfaces]
native-sys = ["build-rs", "native-sys"]
"#
    )
}

fn lock(source: &str) -> Lockfile {
    parse_lockfile(&format!("version=4\n[[package]]\nname=\"wrapper\"\nversion=\"0.1.0\"\nsource=\"{source}\"\n[[package]]\nname=\"native-sys\"\nversion=\"0.1.0\"\nsource=\"{source}\"\n")).unwrap()
}

#[test]
fn exact_git_review_covers_wrapper_and_child_but_never_a_source_substitution() {
    let reviewed = parse_reviewed_targets_toml(&policy()).unwrap();
    let source = GitSourceIdentity::new(URL, REV).unwrap().locked_source();
    let direct = parse_manifest_direct_requirements(
        "Cargo.toml",
        &format!("[dependencies]\nalias={{package=\"wrapper\",git=\"{URL}\",rev=\"{REV}\"}}\n"),
    )
    .unwrap()
    .into_iter()
    .collect::<Vec<_>>();
    assert!(check_reviewed_rust_targets(&reviewed, &direct, &lock(&source)).is_success());
    for replaced in [
        source.replace("reviewed.git", "different.git"),
        source.replace(REV, &"1".repeat(40)),
        format!("git+{URL}?branch=main#{REV}"),
        CRATES_IO_SOURCE.to_owned(),
    ] {
        assert!(!check_reviewed_rust_targets(&reviewed, &direct, &lock(&replaced)).is_success());
    }
    let sibling = parse_lockfile(&format!("version=4\n[[package]]\nname=\"wrapper\"\nversion=\"0.1.0\"\nsource=\"{source}\"\n[[package]]\nname=\"wrapper\"\nversion=\"0.1.0\"\nsource=\"{CRATES_IO_SOURCE}\"\n")).unwrap();
    assert!(!check_reviewed_rust_targets(&reviewed, &direct, &sibling).is_success());
}

#[test]
fn full_locked_commit_cannot_hide_a_floating_manifest_or_an_unreviewed_child() {
    let reviewed = parse_reviewed_targets_toml(&policy()).unwrap();
    let source = GitSourceIdentity::new(URL, REV).unwrap().locked_source();
    for selector in [
        "branch=\"main\"".to_owned(),
        "tag=\"reviewed\"".to_owned(),
        format!("rev=\"{}\"", &REV[..8]),
    ] {
        let direct = parse_manifest_direct_requirements(
            "Cargo.toml",
            &format!("[dependencies]\nwrapper={{git=\"{URL}\",{selector}}}\n"),
        )
        .unwrap()
        .into_iter()
        .collect::<Vec<_>>();
        assert!(!check_reviewed_rust_targets(&reviewed, &direct, &lock(&source)).is_success());
    }
    let reviewed = parse_reviewed_targets_toml(
        &policy()
            .lines()
            .filter(|line| {
                !line.starts_with("native-sys")
                    && !line.starts_with("[rust.families.allowed_surfaces]")
            })
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();
    let report = check_reviewed_rust_targets(&reviewed, &[], &lock(&source));
    assert!(!report.is_success());
    assert!(
        report
            .git_issues()
            .iter()
            .any(|issue| issue.package == "native-sys")
    );
}

#[test]
fn inherited_alias_resolves_by_template_key_and_unused_templates_stay_inactive() {
    let workspace = parse_workspace_dependency_requirements("Cargo.toml", &format!("[workspace.dependencies]\nalias={{package=\"wrapper\",git=\"{URL}\",rev=\"{REV}\"}}\nunused={{git=\"{URL}\",branch=\"main\"}}\n")).unwrap().into_iter().collect::<Vec<_>>();
    let member = parse_manifest_direct_requirements(
        "member/Cargo.toml",
        "[dependencies]\nalias={workspace=true}\n",
    )
    .unwrap()
    .into_iter()
    .collect::<Vec<_>>();
    let effective = resolve_workspace_requirements(&member, &workspace).unwrap();
    assert_eq!(effective.len(), 1);
    assert_eq!(effective[0].dependency_key(), "alias");
    assert_eq!(effective[0].name(), "wrapper");
    assert!(effective[0].git().is_some());
    let source = GitSourceIdentity::new(URL, REV).unwrap().locked_source();
    let inventory = build_inventory(
        &lock(&source),
        InventoryDirectRequirements::new(&member, &workspace),
        &std::collections::BTreeSet::new(),
        None,
        &[],
        OffsetDateTime::UNIX_EPOCH,
        None,
    );
    assert_eq!(inventory.direct_dependencies()[0].name(), "wrapper");
    assert!(inventory.direct_dependencies()[0].inherited());
    assert!(resolve_workspace_requirements(&member, &[]).is_err());
}

#[test]
fn git_scaffolding_round_trips_without_registry_fallback_or_self_certification() {
    let source = GitSourceIdentity::new(URL, REV).unwrap().locked_source();
    let direct = parse_manifest_direct_requirements(
        "Cargo.toml",
        &format!("[dependencies]\nalias={{package=\"wrapper\",git=\"{URL}\",rev=\"{REV}\"}}\n"),
    )
    .unwrap()
    .into_iter()
    .collect::<Vec<_>>();
    let plan = plan_pin_add(
        &lock(&source),
        &parse_reviewed_targets_toml("[rust]\n").unwrap(),
        &direct,
        &parse_pin_add_target("wrapper").unwrap(),
        "upstream".into(),
        "docs/review.md".into(),
        Date::from_calendar_date(2026, time::Month::October, 20).unwrap(),
    )
    .unwrap();
    let parsed = parse_reviewed_targets_toml(plan.family_stub()).unwrap();
    assert_eq!(
        parsed.rust_families()[0].resolved()["wrapper"]
            .git()
            .unwrap()
            .rev(),
        REV
    );
    assert!(plan.record_stub().contains(REVIEW_RECORD_SCAFFOLD_MARKER));
    assert!(!plan.has_non_conforming_direct_requirement());
    assert!(plan.record_stub().contains(&format!(
        "- Direct reviewed set: `wrapper` `git+{URL}?rev={REV}`"
    )));
    assert!(parsed.rust_families()[0].direct().contains_key("wrapper"));
    assert!(
        plan.record_stub()
            .contains("Advisory scanners may exclude Git")
    );
    for table in ["allowed_age_exceptions", "allowed_advisories"] {
        let value = if table == "allowed_age_exceptions" {
            "\"0.1.0\""
        } else {
            "[{id=\"RUSTSEC-2026-0001\",review_by=\"2026-12-31\"}]"
        };
        assert!(
            parse_reviewed_targets_toml(&format!(
                "{}\n[rust.families.{table}]\nwrapper={value}\n",
                policy()
            ))
            .is_err()
        );
    }
    assert!(
        parse_reviewed_targets_toml(&policy().replace(
            "version = \"0.1.0\", url",
            "version = \"0.1.0\", checksum_sha256=\"00\", url"
        ))
        .is_err()
    );
}

#[test]
fn scanner_sources_survive_dedup_and_missing_source_remains_ambiguous() {
    let source = GitSourceIdentity::new(URL, REV).unwrap().locked_source();
    let text = format!(
        "{{\"vulnerabilities\":{{\"found\":true,\"count\":2,\"list\":[{{\"advisory\":{{\"id\":\"RUSTSEC-2026-0001\"}},\"package\":{{\"name\":\"wrapper\",\"version\":\"0.1.0\",\"source\":\"{source}\"}}}},{{\"advisory\":{{\"id\":\"RUSTSEC-2026-0001\"}},\"package\":{{\"name\":\"wrapper\",\"version\":\"0.1.0\",\"source\":\"{CRATES_IO_SOURCE}\"}}}}]}},\"settings\":{{\"ignore\":[]}},\"warnings\":{{}}}}"
    );
    let mut report = parse_cargo_audit_json(&text).unwrap();
    assert_eq!(report.findings().len(), 2);
    let mixed = parse_lockfile(&format!("version=4\n[[package]]\nname=\"wrapper\"\nversion=\"0.1.0\"\nsource=\"{source}\"\n[[package]]\nname=\"wrapper\"\nversion=\"0.1.0\"\nsource=\"{CRATES_IO_SOURCE}\"\n")).unwrap();
    report.attribute_sources(&mixed);
    assert_eq!(
        report
            .findings()
            .iter()
            .filter(|finding| finding.is_registry_finding())
            .count(),
        1
    );
    let mut missing = parse_cargo_audit_json(
        &text
            .replace(&format!(",\"source\":\"{source}\""), "")
            .replace(&format!(",\"source\":\"{CRATES_IO_SOURCE}\""), ""),
    )
    .unwrap();
    missing.attribute_sources(&mixed);
    assert!(
        missing
            .findings()
            .iter()
            .all(|finding| finding.source_status() == AdvisorySourceStatus::Ambiguous)
    );
}
