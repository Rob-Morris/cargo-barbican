use super::*;
use std::collections::BTreeSet;

fn source() -> Source {
    Source {
        name: "sample".into(),
        version: "1.2.3".into(),
        origin: Origin::CratesIo {
            archive_sha256: digest(b"archive"),
        },
    }
}
fn scope() -> Scope {
    Scope {
        build_script_paths: BTreeSet::from(["build.rs".into()]),
        ..Scope::default()
    }
}
fn scan(bytes: &[u8]) -> Inspection {
    let mut scan = ScanAccumulator::new(source()).unwrap();
    scan.scan_file("build.rs", bytes, &scope(), &mut ScanBudget::default())
        .unwrap();
    scan.finish(None)
}
fn allowance(inspection: &Inspection) -> Allowance {
    let mut record = parse_review(&scaffold_review(inspection).unwrap()).unwrap();
    record.reviewer = "Maintainer or agent".into();
    record.reviewed_at_utc = Some(100);
    record.conclusion = Conclusion::ExpectedBehaviour;
    record.rationale="The helper invokes the named compiler for its declared build role; source and all matches were reviewed.".into();
    Allowance::from_text(&render_review(&record).unwrap()).unwrap()
}
#[test]
fn original_bytes_all_occurrences_and_scope_are_explicit() {
    let report = scan(b"\xff // Command::new(\n let s=\"Command::new(\";");
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].occurrences.len(), 2);
    assert_eq!(report.findings[0].occurrences[0].start, 5);
    assert!(
        report.findings[0].occurrences[0]
            .snippet
            .starts_with("\\xff")
    );
    report.validate().unwrap();
    let mut scanner = ScanAccumulator::new(source()).unwrap();
    for path in ["tests/foo.rs", "examples/foo.rs", "benches/foo.rs"] {
        scanner
            .scan_file(path, b"Command::new(", &scope(), &mut ScanBudget::default())
            .unwrap();
    }
    scanner
        .scan_file(
            "src/tests.rs",
            b"Command::new(",
            &scope(),
            &mut ScanBudget::default(),
        )
        .unwrap();
    let scoped = scanner.finish(None);
    assert_eq!(scoped.findings.len(), 1);
    assert_eq!(scoped.input_files, 4);
    assert_eq!(scoped.scanned_files, 1);
    assert_eq!(scoped.scanned_bytes, 13);
}
#[test]
fn exact_rule_file_and_all_occurrences_must_be_reviewed() {
    let report = scan(b"Command::new( Command::new( ureq::get(");
    let mut selected = report.clone();
    selected.findings.truncate(1);
    let grant = allowance(&selected);
    let decision = adjudicate(&report, std::slice::from_ref(&grant), 101).unwrap();
    assert_eq!(decision.allowed.len(), 1);
    assert_eq!(decision.blocked.len(), 1);
    let changed = scan(b"Command::new( Command::new( Command::new( ureq::get(");
    assert_eq!(
        adjudicate(&changed, &[grant], 101).unwrap().allowed.len(),
        0
    );
}
#[test]
fn optional_deadline_pending_and_invalid_record_remain_distinct() {
    let inspection = scan(b"Command::new(");
    let pending = Allowance::from_text(&scaffold_review(&inspection).unwrap()).unwrap();
    assert!(
        !adjudicate(&inspection, &[pending], 101)
            .unwrap()
            .is_success()
    );
    let mut allowed = allowance(&inspection);
    let marked = format!(
        "{}\n{}",
        crate::REVIEW_RECORD_SCAFFOLD_MARKER,
        render_review(&allowed.record).unwrap()
    );
    assert!(parse_review(&marked).is_err());
    assert!(
        adjudicate(&inspection, &[allowed.clone()], 1_000_000)
            .unwrap()
            .is_success()
    );
    allowed.record.review_by_utc = Some(102);
    assert!(
        adjudicate(&inspection, &[allowed.clone()], 101)
            .unwrap()
            .is_success()
    );
    assert!(
        !adjudicate(&inspection, &[allowed], 102)
            .unwrap()
            .is_success()
    );
}
#[test]
fn allocation_limit_retains_earlier_complete_findings_and_labels_partial_group() {
    let mut budget = ScanBudget::default();
    let mut scanner = ScanAccumulator::new(source()).unwrap();
    scanner
        .scan_file("build.rs", b"Command::new(", &scope(), &mut budget)
        .unwrap();
    let many = b"Command::new(".repeat(MAX_OCCURRENCES);
    assert!(
        scanner
            .scan_file("src/lib.rs", &many, &scope(), &mut budget)
            .is_err()
    );
    let report = scanner.finish(None);
    assert!(matches!(report.coverage, Coverage::Incomplete { .. }));
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.path == "build.rs" && f.complete)
    );
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.path == "src/lib.rs" && !f.complete && !f.occurrences.is_empty())
    );
    assert!(scaffold_review(&report).is_err());
    assert!(
        report
            .findings
            .iter()
            .find(|f| !f.complete)
            .unwrap()
            .id()
            .is_err()
    );
    report.validate().unwrap();
}
#[test]
fn cancellation_and_source_prefix_do_not_produce_false_empty_completion() {
    let mut scanner = ScanAccumulator::new(source()).unwrap();
    assert!(
        scanner
            .scan_file_checked(
                "build.rs",
                b"Command::new(",
                &scope(),
                &mut ScanBudget::default(),
                &mut || Err("cancelled".into())
            )
            .is_err()
    );
    assert!(matches!(
        scanner.finish(None).coverage,
        Coverage::Incomplete { .. }
    ));
    let mut git = source();
    git.origin = Origin::Git {
        url: "https://example.com/repo".into(),
        rev: "a".repeat(40),
        subdirectory: "crates/sample".into(),
        materialisation_sha256: digest(b"tree"),
    };
    let mut scanner = ScanAccumulator::new(git).unwrap();
    let scope = Scope {
        explicit_paths: Some(BTreeSet::from(["helpers/build.rs".into()])),
        ..Scope::default()
    };
    scanner
        .scan_file(
            "helpers/build.rs",
            b"Command::new(",
            &scope,
            &mut ScanBudget::default(),
        )
        .unwrap();
    let report = scanner.finish(None);
    report.validate().unwrap();
    assert_eq!(report.semantics, GIT_SEMANTICS);
}
#[test]
fn source_disambiguation_never_guesses_and_reports_roundtrip() {
    let a = scan(b"Command::new(");
    let mut b = a.clone();
    b.source.origin = Origin::CratesIo {
        archive_sha256: digest(b"different"),
    };
    b.findings[0].source_id = b.source.id().unwrap();
    let report = Report {
        schema_version: 1,
        scope: "exact-source-set".into(),
        sources: vec![a.clone(), b],
        excluded: vec![],
        errors: vec![],
    };
    assert_eq!(Report::parse(&report.encode().unwrap()).unwrap(), report);
    assert!(
        select(
            &report,
            &Selection {
                package: Some("sample@1.2.3".into()),
                ..Selection::default()
            }
        )
        .is_err()
    );
    assert_eq!(
        select(
            &report,
            &Selection {
                source_id: Some(a.source.id().unwrap().to_string()),
                ..Selection::default()
            }
        )
        .unwrap(),
        a
    );
}
#[test]
fn repository_preadd_reference_preserves_unrelated_policy_and_is_noop() {
    let before = "# Existing policy\n[rust]\n";
    let reference = IocRecordReference {
        record: "docs/reviews/sample-ioc.md".into(),
        record_sha256: digest(b"record"),
    };
    let after = crate::append_ioc_record(before, &reference).unwrap();
    assert!(after.starts_with(before));
    let parsed = crate::parse_reviewed_targets_toml(&after).unwrap();
    assert!(parsed.rust_families().is_empty());
    assert_eq!(parsed.ioc_records(), std::slice::from_ref(&reference));
    assert_eq!(crate::append_ioc_record(&after, &reference).unwrap(), after);
    let changed = IocRecordReference {
        record_sha256: digest(b"changed"),
        ..reference
    };
    assert!(crate::append_ioc_record(&after, &changed).is_err());
}

#[test]
fn chunked_hash_cancellation_and_escaped_output_are_bounded() {
    let bytes = vec![0xff; 256 * 1024];
    let mut checks = 0;
    assert!(
        digest_checked(&bytes, &mut || {
            checks += 1;
            if checks == 3 {
                Err("cancelled during hash".into())
            } else {
                Ok(())
            }
        })
        .is_err()
    );
    assert_eq!(checks, 3);
    assert_eq!(
        digest_checked(b"stable", &mut || Ok(())).unwrap(),
        digest(b"stable")
    );
    let expanded = "\0".repeat(MAX_REPORT_BYTES / 4);
    assert!(encode_bounded(&expanded).is_err());
    let mut review = allowance(&scan(b"Command::new(")).record;
    review.rationale = expanded;
    assert!(render_review(&review).is_err());
}

#[test]
fn human_snippet_rendering_is_not_finding_authority() {
    let inspection = scan(b"Command::new(");
    let allowance = allowance(&inspection);
    let mut presentation = inspection.clone();
    presentation.findings[0].occurrences[0].snippet = "different escaped display".into();
    assert_eq!(
        presentation.findings[0].id().unwrap(),
        inspection.findings[0].id().unwrap()
    );
    assert!(
        adjudicate(&presentation, &[allowance], 101)
            .unwrap()
            .is_success()
    );
    presentation.findings[0].file_sha256 = digest(b"changed source bytes");
    assert_ne!(
        presentation.findings[0].id().unwrap(),
        inspection.findings[0].id().unwrap()
    );
}

#[test]
fn manifest_role_aliases_are_typed_and_build_defaults_are_distinct() {
    use serde_json::json;
    for value in [
        json!({"lib":{"proc-macro":"true"}}),
        json!({"lib":{"proc_macro":1}}),
        json!({"lib":{"proc-macro":false,"proc_macro":true}}),
        json!({"lib":{"crate-type":["lib"],"crate_type":["proc-macro"]}}),
        json!({"lib":{"crate-type":"proc-macro"}}),
        json!({"lib":{"crate-type":[true]}}),
        json!({"lib":{"proc-macro":true,"path":false}}),
    ] {
        assert!(manifest_roles(&value).is_err());
    }
    assert_eq!(
        manifest_roles(&json!({})).unwrap().build_script,
        BuildScriptRole::Auto
    );
    assert_eq!(
        manifest_roles(&json!({"package":{"build":true}}))
            .unwrap()
            .build_script,
        BuildScriptRole::Path("build.rs".into())
    );
    assert_eq!(
        manifest_roles(&json!({"package":{"build":false}}))
            .unwrap()
            .build_script,
        BuildScriptRole::Disabled
    );
}
