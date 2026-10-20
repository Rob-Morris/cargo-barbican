use super::common::*;

const REV: &str = "901f9946efdaaa289e6b1c5bd56dc67f4b651e51";

fn source() -> String {
    format!("git+https://example.org/reviewed.git?rev={REV}#{REV}")
}

fn git_audit_workspace() -> TempDirGuard {
    let root = fresh_temp_dir();
    write_root_manifest(&root);
    fs::write(
        root.join("Cargo.lock"),
        lockfile_with_package_sources(&[("helper", "0.1.0", Some(&source()))]),
    )
    .unwrap();
    root
}

#[test]
fn zero_finding_audit_discloses_git_without_review_families_and_with_degraded_manifests() {
    for degraded in [false, true] {
        let root = git_audit_workspace();
        let runner = if degraded {
            fs::write(
                root.join("Cargo.toml"),
                "[package]\nname=\"invalid name\"\nversion=\"0.1.0\"\n",
            )
            .unwrap();
            FakeCommandRunner::default().with_workspace_manifest_error("invalid package name")
        } else {
            FakeCommandRunner::default()
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        let exit = run_cli_with_runner(
            Cli::parse_from(["cargo-barbican", "audit", "--format", "json"]),
            &root,
            &FakeCratesIoClient::default(),
            &runner,
            &mut out,
            &mut err,
        )
        .unwrap();
        assert_eq!(exit, ExitCode::SUCCESS);
        let report: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(report["source_context_available"], true);
        assert_eq!(report["git_sources"][0]["source_identity"]["rev"], REV);
        assert_eq!(
            report["git_sources"][0]["advisory_visibility"],
            "not-established-for-git"
        );
        assert!(report["findings"].as_array().unwrap().is_empty());
    }
}

#[test]
fn registry_exception_cannot_hide_source_colliding_git_advisory() {
    let root = git_audit_workspace();
    write_advisory_exception_policy(
        &root,
        "serde",
        "1.0.228",
        PIN_ADD_TEST_CHECKSUM,
        "2026-12-31",
        true,
    );
    fs::write(
        root.join("Cargo.lock"),
        lockfile_with_package_records(&[
            (
                "serde",
                "1.0.228",
                Some(barbican::CRATES_IO_SOURCE),
                Some(PIN_ADD_TEST_CHECKSUM),
            ),
            ("serde", "1.0.228", Some(&source()), None),
        ]),
    )
    .unwrap();
    let lines = [barbican::CRATES_IO_SOURCE.to_owned(), source()].into_iter().map(|source| serde_json::json!({"type":"diagnostic","fields":{"code":"advisory","advisory":{"id":"RUSTSEC-2026-0001"},"graphs":[{"Krate":{"name":"serde","version":"1.0.228","source":source}}]}}).to_string()).collect::<Vec<_>>().join("\n");
    let runner = FakeCommandRunner::default()
        .with_cargo_deny_json(&format!("{lines}\n{}", clean_cargo_deny_jsonl()));
    let mut out = Vec::new();
    let mut err = Vec::new();
    let exit = run_cli_with_runner(
        Cli::parse_from(["cargo-barbican", "audit", "--format", "json"]),
        &root,
        &FakeCratesIoClient::default(),
        &runner,
        &mut out,
        &mut err,
    )
    .unwrap();
    assert_eq!(exit, ExitCode::from(1));
    let report: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 2);
    assert!(
        findings
            .iter()
            .all(|finding| finding["disposition"] == "unreviewed")
    );
    let git = findings
        .iter()
        .find(|finding| finding["package"]["source_identity"]["source"] == "git")
        .unwrap();
    assert!(git["governed_exception"].is_null());
    assert!(git["remediation"].is_null());
}

#[test]
fn failed_delegate_never_echoes_source_credentials() {
    let root = git_audit_workspace();
    let runner = FakeCommandRunner::default()
        .with_cargo_deny_json_failure(2, "error fetching https://user:SECRET@example.org/repo\n");
    let mut out = Vec::new();
    let mut err = Vec::new();
    assert_eq!(
        run_cli_with_runner(
            Cli::parse_from(["cargo-barbican", "audit"]),
            &root,
            &FakeCratesIoClient::default(),
            &runner,
            &mut out,
            &mut err
        )
        .unwrap(),
        ExitCode::from(1)
    );
    let error = String::from_utf8(err).unwrap();
    assert!(error.contains("status 2"));
    assert!(!error.contains("SECRET"));
}

#[test]
fn audit_explains_unavailable_source_policy_without_echoing_config_contents() {
    let root = git_audit_workspace();
    fs::create_dir_all(root.join(".cargo")).unwrap();
    fs::write(root.join(".cargo/config.toml"), "[source.SECRET\n").unwrap();
    for format in ["text", "json"] {
        let mut out = Vec::new();
        let mut err = Vec::new();
        run_cli_with_runner(
            Cli::parse_from(["cargo-barbican", "audit", "--format", format]),
            &root,
            &FakeCratesIoClient::default(),
            &FakeCommandRunner::default(),
            &mut out,
            &mut err,
        )
        .unwrap();
        let text = String::from_utf8(out.clone()).unwrap();
        assert!(!text.contains("SECRET"));
        if format == "json" {
            let report: serde_json::Value = serde_json::from_slice(&out).unwrap();
            assert_eq!(report["source_policy_context"]["status"], "unavailable");
        } else {
            assert!(text.contains("source-policy context unavailable"));
            assert!(text.contains("reviewed advisory exceptions disabled"));
        }
    }
}

#[test]
fn git_update_is_rejected_before_registry_queries_or_mutation() {
    let root = git_audit_workspace();
    let original = fs::read(root.join("Cargo.lock")).unwrap();
    for dry_run in [false, true] {
        let client = FakeCratesIoClient::default();
        let runner = FakeCommandRunner::default();
        let mut args = vec!["cargo-barbican", "update", "helper@0.1.0"];
        if dry_run {
            args.push("--dry-run");
        }
        let mut out = Vec::new();
        let mut err = Vec::new();
        assert_eq!(
            run_cli_with_runner(
                Cli::parse_from(args),
                &root,
                &client,
                &runner,
                &mut out,
                &mut err
            )
            .unwrap(),
            ExitCode::from(1)
        );
        assert!(client.recorded_fetches().is_empty());
        assert_eq!(fs::read(root.join("Cargo.lock")).unwrap(), original);
    }
}
