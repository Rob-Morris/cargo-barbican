use super::common::*;

#[test]
fn audit_runs_cargo_deny_json_by_default() {
    let cli = Cli::parse_from(["cargo-barbican", "audit"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(runner.recorded_audit_calls().is_empty());
    assert_eq!(runner.recorded_audit_json_calls().len(), 0);
    let deny_calls = runner.recorded_deny_json_calls();
    assert_eq!(deny_calls.len(), 1);
    assert_eq!(
        deny_calls[0].2,
        vec![
            barbican::CargoDenyCheck::Advisories,
            barbican::CargoDenyCheck::Bans,
            barbican::CargoDenyCheck::Sources,
        ]
    );
}

#[test]
fn audit_reports_failures() {
    let cli = Cli::parse_from(["cargo-barbican", "audit"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default().with_cargo_deny_json("not-json");
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(runner.recorded_audit_calls().is_empty());
    assert_eq!(runner.recorded_deny_json_calls().len(), 1);
    assert!(
        String::from_utf8(stderr)
            .expect("stderr should be utf8")
            .contains("FAIL cargo deny structured output:")
    );
}

#[test]
fn audit_accepts_reviewed_advisory_with_cargo_deny_scanner() {
    let cli = Cli::parse_from(["cargo-barbican", "audit"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default().with_cargo_deny_json(&cargo_deny_advisory_jsonl());
    let temp_dir = fresh_temp_dir();
    write_advisory_audit_fixture(&temp_dir, None, "2026-09-21");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner_at(
        cli,
        &temp_dir,
        &client,
        &runner,
        fixed_now(),
        &mut stdout,
        &mut stderr,
    )
    .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Audit: PASS"));
    assert!(rendered.contains("Allowed policy exceptions:"));
    assert!(rendered.contains("serde@1.0.228 RUSTSEC-2026-0001 accepted by reviewed family"));
    assert_eq!(runner.recorded_deny_json_calls().len(), 1);
    assert!(runner.recorded_audit_json_calls().is_empty());
}

#[test]
fn audit_fails_unreviewed_advisory_with_cargo_deny_scanner() {
    let cli = Cli::parse_from(["cargo-barbican", "audit"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default().with_cargo_deny_json(&cargo_deny_advisory_jsonl());
    let temp_dir = fresh_temp_dir();
    fs::write(temp_dir.join("barbican.toml"), "").expect("config should write");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner_at(
        cli,
        &temp_dir,
        &client,
        &runner,
        fixed_now(),
        &mut stdout,
        &mut stderr,
    )
    .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Audit: FAIL"));
    assert!(rendered.contains("FAIL RUSTSEC-2026-0001 serde@1.0.228: unreviewed advisory finding"));
    assert!(!rendered.contains("Allowed policy exceptions:"));
}

#[test]
fn audit_fails_expired_reviewed_advisory_with_cargo_deny_scanner() {
    let cli = Cli::parse_from(["cargo-barbican", "audit"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default().with_cargo_deny_json(&cargo_deny_advisory_jsonl());
    let temp_dir = fresh_temp_dir();
    write_advisory_audit_fixture(&temp_dir, None, "2000-01-01");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner_at(
        cli,
        &temp_dir,
        &client,
        &runner,
        fixed_now(),
        &mut stdout,
        &mut stderr,
    )
    .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Audit: FAIL"));
    assert!(rendered.contains("reviewed advisory exception expired"));
}

#[test]
fn audit_accepts_reviewed_advisory_with_cargo_audit_scanner() {
    let cli = Cli::parse_from(["cargo-barbican", "audit"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default().with_cargo_audit_json(&cargo_audit_advisory_json());
    let temp_dir = fresh_temp_dir();
    write_advisory_audit_fixture(
        &temp_dir,
        Some(r#"lockfile_scanner = "cargo-audit""#),
        "2026-09-21",
    );
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner_at(
        cli,
        &temp_dir,
        &client,
        &runner,
        fixed_now(),
        &mut stdout,
        &mut stderr,
    )
    .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Audit: PASS"));
    assert!(rendered.contains("Allowed policy exceptions:"));
    assert_eq!(runner.recorded_deny_json_calls().len(), 1);
    assert_eq!(runner.recorded_audit_json_calls().len(), 1);
    assert_ne!(runner.recorded_audit_json_calls()[0].0, temp_dir);
    assert_eq!(runner.frozen_metadata_calls(), 0);
}

#[test]
fn audit_renders_cargo_audit_remediation_details_and_dependency_path() {
    let cli = Cli::parse_from(["cargo-barbican", "audit"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default()
        .with_cargo_audit_json(&cargo_audit_advisory_with_remediation_json())
        .with_frozen_metadata(advisory_path_metadata_json());
    let temp_dir = fresh_temp_dir();
    fs::write(
        temp_dir.join("barbican.toml"),
        r#"[delegates.advisories]
lockfile_scanner = "cargo-audit"
"#,
    )
    .expect("config should write");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Audit: FAIL"));
    assert!(rendered.contains("FAIL RUSTSEC-2026-0001 serde@1.0.228 (high): unreviewed advisory finding; title: vulnerable parser; fixed in >=1.0.229"));
    assert!(rendered.contains("dependency path: root@0.1.0 -> mid@1.0.0 -> serde@1.0.228"));
    assert_eq!(runner.frozen_metadata_calls(), 1);
}

#[test]
fn audit_json_outputs_structured_findings() {
    let cli = Cli::parse_from(["cargo-barbican", "audit", "--format", "json"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default()
        .with_cargo_audit_json(&cargo_audit_advisory_with_remediation_json())
        .with_frozen_metadata(advisory_path_metadata_json());
    let temp_dir = fresh_temp_dir();
    fs::write(
        temp_dir.join("barbican.toml"),
        r#"[delegates.advisories]
lockfile_scanner = "cargo-audit"
"#,
    )
    .expect("config should write");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&stdout).expect("stdout should be valid json");

    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["status"], "fail");
    assert_eq!(report["success"], false);
    assert_eq!(report["dependency_paths_available"], true);
    assert_eq!(report["findings"][0]["advisory_id"], "RUSTSEC-2026-0001");
    assert_eq!(report["findings"][0]["package"]["spec"], "serde@1.0.228");
    assert_eq!(report["findings"][0]["disposition"], "unreviewed");
    assert_eq!(report["findings"][0]["title"], "vulnerable parser");
    assert_eq!(report["findings"][0]["risk"], "high");
    assert_eq!(report["findings"][0]["patched"][0], ">=1.0.229");
    assert_eq!(
        report["findings"][0]["dependency_path"],
        serde_json::json!(["root@0.1.0", "mid@1.0.0", "serde@1.0.228"])
    );
}

#[test]
fn audit_json_outputs_accepted_exception_details_and_collects_paths() {
    let cli = Cli::parse_from(["cargo-barbican", "audit", "--format", "json"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default()
        .with_cargo_audit_json(&cargo_audit_advisory_with_remediation_json())
        .with_frozen_metadata(advisory_path_metadata_json());
    let temp_dir = fresh_temp_dir();
    write_advisory_audit_fixture(
        &temp_dir,
        Some(r#"lockfile_scanner = "cargo-audit""#),
        "2026-09-21",
    );
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner_at(
        cli,
        &temp_dir,
        &client,
        &runner,
        fixed_now(),
        &mut stdout,
        &mut stderr,
    )
    .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert_eq!(runner.frozen_metadata_calls(), 1);
    let report: serde_json::Value =
        serde_json::from_slice(&stdout).expect("stdout should be valid json");

    assert_eq!(report["status"], "pass");
    assert_eq!(report["dependency_paths_available"], true);
    assert_eq!(report["findings"][0]["disposition"], "accepted");
    assert_eq!(report["findings"][0]["exception"]["family"], "serde-family");
    assert_eq!(
        report["findings"][0]["exception"]["review_record"],
        "docs/dependency-reviews/2026-05-27-serde.md"
    );
    assert_eq!(
        report["findings"][0]["exception"]["review_by"],
        "2026-09-21"
    );
    assert_eq!(
        report["findings"][0]["dependency_path"],
        serde_json::json!(["root@0.1.0", "mid@1.0.0", "serde@1.0.228"])
    );
}

#[test]
fn audit_json_outputs_expired_exception_details() {
    let cli = Cli::parse_from(["cargo-barbican", "audit", "--format", "json"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default()
        .with_cargo_audit_json(&cargo_audit_advisory_with_remediation_json())
        .with_frozen_metadata(advisory_path_metadata_json());
    let temp_dir = fresh_temp_dir();
    write_advisory_audit_fixture(
        &temp_dir,
        Some(r#"lockfile_scanner = "cargo-audit""#),
        "2000-01-01",
    );
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner_at(
        cli,
        &temp_dir,
        &client,
        &runner,
        fixed_now(),
        &mut stdout,
        &mut stderr,
    )
    .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&stdout).expect("stdout should be valid json");

    assert_eq!(report["findings"][0]["disposition"], "expired");
    assert_eq!(report["findings"][0]["exception"]["family"], "serde-family");
    assert_eq!(
        report["findings"][0]["exception"]["review_by"],
        "2000-01-01"
    );
}

#[test]
fn audit_json_distinguishes_missing_dependency_path_from_unavailable_path_collection() {
    let cli = Cli::parse_from(["cargo-barbican", "audit", "--format", "json"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default()
        .with_cargo_audit_json(&cargo_audit_advisory_with_remediation_json())
        .with_frozen_metadata(metadata_without_advisory_target_json());
    let temp_dir = fresh_temp_dir();
    fs::write(
        temp_dir.join("barbican.toml"),
        r#"[delegates.advisories]
lockfile_scanner = "cargo-audit"
"#,
    )
    .expect("config should write");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&stdout).expect("stdout should be valid json");

    assert_eq!(report["dependency_paths_available"], true);
    assert!(report["findings"][0]["dependency_path"].is_null());
}

#[test]
fn audit_json_marks_dependency_paths_unavailable_when_metadata_has_no_resolve_graph() {
    let cli = Cli::parse_from(["cargo-barbican", "audit", "--format", "json"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default()
        .with_cargo_audit_json(&cargo_audit_advisory_with_remediation_json())
        .with_frozen_metadata(metadata_with_packages(&[(
            "serde",
            "1.0.228",
            "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228",
        )]));
    let temp_dir = fresh_temp_dir();
    fs::write(
        temp_dir.join("barbican.toml"),
        r#"[delegates.advisories]
lockfile_scanner = "cargo-audit"
"#,
    )
    .expect("config should write");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&stdout).expect("stdout should be valid json");

    assert_eq!(report["dependency_paths_available"], false);
    assert!(report["findings"][0]["dependency_path"].is_null());
}

#[test]
fn audit_text_notes_dependency_path_metadata_subprocess_failures_on_stderr() {
    let cli = Cli::parse_from(["cargo-barbican", "audit"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default()
        .with_cargo_audit_json(&cargo_audit_advisory_with_remediation_json())
        .with_frozen_metadata_error("metadata failed");
    let temp_dir = fresh_temp_dir();
    fs::write(
        temp_dir.join("barbican.toml"),
        r#"[delegates.advisories]
lockfile_scanner = "cargo-audit"
"#,
    )
    .expect("config should write");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    let rendered_error = String::from_utf8(stderr).expect("stderr should be utf8");
    assert!(rendered.contains("Audit: FAIL"));
    assert!(rendered_error.contains("note: dependency path context unavailable:"));
    assert!(rendered_error.contains("cargo metadata --frozen"));
}

#[test]
fn audit_text_notes_dependency_path_unknown_package_metadata_errors_on_stderr() {
    let cli = Cli::parse_from(["cargo-barbican", "audit"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default()
        .with_cargo_audit_json(&cargo_audit_advisory_with_remediation_json())
        .with_frozen_metadata(metadata_with_unknown_workspace_package_json());
    let temp_dir = fresh_temp_dir();
    fs::write(
        temp_dir.join("barbican.toml"),
        r#"[delegates.advisories]
lockfile_scanner = "cargo-audit"
"#,
    )
    .expect("config should write");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    let rendered_error = String::from_utf8(stderr).expect("stderr should be utf8");
    assert!(rendered_error.contains("referenced unknown package id"));
}

#[test]
fn audit_text_notes_dependency_path_invalid_package_metadata_errors_on_stderr() {
    let cli = Cli::parse_from(["cargo-barbican", "audit"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default()
        .with_cargo_audit_json(&cargo_audit_advisory_with_remediation_json())
        .with_frozen_metadata(metadata_with_invalid_workspace_package_json());
    let temp_dir = fresh_temp_dir();
    fs::write(
        temp_dir.join("barbican.toml"),
        r#"[delegates.advisories]
lockfile_scanner = "cargo-audit"
"#,
    )
    .expect("config should write");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    let rendered_error = String::from_utf8(stderr).expect("stderr should be utf8");
    assert!(rendered_error.contains("is not an exact crate spec"));
}

#[test]
fn audit_accepts_reviewed_advisory_with_both_scanners() {
    let cli = Cli::parse_from(["cargo-barbican", "audit"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default()
        .with_cargo_deny_json(&cargo_deny_advisory_jsonl())
        .with_cargo_audit_json(&cargo_audit_advisory_json());
    let temp_dir = fresh_temp_dir();
    write_advisory_audit_fixture(
        &temp_dir,
        Some(r#"lockfile_scanner = "both""#),
        "2026-09-21",
    );
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner_at(
        cli,
        &temp_dir,
        &client,
        &runner,
        fixed_now(),
        &mut stdout,
        &mut stderr,
    )
    .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert_eq!(rendered.matches("accepted by reviewed family").count(), 1);
    assert_eq!(runner.recorded_deny_json_calls().len(), 1);
    assert_eq!(runner.recorded_audit_json_calls().len(), 1);
}

#[test]
fn audit_generated_deny_config_neutralises_native_advisory_ignore() {
    let cli = Cli::parse_from(["cargo-barbican", "audit"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    fs::write(
        temp_dir.join("deny.toml"),
        r#"[advisories]
ignore = ["RUSTSEC-2026-0001"]
unmaintained = "allow"
"#,
    )
    .expect("deny config should write");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    let generated = runner.recorded_deny_json_config_texts();
    assert_eq!(generated.len(), 1);
    assert!(generated[0].contains("ignore = []"));
    assert!(!generated[0].contains("RUSTSEC-2026-0001"));
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Native delegated advisory ignores:"));
    assert!(rendered.contains("WARN deny.toml ignores RUSTSEC-2026-0001"));
}

#[test]
fn audit_uses_controlled_cwd_to_neutralise_cargo_audit_config() {
    let cli = Cli::parse_from(["cargo-barbican", "audit"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    fs::write(
        temp_dir.join("barbican.toml"),
        r#"[delegates.advisories]
lockfile_scanner = "cargo-audit"
"#,
    )
    .expect("config should write");
    fs::create_dir_all(temp_dir.join(".cargo")).expect("cargo config dir should exist");
    fs::write(
        temp_dir.join(".cargo/audit.toml"),
        r#"[advisories]
ignore = ["RUSTSEC-2026-0001"]
"#,
    )
    .expect("cargo audit config should write");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    let audit_calls = runner.recorded_audit_json_calls();
    assert_eq!(audit_calls.len(), 1);
    assert_ne!(audit_calls[0].0, temp_dir);
    assert_eq!(audit_calls[0].1, temp_dir.join("Cargo.lock"));
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("WARN .cargo/audit.toml ignores RUSTSEC-2026-0001"));
}

#[test]
fn audit_runs_cargo_deny_checks_when_cargo_audit_scans_advisories() {
    let cli = Cli::parse_from(["cargo-barbican", "audit"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default().with_cargo_deny_json(&cargo_deny_bans_error_jsonl());
    let temp_dir = fresh_temp_dir();
    fs::write(
        temp_dir.join("barbican.toml"),
        r#"[delegates.advisories]
lockfile_scanner = "cargo-audit"
"#,
    )
    .expect("config should write");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    assert_eq!(runner.recorded_deny_json_calls().len(), 1);
    assert_eq!(runner.recorded_audit_json_calls().len(), 1);
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("FAIL cargo-deny diagnostic without advisory id"));
    assert!(rendered.contains("FAIL cargo-deny bans check reported 1 error(s)"));
}

#[test]
fn audit_fails_native_delegated_ignore_when_policy_is_deny() {
    let cli = Cli::parse_from(["cargo-barbican", "audit"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    fs::write(
        temp_dir.join("barbican.toml"),
        r#"[delegates]
unmanaged_delegated_policy = "deny"
"#,
    )
    .expect("config should write");
    fs::write(
        temp_dir.join("deny.toml"),
        r#"[advisories]
ignore = ["RUSTSEC-2026-0001"]
"#,
    )
    .expect("deny config should write");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Audit: FAIL"));
    assert!(rendered.contains("Native delegated advisory ignores:"));
    assert!(rendered.contains("FAIL deny.toml ignores RUSTSEC-2026-0001"));
}

#[cfg(unix)]
#[test]
fn audit_rejects_symlinked_deny_toml_without_reading_target() {
    use std::os::unix::fs::symlink;

    let cli = Cli::parse_from(["cargo-barbican", "audit"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    fs::write(temp_dir.join("secret.env"), "SECRET_TOKEN=do-not-print\n")
        .expect("secret target should write");
    symlink(temp_dir.join("secret.env"), temp_dir.join("deny.toml"))
        .expect("deny.toml symlink should create");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    let rendered_error = String::from_utf8(stderr).expect("stderr should be utf8");
    assert!(rendered_error.starts_with("FAIL "));
    assert!(rendered_error.contains("deny.toml is a symlink"));
    assert!(!rendered_error.contains("SECRET_TOKEN"));
}

#[cfg(unix)]
#[test]
fn audit_rejects_symlinked_barbican_toml_without_reading_target() {
    use std::os::unix::fs::symlink;

    let cli = Cli::parse_from(["cargo-barbican", "audit"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    fs::write(temp_dir.join("secret.env"), "SECRET_TOKEN=do-not-print\n")
        .expect("secret target should write");
    symlink(temp_dir.join("secret.env"), temp_dir.join("barbican.toml"))
        .expect("barbican.toml symlink should create");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    let rendered_error = String::from_utf8(stderr).expect("stderr should be utf8");
    assert!(rendered_error.starts_with("FAIL "));
    assert!(rendered_error.contains("barbican.toml is a symlink"));
    assert!(!rendered_error.contains("SECRET_TOKEN"));
}

#[cfg(unix)]
#[test]
fn audit_rejects_symlinked_reviewed_targets_without_reading_target() {
    use std::os::unix::fs::symlink;

    let cli = Cli::parse_from(["cargo-barbican", "audit"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    fs::write(temp_dir.join("secret.env"), "SECRET_TOKEN=do-not-print\n")
        .expect("secret target should write");
    symlink(
        temp_dir.join("secret.env"),
        temp_dir.join("reviewed-targets.toml"),
    )
    .expect("reviewed-targets.toml symlink should create");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    let rendered_error = String::from_utf8(stderr).expect("stderr should be utf8");
    assert!(rendered_error.starts_with("FAIL "));
    assert!(rendered_error.contains("reviewed-targets.toml is a symlink"));
    assert!(!rendered_error.contains("SECRET_TOKEN"));
}

#[test]
fn audit_loads_regular_barbican_and_reviewed_targets_files() {
    let cli = Cli::parse_from(["cargo-barbican", "audit"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    fs::write(
        temp_dir.join("barbican.toml"),
        r#"[delegates.advisories]
lockfile_scanner = "cargo-deny"
"#,
    )
    .expect("barbican config should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        "[rust]\nfamilies = []\n",
    )
    .expect("reviewed targets should write");
    fs::write(temp_dir.join("Cargo.toml"), "[dependencies]\n").expect("manifest should write");
    fs::write(temp_dir.join("Cargo.lock"), "version = 4\n").expect("lockfile should write");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("regular policy files should load");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(
        String::from_utf8(stdout)
            .expect("stdout should be utf8")
            .contains("Audit: PASS")
    );
    assert!(stderr.is_empty());
}

#[test]
fn audit_reports_cargo_audit_settings_ignore_and_idless_warnings() {
    let cli = Cli::parse_from(["cargo-barbican", "audit"]);
    let client = FakeCratesIoClient::default();
    let runner =
        FakeCommandRunner::default().with_cargo_audit_json(&cargo_audit_ignored_and_idless_json());
    let temp_dir = fresh_temp_dir();
    fs::write(
        temp_dir.join("barbican.toml"),
        r#"[delegates.advisories]
lockfile_scanner = "cargo-audit"
"#,
    )
    .expect("config should write");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Audit: FAIL"));
    assert!(
        rendered
            .contains("FAIL cargo-audit runtime settings.ignore still contains RUSTSEC-2026-0001")
    );
    assert!(rendered.contains("FAIL cargo-audit reported 1 warning(s) without advisory ids"));
}

#[test]
fn audit_fails_closed_on_cargo_audit_parse_errors() {
    let cli = Cli::parse_from(["cargo-barbican", "audit"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default().with_cargo_audit_json("not-json");
    let temp_dir = fresh_temp_dir();
    fs::write(
        temp_dir.join("barbican.toml"),
        r#"[delegates.advisories]
lockfile_scanner = "cargo-audit"
"#,
    )
    .expect("config should write");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    assert!(
        String::from_utf8(stderr)
            .expect("stderr should be utf8")
            .contains("FAIL cargo audit structured output:")
    );
}

fn cargo_audit_advisory_with_remediation_json() -> String {
    r#"{
  "vulnerabilities": {
    "found": true,
    "count": 1,
    "list": [
      {
        "advisory": {
          "id": "RUSTSEC-2026-0001",
          "title": "vulnerable parser",
          "severity": "high"
        },
        "package": { "name": "serde", "version": "1.0.228" },
        "versions": { "patched": [">=1.0.229"], "unaffected": [] }
      }
    ]
  },
  "settings": { "ignore": [] },
  "warnings": {}
}"#
    .to_owned()
}

fn advisory_path_metadata_json() -> String {
    r#"{
  "packages": [
    {"name": "root", "id": "path+file:///repo#root@0.1.0", "version": "0.1.0", "targets": []},
    {"name": "mid", "id": "registry+https://github.com/rust-lang/crates.io-index#mid@1.0.0", "version": "1.0.0", "targets": []},
    {"name": "serde", "id": "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228", "version": "1.0.228", "targets": []}
  ],
  "workspace_members": ["path+file:///repo#root@0.1.0"],
  "resolve": {
    "nodes": [
      {
        "id": "path+file:///repo#root@0.1.0",
        "deps": [{"name": "mid", "pkg": "registry+https://github.com/rust-lang/crates.io-index#mid@1.0.0"}]
      },
      {
        "id": "registry+https://github.com/rust-lang/crates.io-index#mid@1.0.0",
        "deps": [{"name": "serde", "pkg": "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228"}]
      },
      {
        "id": "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228",
        "deps": []
      }
    ]
  }
}"#
    .to_owned()
}

fn metadata_without_advisory_target_json() -> String {
    r#"{
  "packages": [
    {"name": "root", "id": "path+file:///repo#root@0.1.0", "version": "0.1.0", "targets": []}
  ],
  "workspace_members": ["path+file:///repo#root@0.1.0"],
  "resolve": {
    "nodes": [
      {
        "id": "path+file:///repo#root@0.1.0",
        "deps": []
      }
    ]
  }
}"#
    .to_owned()
}

fn metadata_with_unknown_workspace_package_json() -> String {
    r#"{
  "packages": [
    {"name": "serde", "id": "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228", "version": "1.0.228", "targets": []}
  ],
  "workspace_members": ["path+file:///repo#root@0.1.0"],
  "resolve": {
    "nodes": [
      {
        "id": "path+file:///repo#root@0.1.0",
        "deps": [{"name": "serde", "pkg": "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228"}]
      },
      {
        "id": "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228",
        "deps": []
      }
    ]
  }
}"#
    .to_owned()
}

fn metadata_with_invalid_workspace_package_json() -> String {
    r#"{
  "packages": [
    {"name": "bad/name", "id": "path+file:///repo#bad-name@0.1.0", "version": "0.1.0", "targets": []},
    {"name": "serde", "id": "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228", "version": "1.0.228", "targets": []}
  ],
  "workspace_members": ["path+file:///repo#bad-name@0.1.0"],
  "resolve": {
    "nodes": [
      {
        "id": "path+file:///repo#bad-name@0.1.0",
        "deps": [{"name": "serde", "pkg": "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228"}]
      },
      {
        "id": "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228",
        "deps": []
      }
    ]
  }
}"#
    .to_owned()
}
