use super::common::*;

#[test]
fn assess_reports_policy_violating_against_non_git_base_directory() {
    let cli = Cli::parse_from(["cargo-barbican", "assess", "--base-dir", "baseline"]);
    let client =
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2020-05-26T00:00:00Z", false);
    let runner = FakeCommandRunner::default().with_cargo_metadata(&metadata_with_packages(&[(
        "serde",
        "1.0.228",
        "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228",
    )]));
    let temp_dir = fresh_temp_dir();
    let baseline_dir = temp_dir.join("baseline");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::create_dir_all(&baseline_dir).expect("baseline directory should be creatable");
    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"1\"\n",
    )
    .expect("current manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_packages(&[("serde", "1.0.228", true)]),
    )
    .expect("current lockfile should write");
    fs::write(
        baseline_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"1\"\n",
    )
    .expect("baseline manifest should write");
    fs::write(
        baseline_dir.join("Cargo.lock"),
        lockfile_with_packages(&[("serde", "1.0.227", true)]),
    )
    .expect("baseline lockfile should write");

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
    assert!(rendered.contains("Suggested classification: policy-violating"));
    assert!(rendered.contains("age violations: serde@1.0.228 ("));
}

#[test]
fn assess_reports_missing_non_git_base_directory_lockfile() {
    let cli = Cli::parse_from(["cargo-barbican", "assess", "--base-dir", "missing"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"1\"\n",
    )
    .expect("current manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_packages(&[("serde", "1.0.227", true)]),
    )
    .expect("current lockfile should write");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    assert!(
        String::from_utf8(stderr)
            .expect("stderr should be utf8")
            .contains("FAIL missing/Cargo.lock: lockfile not found")
    );
}

#[test]
fn assess_checks_against_an_explicit_non_head_base_ref() {
    // Mirrors `run_routine_safe_assess`, but pins that `--base-ref` actually
    // threads a non-HEAD value through both the base lockfile and base
    // manifest `git_show` keying.
    let cli = Cli::parse_from(["cargo-barbican", "assess", "--base-ref", "v2.0.0"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default()
        .with_git_show(
            "v2.0.0:Cargo.lock",
            &lockfile_with_packages(&[("serde", "1.0.227", true)]),
        )
        .with_git_show("v2.0.0:Cargo.toml", "[dependencies]\nserde = \"1\"\n");
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"1\"\n",
    )
    .expect("current manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_packages(&[("serde", "1.0.227", true)]),
    )
    .expect("current lockfile should write");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Suggested classification: routine-safe"));
    assert!(rendered.contains("No policy findings detected."));
}

#[test]
fn assess_accepts_a_custom_lockfile_path() {
    let cli = Cli::parse_from([
        "cargo-barbican",
        "assess",
        "--lockfile",
        "workspace/Cargo.lock",
    ]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default()
        .with_git_show(
            "HEAD:workspace/Cargo.lock",
            &lockfile_with_packages(&[("serde", "1.0.227", true)]),
        )
        .with_git_show("HEAD:Cargo.toml", "[dependencies]\nserde = \"1\"\n");
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"1\"\n",
    )
    .expect("current manifest should write");
    fs::create_dir_all(temp_dir.join("workspace")).expect("workspace dir should be creatable");
    fs::write(
        temp_dir.join("workspace/Cargo.lock"),
        lockfile_with_packages(&[("serde", "1.0.227", true)]),
    )
    .expect("current lockfile should write");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Suggested classification: routine-safe"));
    assert!(rendered.contains("No policy findings detected."));
}

#[test]
fn assess_reports_missing_custom_lockfile_path() {
    let cli = Cli::parse_from([
        "cargo-barbican",
        "assess",
        "--lockfile",
        "workspace/Cargo.lock",
    ]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"1\"\n",
    )
    .expect("current manifest should write");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    assert!(
        String::from_utf8(stderr)
            .expect("stderr should be utf8")
            .contains("FAIL workspace/Cargo.lock: lockfile not found")
    );
}

#[test]
fn assess_reports_routine_safe_when_no_findings_are_present() {
    let (exit_code, rendered, stderr) = run_routine_safe_assess(&[]);

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert!(rendered.contains("Suggested classification: routine-safe"));
    assert!(rendered.contains("No policy findings detected."));
}

#[test]
fn assess_policy_mode_elevated_risk_preserves_routine_safe_success() {
    let (exit_code, rendered, stderr) =
        run_routine_safe_assess(&["--policy-mode", "elevated-risk"]);

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert!(rendered.contains("Suggested classification: routine-safe"));
    assert!(rendered.contains("No policy findings detected."));
    assert!(!rendered.contains("Elevated-risk findings accepted by --policy-mode elevated-risk"));
}

#[test]
fn assess_reports_lockfile_checksum_drift_for_existing_selection() {
    let cli = Cli::parse_from(["cargo-barbican", "assess"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default()
        .with_git_show(
            "HEAD:Cargo.lock",
            &lockfile_with_package_records(&[(
                "serde",
                "1.0.228",
                Some("registry+https://github.com/rust-lang/crates.io-index"),
                Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
            )]),
        )
        .with_git_show("HEAD:Cargo.toml", "[dependencies]\nserde = \"1\"\n");
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"1\"\n",
    )
    .expect("current manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_package_records(&[(
            "serde",
            "1.0.228",
            Some("registry+https://github.com/rust-lang/crates.io-index"),
            Some("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        )]),
    )
    .expect("current lockfile should write");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Suggested classification: policy-violating"));
    assert!(rendered.contains(
        "lockfile checksum drifts: serde@1.0.228 checksum drift: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef -> ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    ));
    assert!(rendered.contains(
        "locked crates.io checksums changed for existing selections: serde@1.0.228 checksum drift"
    ));
}

#[test]
fn assess_reports_elevated_risk_findings_for_new_surfaces() {
    let (exit_code, rendered, stderr) = run_elevated_risk_assess(&[]);

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    assert!(rendered.contains("Suggested classification: elevated-risk"));
    assert!(rendered.contains(
        "new direct dependencies: Cargo.toml:dependencies:forked, Cargo.toml:dependencies:native-sys"
    ));
    assert!(
        rendered.contains("new non-crates.io direct specs: Cargo.toml:dependencies:forked (git)")
    );
    assert!(rendered.contains(
        "source changes: forked@0.1.0 source=git+https://example.com/forked.git#deadbeef"
    ));
    assert!(rendered.contains("new -sys crates: native-sys@1.2.3"));
    assert!(rendered.contains("new/changed build.rs surface: native-sys@1.2.3"));
    assert!(rendered.contains("new/changed proc-macro surface: native-sys@1.2.3"));
    assert!(rendered.contains("Elevated-risk signals:"));
    assert!(!rendered.contains("Elevated-risk findings accepted by --policy-mode elevated-risk"));
}

#[test]
fn assess_policy_mode_elevated_risk_accepts_elevated_risk_findings() {
    let (exit_code, rendered, stderr) =
        run_elevated_risk_assess(&["--policy-mode", "elevated-risk"]);

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert!(rendered.contains("Suggested classification: elevated-risk"));
    assert!(rendered.contains("Elevated-risk signals:"));
    assert!(rendered.contains(
        "Elevated-risk findings accepted by --policy-mode elevated-risk; blocking policy findings would still fail."
    ));
}

#[test]
fn assess_allows_reviewed_execution_surfaces_when_review_record_exists() {
    let (exit_code, rendered, stderr) =
        run_allowed_surface_assess("1.2.3", true, &["build-rs", "proc-macro", "native-sys"]);

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert!(rendered.contains("Suggested classification: routine-safe"));
    assert!(rendered.contains("Allowed policy exceptions:"));
    assert!(rendered.contains(
        "native-sys@1.2.3 build-rs allowed by reviewed family native-family (docs/dependency-reviews/2026-05-27-native.md)"
    ));
    assert!(rendered.contains(
        "native-sys@1.2.3 proc-macro allowed by reviewed family native-family (docs/dependency-reviews/2026-05-27-native.md)"
    ));
    assert!(rendered.contains(
        "native-sys@1.2.3 native-sys allowed by reviewed family native-family (docs/dependency-reviews/2026-05-27-native.md)"
    ));
    assert!(!rendered.contains("Elevated-risk signals:"));
    assert!(!rendered.contains("new/changed build.rs surface: native-sys@1.2.3"));
    assert!(!rendered.contains("new/changed proc-macro surface: native-sys@1.2.3"));
    assert!(!rendered.contains("new -sys crates: native-sys@1.2.3"));
}

#[test]
fn assess_lists_reviewed_age_exception_under_allowed_policy_exceptions() {
    let cli = Cli::parse_from(["cargo-barbican", "assess"]);
    let client =
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2020-05-26T00:00:00Z", false);
    let runner = FakeCommandRunner::default()
        .with_git_show("HEAD:Cargo.lock", "version = 4\n")
        .with_git_show("HEAD:Cargo.toml", "")
        .with_cargo_metadata(
            r#"{
  "packages": [
    {
      "name": "serde",
      "id": "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228",
      "version": "1.0.228",
      "targets": [{"kind": ["lib"]}]
    }
  ],
  "workspace_members": [],
  "resolve": null
}"#,
        );
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("barbican.toml"),
        "[high_scrutiny]\nnew_direct_dependencies = false\n",
    )
    .expect("config should write");
    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"1\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_packages(&[("serde", "1.0.228", true)]),
    )
    .expect("lockfile should write");
    write_age_exception_policy(
        &temp_dir,
        "serde",
        "1.0.228",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        true,
    );

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
    assert!(rendered.contains("Suggested classification: routine-safe"));
    assert!(rendered.contains("Allowed policy exceptions:"));
    assert!(rendered.contains(
        "serde@1.0.228 release age allowed by reviewed family serde-family (docs/dependency-reviews/2026-05-27-serde.md)"
    ));
    assert!(!rendered.contains("age violations"));
}

#[test]
fn assess_does_not_honour_age_exception_with_missing_review_record() {
    let cli = Cli::parse_from(["cargo-barbican", "assess"]);
    let client =
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2020-05-26T00:00:00Z", false);
    let runner = FakeCommandRunner::default()
        .with_git_show("HEAD:Cargo.lock", "version = 4\n")
        .with_git_show("HEAD:Cargo.toml", "")
        .with_cargo_metadata(
            r#"{
  "packages": [
    {
      "name": "serde",
      "id": "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228",
      "version": "1.0.228",
      "targets": [{"kind": ["lib"]}]
    }
  ],
  "workspace_members": [],
  "resolve": null
}"#,
        );
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("barbican.toml"),
        "[high_scrutiny]\nnew_direct_dependencies = false\n",
    )
    .expect("config should write");
    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"1\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_packages(&[("serde", "1.0.228", true)]),
    )
    .expect("lockfile should write");
    write_age_exception_policy(
        &temp_dir,
        "serde",
        "1.0.228",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        false,
    );

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
    assert!(stdout.is_empty());
    let stderr = String::from_utf8(stderr).expect("stderr should be utf8");
    assert_eq!(
        stderr,
        "FAIL allowed release-age exception review record missing for serde@1.0.228: docs/dependency-reviews/2026-05-27-serde.md\n"
    );
}

#[test]
fn assess_blocks_reviewed_age_exception_checksum_mismatch() {
    let cli = Cli::parse_from(["cargo-barbican", "assess"]);
    let client =
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2020-05-26T00:00:00Z", false);
    let runner = FakeCommandRunner::default()
        .with_git_show("HEAD:Cargo.lock", "version = 4\n")
        .with_git_show("HEAD:Cargo.toml", "")
        .with_cargo_metadata(
            r#"{
  "packages": [
    {
      "name": "serde",
      "id": "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228",
      "version": "1.0.228",
      "targets": [{"kind": ["lib"]}]
    }
  ],
  "workspace_members": [],
  "resolve": null
}"#,
        );
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("barbican.toml"),
        "[high_scrutiny]\nnew_direct_dependencies = false\n",
    )
    .expect("config should write");
    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"1\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_packages(&[("serde", "1.0.228", true)]),
    )
    .expect("lockfile should write");
    write_age_exception_policy(
        &temp_dir,
        "serde",
        "1.0.228",
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        true,
    );

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
    assert!(rendered.contains("Suggested classification: policy-violating"));
    assert!(rendered.contains("release-age exception artefact mismatches"));
    assert!(
        rendered
            .contains("reviewed release-age exception artefact checksums did not match crates.io")
    );
    assert!(
        rendered.contains(
            "serde@1.0.228 release-age exception artefact mismatch for family serde-family"
        )
    );
    assert!(
        rendered
            .contains("expected abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
    );
    assert!(
        rendered.contains("found 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    );
}

#[test]
fn assess_fails_closed_when_applicable_allowed_surface_review_record_is_missing() {
    let (exit_code, stdout, stderr) = run_allowed_surface_assess("1.2.3", false, &["build-rs"]);

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    assert!(stderr.contains(
        "FAIL allowed policy exception review record missing for native-sys@1.2.3: docs/dependency-reviews/2026-05-27-native.md"
    ));
}

#[test]
fn assess_does_not_fail_for_unrelated_missing_review_record() {
    let (exit_code, rendered, stderr) = run_allowed_surface_assess("1.2.4", false, &["build-rs"]);

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    assert!(rendered.contains("Suggested classification: elevated-risk"));
    assert!(rendered.contains("Elevated-risk signals:"));
    assert!(!rendered.contains("Allowed policy exceptions:"));
    assert!(rendered.contains("new/changed build.rs surface: native-sys@1.2.4"));
}

#[test]
fn assess_rejects_malformed_allowed_surface_state() {
    let cli = Cli::parse_from(["cargo-barbican", "assess"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default()
        .with_git_show("HEAD:Cargo.lock", "version = 4\n")
        .with_git_show("HEAD:Cargo.toml", "");
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(temp_dir.join("Cargo.toml"), "").expect("current manifest should write");
    fs::write(temp_dir.join("Cargo.lock"), "version = 4\n").expect("lockfile should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        r#"[rust]

[[rust.families]]
name = "native-family"
review_record = "docs/dependency-reviews/2026-05-27-native.md"

[rust.families.resolved]
native-sys = "1.2.3"

[rust.families.allowed_surfaces]
other = ["build-rs"]
"#,
    )
    .expect("reviewed targets should write");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    let rendered = String::from_utf8(stderr).expect("stderr should be utf8");
    assert!(rendered.starts_with("FAIL "));
    assert!(rendered.contains(
        "allowed_surfaces entry for \"other\" references a crate absent from the same resolved map"
    ));
}

#[test]
fn assess_reports_policy_violating_when_new_selection_is_too_fresh() {
    let (exit_code, rendered, stderr) = run_too_fresh_assess(&[]);

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    assert!(rendered.contains("Suggested classification: policy-violating"));
    assert!(rendered.contains("age violations: serde@1.0.228 ("));
    assert!(rendered.contains("Blocking policy findings:"));
    assert!(
        rendered
            .contains("newly selected crates.io versions below the minimum age: serde@1.0.228 (")
    );
}

#[test]
fn assess_policy_mode_elevated_risk_does_not_accept_policy_violations() {
    let (exit_code, rendered, stderr) = run_too_fresh_assess(&["--policy-mode", "elevated-risk"]);

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    assert!(rendered.contains("Suggested classification: policy-violating"));
    assert!(rendered.contains("Blocking policy findings:"));
    assert!(!rendered.contains("Elevated-risk findings accepted by --policy-mode elevated-risk"));
}

#[test]
fn assess_treats_base_manifest_absence_as_expected_for_new_workspace_manifests() {
    let cli = Cli::parse_from(["cargo-barbican", "assess"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default()
        .with_git_show("HEAD:Cargo.lock", "version = 4\n")
        .with_git_show("HEAD:Cargo.toml", "[workspace]\nmembers = []\n")
        .with_git_show_error(
            "HEAD:crates/new-member/Cargo.toml",
            "fatal: path 'crates/new-member/Cargo.toml' does not exist in 'HEAD'",
        );
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::create_dir_all(temp_dir.join("crates/new-member"))
        .expect("member directory should be creatable");
    fs::write(temp_dir.join("Cargo.toml"), "[workspace]\nmembers = []\n")
        .expect("root manifest should write");
    fs::write(temp_dir.join("Cargo.lock"), "version = 4\n").expect("lockfile should write");
    fs::write(
        temp_dir.join("crates/new-member/Cargo.toml"),
        "[dependencies]\nserde = \"1\"\n",
    )
    .expect("member manifest should write");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Suggested classification: elevated-risk"));
    assert!(
        rendered
            .contains("new direct dependencies: crates/new-member/Cargo.toml:dependencies:serde")
    );
    assert!(!rendered.contains("inspection failures"));
}

#[test]
fn assess_reports_non_missing_git_show_errors_for_base_manifests() {
    let cli = Cli::parse_from(["cargo-barbican", "assess"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default()
        .with_git_show("HEAD:Cargo.lock", "version = 4\n")
        .with_git_show_error("HEAD:Cargo.toml", "fatal: bad object HEAD");
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"1\"\n",
    )
    .expect("current manifest should write");
    fs::write(temp_dir.join("Cargo.lock"), "version = 4\n").expect("lockfile should write");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    assert!(String::from_utf8(stderr).expect("stderr should be utf8").contains(
        "FAIL unable to read HEAD:Cargo.toml from git: command exited with status 1; stderr: fatal: bad object HEAD"
    ));
}

#[test]
fn assess_escapes_control_characters_in_non_crates_io_direct_dependency_names() {
    // A hostile `Cargo.toml` can quote a `[dependencies]` table key with an
    // arbitrary TOML string, including one that decodes to a bidi-override
    // control character via `\uXXXX`. Unlike a reviewed-family name, this
    // reaches the render path unmodified (manifest dependency names are not
    // control-character-checked at parse time), so it must render escaped in
    // both the summary line and the elevated-risk finding line rather than
    // reaching the terminal raw.
    let cli = Cli::parse_from(["cargo-barbican", "assess"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default()
        .with_git_show("HEAD:Cargo.lock", "version = 4\n")
        .with_git_show("HEAD:Cargo.toml", "[dependencies]\n")
        .with_cargo_metadata(&metadata_with_packages(&[]));
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\n\"forked\\u202ename\" = { git = \"https://example.com/forked.git\" }\n",
    )
    .expect("current manifest should write");
    fs::write(temp_dir.join("Cargo.lock"), "version = 4\n").expect("current lockfile should write");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(!rendered.contains('\u{202e}'));
    assert!(rendered.contains("Cargo.toml:dependencies:forked\\x202ename (git)"));
    assert!(rendered.contains(
        "new non-crates.io direct Rust dependency specs detected: Cargo.toml:dependencies:forked\\x202ename (git)"
    ));
}
