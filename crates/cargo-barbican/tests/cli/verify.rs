use super::common::*;

#[test]
fn verify_fails_when_reviewed_targets_manifest_is_absent() {
    let cli = Cli::parse_from(["cargo-barbican", "verify"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    write_toolchain_pin(&temp_dir);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(
        String::from_utf8(stdout)
            .expect("stdout should be utf8")
            .contains("Toolchain check: PASS")
    );
    assert!(
        String::from_utf8(stderr)
            .expect("stderr should be utf8")
            .contains("FAIL reviewed-targets.toml: reviewed-targets policy required for verify")
    );
    assert_eq!(*runner.build_calls.borrow(), 0);
    assert_eq!(*runner.test_calls.borrow(), 0);
}

#[test]
fn verify_runs_pin_check_before_build_and_test() {
    let cli = Cli::parse_from(["cargo-barbican", "verify"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    write_toolchain_pin(&temp_dir);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.228\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_package_records(&[
            (
                "serde",
                "1.0.228",
                Some("registry+https://github.com/rust-lang/crates.io-index"),
                Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
            ),
            (
                "serde_derive",
                "1.0.228",
                Some("registry+https://github.com/rust-lang/crates.io-index"),
                None,
            ),
        ]),
    )
    .expect("lockfile should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        r#"[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.direct]
serde = "=1.0.228"

[rust.families.resolved]
serde = { version = "1.0.228", checksum_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }
serde_derive = "1.0.228"

[rust.families.allowed_surfaces]
serde = ["build-rs"]
"#,
    )
    .expect("reviewed targets should write");
    write_review_record(&temp_dir, "docs/dependency-reviews/2026-05-27-serde.md");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Pin check: PASS"));
    assert!(rendered.contains("OK   cargo build --locked"));
    assert!(rendered.contains("OK   cargo test --locked"));
    assert!(rendered.contains("note: advisory audit is a separate gate; run cargo barbican audit"));
    assert!(rendered.contains("Verify: PASS"));
    assert!(
        rendered.find("note: advisory audit is a separate gate; run cargo barbican audit")
            < rendered.find("Verify: PASS"),
        "scope-honesty note should appear immediately before the Verify: PASS token"
    );
    assert_eq!(*runner.build_calls.borrow(), 1);
    assert_eq!(*runner.test_calls.borrow(), 1);
}

#[test]
fn verify_fails_closed_when_no_active_reviewed_families_are_configured() {
    let cli = Cli::parse_from(["cargo-barbican", "verify"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    write_toolchain_pin(&temp_dir);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.228\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_packages(&[("serde", "1.0.228", true)]),
    )
    .expect("lockfile should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        "[rust]\nfamilies = []\n",
    )
    .expect("reviewed targets should write");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(
        String::from_utf8(stdout)
            .expect("stdout should be utf8")
            .contains("Toolchain check: PASS")
    );
    assert!(String::from_utf8(stderr).expect("stderr should be utf8").contains(
        "FAIL reviewed-targets.toml: no active Rust reviewed families; verify requires at least one"
    ));
    assert_eq!(*runner.build_calls.borrow(), 0);
    assert_eq!(*runner.test_calls.borrow(), 0);
}

#[test]
fn verify_stops_before_build_on_reviewed_target_drift() {
    let cli = Cli::parse_from(["cargo-barbican", "verify"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    write_toolchain_pin(&temp_dir);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"1\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_packages(&[("serde", "1.0.227", true)]),
    )
    .expect("lockfile should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        r#"[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.direct]
serde = "=1.0.228"

[rust.families.resolved]
serde = "1.0.228"
"#,
    )
    .expect("reviewed targets should write");
    write_review_record(&temp_dir, "docs/dependency-reviews/2026-05-27-serde.md");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Pin check: FAIL"));
    assert_eq!(*runner.build_calls.borrow(), 0);
    assert_eq!(*runner.test_calls.borrow(), 0);
}

#[test]
fn verify_stops_before_build_on_an_unreviewed_scaffold_record() {
    let cli = Cli::parse_from(["cargo-barbican", "verify"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    write_toolchain_pin(&temp_dir);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.228\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_package_records(&[(
            "serde",
            "1.0.228",
            Some("registry+https://github.com/rust-lang/crates.io-index"),
            Some(checksum),
        )]),
    )
    .expect("lockfile should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        format!(
            r#"[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.direct]
serde = "=1.0.228"

[rust.families.resolved]
serde = {{ version = "1.0.228", checksum_sha256 = "{checksum}" }}
"#
        ),
    )
    .expect("reviewed targets should write");
    let record_path = temp_dir.join("docs/dependency-reviews/2026-05-27-serde.md");
    fs::create_dir_all(record_path.parent().expect("record has a parent"))
        .expect("record dir should create");
    fs::write(
        &record_path,
        format!(
            "# Dependency Review: serde 1.0.228\n\n<!-- {REVIEW_RECORD_SCAFFOLD_MARKER}: complete this scaffold. -->\n\n## Summary\n"
        ),
    )
    .expect("scaffold stub should write");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Pin check: FAIL"));
    assert!(rendered.contains("is an unreviewed scaffold"));
    assert_eq!(*runner.build_calls.borrow(), 0);
    assert_eq!(*runner.test_calls.borrow(), 0);
}

#[test]
fn verify_stops_before_build_when_a_patch_table_targets_a_reviewed_crate() {
    let cli = Cli::parse_from(["cargo-barbican", "verify"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    write_toolchain_pin(&temp_dir);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fs::write(
        temp_dir.join("Cargo.toml"),
        r#"[dependencies]
serde = "=1.0.228"

[patch.crates-io]
serde = { git = "https://attacker.example/serde" }
"#,
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_package_records(&[(
            "serde",
            "1.0.228",
            Some("registry+https://github.com/rust-lang/crates.io-index"),
            Some(checksum),
        )]),
    )
    .expect("lockfile should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        format!(
            r#"[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.direct]
serde = "=1.0.228"

[rust.families.resolved]
serde = {{ version = "1.0.228", checksum_sha256 = "{checksum}" }}
"#
        ),
    )
    .expect("reviewed targets should write");
    write_review_record(&temp_dir, "docs/dependency-reviews/2026-05-27-serde.md");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Pin check: FAIL"));
    assert!(rendered.contains("bypasses review"));
    assert_eq!(*runner.build_calls.borrow(), 0);
    assert_eq!(*runner.test_calls.borrow(), 0);
}

fn nextest_fixture() -> (TempDirGuard, FakeCommandRunner) {
    let root = fresh_temp_dir();
    write_covered_enforce_fixture(&root);
    write_toolchain_pin(&root);
    fs::write(
        root.join("barbican.toml"),
        "[verify]\ntest_runner='nextest'\nnextest_version='0.9.146'\n",
    )
    .unwrap();
    let metadata = serde_json::json!({"workspace_members":["fixture"], "workspace_default_members":["fixture"],
        "packages":[{"name":"fixture","id":"fixture","version":"0.0.0","targets":[{"kind":["lib"],"doctest":true}]}]}).to_string();
    (
        root,
        FakeCommandRunner::default().with_frozen_metadata(&metadata),
    )
}

fn verify_result(root: &Path, runner: &FakeCommandRunner) -> (ExitCode, String, String) {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit = run_cli_with_runner(
        Cli::parse_from(["cargo-barbican", "verify"]),
        root,
        &FakeCratesIoClient::default(),
        runner,
        &mut stdout,
        &mut stderr,
    )
    .unwrap();
    (
        exit,
        String::from_utf8(stdout).unwrap(),
        String::from_utf8(stderr).unwrap(),
    )
}

#[test]
fn nextest_verification_orders_steps_and_preserves_the_verdict() {
    let (root, runner) = nextest_fixture();
    let (exit, stdout, stderr) = verify_result(&root, &runner);
    assert_eq!(exit, ExitCode::SUCCESS, "{stdout}\n{stderr}");
    assert_eq!(
        *runner.verification_calls.borrow(),
        [
            "build",
            "nextest-version",
            "nextest",
            "metadata",
            "doctests"
        ]
    );
    assert_eq!(*runner.doctest_packages.borrow(), ["fixture"]);
    assert!(stdout.contains("OK   cargo nextest run --locked"));
    assert!(stdout.contains("OK   cargo test --doc --locked"));
    assert!(stdout.contains("Verify: PASS"));
    assert_eq!(*runner.test_calls.borrow(), 0);
}

#[test]
fn nextest_version_errors_stop_before_tests_with_install_guidance() {
    for result in [
        Err("no such command".to_owned()),
        Ok("invalid banner".to_owned()),
        Ok("cargo-nextest 0.9.145".to_owned()),
    ] {
        let (root, mut runner) = nextest_fixture();
        runner.nextest_version_result = result;
        let (exit, stdout, stderr) = verify_result(&root, &runner);
        assert_eq!(exit, ExitCode::from(1));
        assert!(!stdout.contains("Verify: PASS"));
        assert!(stderr.contains("cargo install --locked cargo-nextest@0.9.146"));
        assert_eq!(
            *runner.verification_calls.borrow(),
            ["build", "nextest-version"]
        );
    }
}

#[test]
fn nextest_failures_stop_at_the_failing_step() {
    for stage in ["build", "nextest", "metadata", "parse-metadata", "doctests"] {
        let (root, mut runner) = nextest_fixture();
        match stage {
            "build" => runner.cargo_build_result = Err("build failed".to_owned()),
            "nextest" => runner.nextest_result = Err("test failed".to_owned()),
            "metadata" => {
                runner.cargo_metadata_frozen_result = Err("metadata unavailable".to_owned())
            }
            "parse-metadata" => runner.cargo_metadata_frozen_result = Ok("{}".to_owned()),
            "doctests" => runner.doctest_result = Err("doc failed".to_owned()),
            _ => unreachable!(),
        }
        let (exit, stdout, stderr) = verify_result(&root, &runner);
        assert_eq!(exit, ExitCode::from(1), "{stage}");
        assert!(!stdout.contains("Verify: PASS"));
        assert!(stderr.starts_with("FAIL "));
        let calls = runner.verification_calls.borrow();
        assert_eq!(
            *calls.last().unwrap(),
            if stage == "parse-metadata" {
                "metadata"
            } else {
                stage
            }
        );
    }
}

#[test]
fn invalid_verify_policy_stops_before_preflight_in_both_entry_points() {
    for command in [
        vec!["cargo-barbican", "verify"],
        vec!["cargo-barbican", "gatehouse", "pre-release"],
    ] {
        let (root, runner) = nextest_fixture();
        fs::write(
            root.join("barbican.toml"),
            "[verify]\ntest_runner='nextest'\n",
        )
        .unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit = run_cli_with_runner(
            Cli::parse_from(command),
            &root,
            &FakeCratesIoClient::default(),
            &runner,
            &mut stdout,
            &mut stderr,
        )
        .unwrap();
        assert_eq!(exit, ExitCode::from(1));
        assert!(stdout.is_empty());
        assert_eq!(runner.rustup_active_toolchain_calls(), 0);
        assert!(runner.verification_calls.borrow().is_empty());
    }
}

#[test]
fn explicit_default_runner_never_probes_nextest() {
    let (root, runner) = nextest_fixture();
    fs::write(
        root.join("barbican.toml"),
        "[verify]\ntest_runner='cargo-test'\n",
    )
    .unwrap();
    let (exit, stdout, stderr) = verify_result(&root, &runner);
    assert_eq!(exit, ExitCode::SUCCESS, "{stdout}\n{stderr}");
    assert_eq!(*runner.verification_calls.borrow(), ["build", "cargo-test"]);
    assert!(!stdout.contains("nextest"));
}

#[test]
fn gatehouse_uses_nextest_and_reuses_the_toolchain_preflight() {
    let (root, mut runner) = nextest_fixture();
    let mut metadata: serde_json::Value =
        serde_json::from_str(&declared_crates_io_direct_metadata_json("serde", "1.0.228")).unwrap();
    let id = metadata["workspace_members"][0].clone();
    metadata["workspace_default_members"] = serde_json::json!([id]);
    metadata["packages"][0]["targets"] = serde_json::json!([{"kind":["lib"],"doctest":true}]);
    runner.cargo_metadata_frozen_result = Ok(metadata.to_string());
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit = run_cli_with_runner(
        Cli::parse_from(["cargo-barbican", "gatehouse", "pre-release"]),
        &root,
        &FakeCratesIoClient::default(),
        &runner,
        &mut stdout,
        &mut stderr,
    )
    .unwrap();
    let stdout = String::from_utf8(stdout).unwrap();
    assert_eq!(
        exit,
        ExitCode::SUCCESS,
        "{stdout}\n{}",
        String::from_utf8_lossy(&stderr)
    );
    assert_eq!(runner.rustup_active_toolchain_calls(), 1);
    assert_eq!(*runner.test_calls.borrow(), 0);
    assert!(stdout.contains("Gatehouse pre-release: PASS"));
}

#[test]
fn nextest_alias_controls_block_both_entry_points_without_affecting_default_runner() {
    for command in [
        vec!["cargo-barbican", "verify"],
        vec!["cargo-barbican", "gatehouse", "pre-release"],
    ] {
        for config_alias in [false, true] {
            let (root, mut runner) = nextest_fixture();
            if config_alias {
                fs::create_dir_all(root.join(".cargo")).unwrap();
                fs::write(
                    root.join(".cargo/config.toml"),
                    "[alias]\nnextest='redirect'\n",
                )
                .unwrap();
            } else {
                runner
                    .environment
                    .insert("CARGO_ALIAS_NEXTEST".to_owned(), "redirect".into());
            }
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let exit = run_cli_with_runner(
                Cli::parse_from(command.clone()),
                &root,
                &FakeCratesIoClient::default(),
                &runner,
                &mut stdout,
                &mut stderr,
            )
            .unwrap();
            assert_eq!(exit, ExitCode::from(1));
            assert_eq!(runner.rustup_active_toolchain_calls(), 0);
            assert!(runner.verification_calls.borrow().is_empty());
            let stderr = String::from_utf8(stderr).unwrap();
            assert!(stderr.contains(if config_alias {
                "alias.nextest"
            } else {
                "CARGO_ALIAS_NEXTEST"
            }));
        }
    }
    let (root, mut runner) = nextest_fixture();
    fs::write(
        root.join("barbican.toml"),
        "[verify]\ntest_runner='cargo-test'\n",
    )
    .unwrap();
    runner
        .environment
        .insert("CARGO_ALIAS_NEXTEST".to_owned(), "redirect".into());
    fs::create_dir_all(root.join(".cargo")).unwrap();
    fs::write(
        root.join(".cargo/config.toml"),
        "[alias]\nnextest='redirect'\n",
    )
    .unwrap();
    let (exit, stdout, stderr) = verify_result(&root, &runner);
    assert_eq!(exit, ExitCode::SUCCESS, "{stdout}\n{stderr}");
}
