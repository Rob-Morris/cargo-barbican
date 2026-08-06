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
