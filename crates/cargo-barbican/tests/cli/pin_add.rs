use super::common::*;

#[test]
fn pin_add_scaffolds_record_and_family_then_pin_check_passes() {
    let temp_dir = fresh_temp_dir();
    write_pin_add_workspace(&temp_dir);

    let (exit_code, stdout, stderr) = run_pin_add(&temp_dir, "serde");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert!(stdout.contains("Pin add:"));
    assert!(stdout.contains("- docs/dependency-reviews/2020-06-01-serde.md: created"));
    assert!(stdout.contains(
        "- reviewed-targets.toml: appended reviewed family \"serde-2020-06-01\" for serde@1.0.228"
    ));
    assert!(
        stdout.contains("- note: exact direct manifest pin \"=1.0.228\" included in the family")
    );
    assert!(stdout.contains("Next steps:"));
    assert!(stdout.contains("Complete the review record"));
    assert!(stdout.contains("cargo barbican pin check"));

    let record = fs::read_to_string(temp_dir.join("docs/dependency-reviews/2020-06-01-serde.md"))
        .expect("scaffolded review record should exist");
    assert!(record.starts_with("# Dependency Review: serde 1.0.228\n"));
    assert!(record.contains("- Active family name: serde-2020-06-01"));
    assert!(record.contains("- Direct reviewed set: `serde` `=1.0.228`"));
    assert!(record.contains(PIN_ADD_TEST_CHECKSUM));

    let policy = fs::read_to_string(temp_dir.join("reviewed-targets.toml"))
        .expect("reviewed targets should read");
    assert!(policy.contains("name = \"serde-2020-06-01\""));
    assert!(policy.contains("review_record = \"docs/dependency-reviews/2020-06-01-serde.md\""));
    assert!(policy.contains("[rust.families.direct]\nserde = \"=1.0.228\""));
    assert!(policy.contains("[rust.families.resolved.serde]"));
    assert!(policy.contains("version = \"1.0.228\""));
    assert!(policy.contains(&format!("checksum_sha256 = \"{PIN_ADD_TEST_CHECKSUM}\"")));

    let pin_check_cli = Cli::parse_from(["cargo-barbican", "pin", "check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let pin_check_exit = run_cli_with_runner(
        pin_check_cli,
        &temp_dir,
        &client,
        &runner,
        &mut stdout,
        &mut stderr,
    )
    .expect("pin check should run");

    assert_eq!(pin_check_exit, ExitCode::SUCCESS);
    assert!(
        String::from_utf8(stdout)
            .expect("stdout should be utf8")
            .contains("Pin check: PASS")
    );
}

#[test]
fn pin_add_fails_closed_when_crate_is_absent_from_lockfile() {
    let temp_dir = fresh_temp_dir();
    write_pin_add_workspace(&temp_dir);
    let policy_before = fs::read_to_string(temp_dir.join("reviewed-targets.toml"))
        .expect("reviewed targets should read");

    let (exit_code, stdout, stderr) = run_pin_add(&temp_dir, "tokio");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    assert!(stderr.contains("FAIL pin add tokio: not present in Cargo.lock"));
    assert_eq!(
        fs::read_to_string(temp_dir.join("reviewed-targets.toml"))
            .expect("reviewed targets should read"),
        policy_before
    );
    assert!(!temp_dir.join("docs/dependency-reviews").exists());
}

#[test]
fn pin_add_requires_an_exact_spec_for_ambiguous_lockfile_versions() {
    let temp_dir = fresh_temp_dir();
    write_pin_add_workspace(&temp_dir);
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_package_records(&[
            (
                "serde",
                "1.0.228",
                Some("registry+https://github.com/rust-lang/crates.io-index"),
                Some(PIN_ADD_TEST_CHECKSUM),
            ),
            (
                "serde",
                "1.0.100",
                Some("registry+https://github.com/rust-lang/crates.io-index"),
                Some(PIN_ADD_TEST_CHECKSUM),
            ),
        ]),
    )
    .expect("lockfile should write");

    let (ambiguous_exit, ambiguous_stdout, ambiguous_stderr) = run_pin_add(&temp_dir, "serde");

    assert_eq!(ambiguous_exit, ExitCode::from(1));
    assert!(ambiguous_stdout.is_empty());
    assert!(ambiguous_stderr.contains(
        "FAIL pin add serde: multiple resolved versions in Cargo.lock [\"1.0.228\", \"1.0.100\"]"
    ));
    assert!(!temp_dir.join("docs/dependency-reviews").exists());

    let (exact_exit, exact_stdout, exact_stderr) = run_pin_add(&temp_dir, "serde@1.0.100");

    assert_eq!(exact_exit, ExitCode::SUCCESS);
    assert!(exact_stderr.is_empty());
    assert!(exact_stdout.contains(
        "- reviewed-targets.toml: appended reviewed family \"serde-2020-06-01\" for serde@1.0.100"
    ));
    assert!(exact_stdout.contains(
        "- note: serde is a direct dependency but its manifest requirement is not uniformly the exact pin \"=1.0.100\"; no direct entry scaffolded"
    ));
    let policy = fs::read_to_string(temp_dir.join("reviewed-targets.toml"))
        .expect("reviewed targets should read");
    assert!(!policy.contains("[rust.families.direct]"));
}

#[test]
fn pin_add_scaffolds_no_direct_entry_for_transitive_crates() {
    let temp_dir = fresh_temp_dir();
    write_pin_add_workspace(&temp_dir);
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_package_records(&[
            (
                "serde",
                "1.0.228",
                Some("registry+https://github.com/rust-lang/crates.io-index"),
                Some(PIN_ADD_TEST_CHECKSUM),
            ),
            (
                "serde_derive",
                "1.0.228",
                Some("registry+https://github.com/rust-lang/crates.io-index"),
                Some(PIN_ADD_TEST_CHECKSUM),
            ),
        ]),
    )
    .expect("lockfile should write");

    let (exit_code, stdout, stderr) = run_pin_add(&temp_dir, "serde_derive");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert!(!stdout.contains("direct"));
    let policy = fs::read_to_string(temp_dir.join("reviewed-targets.toml"))
        .expect("reviewed targets should read");
    assert!(!policy.contains("[rust.families.direct]"));
    let record =
        fs::read_to_string(temp_dir.join("docs/dependency-reviews/2020-06-01-serde_derive.md"))
            .expect("scaffolded review record should exist");
    assert!(record.contains("- Direct reviewed set:\n"));
}

#[test]
fn pin_add_fails_closed_when_requested_version_is_not_resolved() {
    let temp_dir = fresh_temp_dir();
    write_pin_add_workspace(&temp_dir);

    let (exit_code, stdout, stderr) = run_pin_add(&temp_dir, "serde@9.9.9");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    assert!(
        stderr.contains("FAIL pin add serde@9.9.9: Cargo.lock resolves serde to [\"1.0.228\"]")
    );
    assert!(!temp_dir.join("docs/dependency-reviews").exists());
}

#[test]
fn pin_add_fails_closed_without_reviewed_targets_policy() {
    let temp_dir = fresh_temp_dir();
    write_pin_add_workspace(&temp_dir);
    fs::remove_file(temp_dir.join("reviewed-targets.toml"))
        .expect("reviewed targets should remove");

    let (exit_code, stdout, stderr) = run_pin_add(&temp_dir, "serde");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    assert!(stderr.contains(
        "FAIL pin add: reviewed-targets.toml not found; run `cargo barbican policy init` first"
    ));
    assert!(!temp_dir.join("docs/dependency-reviews").exists());
}

#[cfg(unix)]
#[test]
fn pin_add_refuses_symlinked_reviewed_targets_without_reading_target() {
    use std::os::unix::fs::symlink;

    let temp_dir = fresh_temp_dir();
    write_pin_add_workspace(&temp_dir);
    fs::remove_file(temp_dir.join("reviewed-targets.toml"))
        .expect("reviewed targets should remove");
    fs::write(temp_dir.join("secret.env"), "SECRET_TOKEN=do-not-print\n")
        .expect("secret target should write");
    symlink(
        temp_dir.join("secret.env"),
        temp_dir.join("reviewed-targets.toml"),
    )
    .expect("reviewed-targets.toml symlink should create");

    let cli = Cli::parse_from(["cargo-barbican", "pin", "add", "serde"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
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
    assert!(stdout.is_empty());
    let rendered_error = String::from_utf8(stderr).expect("stderr should be utf8");
    assert!(rendered_error.starts_with("FAIL "));
    assert!(rendered_error.contains("reviewed-targets.toml is a symlink"));
    assert!(!rendered_error.contains("SECRET_TOKEN"));
    assert!(!temp_dir.join("docs/dependency-reviews").exists());
    assert_eq!(
        fs::read_to_string(temp_dir.join("secret.env")).expect("secret target should still read"),
        "SECRET_TOKEN=do-not-print\n",
        "the symlink target must not be mutated by a refused write"
    );
    assert!(
        fs::symlink_metadata(temp_dir.join("reviewed-targets.toml"))
            .expect("reviewed-targets.toml symlink should still exist")
            .file_type()
            .is_symlink()
    );
}

#[cfg(unix)]
#[test]
fn pin_add_refuses_symlinked_review_directory_without_mutation() {
    use std::os::unix::fs::symlink;

    let temp_dir = fresh_temp_dir();
    write_pin_add_workspace(&temp_dir);
    let policy_before = fs::read_to_string(temp_dir.join("reviewed-targets.toml"))
        .expect("reviewed targets should read");
    fs::create_dir_all(temp_dir.join("outside-reviews"))
        .expect("outside review directory should create");
    fs::write(temp_dir.join("outside-reviews/canary.txt"), "untouched\n")
        .expect("canary file should write");
    fs::create_dir_all(temp_dir.join("docs")).expect("docs directory should create");
    symlink(
        temp_dir.join("outside-reviews"),
        temp_dir.join("docs/dependency-reviews"),
    )
    .expect("review directory symlink should create");

    let (exit_code, stdout, stderr) = run_pin_add(&temp_dir, "serde");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    assert!(stderr.starts_with("FAIL "));
    assert_eq!(
        fs::read_to_string(temp_dir.join("reviewed-targets.toml"))
            .expect("reviewed targets should read"),
        policy_before,
        "reviewed-targets.toml must not be mutated when the review directory is blocked"
    );
    assert_eq!(
        fs::read_to_string(temp_dir.join("outside-reviews/canary.txt"))
            .expect("canary file should still read"),
        "untouched\n"
    );
    assert_eq!(
        fs::read_dir(temp_dir.join("outside-reviews"))
            .expect("outside review directory should still read")
            .count(),
        1,
        "no review record should have been written through the symlink"
    );
    assert!(
        fs::symlink_metadata(temp_dir.join("docs/dependency-reviews"))
            .expect("review directory symlink should still exist")
            .file_type()
            .is_symlink()
    );
}

#[test]
fn pin_add_fails_closed_when_crate_is_already_covered_by_a_family() {
    let temp_dir = fresh_temp_dir();
    write_pin_add_workspace(&temp_dir);
    let policy = format!(
        r#"[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.resolved]
serde = {{ version = "1.0.228", checksum_sha256 = "{PIN_ADD_TEST_CHECKSUM}" }}
"#
    );
    fs::write(temp_dir.join("reviewed-targets.toml"), &policy)
        .expect("reviewed targets should write");

    let (exit_code, stdout, stderr) = run_pin_add(&temp_dir, "serde");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    assert!(stderr.contains(
        "FAIL pin add serde: crate is already covered by reviewed family \"serde-family\""
    ));
    assert_eq!(
        fs::read_to_string(temp_dir.join("reviewed-targets.toml"))
            .expect("reviewed targets should read"),
        policy
    );
    assert!(!temp_dir.join("docs/dependency-reviews").exists());
}

#[test]
fn pin_add_fails_closed_when_the_scaffold_family_name_already_exists() {
    let temp_dir = fresh_temp_dir();
    write_pin_add_workspace(&temp_dir);
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        r#"[rust]

[[rust.families]]
name = "serde-2020-06-01"
review_record = "docs/dependency-reviews/2020-06-01-other.md"

[rust.families.resolved]
other-crate = "0.1.0"
"#,
    )
    .expect("reviewed targets should write");

    let (exit_code, stdout, stderr) = run_pin_add(&temp_dir, "serde");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    assert!(
        stderr.contains("FAIL pin add serde: reviewed family \"serde-2020-06-01\" already exists")
    );
    assert!(!temp_dir.join("docs/dependency-reviews").exists());
}

#[test]
fn pin_add_fails_closed_when_the_review_record_path_already_exists() {
    let temp_dir = fresh_temp_dir();
    write_pin_add_workspace(&temp_dir);
    let policy_before = fs::read_to_string(temp_dir.join("reviewed-targets.toml"))
        .expect("reviewed targets should read");
    write_review_record(&temp_dir, "docs/dependency-reviews/2020-06-01-serde.md");

    let (exit_code, stdout, stderr) = run_pin_add(&temp_dir, "serde");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    assert!(stderr.contains(
        "FAIL pin add serde: review record path already exists at docs/dependency-reviews/2020-06-01-serde.md"
    ));
    assert_eq!(
        fs::read_to_string(temp_dir.join("reviewed-targets.toml"))
            .expect("reviewed targets should read"),
        policy_before
    );
    assert_eq!(
        fs::read_to_string(temp_dir.join("docs/dependency-reviews/2020-06-01-serde.md"))
            .expect("pre-existing record should read"),
        "# Dependency Review\n"
    );
}

#[cfg(unix)]
#[test]
fn pin_add_removes_review_record_when_policy_append_fails() {
    let temp_dir = fresh_temp_dir();
    write_pin_add_workspace(&temp_dir);
    let policy_path = temp_dir.join("reviewed-targets.toml");
    let record_path = temp_dir.join("docs/dependency-reviews/2020-06-01-serde.md");
    let original_policy =
        fs::read_to_string(&policy_path).expect("reviewed targets should read before chmod");

    // The atomic policy write creates a temp file next to reviewed-targets.toml
    // before renaming over it, so chmod on the file itself no longer blocks
    // the write (rename only needs directory write permission). Pre-create
    // the review-record directory (which must stay writable) and instead
    // lock down the repo root so the temp-file create in the same directory
    // as reviewed-targets.toml fails.
    fs::create_dir_all(
        record_path
            .parent()
            .expect("record path should have a parent"),
    )
    .expect("review record directory should pre-create");

    let mut read_only = fs::metadata(&temp_dir)
        .expect("repo root metadata should read")
        .permissions();
    read_only.set_mode(0o555);
    fs::set_permissions(&temp_dir, read_only).expect("repo root should become readonly");

    let cli = Cli::parse_from(["cargo-barbican", "pin", "add", "serde"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let result = run_cli_with_runner_at(
        cli,
        &temp_dir,
        &client,
        &runner,
        fixed_now(),
        &mut stdout,
        &mut stderr,
    );

    let mut writable = fs::metadata(&temp_dir)
        .expect("repo root metadata should read after failure")
        .permissions();
    writable.set_mode(0o755);
    fs::set_permissions(&temp_dir, writable).expect("repo root should become writable");

    let exit_code = result.expect("command should run");
    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    let rendered = String::from_utf8(stderr).expect("stderr should be utf8");
    assert!(rendered.starts_with("FAIL "));
    assert!(rendered.contains("unable to write reviewed-targets.toml after creating review record docs/dependency-reviews/2020-06-01-serde.md"));
    assert!(
        rendered
            .contains("removed orphaned review record docs/dependency-reviews/2020-06-01-serde.md")
    );
    assert!(!record_path.exists());
    assert_eq!(
        fs::read_to_string(&policy_path).expect("reviewed targets should still read"),
        original_policy
    );
}
