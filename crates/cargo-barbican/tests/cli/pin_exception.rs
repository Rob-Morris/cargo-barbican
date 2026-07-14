use super::common::*;

fn run_pin_exception(temp_dir: &Path, args: &[&str]) -> (ExitCode, String, String) {
    let mut cli_args = vec!["cargo-barbican", "pin", "exception"];
    cli_args.extend_from_slice(args);
    let cli = Cli::parse_from(cli_args);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner_at(
        cli,
        temp_dir,
        &client,
        &runner,
        fixed_now(),
        &mut stdout,
        &mut stderr,
    )
    .expect("command should run");

    (
        exit_code,
        String::from_utf8(stdout).expect("stdout should be utf8"),
        String::from_utf8(stderr).expect("stderr should be utf8"),
    )
}

#[test]
fn pin_exception_scaffolds_a_bounded_exception_then_pin_check_and_audit_pass() {
    let temp_dir = fresh_temp_dir();
    write_pin_add_workspace(&temp_dir);

    let (exit_code, stdout, stderr) = run_pin_exception(&temp_dir, &["serde", "RUSTSEC-2026-0001"]);

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert!(stdout.contains("Pin exception:"));
    assert!(stdout.contains("- docs/dependency-reviews/2020-06-01-serde.md: created"));
    assert!(stdout.contains(
        "- reviewed-targets.toml: appended reviewed family \"serde-2020-06-01\" accepting RUSTSEC-2026-0001 for serde@1.0.228"
    ));
    assert!(
        stdout.contains("- review by 2020-07-01: audit fails these exceptions once past this date")
    );
    assert!(stdout.contains("the scaffold is not a completed review"));
    assert!(stdout.contains("Prefer remediation"));

    let record = fs::read_to_string(temp_dir.join("docs/dependency-reviews/2020-06-01-serde.md"))
        .expect("scaffolded review record should exist");
    assert!(record.contains(
        "- Allowed advisory exceptions: `RUSTSEC-2026-0001` (review by 2020-07-01)"
    ));
    assert!(record.contains("accepted under bounded reviewed exceptions"));

    let policy = fs::read_to_string(temp_dir.join("reviewed-targets.toml"))
        .expect("reviewed targets should read");
    assert!(policy.contains("[[rust.families.allowed_advisories.serde]]"));
    assert!(policy.contains("id = \"RUSTSEC-2026-0001\""));
    assert!(policy.contains("review_by = \"2020-07-01\""));

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

    let audit_cli = Cli::parse_from(["cargo-barbican", "audit"]);
    let audit_runner =
        FakeCommandRunner::default().with_cargo_deny_json(&cargo_deny_advisory_jsonl());
    let mut audit_stdout = Vec::new();
    let mut audit_stderr = Vec::new();
    let audit_exit = run_cli_with_runner_at(
        audit_cli,
        &temp_dir,
        &client,
        &audit_runner,
        fixed_now(),
        &mut audit_stdout,
        &mut audit_stderr,
    )
    .expect("audit should run");

    assert_eq!(audit_exit, ExitCode::SUCCESS);
    let audit_rendered = String::from_utf8(audit_stdout).expect("stdout should be utf8");
    assert!(audit_rendered.contains("Audit: PASS"));
    assert!(audit_rendered.contains("serde@1.0.228 RUSTSEC-2026-0001 accepted by reviewed family"));
}

#[test]
fn pin_exception_accepts_multiple_advisories_with_an_explicit_review_by() {
    let temp_dir = fresh_temp_dir();
    write_pin_add_workspace(&temp_dir);

    let (exit_code, stdout, stderr) = run_pin_exception(
        &temp_dir,
        &[
            "serde",
            "RUSTSEC-2026-0001",
            "RUSTSEC-2026-0002",
            "--review-by",
            "2020-09-30",
        ],
    );

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert!(stdout.contains("accepting RUSTSEC-2026-0001, RUSTSEC-2026-0002 for serde@1.0.228"));

    let policy = fs::read_to_string(temp_dir.join("reviewed-targets.toml"))
        .expect("reviewed targets should read");
    assert!(policy.contains("id = \"RUSTSEC-2026-0001\""));
    assert!(policy.contains("id = \"RUSTSEC-2026-0002\""));
    assert_eq!(policy.matches("review_by = \"2020-09-30\"").count(), 2);
}

#[test]
fn pin_exception_rejects_invalid_advisory_ids() {
    let temp_dir = fresh_temp_dir();
    write_pin_add_workspace(&temp_dir);
    let policy_before = fs::read_to_string(temp_dir.join("reviewed-targets.toml"))
        .expect("reviewed targets should read");

    let (exit_code, stdout, stderr) = run_pin_exception(&temp_dir, &["serde", "CVE-2026-1234"]);

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    assert!(stderr.contains(
        "FAIL pin exception CVE-2026-1234: expected RustSec advisory ID in RUSTSEC-YYYY-NNNN form"
    ));
    assert_eq!(
        fs::read_to_string(temp_dir.join("reviewed-targets.toml"))
            .expect("reviewed targets should read"),
        policy_before
    );
    assert!(!temp_dir.join("docs/dependency-reviews").exists());
}

#[test]
fn pin_exception_rejects_invalid_review_by_dates() {
    let temp_dir = fresh_temp_dir();
    write_pin_add_workspace(&temp_dir);

    let (exit_code, stdout, stderr) = run_pin_exception(
        &temp_dir,
        &["serde", "RUSTSEC-2026-0001", "--review-by", "next-month"],
    );

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    assert!(stderr.contains(
        "FAIL pin exception --review-by next-month: expected ISO date in YYYY-MM-DD form"
    ));
}

#[test]
fn pin_exception_fails_closed_without_a_reviewed_targets_manifest() {
    let temp_dir = fresh_temp_dir();
    write_pin_add_workspace(&temp_dir);
    fs::remove_file(temp_dir.join("reviewed-targets.toml")).expect("policy should remove");

    let (exit_code, stdout, stderr) = run_pin_exception(&temp_dir, &["serde", "RUSTSEC-2026-0001"]);

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    assert!(stderr.contains(
        "FAIL pin exception: reviewed-targets.toml not found; run `cargo barbican policy init` first"
    ));
}

#[test]
fn pin_exception_requires_a_lockfile_checksum() {
    let temp_dir = fresh_temp_dir();
    write_pin_add_workspace(&temp_dir);
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_package_records(&[("serde", "1.0.228", None, None)]),
    )
    .expect("lockfile should write");

    let (exit_code, stdout, stderr) = run_pin_exception(&temp_dir, &["serde", "RUSTSEC-2026-0001"]);

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    assert!(stderr.contains(
        "FAIL pin exception serde@1.0.228: Cargo.lock records no crates.io checksum; advisory exceptions require a checksum-bound resolved target"
    ));
    assert!(!temp_dir.join("docs/dependency-reviews").exists());
}

#[test]
fn pin_exception_prints_a_paste_ready_fragment_for_covered_families() {
    let temp_dir = fresh_temp_dir();
    write_pin_add_workspace(&temp_dir);
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        format!(
            r#"[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.resolved]
serde = {{ version = "1.0.228", checksum_sha256 = "{PIN_ADD_TEST_CHECKSUM}" }}
"#
        ),
    )
    .expect("policy should write");
    let policy_before = fs::read_to_string(temp_dir.join("reviewed-targets.toml"))
        .expect("reviewed targets should read");

    let (exit_code, stdout, stderr) = run_pin_exception(&temp_dir, &["serde", "RUSTSEC-2026-0001"]);

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    assert!(stderr.contains(
        "FAIL pin exception serde: crate is already covered by reviewed family \"serde-family\"; refusing to rewrite an existing family block automatically"
    ));
    assert!(stderr.contains("[rust.families.allowed_advisories]"));
    assert!(stderr
        .contains("serde = [{ id = \"RUSTSEC-2026-0001\", review_by = \"2020-07-01\" }]"));
    assert!(stderr.contains("docs/dependency-reviews/2026-05-27-serde.md"));
    assert_eq!(
        fs::read_to_string(temp_dir.join("reviewed-targets.toml"))
            .expect("reviewed targets should read"),
        policy_before
    );
    assert!(!temp_dir.join("docs/dependency-reviews").exists());
}

#[test]
fn pin_exception_reports_already_allowed_advisories() {
    let temp_dir = fresh_temp_dir();
    write_pin_add_workspace(&temp_dir);
    write_advisory_exception_policy(
        &temp_dir,
        "serde",
        "1.0.228",
        PIN_ADD_TEST_CHECKSUM,
        "2026-09-21",
        true,
    );

    let (exit_code, stdout, stderr) = run_pin_exception(&temp_dir, &["serde", "RUSTSEC-2026-0001"]);

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    assert!(stderr.contains("RUSTSEC-2026-0001 is already allowed by reviewed family"));
}
