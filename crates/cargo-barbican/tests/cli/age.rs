use super::common::*;

#[test]
fn age_reports_success_for_old_enough_versions() {
    let cli = Cli::parse_from(["cargo-barbican", "age", "serde@1.0.228"]);
    let client =
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2020-05-01T00:00:00Z", false);
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
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
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("OK   serde@1.0.228: published 2020-05-01T00:00:00Z ("));
    assert!(rendered.contains(" old)\n"));
    assert!(stderr.is_empty());
}

#[test]
fn age_uses_barbican_config_minimum_days() {
    let cli = Cli::parse_from(["cargo-barbican", "age", "serde@1.0.228"]);
    let client =
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2020-05-22T00:00:00Z", false);
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("barbican.toml"),
        "[release_age]\nminimum_days = 30\n\n[high_scrutiny]\n\n[delegates]\n",
    )
    .expect("config should write");

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
    assert!(
        String::from_utf8(stderr)
            .expect("stderr should be utf8")
            .contains("below the 30-day minimum")
    );
}

#[test]
fn age_allows_command_line_override_of_minimum_days() {
    let cli = Cli::parse_from([
        "cargo-barbican",
        "age",
        "--min-age-days",
        "3",
        "serde@1.0.228",
    ]);
    let client =
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2020-05-20T00:00:00Z", false);
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("barbican.toml"),
        "[release_age]\nminimum_days = 30\n\n[high_scrutiny]\n\n[delegates]\n",
    )
    .expect("config should write");

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
    assert!(
        String::from_utf8(stdout)
            .expect("stdout should be utf8")
            .contains("OK   serde@1.0.228")
    );
}

#[test]
fn age_preserves_per_spec_failures() {
    let cli = Cli::parse_from(["cargo-barbican", "age", "serde@1.0.228", "bad"]);
    let client =
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2020-05-01T00:00:00Z", false);
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(
        String::from_utf8(stdout)
            .expect("stdout should be utf8")
            .contains("OK   serde@1.0.228")
    );
    assert!(
        String::from_utf8(stderr)
            .expect("stderr should be utf8")
            .contains("FAIL bad: Expected exact crate@version spec, got: \"bad\"")
    );
}

#[test]
fn age_allows_too_fresh_release_with_reviewed_age_exception() {
    let cli = Cli::parse_from(["cargo-barbican", "age", "serde@1.0.228"]);
    let client =
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2020-05-26T00:00:00Z", false);
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

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
    assert!(rendered.contains("ALLOW serde@1.0.228"));
    assert!(rendered.contains(
        "release-age exception allowed by reviewed family serde-family (docs/dependency-reviews/2026-05-27-serde.md)"
    ));
}

#[test]
fn age_does_not_honour_age_exception_with_missing_review_record() {
    let cli = Cli::parse_from(["cargo-barbican", "age", "serde@1.0.228"]);
    let client =
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2020-05-26T00:00:00Z", false);
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

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
    let rendered = String::from_utf8(stderr).expect("stderr should be utf8");
    assert_eq!(
        rendered,
        "FAIL allowed release-age exception review record missing for serde@1.0.228: docs/dependency-reviews/2026-05-27-serde.md\n"
    );
}

#[test]
fn age_ignores_missing_age_exception_record_when_release_is_old_enough() {
    let cli = Cli::parse_from(["cargo-barbican", "age", "serde@1.0.228"]);
    let client =
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2020-05-20T00:00:00Z", false);
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

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

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("OK   serde@1.0.228"));
    assert!(!rendered.contains("review record missing"));
}

#[test]
fn age_blocks_reviewed_age_exception_checksum_mismatch() {
    let cli = Cli::parse_from(["cargo-barbican", "age", "serde@1.0.228"]);
    let client =
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2020-05-26T00:00:00Z", false);
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

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
    assert!(stdout.is_empty());
    let rendered = String::from_utf8(stderr).expect("stderr should be utf8");
    assert!(rendered.contains("release-age exception artefact mismatch"));
    assert!(rendered.contains(
        "expected sha256 abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    ));
    assert!(
        rendered.contains("found 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    );
}

#[test]
fn age_rejects_malformed_age_exception_state() {
    let cli = Cli::parse_from(["cargo-barbican", "age", "serde@1.0.228"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        r#"[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.resolved]
serde = "1.0.228"

[rust.families.allowed_age_exceptions]
serde = "1.0.228"
"#,
    )
    .expect("reviewed targets should write");

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
    let rendered = String::from_utf8(stderr).expect("stderr should be utf8");
    assert!(rendered.starts_with("FAIL "));
    assert!(rendered.contains(
        "allowed_age_exceptions entry for \"serde\" requires the resolved target to carry checksum_sha256"
    ));
}

#[test]
fn age_smoke_tests_the_ureq_client_against_a_local_http_server() {
    // Asserts on a fixed calendar date's age relative to *real* elapsed time,
    // so this genuinely needs the ambient wall clock rather than the shared
    // default's injected `fixed_now()`.
    let cli = Cli::parse_from(["cargo-barbican", "age", "serde@1.0.228"]);
    let Some((base_url, requests, handle)) = spawn_http_stub(
        "HTTP/1.1 200 OK",
        r#"{"version":{"num":"1.0.228","checksum":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","created_at":"2026-05-01T00:00:00Z","yanked":false}}"#,
    ) else {
        eprintln!("[SKIP] no loopback bind available - skipping HTTP smoke test");
        return;
    };
    let client = UreqCratesIoClient::new(base_url);
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code =
        run_cli_with_ambient_clock(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
            .expect("command should run");

    handle.join().expect("stub server should exit cleanly");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    let request = requests
        .recv()
        .expect("stub server should capture the request");
    assert!(request.contains("GET /api/v1/crates/serde/1.0.228 HTTP/1.1"));
    let user_agent = request
        .lines()
        .find_map(|line| {
            line.split_once(':')
                .filter(|(name, _)| name.eq_ignore_ascii_case("User-Agent"))
                .map(|(_, value)| value.trim())
        })
        .expect("stub request should include a User-Agent header");
    assert!(user_agent.contains("cargo-barbican/"));
    assert!(
        String::from_utf8(stdout)
            .expect("stdout should be utf8")
            .contains("OK   serde@1.0.228: published 2026-05-01T00:00:00Z")
    );
}

#[test]
fn age_reports_http_statuses_from_the_ureq_client() {
    let cli = Cli::parse_from(["cargo-barbican", "age", "serde@1.0.228"]);
    let Some((base_url, _requests, handle)) = spawn_http_stub("HTTP/1.1 404 Not Found", "{}")
    else {
        eprintln!("[SKIP] no loopback bind available - skipping HTTP smoke test");
        return;
    };
    let client = UreqCratesIoClient::new(base_url);
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    handle.join().expect("stub server should exit cleanly");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    assert!(
        String::from_utf8(stderr)
            .expect("stderr should be utf8")
            .contains("FAIL serde@1.0.228: crates.io returned HTTP 404 for version metadata")
    );
}

#[test]
fn age_reports_client_failures_to_stderr() {
    let cli = Cli::parse_from(["cargo-barbican", "age", "serde@1.0.228"]);
    let client = FakeCratesIoClient::default().with_error(
        "serde@1.0.228",
        CratesIoClientError::HttpStatus { status_code: 404 },
    );
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    assert!(
        String::from_utf8(stderr)
            .expect("stderr should be utf8")
            .contains("FAIL serde@1.0.228: crates.io returned HTTP 404 for version metadata")
    );
}
