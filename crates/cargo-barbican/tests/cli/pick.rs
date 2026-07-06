use super::common::*;

#[test]
fn pick_smoke_tests_fetch_versions_against_a_local_http_server() {
    // `pick` is the only command that calls `fetch_versions` rather than
    // `fetch_release`, so this is what exercises that endpoint's URL
    // (no version segment) and multi-entry response body over a real
    // socket, rather than through `FakeCratesIoClient`.
    let cli = Cli::parse_from(["cargo-barbican", "pick", "--min-age-days", "0", "serde@^1"]);
    let Some((base_url, requests, handle)) = require_loopback_bind(spawn_http_stub_sequence(&[(
        "HTTP/1.1 200 OK",
        br#"{"versions":[{"num":"1.5.0","checksum":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","created_at":"2000-01-01T00:00:00Z","yanked":false}]}"#,
    )])) else {
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

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    let request = requests
        .recv()
        .expect("stub server should capture the request");
    assert!(request.contains("GET /api/v1/crates/serde HTTP/1.1"));
    assert!(
        String::from_utf8(stdout)
            .expect("stdout should be utf8")
            .contains("Pick serde@1.5.0")
    );
}

#[test]
fn pick_selects_newest_policy_compliant_version() {
    let cli = Cli::parse_from(["cargo-barbican", "pick", "serde@^1"]);
    let client = FakeCratesIoClient::default().with_versions(
        "serde",
        &[
            ("2.0.0", "2020-05-01T00:00:00Z", false),
            ("1.7.0", "2020-05-30T00:00:00Z", false),
            ("1.6.0-alpha.1", "2020-05-01T00:00:00Z", false),
            ("1.5.0", "2020-05-01T00:00:00Z", false),
            ("1.4.0", "2020-05-01T00:00:00Z", true),
        ],
    );
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
    assert!(stderr.is_empty());
    assert_eq!(client.recorded_version_fetches(), vec!["serde".to_owned()]);
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Pick serde@1.5.0"));
    assert!(rendered.contains("selected: serde@1.5.0"));
    assert!(rendered.contains("release age: OK   serde@1.5.0"));
    assert!(rendered.contains("2.0.0: does not match requirement"));
    assert!(rendered.contains("1.6.0-alpha.1: pre-release"));
    assert!(rendered.contains("1.7.0: too fresh"));
    assert!(rendered.contains("1.4.0: yanked"));
}

#[test]
fn pick_fails_closed_when_no_version_satisfies_policy() {
    let cli = Cli::parse_from(["cargo-barbican", "pick", "serde@^1"]);
    let client = FakeCratesIoClient::default()
        .with_versions("serde", &[("1.0.0", "2020-05-30T00:00:00Z", false)]);
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

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    assert!(
        String::from_utf8(stderr)
            .expect("stderr should be utf8")
            .contains("FAIL serde@^1: no version satisfied requirement and policy")
    );
}

#[test]
fn pick_reports_invalid_specs_before_fetching_versions() {
    let cli = Cli::parse_from(["cargo-barbican", "pick", "bad/name@^1"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    assert!(client.recorded_version_fetches().is_empty());
    assert!(
        String::from_utf8(stderr)
            .expect("stderr should be utf8")
            .contains("FAIL bad/name@^1")
    );
}

#[test]
fn pick_reports_version_fetch_failures() {
    let cli = Cli::parse_from(["cargo-barbican", "pick", "serde"]);
    let client = FakeCratesIoClient::default().with_versions_error(
        "serde",
        CratesIoClientError::Transport {
            reason: "network blocked".to_owned(),
        },
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
            .contains("FAIL serde: unable to reach crates.io (network blocked)")
    );
}

#[test]
fn pick_escapes_untrusted_version_strings() {
    let cli = Cli::parse_from(["cargo-barbican", "pick", "serde@^1"]);
    let raw_version = "1.0.0\u{1b}[2K";
    let client = FakeCratesIoClient::default().with_raw_versions(
        "serde",
        vec![fake_raw_version_info(
            raw_version,
            "2020-05-01T00:00:00Z",
            false,
        )],
    );
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

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    let rendered = String::from_utf8(stderr).expect("stderr should be utf8");
    assert!(!rendered.contains('\u{1b}'));
    assert!(rendered.contains("\\x1b"));
    assert!(rendered.contains("1.0.0\\x1b[2K"));
    assert!(rendered.contains("invalid semver"));
}
