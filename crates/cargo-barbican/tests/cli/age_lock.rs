use super::common::*;

#[test]
fn age_lock_reports_when_no_new_registry_packages_were_selected() {
    let cli = Cli::parse_from(["cargo-barbican", "age-lock"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default().with_git_show(
        "HEAD:Cargo.lock",
        &lockfile_with_packages(&[("serde", "1.0.227", true)]),
    );
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_packages(&[("serde", "1.0.227", true)]),
    )
    .expect("current lockfile should write");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert!(
        String::from_utf8(stdout)
            .expect("stdout should be utf8")
            .contains(
                "OK   no newly selected crates.io packages detected in Cargo.lock relative to HEAD"
            )
    );
}

#[test]
fn age_lock_checks_added_registry_packages_against_release_age() {
    // Publish date sits 6 days before `fixed_now()` (2020-06-01), so the added
    // package is too fresh against the injected clock. This also guards the
    // age-lock call site's clock wiring: a regression that ignored the threaded
    // `now` and read the wall clock would see a years-old release and pass.
    let cli = Cli::parse_from(["cargo-barbican", "age-lock"]);
    let client =
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2020-05-26T00:00:00Z", false);
    let runner = FakeCommandRunner::default().with_git_show(
        "HEAD:Cargo.lock",
        &lockfile_with_packages(&[("serde", "1.0.227", true)]),
    );
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_packages(&[("serde", "1.0.228", true)]),
    )
    .expect("current lockfile should write");

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
            .contains("FAIL serde@1.0.228: published 2020-05-26T00:00:00Z")
    );
}

#[test]
fn age_lock_checks_added_registry_packages_against_non_git_base_lockfile() {
    let cli = Cli::parse_from([
        "cargo-barbican",
        "age-lock",
        "--base-lockfile",
        "baseline/Cargo.lock",
    ]);
    let client =
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2999-01-01T00:00:00Z", false);
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let baseline_dir = temp_dir.join("baseline");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::create_dir_all(&baseline_dir).expect("baseline directory should be creatable");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_packages(&[("serde", "1.0.228", true)]),
    )
    .expect("current lockfile should write");
    fs::write(
        baseline_dir.join("Cargo.lock"),
        lockfile_with_packages(&[("serde", "1.0.227", true)]),
    )
    .expect("baseline lockfile should write");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    assert!(
        String::from_utf8(stderr)
            .expect("stderr should be utf8")
            .contains("FAIL serde@1.0.228: published 2999-01-01T00:00:00Z")
    );
}

#[test]
fn age_lock_reports_missing_non_git_base_lockfile() {
    let cli = Cli::parse_from([
        "cargo-barbican",
        "age-lock",
        "--base-lockfile",
        "missing/Cargo.lock",
    ]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

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
fn age_lock_checks_against_an_explicit_non_head_base_ref() {
    // The default base ref is `HEAD`; this pins that `--base-ref` actually
    // threads a non-HEAD value through to the `git_show` keying rather than
    // the command silently comparing against `HEAD` regardless.
    let cli = Cli::parse_from(["cargo-barbican", "age-lock", "--base-ref", "v1.2.3"]);
    let client =
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2999-01-01T00:00:00Z", false);
    let runner = FakeCommandRunner::default().with_git_show(
        "v1.2.3:Cargo.lock",
        &lockfile_with_packages(&[("serde", "1.0.227", true)]),
    );
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_packages(&[("serde", "1.0.228", true)]),
    )
    .expect("current lockfile should write");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    assert!(
        String::from_utf8(stderr)
            .expect("stderr should be utf8")
            .contains("FAIL serde@1.0.228: published 2999-01-01T00:00:00Z")
    );
}

#[test]
fn age_lock_accepts_a_custom_lockfile_path() {
    let cli = Cli::parse_from([
        "cargo-barbican",
        "age-lock",
        "--lockfile",
        "workspace/Cargo.lock",
    ]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default().with_git_show(
        "HEAD:workspace/Cargo.lock",
        &lockfile_with_packages(&[("serde", "1.0.228", true)]),
    );
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::create_dir_all(temp_dir.join("workspace")).expect("workspace dir should be creatable");
    fs::write(
        temp_dir.join("workspace/Cargo.lock"),
        lockfile_with_packages(&[("serde", "1.0.228", true)]),
    )
    .expect("current lockfile should write");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert!(
        String::from_utf8(stdout)
            .expect("stdout should be utf8")
            .contains("OK   no newly selected crates.io packages detected in workspace/Cargo.lock")
    );
}

#[test]
fn age_lock_reports_missing_custom_lockfile_path() {
    let cli = Cli::parse_from([
        "cargo-barbican",
        "age-lock",
        "--lockfile",
        "workspace/Cargo.lock",
    ]);
    let client = FakeCratesIoClient::default();
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
            .contains("FAIL workspace/Cargo.lock: lockfile not found")
    );
}
