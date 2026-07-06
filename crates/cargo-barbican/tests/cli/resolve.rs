use super::common::*;

#[test]
fn resolve_generates_current_manifest_lockfile_and_checks_selected_versions() {
    let cli = Cli::parse_from(["cargo-barbican", "resolve"]);
    let generated_lockfile = lockfile_with_packages(&[("serde", "1.0.228", true)]);
    let client =
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2020-05-01T00:00:00Z", false);
    let runner = FakeCommandRunner::default().with_generated_lockfile(&generated_lockfile);
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"1\"\n",
    )
    .expect("manifest should write");
    fs::write(temp_dir.join("Cargo.lock"), "version = 4\n").expect("base lockfile should write");

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
    assert_eq!(
        fs::read_to_string(temp_dir.join("Cargo.lock")).expect("generated lockfile should read"),
        generated_lockfile
    );
    assert_eq!(runner.recorded_generate_lockfile_calls(), vec![temp_dir]);
    assert_eq!(client.recorded_fetches(), vec!["serde@1.0.228".to_owned()]);
    assert!(
        String::from_utf8(stdout)
            .expect("stdout should be utf8")
            .contains("OK   serde@1.0.228")
    );
}

#[test]
fn resolve_restores_original_lockfile_when_age_gate_fails() {
    let cli = Cli::parse_from(["cargo-barbican", "resolve"]);
    let generated_lockfile = lockfile_with_packages(&[("freshdep", "1.0.0", true)]);
    let client =
        FakeCratesIoClient::default().with_release("freshdep@1.0.0", "2020-05-26T00:00:00Z", false);
    let runner = FakeCommandRunner::default().with_generated_lockfile(&generated_lockfile);
    let temp_dir = fresh_temp_dir();
    let original_lockfile = lockfile_with_packages(&[("serde", "1.0.227", true)]);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nfreshdep = \"1\"\n",
    )
    .expect("manifest should write");
    fs::write(temp_dir.join("Cargo.lock"), &original_lockfile).expect("base lockfile should write");

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
    assert_eq!(
        fs::read_to_string(temp_dir.join("Cargo.lock")).expect("restored lockfile should read"),
        original_lockfile
    );
    assert!(stdout.is_empty());
    assert!(
        String::from_utf8(stderr)
            .expect("stderr should be utf8")
            .contains("FAIL freshdep@1.0.0: published 2020-05-26T00:00:00Z")
    );
}

#[test]
fn resolve_restores_original_lockfile_when_age_recheck_errors() {
    let cli = Cli::parse_from(["cargo-barbican", "resolve"]);
    let generated_lockfile = lockfile_with_packages(&[("freshdep", "1.0.0", true)]);
    let client =
        FakeCratesIoClient::default().with_release("freshdep@1.0.0", "2020-05-01T00:00:00Z", false);
    let runner = FakeCommandRunner::default().with_generated_lockfile(&generated_lockfile);
    let temp_dir = fresh_temp_dir();
    let original_lockfile = lockfile_with_packages(&[("serde", "1.0.227", true)]);
    let mut stdout = FailingWriter;
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nfreshdep = \"1\"\n",
    )
    .expect("manifest should write");
    fs::write(temp_dir.join("Cargo.lock"), &original_lockfile).expect("base lockfile should write");

    let result = run_cli_with_runner_at(
        cli,
        &temp_dir,
        &client,
        &runner,
        fixed_now(),
        &mut stdout,
        &mut stderr,
    );

    let exit_code = result.expect("command should run");
    assert_eq!(exit_code, ExitCode::from(1));
    assert!(
        String::from_utf8(stderr)
            .expect("stderr should be utf8")
            .starts_with("FAIL ")
    );
    assert_eq!(
        fs::read_to_string(temp_dir.join("Cargo.lock")).expect("restored lockfile should read"),
        original_lockfile
    );
}
