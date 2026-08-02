use super::common::*;

#[test]
fn update_updates_selected_package_and_rechecks_the_lockfile_diff() {
    let cli = Cli::parse_from(["cargo-barbican", "update", "serde@1.0.228"]);
    let client =
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2020-05-01T00:00:00Z", false);
    let runner = FakeCommandRunner::default()
        .with_updated_lockfile(&lockfile_with_packages(&[("serde", "1.0.228", true)]))
        .with_cargo_metadata(&metadata_with_packages(&[(
            "serde",
            "1.0.228",
            "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228",
        )]));
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
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
    assert_eq!(
        fs::read_to_string(temp_dir.join("Cargo.lock")).expect("updated lockfile should read"),
        lockfile_with_packages(&[("serde", "1.0.228", true)])
    );
    assert_eq!(
        runner.recorded_updates(),
        vec![(
            "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228".to_owned(),
            "1.0.228".to_owned(),
        )]
    );
    assert_eq!(client.recorded_fetches(), vec!["serde@1.0.228".to_owned()]);
    assert_eq!(
        String::from_utf8(stdout)
            .expect("stdout should be utf8")
            .matches("OK   serde@1.0.228")
            .count(),
        2
    );
}

#[test]
fn update_labels_the_pre_check_and_recheck_as_distinct_phases() {
    let cli = Cli::parse_from(["cargo-barbican", "update", "serde@1.0.228"]);
    let client =
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2020-05-01T00:00:00Z", false);
    let runner = FakeCommandRunner::default()
        .with_updated_lockfile(&lockfile_with_packages(&[("serde", "1.0.228", true)]))
        .with_cargo_metadata(&metadata_with_packages(&[(
            "serde",
            "1.0.228",
            "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228",
        )]));
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
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
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    let pre_check = rendered
        .find("Release-age check for requested versions:")
        .expect("pre-check phase label should be present");
    let recheck = rendered
        .find("Release-age recheck for newly selected versions:")
        .expect("recheck phase label should be present");
    assert!(
        pre_check < recheck,
        "the pre-check label should precede the recheck label"
    );
    // Both phases still run their own release-age check, so the OK line
    // appears once per phase rather than being de-duplicated away.
    assert_eq!(rendered.matches("OK   serde@1.0.228").count(), 2);
}

#[test]
fn update_honours_min_age_override_for_both_age_checks() {
    let cli = Cli::parse_from([
        "cargo-barbican",
        "update",
        "--min-age-days",
        "3",
        "serde@1.0.228",
    ]);
    let client =
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2020-05-20T00:00:00Z", false);
    let runner = FakeCommandRunner::default()
        .with_updated_lockfile(&lockfile_with_packages(&[("serde", "1.0.228", true)]))
        .with_cargo_metadata(&metadata_with_packages(&[(
            "serde",
            "1.0.228",
            "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228",
        )]));
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("barbican.toml"),
        "[release_age]\nminimum_days = 30\n\n[high_scrutiny]\n\n[delegates]\n",
    )
    .expect("config should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_packages(&[("serde", "1.0.227", true)]),
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

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert_eq!(
        fs::read_to_string(temp_dir.join("Cargo.lock")).expect("updated lockfile should read"),
        lockfile_with_packages(&[("serde", "1.0.228", true)])
    );
    assert_eq!(client.recorded_fetches(), vec!["serde@1.0.228".to_owned()]);
    assert_eq!(
        String::from_utf8(stdout)
            .expect("stdout should be utf8")
            .matches("OK   serde@1.0.228")
            .count(),
        2
    );
}

#[test]
fn update_recheck_flags_too_fresh_transitive_selection_under_injected_clock() {
    // The explicit spec is old enough against `fixed_now()` (2020-06-01), but the
    // update pulls in a transitive crate published only 6 days earlier. Only the
    // post-update recheck can catch that, so this guards the update recheck call
    // site's clock wiring: a regression reading the wall clock would see a
    // years-old release and let it through.
    let cli = Cli::parse_from(["cargo-barbican", "update", "serde@1.0.228"]);
    let client = FakeCratesIoClient::default()
        .with_release("serde@1.0.228", "2020-05-01T00:00:00Z", false)
        .with_release("freshdep@1.0.0", "2020-05-26T00:00:00Z", false);
    let runner = FakeCommandRunner::default()
        .with_updated_lockfile(&lockfile_with_packages(&[
            ("freshdep", "1.0.0", true),
            ("serde", "1.0.228", true),
        ]))
        .with_cargo_metadata(&metadata_with_packages(&[(
            "serde",
            "1.0.228",
            "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228",
        )]));
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_packages(&[("serde", "1.0.227", true)]),
    )
    .expect("current lockfile should write");
    let original_lockfile =
        fs::read_to_string(temp_dir.join("Cargo.lock")).expect("lockfile should read");

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
        fs::read_to_string(temp_dir.join("Cargo.lock")).expect("lockfile should read"),
        original_lockfile
    );
    assert!(
        String::from_utf8(stderr)
            .expect("stderr should be utf8")
            .contains("FAIL freshdep@1.0.0: published 2020-05-26T00:00:00Z")
    );
}

#[test]
fn update_dry_run_previews_lockfile_diff_without_mutating_repo() {
    let cli = Cli::parse_from(["cargo-barbican", "update", "--dry-run", "serde@1.0.228"]);
    let client =
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2020-05-01T00:00:00Z", false);
    let runner = FakeCommandRunner::default()
        .with_updated_lockfile(&lockfile_with_packages(&[("serde", "1.0.228", true)]))
        .with_cargo_metadata(&metadata_with_packages(&[(
            "serde",
            "1.0.228",
            "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228",
        )]));
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    let original_lockfile = lockfile_with_packages(&[("serde", "1.0.227", true)]);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(temp_dir.join("Cargo.lock"), &original_lockfile)
        .expect("current lockfile should write");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert_eq!(
        fs::read_to_string(temp_dir.join("Cargo.lock")).expect("original lockfile should read"),
        original_lockfile
    );
    assert_eq!(
        runner.recorded_updates(),
        vec![(
            "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228".to_owned(),
            "1.0.228".to_owned(),
        )]
    );
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert_eq!(rendered.matches("OK   serde@1.0.228").count(), 2);
    assert!(rendered.contains("Dry run preview:"));
    assert!(rendered.contains("diff --git a/Cargo.lock b/Cargo.lock"));
    assert!(rendered.contains("--- a/Cargo.lock"));
    assert!(rendered.contains("+++ b/Cargo.lock"));
}

#[test]
fn update_dry_run_escapes_bidi_and_zero_width_controls_in_lockfile_diff() {
    let cli = Cli::parse_from(["cargo-barbican", "update", "--dry-run", "serde@1.0.228"]);
    let client =
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2020-05-01T00:00:00Z", false);
    let spoofed_source = format!(
        "registry+https://github.com/rust-lang/crates.io-index{}{}",
        '\u{202e}', '\u{200b}'
    );
    let updated_lockfile =
        lockfile_with_package_sources(&[("serde", "1.0.228", Some(&spoofed_source))]);
    let runner = FakeCommandRunner::default()
        .with_updated_lockfile(&updated_lockfile)
        .with_cargo_metadata(&metadata_with_packages(&[(
            "serde",
            "1.0.228",
            "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228",
        )]));
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    let original_lockfile = lockfile_with_packages(&[("serde", "1.0.227", true)]);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(temp_dir.join("Cargo.lock"), &original_lockfile)
        .expect("current lockfile should write");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("\\x202e"));
    assert!(rendered.contains("\\x200b"));
    assert!(!rendered.contains('\u{202e}'));
    assert!(!rendered.contains('\u{200b}'));
    assert!(
        rendered.contains("\n-source = \"registry+https://github.com/rust-lang/crates.io-index\"")
    );
    assert!(
        rendered.contains("\n+source = \"registry+https://github.com/rust-lang/crates.io-index")
    );
    assert!(!rendered.contains("\\n"));
}

#[test]
fn update_dry_run_reports_when_no_lockfile_change_would_be_made() {
    let cli = Cli::parse_from(["cargo-barbican", "update", "--dry-run", "serde@1.0.228"]);
    let lockfile = lockfile_with_packages(&[("serde", "1.0.228", true)]);
    let client =
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2020-05-01T00:00:00Z", false);
    let runner = FakeCommandRunner::default()
        .with_updated_lockfile(&lockfile)
        .with_cargo_metadata(&metadata_with_packages(&[(
            "serde",
            "1.0.228",
            "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228",
        )]));
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(temp_dir.join("Cargo.lock"), &lockfile).expect("current lockfile should write");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert_eq!(
        fs::read_to_string(temp_dir.join("Cargo.lock")).expect("original lockfile should read"),
        lockfile
    );
    assert!(
        String::from_utf8(stdout)
            .expect("stdout should be utf8")
            .contains("Dry run: no Cargo.lock changes would be made.")
    );
}

#[test]
fn update_restores_original_lockfile_when_age_recheck_errors() {
    let cli = Cli::parse_from(["cargo-barbican", "update", "serde@1.0.228"]);
    let client =
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2020-05-01T00:00:00Z", false);
    let runner = FakeCommandRunner::default()
        .with_updated_lockfile(&lockfile_with_packages(&[("serde", "1.0.228", true)]))
        .with_cargo_metadata(&metadata_with_packages(&[(
            "serde",
            "1.0.228",
            "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228",
        )]));
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    let original_lockfile = lockfile_with_packages(&[("serde", "1.0.227", true)]);
    // Before cargo_update_precise mutates Cargo.lock, this single
    // already-allowed spec renders three stdout lines: the pre-check phase
    // label, its one "OK ..." line, and the recheck phase label (written after
    // the mutation). Let those three write through so the induced failure
    // lands on the post-mutation recheck's "OK ..." line instead, which is the
    // path this test exists to exercise.
    let mut stdout = FailAfterWriter::new(3);
    let mut stderr = Vec::new();

    fs::write(temp_dir.join("Cargo.lock"), &original_lockfile)
        .expect("current lockfile should write");

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
    // Confirms the induced stdout failure was hit after the lockfile
    // mutation, not instead of it: if cargo_update_precise never ran, the
    // restored-lockfile assertion above would pass vacuously.
    assert_eq!(
        runner.recorded_updates(),
        vec![(
            "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228".to_owned(),
            "1.0.228".to_owned(),
        )]
    );
    assert_eq!(
        fs::read_to_string(temp_dir.join("Cargo.lock")).expect("restored lockfile should read"),
        original_lockfile
    );
}
