use super::common::*;

#[test]
fn policy_init_creates_minimal_scaffold_and_next_steps() {
    let cli = Cli::parse_from(["cargo-barbican", "policy", "init"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert_eq!(
        fs::read_to_string(temp_dir.join("barbican.toml")).expect("config should exist"),
        include_str!("../../../../templates/barbican.toml")
    );
    assert_eq!(
        fs::read_to_string(temp_dir.join("deny.toml")).expect("deny config should exist"),
        include_str!("../../../../templates/deny.toml")
    );
    assert_eq!(
        fs::read_to_string(temp_dir.join("reviewed-targets.toml"))
            .expect("reviewed targets should exist"),
        include_str!("../../../../templates/reviewed-targets.toml")
    );
    assert_eq!(
        fs::read_to_string(temp_dir.join("docs/dependency-reviews/README.md"))
            .expect("review readme should exist"),
        include_str!("../../../../templates/dependency-reviews/README.md")
    );

    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("- barbican.toml: created\n"));
    assert!(rendered.contains("- deny.toml: created\n"));
    assert!(rendered.contains("- reviewed-targets.toml: created\n"));
    assert!(rendered.contains("- docs/dependency-reviews: created\n"));
    assert!(rendered.contains("- docs/dependency-reviews/README.md: created\n"));
    assert!(rendered.contains(
        "Review the manual adoption guide: https://github.com/rob-morris/cargo-barbican/blob/main/docs/user/adoption.md"
    ));
    assert!(rendered.contains("Review current dependencies"));
    assert!(stderr.is_empty());
}

#[test]
fn policy_init_is_idempotent_for_existing_regular_scaffold() {
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();

    for _ in 0..2 {
        let cli = Cli::parse_from(["cargo-barbican", "policy", "init"]);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code =
            run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
                .expect("command should run");

        assert_eq!(exit_code, ExitCode::SUCCESS);
        assert!(stderr.is_empty());
    }

    let cli = Cli::parse_from(["cargo-barbican", "policy", "init"]);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("- barbican.toml: already present\n"));
    assert!(rendered.contains("- deny.toml: already present\n"));
    assert!(rendered.contains("- reviewed-targets.toml: already present\n"));
    assert!(rendered.contains("- docs/dependency-reviews: already present\n"));
    assert!(rendered.contains("- docs/dependency-reviews/README.md: already present\n"));
    assert!(stderr.is_empty());
}

#[test]
fn policy_init_preserves_existing_regular_deny_toml() {
    let cli = Cli::parse_from(["cargo-barbican", "policy", "init"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let existing_deny = "[bans]\nmultiple-versions = \"warn\"\n";
    fs::write(temp_dir.join("deny.toml"), existing_deny).expect("deny config should write");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert_eq!(
        fs::read_to_string(temp_dir.join("deny.toml")).expect("deny config should still exist"),
        existing_deny
    );
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("- deny.toml: already present\n"));
    assert!(stderr.is_empty());
}

#[test]
fn policy_init_validates_existing_reviewed_targets_policy() {
    let cli = Cli::parse_from(["cargo-barbican", "policy", "init"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    fs::write(temp_dir.join("reviewed-targets.toml"), "[rust]\n")
        .expect("empty reviewed targets policy should write");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("- reviewed-targets.toml: already present\n"));
    assert!(stderr.is_empty());
}

#[test]
fn policy_init_reports_malformed_existing_reviewed_targets_policy() {
    let cli = Cli::parse_from(["cargo-barbican", "policy", "init"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        "[[rust.families]]\nname = \"bad\"\nreview_record = \"docs/dependency-reviews/bad.md\"\n",
    )
    .expect("malformed reviewed targets policy should write");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("- reviewed-targets.toml: blocked (invalid policy:"));
    assert!(stderr.is_empty());
}

#[test]
fn policy_init_escapes_malformed_reviewed_targets_parse_diagnostics() {
    let cli = Cli::parse_from(["cargo-barbican", "policy", "init"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        "[rust]\n\u{001b} = \"pwned\"\n",
    )
    .expect("malformed reviewed targets policy should write");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("- reviewed-targets.toml: blocked (invalid policy:"));
    assert!(!rendered.contains('\u{001b}'));
    assert!(rendered.contains("\\x1b"));
    assert!(rendered.contains("2 | \\x1b = \"pwned\"\n  | ^"));
    assert!(stderr.is_empty());
}

#[test]
fn policy_init_reports_malformed_config_without_creating_dependent_scaffold() {
    let cli = Cli::parse_from(["cargo-barbican", "policy", "init"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    fs::write(
        temp_dir.join("barbican.toml"),
        "[release_age]\nminimum_days = 365001\n",
    )
    .expect("invalid config should write");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("- barbican.toml: blocked (invalid config:"));
    assert!(!temp_dir.join("deny.toml").exists());
    assert!(!temp_dir.join("reviewed-targets.toml").exists());
    assert!(!temp_dir.join("docs/dependency-reviews/README.md").exists());
    assert!(stderr.is_empty());
}

#[test]
fn policy_init_escapes_malformed_config_parse_diagnostics() {
    let cli = Cli::parse_from(["cargo-barbican", "policy", "init"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    fs::write(
        temp_dir.join("barbican.toml"),
        "[delegates]\n\u{001b} = \"pwned\"\n",
    )
    .expect("invalid config should write");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("- barbican.toml: blocked (invalid config:"));
    assert!(!rendered.contains('\u{001b}'));
    assert!(rendered.contains("\\x1b"));
    assert!(rendered.contains("2 | \\x1b = \"pwned\"\n  | ^"));
    assert!(!temp_dir.join("deny.toml").exists());
    assert!(!temp_dir.join("reviewed-targets.toml").exists());
    assert!(stderr.is_empty());
}

#[test]
fn policy_init_escapes_unicode_line_separators_in_parse_diagnostics() {
    let cli = Cli::parse_from(["cargo-barbican", "policy", "init"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        "[rust]\n\u{2028} = \"pwned\"\n",
    )
    .expect("malformed reviewed targets policy should write");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("- reviewed-targets.toml: blocked (invalid policy:"));
    assert!(!rendered.contains('\u{2028}'));
    assert!(rendered.contains("\\x2028"));
    assert!(stderr.is_empty());
}

#[test]
fn policy_init_fails_closed_on_wrong_type_scaffold_paths() {
    let cli = Cli::parse_from(["cargo-barbican", "policy", "init"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    fs::create_dir(temp_dir.join("reviewed-targets.toml")).expect("wrong type path should exist");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("- barbican.toml: created\n"));
    assert!(rendered.contains("- deny.toml: created\n"));
    assert!(
        rendered
            .contains("- reviewed-targets.toml: blocked (expected regular file, found directory)")
    );
    assert!(stderr.is_empty());
}

#[cfg(unix)]
#[test]
fn policy_init_fails_closed_on_symlinked_policy_paths() {
    let cli = Cli::parse_from(["cargo-barbican", "policy", "init"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    fs::write(temp_dir.join("real-reviewed-targets.toml"), "[rust]\n")
        .expect("real target should write");
    std::os::unix::fs::symlink(
        temp_dir.join("real-reviewed-targets.toml"),
        temp_dir.join("reviewed-targets.toml"),
    )
    .expect("symlink should create");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("- deny.toml: created\n"));
    assert!(
        rendered
            .contains("- reviewed-targets.toml: blocked (expected regular file, found symlink)")
    );
    assert!(stderr.is_empty());
}

#[cfg(unix)]
#[test]
fn policy_init_does_not_write_through_symlinked_review_directory() {
    let cli = Cli::parse_from(["cargo-barbican", "policy", "init"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    fs::create_dir_all(temp_dir.join("outside-reviews"))
        .expect("outside review directory should create");
    fs::create_dir_all(temp_dir.join("docs")).expect("docs directory should create");
    std::os::unix::fs::symlink(
        temp_dir.join("outside-reviews"),
        temp_dir.join("docs/dependency-reviews"),
    )
    .expect("review directory symlink should create");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(
        rendered.contains("- docs/dependency-reviews: blocked (expected directory, found symlink)")
    );
    assert!(!temp_dir.join("outside-reviews/README.md").exists());
    assert!(stderr.is_empty());
}

#[cfg(unix)]
#[test]
fn policy_init_does_not_write_through_symlinked_scaffold_ancestors() {
    let cli = Cli::parse_from(["cargo-barbican", "policy", "init"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    fs::create_dir_all(temp_dir.join("outside-docs")).expect("outside docs should create");
    std::os::unix::fs::symlink(temp_dir.join("outside-docs"), temp_dir.join("docs"))
        .expect("docs symlink should create");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(
        rendered.contains(
            "- docs/dependency-reviews: blocked (ancestor docs is not a regular directory)"
        )
    );
    assert!(!temp_dir.join("outside-docs/dependency-reviews").exists());
    assert!(stderr.is_empty());
}
