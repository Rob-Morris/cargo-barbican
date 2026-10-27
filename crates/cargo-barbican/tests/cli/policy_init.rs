use super::common::*;

#[test]
fn policy_init_requires_an_explicit_toolchain_decision() {
    let cli = Cli::parse_from(["cargo-barbican", "policy", "init", "--ci", "github"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(temp_dir.join("barbican.toml").exists());
    assert!(!temp_dir.join("rust-toolchain.toml").exists());
    assert!(!temp_dir.join(".github/workflows/barbican.yml").exists());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains(
        "- rust-toolchain.toml: blocked (missing; rerun with --toolchain <exact-channel>"
    ));
    assert!(rendered.contains(
        "- .github/workflows/barbican.yml: blocked (requires a valid exact rust-toolchain.toml pin)"
    ));
    assert!(stderr.is_empty());
}

#[test]
fn policy_init_uses_an_existing_valid_pin_for_ci_without_requiring_the_flag_again() {
    let cli = Cli::parse_from(["cargo-barbican", "policy", "init", "--ci", "github"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    write_toolchain_pin(&temp_dir);
    let original_pin = fs::read_to_string(temp_dir.join("rust-toolchain.toml"))
        .expect("toolchain pin should exist");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(temp_dir.join(".github/workflows/barbican.yml").exists());
    assert_eq!(
        fs::read_to_string(temp_dir.join("rust-toolchain.toml"))
            .expect("toolchain pin should remain"),
        original_pin
    );
    assert!(
        String::from_utf8(stdout)
            .unwrap()
            .contains("rust-toolchain.toml: already present")
    );
    assert!(stderr.is_empty());
}

#[test]
fn policy_init_refuses_to_replace_a_conflicting_toolchain_pin() {
    let cli = Cli::parse_from(["cargo-barbican", "policy", "init", "--toolchain", "1.96.0"]);
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
            .contains("pins 1.95.0; refusing requested conflicting pin 1.96.0")
    );
    assert_eq!(
        fs::read_to_string(temp_dir.join("rust-toolchain.toml")).expect("toolchain should remain"),
        "[toolchain]\nchannel = \"1.95.0\"\nprofile = \"minimal\"\n"
    );
    assert!(stderr.is_empty());
}

#[test]
fn policy_init_creates_minimal_scaffold_and_next_steps() {
    let cli = Cli::parse_from(["cargo-barbican", "policy", "init", "--toolchain", "1.95.0"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert_eq!(
        fs::read_to_string(temp_dir.join("rust-toolchain.toml"))
            .expect("toolchain pin should exist"),
        "[toolchain]\nchannel = \"1.95.0\"\nprofile = \"minimal\"\n"
    );
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
    assert!(rendered.contains(
        "- rust-toolchain.toml: created (exact channel 1.95.0; rustup profile minimal)\n"
    ));
    assert!(rendered.contains("- deny.toml: created\n"));
    assert!(rendered.contains("- reviewed-targets.toml: created\n"));
    assert!(rendered.contains("- docs/dependency-reviews: created\n"));
    assert!(rendered.contains("- docs/dependency-reviews/README.md: created\n"));
    assert!(rendered.contains(
        "Adoption guide: https://github.com/Rob-Morris/cargo-barbican/blob/v0.36.0/docs/user/adoption.md"
    ));
    assert!(rendered.contains("Review current dependencies"));
    assert!(stderr.is_empty());
}

#[test]
fn policy_init_without_ci_does_not_emit_workflow() {
    let cli = Cli::parse_from(["cargo-barbican", "policy", "init", "--toolchain", "1.95.0"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(!temp_dir.join(".github/workflows/barbican.yml").exists());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("policy init --ci github"));
    assert!(rendered.contains("blob/v0.36.0/docs/user/ci.md#pre-commit-hook"));
    assert!(stderr.is_empty());
}

#[test]
fn policy_init_ci_github_emits_enforcement_workflow() {
    let cli = Cli::parse_from([
        "cargo-barbican",
        "policy",
        "init",
        "--toolchain",
        "1.95.0",
        "--ci",
        "github",
    ]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    // The base scaffold is created independently of the CI workflow.
    assert!(temp_dir.join("barbican.toml").exists());
    assert!(temp_dir.join("reviewed-targets.toml").exists());

    let workflow = fs::read_to_string(temp_dir.join(".github/workflows/barbican.yml"))
        .expect("workflow should exist");
    for gate_command in [
        // Without the all-targets fetch, the gate's frozen cross-platform
        // metadata fails on any runner whose cache lacks other platforms'
        // crates.
        "cargo fetch --locked",
        "cargo barbican gatehouse pre-release",
        "cargo barbican toolchain check",
        "cargo barbican age-lock --base-ref",
        "cargo barbican assess --base-ref",
    ] {
        assert!(
            workflow.contains(gate_command),
            "emitted workflow should run `{gate_command}`"
        );
    }
    assert_eq!(
        workflow
            .matches("cargo barbican gatehouse pre-release")
            .count(),
        1
    );
    assert!(!workflow.contains("cargo barbican inventory --enforce"));
    assert!(workflow.contains("cargo install --locked"));
    assert!(workflow.contains("--tag v0.36.0"));
    assert!(workflow.contains("cargo-deny@0.19.6"));
    assert!(workflow.contains("cargo-audit@0.22.1"));
    assert!(
        workflow.contains("actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6.0.3")
    );
    assert!(
        workflow.contains("Swatinem/rust-cache@c19371144df3bb44fab255c43d04cbc2ab54d1c4 # v2.9.1")
    );

    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("- .github/workflows/barbican.yml: created\n"));
    assert!(
        rendered
            .contains("Review .github/workflows/barbican.yml, then configure required CI checks")
    );
    assert!(stderr.is_empty());
}

#[test]
fn policy_init_ci_github_fails_closed_on_existing_workflow() {
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);

    let first = Cli::parse_from([
        "cargo-barbican",
        "policy",
        "init",
        "--toolchain",
        "1.95.0",
        "--ci",
        "github",
    ]);
    let mut first_stdout = Vec::new();
    let mut first_stderr = Vec::new();
    let first_exit = run_cli_with_runner(
        first,
        &temp_dir,
        &client,
        &runner,
        &mut first_stdout,
        &mut first_stderr,
    )
    .expect("first command should run");
    assert_eq!(first_exit, ExitCode::SUCCESS);

    let workflow_path = temp_dir.join(".github/workflows/barbican.yml");
    let created =
        fs::read_to_string(&workflow_path).expect("workflow should exist after first run");
    let consumer_workflow = "# Consumer-owned workflow\nname: Custom policy checks\n";
    fs::write(&workflow_path, consumer_workflow).expect("custom workflow should be written");

    let second = Cli::parse_from([
        "cargo-barbican",
        "policy",
        "init",
        "--toolchain",
        "1.95.0",
        "--ci",
        "github",
    ]);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let second_exit = run_cli_with_runner(
        second,
        &temp_dir,
        &client,
        &runner,
        &mut stdout,
        &mut stderr,
    )
    .expect("second command should run");

    assert_eq!(second_exit, ExitCode::from(1));
    assert_eq!(
        fs::read_to_string(&workflow_path).expect("workflow should still exist"),
        consumer_workflow,
        "an existing workflow must not be overwritten"
    );
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains(
        "- .github/workflows/barbican.yml: blocked (already exists; refusing to overwrite the CI workflow)"
    ));
    assert!(rendered.contains(
        "The .github/workflows/barbican.yml workflow was not written because a file already exists there"
    ));
    assert!(rendered.contains(&created));
    assert!(created.contains("cargo barbican toolchain check"));
    assert!(created.contains("name: Summarise PR evidence"));
    assert!(stderr.is_empty());
}

#[test]
fn policy_init_is_idempotent_for_existing_regular_scaffold() {
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);

    for _ in 0..2 {
        let cli = Cli::parse_from(["cargo-barbican", "policy", "init", "--toolchain", "1.95.0"]);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code =
            run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
                .expect("command should run");

        assert_eq!(exit_code, ExitCode::SUCCESS);
        assert!(stderr.is_empty());
    }

    let cli = Cli::parse_from(["cargo-barbican", "policy", "init", "--toolchain", "1.95.0"]);
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
    let cli = Cli::parse_from(["cargo-barbican", "policy", "init", "--toolchain", "1.95.0"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
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
    let cli = Cli::parse_from(["cargo-barbican", "policy", "init", "--toolchain", "1.95.0"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
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
    let cli = Cli::parse_from(["cargo-barbican", "policy", "init", "--toolchain", "1.95.0"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
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
    let cli = Cli::parse_from(["cargo-barbican", "policy", "init", "--toolchain", "1.95.0"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
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
    assert!(rendered.contains("source text omitted"));
    assert!(!rendered.contains("pwned"));
    assert!(stderr.is_empty());
}

#[test]
fn policy_init_reports_malformed_config_without_creating_dependent_scaffold() {
    let cli = Cli::parse_from(["cargo-barbican", "policy", "init", "--toolchain", "1.95.0"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
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
    let cli = Cli::parse_from(["cargo-barbican", "policy", "init", "--toolchain", "1.95.0"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
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
    let cli = Cli::parse_from(["cargo-barbican", "policy", "init", "--toolchain", "1.95.0"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
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
    assert!(rendered.contains("source text omitted"));
    assert!(stderr.is_empty());
}

#[test]
fn policy_init_fails_closed_on_wrong_type_scaffold_paths() {
    let cli = Cli::parse_from(["cargo-barbican", "policy", "init", "--toolchain", "1.95.0"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
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
    let cli = Cli::parse_from(["cargo-barbican", "policy", "init", "--toolchain", "1.95.0"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
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
    let cli = Cli::parse_from(["cargo-barbican", "policy", "init", "--toolchain", "1.95.0"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
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
    let cli = Cli::parse_from(["cargo-barbican", "policy", "init", "--toolchain", "1.95.0"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
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

#[test]
fn requested_hook_is_independent_of_report_level_config_and_pin_blocks() {
    for invalid_config in [false, true] {
        let root = fresh_temp_dir();
        write_root_manifest(&root);
        if invalid_config {
            fs::write(root.join("barbican.toml"), "[broken").unwrap();
        }
        let runner = FakeCommandRunner::default();
        let client = FakeCratesIoClient::default();
        let mut stdout = Vec::new();
        let exit = run_cli_with_runner(
            Cli::parse_from([
                "cargo-barbican",
                "policy",
                "init",
                "--pre-commit-hook",
                "--ci",
                "github",
            ]),
            &root,
            &client,
            &runner,
            &mut stdout,
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(exit, ExitCode::from(1));
        assert_eq!(
            fs::read_to_string(root.join(".barbican/hooks/pre-commit")).unwrap(),
            include_str!("../../../../templates/hooks/pre-commit")
        );
        assert_eq!(
            root.join("docs/dependency-reviews/record-template.md")
                .exists(),
            !invalid_config
        );
        assert!(!root.join(".github/workflows/barbican.yml").exists());
        assert_eq!(*runner.cargo_metadata_calls.borrow(), 0);
        assert!(runner.generate_lockfile_calls.borrow().is_empty());
        assert!(runner.audit_json_calls.borrow().is_empty());
        assert!(runner.deny_json_calls.borrow().is_empty());
        assert!(runner.verification_calls.borrow().is_empty());
        assert!(client.fetches.borrow().is_empty());
        let output = String::from_utf8(stdout).unwrap();
        assert!(output.contains("pre-commit: created"));
        assert!(output.contains("ci.md#pre-commit-hook"));
        assert!(!output.contains("Next steps:"));
    }
}

#[test]
fn missing_template_is_added_alongside_custom_process_and_records() {
    let root = fresh_temp_dir();
    write_root_manifest(&root);
    write_toolchain_pin(&root);
    fs::create_dir_all(root.join("docs/dependency-reviews")).unwrap();
    fs::write(
        root.join("docs/dependency-reviews/README.md"),
        "Our own process\n",
    )
    .unwrap();
    fs::write(
        root.join("docs/dependency-reviews/done.md"),
        "Reviewed evidence\n",
    )
    .unwrap();
    for _ in 0..2 {
        let mut stdout = Vec::new();
        let exit = run_cli_with_runner(
            Cli::parse_from(["cargo-barbican", "policy", "init"]),
            &root,
            &FakeCratesIoClient::default(),
            &FakeCommandRunner::default(),
            &mut stdout,
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(exit, ExitCode::SUCCESS);
        assert!(!root.join(".barbican").exists());
        assert_eq!(
            fs::read_to_string(root.join("docs/dependency-reviews/README.md")).unwrap(),
            "Our own process\n"
        );
        assert_eq!(
            fs::read_to_string(root.join("docs/dependency-reviews/done.md")).unwrap(),
            "Reviewed evidence\n"
        );
        let template =
            fs::read_to_string(root.join("docs/dependency-reviews/record-template.md")).unwrap();
        assert_eq!(
            barbican::classify_review_record(Some(&template)),
            barbican::ReviewRecordStatus::ScaffoldPlaceholder
        );
        assert!(
            String::from_utf8(stdout)
                .unwrap()
                .contains("ci.md#pre-commit-hook")
        );
    }
}
