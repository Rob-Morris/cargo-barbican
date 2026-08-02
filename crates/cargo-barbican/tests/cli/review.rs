use super::common::*;

#[test]
fn review_prints_no_changes_message_for_empty_diff() {
    let cli = Cli::parse_from(["cargo-barbican", "review"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default().with_git_diff("");
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    write_workspace_layout(&temp_dir);

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert_eq!(
        String::from_utf8(stdout).expect("stdout should be utf8"),
        "No Rust dependency policy changes detected.\n"
    );
}

#[test]
fn review_prints_checklist_and_diff_for_policy_files() {
    let cli = Cli::parse_from(["cargo-barbican", "review"]);
    let client = FakeCratesIoClient::default();
    let runner =
        FakeCommandRunner::default().with_git_diff("diff --git a/Cargo.lock b/Cargo.lock\n");
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    write_workspace_layout(&temp_dir);

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Review checklist:"));
    assert!(rendered.contains("diff --git a/Cargo.lock b/Cargo.lock"));
    assert!(rendered.contains("reviewed-targets.toml"));
    assert!(rendered.contains("checked-in review record"));

    let recorded_paths = runner.recorded_diff_paths();
    assert!(recorded_paths.contains(&PathBuf::from("Cargo.toml")));
    assert!(recorded_paths.contains(&PathBuf::from("Cargo.lock")));
    assert!(recorded_paths.contains(&PathBuf::from("barbican.toml")));
    assert!(recorded_paths.contains(&PathBuf::from("deny.toml")));
    assert!(recorded_paths.contains(&PathBuf::from("reviewed-targets.toml")));
    assert!(recorded_paths.contains(&PathBuf::from("docs/dependency-reviews")));
    assert!(recorded_paths.contains(&PathBuf::from("app/Cargo.toml")));
    assert!(recorded_paths.contains(&PathBuf::from("crates/barbican/Cargo.toml")));
    assert!(recorded_paths.contains(&PathBuf::from("crates/cargo-barbican/Cargo.toml")));
}

#[test]
fn review_lists_untracked_policy_files_when_no_tracked_changes() {
    let cli = Cli::parse_from(["cargo-barbican", "review"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default()
        .with_git_diff("")
        .with_git_untracked(
            "barbican.toml\0reviewed-targets.toml\0docs/dependency-reviews/2026-07-15-serde.md\0",
        );
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    write_workspace_layout(&temp_dir);

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("No Rust dependency policy changes detected."));
    assert!(rendered.contains("Untracked policy-relevant files"));
    assert!(rendered.contains("  - barbican.toml"));
    assert!(rendered.contains("  - reviewed-targets.toml"));
    assert!(rendered.contains("  - docs/dependency-reviews/2026-07-15-serde.md"));
    // The untracked query is scoped to the same review path set as the diff.
    assert_eq!(
        runner.recorded_untracked_paths(),
        runner.recorded_diff_paths()
    );
    assert!(!runner.recorded_untracked_paths().is_empty());
}

#[test]
fn review_lists_untracked_policy_files_before_a_tracked_diff() {
    let cli = Cli::parse_from(["cargo-barbican", "review"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default()
        .with_git_diff("diff --git a/Cargo.lock b/Cargo.lock\n")
        .with_git_untracked("reviewed-targets.toml\0");
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    write_workspace_layout(&temp_dir);

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Review checklist:"));
    assert!(rendered.contains("  - reviewed-targets.toml"));
    // The visibility note precedes the diff body so a long diff cannot bury it.
    let note = rendered
        .find("Untracked policy-relevant files")
        .expect("untracked note should be present");
    let diff = rendered
        .find("diff --git a/Cargo.lock b/Cargo.lock")
        .expect("diff body should be present");
    assert!(note < diff, "the untracked note should precede the diff");
}

#[test]
fn review_supports_non_git_base_directories() {
    let cli = Cli::parse_from(["cargo-barbican", "review", "--base-dir", "baseline"]);
    let client = FakeCratesIoClient::default();
    let runner =
        FakeCommandRunner::default().with_git_diff("diff --git a/Cargo.lock b/Cargo.lock\n");
    let temp_dir = fresh_temp_dir();
    let base_dir = temp_dir.join("baseline");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    write_workspace_layout(&temp_dir);
    write_workspace_layout(&base_dir);

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[workspace]\nmembers = []\n\n[workspace.dependencies]\nsimilar = \"=3.1.1\"\n",
    )
    .expect("current manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        "version = 4\n\n[[package]]\nname = \"similar\"\nversion = \"3.1.1\"\n",
    )
    .expect("current lockfile should write");
    write_review_record(
        &temp_dir,
        "docs/dependency-reviews/2026-05-30-similar-3.1.1.md",
    );

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Review checklist:"));
    assert!(rendered.contains("diff --git a/Cargo.toml b/Cargo.toml"));
    assert!(rendered.contains("+++ b/Cargo.toml"));
    assert!(rendered.contains("similar = \"=3.1.1\""));
    assert!(rendered.contains(
        "diff --git a/docs/dependency-reviews/2026-05-30-similar-3.1.1.md b/docs/dependency-reviews/2026-05-30-similar-3.1.1.md"
    ));
    assert!(runner.recorded_diff_paths().is_empty());
    // The non-git baseline path surfaces new files as added-file diffs, so it
    // does not run the git untracked-file query.
    assert!(runner.recorded_untracked_paths().is_empty());
    assert!(!rendered.contains("Untracked policy-relevant files"));
}

#[test]
fn review_reports_missing_non_git_base_directory() {
    let cli = Cli::parse_from(["cargo-barbican", "review", "--base-dir", "baseline"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    write_workspace_layout(&temp_dir);

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    assert_eq!(
        String::from_utf8(stderr).expect("stderr should be utf8"),
        "FAIL baseline: review baseline directory not found\n"
    );
}
