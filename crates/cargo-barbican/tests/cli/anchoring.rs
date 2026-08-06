//! Workspace-root anchoring: every command resolves the same root cargo
//! would select before touching policy inputs, so behaviour is identical
//! from any directory inside a consumer repo. These tests drive commands
//! from a subdirectory and assert they read root-anchored files instead of
//! false-greening (pin check) or failing on a missing lockfile.

use super::common::*;

fn member_workspace(temp_dir: &Path) -> PathBuf {
    fs::write(
        temp_dir.join("Cargo.toml"),
        "[workspace]\nmembers = [\"member\"]\n",
    )
    .expect("root manifest should write");
    let member_dir = temp_dir.join("member");
    fs::create_dir_all(&member_dir).expect("member dir should be creatable");
    fs::write(
        member_dir.join("Cargo.toml"),
        "[package]\nname = \"member\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"=1.0.228\"\n",
    )
    .expect("member manifest should write");
    member_dir
}

fn excluded_child_workspace(temp_dir: &Path) -> PathBuf {
    fs::write(
        temp_dir.join("Cargo.toml"),
        "[workspace]\nmembers = []\nexclude = [\"excluded\"]\n",
    )
    .expect("root manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_packages(&[("serde", "1.0.228", true)]),
    )
    .expect("root lockfile should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        r#"[rust]

[[rust.families]]
name = "parent-family"
review_record = "docs/dependency-reviews/parent.md"

[rust.families.resolved]
serde = "1.0.228"
"#,
    )
    .expect("root reviewed targets should write");
    write_review_record(temp_dir, "docs/dependency-reviews/parent.md");

    let child_dir = temp_dir.join("excluded");
    fs::create_dir_all(&child_dir).expect("excluded child dir should create");
    fs::write(
        child_dir.join("Cargo.toml"),
        "[package]\nname = \"excluded\"\nversion = \"0.1.0\"\n",
    )
    .expect("excluded child manifest should write");
    fs::create_dir_all(child_dir.join("src")).expect("excluded child src should create");
    fs::write(child_dir.join("src/lib.rs"), "").expect("excluded child target should write");
    fs::write(
        child_dir.join("Cargo.lock"),
        lockfile_with_packages(&[("sneaky", "1.0.0", true)]),
    )
    .expect("excluded child lockfile should write");
    fs::write(
        child_dir.join("reviewed-targets.toml"),
        r#"[rust]

[[rust.families]]
name = "child-family"
review_record = "docs/dependency-reviews/child.md"

[rust.families.resolved]
sneaky = "2.0.0"
"#,
    )
    .expect("excluded child reviewed targets should write");
    write_review_record(&child_dir, "docs/dependency-reviews/child.md");
    child_dir
}

#[test]
fn pin_check_from_member_directory_enforces_root_reviewed_targets() {
    let cli = Cli::parse_from(["cargo-barbican", "pin", "check"]);
    let client = FakeCratesIoClient::default();
    let temp_dir = fresh_temp_dir();
    let member_dir = member_workspace(&temp_dir);
    let runner = FakeCommandRunner::default().with_workspace_manifest(&temp_dir.join("Cargo.toml"));
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_packages(&[("serde", "1.0.228", true)]),
    )
    .expect("lockfile should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        r#"[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.resolved]
serde = "1.0.228"
"#,
    )
    .expect("reviewed targets should write");
    write_review_record(&temp_dir, "docs/dependency-reviews/2026-05-27-serde.md");

    let exit_code =
        run_cli_with_runner(cli, &member_dir, &client, &runner, &mut stdout, &mut stderr)
            .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Pin check: PASS"));
    assert!(rendered.contains("family: serde-family"));
    assert!(!rendered.contains("skipping"));
}

#[test]
fn pin_check_from_member_directory_skips_when_root_has_no_reviewed_targets() {
    let cli = Cli::parse_from(["cargo-barbican", "pin", "check"]);
    let client = FakeCratesIoClient::default();
    let temp_dir = fresh_temp_dir();
    let member_dir = member_workspace(&temp_dir);
    let runner = FakeCommandRunner::default().with_workspace_manifest(&temp_dir.join("Cargo.toml"));
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_packages(&[("serde", "1.0.228", true)]),
    )
    .expect("lockfile should write");

    let exit_code =
        run_cli_with_runner(cli, &member_dir, &client, &runner, &mut stdout, &mut stderr)
            .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert_eq!(
        String::from_utf8(stdout).expect("stdout should be utf8"),
        "Pin check: no reviewed-targets.toml present; skipping.\n"
    );
}

#[test]
fn age_lock_from_member_directory_reads_the_root_lockfile() {
    let cli = Cli::parse_from(["cargo-barbican", "age-lock"]);
    let client = FakeCratesIoClient::default();
    let temp_dir = fresh_temp_dir();
    let member_dir = member_workspace(&temp_dir);
    let runner = FakeCommandRunner::default()
        .with_workspace_manifest(&temp_dir.join("Cargo.toml"))
        .with_git_show(
            "HEAD:Cargo.lock",
            &lockfile_with_packages(&[("serde", "1.0.228", true)]),
        );
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_packages(&[("serde", "1.0.228", true)]),
    )
    .expect("root lockfile should write");

    let exit_code =
        run_cli_with_runner(cli, &member_dir, &client, &runner, &mut stdout, &mut stderr)
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
fn subdirectory_without_own_manifest_anchors_to_nearest_manifest_directory() {
    // A plain (non-workspace) package root with a bare nested directory:
    // discovery must climb past the manifest-less subdirectory and anchor to
    // the package root, exactly as it did when invoked at the root.
    let cli = Cli::parse_from(["cargo-barbican", "pin", "check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"=1.0.228\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_packages(&[("serde", "1.0.228", true)]),
    )
    .expect("lockfile should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        "[rust]\nfamilies = []\n",
    )
    .expect("reviewed targets should write");
    let nested_dir = temp_dir.join("src/nested");
    fs::create_dir_all(&nested_dir).expect("nested dir should be creatable");

    let exit_code =
        run_cli_with_runner(cli, &nested_dir, &client, &runner, &mut stdout, &mut stderr)
            .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert_eq!(
        String::from_utf8(stdout).expect("stdout should be utf8"),
        "Pin check: no active Rust reviewed families configured in reviewed-targets.toml; skipping.\n"
    );
}

#[test]
fn commands_fail_closed_when_no_workspace_root_can_be_found() {
    let cli = Cli::parse_from(["cargo-barbican", "pin", "check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    let rendered = String::from_utf8(stderr).expect("stderr should be utf8");
    assert!(rendered.starts_with("FAIL workspace root not found: no Cargo.toml in"));
    assert!(rendered.contains("or any parent directory"));
    assert!(rendered.contains("cargo locate-project --workspace"));
}

#[test]
fn excluded_child_uses_its_own_policy_for_pin_check_and_verify() {
    let temp_dir = fresh_temp_dir();
    let child_dir = excluded_child_workspace(&temp_dir);
    write_toolchain_pin(&child_dir);
    let child_manifest = child_dir.join("Cargo.toml");
    let client = FakeCratesIoClient::default();

    for command in [
        vec!["cargo-barbican", "pin", "check"],
        vec!["cargo-barbican", "verify"],
    ] {
        let cli = Cli::parse_from(command);
        let runner = FakeCommandRunner::default().with_workspace_manifest(&child_manifest);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit_code =
            run_cli_with_runner(cli, &child_dir, &client, &runner, &mut stdout, &mut stderr)
                .expect("command should run");

        assert_eq!(exit_code, ExitCode::from(1));
        assert!(stderr.is_empty());
        let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
        assert!(rendered.contains("family: child-family"));
        assert!(rendered.contains("Pin check: FAIL"));
        assert!(!rendered.contains("parent-family"));
        assert_eq!(*runner.build_calls.borrow(), 0);
        assert_eq!(*runner.test_calls.borrow(), 0);
    }
}

#[test]
fn cargo_locates_excluded_child_as_its_own_workspace() {
    let temp_dir = fresh_temp_dir();
    let child_dir = excluded_child_workspace(&temp_dir);

    let located = RealCommandRunner
        .cargo_locate_project_workspace(&child_dir, &child_dir.join("Cargo.toml"))
        .expect("Cargo should locate the excluded child's workspace");

    assert_eq!(PathBuf::from(located.trim()), child_dir.join("Cargo.toml"));
}

#[test]
fn malformed_excluded_child_never_anchors_to_the_parent_policy() {
    let temp_dir = fresh_temp_dir();
    let child_dir = excluded_child_workspace(&temp_dir);
    fs::write(
        temp_dir.join("Cargo.toml"),
        "[workspace]\nmembers = []\nexclude = [\"./excluded\"]\n",
    )
    .expect("root manifest with normalized exclusion should write");
    fs::write(
        child_dir.join("Cargo.toml"),
        "[package\nname = \"broken\"\n",
    )
    .expect("malformed child manifest should write");
    let cli = Cli::parse_from(["cargo-barbican", "pin", "check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code =
        run_cli_with_runner(cli, &child_dir, &client, &runner, &mut stdout, &mut stderr)
            .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(!String::from_utf8_lossy(&stdout).contains("parent-family"));
    assert!(!String::from_utf8_lossy(&stderr).contains("parent-family"));
    assert!(String::from_utf8_lossy(&stderr).contains("Cargo.toml"));
}

#[test]
fn malformed_included_member_anchors_to_parent_and_cannot_skip_policy() {
    let temp_dir = fresh_temp_dir();
    let member_dir = member_workspace(&temp_dir);
    fs::write(
        member_dir.join("Cargo.toml"),
        "[package\nname = \"broken\"\n",
    )
    .expect("malformed member manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_packages(&[("serde", "1.0.228", true)]),
    )
    .expect("root lockfile should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        r#"[rust]

[[rust.families]]
name = "parent-family"
review_record = "docs/dependency-reviews/parent.md"

[rust.families.resolved]
serde = "1.0.228"
"#,
    )
    .expect("root policy should write");
    write_review_record(&temp_dir, "docs/dependency-reviews/parent.md");
    let cli = Cli::parse_from(["cargo-barbican", "pin", "check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code =
        run_cli_with_runner(cli, &member_dir, &client, &runner, &mut stdout, &mut stderr)
            .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(!String::from_utf8_lossy(&stdout).contains("skipping"));
    assert!(String::from_utf8_lossy(&stderr).contains("member/Cargo.toml"));
}

#[test]
fn valid_manifest_fails_closed_when_cargo_cannot_locate_its_workspace() {
    let cli = Cli::parse_from(["cargo-barbican", "pin", "check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default().with_workspace_manifest_error("locate failed");
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    assert!(
        String::from_utf8(stderr)
            .expect("stderr should be utf8")
            .contains("unable to locate Cargo workspace root")
    );
}
