use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use barbican::{CrateRelease, CratesIoClient, CratesIoClientError, ExactCrateSpec};
use cargo_barbican::{Cli, CommandRunner, RunnerError, run_cli_with_runner};
use clap::Parser;

#[derive(Default)]
struct FakeCratesIoClient;

impl CratesIoClient for FakeCratesIoClient {
    fn fetch_release(&self, spec: &ExactCrateSpec) -> Result<CrateRelease, CratesIoClientError> {
        Err(CratesIoClientError::Transport {
            reason: format!("unexpected fetch for {spec}"),
        })
    }
}

#[derive(Default)]
struct FakeCommandRunner;

impl CommandRunner for FakeCommandRunner {
    fn git_show(&self, _current_dir: &Path, object: &str) -> Result<String, RunnerError> {
        Err(runner_error(format!("unexpected git show for {object}")))
    }

    fn cargo_metadata(&self, _current_dir: &Path) -> Result<String, RunnerError> {
        Err(runner_error("unexpected cargo metadata"))
    }

    fn cargo_update_precise(
        &self,
        _current_dir: &Path,
        package_id: &str,
        version: &str,
    ) -> Result<(), RunnerError> {
        Err(runner_error(format!(
            "unexpected cargo update for {package_id}@{version}"
        )))
    }

    fn cargo_generate_lockfile(&self, _current_dir: &Path) -> Result<(), RunnerError> {
        Err(runner_error("unexpected cargo generate-lockfile"))
    }

    fn cargo_tree(&self, _current_dir: &Path) -> Result<String, RunnerError> {
        Err(runner_error("unexpected cargo tree"))
    }

    fn git_diff(&self, _current_dir: &Path, _paths: &[PathBuf]) -> Result<String, RunnerError> {
        Err(runner_error("unexpected git diff"))
    }

    fn cargo_audit(&self, _current_dir: &Path) -> Result<String, RunnerError> {
        Err(runner_error("unexpected cargo audit"))
    }

    fn cargo_deny(&self, _current_dir: &Path) -> Result<(), RunnerError> {
        Err(runner_error("unexpected cargo deny"))
    }

    fn cargo_build_locked(&self, _current_dir: &Path) -> Result<(), RunnerError> {
        Err(runner_error("unexpected cargo build"))
    }

    fn cargo_test_locked(&self, _current_dir: &Path) -> Result<(), RunnerError> {
        Err(runner_error("unexpected cargo test"))
    }
}

fn runner_error(message: impl Into<String>) -> RunnerError {
    RunnerError::Exited {
        code: Some(1),
        stdout: String::new(),
        stderr: message.into(),
    }
}

#[test]
fn inventory_reports_policy_coverage_and_gaps() {
    let temp_dir = fresh_temp_dir();
    write_inventory_fixture(&temp_dir);
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        r#"
[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/serde.md"

[rust.families.direct]
serde = "=1.0.228"

[rust.families.resolved]
serde = { version = "1.0.228", checksum_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }

[rust.families.allowed_surfaces]
serde = ["proc-macro"]
"#,
    )
    .expect("reviewed targets should write");

    let (exit_code, stdout, stderr) = run_inventory(&temp_dir);

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert!(stdout.contains("Dependency inventory:"));
    assert!(stdout.contains("reviewed-targets.toml: configured"));
    assert!(stdout.contains("serde crates/app/Cargo.toml:dependencies =1.0.228 [exact inherited; source=workspace; effective-source=registry]"));
    assert!(stdout.contains("alt crates/app/Cargo.toml:dependencies 1 [not exact; source=alternate-registry; effective-source=alternate-registry]"));
    assert!(stdout.contains("local crates/app/Cargo.toml:dependencies (no version) [not applicable; source=path; effective-source=path]"));
    assert!(stdout.contains("live graph surfaces: not collected in this offline slice"));
    assert!(stdout.contains("serde@1.0.228 proc-macro allowed by serde-family"));
    assert!(stdout.contains(
        "serde-family: 1 direct, 1 resolved, docs/dependency-reviews/serde.md (record missing)"
    ));
    let observational =
        section_between(&stdout, "Observational findings:", "Policy coverage gaps:");
    let policy = section_between(&stdout, "Policy coverage gaps:", "Suggested next actions:");
    assert!(observational.contains(
        "direct dependency loose at crates/app/Cargo.toml:dev-dependencies is not exact: 0.1"
    ));
    assert!(observational.contains("non-crates.io dependency source for local@0.1.0"));
    assert!(!observational.contains("non-crates.io dependency source for app@0.1.0: (none)"));
    assert!(observational.contains("non-crates.io dependency source for app@0.2.0"));
    assert!(observational.contains(
        "non-crates.io dependency source for git-crate@0.1.0: git+https://example.invalid/git-crate"
    ));
    assert!(observational.contains(
        "non-crates.io dependency source for app@0.1.0: git+https://example.invalid/app"
    ));
    assert!(!observational.contains("non-crates.io dependency source for explicit-app@0.1.0"));
    assert!(!observational.contains("missing review record for family serde-family"));
    assert!(!observational.contains("resolved crates.io package is not covered"));
    assert!(policy.contains(
        "missing review record for family serde-family: docs/dependency-reviews/serde.md"
    ));
    assert!(
        policy.contains(
            "resolved crates.io package is not covered by any reviewed family: loose@0.1.0"
        )
    );
    assert!(!policy.contains("direct dependency loose"));
    assert!(!policy.contains("non-crates.io dependency source for local@0.1.0"));
    assert!(
        stdout.contains("Review each finding or gap, update reviewed-targets.toml and review records, then run `cargo barbican verify`.")
    );
}

#[test]
fn inventory_without_reviewed_targets_reports_no_policy() {
    let temp_dir = fresh_temp_dir();
    write_inventory_fixture(&temp_dir);

    let (exit_code, stdout, stderr) = run_inventory(&temp_dir);

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert!(stdout.contains("reviewed-targets.toml: not configured"));
    assert!(stdout.contains("no policy configured yet; resolved crates are not classified as slipped-through policy gaps"));
    let observational =
        section_between(&stdout, "Observational findings:", "Policy coverage gaps:");
    assert!(observational.contains(
        "direct dependency loose at crates/app/Cargo.toml:dev-dependencies is not exact: 0.1"
    ));
    assert!(observational.contains("non-crates.io dependency source for local@0.1.0"));
    assert!(!observational.contains("non-crates.io dependency source for app@0.1.0: (none)"));
    assert!(observational.contains("non-crates.io dependency source for app@0.2.0"));
    assert!(observational.contains(
        "non-crates.io dependency source for git-crate@0.1.0: git+https://example.invalid/git-crate"
    ));
    assert!(observational.contains(
        "non-crates.io dependency source for app@0.1.0: git+https://example.invalid/app"
    ));
    assert!(!observational.contains("non-crates.io dependency source for explicit-app@0.1.0"));
    assert!(stdout.contains("Policy coverage gaps:\n  none\n"));
}

#[test]
fn inventory_reports_configured_empty_policy_without_gaps() {
    let temp_dir = fresh_temp_dir();
    write_workspace_only_fixture(&temp_dir);
    fs::write(temp_dir.join("reviewed-targets.toml"), "[rust]\n").expect("policy should write");

    let (exit_code, stdout, stderr) = run_inventory(&temp_dir);

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert!(stdout.contains("reviewed-targets.toml: configured"));
    assert!(stdout.contains("reviewed-targets.toml has no active Rust families"));
    assert!(stdout.contains("declared allowed surfaces: none"));
    assert!(stdout.contains("Observational findings:\n  none\n"));
    assert!(stdout.contains("Policy coverage gaps:\n  none\n"));
    assert!(
        stdout.contains(
            "Run `cargo barbican pin-check` or `cargo barbican verify` to enforce policy."
        )
    );
}

#[test]
fn inventory_discovers_workspace_members_from_non_crates_globs() {
    let temp_dir = fresh_temp_dir();
    write_libs_glob_fixture(&temp_dir);

    let (exit_code, stdout, stderr) = run_inventory(&temp_dir);

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert!(stdout.contains("glob-member libs/glob-member/Cargo.toml:dependencies =0.1.0"));
    assert!(!stdout.contains("non-crates.io dependency source for glob-member@0.1.0: (none)"));
}

#[test]
fn inventory_prunes_git_and_target_dirs_during_workspace_discovery() {
    let temp_dir = fresh_temp_dir();
    write_pruned_dirs_fixture(&temp_dir);

    let (exit_code, stdout, stderr) = run_inventory(&temp_dir);

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert!(stdout.contains("real-member crates/real-member/Cargo.toml:dependencies =0.1.0"));
    assert!(!stdout.contains("target-phantom crates/real-member/target/phantom/Cargo.toml"));
    assert!(!stdout.contains("git-phantom crates/real-member/.git/phantom/Cargo.toml"));
    assert!(stdout.contains("non-crates.io dependency source for target-phantom@0.1.0: (none)"));
    assert!(stdout.contains("non-crates.io dependency source for git-phantom@0.1.0: (none)"));
}

#[test]
fn inventory_currently_discovers_nested_non_member_manifests_under_walked_roots() {
    let temp_dir = fresh_temp_dir();
    write_nested_non_member_fixture(&temp_dir);

    let (exit_code, stdout, stderr) = run_inventory(&temp_dir);

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert!(stdout.contains(
        "nested-fixture crates/member/examples/nested-fixture/Cargo.toml:dependencies 0.1 [not exact; source=registry; effective-source=registry]"
    ));
    assert!(stdout.contains(
        "direct dependency nested-fixture at crates/member/examples/nested-fixture/Cargo.toml:dependencies is not exact: 0.1"
    ));
}

#[test]
fn inventory_escapes_control_characters_in_rendered_fields() {
    let temp_dir = fresh_temp_dir();
    write_control_character_fixture(&temp_dir);

    let (exit_code, stdout, stderr) = run_inventory(&temp_dir);

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert!(!stdout.contains('\u{1b}'));
    assert!(
        stdout.contains(
            "control_dep crates/app/Cargo.toml:dependencies 0.1\\n  none [not exact; source=registry; effective-source=registry]"
        ),
        "{stdout}"
    );
    assert!(
        stdout.contains(
            "non-crates.io dependency source for control-source@0.1.0: git+https://example.invalid/control\\x1b[1A\\x1b[2K\\n  none"
        ),
        "{stdout}"
    );
    assert!(
        stdout.contains(
            "policy\\nfamily: 1 direct, 1 resolved, docs/dependency-reviews/control\\nrecord.md (record missing)"
        ),
        "{stdout}"
    );
    assert!(
        stdout.contains(
            "missing review record for family policy\\nfamily: docs/dependency-reviews/control\\nrecord.md"
        ),
        "{stdout}"
    );
}

#[test]
fn inventory_fails_on_malformed_reviewed_targets() {
    let temp_dir = fresh_temp_dir();
    write_inventory_fixture(&temp_dir);
    fs::write(temp_dir.join("reviewed-targets.toml"), "not toml").expect("policy should write");

    let cli = Cli::parse_from(["cargo-barbican", "inventory"]);
    let client = FakeCratesIoClient;
    let runner = FakeCommandRunner;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let error = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect_err("command should fail");

    assert!(error.to_string().contains("reviewed-targets.toml"));
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
}

#[test]
fn inventory_fails_when_lockfile_is_missing() {
    let temp_dir = fresh_temp_dir();
    fs::write(
        temp_dir.join("Cargo.toml"),
        "[workspace]\nmembers = []\nresolver = \"3\"\n",
    )
    .expect("manifest should write");

    let cli = Cli::parse_from(["cargo-barbican", "inventory"]);
    let client = FakeCratesIoClient;
    let runner = FakeCommandRunner;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let error = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect_err("command should fail");

    assert_eq!(error.to_string(), "Cargo.lock: lockfile not found");
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
}

fn run_inventory(temp_dir: &Path) -> (ExitCode, String, String) {
    let cli = Cli::parse_from(["cargo-barbican", "inventory"]);
    let client = FakeCratesIoClient;
    let runner = FakeCommandRunner;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    (
        exit_code,
        String::from_utf8(stdout).expect("stdout should be utf8"),
        String::from_utf8(stderr).expect("stderr should be utf8"),
    )
}

fn write_inventory_fixture(root: &Path) {
    fs::create_dir_all(root.join("crates/app")).expect("app dir should create");
    fs::create_dir_all(root.join("app")).expect("explicit app dir should create");
    fs::write(
        root.join("Cargo.toml"),
        r#"
[workspace]
members = ["crates/*", "app"]
resolver = "3"

[workspace.package]
version = "0.1.0"

[workspace.dependencies]
serde = "=1.0.228"
"#,
    )
    .expect("root manifest should write");
    fs::write(
        root.join("crates/app/Cargo.toml"),
        r#"
[package]
name = "app"
version = "0.1.0"
edition = "2024"

[dependencies]
alt = { version = "1", registry = "internal" }
serde = { workspace = true }
local = { path = "../local" }

[dev-dependencies]
loose = "0.1"
"#,
    )
    .expect("member manifest should write");
    fs::write(
        root.join("app/Cargo.toml"),
        r#"
[package]
name = "explicit-app"
version = { workspace = true }
edition = "2024"
"#,
    )
    .expect("explicit member manifest should write");
    fs::write(
        root.join("Cargo.lock"),
        r#"
version = 4

[[package]]
name = "app"
version = "0.1.0"

[[package]]
name = "app"
version = "0.2.0"

[[package]]
name = "app"
version = "0.1.0"
source = "git+https://example.invalid/app"

[[package]]
name = "git-crate"
version = "0.1.0"
source = "git+https://example.invalid/git-crate"

[[package]]
name = "explicit-app"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

[[package]]
name = "loose"
version = "0.1.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "1111111111111111111111111111111111111111111111111111111111111111"

[[package]]
name = "local"
version = "0.1.0"
"#,
    )
    .expect("lockfile should write");
}

fn write_workspace_only_fixture(root: &Path) {
    fs::create_dir_all(root.join("crates/app")).expect("app dir should create");
    fs::write(
        root.join("Cargo.toml"),
        r#"
[workspace]
members = ["crates/*"]
resolver = "3"
"#,
    )
    .expect("root manifest should write");
    fs::write(
        root.join("crates/app/Cargo.toml"),
        r#"
[package]
name = "app"
version = "0.1.0"
edition = "2024"
"#,
    )
    .expect("member manifest should write");
    fs::write(
        root.join("Cargo.lock"),
        r#"
version = 4

[[package]]
name = "app"
version = "0.1.0"
"#,
    )
    .expect("lockfile should write");
}

fn write_libs_glob_fixture(root: &Path) {
    fs::create_dir_all(root.join("libs/glob-member")).expect("member dir should create");
    fs::write(
        root.join("Cargo.toml"),
        r#"
[workspace]
members = ["libs/*"]
resolver = "3"
"#,
    )
    .expect("root manifest should write");
    fs::write(
        root.join("libs/glob-member/Cargo.toml"),
        r#"
[package]
name = "glob-member"
version = "0.1.0"
edition = "2024"

[dependencies]
glob-member = "=0.1.0"
"#,
    )
    .expect("member manifest should write");
    fs::write(
        root.join("Cargo.lock"),
        r#"
version = 4

[[package]]
name = "glob-member"
version = "0.1.0"
"#,
    )
    .expect("lockfile should write");
}

fn write_pruned_dirs_fixture(root: &Path) {
    fs::create_dir_all(root.join("crates/real-member")).expect("member dir should create");
    fs::create_dir_all(root.join("crates/real-member/target/phantom"))
        .expect("target phantom dir should create");
    fs::create_dir_all(root.join("crates/real-member/.git/phantom"))
        .expect("git phantom dir should create");
    fs::write(
        root.join("Cargo.toml"),
        r#"
[workspace]
members = ["crates/*"]
resolver = "3"
"#,
    )
    .expect("root manifest should write");
    fs::write(
        root.join("crates/real-member/Cargo.toml"),
        r#"
[package]
name = "real-member"
version = "0.1.0"
edition = "2024"

[dependencies]
real-member = "=0.1.0"
"#,
    )
    .expect("member manifest should write");
    fs::write(
        root.join("crates/real-member/target/phantom/Cargo.toml"),
        r#"
[package]
name = "target-phantom"
version = "0.1.0"
edition = "2024"
"#,
    )
    .expect("target phantom manifest should write");
    fs::write(
        root.join("crates/real-member/.git/phantom/Cargo.toml"),
        r#"
[package]
name = "git-phantom"
version = "0.1.0"
edition = "2024"
"#,
    )
    .expect("git phantom manifest should write");
    fs::write(
        root.join("Cargo.lock"),
        r#"
version = 4

[[package]]
name = "real-member"
version = "0.1.0"

[[package]]
name = "target-phantom"
version = "0.1.0"

[[package]]
name = "git-phantom"
version = "0.1.0"
"#,
    )
    .expect("lockfile should write");
}

fn write_nested_non_member_fixture(root: &Path) {
    fs::create_dir_all(root.join("crates/member/examples/nested-fixture"))
        .expect("nested fixture dir should create");
    fs::write(
        root.join("Cargo.toml"),
        r#"
[workspace]
members = ["crates/*"]
resolver = "3"
"#,
    )
    .expect("root manifest should write");
    fs::write(
        root.join("crates/member/Cargo.toml"),
        r#"
[package]
name = "member"
version = "0.1.0"
edition = "2024"
"#,
    )
    .expect("member manifest should write");
    fs::write(
        root.join("crates/member/examples/nested-fixture/Cargo.toml"),
        r#"
[package]
name = "nested-fixture"
version = "0.1.0"
edition = "2024"

[dependencies]
nested-fixture = "0.1"
"#,
    )
    .expect("nested manifest should write");
    fs::write(
        root.join("Cargo.lock"),
        r#"
version = 4

[[package]]
name = "member"
version = "0.1.0"

[[package]]
name = "nested-fixture"
version = "0.1.0"
"#,
    )
    .expect("lockfile should write");
}

fn write_control_character_fixture(root: &Path) {
    fs::create_dir_all(root.join("crates/app")).expect("app dir should create");
    fs::write(
        root.join("Cargo.toml"),
        r#"
[workspace]
members = ["crates/*"]
resolver = "3"
"#,
    )
    .expect("root manifest should write");
    fs::write(
        root.join("crates/app/Cargo.toml"),
        r#"
[package]
name = "app"
version = "0.1.0"
edition = "2024"

[dependencies]
control_dep = "0.1\n  none"
"#,
    )
    .expect("member manifest should write");
    fs::write(
        root.join("Cargo.lock"),
        r#"
version = 4

[[package]]
name = "app"
version = "0.1.0"

[[package]]
name = "control-source"
version = "0.1.0"
source = "git+https://example.invalid/control\u001b[1A\u001b[2K\n  none"

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
"#,
    )
    .expect("lockfile should write");
    fs::write(
        root.join("reviewed-targets.toml"),
        r#"
[rust]

[[rust.families]]
name = "policy\nfamily"
review_record = "docs/dependency-reviews/control\nrecord.md"

[rust.families.direct]
serde = "=1.0.228"

[rust.families.resolved]
serde = { version = "1.0.228", checksum_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }
"#,
    )
    .expect("reviewed targets should write");
}

fn fresh_temp_dir() -> PathBuf {
    static NEXT_ID: AtomicU64 = AtomicU64::new(0);
    let mut path = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after epoch")
        .as_nanos();
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    path.push(format!("cargo-barbican-inventory-test-{nanos}-{id}"));
    fs::create_dir_all(&path).expect("temp dir should create");
    path
}

fn section_between<'a>(text: &'a str, start: &str, end: &str) -> &'a str {
    let section_start = text.find(start).expect("section should start");
    let after_start = &text[section_start + start.len()..];
    let section_end = after_start.find(end).expect("section should end");

    &after_start[..section_end]
}
