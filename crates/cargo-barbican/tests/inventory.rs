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

struct FakeCommandRunner {
    frozen_metadata_result: Result<String, String>,
    frozen_metadata_calls: AtomicU64,
}

impl Default for FakeCommandRunner {
    fn default() -> Self {
        Self {
            frozen_metadata_result: Ok(default_metadata_json().to_owned()),
            frozen_metadata_calls: AtomicU64::new(0),
        }
    }
}

impl FakeCommandRunner {
    fn with_frozen_metadata(metadata: impl Into<String>) -> Self {
        Self {
            frozen_metadata_result: Ok(metadata.into()),
            frozen_metadata_calls: AtomicU64::new(0),
        }
    }

    fn with_frozen_metadata_error(message: impl Into<String>) -> Self {
        Self {
            frozen_metadata_result: Err(message.into()),
            frozen_metadata_calls: AtomicU64::new(0),
        }
    }

    fn frozen_metadata_calls(&self) -> u64 {
        self.frozen_metadata_calls.load(Ordering::Relaxed)
    }
}

impl CommandRunner for FakeCommandRunner {
    fn git_show(&self, _current_dir: &Path, object: &str) -> Result<String, RunnerError> {
        Err(runner_error(format!("unexpected git show for {object}")))
    }

    fn cargo_metadata(&self, _current_dir: &Path) -> Result<String, RunnerError> {
        Err(runner_error("unexpected cargo metadata"))
    }

    fn cargo_metadata_frozen(&self, _current_dir: &Path) -> Result<String, RunnerError> {
        self.frozen_metadata_calls.fetch_add(1, Ordering::Relaxed);
        self.frozen_metadata_result.clone().map_err(runner_error)
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

    fn cargo_audit_json(
        &self,
        _controlled_cwd: &Path,
        _lockfile_path: &Path,
    ) -> Result<cargo_barbican::CommandOutput, RunnerError> {
        Err(runner_error("unexpected cargo audit json"))
    }

    fn cargo_deny_json(
        &self,
        _current_dir: &Path,
        _config_path: &Path,
        _checks: &[barbican::CargoDenyCheck],
    ) -> Result<cargo_barbican::CommandOutput, RunnerError> {
        Err(runner_error("unexpected cargo deny json"))
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

    let runner = FakeCommandRunner::with_frozen_metadata(surface_metadata_json());
    let (exit_code, stdout, stderr) = run_inventory_with_runner(&temp_dir, &runner);

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert!(stdout.contains("Dependency inventory:"));
    assert!(stdout.contains("reviewed-targets.toml: configured"));
    assert!(stdout.contains("serde crates/app/Cargo.toml:dependencies =1.0.228 [exact inherited; source=workspace; effective-source=registry]"));
    assert!(stdout.contains("alt crates/app/Cargo.toml:dependencies 1 [not exact; source=alternate-registry; effective-source=alternate-registry]"));
    assert!(stdout.contains("local crates/app/Cargo.toml:dependencies (no version) [not applicable; source=path; effective-source=path]"));
    assert!(stdout.contains("live graph surface status: collected via cargo metadata --frozen"));
    assert!(stdout.contains("serde@1.0.228 proc-macro (declared)"));
    assert!(stdout.contains("loose@0.1.0 build-rs (undeclared)"));
    assert!(stdout.contains("local@0.1.0 native-sys (undeclared)"));
    assert!(!stdout.contains("app@0.1.0 build-rs"));
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
    assert!(!observational.contains("live execution surface is not declared"));
    assert!(policy.contains(
        "missing review record for family serde-family: docs/dependency-reviews/serde.md"
    ));
    assert!(
        policy.contains(
            "resolved crates.io package is not covered by any reviewed family: loose@0.1.0"
        )
    );
    assert!(policy.contains(
        "live execution surface is not declared in reviewed policy: loose@0.1.0 build-rs"
    ));
    assert!(policy.contains(
        "live execution surface is not declared in reviewed policy: local@0.1.0 native-sys"
    ));
    assert!(!policy.contains(
        "live execution surface is not declared in reviewed policy: serde@1.0.228 proc-macro"
    ));
    assert!(
        !policy.contains(
            "live execution surface is not declared in reviewed policy: app@0.1.0 build-rs"
        )
    );
    assert!(!policy.contains("direct dependency loose"));
    assert!(!policy.contains("non-crates.io dependency source for local@0.1.0"));
    assert!(
        stdout.contains("Review each finding or gap, update reviewed-targets.toml and review records, then run `cargo barbican verify`.")
    );
}

#[test]
fn inventory_reports_advisory_exception_and_delegation_state() {
    let temp_dir = fresh_temp_dir();
    write_inventory_fixture(&temp_dir);
    fs::create_dir_all(temp_dir.join("docs/dependency-reviews"))
        .expect("review record dir should create");
    fs::write(
        temp_dir.join("docs/dependency-reviews/serde.md"),
        "reviewed serde advisory exception\n",
    )
    .expect("review record should write");
    fs::write(
        temp_dir.join("barbican.toml"),
        r#"
[delegates]
unmanaged_delegated_policy = "deny"

[delegates.advisories]
lockfile_scanner = "both"

[delegates.cargo_deny]
checks = ["advisories", "bans"]
"#,
    )
    .expect("config should write");
    fs::write(
        temp_dir.join("deny.toml"),
        r#"
[advisories]
ignore = [{ id = "RUSTSEC-2026-0001", reason = "native reviewed elsewhere" }]
"#,
    )
    .expect("deny config should write");
    fs::create_dir_all(temp_dir.join(".cargo")).expect("cargo config dir should create");
    fs::write(
        temp_dir.join(".cargo/audit.toml"),
        r#"
[advisories]
ignore = ["RUSTSEC-2026-0002"]
"#,
    )
    .expect("audit config should write");
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

[rust.families.allowed_advisories]
serde = [{ id = "RUSTSEC-2099-0001", review_by = "2099-01-01" }]

[[rust.families]]
name = "loose-family"
review_record = "docs/dependency-reviews/loose.md"

[rust.families.resolved]
loose = { version = "0.1.0", checksum_sha256 = "1111111111111111111111111111111111111111111111111111111111111111" }

[rust.families.allowed_advisories]
loose = [{ id = "RUSTSEC-2099-0002", review_by = "2099-01-01" }]

[[rust.families]]
name = "stale-family"
review_record = "docs/dependency-reviews/stale.md"

[rust.families.resolved]
stale = { version = "1.0.0", checksum_sha256 = "2222222222222222222222222222222222222222222222222222222222222222" }

[rust.families.allowed_advisories]
stale = [{ id = "RUSTSEC-2000-0001", review_by = "2000-01-01" }]
"#,
    )
    .expect("reviewed targets should write");

    let runner = FakeCommandRunner::default();
    let (exit_code, stdout, stderr) = run_inventory_with_runner(&temp_dir, &runner);

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert!(stdout.contains(
        "deny.toml: configured; cargo-deny non-advisory posture would use checked-in deny.toml"
    ));
    assert!(stdout.contains("Reviewed advisory exceptions:"));
    assert!(stdout.contains("expiry window: soon-to-expire means review_by within 30 day(s)"));
    assert!(stdout.contains("stale means the exception's crate@version is not present"));
    assert!(stdout.contains("serde@1.0.228 RUSTSEC-2099-0001 family=serde-family review_record=docs/dependency-reviews/serde.md review_by=2099-01-01 status=active resolved-target=matched review-record=exists"));
    assert!(stdout.contains("loose@0.1.0 RUSTSEC-2099-0002 family=loose-family review_record=docs/dependency-reviews/loose.md review_by=2099-01-01 status=active resolved-target=matched review-record=missing"));
    assert!(stdout.contains("stale@1.0.0 RUSTSEC-2000-0001 family=stale-family review_record=docs/dependency-reviews/stale.md review_by=2000-01-01 status=stale resolved-target=not matched review-record=missing"));
    assert!(stdout.contains("Advisory delegation:"));
    assert!(stdout.contains("lockfile scanner: both"));
    assert!(stdout.contains("cargo-deny checks: advisories, bans"));
    assert!(stdout.contains("unmanaged delegated policy: deny"));
    assert!(stdout.contains("native delegated advisory ignores:"));
    assert!(stdout.contains("deny.toml ignores RUSTSEC-2026-0001"));
    assert!(stdout.contains(".cargo/audit.toml ignores RUSTSEC-2026-0002"));
}

#[test]
fn inventory_without_reviewed_targets_reports_no_policy() {
    let temp_dir = fresh_temp_dir();
    write_inventory_fixture(&temp_dir);

    let runner = FakeCommandRunner::with_frozen_metadata(surface_metadata_json());
    let (exit_code, stdout, stderr) = run_inventory_with_runner(&temp_dir, &runner);

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert!(stdout.contains("reviewed-targets.toml: not configured"));
    assert!(stdout.contains(
        "deny.toml: not configured; cargo-deny non-advisory posture would use Barbican's generated default base"
    ));
    assert!(stdout.contains("Reviewed advisory exceptions:"));
    assert!(stdout.contains("exceptions: none"));
    assert!(stdout.contains("Advisory delegation:"));
    assert!(stdout.contains("lockfile scanner: cargo-deny"));
    assert!(stdout.contains("cargo-deny checks: advisories, bans, sources"));
    assert!(stdout.contains("unmanaged delegated policy: warn"));
    assert!(stdout.contains("native delegated advisory ignores: none"));
    assert!(stdout.contains("live graph surface status: collected via cargo metadata --frozen"));
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
    assert!(observational.contains(
        "live execution surface is not declared in reviewed policy: serde@1.0.228 proc-macro"
    ));
    assert!(observational.contains(
        "live execution surface is not declared in reviewed policy: loose@0.1.0 build-rs"
    ));
    assert!(observational.contains(
        "live execution surface is not declared in reviewed policy: local@0.1.0 native-sys"
    ));
    assert!(
        !observational.contains(
            "live execution surface is not declared in reviewed policy: app@0.1.0 build-rs"
        )
    );
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
    assert!(stdout.contains("live graph surface status: collected via cargo metadata --frozen"));
    assert!(stdout.contains("live graph surfaces: collected"));
    assert!(stdout.contains(
        "live graph surface findings: no undeclared build.rs / proc-macro / native-sys surfaces detected"
    ));
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
            "non-crates.io dependency source for control-source@0.1.0: git+https://example.invalid/control\\x1b[1A\\x1b[2K\\n  none\\x2028\\x2029"
        ),
        "{stdout}"
    );
    assert!(
        stdout.contains("policy-family: 1 direct, 1 resolved"),
        "{stdout}"
    );
}

#[test]
fn inventory_renders_offline_report_when_frozen_metadata_fails() {
    let temp_dir = fresh_temp_dir();
    write_inventory_fixture(&temp_dir);
    let cli = Cli::parse_from(["cargo-barbican", "inventory"]);
    let client = FakeCratesIoClient;
    let runner = FakeCommandRunner::with_frozen_metadata_error(
        "the lock file needs to be updated but --frozen was passed\u{9b}[2K",
    );
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");
    let stdout = String::from_utf8(stdout).expect("stdout should be utf8");
    let stderr = String::from_utf8(stderr).expect("stderr should be utf8");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert_eq!(runner.frozen_metadata_calls(), 1);
    assert!(stderr.is_empty());
    assert!(stdout.contains("Dependency inventory:"));
    assert!(
        stdout.contains(
            "live graph surfaces: NOT COLLECTED - investigate before trusting this report"
        )
    );
    assert!(stdout.contains(
        "live graph surface status: not collected; live graph surface collection failed: the lock file needs to be updated but --frozen was passed\\x9b[2K"
    ));
    assert!(stdout.contains(
        "live graph surface remediation: resolve the reported graph or metadata issue, then rerun inventory"
    ));
    assert!(stdout.contains("Direct dependencies:"));
    assert!(stdout.contains("Policy coverage gaps:"));
    assert!(
        stdout.contains(
            "Resolve live graph surface collection before trusting this inventory report."
        )
    );
}

#[test]
fn inventory_not_collected_state_prevents_clean_next_action() {
    let temp_dir = fresh_temp_dir();
    write_workspace_only_fixture(&temp_dir);
    fs::write(temp_dir.join("reviewed-targets.toml"), "[rust]\n").expect("policy should write");

    let runner = FakeCommandRunner::with_frozen_metadata_error("invalid metadata package: évil");
    let (exit_code, stdout, stderr) = run_inventory_with_runner(&temp_dir, &runner);

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert!(stdout.contains("reviewed-targets.toml: configured"));
    assert!(stdout.contains("Observational findings:\n  none\n"));
    assert!(stdout.contains("Policy coverage gaps:\n  none\n"));
    assert!(
        stdout.contains(
            "live graph surfaces: NOT COLLECTED - investigate before trusting this report"
        )
    );
    assert!(stdout.contains(
        "live graph surface status: not collected; live graph surface collection failed: invalid metadata package: évil"
    ));
    assert!(
        stdout.contains(
            "Resolve live graph surface collection before trusting this inventory report."
        )
    );
    assert!(
        !stdout.contains(
            "Run `cargo barbican pin-check` or `cargo barbican verify` to enforce policy."
        )
    );
}

#[test]
fn inventory_fails_on_malformed_reviewed_targets() {
    let temp_dir = fresh_temp_dir();
    write_inventory_fixture(&temp_dir);
    fs::write(temp_dir.join("reviewed-targets.toml"), "not toml").expect("policy should write");

    let cli = Cli::parse_from(["cargo-barbican", "inventory"]);
    let client = FakeCratesIoClient;
    let runner = FakeCommandRunner::default();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let error = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect_err("command should fail");

    assert!(error.to_string().contains("reviewed-targets.toml"));
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
}

#[test]
fn inventory_escapes_malformed_reviewed_targets_parse_diagnostics() {
    let temp_dir = fresh_temp_dir();
    write_inventory_fixture(&temp_dir);
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        "[rust]\n\u{001b} = \"pwned\"\n",
    )
    .expect("policy should write");

    let cli = Cli::parse_from(["cargo-barbican", "inventory"]);
    let client = FakeCratesIoClient;
    let runner = FakeCommandRunner::default();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let error = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect_err("command should fail");
    let rendered = error.to_string();

    assert!(rendered.contains("reviewed-targets.toml"));
    assert!(!rendered.contains('\u{001b}'));
    assert!(rendered.contains("\\x1b"));
    assert!(rendered.contains('\n'));
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
    let runner = FakeCommandRunner::default();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let error = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect_err("command should fail");

    assert_eq!(error.to_string(), "Cargo.lock: lockfile not found");
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
}

fn run_inventory(temp_dir: &Path) -> (ExitCode, String, String) {
    let runner = FakeCommandRunner::default();

    run_inventory_with_runner(temp_dir, &runner)
}

fn run_inventory_with_runner(
    temp_dir: &Path,
    runner: &FakeCommandRunner,
) -> (ExitCode, String, String) {
    let cli = Cli::parse_from(["cargo-barbican", "inventory"]);
    let client = FakeCratesIoClient;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, temp_dir, &client, runner, &mut stdout, &mut stderr)
        .expect("command should run");
    assert_eq!(runner.frozen_metadata_calls(), 1);

    (
        exit_code,
        String::from_utf8(stdout).expect("stdout should be utf8"),
        String::from_utf8(stderr).expect("stderr should be utf8"),
    )
}

fn default_metadata_json() -> &'static str {
    r#"{
  "packages": [],
  "workspace_members": [],
  "resolve": {"nodes": []}
}"#
}

fn surface_metadata_json() -> &'static str {
    r#"{
  "packages": [
    {
      "name": "app",
      "id": "path+file:///workspace/crates/app#app@0.1.0",
      "version": "0.1.0",
      "targets": [{"kind": ["custom-build"]}]
    },
    {
      "name": "explicit-app",
      "id": "path+file:///workspace/app#explicit-app@0.1.0",
      "version": "0.1.0",
      "targets": []
    },
    {
      "name": "serde",
      "id": "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228",
      "version": "1.0.228",
      "targets": [{"kind": ["proc-macro"]}]
    },
    {
      "name": "loose",
      "id": "registry+https://github.com/rust-lang/crates.io-index#loose@0.1.0",
      "version": "0.1.0",
      "targets": [{"kind": ["custom-build"]}]
    },
    {
      "name": "local",
      "id": "path+file:///workspace/crates/local#local@0.1.0",
      "version": "0.1.0",
      "links": "local",
      "targets": []
    }
  ],
  "workspace_members": ["path+file:///workspace/crates/app#app@0.1.0"],
  "resolve": {"nodes": []}
}"#
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
source = "git+https://example.invalid/control\u001b[1A\u001b[2K\n  none\u2028\u2029"

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
name = "policy-family"
review_record = "docs/dependency-reviews/control-record.md"

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
