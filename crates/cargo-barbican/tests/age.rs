use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::OnceLock;
use std::sync::mpsc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use barbican::{
    CrateRelease, CratesIoClient, CratesIoClientError, ExactCrateSpec, parse_version_response_body,
};
use cargo_barbican::{Cli, CommandRunner, UreqCratesIoClient, run_cli_with_runner};
use clap::Parser;

#[derive(Default)]
struct FakeCratesIoClient {
    responses: HashMap<String, Result<CrateRelease, CratesIoClientError>>,
    fetches: RefCell<Vec<String>>,
}

impl FakeCratesIoClient {
    fn with_release(mut self, spec: &str, published_at: &str, yanked: bool) -> Self {
        self.responses.insert(
            spec.to_owned(),
            Ok(parse_version_response_body(&format!(
                r#"{{"version":{{"created_at":"{published_at}","yanked":{yanked}}}}}"#
            ))
            .expect("fake response should parse")),
        );
        self
    }

    fn with_error(mut self, spec: &str, error: CratesIoClientError) -> Self {
        self.responses.insert(spec.to_owned(), Err(error));
        self
    }

    fn recorded_fetches(&self) -> Vec<String> {
        self.fetches.borrow().clone()
    }
}

impl CratesIoClient for FakeCratesIoClient {
    fn fetch_release(&self, spec: &ExactCrateSpec) -> Result<CrateRelease, CratesIoClientError> {
        self.fetches.borrow_mut().push(spec.to_string());
        self.responses
            .get(&spec.to_string())
            .cloned()
            .unwrap_or_else(|| {
                Err(CratesIoClientError::Transport {
                    reason: "missing fake response".to_owned(),
                })
            })
    }
}

struct FakeCommandRunner {
    git_show_results: HashMap<String, Result<String, String>>,
    cargo_metadata_result: Result<String, String>,
    cargo_update_result: Result<(), String>,
    cargo_update_lockfile_text: Option<String>,
    git_diff_result: Result<String, String>,
    cargo_audit_result: Result<(), String>,
    cargo_deny_result: Result<(), String>,
    cargo_build_result: Result<(), String>,
    cargo_test_result: Result<(), String>,
    cargo_updates: RefCell<Vec<(String, String)>>,
    git_diff_paths: RefCell<Vec<PathBuf>>,
    audit_calls: RefCell<usize>,
    deny_calls: RefCell<usize>,
    build_calls: RefCell<usize>,
    test_calls: RefCell<usize>,
}

impl Default for FakeCommandRunner {
    fn default() -> Self {
        Self {
            git_show_results: HashMap::new(),
            cargo_metadata_result: Ok(metadata_with_packages(&[])),
            cargo_update_result: Ok(()),
            cargo_update_lockfile_text: None,
            git_diff_result: Ok(String::new()),
            cargo_audit_result: Ok(()),
            cargo_deny_result: Ok(()),
            cargo_build_result: Ok(()),
            cargo_test_result: Ok(()),
            cargo_updates: RefCell::new(Vec::new()),
            git_diff_paths: RefCell::new(Vec::new()),
            audit_calls: RefCell::new(0),
            deny_calls: RefCell::new(0),
            build_calls: RefCell::new(0),
            test_calls: RefCell::new(0),
        }
    }
}

impl FakeCommandRunner {
    fn with_git_show(mut self, object: &str, text: &str) -> Self {
        self.git_show_results
            .insert(object.to_owned(), Ok(text.to_owned()));
        self
    }

    fn with_git_show_error(mut self, object: &str, detail: &str) -> Self {
        self.git_show_results
            .insert(object.to_owned(), Err(detail.to_owned()));
        self
    }

    fn with_cargo_metadata(mut self, text: &str) -> Self {
        self.cargo_metadata_result = Ok(text.to_owned());
        self
    }

    fn with_git_diff(mut self, diff: &str) -> Self {
        self.git_diff_result = Ok(diff.to_owned());
        self
    }

    fn with_updated_lockfile(mut self, text: &str) -> Self {
        self.cargo_update_lockfile_text = Some(text.to_owned());
        self
    }

    fn with_cargo_audit_error(mut self, detail: &str) -> Self {
        self.cargo_audit_result = Err(detail.to_owned());
        self
    }

    fn recorded_updates(&self) -> Vec<(String, String)> {
        self.cargo_updates.borrow().clone()
    }

    fn recorded_diff_paths(&self) -> Vec<PathBuf> {
        self.git_diff_paths.borrow().clone()
    }
}

impl CommandRunner for FakeCommandRunner {
    fn git_show(
        &self,
        _current_dir: &Path,
        object: &str,
    ) -> Result<String, cargo_barbican::RunnerError> {
        self.git_show_results
            .get(object)
            .cloned()
            .unwrap_or_else(|| Err(format!("missing fake git show for {object}")))
            .map_err(runner_exit)
    }

    fn cargo_metadata(&self, _current_dir: &Path) -> Result<String, cargo_barbican::RunnerError> {
        self.cargo_metadata_result.clone().map_err(runner_exit)
    }

    fn cargo_update_precise(
        &self,
        current_dir: &Path,
        package_id: &str,
        version: &str,
    ) -> Result<(), cargo_barbican::RunnerError> {
        self.cargo_updates
            .borrow_mut()
            .push((package_id.to_owned(), version.to_owned()));
        let result = self.cargo_update_result.clone().map_err(runner_exit);

        if result.is_ok() {
            if let Some(lockfile_text) = &self.cargo_update_lockfile_text {
                fs::write(current_dir.join("Cargo.lock"), lockfile_text)
                    .map_err(cargo_barbican::RunnerError::Spawn)?;
            }
        }

        result
    }

    fn git_diff(
        &self,
        _current_dir: &Path,
        paths: &[PathBuf],
    ) -> Result<String, cargo_barbican::RunnerError> {
        self.git_diff_paths.borrow_mut().extend_from_slice(paths);
        self.git_diff_result.clone().map_err(runner_exit)
    }

    fn cargo_audit(&self, _current_dir: &Path) -> Result<(), cargo_barbican::RunnerError> {
        *self.audit_calls.borrow_mut() += 1;
        self.cargo_audit_result.clone().map_err(runner_exit)
    }

    fn cargo_deny(&self, _current_dir: &Path) -> Result<(), cargo_barbican::RunnerError> {
        *self.deny_calls.borrow_mut() += 1;
        self.cargo_deny_result.clone().map_err(runner_exit)
    }

    fn cargo_build_locked(&self, _current_dir: &Path) -> Result<(), cargo_barbican::RunnerError> {
        *self.build_calls.borrow_mut() += 1;
        self.cargo_build_result.clone().map_err(runner_exit)
    }

    fn cargo_test_locked(&self, _current_dir: &Path) -> Result<(), cargo_barbican::RunnerError> {
        *self.test_calls.borrow_mut() += 1;
        self.cargo_test_result.clone().map_err(runner_exit)
    }
}

#[test]
fn age_reports_success_for_old_enough_versions() {
    let cli = Cli::parse_from(["cargo-barbican", "age", "serde@1.0.228"]);
    let client =
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2026-05-01T00:00:00Z", false);
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("OK   serde@1.0.228: published 2026-05-01T00:00:00Z ("));
    assert!(rendered.contains(" old)\n"));
    assert!(stderr.is_empty());
}

#[test]
fn age_uses_barbican_config_minimum_days() {
    let cli = Cli::parse_from(["cargo-barbican", "age", "serde@1.0.228"]);
    let client =
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2026-05-20T00:00:00Z", false);
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("barbican.toml"),
        "[release_age]\nminimum_days = 30\n\n[high_scrutiny]\n\n[delegates]\n",
    )
    .expect("config should write");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    assert!(
        String::from_utf8(stderr)
            .expect("stderr should be utf8")
            .contains("below the 30-day minimum")
    );
}

#[test]
fn age_allows_command_line_override_of_minimum_days() {
    let cli = Cli::parse_from([
        "cargo-barbican",
        "age",
        "--min-age-days",
        "3",
        "serde@1.0.228",
    ]);
    let client =
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2026-05-20T00:00:00Z", false);
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("barbican.toml"),
        "[release_age]\nminimum_days = 30\n\n[high_scrutiny]\n\n[delegates]\n",
    )
    .expect("config should write");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert!(
        String::from_utf8(stdout)
            .expect("stdout should be utf8")
            .contains("OK   serde@1.0.228")
    );
}

#[test]
fn cli_rejects_excessive_min_age_days() {
    assert!(
        Cli::try_parse_from([
            "cargo-barbican",
            "age",
            "--min-age-days",
            "365001",
            "serde@1.0.228",
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from(["cargo-barbican", "age-lock", "--min-age-days", "365001",]).is_err()
    );
    assert!(
        Cli::try_parse_from(["cargo-barbican", "assess", "--min-age-days", "365001",]).is_err()
    );
}

#[test]
fn age_preserves_per_spec_failures() {
    let cli = Cli::parse_from(["cargo-barbican", "age", "serde@1.0.228", "bad"]);
    let client =
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2026-05-01T00:00:00Z", false);
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(
        String::from_utf8(stdout)
            .expect("stdout should be utf8")
            .contains("OK   serde@1.0.228")
    );
    assert!(
        String::from_utf8(stderr)
            .expect("stderr should be utf8")
            .contains("FAIL bad: Expected exact crate@version spec, got: bad")
    );
}

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
    let cli = Cli::parse_from(["cargo-barbican", "age-lock"]);
    let client =
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2999-01-01T00:00:00Z", false);
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
fn resolve_updates_selected_package_and_rechecks_the_lockfile_diff() {
    let cli = Cli::parse_from(["cargo-barbican", "resolve", "serde@1.0.228"]);
    let client =
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2026-05-01T00:00:00Z", false);
    let runner = FakeCommandRunner::default()
        .with_git_show(
            "HEAD:Cargo.lock",
            &lockfile_with_packages(&[("serde", "1.0.227", true)]),
        )
        .with_updated_lockfile(&lockfile_with_packages(&[("serde", "1.0.228", true)]))
        .with_cargo_metadata(&metadata_with_packages(&[(
            "serde",
            "1.0.228",
            "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228",
        )]));
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
fn assess_reports_routine_safe_when_no_findings_are_present() {
    let cli = Cli::parse_from(["cargo-barbican", "assess"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default()
        .with_git_show(
            "HEAD:Cargo.lock",
            &lockfile_with_packages(&[("serde", "1.0.227", true)]),
        )
        .with_git_show("HEAD:Cargo.toml", "[dependencies]\nserde = \"1\"\n");
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"1\"\n",
    )
    .expect("current manifest should write");
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
    assert!(rendered.contains("Suggested classification: routine-safe"));
    assert!(rendered.contains("No policy findings detected."));
}

#[test]
fn assess_reports_elevated_risk_findings_for_new_surfaces() {
    let cli = Cli::parse_from(["cargo-barbican", "assess"]);
    let client = FakeCratesIoClient::default().with_release(
        "native-sys@1.2.3",
        "2026-05-01T00:00:00Z",
        false,
    );
    let runner = FakeCommandRunner::default()
        .with_git_show(
            "HEAD:Cargo.lock",
            &lockfile_with_packages(&[("serde", "1.0.227", true)]),
        )
        .with_git_show("HEAD:Cargo.toml", "[dependencies]\nserde = \"1\"\n")
        .with_cargo_metadata(
            r#"{
  "packages": [
    {
      "name": "native-sys",
      "id": "registry+https://github.com/rust-lang/crates.io-index#native-sys@1.2.3",
      "version": "1.2.3",
      "targets": [
        {"kind": ["custom-build"]},
        {"kind": ["proc-macro"]}
      ]
    }
  ],
  "workspace_members": [],
  "resolve": null
}"#,
        );
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.toml"),
        r#"[dependencies]
serde = "1"
native-sys = "1.2.3"
forked = { git = "https://example.com/forked.git" }
"#,
    )
    .expect("current manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_package_sources(&[
            (
                "serde",
                "1.0.227",
                Some("registry+https://github.com/rust-lang/crates.io-index"),
            ),
            (
                "native-sys",
                "1.2.3",
                Some("registry+https://github.com/rust-lang/crates.io-index"),
            ),
            (
                "forked",
                "0.1.0",
                Some("git+https://example.com/forked.git#deadbeef"),
            ),
        ]),
    )
    .expect("current lockfile should write");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Suggested classification: elevated-risk"));
    assert!(rendered.contains(
        "new direct dependencies: Cargo.toml:dependencies:forked, Cargo.toml:dependencies:native-sys"
    ));
    assert!(
        rendered.contains("new non-crates.io direct specs: Cargo.toml:dependencies:forked (git)")
    );
    assert!(rendered.contains(
        "source changes: forked@0.1.0 source=git+https://example.com/forked.git#deadbeef"
    ));
    assert!(rendered.contains("new -sys crates: native-sys@1.2.3"));
    assert!(rendered.contains("new/changed build.rs surface: native-sys@1.2.3"));
    assert!(rendered.contains("new/changed proc-macro surface: native-sys@1.2.3"));
    assert!(rendered.contains("Elevated-risk signals:"));
}

#[test]
fn assess_reports_policy_violating_when_new_selection_is_too_fresh() {
    let cli = Cli::parse_from(["cargo-barbican", "assess"]);
    let client =
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2999-01-01T00:00:00Z", false);
    let runner = FakeCommandRunner::default()
        .with_git_show(
            "HEAD:Cargo.lock",
            &lockfile_with_packages(&[("serde", "1.0.227", true)]),
        )
        .with_git_show("HEAD:Cargo.toml", "[dependencies]\nserde = \"1\"\n")
        .with_cargo_metadata(&metadata_with_packages(&[(
            "serde",
            "1.0.228",
            "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228",
        )]));
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"1\"\n",
    )
    .expect("current manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_packages(&[("serde", "1.0.228", true)]),
    )
    .expect("current lockfile should write");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Suggested classification: policy-violating"));
    assert!(rendered.contains("age violations: serde@1.0.228 ("));
    assert!(rendered.contains("Blocking policy findings:"));
    assert!(
        rendered
            .contains("newly selected crates.io versions below the minimum age: serde@1.0.228 (")
    );
}

#[test]
fn assess_treats_base_manifest_absence_as_expected_for_new_workspace_manifests() {
    let cli = Cli::parse_from(["cargo-barbican", "assess"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default()
        .with_git_show("HEAD:Cargo.lock", "version = 4\n")
        .with_git_show("HEAD:Cargo.toml", "[workspace]\nmembers = []\n")
        .with_git_show_error(
            "HEAD:crates/new-member/Cargo.toml",
            "fatal: path 'crates/new-member/Cargo.toml' does not exist in 'HEAD'",
        );
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::create_dir_all(temp_dir.join("crates/new-member"))
        .expect("member directory should be creatable");
    fs::write(temp_dir.join("Cargo.toml"), "[workspace]\nmembers = []\n")
        .expect("root manifest should write");
    fs::write(temp_dir.join("Cargo.lock"), "version = 4\n").expect("lockfile should write");
    fs::write(
        temp_dir.join("crates/new-member/Cargo.toml"),
        "[dependencies]\nserde = \"1\"\n",
    )
    .expect("member manifest should write");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Suggested classification: elevated-risk"));
    assert!(
        rendered
            .contains("new direct dependencies: crates/new-member/Cargo.toml:dependencies:serde")
    );
    assert!(!rendered.contains("inspection failures"));
}

#[test]
fn assess_reports_non_missing_git_show_errors_for_base_manifests() {
    let cli = Cli::parse_from(["cargo-barbican", "assess"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default()
        .with_git_show("HEAD:Cargo.lock", "version = 4\n")
        .with_git_show_error("HEAD:Cargo.toml", "fatal: bad object HEAD");
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"1\"\n",
    )
    .expect("current manifest should write");
    fs::write(temp_dir.join("Cargo.lock"), "version = 4\n").expect("lockfile should write");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    assert!(
        String::from_utf8(stderr)
            .expect("stderr should be utf8")
            .contains("FAIL unable to read HEAD:Cargo.toml from git: fatal: bad object HEAD")
    );
}

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
        "No Rust dependency manifest or lockfile changes detected.\n"
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

    let recorded_paths = runner.recorded_diff_paths();
    assert!(recorded_paths.contains(&PathBuf::from("Cargo.toml")));
    assert!(recorded_paths.contains(&PathBuf::from("Cargo.lock")));
    assert!(recorded_paths.contains(&PathBuf::from("deny.toml")));
    assert!(recorded_paths.contains(&PathBuf::from("crates/barbican/Cargo.toml")));
    assert!(recorded_paths.contains(&PathBuf::from("crates/cargo-barbican/Cargo.toml")));
}

#[test]
fn audit_runs_both_delegated_checks() {
    let cli = Cli::parse_from(["cargo-barbican", "audit"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert_eq!(*runner.audit_calls.borrow(), 1);
    assert_eq!(*runner.deny_calls.borrow(), 1);
}

#[test]
fn audit_reports_failures() {
    let cli = Cli::parse_from(["cargo-barbican", "audit"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default().with_cargo_audit_error("boom");
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert_eq!(*runner.audit_calls.borrow(), 1);
    assert_eq!(*runner.deny_calls.borrow(), 0);
    assert!(
        String::from_utf8(stderr)
            .expect("stderr should be utf8")
            .contains("FAIL cargo audit: boom")
    );
}

#[test]
fn verify_runs_locked_build_and_test() {
    let cli = Cli::parse_from(["cargo-barbican", "verify"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert_eq!(*runner.build_calls.borrow(), 1);
    assert_eq!(*runner.test_calls.borrow(), 1);
}

#[test]
fn age_smoke_tests_the_ureq_client_against_a_local_http_server() {
    let cli = Cli::parse_from(["cargo-barbican", "age", "serde@1.0.228"]);
    let Some((base_url, requests, handle)) = spawn_http_stub(
        "HTTP/1.1 200 OK",
        r#"{"version":{"created_at":"2026-05-01T00:00:00Z","yanked":false}}"#,
    ) else {
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
    assert!(request.contains("GET /api/v1/crates/serde/1.0.228 HTTP/1.1"));
    let user_agent = request
        .lines()
        .find_map(|line| {
            line.split_once(':')
                .filter(|(name, _)| name.eq_ignore_ascii_case("User-Agent"))
                .map(|(_, value)| value.trim())
        })
        .expect("stub request should include a User-Agent header");
    assert!(user_agent.contains("cargo-barbican/"));
    assert!(
        String::from_utf8(stdout)
            .expect("stdout should be utf8")
            .contains("OK   serde@1.0.228: published 2026-05-01T00:00:00Z")
    );
}

#[test]
fn age_reports_http_statuses_from_the_ureq_client() {
    let cli = Cli::parse_from(["cargo-barbican", "age", "serde@1.0.228"]);
    let Some((base_url, _requests, handle)) = spawn_http_stub("HTTP/1.1 404 Not Found", "{}")
    else {
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

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    assert!(
        String::from_utf8(stderr)
            .expect("stderr should be utf8")
            .contains("FAIL serde@1.0.228: crates.io returned HTTP 404 for version metadata")
    );
}

#[test]
fn age_reports_client_failures_to_stderr() {
    let cli = Cli::parse_from(["cargo-barbican", "age", "serde@1.0.228"]);
    let client = FakeCratesIoClient::default().with_error(
        "serde@1.0.228",
        CratesIoClientError::HttpStatus { status_code: 404 },
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
            .contains("FAIL serde@1.0.228: crates.io returned HTTP 404 for version metadata")
    );
}

fn write_workspace_layout(temp_dir: &Path) {
    fs::create_dir_all(temp_dir.join("crates/barbican")).expect("crate dir should exist");
    fs::create_dir_all(temp_dir.join("crates/cargo-barbican")).expect("crate dir should exist");
    fs::write(temp_dir.join("Cargo.toml"), "[workspace]\nmembers = []\n")
        .expect("root manifest should write");
    fs::write(temp_dir.join("Cargo.lock"), "version = 4\n").expect("lockfile should write");
    fs::write(temp_dir.join("deny.toml"), "[advisories]\n").expect("deny config should write");
    fs::write(
        temp_dir.join("crates/barbican/Cargo.toml"),
        "[package]\nname = \"barbican\"\nversion = \"0.1.1\"\n",
    )
    .expect("member manifest should write");
    fs::write(
        temp_dir.join("crates/cargo-barbican/Cargo.toml"),
        "[package]\nname = \"cargo-barbican\"\nversion = \"0.1.1\"\n",
    )
    .expect("member manifest should write");
}

fn lockfile_with_packages(packages: &[(&str, &str, bool)]) -> String {
    lockfile_with_package_sources(
        &packages
            .iter()
            .map(|(name, version, crates_io)| {
                (
                    *name,
                    *version,
                    crates_io.then_some("registry+https://github.com/rust-lang/crates.io-index"),
                )
            })
            .collect::<Vec<_>>(),
    )
}

fn lockfile_with_package_sources(packages: &[(&str, &str, Option<&str>)]) -> String {
    let mut lockfile = String::from("version = 4\n");

    for (name, version, source) in packages {
        lockfile.push_str("\n[[package]]\n");
        lockfile.push_str(&format!("name = \"{name}\"\n"));
        lockfile.push_str(&format!("version = \"{version}\"\n"));
        if let Some(source) = source {
            lockfile.push_str(&format!("source = \"{source}\"\n"));
        }
    }

    lockfile
}

fn metadata_with_packages(packages: &[(&str, &str, &str)]) -> String {
    let packages_json = packages
        .iter()
        .map(|(name, version, id)| {
            format!(r#"{{"name":"{name}","id":"{id}","version":"{version}","targets":[]}}"#)
        })
        .collect::<Vec<_>>()
        .join(",");

    format!(r#"{{"packages":[{packages_json}],"workspace_members":[],"resolve":null}}"#)
}

fn fresh_temp_dir() -> PathBuf {
    static BASE: OnceLock<PathBuf> = OnceLock::new();

    let base = BASE.get_or_init(|| {
        let root = std::env::temp_dir().join("cargo-barbican-tests");
        fs::create_dir_all(&root).expect("temp root should be creatable");
        root
    });

    let unique = format!(
        "{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after unix epoch")
            .as_nanos()
    );
    let path = base.join(unique);
    fs::create_dir_all(&path).expect("temp dir should be creatable");
    path
}

fn runner_exit(detail: String) -> cargo_barbican::RunnerError {
    cargo_barbican::RunnerError::Exited {
        code: Some(1),
        stdout: String::new(),
        stderr: detail,
    }
}

fn spawn_http_stub(
    status_line: &str,
    body: &str,
) -> Option<(String, mpsc::Receiver<String>, thread::JoinHandle<()>)> {
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return None,
        Err(error) => panic!("stub listener should bind: {error}"),
    };
    let address = listener
        .local_addr()
        .expect("stub listener should have a local address");
    let (sender, receiver) = mpsc::channel();
    let status_line = status_line.to_owned();
    let body = body.to_owned();

    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("stub should accept one client");
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];

        loop {
            let read = stream.read(&mut buffer).expect("stub request should read");
            if read == 0 {
                break;
            }

            request.extend_from_slice(&buffer[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }

        sender
            .send(String::from_utf8_lossy(&request).into_owned())
            .expect("stub request should send");

        let response = format!(
            "{status_line}\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .expect("stub response should write");
    });

    Some((format!("http://{address}"), receiver, handle))
}
