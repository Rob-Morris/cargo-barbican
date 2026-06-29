use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use barbican::{
    CrateRelease, CratesIoClient, CratesIoClientError, ExactCrateSpec, OffsetDateTime,
    parse_version_response_body,
};
use cargo_barbican::{
    Cli, CommandOutput, CommandRunner, UreqCratesIoClient, run_cli_with_runner,
    run_cli_with_runner_at,
};
use clap::Parser;
use miniz_oxide::deflate::compress_to_vec;
use sha2::{Digest, Sha256};
use tar::{Builder, Header};

#[derive(Default)]
struct FakeCratesIoClient {
    responses: HashMap<String, Result<CrateRelease, CratesIoClientError>>,
    tarball_responses: HashMap<String, Result<Vec<u8>, CratesIoClientError>>,
    fetches: RefCell<Vec<String>>,
    tarball_fetches: RefCell<Vec<String>>,
}

impl FakeCratesIoClient {
    fn with_release(self, spec: &str, published_at: &str, yanked: bool) -> Self {
        self.with_release_checksum(
            spec,
            published_at,
            yanked,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
    }

    fn with_release_checksum(
        mut self,
        spec: &str,
        published_at: &str,
        yanked: bool,
        checksum_sha256_hex: &str,
    ) -> Self {
        self.responses.insert(
            spec.to_owned(),
            Ok(parse_version_response_body(&format!(
                r#"{{"version":{{"checksum":"{checksum_sha256_hex}","created_at":"{published_at}","yanked":{yanked}}}}}"#
            ))
            .expect("fake response should parse")),
        );
        self
    }

    fn with_error(mut self, spec: &str, error: CratesIoClientError) -> Self {
        self.responses.insert(spec.to_owned(), Err(error));
        self
    }

    fn with_tarball(mut self, spec: &str, tarball: &[u8]) -> Self {
        self.tarball_responses
            .insert(spec.to_owned(), Ok(tarball.to_vec()));
        self
    }

    fn recorded_fetches(&self) -> Vec<String> {
        self.fetches.borrow().clone()
    }

    fn recorded_tarball_fetches(&self) -> Vec<String> {
        self.tarball_fetches.borrow().clone()
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

    fn fetch_release_tarball(&self, spec: &ExactCrateSpec) -> Result<Vec<u8>, CratesIoClientError> {
        self.tarball_fetches.borrow_mut().push(spec.to_string());
        self.tarball_responses
            .get(&spec.to_string())
            .cloned()
            .unwrap_or_else(|| {
                Err(CratesIoClientError::Transport {
                    reason: "missing fake tarball response".to_owned(),
                })
            })
    }
}

struct FakeCommandRunner {
    git_show_results: HashMap<String, Result<String, String>>,
    cargo_metadata_result: Result<String, String>,
    cargo_update_result: Result<(), String>,
    cargo_update_lockfile_text: Option<String>,
    cargo_generate_lockfile_result: Result<(), String>,
    cargo_tree_result: Result<String, String>,
    git_diff_result: Result<String, String>,
    cargo_audit_result: Result<String, String>,
    cargo_audit_json_result: Result<CommandOutput, String>,
    cargo_deny_json_result: Result<CommandOutput, String>,
    cargo_build_result: Result<(), String>,
    cargo_test_result: Result<(), String>,
    cargo_updates: RefCell<Vec<(String, String)>>,
    generate_lockfile_calls: RefCell<Vec<PathBuf>>,
    cargo_tree_calls: RefCell<Vec<PathBuf>>,
    git_diff_paths: RefCell<Vec<PathBuf>>,
    audit_calls: RefCell<Vec<PathBuf>>,
    audit_json_calls: RefCell<Vec<(PathBuf, PathBuf)>>,
    deny_json_calls: RefCell<Vec<(PathBuf, PathBuf, Vec<barbican::CargoDenyCheck>)>>,
    deny_json_config_texts: RefCell<Vec<String>>,
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
            cargo_generate_lockfile_result: Ok(()),
            cargo_tree_result: Ok(String::new()),
            git_diff_result: Ok(String::new()),
            cargo_audit_result: Ok(String::new()),
            cargo_audit_json_result: Ok(CommandOutput {
                stdout: clean_cargo_audit_json().to_owned(),
                stderr: String::new(),
            }),
            cargo_deny_json_result: Ok(CommandOutput {
                stdout: String::new(),
                stderr: clean_cargo_deny_jsonl().to_owned(),
            }),
            cargo_build_result: Ok(()),
            cargo_test_result: Ok(()),
            cargo_updates: RefCell::new(Vec::new()),
            generate_lockfile_calls: RefCell::new(Vec::new()),
            cargo_tree_calls: RefCell::new(Vec::new()),
            git_diff_paths: RefCell::new(Vec::new()),
            audit_calls: RefCell::new(Vec::new()),
            audit_json_calls: RefCell::new(Vec::new()),
            deny_json_calls: RefCell::new(Vec::new()),
            deny_json_config_texts: RefCell::new(Vec::new()),
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

    fn with_cargo_tree(mut self, output: &str) -> Self {
        self.cargo_tree_result = Ok(output.to_owned());
        self
    }

    fn with_cargo_tree_error(mut self, detail: &str) -> Self {
        self.cargo_tree_result = Err(detail.to_owned());
        self
    }

    fn with_cargo_generate_lockfile_error(mut self, detail: &str) -> Self {
        self.cargo_generate_lockfile_result = Err(detail.to_owned());
        self
    }

    fn with_cargo_audit_error(mut self, detail: &str) -> Self {
        self.cargo_audit_result = Err(detail.to_owned());
        self
    }

    fn with_cargo_audit(mut self, output: &str) -> Self {
        self.cargo_audit_result = Ok(output.to_owned());
        self
    }

    fn with_cargo_audit_json(mut self, stdout: &str) -> Self {
        self.cargo_audit_json_result = Ok(CommandOutput {
            stdout: stdout.to_owned(),
            stderr: String::new(),
        });
        self
    }

    fn with_cargo_deny_json(mut self, stderr: &str) -> Self {
        self.cargo_deny_json_result = Ok(CommandOutput {
            stdout: String::new(),
            stderr: stderr.to_owned(),
        });
        self
    }

    fn recorded_updates(&self) -> Vec<(String, String)> {
        self.cargo_updates.borrow().clone()
    }

    fn recorded_generate_lockfile_calls(&self) -> Vec<PathBuf> {
        self.generate_lockfile_calls.borrow().clone()
    }

    fn recorded_cargo_tree_calls(&self) -> Vec<PathBuf> {
        self.cargo_tree_calls.borrow().clone()
    }

    fn recorded_audit_calls(&self) -> Vec<PathBuf> {
        self.audit_calls.borrow().clone()
    }

    fn recorded_audit_json_calls(&self) -> Vec<(PathBuf, PathBuf)> {
        self.audit_json_calls.borrow().clone()
    }

    fn recorded_deny_json_calls(&self) -> Vec<(PathBuf, PathBuf, Vec<barbican::CargoDenyCheck>)> {
        self.deny_json_calls.borrow().clone()
    }

    fn recorded_deny_json_config_texts(&self) -> Vec<String> {
        self.deny_json_config_texts.borrow().clone()
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

    fn cargo_metadata_frozen(
        &self,
        _current_dir: &Path,
    ) -> Result<String, cargo_barbican::RunnerError> {
        Err(runner_exit("unexpected frozen cargo metadata".to_owned()))
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

        if result.is_ok()
            && let Some(lockfile_text) = &self.cargo_update_lockfile_text
        {
            fs::write(current_dir.join("Cargo.lock"), lockfile_text)
                .map_err(cargo_barbican::RunnerError::Spawn)?;
        }

        result
    }

    fn cargo_generate_lockfile(
        &self,
        current_dir: &Path,
    ) -> Result<(), cargo_barbican::RunnerError> {
        self.generate_lockfile_calls
            .borrow_mut()
            .push(current_dir.to_path_buf());
        let result = self
            .cargo_generate_lockfile_result
            .clone()
            .map_err(runner_exit);

        if result.is_ok() {
            fs::write(current_dir.join("Cargo.lock"), "version = 4\n")
                .map_err(cargo_barbican::RunnerError::Spawn)?;
        }

        result
    }

    fn cargo_tree(&self, current_dir: &Path) -> Result<String, cargo_barbican::RunnerError> {
        self.cargo_tree_calls
            .borrow_mut()
            .push(current_dir.to_path_buf());
        self.cargo_tree_result.clone().map_err(runner_exit)
    }

    fn git_diff(
        &self,
        _current_dir: &Path,
        paths: &[PathBuf],
    ) -> Result<String, cargo_barbican::RunnerError> {
        self.git_diff_paths.borrow_mut().extend_from_slice(paths);
        self.git_diff_result.clone().map_err(runner_exit)
    }

    fn cargo_audit(&self, current_dir: &Path) -> Result<String, cargo_barbican::RunnerError> {
        self.audit_calls
            .borrow_mut()
            .push(current_dir.to_path_buf());
        self.cargo_audit_result.clone().map_err(runner_exit)
    }

    fn cargo_audit_json(
        &self,
        controlled_cwd: &Path,
        lockfile_path: &Path,
    ) -> Result<CommandOutput, cargo_barbican::RunnerError> {
        self.audit_json_calls
            .borrow_mut()
            .push((controlled_cwd.to_path_buf(), lockfile_path.to_path_buf()));
        self.cargo_audit_json_result.clone().map_err(runner_exit)
    }

    fn cargo_deny_json(
        &self,
        current_dir: &Path,
        config_path: &Path,
        checks: &[barbican::CargoDenyCheck],
    ) -> Result<CommandOutput, cargo_barbican::RunnerError> {
        self.deny_json_calls.borrow_mut().push((
            current_dir.to_path_buf(),
            config_path.to_path_buf(),
            checks.to_vec(),
        ));
        self.deny_json_config_texts
            .borrow_mut()
            .push(fs::read_to_string(config_path).unwrap_or_else(|error| error.to_string()));
        self.cargo_deny_json_result.clone().map_err(runner_exit)
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
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2020-05-01T00:00:00Z", false);
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

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
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("OK   serde@1.0.228: published 2020-05-01T00:00:00Z ("));
    assert!(rendered.contains(" old)\n"));
    assert!(stderr.is_empty());
}

#[test]
fn age_uses_barbican_config_minimum_days() {
    let cli = Cli::parse_from(["cargo-barbican", "age", "serde@1.0.228"]);
    let client =
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2020-05-22T00:00:00Z", false);
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("barbican.toml"),
        "[release_age]\nminimum_days = 30\n\n[high_scrutiny]\n\n[delegates]\n",
    )
    .expect("config should write");

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
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2020-05-20T00:00:00Z", false);
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("barbican.toml"),
        "[release_age]\nminimum_days = 30\n\n[high_scrutiny]\n\n[delegates]\n",
    )
    .expect("config should write");

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
        Cli::try_parse_from([
            "cargo-barbican",
            "resolve",
            "--min-age-days",
            "365001",
            "serde@1.0.228",
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from(["cargo-barbican", "assess", "--min-age-days", "365001",]).is_err()
    );
    assert!(
        Cli::try_parse_from([
            "cargo-barbican",
            "age-lock",
            "--base-ref",
            "HEAD",
            "--base-lockfile",
            "baseline/Cargo.lock",
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from([
            "cargo-barbican",
            "assess",
            "--base-ref",
            "HEAD",
            "--base-dir",
            "baseline",
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from(["cargo-barbican", "assess", "--policy-mode", "permissive",]).is_err()
    );
}

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
        include_str!("../../../templates/barbican.toml")
    );
    assert_eq!(
        fs::read_to_string(temp_dir.join("reviewed-targets.toml"))
            .expect("reviewed targets should exist"),
        include_str!("../../../templates/reviewed-targets.toml")
    );
    assert_eq!(
        fs::read_to_string(temp_dir.join("docs/dependency-reviews/README.md"))
            .expect("review readme should exist"),
        include_str!("../../../templates/dependency-reviews/README.md")
    );
    assert!(!temp_dir.join("deny.toml").exists());

    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("- barbican.toml: created\n"));
    assert!(rendered.contains("- reviewed-targets.toml: created\n"));
    assert!(rendered.contains("- docs/dependency-reviews: created\n"));
    assert!(rendered.contains("- docs/dependency-reviews/README.md: created\n"));
    assert!(rendered.contains("Review the manual adoption guide: docs/user/adoption.md"));
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
    assert!(rendered.contains("- reviewed-targets.toml: already present\n"));
    assert!(rendered.contains("- docs/dependency-reviews: already present\n"));
    assert!(rendered.contains("- docs/dependency-reviews/README.md: already present\n"));
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
            .contains("FAIL bad: Expected exact crate@version spec, got: \"bad\"")
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
fn resolve_updates_selected_package_and_rechecks_the_lockfile_diff() {
    let cli = Cli::parse_from(["cargo-barbican", "resolve", "serde@1.0.228"]);
    let client =
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2026-05-01T00:00:00Z", false);
    let runner = FakeCommandRunner::default()
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
fn resolve_honours_min_age_override_for_both_age_checks() {
    let cli = Cli::parse_from([
        "cargo-barbican",
        "resolve",
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
fn resolve_recheck_flags_too_fresh_transitive_selection_under_injected_clock() {
    // The explicit spec is old enough against `fixed_now()` (2020-06-01), but the
    // update pulls in a transitive crate published only 6 days earlier. Only the
    // post-update recheck can catch that, so this guards the resolve recheck call
    // site's clock wiring: a regression reading the wall clock would see a
    // years-old release and let it through.
    let cli = Cli::parse_from(["cargo-barbican", "resolve", "serde@1.0.228"]);
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
fn resolve_dry_run_previews_lockfile_diff_without_mutating_repo() {
    let cli = Cli::parse_from(["cargo-barbican", "resolve", "--dry-run", "serde@1.0.228"]);
    let client =
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2026-05-01T00:00:00Z", false);
    let runner = FakeCommandRunner::default()
        .with_updated_lockfile(&lockfile_with_packages(&[("serde", "1.0.228", true)]))
        .with_cargo_metadata(&metadata_with_packages(&[(
            "serde",
            "1.0.228",
            "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228",
        )]));
    let temp_dir = fresh_temp_dir();
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
fn resolve_dry_run_reports_when_no_lockfile_change_would_be_made() {
    let cli = Cli::parse_from(["cargo-barbican", "resolve", "--dry-run", "serde@1.0.228"]);
    let lockfile = lockfile_with_packages(&[("serde", "1.0.228", true)]);
    let client =
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2026-05-01T00:00:00Z", false);
    let runner = FakeCommandRunner::default()
        .with_updated_lockfile(&lockfile)
        .with_cargo_metadata(&metadata_with_packages(&[(
            "serde",
            "1.0.228",
            "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228",
        )]));
    let temp_dir = fresh_temp_dir();
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
fn assess_reports_policy_violating_against_non_git_base_directory() {
    let cli = Cli::parse_from(["cargo-barbican", "assess", "--base-dir", "baseline"]);
    let client =
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2020-05-26T00:00:00Z", false);
    let runner = FakeCommandRunner::default().with_cargo_metadata(&metadata_with_packages(&[(
        "serde",
        "1.0.228",
        "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228",
    )]));
    let temp_dir = fresh_temp_dir();
    let baseline_dir = temp_dir.join("baseline");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::create_dir_all(&baseline_dir).expect("baseline directory should be creatable");
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
    fs::write(
        baseline_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"1\"\n",
    )
    .expect("baseline manifest should write");
    fs::write(
        baseline_dir.join("Cargo.lock"),
        lockfile_with_packages(&[("serde", "1.0.227", true)]),
    )
    .expect("baseline lockfile should write");

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
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Suggested classification: policy-violating"));
    assert!(rendered.contains("age violations: serde@1.0.228 ("));
}

#[test]
fn assess_reports_missing_non_git_base_directory_lockfile() {
    let cli = Cli::parse_from(["cargo-barbican", "assess", "--base-dir", "missing"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
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

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    assert!(
        String::from_utf8(stderr)
            .expect("stderr should be utf8")
            .contains("FAIL missing/Cargo.lock: lockfile not found")
    );
}

#[test]
fn assess_reports_routine_safe_when_no_findings_are_present() {
    let (exit_code, rendered, stderr) = run_routine_safe_assess(&[]);

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert!(rendered.contains("Suggested classification: routine-safe"));
    assert!(rendered.contains("No policy findings detected."));
}

#[test]
fn assess_policy_mode_elevated_risk_preserves_routine_safe_success() {
    let (exit_code, rendered, stderr) =
        run_routine_safe_assess(&["--policy-mode", "elevated-risk"]);

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert!(rendered.contains("Suggested classification: routine-safe"));
    assert!(rendered.contains("No policy findings detected."));
    assert!(!rendered.contains("Elevated-risk findings accepted by --policy-mode elevated-risk"));
}

#[test]
fn assess_reports_lockfile_checksum_drift_for_existing_selection() {
    let cli = Cli::parse_from(["cargo-barbican", "assess"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default()
        .with_git_show(
            "HEAD:Cargo.lock",
            &lockfile_with_package_records(&[(
                "serde",
                "1.0.228",
                Some("registry+https://github.com/rust-lang/crates.io-index"),
                Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
            )]),
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
        lockfile_with_package_records(&[(
            "serde",
            "1.0.228",
            Some("registry+https://github.com/rust-lang/crates.io-index"),
            Some("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        )]),
    )
    .expect("current lockfile should write");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Suggested classification: policy-violating"));
    assert!(rendered.contains(
        "lockfile checksum drifts: serde@1.0.228 checksum drift: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef -> ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    ));
    assert!(rendered.contains(
        "locked crates.io checksums changed for existing selections: serde@1.0.228 checksum drift"
    ));
}

fn run_routine_safe_assess(args: &[&str]) -> (ExitCode, String, String) {
    let mut raw_args = vec!["cargo-barbican", "assess"];
    raw_args.extend_from_slice(args);
    let cli = Cli::parse_from(raw_args);
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

    (
        exit_code,
        String::from_utf8(stdout).expect("stdout should be utf8"),
        String::from_utf8(stderr).expect("stderr should be utf8"),
    )
}

#[test]
fn assess_reports_elevated_risk_findings_for_new_surfaces() {
    let (exit_code, rendered, stderr) = run_elevated_risk_assess(&[]);

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
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
    assert!(!rendered.contains("Elevated-risk findings accepted by --policy-mode elevated-risk"));
}

#[test]
fn assess_policy_mode_elevated_risk_accepts_elevated_risk_findings() {
    let (exit_code, rendered, stderr) =
        run_elevated_risk_assess(&["--policy-mode", "elevated-risk"]);

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert!(rendered.contains("Suggested classification: elevated-risk"));
    assert!(rendered.contains("Elevated-risk signals:"));
    assert!(rendered.contains(
        "Elevated-risk findings accepted by --policy-mode elevated-risk; blocking policy findings would still fail."
    ));
}

#[test]
fn assess_allows_reviewed_execution_surfaces_when_review_record_exists() {
    let (exit_code, rendered, stderr) =
        run_allowed_surface_assess("1.2.3", true, &["build-rs", "proc-macro", "native-sys"]);

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert!(rendered.contains("Suggested classification: routine-safe"));
    assert!(rendered.contains("Allowed policy exceptions:"));
    assert!(rendered.contains(
        "native-sys@1.2.3 build-rs allowed by reviewed family native-family (docs/dependency-reviews/2026-05-27-native.md)"
    ));
    assert!(rendered.contains(
        "native-sys@1.2.3 proc-macro allowed by reviewed family native-family (docs/dependency-reviews/2026-05-27-native.md)"
    ));
    assert!(rendered.contains(
        "native-sys@1.2.3 native-sys allowed by reviewed family native-family (docs/dependency-reviews/2026-05-27-native.md)"
    ));
    assert!(!rendered.contains("Elevated-risk signals:"));
    assert!(!rendered.contains("new/changed build.rs surface: native-sys@1.2.3"));
    assert!(!rendered.contains("new/changed proc-macro surface: native-sys@1.2.3"));
    assert!(!rendered.contains("new -sys crates: native-sys@1.2.3"));
}

#[test]
fn age_allows_too_fresh_release_with_reviewed_age_exception() {
    let cli = Cli::parse_from(["cargo-barbican", "age", "serde@1.0.228"]);
    let client =
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2020-05-26T00:00:00Z", false);
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    write_age_exception_policy(
        &temp_dir,
        "serde",
        "1.0.228",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        true,
    );

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
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("ALLOW serde@1.0.228"));
    assert!(rendered.contains(
        "release-age exception allowed by reviewed family serde-family (docs/dependency-reviews/2026-05-27-serde.md)"
    ));
}

#[test]
fn age_does_not_honour_age_exception_with_missing_review_record() {
    let cli = Cli::parse_from(["cargo-barbican", "age", "serde@1.0.228"]);
    let client =
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2020-05-26T00:00:00Z", false);
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    write_age_exception_policy(
        &temp_dir,
        "serde",
        "1.0.228",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        false,
    );

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
    let rendered = String::from_utf8(stderr).expect("stderr should be utf8");
    assert!(rendered.contains(
        "FAIL allowed release-age exception review record missing for serde@1.0.228: docs/dependency-reviews/2026-05-27-serde.md"
    ));
    assert!(!rendered.contains("ALLOW"));
}

#[test]
fn age_ignores_missing_age_exception_record_when_release_is_old_enough() {
    let cli = Cli::parse_from(["cargo-barbican", "age", "serde@1.0.228"]);
    let client =
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2020-05-20T00:00:00Z", false);
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    write_age_exception_policy(
        &temp_dir,
        "serde",
        "1.0.228",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        false,
    );

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
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("OK   serde@1.0.228"));
    assert!(!rendered.contains("review record missing"));
}

#[test]
fn age_blocks_reviewed_age_exception_checksum_mismatch() {
    let cli = Cli::parse_from(["cargo-barbican", "age", "serde@1.0.228"]);
    let client =
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2020-05-26T00:00:00Z", false);
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    write_age_exception_policy(
        &temp_dir,
        "serde",
        "1.0.228",
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        true,
    );

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
    let rendered = String::from_utf8(stderr).expect("stderr should be utf8");
    assert!(rendered.contains("release-age exception artefact mismatch"));
    assert!(rendered.contains(
        "expected sha256 abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    ));
    assert!(
        rendered.contains("found 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    );
}

#[test]
fn age_rejects_malformed_age_exception_state() {
    let cli = Cli::parse_from(["cargo-barbican", "age", "serde@1.0.228"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        r#"[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.resolved]
serde = "1.0.228"

[rust.families.allowed_age_exceptions]
serde = "1.0.228"
"#,
    )
    .expect("reviewed targets should write");

    let error = run_cli_with_runner_at(
        cli,
        &temp_dir,
        &client,
        &runner,
        fixed_now(),
        &mut stdout,
        &mut stderr,
    )
    .expect_err("malformed reviewed targets should fail");

    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
    assert!(error.to_string().contains(
        "allowed_age_exceptions entry for \"serde\" requires the resolved target to carry checksum_sha256"
    ));
}

#[test]
fn assess_lists_reviewed_age_exception_under_allowed_policy_exceptions() {
    let cli = Cli::parse_from(["cargo-barbican", "assess"]);
    let client =
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2020-05-26T00:00:00Z", false);
    let runner = FakeCommandRunner::default()
        .with_git_show("HEAD:Cargo.lock", "version = 4\n")
        .with_git_show("HEAD:Cargo.toml", "")
        .with_cargo_metadata(
            r#"{
  "packages": [
    {
      "name": "serde",
      "id": "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228",
      "version": "1.0.228",
      "targets": [{"kind": ["lib"]}]
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
        temp_dir.join("barbican.toml"),
        "[high_scrutiny]\nnew_direct_dependencies = false\n",
    )
    .expect("config should write");
    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"1\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_packages(&[("serde", "1.0.228", true)]),
    )
    .expect("lockfile should write");
    write_age_exception_policy(
        &temp_dir,
        "serde",
        "1.0.228",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        true,
    );

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
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Suggested classification: routine-safe"));
    assert!(rendered.contains("Allowed policy exceptions:"));
    assert!(rendered.contains(
        "serde@1.0.228 release age allowed by reviewed family serde-family (docs/dependency-reviews/2026-05-27-serde.md)"
    ));
    assert!(!rendered.contains("age violations"));
}

#[test]
fn assess_does_not_honour_age_exception_with_missing_review_record() {
    let cli = Cli::parse_from(["cargo-barbican", "assess"]);
    let client =
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2020-05-26T00:00:00Z", false);
    let runner = FakeCommandRunner::default()
        .with_git_show("HEAD:Cargo.lock", "version = 4\n")
        .with_git_show("HEAD:Cargo.toml", "")
        .with_cargo_metadata(
            r#"{
  "packages": [
    {
      "name": "serde",
      "id": "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228",
      "version": "1.0.228",
      "targets": [{"kind": ["lib"]}]
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
        temp_dir.join("barbican.toml"),
        "[high_scrutiny]\nnew_direct_dependencies = false\n",
    )
    .expect("config should write");
    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"1\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_packages(&[("serde", "1.0.228", true)]),
    )
    .expect("lockfile should write");
    write_age_exception_policy(
        &temp_dir,
        "serde",
        "1.0.228",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        false,
    );

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
    let stderr = String::from_utf8(stderr).expect("stderr should be utf8");
    assert!(stderr.contains(
        "FAIL allowed release-age exception review record missing for serde@1.0.228: docs/dependency-reviews/2026-05-27-serde.md"
    ));
}

#[test]
fn assess_blocks_reviewed_age_exception_checksum_mismatch() {
    let cli = Cli::parse_from(["cargo-barbican", "assess"]);
    let client =
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2020-05-26T00:00:00Z", false);
    let runner = FakeCommandRunner::default()
        .with_git_show("HEAD:Cargo.lock", "version = 4\n")
        .with_git_show("HEAD:Cargo.toml", "")
        .with_cargo_metadata(
            r#"{
  "packages": [
    {
      "name": "serde",
      "id": "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228",
      "version": "1.0.228",
      "targets": [{"kind": ["lib"]}]
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
        temp_dir.join("barbican.toml"),
        "[high_scrutiny]\nnew_direct_dependencies = false\n",
    )
    .expect("config should write");
    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"1\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_packages(&[("serde", "1.0.228", true)]),
    )
    .expect("lockfile should write");
    write_age_exception_policy(
        &temp_dir,
        "serde",
        "1.0.228",
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        true,
    );

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
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Suggested classification: policy-violating"));
    assert!(rendered.contains("release-age exception artefact mismatches"));
    assert!(
        rendered
            .contains("reviewed release-age exception artefact checksums did not match crates.io")
    );
    assert!(
        rendered.contains(
            "serde@1.0.228 release-age exception artefact mismatch for family serde-family"
        )
    );
    assert!(
        rendered
            .contains("expected abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
    );
    assert!(
        rendered.contains("found 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    );
}

#[test]
fn assess_fails_closed_when_applicable_allowed_surface_review_record_is_missing() {
    let (exit_code, stdout, stderr) = run_allowed_surface_assess("1.2.3", false, &["build-rs"]);

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    assert!(stderr.contains(
        "FAIL allowed policy exception review record missing for native-sys@1.2.3: docs/dependency-reviews/2026-05-27-native.md"
    ));
}

#[test]
fn assess_does_not_fail_for_unrelated_missing_review_record() {
    let (exit_code, rendered, stderr) = run_allowed_surface_assess("1.2.4", false, &["build-rs"]);

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    assert!(rendered.contains("Suggested classification: elevated-risk"));
    assert!(rendered.contains("Elevated-risk signals:"));
    assert!(!rendered.contains("Allowed policy exceptions:"));
    assert!(rendered.contains("new/changed build.rs surface: native-sys@1.2.4"));
}

#[test]
fn assess_rejects_malformed_allowed_surface_state() {
    let cli = Cli::parse_from(["cargo-barbican", "assess"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default()
        .with_git_show("HEAD:Cargo.lock", "version = 4\n")
        .with_git_show("HEAD:Cargo.toml", "");
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(temp_dir.join("Cargo.toml"), "").expect("current manifest should write");
    fs::write(temp_dir.join("Cargo.lock"), "version = 4\n").expect("lockfile should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        r#"[rust]

[[rust.families]]
name = "native-family"
review_record = "docs/dependency-reviews/2026-05-27-native.md"

[rust.families.resolved]
native-sys = "1.2.3"

[rust.families.allowed_surfaces]
other = ["build-rs"]
"#,
    )
    .expect("reviewed targets should write");

    let error = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect_err("malformed reviewed targets should fail");

    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
    assert!(error.to_string().contains(
        "allowed_surfaces entry for \"other\" references a crate absent from the same resolved map"
    ));
}

fn run_allowed_surface_assess(
    current_version: &str,
    write_record: bool,
    allowed_surfaces: &[&str],
) -> (ExitCode, String, String) {
    let cli = Cli::parse_from(["cargo-barbican", "assess"]);
    let client = FakeCratesIoClient::default().with_release(
        &format!("native-sys@{current_version}"),
        "2020-05-01T00:00:00Z",
        false,
    );
    let runner = FakeCommandRunner::default()
        .with_git_show("HEAD:Cargo.lock", "version = 4\n")
        .with_git_show("HEAD:Cargo.toml", "")
        .with_cargo_metadata(&format!(
            r#"{{
  "packages": [
    {{
      "name": "native-sys",
      "id": "registry+https://github.com/rust-lang/crates.io-index#native-sys@{current_version}",
      "version": "{current_version}",
      "targets": [
        {{"kind": ["custom-build"]}},
        {{"kind": ["proc-macro"]}}
      ]
    }}
  ],
  "workspace_members": [],
  "resolve": null
}}"#
        ));
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("barbican.toml"),
        "[high_scrutiny]\nnew_direct_dependencies = false\n",
    )
    .expect("config should write");
    fs::write(
        temp_dir.join("Cargo.toml"),
        format!("[dependencies]\nnative-sys = \"{current_version}\"\n"),
    )
    .expect("current manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_packages(&[("native-sys", current_version, true)]),
    )
    .expect("current lockfile should write");
    let allowed_surface_section = if allowed_surfaces.is_empty() {
        String::new()
    } else {
        format!(
            "\n[rust.families.allowed_surfaces]\nnative-sys = [{}]\n",
            allowed_surfaces
                .iter()
                .map(|surface| format!("\"{surface}\""))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        format!(
            r#"[rust]

[[rust.families]]
name = "native-family"
review_record = "docs/dependency-reviews/2026-05-27-native.md"

[rust.families.resolved]
native-sys = "1.2.3"
{allowed_surface_section}"#
        ),
    )
    .expect("reviewed targets should write");
    if write_record {
        write_review_record(&temp_dir, "docs/dependency-reviews/2026-05-27-native.md");
    }

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

    (
        exit_code,
        String::from_utf8(stdout).expect("stdout should be utf8"),
        String::from_utf8(stderr).expect("stderr should be utf8"),
    )
}

fn run_elevated_risk_assess(args: &[&str]) -> (ExitCode, String, String) {
    let mut raw_args = vec!["cargo-barbican", "assess"];
    raw_args.extend_from_slice(args);
    let cli = Cli::parse_from(raw_args);
    let client = FakeCratesIoClient::default().with_release(
        "native-sys@1.2.3",
        "2020-05-01T00:00:00Z",
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
    },
    {
      "name": "forked",
      "id": "git+https://example.com/forked.git#forked@0.1.0",
      "version": "0.1.0",
      "targets": []
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

    (
        exit_code,
        String::from_utf8(stdout).expect("stdout should be utf8"),
        String::from_utf8(stderr).expect("stderr should be utf8"),
    )
}

#[test]
fn assess_reports_policy_violating_when_new_selection_is_too_fresh() {
    let (exit_code, rendered, stderr) = run_too_fresh_assess(&[]);

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    assert!(rendered.contains("Suggested classification: policy-violating"));
    assert!(rendered.contains("age violations: serde@1.0.228 ("));
    assert!(rendered.contains("Blocking policy findings:"));
    assert!(
        rendered
            .contains("newly selected crates.io versions below the minimum age: serde@1.0.228 (")
    );
}

#[test]
fn assess_policy_mode_elevated_risk_does_not_accept_policy_violations() {
    let (exit_code, rendered, stderr) = run_too_fresh_assess(&["--policy-mode", "elevated-risk"]);

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    assert!(rendered.contains("Suggested classification: policy-violating"));
    assert!(rendered.contains("Blocking policy findings:"));
    assert!(!rendered.contains("Elevated-risk findings accepted by --policy-mode elevated-risk"));
}

fn run_too_fresh_assess(args: &[&str]) -> (ExitCode, String, String) {
    let mut raw_args = vec!["cargo-barbican", "assess"];
    raw_args.extend_from_slice(args);
    let cli = Cli::parse_from(raw_args);
    let client =
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2020-05-26T00:00:00Z", false);
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

    (
        exit_code,
        String::from_utf8(stdout).expect("stdout should be utf8"),
        String::from_utf8(stderr).expect("stderr should be utf8"),
    )
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

#[test]
fn audit_runs_cargo_deny_json_by_default() {
    let cli = Cli::parse_from(["cargo-barbican", "audit"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(runner.recorded_audit_calls().is_empty());
    assert_eq!(runner.recorded_audit_json_calls().len(), 0);
    let deny_calls = runner.recorded_deny_json_calls();
    assert_eq!(deny_calls.len(), 1);
    assert_eq!(
        deny_calls[0].2,
        vec![
            barbican::CargoDenyCheck::Advisories,
            barbican::CargoDenyCheck::Bans,
            barbican::CargoDenyCheck::Sources,
        ]
    );
}

#[test]
fn audit_reports_failures() {
    let cli = Cli::parse_from(["cargo-barbican", "audit"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default().with_cargo_deny_json("not-json");
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(runner.recorded_audit_calls().is_empty());
    assert_eq!(runner.recorded_deny_json_calls().len(), 1);
    assert!(
        String::from_utf8(stderr)
            .expect("stderr should be utf8")
            .contains("FAIL cargo deny structured output:")
    );
}

#[test]
fn audit_accepts_reviewed_advisory_with_cargo_deny_scanner() {
    let cli = Cli::parse_from(["cargo-barbican", "audit"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default().with_cargo_deny_json(&cargo_deny_advisory_jsonl());
    let temp_dir = fresh_temp_dir();
    write_advisory_audit_fixture(&temp_dir, None, "2026-09-21");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

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
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Audit: PASS"));
    assert!(rendered.contains("Allowed policy exceptions:"));
    assert!(rendered.contains("serde@1.0.228 RUSTSEC-2026-0001 accepted by reviewed family"));
    assert_eq!(runner.recorded_deny_json_calls().len(), 1);
    assert!(runner.recorded_audit_json_calls().is_empty());
}

#[test]
fn audit_fails_unreviewed_advisory_with_cargo_deny_scanner() {
    let cli = Cli::parse_from(["cargo-barbican", "audit"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default().with_cargo_deny_json(&cargo_deny_advisory_jsonl());
    let temp_dir = fresh_temp_dir();
    fs::write(temp_dir.join("barbican.toml"), "").expect("config should write");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

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
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Audit: FAIL"));
    assert!(rendered.contains("FAIL RUSTSEC-2026-0001 serde@1.0.228: unreviewed advisory finding"));
    assert!(!rendered.contains("Allowed policy exceptions:"));
}

#[test]
fn audit_fails_expired_reviewed_advisory_with_cargo_deny_scanner() {
    let cli = Cli::parse_from(["cargo-barbican", "audit"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default().with_cargo_deny_json(&cargo_deny_advisory_jsonl());
    let temp_dir = fresh_temp_dir();
    write_advisory_audit_fixture(&temp_dir, None, "2000-01-01");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

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
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Audit: FAIL"));
    assert!(rendered.contains("reviewed advisory exception expired"));
}

#[test]
fn audit_accepts_reviewed_advisory_with_cargo_audit_scanner() {
    let cli = Cli::parse_from(["cargo-barbican", "audit"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default().with_cargo_audit_json(&cargo_audit_advisory_json());
    let temp_dir = fresh_temp_dir();
    write_advisory_audit_fixture(
        &temp_dir,
        Some(r#"lockfile_scanner = "cargo-audit""#),
        "2026-09-21",
    );
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

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
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Audit: PASS"));
    assert!(rendered.contains("Allowed policy exceptions:"));
    assert_eq!(runner.recorded_deny_json_calls().len(), 1);
    assert_eq!(runner.recorded_audit_json_calls().len(), 1);
    assert_ne!(runner.recorded_audit_json_calls()[0].0, temp_dir);
}

#[test]
fn audit_accepts_reviewed_advisory_with_both_scanners() {
    let cli = Cli::parse_from(["cargo-barbican", "audit"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default()
        .with_cargo_deny_json(&cargo_deny_advisory_jsonl())
        .with_cargo_audit_json(&cargo_audit_advisory_json());
    let temp_dir = fresh_temp_dir();
    write_advisory_audit_fixture(
        &temp_dir,
        Some(r#"lockfile_scanner = "both""#),
        "2026-09-21",
    );
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

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
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert_eq!(rendered.matches("accepted by reviewed family").count(), 1);
    assert_eq!(runner.recorded_deny_json_calls().len(), 1);
    assert_eq!(runner.recorded_audit_json_calls().len(), 1);
}

#[test]
fn audit_generated_deny_config_neutralises_native_advisory_ignore() {
    let cli = Cli::parse_from(["cargo-barbican", "audit"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    fs::write(
        temp_dir.join("deny.toml"),
        r#"[advisories]
ignore = ["RUSTSEC-2026-0001"]
unmaintained = "allow"
"#,
    )
    .expect("deny config should write");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    let generated = runner.recorded_deny_json_config_texts();
    assert_eq!(generated.len(), 1);
    assert!(generated[0].contains("ignore = []"));
    assert!(!generated[0].contains("RUSTSEC-2026-0001"));
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Native delegated advisory ignores:"));
    assert!(rendered.contains("WARN deny.toml ignores RUSTSEC-2026-0001"));
}

#[test]
fn audit_uses_controlled_cwd_to_neutralise_cargo_audit_config() {
    let cli = Cli::parse_from(["cargo-barbican", "audit"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    fs::write(
        temp_dir.join("barbican.toml"),
        r#"[delegates.advisories]
lockfile_scanner = "cargo-audit"
"#,
    )
    .expect("config should write");
    fs::create_dir_all(temp_dir.join(".cargo")).expect("cargo config dir should exist");
    fs::write(
        temp_dir.join(".cargo/audit.toml"),
        r#"[advisories]
ignore = ["RUSTSEC-2026-0001"]
"#,
    )
    .expect("cargo audit config should write");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    let audit_calls = runner.recorded_audit_json_calls();
    assert_eq!(audit_calls.len(), 1);
    assert_ne!(audit_calls[0].0, temp_dir);
    assert_eq!(audit_calls[0].1, temp_dir.join("Cargo.lock"));
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("WARN .cargo/audit.toml ignores RUSTSEC-2026-0001"));
}

#[test]
fn audit_runs_cargo_deny_checks_when_cargo_audit_scans_advisories() {
    let cli = Cli::parse_from(["cargo-barbican", "audit"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default().with_cargo_deny_json(&cargo_deny_bans_error_jsonl());
    let temp_dir = fresh_temp_dir();
    fs::write(
        temp_dir.join("barbican.toml"),
        r#"[delegates.advisories]
lockfile_scanner = "cargo-audit"
"#,
    )
    .expect("config should write");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    assert_eq!(runner.recorded_deny_json_calls().len(), 1);
    assert_eq!(runner.recorded_audit_json_calls().len(), 1);
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("FAIL cargo-deny diagnostic without advisory id"));
    assert!(rendered.contains("FAIL cargo-deny bans check reported 1 error(s)"));
}

#[test]
fn audit_fails_native_delegated_ignore_when_policy_is_deny() {
    let cli = Cli::parse_from(["cargo-barbican", "audit"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    fs::write(
        temp_dir.join("barbican.toml"),
        r#"[delegates]
unmanaged_delegated_policy = "deny"
"#,
    )
    .expect("config should write");
    fs::write(
        temp_dir.join("deny.toml"),
        r#"[advisories]
ignore = ["RUSTSEC-2026-0001"]
"#,
    )
    .expect("deny config should write");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Audit: FAIL"));
    assert!(rendered.contains("Native delegated advisory ignores:"));
    assert!(rendered.contains("FAIL deny.toml ignores RUSTSEC-2026-0001"));
}

#[cfg(unix)]
#[test]
fn audit_rejects_symlinked_deny_toml_without_reading_target() {
    use std::os::unix::fs::symlink;

    let cli = Cli::parse_from(["cargo-barbican", "audit"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    fs::write(temp_dir.join("secret.env"), "SECRET_TOKEN=do-not-print\n")
        .expect("secret target should write");
    symlink(temp_dir.join("secret.env"), temp_dir.join("deny.toml"))
        .expect("deny.toml symlink should create");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let error = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect_err("symlinked deny.toml should fail closed");

    let rendered_error = error.to_string();
    assert!(rendered_error.contains("deny.toml is a symlink"));
    assert!(!rendered_error.contains("SECRET_TOKEN"));
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
}

#[cfg(unix)]
#[test]
fn audit_rejects_symlinked_barbican_toml_without_reading_target() {
    use std::os::unix::fs::symlink;

    let cli = Cli::parse_from(["cargo-barbican", "audit"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    fs::write(temp_dir.join("secret.env"), "SECRET_TOKEN=do-not-print\n")
        .expect("secret target should write");
    symlink(temp_dir.join("secret.env"), temp_dir.join("barbican.toml"))
        .expect("barbican.toml symlink should create");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let error = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect_err("symlinked barbican.toml should fail closed");

    let rendered_error = error.to_string();
    assert!(rendered_error.contains("barbican.toml is a symlink"));
    assert!(!rendered_error.contains("SECRET_TOKEN"));
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
}

#[cfg(unix)]
#[test]
fn audit_rejects_symlinked_reviewed_targets_without_reading_target() {
    use std::os::unix::fs::symlink;

    let cli = Cli::parse_from(["cargo-barbican", "audit"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    fs::write(temp_dir.join("secret.env"), "SECRET_TOKEN=do-not-print\n")
        .expect("secret target should write");
    symlink(
        temp_dir.join("secret.env"),
        temp_dir.join("reviewed-targets.toml"),
    )
    .expect("reviewed-targets.toml symlink should create");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let error = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect_err("symlinked reviewed-targets.toml should fail closed");

    let rendered_error = error.to_string();
    assert!(rendered_error.contains("reviewed-targets.toml is a symlink"));
    assert!(!rendered_error.contains("SECRET_TOKEN"));
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
}

#[test]
fn audit_loads_regular_barbican_and_reviewed_targets_files() {
    let cli = Cli::parse_from(["cargo-barbican", "audit"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    fs::write(
        temp_dir.join("barbican.toml"),
        r#"[delegates.advisories]
lockfile_scanner = "cargo-deny"
"#,
    )
    .expect("barbican config should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        "[rust]\nfamilies = []\n",
    )
    .expect("reviewed targets should write");
    fs::write(temp_dir.join("Cargo.toml"), "[dependencies]\n").expect("manifest should write");
    fs::write(temp_dir.join("Cargo.lock"), "version = 4\n").expect("lockfile should write");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("regular policy files should load");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(
        String::from_utf8(stdout)
            .expect("stdout should be utf8")
            .contains("Audit: PASS")
    );
    assert!(stderr.is_empty());
}

#[test]
fn audit_reports_cargo_audit_settings_ignore_and_idless_warnings() {
    let cli = Cli::parse_from(["cargo-barbican", "audit"]);
    let client = FakeCratesIoClient::default();
    let runner =
        FakeCommandRunner::default().with_cargo_audit_json(&cargo_audit_ignored_and_idless_json());
    let temp_dir = fresh_temp_dir();
    fs::write(
        temp_dir.join("barbican.toml"),
        r#"[delegates.advisories]
lockfile_scanner = "cargo-audit"
"#,
    )
    .expect("config should write");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Audit: FAIL"));
    assert!(
        rendered
            .contains("FAIL cargo-audit runtime settings.ignore still contains RUSTSEC-2026-0001")
    );
    assert!(rendered.contains("FAIL cargo-audit reported 1 warning(s) without advisory ids"));
}

#[test]
fn audit_fails_closed_on_cargo_audit_parse_errors() {
    let cli = Cli::parse_from(["cargo-barbican", "audit"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default().with_cargo_audit_json("not-json");
    let temp_dir = fresh_temp_dir();
    fs::write(
        temp_dir.join("barbican.toml"),
        r#"[delegates.advisories]
lockfile_scanner = "cargo-audit"
"#,
    )
    .expect("config should write");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    assert!(
        String::from_utf8(stderr)
            .expect("stderr should be utf8")
            .contains("FAIL cargo audit structured output:")
    );
}

#[test]
fn verify_fails_when_reviewed_targets_manifest_is_absent() {
    let cli = Cli::parse_from(["cargo-barbican", "verify"]);
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
            .contains("FAIL reviewed-targets.toml: reviewed-targets policy required for verify")
    );
    assert_eq!(*runner.build_calls.borrow(), 0);
    assert_eq!(*runner.test_calls.borrow(), 0);
}

#[test]
fn verify_runs_pin_check_before_build_and_test() {
    let cli = Cli::parse_from(["cargo-barbican", "verify"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.228\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_package_records(&[
            (
                "serde",
                "1.0.228",
                Some("registry+https://github.com/rust-lang/crates.io-index"),
                Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
            ),
            (
                "serde_derive",
                "1.0.228",
                Some("registry+https://github.com/rust-lang/crates.io-index"),
                None,
            ),
        ]),
    )
    .expect("lockfile should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        r#"[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.direct]
serde = "=1.0.228"

[rust.families.resolved]
serde = { version = "1.0.228", checksum_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }
serde_derive = "1.0.228"

[rust.families.allowed_surfaces]
serde = ["build-rs"]
"#,
    )
    .expect("reviewed targets should write");
    write_review_record(&temp_dir, "docs/dependency-reviews/2026-05-27-serde.md");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Pin check: PASS"));
    assert_eq!(*runner.build_calls.borrow(), 1);
    assert_eq!(*runner.test_calls.borrow(), 1);
}

#[test]
fn verify_stops_before_build_on_reviewed_target_drift() {
    let cli = Cli::parse_from(["cargo-barbican", "verify"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"1\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_packages(&[("serde", "1.0.227", true)]),
    )
    .expect("lockfile should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        r#"[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.direct]
serde = "=1.0.228"

[rust.families.resolved]
serde = "1.0.228"
"#,
    )
    .expect("reviewed targets should write");
    write_review_record(&temp_dir, "docs/dependency-reviews/2026-05-27-serde.md");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Pin check: FAIL"));
    assert_eq!(*runner.build_calls.borrow(), 0);
    assert_eq!(*runner.test_calls.borrow(), 0);
}

#[test]
fn age_smoke_tests_the_ureq_client_against_a_local_http_server() {
    let cli = Cli::parse_from(["cargo-barbican", "age", "serde@1.0.228"]);
    let Some((base_url, requests, handle)) = spawn_http_stub(
        "HTTP/1.1 200 OK",
        r#"{"version":{"checksum":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","created_at":"2026-05-01T00:00:00Z","yanked":false}}"#,
    ) else {
        eprintln!("[SKIP] no loopback bind available - skipping HTTP smoke test");
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
        eprintln!("[SKIP] no loopback bind available - skipping HTTP smoke test");
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

#[test]
fn inspect_reports_routine_safe_for_clean_crate() {
    let tarball = build_crate_tarball(&[
        (
            "Cargo.toml",
            "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n",
        ),
        ("src/lib.rs", "pub fn ok() {}\n"),
        (
            ".cargo_vcs_info.json",
            "{\n  \"git\": {\"sha1\": \"abc123\"},\n  \"path_in_vcs\": \"sample\"\n}\n",
        ),
    ]);
    let checksum = sha256_hex(&tarball);
    let cli = Cli::parse_from(["cargo-barbican", "inspect", "sample@0.1.0"]);
    let client = FakeCratesIoClient::default()
        .with_release_checksum("sample@0.1.0", "2026-05-01T00:00:00Z", false, &checksum)
        .with_tarball("sample@0.1.0", &tarball);
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Inspect sample@0.1.0"));
    assert!(rendered.contains("classification: routine-safe"));
    assert!(rendered.contains("checksum: ok"));
    assert!(rendered.contains("provenance: git abc123 (sample)"));
    assert!(rendered.contains("build.rs surfaces: none"));
    assert!(rendered.contains("proc-macro surface: no"));
    assert_eq!(client.recorded_fetches(), vec!["sample@0.1.0".to_owned()]);
    assert_eq!(
        client.recorded_tarball_fetches(),
        vec!["sample@0.1.0".to_owned()]
    );
}

#[test]
fn gatehouse_candidate_renders_isolated_dossier_and_cleans_up_sandbox() {
    let tarball = build_crate_tarball(&[
        (
            "Cargo.toml",
            "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n",
        ),
        ("src/lib.rs", "pub fn ok() {}\n"),
        (
            ".cargo_vcs_info.json",
            "{\n  \"git\": {\"sha1\": \"abc123\"},\n  \"path_in_vcs\": \"sample\"\n}\n",
        ),
    ]);
    let checksum = sha256_hex(&tarball);
    let cli = Cli::parse_from(["cargo-barbican", "gatehouse", "candidate", "sample@0.1.0"]);
    let client = FakeCratesIoClient::default()
        .with_release_checksum("sample@0.1.0", "2020-05-01T00:00:00Z", false, &checksum)
        .with_tarball("sample@0.1.0", &tarball);
    let runner = FakeCommandRunner::default()
        .with_cargo_tree("cargo-barbican-gatehouse-candidate v0.0.0\n+-- sample v0.1.0\n")
        .with_cargo_audit("No vulnerable packages found\n");
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

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
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Gatehouse candidate: sample@0.1.0"));
    assert!(rendered.contains("Inspect evidence:"));
    assert!(rendered.contains("classification: routine-safe"));
    assert!(rendered.contains("Sandbox lockfile:"));
    assert!(rendered.contains("OK generated with cargo generate-lockfile"));
    assert!(rendered.contains("Cargo tree:"));
    assert!(rendered.contains("sample v0.1.0"));
    assert!(rendered.contains("Cargo audit:"));
    assert!(rendered.contains("No vulnerable packages found"));
    assert!(rendered.contains("Suggested next step:"));
    assert_eq!(client.recorded_fetches(), vec!["sample@0.1.0".to_owned()]);
    assert_eq!(
        client.recorded_tarball_fetches(),
        vec!["sample@0.1.0".to_owned()]
    );
    let lockfile_calls = runner.recorded_generate_lockfile_calls();
    assert_eq!(lockfile_calls.len(), 1);
    assert_eq!(runner.recorded_cargo_tree_calls(), lockfile_calls);
    assert_eq!(runner.recorded_audit_calls(), lockfile_calls);
    assert!(!lockfile_calls[0].exists());
    assert!(!temp_dir.join("Cargo.toml").exists());
    assert!(!temp_dir.join("Cargo.lock").exists());
}

#[test]
fn gatehouse_candidate_preserves_sandbox_when_requested() {
    let tarball = build_crate_tarball(&[
        (
            "Cargo.toml",
            "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n",
        ),
        ("src/lib.rs", "pub fn ok() {}\n"),
    ]);
    let checksum = sha256_hex(&tarball);
    let cli = Cli::parse_from([
        "cargo-barbican",
        "gatehouse",
        "candidate",
        "--preserve-sandbox",
        "sample@0.1.0",
    ]);
    let client = FakeCratesIoClient::default()
        .with_release_checksum("sample@0.1.0", "2020-05-01T00:00:00Z", false, &checksum)
        .with_tarball("sample@0.1.0", &tarball);
    let runner = FakeCommandRunner::default()
        .with_cargo_tree("sample v0.1.0\n")
        .with_cargo_audit("No vulnerable packages found\n");
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

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
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("status: preserved for inspection"));
    let sandbox_path = runner.recorded_generate_lockfile_calls()[0].clone();
    assert!(sandbox_path.is_dir());
    assert!(rendered.contains(&sandbox_path.display().to_string()));
    assert!(sandbox_path.join("src/lib.rs").is_file());
    assert!(sandbox_path.join("Cargo.lock").is_file());
    assert!(
        fs::read_to_string(sandbox_path.join("Cargo.toml"))
            .expect("candidate manifest should read")
            .contains("\"sample\" = \"=0.1.0\"")
    );

    fs::remove_dir_all(sandbox_path).expect("preserved sandbox should clean up");
}

#[test]
fn gatehouse_candidate_rejects_non_exact_specs_before_sandboxing() {
    let cli = Cli::parse_from(["cargo-barbican", "gatehouse", "candidate", "sample"]);
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
            .contains("Expected exact crate@version spec")
    );
    assert!(runner.recorded_generate_lockfile_calls().is_empty());
}

#[test]
fn gatehouse_candidate_reports_cargo_audit_failures_in_the_dossier() {
    let tarball = build_crate_tarball(&[
        (
            "Cargo.toml",
            "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n",
        ),
        ("src/lib.rs", "pub fn ok() {}\n"),
    ]);
    let checksum = sha256_hex(&tarball);
    let cli = Cli::parse_from(["cargo-barbican", "gatehouse", "candidate", "sample@0.1.0"]);
    let client = FakeCratesIoClient::default()
        .with_release_checksum("sample@0.1.0", "2020-05-01T00:00:00Z", false, &checksum)
        .with_tarball("sample@0.1.0", &tarball);
    let runner = FakeCommandRunner::default()
        .with_cargo_tree("sample v0.1.0\n")
        .with_cargo_audit_error("vulnerable dependency found");
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

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
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Cargo audit:"));
    assert!(rendered.contains("FAIL command exited with status 1"));
    assert!(rendered.contains("stderr: vulnerable dependency found"));
    assert!(
        rendered.contains("Do not admit this candidate until the failed evidence is reviewed.")
    );
    assert!(!runner.recorded_generate_lockfile_calls()[0].exists());
}

#[test]
fn gatehouse_candidate_reports_fetch_failures_in_the_dossier() {
    let cli = Cli::parse_from(["cargo-barbican", "gatehouse", "candidate", "sample@0.1.0"]);
    let client = FakeCratesIoClient::default().with_error(
        "sample@0.1.0",
        CratesIoClientError::Transport {
            reason: "network blocked".to_owned(),
        },
    );
    let runner = FakeCommandRunner::default()
        .with_cargo_tree("sample v0.1.0\n")
        .with_cargo_audit("No vulnerable packages found\n");
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Inspect evidence:"));
    assert!(rendered.contains("FAIL sample@0.1.0: unable to reach crates.io (network blocked)"));
    assert!(rendered.contains("Cargo tree:"));
    assert!(rendered.contains("Cargo audit:"));
    assert!(
        rendered.contains("Do not admit this candidate until the failed evidence is reviewed.")
    );
    assert!(!runner.recorded_generate_lockfile_calls()[0].exists());
}

#[test]
fn gatehouse_candidate_reports_tarball_fetch_failures_in_the_dossier() {
    let cli = Cli::parse_from(["cargo-barbican", "gatehouse", "candidate", "sample@0.1.0"]);
    let client = FakeCratesIoClient::default().with_release_checksum(
        "sample@0.1.0",
        "2020-05-01T00:00:00Z",
        false,
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
    let runner = FakeCommandRunner::default()
        .with_cargo_tree("sample v0.1.0\n")
        .with_cargo_audit("No vulnerable packages found\n");
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Inspect evidence:"));
    assert!(
        rendered.contains(
            "FAIL sample@0.1.0: unable to reach crates.io (missing fake tarball response)"
        )
    );
    assert!(rendered.contains("Cargo tree:"));
    assert!(rendered.contains("Cargo audit:"));
    assert!(
        rendered.contains("Do not admit this candidate until the failed evidence is reviewed.")
    );
    assert!(!runner.recorded_generate_lockfile_calls()[0].exists());
}

#[test]
fn gatehouse_candidate_keeps_collecting_evidence_after_non_routine_inspect() {
    let tarball = build_crate_tarball(&[
        (
            "Cargo.toml",
            "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n",
        ),
        ("build.rs", "fn main() {}\n"),
        ("src/lib.rs", "pub fn ok() {}\n"),
    ]);
    let checksum = sha256_hex(&tarball);
    let cli = Cli::parse_from(["cargo-barbican", "gatehouse", "candidate", "sample@0.1.0"]);
    let client = FakeCratesIoClient::default()
        .with_release_checksum("sample@0.1.0", "2020-05-01T00:00:00Z", false, &checksum)
        .with_tarball("sample@0.1.0", &tarball);
    let runner = FakeCommandRunner::default()
        .with_cargo_tree("sample v0.1.0\n")
        .with_cargo_audit("No vulnerable packages found\n");
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

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
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("classification: elevated-risk"));
    assert!(rendered.contains("build.rs surfaces: build.rs"));
    assert!(rendered.contains("Sandbox lockfile:"));
    assert!(rendered.contains("Cargo tree:"));
    assert!(rendered.contains("Cargo audit:"));
    assert_eq!(runner.recorded_cargo_tree_calls().len(), 1);
    assert_eq!(runner.recorded_audit_calls().len(), 1);
}

#[test]
fn gatehouse_candidate_honours_injected_clock_for_release_age() {
    // An otherwise-clean crate published 6 days before `fixed_now()` (2020-06-01)
    // is too fresh and must classify policy-violating. Age is the sole driver
    // here, so this guards the gatehouse candidate call site's clock wiring:
    // under the wall clock the release would read as years old and wrongly pass.
    let tarball = build_crate_tarball(&[
        (
            "Cargo.toml",
            "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n",
        ),
        ("src/lib.rs", "pub fn ok() {}\n"),
    ]);
    let checksum = sha256_hex(&tarball);
    let cli = Cli::parse_from(["cargo-barbican", "gatehouse", "candidate", "sample@0.1.0"]);
    let client = FakeCratesIoClient::default()
        .with_release_checksum("sample@0.1.0", "2020-05-26T00:00:00Z", false, &checksum)
        .with_tarball("sample@0.1.0", &tarball);
    let runner = FakeCommandRunner::default()
        .with_cargo_tree("sample v0.1.0\n")
        .with_cargo_audit("No vulnerable packages found\n");
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

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
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("classification: policy-violating"));
    assert!(rendered.contains("below the 7-day minimum"));
}

#[test]
fn gatehouse_candidate_lockfile_generation_failure_skips_later_evidence() {
    let tarball = build_crate_tarball(&[
        (
            "Cargo.toml",
            "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n",
        ),
        ("src/lib.rs", "pub fn ok() {}\n"),
    ]);
    let checksum = sha256_hex(&tarball);
    let cli = Cli::parse_from(["cargo-barbican", "gatehouse", "candidate", "sample@0.1.0"]);
    let client = FakeCratesIoClient::default()
        .with_release_checksum("sample@0.1.0", "2020-05-01T00:00:00Z", false, &checksum)
        .with_tarball("sample@0.1.0", &tarball);
    let runner = FakeCommandRunner::default().with_cargo_generate_lockfile_error("lock failed");
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

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
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Sandbox lockfile:"));
    assert!(rendered.contains("FAIL command exited with status 1"));
    assert!(rendered.contains("stderr: lock failed"));
    assert!(!rendered.contains("Cargo tree:"));
    assert!(!rendered.contains("Cargo audit:"));
    assert!(runner.recorded_cargo_tree_calls().is_empty());
    assert!(runner.recorded_audit_calls().is_empty());
    assert!(!runner.recorded_generate_lockfile_calls()[0].exists());
}

#[test]
fn gatehouse_candidate_renders_empty_success_output_explicitly() {
    let tarball = build_crate_tarball(&[
        (
            "Cargo.toml",
            "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n",
        ),
        ("src/lib.rs", "pub fn ok() {}\n"),
    ]);
    let checksum = sha256_hex(&tarball);
    let cli = Cli::parse_from(["cargo-barbican", "gatehouse", "candidate", "sample@0.1.0"]);
    let client = FakeCratesIoClient::default()
        .with_release_checksum("sample@0.1.0", "2020-05-01T00:00:00Z", false, &checksum)
        .with_tarball("sample@0.1.0", &tarball);
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

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
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Cargo tree:\n  OK\n  output: none"));
    assert!(rendered.contains("Cargo audit:\n  OK\n  output: none"));
}

#[test]
fn gatehouse_candidate_reports_cargo_tree_failures_in_the_dossier() {
    let tarball = build_crate_tarball(&[
        (
            "Cargo.toml",
            "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n",
        ),
        ("src/lib.rs", "pub fn ok() {}\n"),
    ]);
    let checksum = sha256_hex(&tarball);
    let cli = Cli::parse_from(["cargo-barbican", "gatehouse", "candidate", "sample@0.1.0"]);
    let client = FakeCratesIoClient::default()
        .with_release_checksum("sample@0.1.0", "2020-05-01T00:00:00Z", false, &checksum)
        .with_tarball("sample@0.1.0", &tarball);
    let runner = FakeCommandRunner::default()
        .with_cargo_tree_error("tree failed")
        .with_cargo_audit("No vulnerable packages found\n");
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

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
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Cargo tree:"));
    assert!(rendered.contains("stderr: tree failed"));
    assert!(rendered.contains("Cargo audit:"));
    assert!(rendered.contains("No vulnerable packages found"));
}

#[test]
fn inspect_honours_injected_clock_for_release_age() {
    // An otherwise-clean crate published 6 days before `fixed_now()` (2020-06-01)
    // is too fresh and must classify policy-violating. Age is the sole driver
    // here, so this guards the inspect call site's clock wiring: under the wall
    // clock the release would read as years old and wrongly pass routine-safe.
    let tarball = build_crate_tarball(&[
        (
            "Cargo.toml",
            "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n",
        ),
        ("src/lib.rs", "pub fn ok() {}\n"),
        (
            ".cargo_vcs_info.json",
            "{\n  \"git\": {\"sha1\": \"abc123\"},\n  \"path_in_vcs\": \"sample\"\n}\n",
        ),
    ]);
    let checksum = sha256_hex(&tarball);
    let cli = Cli::parse_from(["cargo-barbican", "inspect", "sample@0.1.0"]);
    let client = FakeCratesIoClient::default()
        .with_release_checksum("sample@0.1.0", "2020-05-26T00:00:00Z", false, &checksum)
        .with_tarball("sample@0.1.0", &tarball);
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

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
    let rendered = String::from_utf8(stderr).expect("stderr should be utf8");
    assert!(rendered.contains("classification: policy-violating"));
    assert!(rendered.contains("below the 7-day minimum"));
}

#[test]
fn inspect_renders_reviewed_release_age_exception() {
    let tarball = build_crate_tarball(&[
        (
            "Cargo.toml",
            "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n",
        ),
        ("src/lib.rs", "pub fn ok() {}\n"),
    ]);
    let checksum = sha256_hex(&tarball);
    let cli = Cli::parse_from(["cargo-barbican", "inspect", "sample@0.1.0"]);
    let client = FakeCratesIoClient::default()
        .with_release_checksum("sample@0.1.0", "2020-05-26T00:00:00Z", false, &checksum)
        .with_tarball("sample@0.1.0", &tarball);
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    write_age_exception_policy(&temp_dir, "sample", "0.1.0", &checksum, true);

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
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("classification: routine-safe"));
    assert!(rendered.contains("release age: ALLOW sample@0.1.0"));
    assert!(rendered.contains(
        "release-age exception allowed by reviewed family sample-family (docs/dependency-reviews/2026-05-27-sample.md)"
    ));
}

#[test]
fn gatehouse_candidate_renders_reviewed_release_age_exception() {
    let tarball = build_crate_tarball(&[
        (
            "Cargo.toml",
            "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n",
        ),
        ("src/lib.rs", "pub fn ok() {}\n"),
    ]);
    let checksum = sha256_hex(&tarball);
    let cli = Cli::parse_from(["cargo-barbican", "gatehouse", "candidate", "sample@0.1.0"]);
    let client = FakeCratesIoClient::default()
        .with_release_checksum("sample@0.1.0", "2020-05-26T00:00:00Z", false, &checksum)
        .with_tarball("sample@0.1.0", &tarball);
    let runner = FakeCommandRunner::default()
        .with_cargo_tree("sample v0.1.0")
        .with_cargo_audit("No vulnerable packages found");
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    write_age_exception_policy(&temp_dir, "sample", "0.1.0", &checksum, true);

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
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Gatehouse candidate: sample@0.1.0"));
    assert!(rendered.contains("release age: ALLOW sample@0.1.0"));
    assert!(rendered.contains(
        "release-age exception allowed by reviewed family sample-family (docs/dependency-reviews/2026-05-27-sample.md)"
    ));
}

#[test]
fn inspect_reports_elevated_risk_for_build_script_and_native_surface() {
    let tarball = build_crate_tarball(&[
        (
            "Cargo.toml",
            "[package]\nname = \"native-sys\"\nversion = \"0.1.0\"\nlinks = \"native\"\n",
        ),
        ("build.rs", "fn main() {}\n"),
        ("src/lib.rs", "pub fn ok() {}\n"),
        ("vendor/native.c", "int native(void) { return 0; }\n"),
    ]);
    let checksum = sha256_hex(&tarball);
    let cli = Cli::parse_from(["cargo-barbican", "inspect", "native-sys@0.1.0"]);
    let client = FakeCratesIoClient::default()
        .with_release_checksum("native-sys@0.1.0", "2026-05-01T00:00:00Z", false, &checksum)
        .with_tarball("native-sys@0.1.0", &tarball);
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    let rendered = String::from_utf8(stderr).expect("stderr should be utf8");
    assert!(rendered.contains("classification: elevated-risk"));
    assert!(rendered.contains("build.rs surfaces: build.rs"));
    assert!(rendered.contains("crate name ends with -sys"));
    assert!(rendered.contains("package.links=native"));
    assert!(rendered.contains("native sources: vendor/native.c"));
}

#[test]
fn inspect_reports_policy_violation_for_checksum_mismatch() {
    let tarball = build_crate_tarball(&[
        (
            "Cargo.toml",
            "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n",
        ),
        (
            "build.rs",
            "fn main() { std::process::Command::new(\"curl\"); }\n",
        ),
    ]);
    let cli = Cli::parse_from(["cargo-barbican", "inspect", "sample@0.1.0"]);
    let client = FakeCratesIoClient::default()
        .with_release_checksum(
            "sample@0.1.0",
            "2026-05-01T00:00:00Z",
            false,
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        )
        .with_tarball("sample@0.1.0", &tarball);
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    let rendered = String::from_utf8(stderr).expect("stderr should be utf8");
    assert!(rendered.contains("classification: policy-violating"));
    assert!(rendered.contains("checksum: FAIL local sha256"));
    assert!(rendered.contains("build.rs surfaces: none"));
    assert!(rendered.contains("IOC hits: none"));
}

#[test]
fn pin_check_skips_when_reviewed_targets_manifest_is_absent() {
    let cli = Cli::parse_from(["cargo-barbican", "pin-check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.228\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_packages(&[("serde", "1.0.228", true)]),
    )
    .expect("lockfile should write");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert_eq!(
        String::from_utf8(stdout).expect("stdout should be utf8"),
        "Pin check: no reviewed-targets.toml present; skipping.\n"
    );
    assert!(stderr.is_empty());
}

#[test]
fn pin_check_passes_when_reviewed_targets_match_manifest_and_lockfile() {
    let cli = Cli::parse_from(["cargo-barbican", "pin-check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.228\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_package_records(&[
            (
                "serde",
                "1.0.228",
                Some("registry+https://github.com/rust-lang/crates.io-index"),
                Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
            ),
            (
                "serde_derive",
                "1.0.228",
                Some("registry+https://github.com/rust-lang/crates.io-index"),
                None,
            ),
        ]),
    )
    .expect("lockfile should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        r#"[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.direct]
serde = "=1.0.228"

[rust.families.resolved]
serde = { version = "1.0.228", checksum_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }
serde_derive = "1.0.228"
"#,
    )
    .expect("reviewed targets should write");
    write_review_record(&temp_dir, "docs/dependency-reviews/2026-05-27-serde.md");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Pin check: PASS"));
    assert!(rendered.contains("family: serde-family"));
    assert!(rendered.contains("review record ok at docs/dependency-reviews/2026-05-27-serde.md"));
    assert!(rendered.contains("direct spec ok for serde=1.0.228"));
    assert!(rendered.contains(
        "Cargo.lock ok for serde: matched {version=1.0.228, checksum_sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}"
    ));
    assert!(rendered.contains("Cargo.lock ok for serde_derive: matched {version=1.0.228}"));
}

#[test]
fn pin_check_renders_reviewed_advisory_exceptions() {
    let cli = Cli::parse_from(["cargo-barbican", "pin-check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.228\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_package_records(&[(
            "serde",
            "1.0.228",
            Some("registry+https://github.com/rust-lang/crates.io-index"),
            Some(checksum),
        )]),
    )
    .expect("lockfile should write");
    write_advisory_exception_policy(&temp_dir, "serde", "1.0.228", checksum, "2026-09-21", true);

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Pin check: PASS"));
    assert!(rendered.contains("Allowed policy exceptions:"));
    assert!(rendered.contains(
        "  - serde@1.0.228 RUSTSEC-2026-0001 accepted by reviewed family serde-family (docs/dependency-reviews/2026-05-27-serde.md), review by 2026-09-21"
    ));
}

#[test]
fn pin_check_fails_when_advisory_exception_review_record_is_missing() {
    let cli = Cli::parse_from(["cargo-barbican", "pin-check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.228\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_package_records(&[(
            "serde",
            "1.0.228",
            Some("registry+https://github.com/rust-lang/crates.io-index"),
            Some(checksum),
        )]),
    )
    .expect("lockfile should write");
    write_advisory_exception_policy(&temp_dir, "serde", "1.0.228", checksum, "2026-09-21", false);

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Pin check: FAIL"));
    assert!(
        rendered.contains("review record missing at docs/dependency-reviews/2026-05-27-serde.md")
    );
    assert!(!rendered.contains("Allowed policy exceptions:"));
}

#[test]
fn pin_check_does_not_fail_when_advisory_review_by_has_elapsed() {
    // Pin-check renders reviewed advisory exceptions but does not apply advisory
    // lifecycle policy. Commands that use exceptions to suppress advisory
    // findings must enforce `review_by` expiry at that suppression point.
    let cli = Cli::parse_from(["cargo-barbican", "pin-check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.228\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_package_records(&[(
            "serde",
            "1.0.228",
            Some("registry+https://github.com/rust-lang/crates.io-index"),
            Some(checksum),
        )]),
    )
    .expect("lockfile should write");
    write_advisory_exception_policy(&temp_dir, "serde", "1.0.228", checksum, "2000-01-01", true);

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Pin check: PASS"));
    assert!(rendered.contains("review by 2000-01-01"));
}

#[test]
fn pin_check_fails_when_advisory_exception_resolved_target_drifts() {
    let cli = Cli::parse_from(["cargo-barbican", "pin-check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.228\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_package_records(&[(
            "serde",
            "1.0.227",
            Some("registry+https://github.com/rust-lang/crates.io-index"),
            Some(checksum),
        )]),
    )
    .expect("lockfile should write");
    write_advisory_exception_policy(&temp_dir, "serde", "1.0.228", checksum, "2026-09-21", true);

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Pin check: FAIL"));
    assert!(
        rendered
            .contains(r#"Cargo.lock mismatch for serde: expected {version=1.0.228, checksum_sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}, found versions ["1.0.227"], checksums ["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"]"#)
    );
    assert!(!rendered.contains("Allowed policy exceptions:"));
    assert!(!rendered.contains("accepted by reviewed family"));
}

#[test]
fn pin_check_does_not_render_advisory_exception_when_checksum_drifts() {
    let cli = Cli::parse_from(["cargo-barbican", "pin-check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let reviewed_checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let lockfile_checksum = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.228\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_package_records(&[(
            "serde",
            "1.0.228",
            Some("registry+https://github.com/rust-lang/crates.io-index"),
            Some(lockfile_checksum),
        )]),
    )
    .expect("lockfile should write");
    write_advisory_exception_policy(
        &temp_dir,
        "serde",
        "1.0.228",
        reviewed_checksum,
        "2026-09-21",
        true,
    );

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Pin check: FAIL"));
    assert!(
        rendered
            .contains(r#"Cargo.lock mismatch for serde: expected {version=1.0.228, checksum_sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}, found versions ["1.0.228"], checksums ["deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"]"#)
    );
    assert!(!rendered.contains("Allowed policy exceptions:"));
    assert!(!rendered.contains("accepted by reviewed family"));
}

#[test]
fn pin_check_renders_only_bound_advisory_exceptions_in_order() {
    let cli = Cli::parse_from(["cargo-barbican", "pin-check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let alpha_checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let beta_checksum = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    let drifted_checksum = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.228\"\nquote = \"=1.0.40\"\nsyn = \"=2.0.100\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_package_records(&[
            (
                "serde",
                "1.0.228",
                Some("registry+https://github.com/rust-lang/crates.io-index"),
                Some(alpha_checksum),
            ),
            (
                "syn",
                "2.0.99",
                Some("registry+https://github.com/rust-lang/crates.io-index"),
                Some(drifted_checksum),
            ),
            (
                "quote",
                "1.0.40",
                Some("registry+https://github.com/rust-lang/crates.io-index"),
                Some(beta_checksum),
            ),
        ]),
    )
    .expect("lockfile should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        format!(
            r#"[rust]

[[rust.families]]
name = "alpha-family"
review_record = "docs/dependency-reviews/2026-05-27-alpha.md"

[rust.families.direct]
serde = "=1.0.228"
syn = "=2.0.100"

[rust.families.resolved]
serde = {{ version = "1.0.228", checksum_sha256 = "{alpha_checksum}" }}
syn = {{ version = "2.0.100", checksum_sha256 = "{drifted_checksum}" }}

[rust.families.allowed_advisories]
serde = [
  {{ id = "RUSTSEC-2026-0001", review_by = "2026-09-21" }},
  {{ id = "RUSTSEC-2026-0002", review_by = "2026-10-01" }},
]
syn = [
  {{ id = "RUSTSEC-2026-9999", review_by = "2026-09-21" }},
]

[[rust.families]]
name = "beta-family"
review_record = "docs/dependency-reviews/2026-05-27-beta.md"

[rust.families.direct]
quote = "=1.0.40"

[rust.families.resolved]
quote = {{ version = "1.0.40", checksum_sha256 = "{beta_checksum}" }}

[rust.families.allowed_advisories]
quote = [
  {{ id = "RUSTSEC-2026-0003", review_by = "2026-11-01" }},
]
"#
        ),
    )
    .expect("reviewed targets should write");
    write_review_record(&temp_dir, "docs/dependency-reviews/2026-05-27-alpha.md");
    write_review_record(&temp_dir, "docs/dependency-reviews/2026-05-27-beta.md");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Pin check: FAIL"));
    assert!(rendered.contains("Allowed policy exceptions:"));
    let first = rendered
        .find("serde@1.0.228 RUSTSEC-2026-0001 accepted by reviewed family alpha-family")
        .expect("first serde advisory should render");
    let second = rendered
        .find("serde@1.0.228 RUSTSEC-2026-0002 accepted by reviewed family alpha-family")
        .expect("second serde advisory should render");
    let third = rendered
        .find("quote@1.0.40 RUSTSEC-2026-0003 accepted by reviewed family beta-family")
        .expect("quote advisory should render");
    assert!(first < second);
    assert!(second < third);
    assert!(!rendered.contains("syn@2.0.100 RUSTSEC-2026-9999 accepted by reviewed family"));
}

#[test]
fn pin_check_suppresses_advisory_exceptions_for_families_missing_review_records() {
    let cli = Cli::parse_from(["cargo-barbican", "pin-check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let alpha_checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let beta_checksum = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.228\"\nquote = \"=1.0.40\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_package_records(&[
            (
                "serde",
                "1.0.228",
                Some("registry+https://github.com/rust-lang/crates.io-index"),
                Some(alpha_checksum),
            ),
            (
                "quote",
                "1.0.40",
                Some("registry+https://github.com/rust-lang/crates.io-index"),
                Some(beta_checksum),
            ),
        ]),
    )
    .expect("lockfile should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        format!(
            r#"[rust]

[[rust.families]]
name = "alpha-family"
review_record = "docs/dependency-reviews/2026-05-27-alpha.md"

[rust.families.direct]
serde = "=1.0.228"

[rust.families.resolved]
serde = {{ version = "1.0.228", checksum_sha256 = "{alpha_checksum}" }}

[rust.families.allowed_advisories]
serde = [
  {{ id = "RUSTSEC-2026-0001", review_by = "2026-09-21" }},
]

[[rust.families]]
name = "beta-family"
review_record = "docs/dependency-reviews/2026-05-27-beta.md"

[rust.families.direct]
quote = "=1.0.40"

[rust.families.resolved]
quote = {{ version = "1.0.40", checksum_sha256 = "{beta_checksum}" }}

[rust.families.allowed_advisories]
quote = [
  {{ id = "RUSTSEC-2026-0002", review_by = "2026-10-01" }},
]
"#
        ),
    )
    .expect("reviewed targets should write");
    write_review_record(&temp_dir, "docs/dependency-reviews/2026-05-27-alpha.md");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Pin check: FAIL"));
    assert!(
        rendered.contains("review record missing at docs/dependency-reviews/2026-05-27-beta.md")
    );
    assert!(rendered.contains("Allowed policy exceptions:"));
    assert!(
        rendered
            .contains("serde@1.0.228 RUSTSEC-2026-0001 accepted by reviewed family alpha-family")
    );
    assert!(
        !rendered
            .contains("quote@1.0.40 RUSTSEC-2026-0002 accepted by reviewed family beta-family")
    );
}

#[test]
fn pin_check_renders_bound_advisory_exception_when_direct_spec_drifts() {
    let cli = Cli::parse_from(["cargo-barbican", "pin-check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.227\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_package_records(&[(
            "serde",
            "1.0.228",
            Some("registry+https://github.com/rust-lang/crates.io-index"),
            Some(checksum),
        )]),
    )
    .expect("lockfile should write");
    write_advisory_exception_policy(&temp_dir, "serde", "1.0.228", checksum, "2026-09-21", true);

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Pin check: FAIL"));
    assert!(rendered.contains(r#"direct spec mismatch for serde: expected "=1.0.228""#));
    assert!(rendered.contains("Allowed policy exceptions:"));
    assert!(
        rendered
            .contains("serde@1.0.228 RUSTSEC-2026-0001 accepted by reviewed family serde-family")
    );
}

#[test]
fn pin_check_fails_when_allowed_surface_state_is_malformed() {
    let cli = Cli::parse_from(["cargo-barbican", "pin-check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.228\"\n",
    )
    .expect("manifest should write");
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

[rust.families.allowed_surfaces]
serde_derive = ["proc-macro"]
"#,
    )
    .expect("reviewed targets should write");
    write_review_record(&temp_dir, "docs/dependency-reviews/2026-05-27-serde.md");

    let error = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect_err("malformed reviewed targets should fail");

    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
    assert!(error.to_string().contains(
        "allowed_surfaces entry for \"serde_derive\" references a crate absent from the same resolved map"
    ));
}

#[test]
fn pin_check_fails_when_allowed_age_exception_state_is_malformed() {
    let cli = Cli::parse_from(["cargo-barbican", "pin-check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.228\"\n",
    )
    .expect("manifest should write");
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

[rust.families.allowed_age_exceptions]
serde = "1.0.228"
"#,
    )
    .expect("reviewed targets should write");
    write_review_record(&temp_dir, "docs/dependency-reviews/2026-05-27-serde.md");

    let error = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect_err("malformed reviewed targets should fail");

    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
    assert!(error.to_string().contains(
        "allowed_age_exceptions entry for \"serde\" requires the resolved target to carry checksum_sha256"
    ));
}

#[test]
fn pin_check_fails_when_review_record_is_missing() {
    let cli = Cli::parse_from(["cargo-barbican", "pin-check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.228\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_packages(&[
            ("serde", "1.0.228", true),
            ("serde_derive", "1.0.228", true),
        ]),
    )
    .expect("lockfile should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        r#"[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.direct]
serde = "=1.0.228"

[rust.families.resolved]
serde = "1.0.228"
serde_derive = "1.0.228"
"#,
    )
    .expect("reviewed targets should write");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Pin check: FAIL"));
    assert!(
        rendered.contains("review record missing at docs/dependency-reviews/2026-05-27-serde.md")
    );
}

#[test]
fn pin_check_fails_when_manifest_or_lockfile_drift_from_reviewed_targets() {
    let cli = Cli::parse_from(["cargo-barbican", "pin-check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"1\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_packages(&[("serde", "1.0.227", true)]),
    )
    .expect("lockfile should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        r#"[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.direct]
serde = "=1.0.228"

[rust.families.resolved]
serde = "1.0.228"
"#,
    )
    .expect("reviewed targets should write");
    write_review_record(&temp_dir, "docs/dependency-reviews/2026-05-27-serde.md");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Pin check: FAIL"));
    assert!(rendered.contains(r#"direct spec mismatch for serde: expected "=1.0.228""#));
    assert!(rendered.contains(r#"found ["Cargo.toml:dependencies:1 (registry)"]"#));
    assert!(
        rendered
            .contains(r#"Cargo.lock mismatch for serde: expected {version=1.0.228}, found versions ["1.0.227"], checksums []"#)
    );
}

#[test]
fn pin_check_fails_when_reviewed_checksum_drifts_from_lockfile() {
    let cli = Cli::parse_from(["cargo-barbican", "pin-check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.228\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_package_records(&[(
            "serde",
            "1.0.228",
            Some("registry+https://github.com/rust-lang/crates.io-index"),
            Some("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
        )]),
    )
    .expect("lockfile should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        r#"[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.direct]
serde = "=1.0.228"

[rust.families.resolved]
serde = { version = "1.0.228", checksum_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }
"#,
    )
    .expect("reviewed targets should write");
    write_review_record(&temp_dir, "docs/dependency-reviews/2026-05-27-serde.md");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Pin check: FAIL"));
    assert!(rendered.contains(
        "Cargo.lock mismatch for serde: expected {version=1.0.228, checksum_sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}, found versions [\"1.0.228\"], checksums [\"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\"]"
    ));
}

#[test]
fn pin_check_fails_when_reviewed_checksum_is_missing_from_lockfile() {
    let cli = Cli::parse_from(["cargo-barbican", "pin-check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.228\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_package_records(&[(
            "serde",
            "1.0.228",
            Some("registry+https://github.com/rust-lang/crates.io-index"),
            None,
        )]),
    )
    .expect("lockfile should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        r#"[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.direct]
serde = "=1.0.228"

[rust.families.resolved]
serde = { version = "1.0.228", checksum_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }
"#,
    )
    .expect("reviewed targets should write");
    write_review_record(&temp_dir, "docs/dependency-reviews/2026-05-27-serde.md");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Pin check: FAIL"));
    assert!(rendered.contains(
        "Cargo.lock mismatch for serde: expected {version=1.0.228, checksum_sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}, found versions [\"1.0.228\"], checksums []"
    ));
}

#[test]
fn pin_check_accepts_uppercase_lockfile_checksum_for_reviewed_target() {
    let cli = Cli::parse_from(["cargo-barbican", "pin-check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.228\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_package_records(&[(
            "serde",
            "1.0.228",
            Some("registry+https://github.com/rust-lang/crates.io-index"),
            Some("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"),
        )]),
    )
    .expect("lockfile should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        r#"[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.direct]
serde = "=1.0.228"

[rust.families.resolved]
serde = { version = "1.0.228", checksum_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }
"#,
    )
    .expect("reviewed targets should write");
    write_review_record(&temp_dir, "docs/dependency-reviews/2026-05-27-serde.md");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains(
        "Cargo.lock ok for serde: matched {version=1.0.228, checksum_sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}"
    ));
}

fn build_crate_tarball(files: &[(&str, &str)]) -> Vec<u8> {
    let mut tarball = Vec::new();
    {
        let mut builder = Builder::new(&mut tarball);
        for (path, contents) in files {
            let full_path = format!("sample-0.1.0/{path}");
            let bytes = contents.as_bytes();
            let mut header = Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, full_path, bytes)
                .expect("fixture tar append should succeed");
        }
        builder.finish().expect("fixture tar should finish");
    }

    let deflated = compress_to_vec(&tarball, 6);
    let mut gzip = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];
    gzip.extend(deflated);
    gzip.extend([0, 0, 0, 0]);
    gzip.extend((tarball.len() as u32).to_le_bytes());
    gzip
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);

    for byte in digest {
        output.push(char::from(b"0123456789abcdef"[(byte >> 4) as usize]));
        output.push(char::from(b"0123456789abcdef"[(byte & 0x0f) as usize]));
    }

    output
}

fn write_workspace_layout(temp_dir: &Path) {
    fs::create_dir_all(temp_dir.join("app")).expect("workspace member dir should exist");
    fs::create_dir_all(temp_dir.join("crates/barbican")).expect("crate dir should exist");
    fs::create_dir_all(temp_dir.join("crates/cargo-barbican")).expect("crate dir should exist");
    fs::create_dir_all(temp_dir.join("docs/dependency-reviews")).expect("review dir should exist");
    fs::write(
        temp_dir.join("Cargo.toml"),
        "[workspace]\nmembers = [\"crates/*\", \"app\"]\n",
    )
    .expect("root manifest should write");
    fs::write(temp_dir.join("Cargo.lock"), "version = 4\n").expect("lockfile should write");
    fs::write(
        temp_dir.join("barbican.toml"),
        "[release_age]\nminimum_days = 7\n",
    )
    .expect("barbican config should write");
    fs::write(temp_dir.join("deny.toml"), "[advisories]\n").expect("deny config should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        "[rust]\nfamilies = []\n",
    )
    .expect("reviewed targets should write");
    fs::write(
        temp_dir.join("docs/dependency-reviews/2026-05-27-sample.md"),
        "# Dependency Review: sample\n",
    )
    .expect("review record should write");
    fs::write(
        temp_dir.join("app/Cargo.toml"),
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n",
    )
    .expect("workspace member manifest should write");
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

fn write_review_record(temp_dir: &Path, relative_path: &str) {
    let path = temp_dir.join(relative_path);
    let parent = path.parent().expect("review record should have a parent");
    fs::create_dir_all(parent).expect("review record dir should exist");
    fs::write(path, "# Dependency Review\n").expect("review record should write");
}

fn write_age_exception_policy(
    temp_dir: &Path,
    crate_name: &str,
    version: &str,
    checksum: &str,
    write_record: bool,
) {
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        format!(
            r#"[rust]

[[rust.families]]
name = "{crate_name}-family"
review_record = "docs/dependency-reviews/2026-05-27-{crate_name}.md"

[rust.families.resolved]
{crate_name} = {{ version = "{version}", checksum_sha256 = "{checksum}" }}

[rust.families.allowed_age_exceptions]
{crate_name} = "{version}"
"#
        ),
    )
    .expect("reviewed targets should write");

    if write_record {
        write_review_record(
            temp_dir,
            &format!("docs/dependency-reviews/2026-05-27-{crate_name}.md"),
        );
    }
}

fn write_advisory_exception_policy(
    temp_dir: &Path,
    crate_name: &str,
    version: &str,
    checksum: &str,
    review_by: &str,
    write_record: bool,
) {
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        format!(
            r#"[rust]

[[rust.families]]
name = "{crate_name}-family"
review_record = "docs/dependency-reviews/2026-05-27-{crate_name}.md"

[rust.families.direct]
{crate_name} = "={version}"

[rust.families.resolved]
{crate_name} = {{ version = "{version}", checksum_sha256 = "{checksum}" }}

[rust.families.allowed_advisories]
{crate_name} = [
  {{ id = "RUSTSEC-2026-0001", review_by = "{review_by}" }},
]
"#
        ),
    )
    .expect("reviewed targets should write");

    if write_record {
        write_review_record(
            temp_dir,
            &format!("docs/dependency-reviews/2026-05-27-{crate_name}.md"),
        );
    }
}

fn lockfile_with_packages(packages: &[(&str, &str, bool)]) -> String {
    lockfile_with_package_records(
        &packages
            .iter()
            .map(|(name, version, crates_io)| {
                (
                    *name,
                    *version,
                    crates_io.then_some("registry+https://github.com/rust-lang/crates.io-index"),
                    None,
                )
            })
            .collect::<Vec<_>>(),
    )
}

fn lockfile_with_package_sources(packages: &[(&str, &str, Option<&str>)]) -> String {
    lockfile_with_package_records(
        &packages
            .iter()
            .map(|(name, version, source)| (*name, *version, *source, None))
            .collect::<Vec<_>>(),
    )
}

fn lockfile_with_package_records(packages: &[(&str, &str, Option<&str>, Option<&str>)]) -> String {
    let mut lockfile = String::from("version = 4\n");

    for (name, version, source, checksum) in packages {
        lockfile.push_str("\n[[package]]\n");
        lockfile.push_str(&format!("name = \"{name}\"\n"));
        lockfile.push_str(&format!("version = \"{version}\"\n"));
        if let Some(source) = source {
            lockfile.push_str(&format!("source = \"{source}\"\n"));
        }
        if let Some(checksum) = checksum {
            lockfile.push_str(&format!("checksum = \"{checksum}\"\n"));
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

fn clean_cargo_deny_jsonl() -> &'static str {
    r#"{"type":"summary","fields":{"advisories":{"errors":0,"warnings":0,"helps":0,"notes":0},"bans":{"errors":0,"warnings":0,"helps":0,"notes":0},"sources":{"errors":0,"warnings":0,"helps":0,"notes":0}}}
"#
}

fn clean_cargo_audit_json() -> &'static str {
    r#"{
  "vulnerabilities": { "found": false, "count": 0, "list": [] },
  "settings": { "ignore": [] },
  "warnings": {}
}"#
}

fn cargo_deny_advisory_jsonl() -> String {
    r#"{"type":"diagnostic","fields":{"severity":"error","code":"vulnerability","advisory":{"id":"RUSTSEC-2026-0001"},"graphs":[{"Krate":{"name":"serde","version":"1.0.228"}}]}}
{"type":"summary","fields":{"advisories":{"errors":1,"warnings":0,"helps":0,"notes":0},"bans":{"errors":0,"warnings":0,"helps":0,"notes":0},"sources":{"errors":0,"warnings":0,"helps":0,"notes":0}}}
"#
    .to_owned()
}

fn cargo_deny_bans_error_jsonl() -> String {
    r#"{"type":"diagnostic","fields":{"severity":"error","code":"banned"}}
{"type":"summary","fields":{"advisories":{"errors":0,"warnings":0,"helps":0,"notes":0},"bans":{"errors":1,"warnings":0,"helps":0,"notes":0},"sources":{"errors":0,"warnings":0,"helps":0,"notes":0}}}
"#
    .to_owned()
}

fn cargo_audit_advisory_json() -> String {
    r#"{
  "vulnerabilities": {
    "found": true,
    "count": 1,
    "list": [
      {
        "advisory": { "id": "RUSTSEC-2026-0001" },
        "package": { "name": "serde", "version": "1.0.228" }
      }
    ]
  },
  "settings": { "ignore": [] },
  "warnings": {}
}"#
    .to_owned()
}

fn cargo_audit_ignored_and_idless_json() -> String {
    r#"{
  "vulnerabilities": { "found": false, "count": 0, "list": [] },
  "settings": { "ignore": ["RUSTSEC-2026-0001"] },
  "warnings": {
    "yanked": [
      {
        "package": { "name": "serde", "version": "1.0.228" }
      }
    ]
  }
}"#
    .to_owned()
}

fn write_advisory_audit_fixture(temp_dir: &Path, advisory_config: Option<&str>, review_by: &str) {
    let checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.228\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_package_records(&[(
            "serde",
            "1.0.228",
            Some("registry+https://github.com/rust-lang/crates.io-index"),
            Some(checksum),
        )]),
    )
    .expect("lockfile should write");
    if let Some(advisory_config) = advisory_config {
        fs::write(
            temp_dir.join("barbican.toml"),
            format!("[delegates.advisories]\n{advisory_config}\n"),
        )
        .expect("config should write");
    }
    write_advisory_exception_policy(temp_dir, "serde", "1.0.228", checksum, review_by, true);
}

fn fresh_temp_dir() -> PathBuf {
    static BASE: OnceLock<PathBuf> = OnceLock::new();
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let base = BASE.get_or_init(|| {
        let root = std::env::temp_dir().join("cargo-barbican-tests");
        fs::create_dir_all(&root).expect("temp root should be creatable");
        root
    });

    let unique = format!(
        "{}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after unix epoch")
            .as_nanos(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let path = base.join(unique);
    fs::create_dir_all(&path).expect("temp dir should be creatable");
    path
}

fn fixed_now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_590_969_600).expect("fixed timestamp should parse")
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
