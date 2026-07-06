//! Shared test fixtures and fakes for the `cli` integration test binary.
//!
//! Everything here is re-exported to per-command test modules via a single
//! `use super::common::*;`, so this module is deliberately broad: fakes,
//! fixture builders, and re-exported external items all live in one place
//! rather than being scattered/duplicated across command modules.

pub(crate) use std::cell::RefCell;
pub(crate) use std::collections::HashMap;
pub(crate) use std::env;
pub(crate) use std::fs;
pub(crate) use std::io::{self, Read, Write};
pub(crate) use std::net::TcpListener;
#[cfg(unix)]
pub(crate) use std::os::unix::fs::PermissionsExt;
pub(crate) use std::path::{Path, PathBuf};
pub(crate) use std::process::ExitCode;
pub(crate) use std::sync::OnceLock;
pub(crate) use std::sync::atomic::{AtomicU64, Ordering};
pub(crate) use std::sync::mpsc;
pub(crate) use std::thread;
pub(crate) use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) use barbican::{
    CrateRelease, CratesIoClient, CratesIoClientError, ExactCrateSpec, OffsetDateTime, VersionInfo,
    parse_version_response_body,
};
// `run_cli_with_runner` is deliberately NOT re-exported here: this module
// defines its own fixed-clock `run_cli_with_runner` below, which would
// otherwise collide with this name.
pub(crate) use cargo_barbican::{
    Cli, CommandOutput, CommandRunner, UreqCratesIoClient, run_cli_with_runner_at,
};
pub(crate) use clap::Parser;
pub(crate) use miniz_oxide::deflate::compress_to_vec;
pub(crate) use sha2::{Digest, Sha256};
pub(crate) use tar::{Builder, Header};

#[derive(Default)]
pub(crate) struct FakeCratesIoClient {
    pub(crate) responses: HashMap<String, Result<CrateRelease, CratesIoClientError>>,
    pub(crate) version_responses: HashMap<String, Result<Vec<VersionInfo>, CratesIoClientError>>,
    pub(crate) tarball_responses: HashMap<String, Result<Vec<u8>, CratesIoClientError>>,
    pub(crate) fetches: RefCell<Vec<String>>,
    pub(crate) version_fetches: RefCell<Vec<String>>,
    pub(crate) tarball_fetches: RefCell<Vec<String>>,
}

impl FakeCratesIoClient {
    pub(crate) fn with_release(self, spec: &str, published_at: &str, yanked: bool) -> Self {
        self.with_release_checksum(
            spec,
            published_at,
            yanked,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
    }

    pub(crate) fn with_release_checksum(
        mut self,
        spec: &str,
        published_at: &str,
        yanked: bool,
        checksum_sha256_hex: &str,
    ) -> Self {
        self.responses.insert(
            spec.to_owned(),
            Ok(parse_version_response_body(&format!(
                r#"{{"version":{{"num":"0.0.0","checksum":"{checksum_sha256_hex}","created_at":"{published_at}","yanked":{yanked}}}}}"#
            ))
            .expect("fake response should parse")),
        );
        self
    }

    pub(crate) fn with_error(mut self, spec: &str, error: CratesIoClientError) -> Self {
        self.responses.insert(spec.to_owned(), Err(error));
        self
    }

    pub(crate) fn with_versions(
        mut self,
        crate_name: &str,
        versions: &[(&str, &str, bool)],
    ) -> Self {
        self.version_responses.insert(
            crate_name.to_owned(),
            Ok(versions
                .iter()
                .map(|(num, published_at, yanked)| fake_version_info(num, published_at, *yanked))
                .collect()),
        );
        self
    }

    pub(crate) fn with_raw_versions(
        mut self,
        crate_name: &str,
        versions: Vec<VersionInfo>,
    ) -> Self {
        self.version_responses
            .insert(crate_name.to_owned(), Ok(versions));
        self
    }

    pub(crate) fn with_versions_error(
        mut self,
        crate_name: &str,
        error: CratesIoClientError,
    ) -> Self {
        self.version_responses
            .insert(crate_name.to_owned(), Err(error));
        self
    }

    pub(crate) fn with_tarball(mut self, spec: &str, tarball: &[u8]) -> Self {
        self.tarball_responses
            .insert(spec.to_owned(), Ok(tarball.to_vec()));
        self
    }

    pub(crate) fn recorded_fetches(&self) -> Vec<String> {
        self.fetches.borrow().clone()
    }

    pub(crate) fn recorded_version_fetches(&self) -> Vec<String> {
        self.version_fetches.borrow().clone()
    }

    pub(crate) fn recorded_tarball_fetches(&self) -> Vec<String> {
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

    fn fetch_versions(&self, crate_name: &str) -> Result<Vec<VersionInfo>, CratesIoClientError> {
        self.version_fetches
            .borrow_mut()
            .push(crate_name.to_owned());
        self.version_responses
            .get(crate_name)
            .cloned()
            .unwrap_or_else(|| {
                Err(CratesIoClientError::Transport {
                    reason: "missing fake versions response".to_owned(),
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

pub(crate) fn fake_version_info(num: &str, published_at: &str, yanked: bool) -> VersionInfo {
    let release = parse_version_response_body(&format!(
        r#"{{"version":{{"num":"{num}","checksum":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","created_at":"{published_at}","yanked":{yanked}}}}}"#
    ))
    .expect("fake version response should parse");

    VersionInfo {
        num: num.to_owned(),
        checksum_sha256_hex: release.checksum_sha256_hex,
        published_at_raw: release.published_at_raw,
        published_at: release.published_at,
        yanked,
    }
}

pub(crate) fn fake_raw_version_info(num: &str, published_at: &str, yanked: bool) -> VersionInfo {
    let mut version = fake_version_info("0.0.0", published_at, yanked);
    version.num = num.to_owned();
    version
}

pub(crate) struct FailingWriter;

impl Write for FailingWriter {
    fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("stdout blocked"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Succeeds through the first `allowed_lines` completed `\n`-terminated
/// lines, then fails every write after that. Counting completed lines rather
/// than raw `write` calls keeps this independent of how many underlying
/// `write` calls a single `writeln!` happens to expand to. Lets a test place
/// the induced failure strictly after a known number of prior stdout reports
/// (e.g. after a pre-flight report has already been rendered), rather than
/// failing unconditionally from the very first write.
pub(crate) struct FailAfterWriter {
    pub(crate) remaining_lines: u32,
    pub(crate) blocked: bool,
}

impl FailAfterWriter {
    pub(crate) fn new(allowed_lines: u32) -> Self {
        Self {
            remaining_lines: allowed_lines,
            blocked: false,
        }
    }
}

impl Write for FailAfterWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.blocked {
            return Err(io::Error::other("stdout blocked"));
        }
        for &byte in buf {
            if byte == b'\n' {
                if self.remaining_lines == 0 {
                    self.blocked = true;
                    return Err(io::Error::other("stdout blocked"));
                }
                self.remaining_lines -= 1;
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) struct FakeCommandRunner {
    pub(crate) git_show_results: HashMap<String, Result<String, String>>,
    pub(crate) cargo_metadata_result: Result<String, String>,
    pub(crate) cargo_update_result: Result<(), String>,
    pub(crate) cargo_update_lockfile_text: Option<String>,
    pub(crate) cargo_generate_lockfile_result: Result<(), String>,
    pub(crate) cargo_generate_lockfile_text: Option<String>,
    pub(crate) cargo_tree_result: Result<String, String>,
    pub(crate) git_diff_result: Result<String, String>,
    pub(crate) cargo_audit_result: Result<String, String>,
    /// `RealCommandRunner::cargo_audit_json`/`cargo_deny_json` return
    /// `Ok(CommandOutput)` regardless of the subprocess's exit status (see
    /// `output_from_prepared_command`) — a non-zero exit is data on stdout,
    /// not an `Err`. Only a spawn failure could ever produce an `Err` here,
    /// which is not what these two fields model, so they are not
    /// independently fallible the way `cargo_audit_result` etc. are.
    pub(crate) cargo_audit_json_result: CommandOutput,
    pub(crate) cargo_deny_json_result: CommandOutput,
    pub(crate) cargo_build_result: Result<(), String>,
    pub(crate) cargo_test_result: Result<(), String>,
    pub(crate) cargo_updates: RefCell<Vec<(String, String)>>,
    pub(crate) generate_lockfile_calls: RefCell<Vec<PathBuf>>,
    pub(crate) cargo_tree_calls: RefCell<Vec<PathBuf>>,
    pub(crate) git_diff_paths: RefCell<Vec<PathBuf>>,
    pub(crate) audit_calls: RefCell<Vec<PathBuf>>,
    pub(crate) audit_json_calls: RefCell<Vec<(PathBuf, PathBuf)>>,
    pub(crate) deny_json_calls: RefCell<Vec<(PathBuf, PathBuf, Vec<barbican::CargoDenyCheck>)>>,
    pub(crate) deny_json_config_texts: RefCell<Vec<String>>,
    pub(crate) build_calls: RefCell<usize>,
    pub(crate) test_calls: RefCell<usize>,
    /// Only `inventory` calls `cargo_metadata_frozen`; it defaults to a
    /// minimal-but-valid baseline (matching the rest of this fake's
    /// permissive-by-default philosophy), overridden per test via
    /// `with_frozen_metadata`/`with_frozen_metadata_error`.
    pub(crate) cargo_metadata_frozen_result: Result<String, String>,
    pub(crate) cargo_metadata_frozen_calls: RefCell<u64>,
}

impl Default for FakeCommandRunner {
    fn default() -> Self {
        Self {
            git_show_results: HashMap::new(),
            cargo_metadata_result: Ok(metadata_with_packages(&[])),
            cargo_update_result: Ok(()),
            cargo_update_lockfile_text: None,
            cargo_generate_lockfile_result: Ok(()),
            cargo_generate_lockfile_text: None,
            cargo_tree_result: Ok(String::new()),
            git_diff_result: Ok(String::new()),
            cargo_audit_result: Ok(String::new()),
            cargo_audit_json_result: CommandOutput {
                stdout: clean_cargo_audit_json().to_owned(),
                stderr: String::new(),
            },
            cargo_deny_json_result: CommandOutput {
                stdout: String::new(),
                stderr: clean_cargo_deny_jsonl().to_owned(),
            },
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
            cargo_metadata_frozen_result: Ok(default_metadata_json().to_owned()),
            cargo_metadata_frozen_calls: RefCell::new(0),
        }
    }
}

impl FakeCommandRunner {
    pub(crate) fn with_git_show(mut self, object: &str, text: &str) -> Self {
        self.git_show_results
            .insert(object.to_owned(), Ok(text.to_owned()));
        self
    }

    pub(crate) fn with_git_show_error(mut self, object: &str, detail: &str) -> Self {
        self.git_show_results
            .insert(object.to_owned(), Err(detail.to_owned()));
        self
    }

    pub(crate) fn with_cargo_metadata(mut self, text: &str) -> Self {
        self.cargo_metadata_result = Ok(text.to_owned());
        self
    }

    pub(crate) fn with_git_diff(mut self, diff: &str) -> Self {
        self.git_diff_result = Ok(diff.to_owned());
        self
    }

    pub(crate) fn with_updated_lockfile(mut self, text: &str) -> Self {
        self.cargo_update_lockfile_text = Some(text.to_owned());
        self
    }

    pub(crate) fn with_cargo_tree(mut self, output: &str) -> Self {
        self.cargo_tree_result = Ok(output.to_owned());
        self
    }

    pub(crate) fn with_cargo_tree_error(mut self, detail: &str) -> Self {
        self.cargo_tree_result = Err(detail.to_owned());
        self
    }

    pub(crate) fn with_cargo_generate_lockfile_error(mut self, detail: &str) -> Self {
        self.cargo_generate_lockfile_result = Err(detail.to_owned());
        self
    }

    pub(crate) fn with_generated_lockfile(mut self, text: &str) -> Self {
        self.cargo_generate_lockfile_text = Some(text.to_owned());
        self
    }

    pub(crate) fn with_cargo_audit_error(mut self, detail: &str) -> Self {
        self.cargo_audit_result = Err(detail.to_owned());
        self
    }

    pub(crate) fn with_cargo_audit(mut self, output: &str) -> Self {
        self.cargo_audit_result = Ok(output.to_owned());
        self
    }

    pub(crate) fn with_cargo_audit_json(mut self, stdout: &str) -> Self {
        self.cargo_audit_json_result = CommandOutput {
            stdout: stdout.to_owned(),
            stderr: String::new(),
        };
        self
    }

    pub(crate) fn with_cargo_deny_json(mut self, stderr: &str) -> Self {
        self.cargo_deny_json_result = CommandOutput {
            stdout: String::new(),
            stderr: stderr.to_owned(),
        };
        self
    }

    pub(crate) fn recorded_updates(&self) -> Vec<(String, String)> {
        self.cargo_updates.borrow().clone()
    }

    pub(crate) fn recorded_generate_lockfile_calls(&self) -> Vec<PathBuf> {
        self.generate_lockfile_calls.borrow().clone()
    }

    pub(crate) fn recorded_cargo_tree_calls(&self) -> Vec<PathBuf> {
        self.cargo_tree_calls.borrow().clone()
    }

    pub(crate) fn recorded_audit_calls(&self) -> Vec<PathBuf> {
        self.audit_calls.borrow().clone()
    }

    pub(crate) fn recorded_audit_json_calls(&self) -> Vec<(PathBuf, PathBuf)> {
        self.audit_json_calls.borrow().clone()
    }

    pub(crate) fn recorded_deny_json_calls(
        &self,
    ) -> Vec<(PathBuf, PathBuf, Vec<barbican::CargoDenyCheck>)> {
        self.deny_json_calls.borrow().clone()
    }

    pub(crate) fn recorded_deny_json_config_texts(&self) -> Vec<String> {
        self.deny_json_config_texts.borrow().clone()
    }

    pub(crate) fn recorded_diff_paths(&self) -> Vec<PathBuf> {
        self.git_diff_paths.borrow().clone()
    }

    pub(crate) fn with_frozen_metadata(mut self, metadata: impl Into<String>) -> Self {
        self.cargo_metadata_frozen_result = Ok(metadata.into());
        self
    }

    pub(crate) fn with_frozen_metadata_error(mut self, message: impl Into<String>) -> Self {
        self.cargo_metadata_frozen_result = Err(message.into());
        self
    }

    pub(crate) fn frozen_metadata_calls(&self) -> u64 {
        *self.cargo_metadata_frozen_calls.borrow()
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
        *self.cargo_metadata_frozen_calls.borrow_mut() += 1;
        self.cargo_metadata_frozen_result
            .clone()
            .map_err(runner_exit)
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
            let lockfile_text = self
                .cargo_generate_lockfile_text
                .as_deref()
                .unwrap_or("version = 4\n");
            fs::write(current_dir.join("Cargo.lock"), lockfile_text)
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
        Ok(self.cargo_audit_json_result.clone())
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
        Ok(self.cargo_deny_json_result.clone())
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

pub(crate) fn run_routine_safe_assess(args: &[&str]) -> (ExitCode, String, String) {
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

pub(crate) fn run_allowed_surface_assess(
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

pub(crate) fn run_elevated_risk_assess(args: &[&str]) -> (ExitCode, String, String) {
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

pub(crate) fn run_too_fresh_assess(args: &[&str]) -> (ExitCode, String, String) {
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

pub(crate) const PIN_ADD_TEST_CHECKSUM: &str =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

pub(crate) fn write_pin_add_workspace(temp_dir: &Path) {
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
            Some(PIN_ADD_TEST_CHECKSUM),
        )]),
    )
    .expect("lockfile should write");
    fs::write(temp_dir.join("reviewed-targets.toml"), "[rust]\n")
        .expect("reviewed targets should write");
}

pub(crate) fn run_pin_add(temp_dir: &Path, spec: &str) -> (ExitCode, String, String) {
    let cli = Cli::parse_from(["cargo-barbican", "pin", "add", spec]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner_at(
        cli,
        temp_dir,
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

pub(crate) fn build_crate_tarball(files: &[(&str, &str)]) -> Vec<u8> {
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

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);

    for byte in digest {
        output.push(char::from(b"0123456789abcdef"[(byte >> 4) as usize]));
        output.push(char::from(b"0123456789abcdef"[(byte & 0x0f) as usize]));
    }

    output
}

pub(crate) fn write_workspace_layout(temp_dir: &Path) {
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

pub(crate) fn write_review_record(temp_dir: &Path, relative_path: &str) {
    let path = temp_dir.join(relative_path);
    let parent = path.parent().expect("review record should have a parent");
    fs::create_dir_all(parent).expect("review record dir should exist");
    fs::write(path, "# Dependency Review\n").expect("review record should write");
}

pub(crate) fn write_age_exception_policy(
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

pub(crate) fn write_advisory_exception_policy(
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

pub(crate) fn lockfile_with_packages(packages: &[(&str, &str, bool)]) -> String {
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

pub(crate) fn lockfile_with_package_sources(packages: &[(&str, &str, Option<&str>)]) -> String {
    lockfile_with_package_records(
        &packages
            .iter()
            .map(|(name, version, source)| (*name, *version, *source, None))
            .collect::<Vec<_>>(),
    )
}

pub(crate) fn lockfile_with_package_records(
    packages: &[(&str, &str, Option<&str>, Option<&str>)],
) -> String {
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

pub(crate) fn metadata_with_packages(packages: &[(&str, &str, &str)]) -> String {
    let packages_json = packages
        .iter()
        .map(|(name, version, id)| {
            format!(r#"{{"name":"{name}","id":"{id}","version":"{version}","targets":[]}}"#)
        })
        .collect::<Vec<_>>()
        .join(",");

    format!(r#"{{"packages":[{packages_json}],"workspace_members":[],"resolve":null}}"#)
}

pub(crate) fn clean_cargo_deny_jsonl() -> &'static str {
    r#"{"type":"summary","fields":{"advisories":{"errors":0,"warnings":0,"helps":0,"notes":0},"bans":{"errors":0,"warnings":0,"helps":0,"notes":0},"sources":{"errors":0,"warnings":0,"helps":0,"notes":0}}}
"#
}

pub(crate) fn clean_cargo_audit_json() -> &'static str {
    r#"{
  "vulnerabilities": { "found": false, "count": 0, "list": [] },
  "settings": { "ignore": [] },
  "warnings": {}
}"#
}

pub(crate) fn cargo_deny_advisory_jsonl() -> String {
    r#"{"type":"diagnostic","fields":{"severity":"error","code":"vulnerability","advisory":{"id":"RUSTSEC-2026-0001"},"graphs":[{"Krate":{"name":"serde","version":"1.0.228"}}]}}
{"type":"summary","fields":{"advisories":{"errors":1,"warnings":0,"helps":0,"notes":0},"bans":{"errors":0,"warnings":0,"helps":0,"notes":0},"sources":{"errors":0,"warnings":0,"helps":0,"notes":0}}}
"#
    .to_owned()
}

pub(crate) fn cargo_deny_bans_error_jsonl() -> String {
    r#"{"type":"diagnostic","fields":{"severity":"error","code":"banned"}}
{"type":"summary","fields":{"advisories":{"errors":0,"warnings":0,"helps":0,"notes":0},"bans":{"errors":1,"warnings":0,"helps":0,"notes":0},"sources":{"errors":0,"warnings":0,"helps":0,"notes":0}}}
"#
    .to_owned()
}

pub(crate) fn cargo_audit_advisory_json() -> String {
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

pub(crate) fn cargo_audit_ignored_and_idless_json() -> String {
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

pub(crate) fn write_advisory_audit_fixture(
    temp_dir: &Path,
    advisory_config: Option<&str>,
    review_by: &str,
) {
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

/// Owns a `fresh_temp_dir()` directory and removes it on drop, so a panicking
/// assertion partway through a test does not leak a fixture directory under
/// the shared `cargo-barbican-tests` root for the lifetime of the machine.
/// `Deref<Target = Path>` (plus `AsRef<Path>`) means existing call sites that
/// pass `&temp_dir` or call `temp_dir.join(...)` need no changes. The two
/// `PartialEq` impls below cover the handful of call sites that compare a
/// recorded `PathBuf` directly against `temp_dir` itself.
#[derive(Debug)]
pub(crate) struct TempDirGuard(PathBuf);

impl std::ops::Deref for TempDirGuard {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for TempDirGuard {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl PartialEq<TempDirGuard> for PathBuf {
    fn eq(&self, other: &TempDirGuard) -> bool {
        self.as_path() == other.0.as_path()
    }
}

impl PartialEq<PathBuf> for TempDirGuard {
    fn eq(&self, other: &PathBuf) -> bool {
        self.0.as_path() == other.as_path()
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub(crate) fn fresh_temp_dir() -> TempDirGuard {
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
    TempDirGuard(path)
}

pub(crate) fn fixed_now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_590_969_600).expect("fixed timestamp should parse")
}

/// The shared default for driving the CLI in tests: an injected fixed clock
/// (`fixed_now()`), not the ambient wall clock. Shadows the re-exported
/// `cargo_barbican::run_cli_with_runner` (see the `pub(crate) use` above) so
/// every existing call site gets a deterministic clock without editing each
/// one; call sites that genuinely need real time opt in explicitly via
/// [`run_cli_with_ambient_clock`].
pub(crate) fn run_cli_with_runner<C, R>(
    cli: Cli,
    current_dir: &Path,
    client: &C,
    runner: &R,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<ExitCode, cargo_barbican::CommandError>
where
    C: CratesIoClient + ?Sized,
    R: CommandRunner + ?Sized,
{
    run_cli_with_runner_at(
        cli,
        current_dir,
        client,
        runner,
        fixed_now(),
        stdout,
        stderr,
    )
}

/// Explicit opt-in to the real wall clock, for the handful of tests (the
/// loopback HTTP smoke tests) that assert on dates relative to whenever the
/// test actually runs rather than an injected `now`.
pub(crate) fn run_cli_with_ambient_clock<C, R>(
    cli: Cli,
    current_dir: &Path,
    client: &C,
    runner: &R,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<ExitCode, cargo_barbican::CommandError>
where
    C: CratesIoClient + ?Sized,
    R: CommandRunner + ?Sized,
{
    cargo_barbican::run_cli_with_runner(cli, current_dir, client, runner, stdout, stderr)
}

pub(crate) fn runner_exit(detail: String) -> cargo_barbican::RunnerError {
    cargo_barbican::RunnerError::Exited {
        code: Some(1),
        stdout: String::new(),
        stderr: detail,
    }
}

/// `CARGO_BARBICAN_TEST_ALLOW_BIND_SKIP` env var name. A sandboxed CI runner
/// that cannot bind a loopback socket is the only sanctioned reason to skip
/// these tests; without it, a bind failure must fail the suite loudly rather
/// than silently drop the only end-to-end HTTP coverage this binary has.
pub(crate) const ALLOW_BIND_SKIP_ENV: &str = "CARGO_BARBICAN_TEST_ALLOW_BIND_SKIP";

pub(crate) fn require_loopback_bind<T>(bound: Option<T>) -> Option<T> {
    if bound.is_some() {
        return bound;
    }

    if env::var(ALLOW_BIND_SKIP_ENV).as_deref() == Ok("1") {
        eprintln!(
            "[SKIP] no loopback bind available - skipping HTTP smoke test ({ALLOW_BIND_SKIP_ENV}=1)"
        );
        None
    } else {
        panic!(
            "no loopback bind available for an HTTP smoke test; this drops the only \
             end-to-end HTTP coverage cargo-barbican has, so it fails loudly by default. \
             Set {ALLOW_BIND_SKIP_ENV}=1 to allow a silent skip in a sandboxed environment \
             that cannot bind a loopback socket."
        );
    }
}

pub(crate) fn spawn_http_stub(
    status_line: &str,
    body: &str,
) -> Option<(String, mpsc::Receiver<String>, thread::JoinHandle<()>)> {
    require_loopback_bind(spawn_http_stub_sequence(&[(status_line, body.as_bytes())]))
}

/// Serves one response per entry in `responses`, in order, each on its own
/// accepted connection (the stub always answers `Connection: close`, and
/// `ureq` does not pipeline requests onto a closed connection). This is what
/// lets a single stub server stand in for a full two-request flow such as
/// `inspect` fetching version metadata and then the release tarball.
pub(crate) fn spawn_http_stub_sequence(
    responses: &[(&str, &[u8])],
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
    let responses = responses
        .iter()
        .map(|(status_line, body)| ((*status_line).to_owned(), (*body).to_owned()))
        .collect::<Vec<_>>();

    let handle = thread::spawn(move || {
        for (status_line, body) in responses {
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

            let header = format!(
                "{status_line}\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream
                .write_all(header.as_bytes())
                .expect("stub response header should write");
            stream
                .write_all(&body)
                .expect("stub response body should write");
        }
    });

    Some((format!("http://{address}"), receiver, handle))
}

/// Serves `version_body` on the first connection, then a second connection
/// whose body is `tarball_len` zero bytes streamed in fixed-size chunks
/// rather than materialised as one large `Vec` — real bytes have to cross
/// the wire for `ureq`'s length-limited body reader to trip, but the fixture
/// need not hold the whole oversized body in memory at once to produce them.
pub(crate) fn spawn_oversized_tarball_stub(
    version_body: &[u8],
    tarball_len: usize,
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
    let version_body = version_body.to_owned();

    let handle = thread::spawn(move || {
        let read_one_request = |stream: &mut std::net::TcpStream| {
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
            String::from_utf8_lossy(&request).into_owned()
        };

        let (mut stream, _) = listener
            .accept()
            .expect("stub should accept the version request");
        sender
            .send(read_one_request(&mut stream))
            .expect("stub request should send");
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n",
            version_body.len()
        );
        stream
            .write_all(header.as_bytes())
            .expect("stub version response should write");
        stream
            .write_all(&version_body)
            .expect("stub version body should write");

        let (mut stream, _) = listener
            .accept()
            .expect("stub should accept the tarball request");
        sender
            .send(read_one_request(&mut stream))
            .expect("stub request should send");
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {tarball_len}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n"
        );
        stream
            .write_all(header.as_bytes())
            .expect("stub tarball response header should write");
        // A well-behaved client stops reading (and may close the connection)
        // the instant it has seen one byte past its own limit, well before
        // this loop finishes writing `tarball_len` bytes. That is the
        // scenario under test, so a write error here means the client did
        // its job — it is not a stub failure — and the loop simply stops.
        let chunk = [0_u8; 64 * 1024];
        let mut remaining = tarball_len;
        while remaining > 0 {
            let write_len = remaining.min(chunk.len());
            if stream.write_all(&chunk[..write_len]).is_err() {
                break;
            }
            remaining -= write_len;
        }
    });

    Some((format!("http://{address}"), receiver, handle))
}

pub(crate) fn run_inventory(temp_dir: &Path) -> (ExitCode, String, String) {
    let runner = FakeCommandRunner::default();

    run_inventory_with_runner(temp_dir, &runner)
}

pub(crate) fn run_inventory_with_runner(
    temp_dir: &Path,
    runner: &FakeCommandRunner,
) -> (ExitCode, String, String) {
    let cli = Cli::parse_from(["cargo-barbican", "inventory"]);
    let client = FakeCratesIoClient::default();
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

pub(crate) fn run_inventory_with_runner_at(
    temp_dir: &Path,
    runner: &FakeCommandRunner,
    now: OffsetDateTime,
) -> (ExitCode, String, String) {
    let cli = Cli::parse_from(["cargo-barbican", "inventory"]);
    let client = FakeCratesIoClient::default();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner_at(
        cli,
        temp_dir,
        &client,
        runner,
        now,
        &mut stdout,
        &mut stderr,
    )
    .expect("command should run");
    assert_eq!(runner.frozen_metadata_calls(), 1);

    (
        exit_code,
        String::from_utf8(stdout).expect("stdout should be utf8"),
        String::from_utf8(stderr).expect("stderr should be utf8"),
    )
}

pub(crate) fn default_metadata_json() -> &'static str {
    r#"{
  "packages": [],
  "workspace_members": [],
  "resolve": {"nodes": []}
}"#
}

pub(crate) fn surface_metadata_json() -> &'static str {
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

pub(crate) fn write_inventory_fixture(root: &Path) {
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

pub(crate) fn write_workspace_only_fixture(root: &Path) {
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

pub(crate) fn write_libs_glob_fixture(root: &Path) {
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

pub(crate) fn write_pruned_dirs_fixture(root: &Path) {
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

pub(crate) fn write_nested_non_member_fixture(root: &Path) {
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

pub(crate) fn write_control_character_fixture(root: &Path) {
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

pub(crate) fn section_between<'a>(text: &'a str, start: &str, end: &str) -> &'a str {
    let section_start = text.find(start).expect("section should start");
    let after_start = &text[section_start + start.len()..];
    let section_end = after_start.find(end).expect("section should end");

    &after_start[..section_end]
}
