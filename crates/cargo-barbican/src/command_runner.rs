use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Output};
use std::{env, ffi::OsStr};

/// A delegated scanner binary cargo-barbican shells out to. Each variant is a
/// cargo subcommand — an executable named `cargo-<name>` on `PATH` — which is
/// why availability is probed by spawning that binary directly rather than
/// through `cargo <name>`: only a direct spawn surfaces a true ENOENT when the
/// binary is absent (spawning `cargo` instead just makes cargo exit non-zero
/// with a "no such command" message, indistinguishable from a runtime error).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Delegate {
    CargoDeny,
    CargoAudit,
}

impl Delegate {
    pub fn binary(self) -> &'static str {
        match self {
            Self::CargoDeny => "cargo-deny",
            Self::CargoAudit => "cargo-audit",
        }
    }

    pub fn install_command(self) -> &'static str {
        match self {
            Self::CargoDeny => "cargo install --locked cargo-deny@0.19.6",
            Self::CargoAudit => "cargo install --locked cargo-audit@0.22.1",
        }
    }
}

pub trait CommandRunner {
    fn git_show(&self, current_dir: &Path, object: &str) -> Result<String, RunnerError>;
    /// Whether the delegate binary can be found on `PATH`. `Ok(false)` means a
    /// clean ENOENT (not installed); an `Err` is any other spawn failure and
    /// stays fail-closed. No default impl on purpose: a defaulted `Ok(true)`
    /// would silently fail open if an implementor forgot to override it.
    fn delegate_available(&self, delegate: Delegate) -> Result<bool, RunnerError>;
    fn cargo_metadata(&self, current_dir: &Path) -> Result<String, RunnerError>;
    fn cargo_metadata_frozen(&self, current_dir: &Path) -> Result<String, RunnerError>;
    fn cargo_locate_project_workspace(
        &self,
        current_dir: &Path,
        manifest_path: &Path,
    ) -> Result<String, RunnerError>;
    fn cargo_update_precise(
        &self,
        current_dir: &Path,
        package_id: &str,
        version: &str,
    ) -> Result<(), RunnerError>;
    fn cargo_generate_lockfile(&self, current_dir: &Path) -> Result<(), RunnerError>;
    fn cargo_tree(&self, current_dir: &Path) -> Result<String, RunnerError>;
    fn git_diff(&self, current_dir: &Path, paths: &[PathBuf]) -> Result<String, RunnerError>;
    fn git_untracked(&self, current_dir: &Path, paths: &[PathBuf]) -> Result<String, RunnerError>;
    fn cargo_audit(&self, current_dir: &Path) -> Result<String, RunnerError>;
    fn cargo_audit_json(
        &self,
        controlled_cwd: &Path,
        lockfile_path: &Path,
    ) -> Result<CommandOutput, RunnerError>;
    fn cargo_deny_json(
        &self,
        current_dir: &Path,
        config_path: &Path,
        checks: &[barbican::CargoDenyCheck],
    ) -> Result<CommandOutput, RunnerError>;
    fn cargo_build_locked(&self, current_dir: &Path) -> Result<(), RunnerError>;
    fn cargo_test_locked(&self, current_dir: &Path) -> Result<(), RunnerError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub stdout: String,
    pub stderr: String,
    /// The delegate's exit code, or `None` if it was terminated by a signal.
    /// A delegate legitimately exits non-zero when it finds advisories, so
    /// this is consulted only once the structured output has failed to parse:
    /// a non-zero exit there means the delegate itself failed, not that it
    /// reported findings.
    pub exit_code: Option<i32>,
}

#[derive(Debug)]
pub enum RunnerError {
    Spawn(io::Error),
    Exited {
        code: Option<i32>,
        stdout: String,
        stderr: String,
    },
}

/// The single `RunnerError` renderer: every failed subprocess call renders
/// through here, so the exit code is never silently dropped just because
/// stdout or stderr happened to carry text — the two former sibling
/// renderers (this one and gatehouse's now-removed `render_runner_error`)
/// disagreed on exactly that, one keeping the code and one dropping it
/// whenever output was present.
impl fmt::Display for RunnerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spawn(error) => write!(formatter, "unable to start command: {error}"),
            Self::Exited {
                code,
                stdout,
                stderr,
            } => {
                match code {
                    Some(code) => write!(formatter, "command exited with status {code}")?,
                    None => write!(formatter, "command terminated without an exit code")?,
                }
                if !stdout.is_empty() {
                    write!(formatter, "; stdout: {stdout}")?;
                }
                if !stderr.is_empty() {
                    write!(formatter, "; stderr: {stderr}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for RunnerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Spawn(error) => Some(error),
            Self::Exited { .. } => None,
        }
    }
}

pub struct RealCommandRunner;

impl CommandRunner for RealCommandRunner {
    fn git_show(&self, current_dir: &Path, object: &str) -> Result<String, RunnerError> {
        run_command(current_dir, "git", ["show", object])
    }

    fn delegate_available(&self, delegate: Delegate) -> Result<bool, RunnerError> {
        classify_probe_spawn(
            ProcessCommand::new(delegate.binary())
                .arg("--version")
                .output(),
        )
    }

    fn cargo_metadata(&self, current_dir: &Path) -> Result<String, RunnerError> {
        run_cargo_command(current_dir, ["metadata", "--format-version", "1"])
    }

    fn cargo_metadata_frozen(&self, current_dir: &Path) -> Result<String, RunnerError> {
        run_cargo_command(
            current_dir,
            ["metadata", "--format-version", "1", "--frozen"],
        )
    }

    fn cargo_locate_project_workspace(
        &self,
        current_dir: &Path,
        manifest_path: &Path,
    ) -> Result<String, RunnerError> {
        let mut command = prepared_cargo_command(current_dir);
        command.args([
            "locate-project",
            "--workspace",
            "--message-format",
            "plain",
            "--manifest-path",
        ]);
        command.arg(manifest_path);
        stdout_from_output(run_prepared_command(command)?)
    }

    fn cargo_update_precise(
        &self,
        current_dir: &Path,
        package_id: &str,
        version: &str,
    ) -> Result<(), RunnerError> {
        run_cargo_command_status(
            current_dir,
            [
                "update",
                "--workspace",
                "-p",
                package_id,
                "--precise",
                version,
            ],
        )
    }

    fn git_diff(&self, current_dir: &Path, paths: &[PathBuf]) -> Result<String, RunnerError> {
        let mut command = ProcessCommand::new("git");
        command
            .current_dir(current_dir)
            .args(["diff", "HEAD", "--"]);
        for path in paths {
            command.arg(path);
        }

        stdout_from_output(run_prepared_command(command)?)
    }

    fn git_untracked(&self, current_dir: &Path, paths: &[PathBuf]) -> Result<String, RunnerError> {
        let mut command = ProcessCommand::new("git");
        command.current_dir(current_dir).args([
            "ls-files",
            "--others",
            "--exclude-standard",
            "-z",
            "--",
        ]);
        for path in paths {
            command.arg(path);
        }

        stdout_from_output(run_prepared_command(command)?)
    }

    fn cargo_generate_lockfile(&self, current_dir: &Path) -> Result<(), RunnerError> {
        run_cargo_command_status(current_dir, ["generate-lockfile"])
    }

    fn cargo_tree(&self, current_dir: &Path) -> Result<String, RunnerError> {
        run_cargo_command(current_dir, ["tree", "--edges", "normal"])
    }

    fn cargo_audit(&self, current_dir: &Path) -> Result<String, RunnerError> {
        run_cargo_command(current_dir, ["audit"])
    }

    fn cargo_audit_json(
        &self,
        controlled_cwd: &Path,
        lockfile_path: &Path,
    ) -> Result<CommandOutput, RunnerError> {
        let mut command = prepared_cargo_command(controlled_cwd);
        command.args(["audit", "--json", "-f"]);
        command.arg(lockfile_path);
        command.arg("-d");
        command.arg(advisory_database_path());

        output_from_prepared_command(command)
    }

    fn cargo_deny_json(
        &self,
        current_dir: &Path,
        config_path: &Path,
        checks: &[barbican::CargoDenyCheck],
    ) -> Result<CommandOutput, RunnerError> {
        let mut command = prepared_cargo_command(current_dir);
        command.args(["deny", "-f", "json", "check", "-c"]);
        command.arg(config_path);
        for check in checks {
            command.arg(check.as_str());
        }

        output_from_prepared_command(command)
    }

    fn cargo_build_locked(&self, current_dir: &Path) -> Result<(), RunnerError> {
        run_cargo_command_status(current_dir, ["build", "--locked"])
    }

    fn cargo_test_locked(&self, current_dir: &Path) -> Result<(), RunnerError> {
        run_cargo_test_locked(current_dir)
    }
}

fn run_command<const N: usize>(
    current_dir: &Path,
    program: &str,
    args: [&str; N],
) -> Result<String, RunnerError> {
    let mut command = ProcessCommand::new(program);
    command.current_dir(current_dir).args(args);

    stdout_from_output(run_prepared_command(command)?)
}

fn run_cargo_command<const N: usize>(
    current_dir: &Path,
    args: [&str; N],
) -> Result<String, RunnerError> {
    let mut command = prepared_cargo_command(current_dir);
    command.args(args);

    stdout_from_output(run_prepared_command(command)?)
}

fn run_cargo_command_status<const N: usize>(
    current_dir: &Path,
    args: [&str; N],
) -> Result<(), RunnerError> {
    let mut command = prepared_cargo_command(current_dir);
    command.args(args);

    stdout_from_output(run_prepared_command(command)?).map(|_| ())
}

fn run_cargo_test_locked(current_dir: &Path) -> Result<(), RunnerError> {
    let mut command = prepared_cargo_command(current_dir);
    command.args(["test", "--locked"]);

    if should_force_serial_nested_tests() {
        command.env("RUST_TEST_THREADS", "1");
    }

    stdout_from_output(run_prepared_command(command)?).map(|_| ())
}

fn prepared_cargo_command(current_dir: &Path) -> ProcessCommand {
    let mut command = ProcessCommand::new("cargo");
    command.current_dir(current_dir);

    for (name, _) in env::vars_os() {
        if should_strip_from_nested_cargo_env(&name) {
            command.env_remove(name);
        }
    }

    command
}

fn should_strip_from_nested_cargo_env(name: &OsStr) -> bool {
    let name = name.to_string_lossy();

    if matches!(
        name.as_ref(),
        "CARGO_MAKEFLAGS"
            | "CARGO_TARGET_TMPDIR"
            | "DYLD_FALLBACK_LIBRARY_PATH"
            | "DYLD_LIBRARY_PATH"
            | "LD_LIBRARY_PATH"
            | "MAKEFLAGS"
            | "MFLAGS"
            | "NUM_JOBS"
            | "OUT_DIR"
            | "RUST_RECURSION_COUNT"
    ) {
        return true;
    }

    if !name.starts_with("CARGO_") {
        return false;
    }

    !should_preserve_cargo_env(name.as_ref())
}

fn should_preserve_cargo_env(name: &str) -> bool {
    matches!(name, "CARGO_HOME" | "CARGO_TARGET_DIR")
        || name.starts_with("CARGO_ALIAS_")
        || name.starts_with("CARGO_BUILD_")
        || name.starts_with("CARGO_HTTP_")
        || name.starts_with("CARGO_INSTALL_")
        || name.starts_with("CARGO_NET_")
        || name.starts_with("CARGO_PROFILE_")
        || name.starts_with("CARGO_REGISTRIES_")
        || name.starts_with("CARGO_REGISTRY_")
        || name.starts_with("CARGO_TARGET_")
        || name.starts_with("CARGO_TERM_")
        || name.starts_with("CARGO_UNSTABLE_")
}

fn should_force_serial_nested_tests() -> bool {
    should_force_serial_nested_tests_with_env(
        env::var_os("RUST_TEST_THREADS").is_some(),
        env::var_os("CARGO_MANIFEST_DIR").is_some(),
    )
}

fn should_force_serial_nested_tests_with_env(
    has_rust_test_threads_override: bool,
    running_inside_cargo: bool,
) -> bool {
    running_inside_cargo && !has_rust_test_threads_override
}

fn run_prepared_command(mut command: ProcessCommand) -> Result<Output, RunnerError> {
    command.output().map_err(RunnerError::Spawn)
}

fn output_from_prepared_command(command: ProcessCommand) -> Result<CommandOutput, RunnerError> {
    let output = run_prepared_command(command)?;
    Ok(CommandOutput {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        exit_code: output.status.code(),
    })
}

/// A `NotFound` spawn error is the one benign outcome — the binary simply is
/// not installed — and resolves to `Ok(false)`. Every other spawn error stays
/// fail-closed as `Err`. A spawned process that exits (even non-zero) proves
/// the binary exists, so any `Ok(_)` output means available.
fn classify_probe_spawn(spawn: io::Result<Output>) -> Result<bool, RunnerError> {
    match spawn {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(RunnerError::Spawn(error)),
    }
}

fn stdout_from_output(output: Output) -> Result<String, RunnerError> {
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(RunnerError::Exited {
            code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).trim().to_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        })
    }
}

fn advisory_database_path() -> PathBuf {
    env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")))
        .unwrap_or_else(|| PathBuf::from(".cargo"))
        .join("advisory-db")
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::io;

    use super::{
        RunnerError, classify_probe_spawn, should_force_serial_nested_tests_with_env,
        should_strip_from_nested_cargo_env,
    };

    #[test]
    fn probe_treats_missing_binary_as_unavailable_not_an_error() {
        let outcome = classify_probe_spawn(Err(io::Error::from(io::ErrorKind::NotFound)));
        assert!(!outcome.expect("ENOENT should be a clean unavailable"));
    }

    #[test]
    fn probe_keeps_other_spawn_failures_fail_closed() {
        let outcome = classify_probe_spawn(Err(io::Error::from(io::ErrorKind::PermissionDenied)));
        assert!(matches!(outcome, Err(RunnerError::Spawn(_))));
    }

    #[test]
    fn strips_cargo_run_metadata_from_nested_cargo_commands() {
        for name in [
            "CARGO_BIN_NAME",
            "CARGO_BIN_EXE_cargo_barbican",
            "CARGO_CRATE_NAME",
            "CARGO_ENCODED_RUSTFLAGS",
            "CARGO_MAKEFLAGS",
            "CARGO_MANIFEST_DIR",
            "CARGO_MANIFEST_PATH",
            "CARGO_PKG_NAME",
            "CARGO_PRIMARY_PACKAGE",
            "CARGO_TARGET_TMPDIR",
            "DYLD_FALLBACK_LIBRARY_PATH",
            "DYLD_LIBRARY_PATH",
            "LD_LIBRARY_PATH",
            "MAKEFLAGS",
            "MFLAGS",
            "NUM_JOBS",
            "OUT_DIR",
            "RUST_RECURSION_COUNT",
        ] {
            assert!(should_strip_from_nested_cargo_env(OsStr::new(name)));
        }
    }

    #[test]
    fn preserves_user_level_cargo_configuration_env() {
        for name in [
            "CARGO_HOME",
            "CARGO_TARGET_DIR",
            "CARGO_TERM_COLOR",
            "CARGO_HTTP_TIMEOUT",
            "CARGO_REGISTRIES_CRATES_IO_PROTOCOL",
            "PATH",
            "HOME",
        ] {
            assert!(!should_strip_from_nested_cargo_env(OsStr::new(name)));
        }
    }

    #[test]
    fn forces_serial_nested_tests_only_for_self_hosted_cargo_without_override() {
        assert!(should_force_serial_nested_tests_with_env(false, true));
        assert!(!should_force_serial_nested_tests_with_env(true, true));
        assert!(!should_force_serial_nested_tests_with_env(false, false));
    }
}
