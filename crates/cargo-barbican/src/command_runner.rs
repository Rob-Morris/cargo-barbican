use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Output};

pub trait CommandRunner {
    fn git_show(&self, current_dir: &Path, object: &str) -> Result<String, RunnerError>;
    fn cargo_metadata(&self, current_dir: &Path) -> Result<String, RunnerError>;
    fn cargo_update_precise(
        &self,
        current_dir: &Path,
        package_id: &str,
        version: &str,
    ) -> Result<(), RunnerError>;
    fn git_diff(&self, current_dir: &Path, paths: &[PathBuf]) -> Result<String, RunnerError>;
    fn cargo_audit(&self, current_dir: &Path) -> Result<(), RunnerError>;
    fn cargo_deny(&self, current_dir: &Path) -> Result<(), RunnerError>;
    fn cargo_build_locked(&self, current_dir: &Path) -> Result<(), RunnerError>;
    fn cargo_test_locked(&self, current_dir: &Path) -> Result<(), RunnerError>;
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

impl fmt::Display for RunnerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spawn(error) => write!(formatter, "{error}"),
            Self::Exited { stderr, .. } if !stderr.is_empty() => write!(formatter, "{stderr}"),
            Self::Exited { stdout, .. } if !stdout.is_empty() => write!(formatter, "{stdout}"),
            Self::Exited {
                code: Some(code), ..
            } => write!(formatter, "command exited with status {code}"),
            Self::Exited { code: None, .. } => {
                write!(formatter, "command terminated without an exit code")
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

    fn cargo_metadata(&self, current_dir: &Path) -> Result<String, RunnerError> {
        run_command(current_dir, "cargo", ["metadata", "--format-version", "1"])
    }

    fn cargo_update_precise(
        &self,
        current_dir: &Path,
        package_id: &str,
        version: &str,
    ) -> Result<(), RunnerError> {
        run_command_status(
            current_dir,
            "cargo",
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
        command.current_dir(current_dir).arg("diff").arg("--");
        for path in paths {
            command.arg(path);
        }

        stdout_from_output(run_prepared_command(command)?)
    }

    fn cargo_audit(&self, current_dir: &Path) -> Result<(), RunnerError> {
        run_command_status(current_dir, "cargo", ["audit"])
    }

    fn cargo_deny(&self, current_dir: &Path) -> Result<(), RunnerError> {
        run_command_status(
            current_dir,
            "cargo",
            ["deny", "check", "advisories", "bans", "sources"],
        )
    }

    fn cargo_build_locked(&self, current_dir: &Path) -> Result<(), RunnerError> {
        run_command_status(current_dir, "cargo", ["build", "--locked"])
    }

    fn cargo_test_locked(&self, current_dir: &Path) -> Result<(), RunnerError> {
        run_command_status(current_dir, "cargo", ["test", "--locked"])
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

fn run_command_status<const N: usize>(
    current_dir: &Path,
    program: &str,
    args: [&str; N],
) -> Result<(), RunnerError> {
    let mut command = ProcessCommand::new(program);
    command.current_dir(current_dir).args(args);

    stdout_from_output(run_prepared_command(command)?).map(|_| ())
}

fn run_prepared_command(mut command: ProcessCommand) -> Result<Output, RunnerError> {
    command.output().map_err(RunnerError::Spawn)
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
