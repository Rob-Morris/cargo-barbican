use std::io::Write;
use std::path::Path;
use std::process::ExitCode;
use std::{fs, io};

use crate::cli::REVIEWED_TARGETS_CONFIG_FILE;
use crate::command_runner::CommandRunner;

use super::pin_check::run_pin_check;
use super::{CommandError, fail};

pub(super) fn run_verify<R>(
    current_dir: &Path,
    runner: &R,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<ExitCode, CommandError>
where
    R: CommandRunner + ?Sized,
{
    match fs::symlink_metadata(current_dir.join(REVIEWED_TARGETS_CONFIG_FILE)) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => {
            return fail(
                stderr,
                format!("{REVIEWED_TARGETS_CONFIG_FILE}: reviewed-targets policy is not a file"),
            );
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return fail(
                stderr,
                format!(
                    "{REVIEWED_TARGETS_CONFIG_FILE}: reviewed-targets policy required for verify"
                ),
            );
        }
        Err(error) => {
            return fail(
                stderr,
                format!("unable to inspect {REVIEWED_TARGETS_CONFIG_FILE}: {error}"),
            );
        }
    }

    let pin_check_exit =
        run_pin_check(Path::new(REVIEWED_TARGETS_CONFIG_FILE), current_dir, stdout)?;
    if pin_check_exit != ExitCode::SUCCESS {
        return Ok(pin_check_exit);
    }

    if let Err(error) = runner.cargo_build_locked(current_dir) {
        return fail(stderr, format!("cargo build --locked: {error}"));
    }
    if let Err(error) = runner.cargo_test_locked(current_dir) {
        return fail(stderr, format!("cargo test --locked: {error}"));
    }

    Ok(ExitCode::SUCCESS)
}
