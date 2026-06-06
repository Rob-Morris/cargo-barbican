use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use crate::command_runner::CommandRunner;

use super::{CommandError, fail};

pub(super) fn run_verify<R>(
    current_dir: &Path,
    runner: &R,
    stderr: &mut dyn Write,
) -> Result<ExitCode, CommandError>
where
    R: CommandRunner + ?Sized,
{
    if let Err(error) = runner.cargo_build_locked(current_dir) {
        return fail(stderr, format!("cargo build --locked: {error}"));
    }
    if let Err(error) = runner.cargo_test_locked(current_dir) {
        return fail(stderr, format!("cargo test --locked: {error}"));
    }

    Ok(ExitCode::SUCCESS)
}
