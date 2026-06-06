use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use crate::command_runner::CommandRunner;

use super::{CommandError, fail};

pub(super) fn run_audit<R>(
    current_dir: &Path,
    runner: &R,
    stderr: &mut dyn Write,
) -> Result<ExitCode, CommandError>
where
    R: CommandRunner + ?Sized,
{
    if let Err(error) = runner.cargo_audit(current_dir) {
        return fail(stderr, format!("cargo audit: {error}"));
    }
    if let Err(error) = runner.cargo_deny(current_dir) {
        return fail(
            stderr,
            format!("cargo deny check advisories bans sources: {error}"),
        );
    }

    Ok(ExitCode::SUCCESS)
}
