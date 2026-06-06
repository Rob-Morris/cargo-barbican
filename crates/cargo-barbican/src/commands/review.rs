use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use crate::command_runner::CommandRunner;

use super::{CommandError, fail, review_paths};

pub(super) fn run_review<R>(
    current_dir: &Path,
    runner: &R,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<ExitCode, CommandError>
where
    R: CommandRunner + ?Sized,
{
    let paths = review_paths(current_dir).map_err(CommandError::Io)?;
    let diff = match runner.git_diff(current_dir, &paths) {
        Ok(diff) => diff,
        Err(error) => return fail(stderr, format!("git diff: {error}")),
    };

    if diff.trim().is_empty() {
        writeln!(
            stdout,
            "No Rust dependency manifest or lockfile changes detected."
        )
        .map_err(CommandError::Io)?;
        return Ok(ExitCode::SUCCESS);
    }

    writeln!(
        stdout,
        "Review checklist:\n  - Confirm the changed crates and versions are the ones you intended.\n  - Confirm the routine workflow only changed the root Cargo.lock.\n  - Check for unexpected registry, git, path, patch, or source-replacement changes.\n  - Check for new build-dependencies, proc-macro crates, or native -sys / FFI crates.\n"
    )
    .map_err(CommandError::Io)?;
    write!(stdout, "{diff}").map_err(CommandError::Io)?;

    Ok(ExitCode::SUCCESS)
}
