use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use barbican::{CratesIoClient, added_crates_io_specs};

use crate::command_runner::CommandRunner;

use super::{
    CommandError, fail, finish_release_age_checks, load_config, load_current_and_base_lockfiles,
};

pub(super) fn run_age_lock<C, R>(
    base_ref: &str,
    min_age_days: Option<u64>,
    lockfile: &Path,
    current_dir: &Path,
    client: &C,
    runner: &R,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<ExitCode, CommandError>
where
    C: CratesIoClient + ?Sized,
    R: CommandRunner + ?Sized,
{
    let minimum_days = min_age_days.unwrap_or(load_config(current_dir)?.release_age.minimum_days);

    recheck_lockfile_age(
        base_ref,
        lockfile,
        minimum_days,
        current_dir,
        client,
        runner,
        stdout,
        stderr,
    )
}

pub(super) fn recheck_lockfile_age<C, R>(
    base_ref: &str,
    lockfile: &Path,
    minimum_days: u64,
    current_dir: &Path,
    client: &C,
    runner: &R,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<ExitCode, CommandError>
where
    C: CratesIoClient + ?Sized,
    R: CommandRunner + ?Sized,
{
    let lockfile_display = lockfile.display().to_string();
    let (current, base) =
        match load_current_and_base_lockfiles(current_dir, runner, base_ref, lockfile) {
            Ok(lockfiles) => lockfiles,
            Err(error) => return fail(stderr, error),
        };
    let specs = match added_crates_io_specs(&current, &base) {
        Ok(specs) => specs,
        Err(error) => {
            return fail(stderr, format!("{}: {error}", lockfile.display()));
        }
    };

    if specs.is_empty() {
        writeln!(
            stdout,
            "OK   no newly selected crates.io packages detected in {lockfile_display} relative to {base_ref}"
        )
        .map_err(CommandError::Io)?;
        return Ok(ExitCode::SUCCESS);
    }

    finish_release_age_checks(&specs, minimum_days, client, stdout, stderr)
}
