use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use barbican::{CratesIoClient, Lockfile, OffsetDateTime, added_crates_io_specs};

use crate::command_runner::CommandRunner;

use super::{
    CommandError, DEFAULT_BASE_REF, ReviewedReleaseAgeExceptions, fail, finish_release_age_checks,
    load_current_lockfile, load_git_base_lockfile, load_lockfile_from_path,
    load_release_age_context,
};

pub(super) fn run_age_lock<C, R>(
    base_ref: Option<&str>,
    base_lockfile: Option<&Path>,
    min_age_days: Option<u64>,
    lockfile: &Path,
    current_dir: &Path,
    client: &C,
    runner: &R,
    now: OffsetDateTime,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<ExitCode, CommandError>
where
    C: CratesIoClient + ?Sized,
    R: CommandRunner + ?Sized,
{
    let (minimum_days, reviewed_release_age_exceptions) =
        load_release_age_context(current_dir, min_age_days)?;
    let current = match load_current_lockfile(current_dir, lockfile) {
        Ok(lockfile) => lockfile,
        Err(error) => return fail(stderr, error),
    };
    let lockfile_display = lockfile.display().to_string();

    let (base, base_label) = if let Some(base_lockfile) = base_lockfile {
        let display = base_lockfile.display().to_string();
        let path = current_dir.join(base_lockfile);
        let base = match load_lockfile_from_path(&path, &display) {
            Ok(lockfile) => lockfile,
            Err(error) => return fail(stderr, error),
        };

        (base, display)
    } else {
        let base_ref = base_ref.unwrap_or(DEFAULT_BASE_REF);
        let base = match load_git_base_lockfile(current_dir, runner, base_ref, lockfile) {
            Ok(lockfile) => lockfile,
            Err(error) => return fail(stderr, error),
        };

        (base, base_ref.to_owned())
    };

    recheck_lockfile_age_against_lockfiles(
        &current,
        &base,
        &lockfile_display,
        &base_label,
        minimum_days,
        &reviewed_release_age_exceptions,
        client,
        now,
        stdout,
        stderr,
    )
}

pub(super) fn recheck_lockfile_age_against_lockfiles<C>(
    current: &Lockfile,
    base: &Lockfile,
    lockfile_display: &str,
    base_label: &str,
    minimum_days: u64,
    reviewed_release_age_exceptions: &ReviewedReleaseAgeExceptions,
    client: &C,
    now: OffsetDateTime,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<ExitCode, CommandError>
where
    C: CratesIoClient + ?Sized,
{
    let specs = match added_crates_io_specs(current, base) {
        Ok(specs) => specs,
        Err(error) => {
            return fail(stderr, format!("{lockfile_display}: {error}"));
        }
    };

    if specs.is_empty() {
        writeln!(
            stdout,
            "OK   no newly selected crates.io packages detected in {lockfile_display} relative to {base_label}"
        )
        .map_err(CommandError::Io)?;
        return Ok(ExitCode::SUCCESS);
    }

    finish_release_age_checks(
        &specs,
        minimum_days,
        reviewed_release_age_exceptions,
        client,
        now,
        stdout,
        stderr,
    )
}
