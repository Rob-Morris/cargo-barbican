use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use barbican::{CratesIoClient, OffsetDateTime, parse_lockfile};

use crate::command_runner::CommandRunner;

use super::age_lock::recheck_lockfile_age_against_lockfiles;
use super::lockfile_ops::{LockfileRestoreGuard, MemoizingCratesIoClient};
use super::{
    CommandError, fail, load_current_lockfile_text, load_current_lockfile_with_text,
    load_release_age_context, release_age_override_note,
};

pub(super) fn run_resolve<C, R>(
    min_age_days: Option<u64>,
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
    let memoized_client = MemoizingCratesIoClient::new(client);
    let (minimum_days, reviewed_release_age_exceptions) =
        load_release_age_context(current_dir, min_age_days)?;
    if let Some(note) = release_age_override_note(current_dir, min_age_days)? {
        writeln!(stdout, "{note}").map_err(CommandError::Io)?;
    }
    let base_lockfile_text = match load_current_lockfile_text(current_dir, Path::new("Cargo.lock"))
    {
        Ok(text) => text,
        Err(error) => return fail(stderr, error),
    };
    let base_lockfile = match parse_lockfile(&base_lockfile_text) {
        Ok(lockfile) => lockfile,
        Err(source) => {
            return fail(
                stderr,
                CommandError::LockfileParse {
                    path: "Cargo.lock".to_owned(),
                    source,
                },
            );
        }
    };

    let mut restore_guard = LockfileRestoreGuard::new(current_dir, &base_lockfile_text);

    if let Err(error) = runner.cargo_generate_lockfile(current_dir) {
        restore_guard.restore_now()?;
        return fail(stderr, format!("cargo generate-lockfile: {error}"));
    }

    let (current_lockfile, _) =
        match load_current_lockfile_with_text(current_dir, Path::new("Cargo.lock")) {
            Ok(lockfile_with_text) => lockfile_with_text,
            Err(error) => {
                restore_guard.restore_now()?;
                return fail(stderr, error);
            }
        };

    let age_recheck_exit = match recheck_lockfile_age_against_lockfiles(
        &current_lockfile,
        &base_lockfile,
        "Cargo.lock",
        "pre-resolve Cargo.lock",
        minimum_days,
        &reviewed_release_age_exceptions,
        &memoized_client,
        now,
        stdout,
        stderr,
    ) {
        Ok(exit_code) => exit_code,
        Err(error) => {
            restore_guard.restore_now()?;
            return Err(error);
        }
    };

    if age_recheck_exit == ExitCode::SUCCESS {
        restore_guard.disarm();
    } else {
        restore_guard.restore_now()?;
    }

    Ok(age_recheck_exit)
}
