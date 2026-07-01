use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use barbican::{CratesIoClient, OffsetDateTime, parse_lockfile};

use crate::cli::REVIEWED_TARGETS_CONFIG_FILE;
use crate::command_runner::CommandRunner;

use super::age_lock::recheck_lockfile_age_against_lockfiles;
use super::update::{MemoizingCratesIoClient, restore_base_lockfile};
use super::{
    CommandError, fail, load_config, load_current_lockfile_text, load_current_lockfile_with_text,
    load_reviewed_release_age_exceptions,
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
    let minimum_days = min_age_days.unwrap_or(load_config(current_dir)?.release_age.minimum_days);
    let reviewed_release_age_exceptions =
        load_reviewed_release_age_exceptions(current_dir, Path::new(REVIEWED_TARGETS_CONFIG_FILE))?;
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

    if let Err(error) = runner.cargo_generate_lockfile(current_dir) {
        restore_base_lockfile(current_dir, &base_lockfile_text, stderr)?;
        return fail(stderr, format!("cargo generate-lockfile: {error}"));
    }

    let (current_lockfile, _) =
        match load_current_lockfile_with_text(current_dir, Path::new("Cargo.lock")) {
            Ok(lockfile_with_text) => lockfile_with_text,
            Err(error) => {
                restore_base_lockfile(current_dir, &base_lockfile_text, stderr)?;
                return fail(stderr, error);
            }
        };

    let age_recheck_exit = recheck_lockfile_age_against_lockfiles(
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
    )?;

    if age_recheck_exit != ExitCode::SUCCESS {
        restore_base_lockfile(current_dir, &base_lockfile_text, stderr)?;
    }

    Ok(age_recheck_exit)
}
