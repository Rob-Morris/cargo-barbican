use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use super::age_lock::recheck_lockfile_age_against_lockfiles;
use super::lockfile_ops::{LockfileRestoreGuard, MemoizingCratesIoClient};
use super::{CommandError, load_release_age_context, release_age_override_note};
use crate::command_runner::CommandRunner;
use barbican::{CratesIoClient, OffsetDateTime};

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
    let mut guard = LockfileRestoreGuard::capture(current_dir, true)?;
    let (base, original_text) = guard.original();
    let initial = original_text.is_none();
    let result = (|| {
        let memoized = MemoizingCratesIoClient::new(client);
        let (minimum_days, exceptions) = load_release_age_context(current_dir, min_age_days)?;
        if let Some(note) = release_age_override_note(current_dir, min_age_days)? {
            writeln!(stdout, "{note}").map_err(CommandError::Io)?;
        }
        guard.mutate("cargo generate-lockfile", || {
            runner.cargo_generate_lockfile(current_dir)
        })?;
        let (current, _) = guard.current()?;
        let label = if initial {
            writeln!(stdout, "Initial resolution: no previous Cargo.lock existed; checking every selected crates.io version. This prepares a graph for review, not approval to build.")
                .map_err(CommandError::Io)?;
            "initially absent Cargo.lock"
        } else {
            "pre-resolve Cargo.lock"
        };
        recheck_lockfile_age_against_lockfiles(
            &current,
            &base,
            "Cargo.lock",
            label,
            minimum_days,
            &exceptions,
            &memoized,
            now,
            stdout,
            stderr,
        )
    })();
    guard.finish(result)
}
