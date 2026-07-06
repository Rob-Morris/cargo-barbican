use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use barbican::{CratesIoClient, OffsetDateTime};

use super::{
    CommandError, exit_code_from_policy_failures, finish_release_age_checks,
    load_release_age_context, parse_specs,
};

pub(super) fn run_age<C>(
    min_age_days: Option<u64>,
    raw_specs: Vec<String>,
    current_dir: &Path,
    client: &C,
    now: OffsetDateTime,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<ExitCode, CommandError>
where
    C: CratesIoClient + ?Sized,
{
    let (minimum_days, reviewed_release_age_exceptions) =
        load_release_age_context(current_dir, min_age_days)?;
    let parse_result = parse_specs(raw_specs, stderr)?;
    let age_exit = finish_release_age_checks(
        &parse_result.specs,
        minimum_days,
        &reviewed_release_age_exceptions,
        client,
        now,
        stdout,
        stderr,
    )?;

    Ok(exit_code_from_policy_failures(
        parse_result.failed || age_exit != ExitCode::SUCCESS,
    ))
}
