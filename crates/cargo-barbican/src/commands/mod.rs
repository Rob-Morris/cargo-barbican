mod age;
mod age_lock;
mod assess;
mod audit;
mod diff_render;
mod errors;
mod gatehouse;
mod inspect;
mod inventory;
mod loaders;
mod lockfile_ops;
mod pick;
mod pin;
mod pin_check;
mod policy;
mod render;
mod resolve;
mod review;
mod scaffold_fs;
mod scratch_dir;
mod update;
mod verify;
mod workspace;

use std::env;
use std::ffi::OsString;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use barbican::{
    CratesIoClient, ExactCrateSpec, OffsetDateTime, ReleaseAgeGateVerdict, check_release_age_at,
    classify_release_age_gate,
};
use clap::Parser;

use crate::cli::{Cli, Command};
use crate::command_runner::{CommandRunner, RealCommandRunner};
use crate::crates_io_http::{
    CRATES_IO_BASE_URL_ENV, DEFAULT_CRATES_IO_BASE_URL, UreqCratesIoClient,
};

use loaders::crates_io_base_url;

pub use errors::CommandError;
pub(crate) use errors::{escape_diagnostic_for_terminal, exit_code_from_policy_failures};
pub(crate) use loaders::{
    NativeDelegatedIgnore, ReviewRecordStatusCache, ReviewedReleaseAgeExceptions,
    check_review_record_paths, collect_reviewed_release_age_exceptions,
    load_base_manifest_dependencies, load_config, load_current_lockfile,
    load_current_lockfile_text, load_current_lockfile_with_text,
    load_current_manifest_direct_and_workspace_requirements,
    load_current_manifest_direct_requirements, load_git_base_lockfile, load_lockfile_from_path,
    load_manifest_dependencies_from_root, load_manifest_patched_crate_names,
    load_manifest_texts_from_root, load_native_delegated_ignores, load_release_age_context,
    load_reviewed_targets, parse_manifest_requirements, read_optional_text_no_symlink,
    release_age_override_note, source_replacement_finding,
};
pub(crate) use render::{
    escape_render_field, fail, join_display, render_allowed_policy_exceptions,
    render_incomplete_release_age_exception_review_record, render_release_age_report,
};
pub(crate) use workspace::{
    REVIEW_RECORDS_DIR, collect_relative_files_matching, insert_review_root_paths, review_paths,
    workspace_manifest_paths,
};

pub(super) const DEFAULT_BASE_REF: &str = "HEAD";

pub fn run(stdout: &mut dyn Write, stderr: &mut dyn Write) -> Result<ExitCode, CommandError> {
    let cli = Cli::parse_from(cargo_subcommand_args(env::args_os()));

    match run_at(cli, stdout, stderr) {
        Ok(exit_code) => Ok(exit_code),
        Err(error) => fail(stderr, error),
    }
}

fn run_at(
    cli: Cli,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<ExitCode, CommandError> {
    let current_dir = env::current_dir().map_err(CommandError::Io)?;
    let base_url = crates_io_base_url()?;
    if base_url != DEFAULT_CRATES_IO_BASE_URL {
        writeln!(
            stdout,
            "note: crates.io source overridden to {base_url} via {CRATES_IO_BASE_URL_ENV}"
        )
        .map_err(CommandError::Io)?;
    }
    let client = UreqCratesIoClient::new(base_url);
    let runner = RealCommandRunner;

    run_cli_with_runner(cli, &current_dir, &client, &runner, stdout, stderr)
}

fn cargo_subcommand_args<I>(args: I) -> Vec<OsString>
where
    I: IntoIterator<Item = OsString>,
{
    let mut args = args.into_iter();
    let Some(program) = args.next() else {
        return Vec::new();
    };

    let mut normalised = vec![program];
    match args.next() {
        Some(first) if first == "barbican" => normalised.extend(args),
        Some(first) => {
            normalised.push(first);
            normalised.extend(args);
        }
        None => {}
    }

    normalised
}

pub fn run_cli_with_runner<C, R>(
    cli: Cli,
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
    run_cli_with_runner_at(
        cli,
        current_dir,
        client,
        runner,
        OffsetDateTime::now_utc(),
        stdout,
        stderr,
    )
}

/// The single seam every subcommand's failure funnels through: whatever a
/// command returns as `Err(CommandError)` is rendered here as one
/// `FAIL `-prefixed stderr line via [`fail`], rather than each command
/// choosing ad hoc between rendering its own failure and letting the error
/// bubble to the process boundary with no stable token at all. Exit codes
/// are unchanged by this — a propagated `CommandError` still exits `1`.
pub fn run_cli_with_runner_at<C, R>(
    cli: Cli,
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
    match dispatch_command(cli, current_dir, client, runner, now, stdout, stderr) {
        Ok(exit_code) => Ok(exit_code),
        Err(error) => fail(stderr, error),
    }
}

fn dispatch_command<C, R>(
    cli: Cli,
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
    let allow_manifest_degradation = matches!(&cli.command, Command::Audit { .. });
    let workspace =
        workspace::discover_workspace_root(current_dir, runner, allow_manifest_degradation)?;
    let current_dir = workspace.root();

    match cli.command {
        Command::Age {
            min_age_days,
            specs,
        } => age::run_age(
            min_age_days,
            specs,
            current_dir,
            client,
            now,
            stdout,
            stderr,
        ),
        Command::AgeLock {
            base_ref,
            base_lockfile,
            min_age_days,
            lockfile,
        } => age_lock::run_age_lock(
            base_ref.as_deref(),
            base_lockfile.as_deref(),
            min_age_days,
            &lockfile,
            current_dir,
            client,
            runner,
            now,
            stdout,
            stderr,
        ),
        Command::Update {
            dry_run,
            min_age_days,
            specs,
        } => update::run_update(
            dry_run,
            min_age_days,
            specs,
            current_dir,
            client,
            runner,
            now,
            stdout,
            stderr,
        ),
        Command::Resolve { min_age_days } => resolve::run_resolve(
            min_age_days,
            current_dir,
            client,
            runner,
            now,
            stdout,
            stderr,
        ),
        Command::Assess {
            base_ref,
            base_dir,
            policy_mode,
            min_age_days,
            lockfile,
        } => assess::run_assess(
            base_ref.as_deref(),
            base_dir.as_deref(),
            policy_mode,
            min_age_days,
            &lockfile,
            current_dir,
            client,
            runner,
            now,
            stdout,
            stderr,
        ),
        Command::Inspect {
            min_age_days,
            specs,
        } => inspect::run_inspect(
            min_age_days,
            specs,
            current_dir,
            client,
            now,
            stdout,
            stderr,
        ),
        Command::Pick { min_age_days, spec } => {
            pick::run_pick(min_age_days, spec, current_dir, client, now, stdout, stderr)
        }
        Command::Gatehouse { command } => {
            gatehouse::run_gatehouse(command, current_dir, client, runner, now, stdout, stderr)
        }
        Command::Policy { command } => policy::run_policy(command, current_dir, stdout),
        Command::Inventory { enforce } => {
            inventory::run_inventory(current_dir, runner, now, enforce, stdout)
        }
        Command::Pin { command } => pin::run_pin(command, current_dir, now, stdout, stderr),
        Command::Review { base_dir } => {
            review::run_review(base_dir.as_deref(), current_dir, runner, stdout, stderr)
        }
        Command::Audit { format } => audit::run_audit(
            format,
            current_dir,
            workspace.degradation_reason(),
            runner,
            now,
            stdout,
            stderr,
        ),
        Command::Verify => verify::run_verify(current_dir, runner, stdout, stderr),
    }
}

pub(super) struct ParseSpecsResult {
    pub(super) specs: Vec<ExactCrateSpec>,
    pub(super) failed: bool,
}

pub(super) fn parse_specs(
    raw_specs: Vec<String>,
    stderr: &mut dyn Write,
) -> Result<ParseSpecsResult, CommandError> {
    let mut specs = Vec::new();
    let mut failed = false;

    for raw_spec in raw_specs {
        match raw_spec.parse::<ExactCrateSpec>() {
            Ok(spec) => specs.push(spec),
            Err(error) => {
                writeln!(stderr, "FAIL {raw_spec}: {error}").map_err(CommandError::Io)?;
                failed = true;
            }
        }
    }

    Ok(ParseSpecsResult { specs, failed })
}

pub(super) fn finish_release_age_checks<C>(
    specs: &[ExactCrateSpec],
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
    let mut failed = false;
    let mut allowed_reports = Vec::new();
    let mut routine_reports = Vec::new();

    for spec in specs {
        let age_exception = reviewed_release_age_exceptions
            .honoured()
            .iter()
            .find(|exception| exception.spec() == spec);
        match check_release_age_at(client, spec, now, minimum_days, age_exception) {
            Ok(report) => match classify_release_age_gate(
                report.outcome(),
                reviewed_release_age_exceptions.unsatisfied_for_spec(spec),
            ) {
                ReleaseAgeGateVerdict::Routine => {
                    routine_reports.push(report);
                }
                ReleaseAgeGateVerdict::AllowedByException => {
                    allowed_reports.push(report);
                }
                ReleaseAgeGateVerdict::IncompleteReviewRecord(exception) => {
                    writeln!(
                        stderr,
                        "FAIL {}",
                        render_incomplete_release_age_exception_review_record(exception)
                    )
                    .map_err(CommandError::Io)?;
                    failed = true;
                }
                ReleaseAgeGateVerdict::Blocked => {
                    writeln!(stderr, "{}", render_release_age_report(&report))
                        .map_err(CommandError::Io)?;
                    failed = true;
                }
            },
            Err(error) => {
                writeln!(stderr, "FAIL {spec}: {error}").map_err(CommandError::Io)?;
                failed = true;
            }
        }
    }

    for report in routine_reports {
        writeln!(stdout, "{}", render_release_age_report(&report)).map_err(CommandError::Io)?;
    }

    if !allowed_reports.is_empty() {
        writeln!(stdout, "Allowed policy exceptions:").map_err(CommandError::Io)?;
        for report in allowed_reports {
            writeln!(stdout, "  - {}", render_release_age_report(&report))
                .map_err(CommandError::Io)?;
        }
    }

    Ok(exit_code_from_policy_failures(failed))
}
