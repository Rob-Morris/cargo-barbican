use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use barbican::{
    CratesIoClient, RustAssessmentClassification, RustAssessmentReport, assess_rust_update,
    parse_cargo_metadata,
};

use crate::command_runner::CommandRunner;

use super::{
    CommandError, fail, load_base_manifest_dependencies, load_config,
    load_current_and_base_lockfiles, load_current_manifest_dependencies,
};

pub(super) fn run_assess<C, R>(
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
    let config = load_config(current_dir)?;
    let minimum_days = min_age_days.unwrap_or(config.release_age.minimum_days);
    let (current_lockfile, base_lockfile) =
        match load_current_and_base_lockfiles(current_dir, runner, base_ref, lockfile) {
            Ok(lockfiles) => lockfiles,
            Err(error) => return fail(stderr, error),
        };
    let current_manifests = match load_current_manifest_dependencies(current_dir) {
        Ok(manifests) => manifests,
        Err(error) => return fail(stderr, error),
    };
    let base_manifests = match load_base_manifest_dependencies(current_dir, runner, base_ref) {
        Ok(manifests) => manifests,
        Err(error) => return fail(stderr, error),
    };
    let metadata_text = match runner.cargo_metadata(current_dir) {
        Ok(text) => text,
        Err(error) => return fail(stderr, format!("cargo metadata: {error}")),
    };
    let metadata = match parse_cargo_metadata(&metadata_text) {
        Ok(metadata) => metadata,
        Err(error) => return fail(stderr, format!("cargo metadata: {error}")),
    };
    let report = assess_rust_update(
        client,
        &current_lockfile,
        &base_lockfile,
        &current_manifests,
        &base_manifests,
        &metadata,
        minimum_days,
        &config.high_scrutiny,
    );

    render_assessment_report(stdout, &report)?;

    Ok(match report.classification() {
        RustAssessmentClassification::RoutineSafe => ExitCode::SUCCESS,
        RustAssessmentClassification::ElevatedRisk
        | RustAssessmentClassification::PolicyViolating => ExitCode::from(1),
    })
}

fn render_assessment_report(
    stdout: &mut dyn Write,
    report: &RustAssessmentReport,
) -> Result<(), CommandError> {
    writeln!(
        stdout,
        "Suggested classification: {}",
        report.classification()
    )
    .map_err(CommandError::Io)?;
    writeln!(stdout).map_err(CommandError::Io)?;
    writeln!(stdout, "Rust Assessment").map_err(CommandError::Io)?;
    writeln!(
        stdout,
        "  - newly selected lock entries: {}; newly introduced crate names: {}",
        report.newly_selected_lock_entries(),
        report.newly_introduced_crate_names()
    )
    .map_err(CommandError::Io)?;

    render_assessment_line(
        stdout,
        "new direct dependencies",
        report.new_direct_dependencies(),
    )?;
    render_assessment_line(
        stdout,
        "new non-crates.io direct specs",
        report.non_crates_io_direct_dependencies(),
    )?;
    render_assessment_line(stdout, "age violations", report.age_violations())?;
    render_assessment_line(stdout, "yanked versions", report.yanked_versions())?;
    render_assessment_line(
        stdout,
        "source changes",
        report.non_crates_io_source_changes(),
    )?;
    render_assessment_line(stdout, "new -sys crates", report.native_sys_crates())?;
    render_assessment_line(
        stdout,
        "new/changed build.rs surface",
        report.build_rs_surfaces(),
    )?;
    render_assessment_line(
        stdout,
        "new/changed proc-macro surface",
        report.proc_macro_surfaces(),
    )?;
    render_assessment_line(stdout, "inspection failures", report.inspection_failures())?;
    writeln!(stdout).map_err(CommandError::Io)?;

    render_finding_section(
        stdout,
        "Blocking policy findings:",
        report.blocking_findings(),
    )?;
    render_finding_section(stdout, "Elevated-risk signals:", report.elevated_findings())?;

    if report.blocking_findings().is_empty() && report.elevated_findings().is_empty() {
        writeln!(stdout, "No policy findings detected.").map_err(CommandError::Io)?;
    }

    Ok(())
}
fn render_assessment_line(
    stdout: &mut dyn Write,
    label: &str,
    values: &[String],
) -> Result<(), CommandError> {
    if values.is_empty() {
        return Ok(());
    }

    writeln!(stdout, "  - {label}: {}", values.join(", ")).map_err(CommandError::Io)
}

fn render_finding_section(
    stdout: &mut dyn Write,
    header: &str,
    findings: &[String],
) -> Result<(), CommandError> {
    if findings.is_empty() {
        return Ok(());
    }

    writeln!(stdout, "{header}").map_err(CommandError::Io)?;
    for finding in findings {
        writeln!(stdout, "  - {finding}").map_err(CommandError::Io)?;
    }
    writeln!(stdout).map_err(CommandError::Io)
}
