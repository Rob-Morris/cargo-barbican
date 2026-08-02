use std::fmt::Display;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use barbican::{
    CratesIoClient, OffsetDateTime, ReleaseAgeGateVerdict, ReleaseAgeOutcome,
    ReviewedExecutionSurfaceAllowance, ReviewedReleaseAgeException, RustAssessmentClassification,
    RustAssessmentFinding, RustAssessmentFindingCategory, RustAssessmentFindingSeverity,
    RustAssessmentReport, classify_release_age_gate, parse_cargo_metadata,
};

use crate::cli::{AssessPolicyMode, REVIEWED_TARGETS_CONFIG_FILE};
use crate::command_runner::CommandRunner;

use super::{
    CommandError, DEFAULT_BASE_REF, ReviewRecordStatusCache,
    collect_reviewed_release_age_exceptions, fail, join_display, load_base_manifest_dependencies,
    load_config, load_current_lockfile, load_git_base_lockfile, load_lockfile_from_path,
    load_manifest_dependencies_from_root, load_reviewed_targets, render_allowed_policy_exceptions,
    render_incomplete_release_age_exception_review_record,
};

pub(super) fn run_assess<C, R>(
    base_ref: Option<&str>,
    base_dir: Option<&Path>,
    policy_mode: AssessPolicyMode,
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
    let config = load_config(current_dir)?;
    let minimum_days = min_age_days.unwrap_or(config.release_age.minimum_days);
    let reviewed_targets =
        load_reviewed_targets(current_dir, Path::new(REVIEWED_TARGETS_CONFIG_FILE))?;
    let reviewed_execution_surface_allowances = reviewed_targets
        .as_ref()
        .map(|reviewed_targets| reviewed_targets.execution_surface_allowances())
        .unwrap_or_default();
    let mut review_record_statuses = ReviewRecordStatusCache::new(current_dir);
    let reviewed_release_age_exceptions = reviewed_targets
        .as_ref()
        .map(|reviewed_targets| {
            collect_reviewed_release_age_exceptions(reviewed_targets, &mut review_record_statuses)
        })
        .unwrap_or_default();
    let base_root = base_dir.map(|base_dir| current_dir.join(base_dir));
    let current_lockfile = match load_current_lockfile(current_dir, lockfile) {
        Ok(lockfile) => lockfile,
        Err(error) => return fail(stderr, error),
    };
    let base_lockfile = if let Some(base_root) = &base_root {
        let base_lockfile_path = base_root.join(lockfile);
        let display = base_dir
            .expect("base_root implies base_dir")
            .join(lockfile)
            .display()
            .to_string();

        match load_lockfile_from_path(&base_lockfile_path, &display) {
            Ok(lockfile) => lockfile,
            Err(error) => return fail(stderr, error),
        }
    } else {
        let base_ref = base_ref.unwrap_or(DEFAULT_BASE_REF);
        match load_git_base_lockfile(current_dir, runner, base_ref, lockfile) {
            Ok(lockfile) => lockfile,
            Err(error) => return fail(stderr, error),
        }
    };
    let current_manifests = match load_manifest_dependencies_from_root(current_dir) {
        Ok(manifests) => manifests,
        Err(error) => return fail(stderr, error),
    };
    let base_manifests = if let Some(base_root) = &base_root {
        match load_manifest_dependencies_from_root(base_root) {
            Ok(manifests) => manifests,
            Err(error) => return fail(stderr, error),
        }
    } else {
        let base_ref = base_ref.unwrap_or(DEFAULT_BASE_REF);
        match load_base_manifest_dependencies(current_dir, runner, base_ref) {
            Ok(manifests) => manifests,
            Err(error) => return fail(stderr, error),
        }
    };
    let metadata_text = match runner.cargo_metadata(current_dir) {
        Ok(text) => text,
        Err(error) => return fail(stderr, format!("cargo metadata: {error}")),
    };
    let metadata = match parse_cargo_metadata(&metadata_text) {
        Ok(metadata) => metadata,
        Err(error) => return fail(stderr, format!("cargo metadata: {error}")),
    };
    let report = barbican::assess_rust_update_at(
        client,
        &current_lockfile,
        &base_lockfile,
        &current_manifests,
        &base_manifests,
        &metadata,
        minimum_days,
        &config.high_scrutiny,
        &reviewed_execution_surface_allowances,
        reviewed_release_age_exceptions.honoured(),
        now,
    );

    let mut incomplete_allowed_surface = None;
    for allowed_surface in report.allowed_execution_surfaces() {
        if !review_record_statuses
            .status(allowed_surface.review_record())
            .is_satisfied()
        {
            incomplete_allowed_surface = Some(allowed_surface);
            break;
        }
    }
    if let Some(allowed_surface) = incomplete_allowed_surface {
        return fail(
            stderr,
            format!(
                "allowed policy exception review record not completed for {}: {}",
                allowed_surface.spec(),
                allowed_surface.review_record()
            ),
        );
    }

    // Every age_violations() entry is by construction a TooFresh outcome; classify it
    // against the same precedence rule the age-focused commands use.
    if let Some(exception) = report.age_violations().iter().find_map(|violation| {
        match classify_release_age_gate(
            &ReleaseAgeOutcome::TooFresh,
            reviewed_release_age_exceptions.unsatisfied_for_spec(violation.spec()),
        ) {
            ReleaseAgeGateVerdict::IncompleteReviewRecord(exception) => Some(exception),
            _ => None,
        }
    }) {
        return fail(
            stderr,
            render_incomplete_release_age_exception_review_record(exception),
        );
    }

    render_assessment_report(stdout, &report)?;

    if accepts_elevated_risk(report.classification(), policy_mode) {
        writeln!(
            stdout,
            "Elevated-risk findings accepted by --policy-mode elevated-risk; blocking policy findings would still fail."
        )
        .map_err(CommandError::Io)?;
    }

    Ok(assessment_exit_code(report.classification(), policy_mode))
}

fn assessment_exit_code(
    classification: RustAssessmentClassification,
    policy_mode: AssessPolicyMode,
) -> ExitCode {
    if accepts_elevated_risk(classification, policy_mode) {
        return ExitCode::SUCCESS;
    }

    match classification {
        RustAssessmentClassification::RoutineSafe => ExitCode::SUCCESS,
        RustAssessmentClassification::ElevatedRisk
        | RustAssessmentClassification::PolicyViolating => ExitCode::from(1),
    }
}

fn accepts_elevated_risk(
    classification: RustAssessmentClassification,
    policy_mode: AssessPolicyMode,
) -> bool {
    classification == RustAssessmentClassification::ElevatedRisk
        && policy_mode == AssessPolicyMode::ElevatedRisk
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
        &report.new_direct_dependencies(),
    )?;
    render_assessment_line(
        stdout,
        "new non-crates.io direct specs",
        &rendered_non_crates_io_direct_dependencies(report),
    )?;
    render_assessment_line(stdout, "age violations", &report.age_violations())?;
    render_assessment_line(stdout, "yanked versions", &report.yanked_versions())?;
    render_assessment_line(
        stdout,
        "release-age exception artefact mismatches",
        &report.release_age_exception_mismatches(),
    )?;
    render_assessment_line(
        stdout,
        "lockfile checksum drifts",
        &report.locked_checksum_drifts(),
    )?;
    render_assessment_line(
        stdout,
        "source changes",
        &report.non_crates_io_source_changes(),
    )?;
    render_assessment_line(stdout, "new -sys crates", &report.native_sys_crates())?;
    render_assessment_line(
        stdout,
        "new/changed build.rs surface",
        &report.build_rs_surfaces(),
    )?;
    render_assessment_line(
        stdout,
        "new/changed proc-macro surface",
        &report.proc_macro_surfaces(),
    )?;
    render_assessment_line(stdout, "inspection failures", &report.inspection_failures())?;
    writeln!(stdout).map_err(CommandError::Io)?;

    render_finding_section(
        stdout,
        "Blocking policy findings:",
        report,
        RustAssessmentFindingSeverity::Blocking,
    )?;
    render_finding_section(
        stdout,
        "Elevated-risk signals:",
        report,
        RustAssessmentFindingSeverity::Elevated,
    )?;
    render_assess_allowed_exceptions(
        stdout,
        report.allowed_execution_surfaces(),
        report.allowed_release_age_exceptions(),
    )?;

    if report.findings().is_empty() {
        writeln!(stdout, "No policy findings detected.").map_err(CommandError::Io)?;
    }

    Ok(())
}

fn render_assess_allowed_exceptions(
    stdout: &mut dyn Write,
    allowed_surfaces: &[ReviewedExecutionSurfaceAllowance],
    allowed_age_exceptions: &[ReviewedReleaseAgeException],
) -> Result<(), CommandError> {
    if allowed_surfaces.is_empty() && allowed_age_exceptions.is_empty() {
        return Ok(());
    }

    // Both allowance types embed a policy-owner-controlled reviewed-targets.toml
    // family name in their Display; route through the shared escaping helper
    // rather than interpolating them directly, matching how pin check and
    // audit render the same reviewed-family data.
    let exceptions = allowed_surfaces
        .iter()
        .map(ToString::to_string)
        .chain(allowed_age_exceptions.iter().map(ToString::to_string));
    render_allowed_policy_exceptions(stdout, exceptions)?;
    writeln!(stdout).map_err(CommandError::Io)
}

fn render_assessment_line<T: Display>(
    stdout: &mut dyn Write,
    label: &str,
    values: &[T],
) -> Result<(), CommandError> {
    if values.is_empty() {
        return Ok(());
    }

    writeln!(stdout, "  - {label}: {}", join_display(values, ", ")).map_err(CommandError::Io)
}

fn rendered_non_crates_io_direct_dependencies(report: &RustAssessmentReport) -> Vec<String> {
    report
        .non_crates_io_direct_dependencies()
        .into_iter()
        .map(|dependency| format!("{dependency} ({})", dependency.source_kind()))
        .collect()
}

fn render_finding_section(
    stdout: &mut dyn Write,
    header: &str,
    report: &RustAssessmentReport,
    severity: RustAssessmentFindingSeverity,
) -> Result<(), CommandError> {
    let findings = report
        .findings()
        .iter()
        .copied()
        .filter(|finding| finding.severity() == severity)
        .collect::<Vec<_>>();

    if findings.is_empty() {
        return Ok(());
    }

    writeln!(stdout, "{header}").map_err(CommandError::Io)?;
    for finding in findings {
        writeln!(stdout, "  - {}", render_finding_summary(report, finding))
            .map_err(CommandError::Io)?;
    }
    writeln!(stdout).map_err(CommandError::Io)
}

fn render_finding_summary(report: &RustAssessmentReport, finding: RustAssessmentFinding) -> String {
    match finding.category() {
        RustAssessmentFindingCategory::NewDirectDependencies => format!(
            "new direct Rust dependencies added: {}",
            join_display(&report.new_direct_dependencies(), ", ")
        ),
        RustAssessmentFindingCategory::NonCratesIoDirectDependencies => format!(
            "new non-crates.io direct Rust dependency specs detected: {}",
            join_display(&rendered_non_crates_io_direct_dependencies(report), ", ")
        ),
        RustAssessmentFindingCategory::AgeViolations => format!(
            "newly selected crates.io versions below the minimum age: {}",
            join_display(&report.age_violations(), ", ")
        ),
        RustAssessmentFindingCategory::YankedVersions => format!(
            "newly selected yanked crate versions: {}",
            join_display(&report.yanked_versions(), ", ")
        ),
        RustAssessmentFindingCategory::ReleaseAgeExceptionArtefactMismatches => format!(
            "reviewed release-age exception artefact checksums did not match crates.io: {}",
            join_display(&report.release_age_exception_mismatches(), ", ")
        ),
        RustAssessmentFindingCategory::LockedChecksumDrifts => format!(
            "locked crates.io checksums changed for existing selections: {}",
            join_display(&report.locked_checksum_drifts(), ", ")
        ),
        RustAssessmentFindingCategory::NonCratesIoSourceChanges => format!(
            "non-crates.io source changes detected: {}",
            join_display(&report.non_crates_io_source_changes(), ", ")
        ),
        RustAssessmentFindingCategory::NativeSysCrates => format!(
            "new native -sys crates introduced: {}",
            join_display(&report.native_sys_crates(), ", ")
        ),
        RustAssessmentFindingCategory::BuildRsSurfaces => format!(
            "new or changed build.rs surface detected: {}",
            join_display(&report.build_rs_surfaces(), ", ")
        ),
        RustAssessmentFindingCategory::ProcMacroSurfaces => format!(
            "new or changed proc-macro surface detected: {}",
            join_display(&report.proc_macro_surfaces(), ", ")
        ),
        RustAssessmentFindingCategory::InspectionFailures => format!(
            "failed to inspect some Rust dependency surfaces: {}",
            join_display(&report.inspection_failures(), "; ")
        ),
    }
}
