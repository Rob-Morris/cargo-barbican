use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use barbican::{
    ObservedDirectDependency, ReviewedResolvedTarget, RustReviewedTargetsReport,
    check_reviewed_rust_targets,
};

use super::inventory::escape_render_field;
use super::{
    CommandError, ReviewRecordCheck, check_review_record_paths, load_current_lockfile,
    load_current_manifest_direct_requirements, load_reviewed_targets,
};

pub(super) fn run_pin_check(
    config_path: &Path,
    current_dir: &Path,
    stdout: &mut dyn Write,
) -> Result<ExitCode, CommandError> {
    let Some(reviewed_targets) = load_reviewed_targets(current_dir, config_path)? else {
        writeln!(
            stdout,
            "Pin check: no {} present; skipping.",
            config_path.display()
        )
        .map_err(CommandError::Io)?;
        return Ok(ExitCode::SUCCESS);
    };

    if reviewed_targets.rust_families().is_empty() {
        writeln!(
            stdout,
            "Pin check: no active Rust reviewed families configured in {}; skipping.",
            config_path.display()
        )
        .map_err(CommandError::Io)?;
        return Ok(ExitCode::SUCCESS);
    }

    let manifest_requirements = load_current_manifest_direct_requirements(current_dir)?;
    let review_record_checks = check_review_record_paths(current_dir, &reviewed_targets);
    let lockfile = load_current_lockfile(current_dir, Path::new("Cargo.lock"))?;

    let report = check_reviewed_rust_targets(&reviewed_targets, &manifest_requirements, &lockfile);

    render_pin_check_report(
        stdout,
        &report,
        &review_record_checks,
        &config_path.display().to_string(),
    )?;

    Ok(
        if report.is_success()
            && review_record_checks
                .iter()
                .all(ReviewRecordCheck::is_success)
        {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        },
    )
}

fn render_pin_check_report(
    stdout: &mut dyn Write,
    report: &RustReviewedTargetsReport,
    review_record_checks: &[ReviewRecordCheck],
    manifest_path: &str,
) -> Result<(), CommandError> {
    if report.is_success()
        && review_record_checks
            .iter()
            .all(ReviewRecordCheck::is_success)
    {
        writeln!(stdout, "Pin check: PASS").map_err(CommandError::Io)?;
    } else {
        writeln!(stdout, "Pin check: FAIL").map_err(CommandError::Io)?;
    }
    writeln!(stdout, "  manifest: {manifest_path}").map_err(CommandError::Io)?;
    let review_record_check_for = |name: &str| {
        review_record_checks
            .iter()
            .find(|check| check.family_name() == name)
    };

    for family in report.families() {
        writeln!(
            stdout,
            "  family: {} ({})",
            family.name(),
            family.review_record()
        )
        .map_err(CommandError::Io)?;

        if let Some(review_record_check) = review_record_check_for(family.name()) {
            if review_record_check.is_success() {
                writeln!(
                    stdout,
                    "  - {}: review record ok at {}",
                    family.name(),
                    review_record_check.review_record()
                )
                .map_err(CommandError::Io)?;
            } else {
                writeln!(
                    stdout,
                    "  - {}: review record missing at {}",
                    family.name(),
                    review_record_check.review_record()
                )
                .map_err(CommandError::Io)?;
            }
        }

        for check in family.direct_checks() {
            if check.is_success() {
                writeln!(
                    stdout,
                    "  - {}: direct spec ok for {}{}",
                    family.name(),
                    check.crate_name(),
                    check.expected_requirement()
                )
                .map_err(CommandError::Io)?;
            } else {
                writeln!(
                    stdout,
                    "  - {}: direct spec mismatch for {}: expected {:?}, found {}",
                    family.name(),
                    check.crate_name(),
                    check.expected_requirement(),
                    render_observed_direct_dependencies(check.observed())
                )
                .map_err(CommandError::Io)?;
            }
        }

        for check in family.resolved_checks() {
            if check.is_success() {
                writeln!(
                    stdout,
                    "  - {}: Cargo.lock ok for {}: matched {}",
                    family.name(),
                    check.crate_name(),
                    render_resolved_target(check.expected_target())
                )
                .map_err(CommandError::Io)?;
            } else {
                writeln!(
                    stdout,
                    "  - {}: Cargo.lock mismatch for {}: expected {}, found versions {}, checksums {}",
                    family.name(),
                    check.crate_name(),
                    render_resolved_target(check.expected_target()),
                    render_values(check.actual_versions().iter()),
                    render_values(check.actual_checksums_sha256().iter())
                )
                .map_err(CommandError::Io)?;
            }
        }
    }

    let advisory_exceptions = report
        .families()
        .iter()
        .filter(|family| {
            review_record_check_for(family.name()).is_some_and(ReviewRecordCheck::is_success)
        })
        .flat_map(|family| family.advisory_exceptions_with_matching_resolved_target())
        .collect::<Vec<_>>();
    if !advisory_exceptions.is_empty() {
        writeln!(stdout, "Allowed policy exceptions:").map_err(CommandError::Io)?;
        for exception in advisory_exceptions {
            writeln!(
                stdout,
                "  - {}",
                escape_render_field(&exception.to_string())
            )
            .map_err(CommandError::Io)?;
        }
    }

    Ok(())
}

fn render_observed_direct_dependencies(observed: &[ObservedDirectDependency]) -> String {
    if observed.is_empty() {
        return "[]".to_owned();
    }

    format!(
        "{:?}",
        observed
            .iter()
            .map(render_observed_direct_dependency)
            .collect::<Vec<_>>()
    )
}

fn render_resolved_target(target: &ReviewedResolvedTarget) -> String {
    match target.checksum_sha256() {
        Some(checksum) => {
            format!(
                "{{version={}, checksum_sha256={}}}",
                target.version(),
                checksum
            )
        }
        None => format!("{{version={}}}", target.version()),
    }
}

fn render_values<'a, T>(values: impl Iterator<Item = &'a T>) -> String
where
    T: std::fmt::Display + 'a,
{
    format!(
        "[{}]",
        values
            .map(|value| format!("\"{value}\""))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn render_observed_direct_dependency(entry: &ObservedDirectDependency) -> String {
    let requirement = entry.version_requirement().unwrap_or("(no version)");

    format!(
        "{}:{}:{} ({})",
        entry.manifest_path(),
        entry.section(),
        requirement,
        entry.source_kind()
    )
}
