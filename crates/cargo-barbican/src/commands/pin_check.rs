use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use barbican::{
    ObservedDirectDependency, PatchedReviewedCrate, REVIEW_RECORD_SCAFFOLD_MARKER,
    ReviewRecordFact, ReviewRecordStatus, ReviewedResolvedTarget, ReviewedTargets,
    RustReviewedTargetsReport, check_reviewed_rust_targets, patched_reviewed_crates,
};

use crate::command_runner::{CommandRunner, cargo_home_from_environment};

use super::{
    CommandError, check_review_record_paths, escape_render_field, load_current_lockfile,
    load_current_manifest_direct_requirements, load_effective_cargo_configs,
    load_manifest_patched_crate_names, load_reviewed_targets, render_allowed_policy_exceptions,
    source_replacement_finding,
};

pub(super) fn run_pin_check<R>(
    config_path: &Path,
    current_dir: &Path,
    runner: &R,
    stdout: &mut dyn Write,
) -> Result<ExitCode, CommandError>
where
    R: CommandRunner + ?Sized,
{
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

    let Some(cargo_home) = cargo_home_from_environment(|name| runner.environment_variable(name))
    else {
        return Err(CommandError::CargoHomeUnresolved);
    };
    let cargo_configs = load_effective_cargo_configs(current_dir, &cargo_home)?;

    enforce_reviewed_targets(
        &reviewed_targets,
        config_path,
        current_dir,
        &cargo_configs,
        stdout,
    )
}

pub(super) fn enforce_reviewed_targets(
    reviewed_targets: &ReviewedTargets,
    config_path: &Path,
    current_dir: &Path,
    cargo_configs: &[super::loaders::EffectiveCargoConfig],
    stdout: &mut dyn Write,
) -> Result<ExitCode, CommandError> {
    let manifest_requirements = load_current_manifest_direct_requirements(current_dir)?;
    let review_record_checks = check_review_record_paths(current_dir, reviewed_targets);
    let lockfile = load_current_lockfile(current_dir, Path::new("Cargo.lock"))?;
    let patched_crate_names = load_manifest_patched_crate_names(current_dir)?;
    let patched_reviewed = patched_reviewed_crates(reviewed_targets, &patched_crate_names);
    let source_replacement = source_replacement_finding(cargo_configs)?;

    let report = check_reviewed_rust_targets(reviewed_targets, &manifest_requirements, &lockfile);

    render_pin_check_report(
        stdout,
        &report,
        &review_record_checks,
        &patched_reviewed,
        source_replacement.as_deref(),
        &config_path.display().to_string(),
    )?;

    Ok(
        if report.is_success()
            && review_record_checks
                .iter()
                .all(ReviewRecordFact::is_satisfied)
            && patched_reviewed.is_empty()
            && source_replacement.is_none()
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
    review_record_checks: &[ReviewRecordFact],
    patched_reviewed: &[PatchedReviewedCrate],
    source_replacement: Option<&str>,
    manifest_path: &str,
) -> Result<(), CommandError> {
    if report.is_success()
        && review_record_checks
            .iter()
            .all(ReviewRecordFact::is_satisfied)
        && patched_reviewed.is_empty()
        && source_replacement.is_none()
    {
        writeln!(stdout, "Pin check: PASS").map_err(CommandError::Io)?;
    } else {
        writeln!(stdout, "Pin check: FAIL").map_err(CommandError::Io)?;
    }
    writeln!(stdout, "  manifest: {manifest_path}").map_err(CommandError::Io)?;

    if let Some(source_replacement) = source_replacement {
        writeln!(
            stdout,
            "  - source replacement detected: {}",
            escape_render_field(source_replacement)
        )
        .map_err(CommandError::Io)?;
    }

    for patched in patched_reviewed {
        writeln!(
            stdout,
            "  - {}: [patch] targets reviewed crate {}, which bypasses review",
            escape_render_field(patched.family()),
            escape_render_field(patched.crate_name())
        )
        .map_err(CommandError::Io)?;
    }
    let review_record_check_for = |name: &str| {
        review_record_checks
            .iter()
            .find(|check| check.family_name() == name)
    };

    for family in report.families() {
        let family_name = escape_render_field(family.name());
        writeln!(
            stdout,
            "  family: {} ({})",
            family_name,
            escape_render_field(family.review_record())
        )
        .map_err(CommandError::Io)?;

        if let Some(review_record_check) = review_record_check_for(family.name()) {
            let record_path = escape_render_field(review_record_check.review_record());
            match review_record_check.status() {
                ReviewRecordStatus::Completed => {
                    writeln!(
                        stdout,
                        "  - {family_name}: review record ok at {record_path}"
                    )
                    .map_err(CommandError::Io)?;
                }
                ReviewRecordStatus::Missing => {
                    writeln!(
                        stdout,
                        "  - {family_name}: review record missing at {record_path}"
                    )
                    .map_err(CommandError::Io)?;
                }
                ReviewRecordStatus::Empty => {
                    writeln!(
                        stdout,
                        "  - {family_name}: review record at {record_path} is empty; complete the review before this family is trusted"
                    )
                    .map_err(CommandError::Io)?;
                }
                ReviewRecordStatus::ScaffoldPlaceholder => {
                    writeln!(
                        stdout,
                        "  - {family_name}: review record at {record_path} is an unreviewed scaffold (still carries the {REVIEW_RECORD_SCAFFOLD_MARKER} marker); complete the review and delete that line"
                    )
                    .map_err(CommandError::Io)?;
                }
            }
        }

        for check in family.direct_checks() {
            let crate_name = escape_render_field(check.crate_name());
            if check.is_success() {
                writeln!(
                    stdout,
                    "  - {}: direct spec ok for {}{}",
                    family_name,
                    crate_name,
                    escape_render_field(check.expected_requirement())
                )
                .map_err(CommandError::Io)?;
            } else {
                writeln!(
                    stdout,
                    "  - {}: direct spec mismatch for {}: expected {:?}, found {}",
                    family_name,
                    crate_name,
                    escape_render_field(check.expected_requirement()),
                    render_observed_direct_dependencies(check.observed())
                )
                .map_err(CommandError::Io)?;
            }
        }

        for check in family.resolved_checks() {
            let crate_name = escape_render_field(check.crate_name());
            if check.is_success() {
                writeln!(
                    stdout,
                    "  - {}: Cargo.lock ok for {}: matched {}",
                    family_name,
                    crate_name,
                    render_resolved_target(check.expected_target())
                )
                .map_err(CommandError::Io)?;
            } else {
                writeln!(
                    stdout,
                    "  - {}: Cargo.lock mismatch for {}: expected {}, found versions {}, checksums {}{}{}",
                    family_name,
                    crate_name,
                    render_resolved_target(check.expected_target()),
                    render_values(check.actual_versions().iter()),
                    render_values(check.actual_checksums_sha256().iter()),
                    render_non_crates_io_sources_suffix(check.non_crates_io_sources()),
                    if check.expected_target().checksum_sha256().is_some()
                        && check.has_checksumless_entry()
                    {
                        ", checksum-less entry present"
                    } else {
                        ""
                    }
                )
                .map_err(CommandError::Io)?;
            }
        }
    }

    let advisory_exceptions =
        report.advisory_exceptions_bound_to_reviewed_records(review_record_checks);
    render_allowed_policy_exceptions(stdout, advisory_exceptions)?;

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
    let version = escape_render_field(target.version());
    match target.checksum_sha256() {
        Some(checksum) => {
            format!("{{version={version}, checksum_sha256={checksum}}}")
        }
        None => format!("{{version={version}}}"),
    }
}

fn render_values<'a, T>(values: impl Iterator<Item = &'a T>) -> String
where
    T: std::fmt::Display + 'a,
{
    format!(
        "[{}]",
        values
            .map(|value| format!("\"{}\"", escape_render_field(&value.to_string())))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn render_non_crates_io_sources_suffix(sources: &std::collections::BTreeSet<String>) -> String {
    if sources.is_empty() {
        return String::new();
    }

    let escaped = sources
        .iter()
        .map(|source| escape_render_field(source))
        .collect::<Vec<_>>();

    format!(", non-crates.io sources {}", render_values(escaped.iter()))
}

fn render_observed_direct_dependency(entry: &ObservedDirectDependency) -> String {
    let requirement = entry.version_requirement().unwrap_or("(no version)");

    format!(
        "{}:{}:{} ({})",
        escape_render_field(entry.manifest_path()),
        escape_render_field(entry.section()),
        escape_render_field(requirement),
        entry.source_kind()
    )
}
