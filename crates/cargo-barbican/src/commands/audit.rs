use std::fs;
use std::io;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use barbican::{
    AdvisoryAuditCompletenessFailure, AdvisoryAuditOutcome, AdvisoryDisposition, AdvisoryFinding,
    AdvisoryFindingId, CargoDenyNoAdvisoryDiagnostic, LockfileAdvisoryScanner, OffsetDateTime,
    ReviewRecordFact, ReviewedAdvisoryException, ReviewedTargets, RustReviewedTargetsReport,
    UnmanagedDelegatedPolicyMode, check_reviewed_rust_targets, evaluate_advisory_audit,
    generate_cargo_deny_runtime_config, parse_cargo_audit_json, parse_cargo_deny_json_lines,
};

use crate::command_runner::CommandRunner;

use super::scratch_dir::ScratchDir;
use super::{
    CommandError, NativeDelegatedIgnore, check_review_record_paths, escape_diagnostic_for_terminal,
    escape_render_field, fail, load_config, load_current_lockfile,
    load_current_manifest_direct_requirements, load_native_delegated_ignores,
    load_reviewed_targets, read_optional_text_no_symlink, render_allowed_policy_exceptions,
};

pub(super) fn run_audit<R>(
    current_dir: &Path,
    runner: &R,
    now: OffsetDateTime,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<ExitCode, CommandError>
where
    R: CommandRunner + ?Sized,
{
    let config = load_config(current_dir)?;
    let reviewed_targets = load_reviewed_targets(current_dir, Path::new("reviewed-targets.toml"))?;
    let (pin_report, review_record_checks) =
        load_review_evidence(current_dir, reviewed_targets.as_ref())?;
    let bound_exceptions = bound_advisory_exceptions(&pin_report, &review_record_checks);

    let user_deny_toml = read_optional_text_no_symlink(current_dir, Path::new("deny.toml"))
        .map_err(CommandError::Io)?;
    let native_ignores = load_native_delegated_ignores(current_dir)?;
    let scratch = ScratchDir::create("cargo-barbican-audit", false).map_err(CommandError::Io)?;
    let generated_config = generate_cargo_deny_runtime_config(
        user_deny_toml.as_deref(),
        &config.delegates.cargo_deny.checks,
    )
    .map_err(|error| CommandError::Io(io::Error::other(error)))?;
    let generated_config_path = scratch.path().join("deny.toml");
    fs::write(&generated_config_path, generated_config).map_err(CommandError::Io)?;

    let cargo_deny_report = match runner.cargo_deny_json(
        current_dir,
        &generated_config_path,
        &config.delegates.cargo_deny.checks,
    ) {
        Ok(output) => match parse_cargo_deny_json_lines(&output.stderr) {
            Ok(report) => report,
            Err(error) => {
                return fail(
                    stderr,
                    format!(
                        "cargo deny structured output: {}",
                        escape_diagnostic_for_terminal(&error.to_string())
                    ),
                );
            }
        },
        Err(error) => return fail(stderr, format!("cargo deny -f json: {error}")),
    };

    let cargo_audit_report = if matches!(
        config.delegates.advisories.lockfile_scanner,
        LockfileAdvisoryScanner::CargoAudit | LockfileAdvisoryScanner::Both
    ) {
        let lockfile_path = current_dir.join("Cargo.lock");
        match runner.cargo_audit_json(scratch.path(), &lockfile_path) {
            Ok(output) => match parse_cargo_audit_json(&output.stdout) {
                Ok(report) => Some(report),
                Err(error) => {
                    return fail(
                        stderr,
                        format!(
                            "cargo audit structured output: {}",
                            escape_diagnostic_for_terminal(&error.to_string())
                        ),
                    );
                }
            },
            Err(error) => return fail(stderr, format!("cargo audit --json: {error}")),
        }
    } else {
        None
    };

    let outcome = evaluate_advisory_audit(
        config.delegates.advisories.lockfile_scanner,
        &config.delegates.cargo_deny.checks,
        Some(&cargo_deny_report),
        cargo_audit_report.as_ref(),
        &bound_exceptions,
        now,
    );
    let native_ignores_fail = !native_ignores.is_empty()
        && matches!(
            config.delegates.unmanaged_delegated_policy,
            UnmanagedDelegatedPolicyMode::Deny
        );
    let passed = outcome.is_success() && !native_ignores_fail;

    render_audit_report(
        stdout,
        passed,
        &outcome,
        &native_ignores,
        config.delegates.unmanaged_delegated_policy,
    )?;

    Ok(if passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

fn load_review_evidence(
    current_dir: &Path,
    reviewed_targets: Option<&ReviewedTargets>,
) -> Result<(Option<RustReviewedTargetsReport>, Vec<ReviewRecordFact>), CommandError> {
    let Some(reviewed_targets) = reviewed_targets else {
        return Ok((None, Vec::new()));
    };

    let manifest_requirements = load_current_manifest_direct_requirements(current_dir)?;
    let lockfile = load_current_lockfile(current_dir, Path::new("Cargo.lock"))?;
    let pin_report =
        check_reviewed_rust_targets(reviewed_targets, &manifest_requirements, &lockfile);
    let review_record_checks = check_review_record_paths(current_dir, reviewed_targets);

    Ok((Some(pin_report), review_record_checks))
}

fn bound_advisory_exceptions<'a>(
    pin_report: &'a Option<RustReviewedTargetsReport>,
    review_record_checks: &[ReviewRecordFact],
) -> Vec<&'a ReviewedAdvisoryException> {
    let Some(pin_report) = pin_report else {
        return Vec::new();
    };

    pin_report.advisory_exceptions_bound_to_reviewed_records(review_record_checks)
}

fn render_audit_report(
    stdout: &mut dyn Write,
    passed: bool,
    outcome: &AdvisoryAuditOutcome,
    native_ignores: &[NativeDelegatedIgnore],
    unmanaged_policy: UnmanagedDelegatedPolicyMode,
) -> Result<(), CommandError> {
    writeln!(stdout, "Audit: {}", if passed { "PASS" } else { "FAIL" })
        .map_err(CommandError::Io)?;

    render_allowed_policy_exceptions(stdout, outcome.accepted_exceptions())?;
    render_native_ignores(stdout, native_ignores, unmanaged_policy)?;

    for disposition in outcome.reconciliation().dispositions() {
        match disposition {
            AdvisoryDisposition::Accepted { .. } => {}
            AdvisoryDisposition::Expired { finding, exception } => {
                writeln!(
                    stdout,
                    "FAIL {}: reviewed advisory exception expired for reviewed family {} ({}), review by {}",
                    render_finding(finding),
                    escape_render_field(exception.family()),
                    escape_render_field(exception.review_record()),
                    exception.review_by(),
                )
                .map_err(CommandError::Io)?;
            }
            AdvisoryDisposition::Unreviewed { finding } => {
                writeln!(
                    stdout,
                    "FAIL {}: unreviewed advisory finding",
                    render_finding(finding)
                )
                .map_err(CommandError::Io)?;
            }
        }
    }
    for failure in outcome.completeness_failures() {
        writeln!(
            stdout,
            "FAIL advisory scan incomplete: {}",
            render_completeness_failure(failure)
        )
        .map_err(CommandError::Io)?;
    }
    for diagnostic in outcome.cargo_deny_no_advisory_errors() {
        writeln!(
            stdout,
            "FAIL cargo-deny diagnostic without advisory id: {}",
            render_no_advisory_diagnostic(diagnostic)
        )
        .map_err(CommandError::Io)?;
    }
    for count in outcome.cargo_deny_non_advisory_errors() {
        writeln!(
            stdout,
            "FAIL cargo-deny {} check reported {} error(s)",
            escape_render_field(count.check()),
            count.errors()
        )
        .map_err(CommandError::Io)?;
    }
    for ignored in outcome.cargo_audit_settings_ignore() {
        writeln!(
            stdout,
            "FAIL cargo-audit runtime settings.ignore still contains {}",
            escape_render_field(ignored)
        )
        .map_err(CommandError::Io)?;
    }
    if outcome.cargo_audit_idless_warnings() > 0 {
        writeln!(
            stdout,
            "FAIL cargo-audit reported {} warning(s) without advisory ids",
            outcome.cargo_audit_idless_warnings()
        )
        .map_err(CommandError::Io)?;
    }

    Ok(())
}

fn render_native_ignores(
    stdout: &mut dyn Write,
    native_ignores: &[NativeDelegatedIgnore],
    unmanaged_policy: UnmanagedDelegatedPolicyMode,
) -> Result<(), CommandError> {
    if native_ignores.is_empty() {
        return Ok(());
    }

    let prefix = match unmanaged_policy {
        UnmanagedDelegatedPolicyMode::Warn => "WARN",
        UnmanagedDelegatedPolicyMode::Deny => "FAIL",
        UnmanagedDelegatedPolicyMode::Allow => "ALLOW",
    };
    writeln!(stdout, "Native delegated advisory ignores:").map_err(CommandError::Io)?;
    for entry in native_ignores {
        writeln!(
            stdout,
            "  - {prefix} {} ignores {}",
            entry.source(),
            entry
                .advisory_ids()
                .iter()
                .map(|id| escape_render_field(id))
                .collect::<Vec<_>>()
                .join(", ")
        )
        .map_err(CommandError::Io)?;
    }

    Ok(())
}

fn render_finding(finding: &AdvisoryFinding) -> String {
    format!(
        "{} {}",
        render_finding_id(finding.advisory_id()),
        finding.package()
    )
}

fn render_finding_id(id: &AdvisoryFindingId) -> String {
    match id {
        AdvisoryFindingId::RustSec(_) => id.to_string(),
        AdvisoryFindingId::Unnormalised(raw) => escape_render_field(raw),
    }
}

fn render_completeness_failure(failure: &AdvisoryAuditCompletenessFailure) -> String {
    match failure {
        AdvisoryAuditCompletenessFailure::MissingCargoDenyReport => {
            "missing cargo-deny structured report".to_owned()
        }
        AdvisoryAuditCompletenessFailure::MissingCargoAuditReport => {
            "missing cargo-audit structured report".to_owned()
        }
        AdvisoryAuditCompletenessFailure::MissingCargoDenySummaryCheck { check } => {
            format!("cargo-deny summary missing {} check", check.as_str())
        }
        AdvisoryAuditCompletenessFailure::CargoDenyAdvisoryErrorsUnenumerated => {
            "cargo-deny advisories summary reported errors but no advisory findings were enumerated"
                .to_owned()
        }
    }
}

fn render_no_advisory_diagnostic(diagnostic: &CargoDenyNoAdvisoryDiagnostic) -> String {
    format!(
        "line {}, severity {}, code {}",
        diagnostic.line(),
        diagnostic
            .severity()
            .map(escape_render_field)
            .unwrap_or_else(|| "(missing)".to_owned()),
        diagnostic
            .code()
            .map(escape_render_field)
            .unwrap_or_else(|| "(missing)".to_owned())
    )
}
