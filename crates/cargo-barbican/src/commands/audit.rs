use std::collections::BTreeMap;
use std::fmt::Write as FmtWrite;
use std::fs;
use std::io;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use barbican::{
    AdvisoryAuditCompletenessFailure, AdvisoryAuditOutcome, AdvisoryDisposition, AdvisoryFinding,
    AdvisoryFindingId, CargoDenyNoAdvisoryDiagnostic, ExactCrateSpec, LockfileAdvisoryScanner,
    MetadataDependencyPath, OffsetDateTime, ReviewRecordFact, ReviewedAdvisoryException,
    ReviewedTargets, RustReviewedTargetsReport, UnmanagedDelegatedPolicyMode,
    check_reviewed_rust_targets, evaluate_advisory_audit, generate_cargo_deny_runtime_config,
    parse_cargo_audit_json, parse_cargo_deny_json_lines, parse_cargo_metadata,
    shortest_workspace_dependency_path,
};
use serde_json::json;

use crate::cli::AuditOutputFormat;
use crate::command_runner::CommandRunner;

use super::scratch_dir::ScratchDir;
use super::{
    CommandError, NativeDelegatedIgnore, check_review_record_paths, escape_diagnostic_for_terminal,
    escape_render_field, fail, load_config, load_current_lockfile,
    load_current_manifest_direct_requirements, load_native_delegated_ignores,
    load_reviewed_targets, read_optional_text_no_symlink, render_allowed_policy_exceptions,
};

pub(super) fn run_audit<R>(
    output_format: AuditOutputFormat,
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
    let dependency_paths = collect_dependency_paths(current_dir, runner, &outcome, output_format);

    match output_format {
        AuditOutputFormat::Text => {
            if let Some(reason) = dependency_paths.unavailable_reason() {
                writeln!(
                    stderr,
                    "note: dependency path context unavailable: {}",
                    escape_diagnostic_for_terminal(reason)
                )
                .map_err(CommandError::Io)?;
            }
            render_audit_report(
                stdout,
                passed,
                &outcome,
                &dependency_paths,
                &native_ignores,
                config.delegates.unmanaged_delegated_policy,
            )?;
        }
        AuditOutputFormat::Json => render_audit_json_report(
            stdout,
            passed,
            &outcome,
            &dependency_paths,
            &native_ignores,
            config.delegates.unmanaged_delegated_policy,
        )?,
    }

    Ok(if passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

fn collect_dependency_paths<R>(
    current_dir: &Path,
    runner: &R,
    outcome: &AdvisoryAuditOutcome,
    output_format: AuditOutputFormat,
) -> DependencyPathReport
where
    R: CommandRunner + ?Sized,
{
    let mut targets = Vec::new();
    for disposition in outcome.reconciliation().dispositions() {
        if matches!(output_format, AuditOutputFormat::Text)
            && matches!(disposition, AdvisoryDisposition::Accepted { .. })
        {
            continue;
        }
        let package = disposition.finding().package();
        if !targets.contains(package) {
            targets.push(package.clone());
        }
    }
    if targets.is_empty() {
        return DependencyPathReport::available(BTreeMap::new());
    }

    let metadata_text = match runner.cargo_metadata_frozen(current_dir) {
        Ok(text) => text,
        Err(error) => {
            return DependencyPathReport::unavailable(format!("cargo metadata --frozen: {error}"));
        }
    };
    let metadata = match parse_cargo_metadata(&metadata_text) {
        Ok(metadata) => metadata,
        Err(error) => {
            return DependencyPathReport::unavailable(format!(
                "cargo metadata --frozen output: {error}"
            ));
        }
    };

    let mut paths = BTreeMap::new();
    for target in targets {
        match shortest_workspace_dependency_path(&metadata, &target) {
            Ok(Some(path)) => {
                paths.insert(target, path);
            }
            Ok(None) => {}
            Err(error) => return DependencyPathReport::unavailable(format!("{target}: {error}")),
        }
    }

    DependencyPathReport::available(paths)
}

struct DependencyPathReport {
    paths: BTreeMap<ExactCrateSpec, MetadataDependencyPath>,
    available: bool,
    unavailable_reason: Option<String>,
}

impl DependencyPathReport {
    fn available(paths: BTreeMap<ExactCrateSpec, MetadataDependencyPath>) -> Self {
        Self {
            paths,
            available: true,
            unavailable_reason: None,
        }
    }

    fn unavailable(reason: String) -> Self {
        Self {
            paths: BTreeMap::new(),
            available: false,
            unavailable_reason: Some(reason),
        }
    }

    fn unavailable_reason(&self) -> Option<&str> {
        self.unavailable_reason.as_deref()
    }
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
    dependency_paths: &DependencyPathReport,
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
                    "{}",
                    render_finding_failure(
                        finding,
                        &format!(
                            "reviewed advisory exception expired for reviewed family {} ({}), review by {}",
                            escape_render_field(exception.family()),
                            escape_render_field(exception.review_record()),
                            exception.review_by(),
                        ),
                    ),
                )
                .map_err(CommandError::Io)?;
                render_dependency_path(stdout, finding, dependency_paths)?;
            }
            AdvisoryDisposition::Unreviewed { finding } => {
                writeln!(
                    stdout,
                    "{}",
                    render_finding_failure(finding, "unreviewed advisory finding")
                )
                .map_err(CommandError::Io)?;
                render_dependency_path(stdout, finding, dependency_paths)?;
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

fn render_audit_json_report(
    stdout: &mut dyn Write,
    passed: bool,
    outcome: &AdvisoryAuditOutcome,
    dependency_paths: &DependencyPathReport,
    native_ignores: &[NativeDelegatedIgnore],
    unmanaged_policy: UnmanagedDelegatedPolicyMode,
) -> Result<(), CommandError> {
    let findings = outcome
        .reconciliation()
        .dispositions()
        .iter()
        .map(|disposition| finding_json(disposition, dependency_paths))
        .collect::<Vec<_>>();
    let report = json!({
        "schema_version": 1,
        "status": if passed { "pass" } else { "fail" },
        "success": passed,
        "dependency_paths_available": dependency_paths.available,
        "findings": findings,
        "completeness_failures": outcome
            .completeness_failures()
            .iter()
            .map(render_completeness_failure)
            .collect::<Vec<_>>(),
        "cargo_deny": {
            "no_advisory_errors": outcome
                .cargo_deny_no_advisory_errors()
                .iter()
                .map(no_advisory_diagnostic_json)
                .collect::<Vec<_>>(),
            "non_advisory_errors": outcome
                .cargo_deny_non_advisory_errors()
                .iter()
                .map(|count| json!({
                    "check": count.check(),
                    "errors": count.errors(),
                }))
                .collect::<Vec<_>>(),
        },
        "cargo_audit": {
            "settings_ignore": outcome.cargo_audit_settings_ignore(),
            "idless_warnings": outcome.cargo_audit_idless_warnings(),
        },
        "native_delegated_ignores": native_ignores
            .iter()
            .map(|entry| json!({
                "source": entry.source(),
                "advisory_ids": entry.advisory_ids(),
                "policy": unmanaged_policy_json(unmanaged_policy),
            }))
            .collect::<Vec<_>>(),
    });

    serde_json::to_writer_pretty(&mut *stdout, &report)
        .map_err(|error| CommandError::Io(io::Error::other(error)))?;
    writeln!(stdout).map_err(CommandError::Io)
}

fn finding_json(
    disposition: &AdvisoryDisposition,
    dependency_paths: &DependencyPathReport,
) -> serde_json::Value {
    let finding = disposition.finding();
    let details = finding.details();
    json!({
        "advisory_id": finding.advisory_id().to_string(),
        "package": {
            "spec": finding.package().to_string(),
            "name": finding.package().crate_name(),
            "version": finding.package().version(),
        },
        "disposition": disposition_json(disposition),
        "title": details.title(),
        "risk": details.risk_label(),
        "severity": details.severity(),
        "cvss": details.cvss(),
        "informational": details.informational(),
        "patched": details.patched_versions(),
        "dependency_path": dependency_paths
            .paths
            .get(finding.package())
            .map(|path| {
                path.packages()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            }),
        "exception": exception_json(disposition),
    })
}

fn disposition_json(disposition: &AdvisoryDisposition) -> &'static str {
    match disposition {
        AdvisoryDisposition::Accepted { .. } => "accepted",
        AdvisoryDisposition::Expired { .. } => "expired",
        AdvisoryDisposition::Unreviewed { .. } => "unreviewed",
    }
}

fn exception_json(disposition: &AdvisoryDisposition) -> Option<serde_json::Value> {
    match disposition {
        AdvisoryDisposition::Accepted { exception, .. }
        | AdvisoryDisposition::Expired { exception, .. } => Some(json!({
            "family": exception.family(),
            "review_record": exception.review_record(),
            "review_by": exception.review_by().to_string(),
        })),
        AdvisoryDisposition::Unreviewed { .. } => None,
    }
}

fn no_advisory_diagnostic_json(diagnostic: &CargoDenyNoAdvisoryDiagnostic) -> serde_json::Value {
    json!({
        "line": diagnostic.line(),
        "severity": diagnostic.severity(),
        "code": diagnostic.code(),
    })
}

fn unmanaged_policy_json(policy: UnmanagedDelegatedPolicyMode) -> &'static str {
    match policy {
        UnmanagedDelegatedPolicyMode::Warn => "warn",
        UnmanagedDelegatedPolicyMode::Deny => "deny",
        UnmanagedDelegatedPolicyMode::Allow => "allow",
    }
}

fn render_finding_failure(finding: &AdvisoryFinding, reason: &str) -> String {
    let mut rendered = format!("FAIL {}", render_finding(finding));
    if let Some(risk) = finding.details().risk_label() {
        write!(&mut rendered, " ({})", escape_render_field(risk))
            .expect("writing to a String cannot fail");
    }
    write!(&mut rendered, ": {reason}").expect("writing to a String cannot fail");
    if let Some(title) = finding.details().title() {
        write!(&mut rendered, "; title: {}", escape_render_field(title))
            .expect("writing to a String cannot fail");
    }
    if !finding.details().patched_versions().is_empty() {
        write!(
            &mut rendered,
            "; fixed in {}",
            finding
                .details()
                .patched_versions()
                .iter()
                .map(|version| escape_render_field(version))
                .collect::<Vec<_>>()
                .join(", ")
        )
        .expect("writing to a String cannot fail");
    }
    rendered
}

fn render_dependency_path(
    stdout: &mut dyn Write,
    finding: &AdvisoryFinding,
    dependency_paths: &DependencyPathReport,
) -> Result<(), CommandError> {
    let Some(path) = dependency_paths.paths.get(finding.package()) else {
        return Ok(());
    };
    writeln!(
        stdout,
        "  dependency path: {}",
        path.packages()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" -> ")
    )
    .map_err(CommandError::Io)
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
