use std::fmt::Display;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use barbican::{
    CratesIoClient, OffsetDateTime, ReleaseAgeOutcome, RustAssessmentClassification,
    RustInspectReport, evaluate_release_age, inspect_published_crate_at,
};

use crate::cli::REVIEWED_TARGETS_CONFIG_FILE;

use super::{
    CommandError, exit_code_from_policy_failures, join_display, load_config,
    load_reviewed_release_age_exceptions, parse_specs,
    render_missing_release_age_exception_review_record, render_release_age_report,
};

pub(super) fn run_inspect<C>(
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
    let minimum_days = min_age_days.unwrap_or(load_config(current_dir)?.release_age.minimum_days);
    let reviewed_release_age_exceptions =
        load_reviewed_release_age_exceptions(current_dir, Path::new(REVIEWED_TARGETS_CONFIG_FILE))?;
    let parse_result = parse_specs(raw_specs, stderr)?;
    let mut failed = parse_result.failed;

    for spec in parse_result.specs {
        let release = match client.fetch_release(&spec) {
            Ok(release) => release,
            Err(error) => {
                writeln!(stderr, "FAIL {spec}: {error}").map_err(CommandError::Io)?;
                failed = true;
                continue;
            }
        };
        let age_exception = reviewed_release_age_exceptions
            .honoured()
            .iter()
            .find(|exception| exception.spec() == &spec);
        let release_age = evaluate_release_age(
            spec.clone(),
            release.clone(),
            now,
            minimum_days,
            age_exception,
        );
        if matches!(release_age.outcome(), ReleaseAgeOutcome::TooFresh)
            && let Some(exception) = reviewed_release_age_exceptions.missing_for_spec(&spec)
        {
            writeln!(
                stderr,
                "{}",
                render_missing_release_age_exception_review_record(exception)
            )
            .map_err(CommandError::Io)?;
            failed = true;
            continue;
        }

        let tarball = match client.fetch_release_tarball(&spec) {
            Ok(tarball) => tarball,
            Err(error) => {
                writeln!(stderr, "FAIL {spec}: {error}").map_err(CommandError::Io)?;
                failed = true;
                continue;
            }
        };
        let report =
            inspect_published_crate_at(spec, release, &tarball, now, minimum_days, age_exception);
        let rendered = render_inspect_report(&report);

        match report.classification() {
            RustAssessmentClassification::RoutineSafe => {
                write!(stdout, "{rendered}").map_err(CommandError::Io)?;
            }
            RustAssessmentClassification::ElevatedRisk
            | RustAssessmentClassification::PolicyViolating => {
                write!(stderr, "{rendered}").map_err(CommandError::Io)?;
                failed = true;
            }
        }
    }

    Ok(exit_code_from_policy_failures(failed))
}

pub(super) fn render_inspect_report(report: &RustInspectReport) -> String {
    let mut rendered = String::new();
    rendered.push_str(&format!("Inspect {}\n", report.spec()));
    rendered.push_str(&format!("  classification: {}\n", report.classification()));
    rendered.push_str(&format!(
        "  release age: {}\n",
        render_release_age_report(report.release_age())
    ));

    if report.checksum_matches() {
        rendered.push_str(&format!(
            "  checksum: ok (sha256 {})\n",
            report.local_checksum_sha256_hex()
        ));
    } else {
        rendered.push_str(&format!(
            "  checksum: FAIL local sha256 {} != crates.io {}\n",
            report.local_checksum_sha256_hex(),
            report.published_checksum_sha256_hex()
        ));
    }

    match report.vcs_info() {
        Some(vcs_info) => rendered.push_str(&format!("  provenance: {vcs_info}\n")),
        None => rendered.push_str("  provenance: .cargo_vcs_info.json not present\n"),
    }

    rendered.push_str(&format!(
        "  build.rs surfaces: {}\n",
        render_slice(report.build_script_paths())
    ));
    rendered.push_str(&format!(
        "  proc-macro surface: {}\n",
        if report.proc_macro() { "yes" } else { "no" }
    ));
    rendered.push_str(&format!(
        "  native FFI surfaces: {}\n",
        render_native_ffi_surface(report)
    ));
    rendered.push_str(&format!(
        "  IOC hits: {}\n",
        render_slice(report.ioc_hits())
    ));
    rendered.push_str(&format!(
        "  inspection failures: {}\n\n",
        render_slice(report.inspection_failures())
    ));

    rendered
}

fn render_native_ffi_surface(report: &RustInspectReport) -> String {
    let mut parts = Vec::new();

    if report.native_sys_crate() {
        parts.push("crate name ends with -sys".to_owned());
    }
    if let Some(links) = report.package_links() {
        parts.push(format!("package.links={links}"));
    }
    if !report.native_source_paths().is_empty() {
        parts.push(format!(
            "native sources: {}",
            join_display(report.native_source_paths(), ", ")
        ));
    }

    if parts.is_empty() {
        "none".to_owned()
    } else {
        parts.join("; ")
    }
}

fn render_slice<T: Display>(values: &[T]) -> String {
    if values.is_empty() {
        "none".to_owned()
    } else {
        join_display(values, ", ")
    }
}
