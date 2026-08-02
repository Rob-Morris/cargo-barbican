use std::fmt::Display;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use barbican::{
    CratesIoClient, OffsetDateTime, ReleaseAgeGateVerdict, RustAssessmentClassification,
    RustInspectReport, classify_release_age_gate, evaluate_release_age, inspect_published_crate_at,
};

use super::{
    CommandError, escape_render_field, exit_code_from_policy_failures, join_display,
    load_release_age_context, parse_specs, release_age_override_note,
    render_incomplete_release_age_exception_review_record, render_release_age_report,
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
    let (minimum_days, reviewed_release_age_exceptions) =
        load_release_age_context(current_dir, min_age_days)?;
    if let Some(note) = release_age_override_note(current_dir, min_age_days)? {
        writeln!(stdout, "{note}").map_err(CommandError::Io)?;
    }
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
        if let ReleaseAgeGateVerdict::IncompleteReviewRecord(exception) = classify_release_age_gate(
            release_age.outcome(),
            reviewed_release_age_exceptions.unsatisfied_for_spec(&spec),
        ) {
            writeln!(
                stderr,
                "FAIL {}",
                render_incomplete_release_age_exception_review_record(exception)
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
        let rendered = render_inspect_report(&report, InspectRenderContext::Inspect);

        write!(stdout, "{rendered}").map_err(CommandError::Io)?;
        if !matches!(
            report.classification(),
            RustAssessmentClassification::RoutineSafe
        ) {
            failed = true;
        }
    }

    Ok(exit_code_from_policy_failures(failed))
}

/// Where a rendered inspect report is being shown.
///
/// `inspect` and `gatehouse candidate` share the same report body, but the
/// pointer to `gatehouse candidate` for a fuller dossier is only useful from
/// `inspect`: inside the dossier it would tell the reviewer to re-run the exact
/// command they already ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum InspectRenderContext {
    Inspect,
    GatehouseCandidate,
}

pub(super) fn render_inspect_report(
    report: &RustInspectReport,
    context: InspectRenderContext,
) -> String {
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
        // `vcs_info` (git_sha1 / path_in_vcs) is parsed from the published
        // tarball's `.cargo_vcs_info.json` — network-sourced and untrusted —
        // so it is escaped before rendering, matching every other untrusted
        // field in this report.
        Some(vcs_info) => rendered.push_str(&format!(
            "  provenance: {}\n",
            escape_render_field(&vcs_info.to_string())
        )),
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
        "  inspection failures: {}\n",
        render_slice(report.inspection_failures())
    ));

    rendered.push_str(&render_policy_violation_explanation(report, context));
    rendered.push('\n');

    rendered
}

/// Explains a `policy-violating` verdict and, where an execution surface is in
/// play, the reviewed-family path forward.
///
/// Returns an empty string for non-`policy-violating` reports so the routine
/// and elevated evidence bodies are unchanged. The block never downgrades or
/// bypasses the fail-closed verdict: recording an `allowed_surfaces` allowance
/// does not change what `inspect` reports (it never consults allowances); it
/// lets the repo intake gate admit the reviewed surface.
fn render_policy_violation_explanation(
    report: &RustInspectReport,
    context: InspectRenderContext,
) -> String {
    if !matches!(
        report.classification(),
        RustAssessmentClassification::PolicyViolating
    ) {
        return String::new();
    }

    let mut drivers = Vec::new();
    if !report.release_age().is_success() {
        drivers.push("the release-age gate above");
    }
    if !report.checksum_matches() {
        drivers.push("the checksum mismatch above");
    }
    if !report.ioc_hits().is_empty() {
        drivers.push("the IOC hits above");
    }
    if !report.inspection_failures().is_empty() {
        drivers.push("the inspection failures above");
    }

    let mut block = String::new();
    block.push_str(&format!(
        "  verdict basis: policy-violating is driven by {}.\n",
        join_conjunction(&drivers)
    ));

    // The reviewed-family path only helps when the driver is an execution
    // surface the reviewer can bless, i.e. an IOC hit (which is always found on
    // a build script, proc-macro, or native source). A too-fresh, yanked,
    // checksum-mismatched, or inspection-failed verdict is not something
    // `allowed_surfaces` can address, so pointing there would mislead.
    if !report.ioc_hits().is_empty() {
        block.push_str(
            "  remediation: review the flagged execution surface in the crate source; \
             if it is acceptable, record the crate in a reviewed family with an \
             allowed_surfaces allowance so the repo intake gate (assess, pin check, verify) \
             admits the surface. This does not change what inspect reports.\n",
        );
        block.push_str(&format!(
            "  reviewed-family path: once {} is resolved in Cargo.lock, `cargo barbican pin add {}` \
             scaffolds the reviewed family and review record; see docs/user/configuration.md for the \
             allowed_surfaces mechanism.\n",
            report.spec().crate_name(),
            report.spec().crate_name()
        ));
        if matches!(context, InspectRenderContext::Inspect) {
            block.push_str(&format!(
                "  fuller dossier: `cargo barbican gatehouse candidate {}` assembles sandboxed \
                 cargo tree and audit evidence alongside this inspection.\n",
                report.spec()
            ));
        }
    }

    block
}

fn join_conjunction(parts: &[&str]) -> String {
    match parts {
        [] => "the findings above".to_owned(),
        [only] => (*only).to_owned(),
        [head @ .., last] => format!("{} and {last}", head.join(", ")),
    }
}

fn render_native_ffi_surface(report: &RustInspectReport) -> String {
    let mut parts = Vec::new();

    if report.native_sys_crate() {
        parts.push("crate name ends with -sys".to_owned());
    }
    if let Some(links) = report.package_links() {
        // `package.links` is parsed from the published `Cargo.toml` —
        // untrusted, unrestricted TOML string content — so it is escaped
        // before rendering.
        parts.push(format!("package.links={}", escape_render_field(links)));
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
