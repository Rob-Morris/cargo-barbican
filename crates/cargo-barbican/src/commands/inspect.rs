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
    legacy_ioc: Option<&crate::ioc_intake::Context>,
    client: &C,
    now: OffsetDateTime,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<ExitCode, CommandError>
where
    C: CratesIoClient + ?Sized,
{
    run_inspect_with_clock(
        min_age_days,
        raw_specs,
        current_dir,
        legacy_ioc,
        client,
        now,
        stdout,
        stderr,
        &mut OffsetDateTime::now_utc,
    )
}

fn run_inspect_with_clock<C>(
    min_age_days: Option<u64>,
    raw_specs: Vec<String>,
    current_dir: &Path,
    legacy_ioc: Option<&crate::ioc_intake::Context>,
    client: &C,
    now: OffsetDateTime,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    clock: &mut dyn FnMut() -> OffsetDateTime,
) -> Result<ExitCode, CommandError>
where
    C: CratesIoClient + ?Sized,
{
    let ioc_authority = super::ioc::RepositoryAllowances::capture(current_dir)
        .map_err(|detail| CommandError::Io(std::io::Error::other(detail)))?;
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
        if let Some(ctx) = legacy_ioc {
            super::ioc::begin_legacy(ctx, &spec, &release)
                .map_err(|detail| CommandError::Io(std::io::Error::other(detail)))?;
        }
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
        if let Some(ctx) = legacy_ioc {
            super::ioc::remember_legacy(ctx, &report)
                .map_err(|detail| CommandError::Io(std::io::Error::other(detail)))?;
        }
        let (classification, ioc_decision) =
            current_ioc_decision(&report, &ioc_authority, now, clock)
                .map_err(|detail| CommandError::Io(std::io::Error::other(detail)))?;
        let rendered = render_inspect_report(
            &report,
            InspectRenderContext::Inspect,
            classification,
            ioc_decision.as_ref(),
        );

        write!(stdout, "{rendered}").map_err(CommandError::Io)?;
        if !matches!(classification, RustAssessmentClassification::RoutineSafe) {
            failed = true;
        }
    }

    Ok(exit_code_from_policy_failures(failed))
}

pub(super) fn current_ioc_decision(
    report: &RustInspectReport,
    authority: &super::ioc::RepositoryAllowances,
    started_at: OffsetDateTime,
    clock: &mut dyn FnMut() -> OffsetDateTime,
) -> Result<
    (
        RustAssessmentClassification,
        Option<barbican::ioc::Decision>,
    ),
    String,
> {
    authority.check()?;
    let checked_at = clock();
    if checked_at < started_at {
        return Err("clock rollback during IOC disposition".into());
    }
    let classification = report
        .classification_with_ioc_allowances(&authority.allowances, checked_at.unix_timestamp())?;
    let decision = report
        .ioc_inspection()
        .map(|inspection| {
            barbican::ioc::adjudicate(
                inspection,
                &authority.allowances,
                checked_at.unix_timestamp(),
            )
        })
        .transpose()?;
    Ok((classification, decision))
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
    classification: RustAssessmentClassification,
    ioc_decision: Option<&barbican::ioc::Decision>,
) -> String {
    let mut rendered = String::new();
    rendered.push_str(&format!("Inspect {}\n", report.spec()));
    rendered.push_str(&format!("  classification: {}\n", classification));
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
    if let Some(decision) = ioc_decision {
        rendered.push_str(&format!(
            "  IOC disposition: {} reviewed-allowed, {} unreviewed; raw matches retained.\n",
            decision.allowed.len(),
            decision.blocked.len()
        ));
        for error in &decision.errors {
            rendered.push_str(&format!("  IOC policy: {}\n", escape_render_field(error)));
        }
    }
    rendered.push_str(&format!(
        "  inspection failures: {}\n",
        render_slice(report.inspection_failures())
    ));

    rendered.push_str(&render_policy_violation_explanation(
        report,
        context,
        classification,
        ioc_decision.is_none_or(|decision| !decision.is_success()),
    ));
    rendered.push('\n');

    rendered
}

fn render_policy_violation_explanation(
    report: &RustInspectReport,
    context: InspectRenderContext,
    classification: RustAssessmentClassification,
    unresolved_ioc: bool,
) -> String {
    if !matches!(
        classification,
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
    if unresolved_ioc && !report.ioc_hits().is_empty() {
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

    if unresolved_ioc && !report.ioc_hits().is_empty() {
        block.push_str(&format!(
            "  remediation: collect a source-aware report with `cargo barbican ioc check {} --output REPORT`, then use `pin exception --ioc --inspection REPORT --review-record PATH` to scaffold exact finding rationale. Completed source review and explicit authority publication are separate. An IOC allowance does not grant an allowed_surfaces exception.\n", report.spec()
        ));
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

#[cfg(test)]
mod tests {
    use super::*;
    use barbican::{CrateRelease, CratesIoClientError, ExactCrateSpec, ioc};
    use std::cell::Cell;
    use std::fs;

    struct Acquisition {
        release: CrateRelease,
        archive: Vec<u8>,
        clock: Cell<i64>,
        after_fetch: i64,
        change_record: Option<std::path::PathBuf>,
    }
    impl CratesIoClient for Acquisition {
        fn fetch_release(&self, _: &ExactCrateSpec) -> Result<CrateRelease, CratesIoClientError> {
            Ok(self.release.clone())
        }
        fn fetch_release_tarball(
            &self,
            _: &ExactCrateSpec,
        ) -> Result<Vec<u8>, CratesIoClientError> {
            self.clock.set(self.after_fetch);
            if let Some(path) = &self.change_record {
                let old = fs::read_to_string(path).unwrap();
                fs::write(path, format!("{old}\nChanged during acquisition\n")).unwrap();
            }
            Ok(self.archive.clone())
        }
    }
    fn at(value: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(value).unwrap()
    }
    fn fixture(
        after_fetch: i64,
    ) -> (
        crate::verified_source::Stage,
        Acquisition,
        RustInspectReport,
    ) {
        let stage = crate::verified_source::Stage::new().unwrap();
        let mut archive = tar::Builder::new(Vec::new());
        for (path, bytes) in [
            (
                "Cargo.toml",
                "[package]\nname='clock-fixture'\nversion='1.0.0'\nedition='2021'\nbuild='build.rs'\n",
            ),
            (
                "build.rs",
                "// Command::new( is inert source evidence\nfn main() {}\n",
            ),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o644);
            header.set_size(bytes.len() as u64);
            header.set_cksum();
            archive
                .append_data(
                    &mut header,
                    format!("clock-fixture-1.0.0/{path}"),
                    bytes.as_bytes(),
                )
                .unwrap();
        }
        let tar = archive.into_inner().unwrap();
        let mut crc = 0xffff_ffff_u32;
        for byte in &tar {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                crc = (crc >> 1) ^ 0xedb8_8320_u32.wrapping_mul(crc & 1);
            }
        }
        let mut archive = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];
        archive.extend(miniz_oxide::deflate::compress_to_vec(&tar, 6));
        archive.extend((!crc).to_le_bytes());
        archive.extend((tar.len() as u32).to_le_bytes());
        let release = CrateRelease {
            checksum_sha256_hex: ioc::digest(&archive),
            published_at: at(0),
            published_at_raw: "1970-01-01T00:00:00Z".into(),
            yanked: false,
        };
        let report = inspect_published_crate_at(
            "clock-fixture@1.0.0".parse().unwrap(),
            release.clone(),
            &archive,
            at(90),
            0,
            None,
        );
        let mut record =
            ioc::parse_review(&ioc::scaffold_review(report.ioc_inspection().unwrap()).unwrap())
                .unwrap();
        record.reviewer = "fixture reviewer".into();
        record.reviewed_at_utc = Some(80);
        record.conclusion = ioc::Conclusion::ExpectedBehaviour;
        record.rationale =
            "The literal occurs in an authored inert comment. No package code is executed.".into();
        record.review_by_utc = Some(100);
        let text = ioc::render_review(&record).unwrap();
        fs::write(stage.root.join("ioc.md"), &text).unwrap();
        fs::write(
            stage.root.join("reviewed-targets.toml"),
            barbican::append_ioc_record(
                "[rust]\n",
                &ioc::IocRecordReference {
                    record: "ioc.md".into(),
                    record_sha256: ioc::digest(text.as_bytes()),
                },
            )
            .unwrap(),
        )
        .unwrap();
        (
            stage,
            Acquisition {
                release,
                archive,
                clock: Cell::new(90),
                after_fetch,
                change_record: None,
            },
            report,
        )
    }

    #[test]
    fn legacy_ioc_uses_post_acquisition_time_for_expiry_and_rejects_rollback() {
        for checked_at in [99, 100, 89] {
            let (stage, client, _) = fixture(checked_at);
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let result = run_inspect_with_clock(
                Some(0),
                vec!["clock-fixture@1.0.0".into()],
                &stage.root,
                None,
                &client,
                at(90),
                &mut stdout,
                &mut stderr,
                &mut || at(client.clock.get()),
            );
            if checked_at < 90 {
                assert!(result.unwrap_err().to_string().contains("clock rollback"));
                continue;
            }
            assert_eq!(result.unwrap(), ExitCode::from(1));
            let output = String::from_utf8(stdout).unwrap();
            if checked_at < 100 {
                assert!(
                    output.contains("1 reviewed-allowed, 0 unreviewed"),
                    "{output}"
                );
                assert!(output.contains("classification: elevated-risk"), "{output}");
            } else {
                assert!(
                    output.contains("0 reviewed-allowed, 1 unreviewed"),
                    "{output}"
                );
                assert!(output.contains("expired"), "{output}");
            }
        }
    }

    #[test]
    fn candidate_ioc_uses_same_current_clock_and_record_guard() {
        for checked_at in [99, 100, 89] {
            let (stage, client, _) = fixture(checked_at);
            let authority = super::super::ioc::RepositoryAllowances::capture(&stage.root).unwrap();
            let (_, age) = load_release_age_context(&stage.root, Some(0)).unwrap();
            let result = super::super::gatehouse::render_candidate_inspect(
                &"clock-fixture@1.0.0".parse().unwrap(),
                0,
                &age,
                &authority,
                None,
                &client,
                at(90),
                &mut || at(client.clock.get()),
            );
            if checked_at < 90 {
                assert!(result.unwrap_err().contains("clock rollback"));
            } else {
                let (output, failed) = result.unwrap();
                assert!(failed);
                assert!(
                    output.contains(if checked_at < 100 {
                        "1 reviewed-allowed, 0 unreviewed"
                    } else {
                        "0 reviewed-allowed, 1 unreviewed"
                    }),
                    "{output}"
                );
            }
        }
        let (stage, mut client, _) = fixture(99);
        let authority = super::super::ioc::RepositoryAllowances::capture(&stage.root).unwrap();
        let (_, age) = load_release_age_context(&stage.root, Some(0)).unwrap();
        client.change_record = Some(stage.root.join("ioc.md"));
        let result = super::super::gatehouse::render_candidate_inspect(
            &"clock-fixture@1.0.0".parse().unwrap(),
            0,
            &age,
            &authority,
            None,
            &client,
            at(90),
            &mut || at(client.clock.get()),
        );
        assert!(result.unwrap_err().contains("record bytes changed"));
    }

    #[test]
    fn documented_ioc_completion_requires_machine_fields_and_external_marker_removal() {
        let (_, _, report) = fixture(99);
        let scaffold = ioc::scaffold_review(report.ioc_inspection().unwrap()).unwrap();
        let mut record = ioc::parse_review(&scaffold).unwrap();
        record.reviewer = "authorised agent".into();
        record.reviewed_at_utc = Some(90);
        record.conclusion = ioc::Conclusion::ExpectedBehaviour;
        record.rationale = "The exact literal is in the authored fixture's inert comment; no candidate execution is inferred.".into();
        let completed_block = serde_json::to_string_pretty(&record).unwrap();
        let (prefix, remaining) = scaffold.split_once("```barbican-ioc-review-v1\n").unwrap();
        let (_, suffix) = remaining.split_once("\n```").unwrap();
        let edited = format!("{prefix}```barbican-ioc-review-v1\n{completed_block}\n```{suffix}");
        assert!(
            ioc::parse_review(&edited)
                .unwrap_err()
                .contains("pending scaffold marker")
        );
        let complete = edited.replace(barbican::REVIEW_RECORD_SCAFFOLD_MARKER, "");
        ioc::parse_review(&complete)
            .unwrap()
            .validate_completed(99)
            .unwrap();
        let guide = include_str!("../../../../docs/user/ioc.md");
        assert!(guide.contains(barbican::REVIEW_RECORD_SCAFFOLD_MARKER));
        assert!(guide.contains("positional argument"));
    }
}
