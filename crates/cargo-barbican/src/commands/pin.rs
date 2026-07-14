use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use barbican::{
    OffsetDateTime, PinAddPlan, PinAddRejection, PinExceptionAdvisory, PinExceptionRejection,
    RustSecAdvisoryId, format_iso_date, parse_iso_date, parse_pin_add_target,
    parse_reviewed_targets_toml, pin_exception_default_review_by, pin_family_name,
    pin_review_record_path, plan_pin_add, plan_pin_exception,
};

use crate::cli::{PinCommand, REVIEWED_TARGETS_CONFIG_FILE};

use super::lockfile_ops::write_file_atomically;
use super::scaffold_fs::{ScaffoldState, confined_scaffold_state, write_new_file};
use super::{
    CommandError, REVIEW_RECORDS_DIR, fail, load_current_manifest_direct_requirements,
    load_reviewed_targets, read_optional_text_no_symlink,
};

pub(super) fn run_pin(
    command: PinCommand,
    current_dir: &Path,
    now: OffsetDateTime,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<ExitCode, CommandError> {
    match command {
        PinCommand::Add { spec } => run_pin_add(&spec, current_dir, now, stdout, stderr),
        PinCommand::Exception {
            spec,
            advisories,
            review_by,
        } => run_pin_exception(
            &spec,
            &advisories,
            review_by.as_deref(),
            current_dir,
            now,
            stdout,
            stderr,
        ),
        PinCommand::Check { config } => {
            super::pin_check::run_pin_check(&config, current_dir, stdout)
        }
    }
}

fn run_pin_add(
    spec: &str,
    current_dir: &Path,
    now: OffsetDateTime,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<ExitCode, CommandError> {
    let target = match parse_pin_add_target(spec) {
        Ok(target) => target,
        Err(error) => return fail(stderr, format!("pin add {spec}: {error}")),
    };

    let config_path = Path::new(REVIEWED_TARGETS_CONFIG_FILE);
    let Some(reviewed_targets) = load_reviewed_targets(current_dir, config_path)? else {
        return fail(
            stderr,
            format!(
                "pin add: {REVIEWED_TARGETS_CONFIG_FILE} not found; run `cargo barbican policy init` first"
            ),
        );
    };

    let lockfile = super::load_current_lockfile(current_dir, Path::new("Cargo.lock"))?;
    let manifest_requirements = load_current_manifest_direct_requirements(current_dir)?;
    let date = now.date();
    let family_name = pin_family_name(target.crate_name(), date);
    let review_record = pin_review_record_path(REVIEW_RECORDS_DIR, target.crate_name(), date);

    let plan = match plan_pin_add(
        &lockfile,
        &reviewed_targets,
        &manifest_requirements,
        &target,
        family_name,
        review_record,
        date,
    ) {
        Ok(plan) => plan,
        Err(rejection) => return fail(stderr, render_pin_add_rejection(&rejection)),
    };

    if let Some(exit) = write_family_scaffold(current_dir, config_path, &plan, "pin add", stderr)? {
        return Ok(exit);
    }

    writeln!(stdout, "Pin add:").map_err(CommandError::Io)?;
    writeln!(stdout, "- {}: created", plan.review_record()).map_err(CommandError::Io)?;
    writeln!(
        stdout,
        "- {REVIEWED_TARGETS_CONFIG_FILE}: appended reviewed family \"{}\" for {}",
        plan.family_name(),
        plan.exact()
    )
    .map_err(CommandError::Io)?;
    if plan.checksum().is_none() {
        writeln!(
            stdout,
            "- note: no Cargo.lock checksum for {}; the family pins by exact version only",
            plan.exact()
        )
        .map_err(CommandError::Io)?;
    }
    let exact_requirement = format!("={}", plan.exact().version());
    if plan.direct_requirement().is_some() {
        writeln!(
            stdout,
            "- note: exact direct manifest pin \"{exact_requirement}\" included in the family"
        )
        .map_err(CommandError::Io)?;
    } else if plan.has_non_conforming_direct_requirement() {
        writeln!(
            stdout,
            "- note: {} is a direct dependency but its manifest requirement is not uniformly the exact pin \"{exact_requirement}\"; no direct entry scaffolded — consider exact-pinning the manifest",
            plan.exact().crate_name()
        )
        .map_err(CommandError::Io)?;
    }
    writeln!(
        stdout,
        "\nNext steps:\n- Complete the review record at {}; the scaffold is not a completed review.\n- Run `cargo barbican pin check`, then `cargo barbican audit`, then `cargo barbican verify`.",
        plan.review_record()
    )
    .map_err(CommandError::Io)?;

    Ok(ExitCode::SUCCESS)
}

/// The shared fail-closed scaffold write sequence for `pin add` and
/// `pin exception`: refuse existing record paths, re-parse the appended
/// policy before writing, and clean up the record if the config write fails.
/// Returns `Some(exit)` when the write was refused with a rendered failure.
fn write_family_scaffold(
    current_dir: &Path,
    config_path: &Path,
    plan: &PinAddPlan,
    command_label: &str,
    stderr: &mut dyn Write,
) -> Result<Option<ExitCode>, CommandError> {
    match confined_scaffold_state(current_dir, Path::new(plan.review_record()))? {
        ScaffoldState::Missing => {}
        _ => {
            return fail(
                stderr,
                format!(
                    "{command_label} {}: review record path already exists at {}; refusing to overwrite",
                    plan.exact().crate_name(),
                    plan.review_record()
                ),
            )
            .map(Some);
        }
    }

    // Re-reads via the same symlink-refusing helper load_reviewed_targets used
    // above rather than a plain fs::read_to_string, so a symlink swapped in
    // between the two reads (TOCTOU) is refused here too instead of silently
    // followed.
    let existing_policy_text =
        read_optional_text_no_symlink(current_dir, config_path).map_err(|source| {
            CommandError::ReviewedTargetsRead {
                path: config_path.display().to_string(),
                source,
            }
        })?;
    let Some(existing_policy_text) = existing_policy_text else {
        return Err(CommandError::ReviewedTargetsRead {
            path: config_path.display().to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("{} vanished after the initial read", config_path.display()),
            ),
        });
    };
    let updated_policy_text = format!("{existing_policy_text}{}", plan.family_stub());
    if let Err(source) = parse_reviewed_targets_toml(&updated_policy_text) {
        return Err(CommandError::ReviewedTargetsParse {
            path: config_path.display().to_string(),
            source: Box::new(source),
        });
    }

    write_new_file(
        current_dir,
        Path::new(plan.review_record()),
        plan.record_stub(),
    )?;
    if let Err(source) = write_file_atomically(&current_dir.join(config_path), &updated_policy_text)
    {
        let cleanup_source = fs::remove_file(current_dir.join(plan.review_record())).err();
        return Err(CommandError::PinAddConfigWrite {
            config_path: config_path.display().to_string(),
            review_record_path: plan.review_record().to_owned(),
            source,
            cleanup_source,
        });
    }

    Ok(None)
}

fn run_pin_exception(
    spec: &str,
    advisory_args: &[String],
    review_by: Option<&str>,
    current_dir: &Path,
    now: OffsetDateTime,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<ExitCode, CommandError> {
    let target = match parse_pin_add_target(spec) {
        Ok(target) => target,
        Err(error) => return fail(stderr, format!("pin exception {spec}: {error}")),
    };
    let review_by_date = match review_by {
        Some(text) => match parse_iso_date(text) {
            Ok(date) => date,
            Err(error) => {
                return fail(stderr, format!("pin exception --review-by {text}: {error}"));
            }
        },
        None => match pin_exception_default_review_by(now.date()) {
            Some(date) => date,
            None => {
                return fail(
                    stderr,
                    "pin exception: cannot derive the default review-by date; pass --review-by",
                );
            }
        },
    };
    let mut advisories = Vec::new();
    for raw in advisory_args {
        match RustSecAdvisoryId::parse(raw) {
            Ok(advisory_id) => {
                advisories.push(PinExceptionAdvisory::new(advisory_id, review_by_date));
            }
            Err(error) => return fail(stderr, format!("pin exception {raw}: {error}")),
        }
    }

    let config_path = Path::new(REVIEWED_TARGETS_CONFIG_FILE);
    let Some(reviewed_targets) = load_reviewed_targets(current_dir, config_path)? else {
        return fail(
            stderr,
            format!(
                "pin exception: {REVIEWED_TARGETS_CONFIG_FILE} not found; run `cargo barbican policy init` first"
            ),
        );
    };

    let lockfile = super::load_current_lockfile(current_dir, Path::new("Cargo.lock"))?;
    let manifest_requirements = load_current_manifest_direct_requirements(current_dir)?;
    let date = now.date();
    let family_name = pin_family_name(target.crate_name(), date);
    let review_record = pin_review_record_path(REVIEW_RECORDS_DIR, target.crate_name(), date);

    let plan = match plan_pin_exception(
        &lockfile,
        &reviewed_targets,
        &manifest_requirements,
        &target,
        &advisories,
        family_name,
        review_record,
        date,
    ) {
        Ok(plan) => plan,
        Err(rejection) => return render_pin_exception_rejection(&rejection, stderr),
    };

    if let Some(exit) =
        write_family_scaffold(current_dir, config_path, plan.base(), "pin exception", stderr)?
    {
        return Ok(exit);
    }

    let accepted = plan
        .advisories()
        .iter()
        .map(|advisory| advisory.advisory_id().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    writeln!(stdout, "Pin exception:").map_err(CommandError::Io)?;
    writeln!(stdout, "- {}: created", plan.base().review_record()).map_err(CommandError::Io)?;
    writeln!(
        stdout,
        "- {REVIEWED_TARGETS_CONFIG_FILE}: appended reviewed family \"{}\" accepting {} for {}",
        plan.base().family_name(),
        accepted,
        plan.base().exact()
    )
    .map_err(CommandError::Io)?;
    writeln!(
        stdout,
        "- review by {}: audit fails these exceptions once past this date",
        format_iso_date(review_by_date)
    )
    .map_err(CommandError::Io)?;
    writeln!(
        stdout,
        "\nNext steps:\n- Complete the review record at {}; the scaffold is not a completed review.\n- Prefer remediation: bump the graph to a patched release and remove the exception when one is adoptable.\n- Run `cargo barbican pin check`, then `cargo barbican audit`, then `cargo barbican verify`.",
        plan.base().review_record()
    )
    .map_err(CommandError::Io)?;

    Ok(ExitCode::SUCCESS)
}

fn render_pin_exception_rejection(
    rejection: &PinExceptionRejection,
    stderr: &mut dyn Write,
) -> Result<ExitCode, CommandError> {
    match rejection {
        PinExceptionRejection::Target(target) => fail(
            stderr,
            render_pin_add_rejection(target).replacen("pin add", "pin exception", 1),
        ),
        PinExceptionRejection::MissingChecksum {
            crate_name,
            version,
        } => fail(
            stderr,
            format!(
                "pin exception {crate_name}@{version}: Cargo.lock records no crates.io checksum; advisory exceptions require a checksum-bound resolved target"
            ),
        ),
        PinExceptionRejection::DuplicateAdvisory { advisory_id } => fail(
            stderr,
            format!("pin exception: duplicate advisory id {advisory_id}"),
        ),
        PinExceptionRejection::AlreadyAllowed {
            advisory_id,
            family,
        } => fail(
            stderr,
            format!(
                "pin exception: {advisory_id} is already allowed by reviewed family \"{family}\" in {REVIEWED_TARGETS_CONFIG_FILE}"
            ),
        ),
        PinExceptionRejection::CoveredResolvedMismatch {
            family,
            crate_name,
            reviewed_version,
            resolved_version,
        } => fail(
            stderr,
            format!(
                "pin exception {crate_name}: reviewed family \"{family}\" resolves {crate_name} at {reviewed_version} but Cargo.lock resolves {resolved_version}; reconcile the family with `cargo barbican pin check` first"
            ),
        ),
        PinExceptionRejection::CoveredWithoutChecksum { family, crate_name } => fail(
            stderr,
            format!(
                "pin exception {crate_name}: reviewed family \"{family}\" covers {crate_name} without a checksum_sha256; upgrade its resolved entry to the structured checksum form before adding advisory exceptions"
            ),
        ),
        PinExceptionRejection::CoveredFamilyManualEdit {
            family,
            review_record,
            crate_name,
            fragment,
            extend_existing,
        } => {
            let exit = fail(
                stderr,
                format!(
                    "pin exception {crate_name}: crate is already covered by reviewed family \"{family}\"; refusing to rewrite an existing family block automatically"
                ),
            )?;
            let instruction = if *extend_existing {
                format!(
                    "Append this entry to the existing allowed_advisories list for {crate_name} in family \"{family}\" ({REVIEWED_TARGETS_CONFIG_FILE}):"
                )
            } else {
                format!(
                    "Add this inside the [[rust.families]] block for family \"{family}\" in {REVIEWED_TARGETS_CONFIG_FILE} (before any following family):"
                )
            };
            writeln!(
                stderr,
                "\n{instruction}\n\n{fragment}\nThen record the accepted advisories in {review_record} and re-run `cargo barbican pin check` and `cargo barbican audit`."
            )
            .map_err(CommandError::Io)?;
            Ok(exit)
        }
    }
}

fn render_pin_add_rejection(rejection: &PinAddRejection) -> String {
    match rejection {
        PinAddRejection::NotInLockfile { crate_name } => format!(
            "pin add {crate_name}: not present in Cargo.lock; add the dependency and run `cargo barbican resolve` first"
        ),
        PinAddRejection::VersionNotResolved {
            crate_name,
            version,
            resolved_versions,
        } => format!(
            "pin add {crate_name}@{version}: Cargo.lock resolves {crate_name} to {}; pass one of those exact versions",
            render_versions(resolved_versions)
        ),
        PinAddRejection::AmbiguousVersion {
            crate_name,
            resolved_versions,
        } => format!(
            "pin add {crate_name}: multiple resolved versions in Cargo.lock {}; pass an exact crate@version",
            render_versions(resolved_versions)
        ),
        PinAddRejection::AlreadyCovered { crate_name, family } => format!(
            "pin add {crate_name}: crate is already covered by reviewed family \"{family}\" in {REVIEWED_TARGETS_CONFIG_FILE}"
        ),
        PinAddRejection::FamilyAlreadyExists {
            crate_name,
            family_name,
        } => format!(
            "pin add {crate_name}: reviewed family \"{family_name}\" already exists in {REVIEWED_TARGETS_CONFIG_FILE}"
        ),
    }
}

fn render_versions(versions: &[String]) -> String {
    format!(
        "[{}]",
        versions
            .iter()
            .map(|version| format!("\"{version}\""))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

#[cfg(test)]
mod tests {
    use barbican::{OffsetDateTime, compose_pin_review_record};

    fn section_headings(text: &str) -> Vec<&str> {
        text.lines()
            .filter(|line| line.starts_with("## "))
            .collect()
    }

    #[test]
    fn scaffolded_review_record_sections_match_the_shipped_record_template() {
        let spec =
            barbican::ExactCrateSpec::from_parts("serde", "1.0.228").expect("spec should parse");
        let template_readme_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../templates/dependency-reviews/README.md");
        let template_readme = std::fs::read_to_string(template_readme_path)
            .expect("shipped record template README should be readable");

        let fence_start = template_readme
            .find("```md\n")
            .expect("record template README should contain a ```md template block");
        let template_body = &template_readme[fence_start + "```md\n".len()..];
        let fence_end = template_body
            .rfind("\n```")
            .expect("record template block should be closed");
        let template = &template_body[..fence_end];

        assert!(template.starts_with("# Dependency Review:"));

        let scaffolded = compose_pin_review_record(
            &spec,
            None,
            true,
            "serde-2026-07-02",
            Some("=1.0.228"),
            &[],
            OffsetDateTime::from_unix_timestamp(1_590_969_600)
                .expect("fixed timestamp should parse")
                .date(),
        );

        assert!(scaffolded.starts_with("# Dependency Review:"));
        assert_eq!(
            section_headings(&scaffolded),
            section_headings(template),
            "scaffolded review record sections drifted from the shipped record template"
        );
    }
}
