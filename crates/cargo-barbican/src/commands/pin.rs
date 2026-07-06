use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use barbican::{
    CargoManifestDirectRequirement, ExactCrateSpec, LockedPackage, OffsetDateTime, PinAddTarget,
    ReviewedTargets, compose_pin_family_stub, compose_pin_review_record, parse_pin_add_target,
    parse_reviewed_targets_toml, pin_family_name, pin_review_record_path,
};

use crate::cli::{PinCommand, REVIEWED_TARGETS_CONFIG_FILE};

use super::scaffold_fs::{ScaffoldState, confined_scaffold_state, write_new_file};
use super::{
    CommandError, REVIEW_RECORDS_DIR, fail, load_current_manifest_direct_requirements,
    load_reviewed_targets,
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
    let matching_packages = lockfile
        .packages()
        .iter()
        .filter(|package| package.name == target.crate_name())
        .collect::<Vec<_>>();
    if matching_packages.is_empty() {
        return fail(
            stderr,
            format!(
                "pin add {}: not present in Cargo.lock; add the dependency and run `cargo barbican resolve` first",
                target.crate_name()
            ),
        );
    }

    let package = match select_locked_package(&matching_packages, &target) {
        Ok(package) => package,
        Err(message) => return fail(stderr, message),
    };

    if let Some(covering_family) = family_covering_crate(&reviewed_targets, target.crate_name()) {
        return fail(
            stderr,
            format!(
                "pin add {}: crate is already covered by reviewed family \"{covering_family}\" in {REVIEWED_TARGETS_CONFIG_FILE}",
                target.crate_name()
            ),
        );
    }

    let date = now.date();
    let family_name = pin_family_name(target.crate_name(), date);
    if reviewed_targets
        .rust_families()
        .iter()
        .any(|family| family.name() == family_name)
    {
        return fail(
            stderr,
            format!(
                "pin add {}: reviewed family \"{family_name}\" already exists in {REVIEWED_TARGETS_CONFIG_FILE}",
                target.crate_name()
            ),
        );
    }

    let review_record = pin_review_record_path(REVIEW_RECORDS_DIR, target.crate_name(), date);
    match confined_scaffold_state(current_dir, Path::new(&review_record))? {
        ScaffoldState::Missing => {}
        _ => {
            return fail(
                stderr,
                format!(
                    "pin add {}: review record path already exists at {review_record}; refusing to overwrite",
                    target.crate_name()
                ),
            );
        }
    }

    let manifest_requirements = load_current_manifest_direct_requirements(current_dir)?;
    let observed_direct = manifest_requirements
        .iter()
        .filter(|requirement| requirement.name() == package.name)
        .collect::<Vec<_>>();
    let exact = package.exact_spec();
    let exact_requirement = format!("={}", exact.version());
    let direct_requirement = exact_direct_requirement(&observed_direct, exact);

    let family_stub = compose_pin_family_stub(
        &family_name,
        &review_record,
        exact,
        package.checksum(),
        direct_requirement.as_deref(),
    );
    let record_stub = compose_pin_review_record(
        exact,
        package.checksum(),
        package.is_crates_io(),
        &family_name,
        direct_requirement.as_deref(),
        date,
    );

    let existing_policy_text =
        fs::read_to_string(current_dir.join(config_path)).map_err(|source| {
            CommandError::ReviewedTargetsRead {
                path: config_path.display().to_string(),
                source,
            }
        })?;
    let updated_policy_text = format!("{existing_policy_text}{family_stub}");
    if let Err(source) = parse_reviewed_targets_toml(&updated_policy_text) {
        return Err(CommandError::ReviewedTargetsParse {
            path: config_path.display().to_string(),
            source: Box::new(source),
        });
    }

    write_new_file(current_dir, Path::new(&review_record), &record_stub)?;
    if let Err(source) = fs::write(current_dir.join(config_path), updated_policy_text) {
        let cleanup_source = fs::remove_file(current_dir.join(&review_record)).err();
        return Err(CommandError::PinAddConfigWrite {
            config_path: config_path.display().to_string(),
            review_record_path: review_record,
            source,
            cleanup_source,
        });
    }

    writeln!(stdout, "Pin add:").map_err(CommandError::Io)?;
    writeln!(stdout, "- {review_record}: created").map_err(CommandError::Io)?;
    writeln!(
        stdout,
        "- {REVIEWED_TARGETS_CONFIG_FILE}: appended reviewed family \"{family_name}\" for {}@{}",
        package.name, package.version
    )
    .map_err(CommandError::Io)?;
    if package.checksum().is_none() {
        writeln!(
            stdout,
            "- note: no Cargo.lock checksum for {}@{}; the family pins by exact version only",
            package.name, package.version
        )
        .map_err(CommandError::Io)?;
    }
    if direct_requirement.is_some() {
        writeln!(
            stdout,
            "- note: exact direct manifest pin \"{exact_requirement}\" included in the family"
        )
        .map_err(CommandError::Io)?;
    } else if !observed_direct.is_empty() {
        writeln!(
            stdout,
            "- note: {} is a direct dependency but its manifest requirement is not uniformly the exact pin \"{exact_requirement}\"; no direct entry scaffolded — consider exact-pinning the manifest",
            package.name
        )
        .map_err(CommandError::Io)?;
    }
    writeln!(
        stdout,
        "\nNext steps:\n- Complete the review record at {review_record}; the scaffold is not a completed review.\n- Run `cargo barbican pin check`, then `cargo barbican verify`."
    )
    .map_err(CommandError::Io)?;

    Ok(ExitCode::SUCCESS)
}

fn select_locked_package<'a>(
    matching_packages: &[&'a LockedPackage],
    target: &PinAddTarget,
) -> Result<&'a LockedPackage, String> {
    match target.version() {
        Some(version) => matching_packages
            .iter()
            .copied()
            .find(|package| package.version == version)
            .ok_or_else(|| {
                format!(
                    "pin add {}@{version}: Cargo.lock resolves {} to {}; pass one of those exact versions",
                    target.crate_name(),
                    target.crate_name(),
                    render_versions(matching_packages)
                )
            }),
        None => {
            if matching_packages.len() > 1 {
                Err(format!(
                    "pin add {}: multiple resolved versions in Cargo.lock {}; pass an exact crate@version",
                    target.crate_name(),
                    render_versions(matching_packages)
                ))
            } else {
                Ok(matching_packages[0])
            }
        }
    }
}

fn exact_direct_requirement(
    observed_direct: &[&CargoManifestDirectRequirement],
    exact: &ExactCrateSpec,
) -> Option<String> {
    let exact_requirement = format!("={}", exact.version());
    (!observed_direct.is_empty()
        && observed_direct.iter().all(|requirement| {
            requirement.source_kind().requires_exact_pin()
                && requirement.version_requirement() == Some(exact_requirement.as_str())
        }))
    .then_some(exact_requirement)
}

fn family_covering_crate<'a>(
    reviewed_targets: &'a ReviewedTargets,
    crate_name: &str,
) -> Option<&'a str> {
    reviewed_targets
        .rust_families()
        .iter()
        .find(|family| family.resolved().contains_key(crate_name))
        .map(|family| family.name())
}

fn render_versions(packages: &[&barbican::LockedPackage]) -> String {
    format!(
        "[{}]",
        packages
            .iter()
            .map(|package| format!("\"{}\"", package.version))
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
