use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use barbican::{
    OffsetDateTime, ReviewRecordStatus, ReviewedTargets, RustReviewedTargetsReport,
    check_reviewed_rust_targets, classify_review_record, parse_lockfile, plan_family_addition,
};

use super::pin_files::{Inputs, Prepared, record_path};
use super::scaffold_fs::{ScaffoldState, confined_scaffold_state};
use super::{
    CommandError, escape_render_field, fail, load_config,
    load_current_manifest_direct_requirements, load_reviewed_targets,
    read_optional_text_no_symlink,
};
use crate::command_runner::{CommandRunner, cargo_home_from_environment};

pub(super) fn add<R: CommandRunner + ?Sized>(
    family: &str,
    requests: &[String],
    root: &Path,
    runner: &R,
    now: OffsetDateTime,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<ExitCode, CommandError> {
    load_config(root)?;
    let inputs = Inputs::capture(root, runner)?;
    let context = super::pin_files::PolicyInputs::load(&inputs)?;
    let policy = context.policy;
    let lock = context.lockfile;
    let requirements = context.requirements;
    let plan = match plan_family_addition(&policy, &lock, &requirements, family, requests) {
        Ok(plan) => plan,
        Err(source) => return fail(stderr, source),
    };
    if plan.is_noop() {
        inputs.check()?;
        writeln!(stdout, "Family addition: no changes; every requested target is already a member. No writes or review completion.").map_err(CommandError::Io)?;
        return view(Some(family), root, runner, stdout, stderr);
    }
    let prepared = match Prepared::addition(inputs, &policy, &plan, now.date()) {
        Ok(prepared) => prepared,
        Err(source) => {
            writeln!(stdout, "Non-applying addition proposal; no writes made. Manually prepare PENDING evidence before changing policy:").map_err(CommandError::Io)?;
            for member in plan.members() {
                writeln!(
                    stdout,
                    "- {}: {}",
                    member.selected().spec(),
                    escape_render_field(&member.selected().source_string())
                )
                .map_err(CommandError::Io)?;
            }
            return Err(source);
        }
    };
    prepared.apply()?;
    writeln!(
        stdout,
        "Family addition: prepared; human review remains PENDING."
    )
    .map_err(CommandError::Io)?;
    for member in plan.members() {
        writeln!(
            stdout,
            "- {}: {}",
            member.selected().spec(),
            if member.already_present() {
                "already a member; unchanged"
            } else {
                "added"
            }
        )
        .map_err(CommandError::Io)?;
        if member.omitted_direct() {
            writeln!(stdout, "  No direct fence added: declarations are not uniformly exact; resolved facts only.").map_err(CommandError::Io)?;
        }
        if let Some(direct) = member.direct() {
            writeln!(
                stdout,
                "  Direct intent added: {}",
                escape_render_field(&direct.to_string())
            )
            .map_err(CommandError::Io)?;
        }
    }
    for (path, families) in prepared.reopened() {
        writeln!(
            stdout,
            "- Review record {}: PENDING; affected families: {}",
            escape_render_field(&path.display().to_string()),
            families
                .iter()
                .map(|name| escape_render_field(name))
                .collect::<Vec<_>>()
                .join(", ")
        )
        .map_err(CommandError::Io)?;
    }
    writeln!(stdout, "Existing facts, grants and deadlines were preserved; no new grants or source permissions were created. Complete the expanded review, then run cargo barbican pin check and cargo barbican gatehouse policy-check (or pre-release).").map_err(CommandError::Io)?;
    Ok(ExitCode::SUCCESS)
}

pub(super) fn view<R: CommandRunner + ?Sized>(
    selected: Option<&str>,
    root: &Path,
    runner: &R,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<ExitCode, CommandError> {
    load_config(root)?;
    let policy =
        load_reviewed_targets(root, Path::new("reviewed-targets.toml"))?.unwrap_or_default();
    if let Some(name) = selected
        && !policy
            .rust_families()
            .iter()
            .any(|family| family.name() == name)
    {
        return fail(
            stderr,
            "unknown family; use cargo barbican pin list for exact names",
        );
    }
    if policy.rust_families().is_empty() {
        writeln!(stdout, "No reviewed families configured. Use cargo barbican policy init to scaffold policy, then pin add for deliberate review.").map_err(CommandError::Io)?;
        return Ok(ExitCode::SUCCESS);
    }
    let parity = parity(root, &policy);
    let mut records = BTreeMap::new();
    let cargo_home = cargo_home_from_environment(|name| runner.environment_variable(name));
    let protected = protected_paths(root, cargo_home.as_deref());
    writeln!(
        stdout,
        "Reviewed families (declarations and diagnostics; not an enforcement verdict):"
    )
    .map_err(CommandError::Io)?;
    for family in policy
        .rust_families()
        .iter()
        .filter(|family| selected.is_none_or(|name| family.name() == name))
    {
        let path = record_path(root, family.review_record());
        let key = path
            .as_ref()
            .map(|path| path.clone())
            .unwrap_or_else(|_| PathBuf::from(family.review_record()));
        let status = records
            .entry(key)
            .or_insert_with(|| record_status(root, path, &protected));
        writeln!(
            stdout,
            "\nFamily: {}\n  Declared members: {} resolved, {} direct\n  Review record: {} — {}",
            escape_render_field(family.name()),
            family.resolved().len(),
            family.direct().len(),
            escape_render_field(family.review_record()),
            escape_render_field(status)
        )
        .map_err(CommandError::Io)?;
        let sharing = policy
            .rust_families()
            .iter()
            .filter(|other| {
                match (
                    record_path(root, other.review_record()),
                    record_path(root, family.review_record()),
                ) {
                    (Ok(left), Ok(right)) => left == right,
                    _ => false,
                }
            })
            .map(|family| escape_render_field(family.name()))
            .collect::<Vec<_>>()
            .join(", ");
        writeln!(
            stdout,
            "  Shared review scope: {sharing}; PENDING affects all citing families."
        )
        .map_err(CommandError::Io)?;
        match &parity {
            Ok(report) => {
                if let Some(facts) = report
                    .families()
                    .iter()
                    .find(|facts| facts.name() == family.name())
                {
                    writeln!(stdout, "  Manifest/lock parity: {} (scoped; audit/source overrides/toolchain/execution checked by their owning gates)", if facts.is_success() { "matches" } else { "mismatch" }).map_err(CommandError::Io)?;
                    if selected.is_some() {
                        for check in facts
                            .direct_checks()
                            .iter()
                            .filter(|check| !check.is_success())
                        {
                            writeln!(
                                stdout,
                                "    Direct mismatch: {}; expected {}; current {}",
                                check.crate_name(),
                                escape_render_field(&check.expected_target().to_string()),
                                escape_render_field(
                                    &check
                                        .observed()
                                        .iter()
                                        .map(|entry| format!(
                                            "{} [{}]: {:?} {}{}",
                                            entry.manifest_path(),
                                            entry.section(),
                                            entry.source_kind(),
                                            entry
                                                .version_requirement()
                                                .unwrap_or("(no version requirement)"),
                                            entry
                                                .git()
                                                .map_or(String::new(), |git| format!(" {git}"))
                                        ))
                                        .collect::<Vec<_>>()
                                        .join("; ")
                                )
                            )
                            .map_err(CommandError::Io)?;
                        }
                        for check in facts
                            .resolved_checks()
                            .iter()
                            .filter(|check| !check.is_success())
                        {
                            writeln!(stdout, "    Resolved mismatch: {}; expected {} ({}, checksum {}); current versions {:?}, checksums {:?}, sources {}, checksumless {}", check.crate_name(), check.expected_target().spec(), escape_render_field(&check.expected_target().source_string()), check.expected_target().checksum_sha256().map_or("not recorded", |digest| digest.as_str()), check.actual_versions(), check.actual_checksums_sha256(), escape_render_field(&check.non_crates_io_sources().iter().map(|source| barbican::source_diagnostic(Some(source))).collect::<Vec<_>>().join(", ")), check.has_checksumless_entry())
                                .map_err(CommandError::Io)?;
                        }
                    }
                }
            }
            Err(reason) => {
                writeln!(
                    stdout,
                    "  Manifest/lock parity: unavailable — {}",
                    escape_render_field(reason)
                )
                .map_err(CommandError::Io)?;
            }
        }
        if selected.is_some() {
            for (name, target) in family.resolved() {
                let identity = target.git().map_or_else(
                    || {
                        format!(
                            "crates.io {} checksum_sha256 {}",
                            target.version(),
                            target
                                .checksum_sha256()
                                .map_or("not recorded (legacy declaration)", |checksum| checksum
                                    .as_str())
                        )
                    },
                    |git| format!("Git {git}; package version {}", target.version()),
                );
                writeln!(
                    stdout,
                    "  Resolved {name}: {}",
                    escape_render_field(&identity)
                )
                .map_err(CommandError::Io)?;
            }
            for (name, direct) in family.direct() {
                writeln!(
                    stdout,
                    "  Direct {name}: {}",
                    escape_render_field(&direct.to_string())
                )
                .map_err(CommandError::Io)?;
            }
            for grant in family.execution_surface_allowances() {
                writeln!(
                    stdout,
                    "  Declared surface grant: {}",
                    escape_render_field(&grant.to_string())
                )
                .map_err(CommandError::Io)?;
            }
            for grant in family.release_age_exceptions() {
                writeln!(
                    stdout,
                    "  Declared age exception: {}",
                    escape_render_field(&grant.to_string())
                )
                .map_err(CommandError::Io)?;
            }
            for grant in family.advisory_exceptions() {
                writeln!(
                    stdout,
                    "  Declared advisory exception: {}",
                    escape_render_field(&grant.to_string())
                )
                .map_err(CommandError::Io)?;
            }
            writeln!(
                stdout,
                "  Grants are declarations, not a claim they are currently honoured."
            )
            .map_err(CommandError::Io)?;
        } else {
            writeln!(
                stdout,
                "  Inspect: cargo barbican pin show -- {}",
                shell_argument(family.name())
            )
            .map_err(CommandError::Io)?;
        }
    }
    writeln!(stdout, "\nRecord completion is content classification, not authenticated approval. Use pin check / gatehouse policy-check for enforcement.").map_err(CommandError::Io)?;
    Ok(ExitCode::SUCCESS)
}

fn parity(root: &Path, policy: &ReviewedTargets) -> Result<RustReviewedTargetsReport, String> {
    if !matches!(
        confined_scaffold_state(root, Path::new("Cargo.lock")),
        Ok(ScaffoldState::RegularFile)
    ) {
        return Err("Cargo.lock missing, unsafe or not a regular file".to_owned());
    }
    let text = read_optional_text_no_symlink(root, Path::new("Cargo.lock"))
        .map_err(|source| source.to_string())?
        .ok_or("Cargo.lock missing")?;
    let lock = parse_lockfile(&text).map_err(|source| source.to_string())?;
    let requirements =
        load_current_manifest_direct_requirements(root).map_err(|source| source.to_string())?;
    Ok(check_reviewed_rust_targets(policy, &requirements, &lock))
}

fn protected_paths(root: &Path, cargo_home: Option<&Path>) -> Result<Vec<PathBuf>, String> {
    let mut paths = super::workspace_manifest_paths(root)
        .map_err(|source| source.to_string())?
        .into_iter()
        .map(|path| root.join(path))
        .collect::<Vec<_>>();
    paths.extend(
        super::pin_files::PROTECTED_INPUTS
            .iter()
            .map(|path| root.join(path)),
    );
    for directory in root
        .ancestors()
        .map(|path| path.join(".cargo"))
        .chain(cargo_home.map(|path| root.join(path)))
    {
        paths.extend([directory.join("config"), directory.join("config.toml")]);
    }
    Ok(paths)
}

fn record_status(
    root: &Path,
    path: Result<PathBuf, CommandError>,
    protected: &Result<Vec<PathBuf>, String>,
) -> String {
    let read = || -> Result<ReviewRecordStatus, String> {
        let path = path.map_err(|source| source.to_string())?;
        let relative = path
            .strip_prefix(root)
            .map_err(|source| source.to_string())?;
        match confined_scaffold_state(root, relative).map_err(|source| source.to_string())? {
            ScaffoldState::Missing => return Ok(ReviewRecordStatus::Missing),
            ScaffoldState::RegularFile => {}
            _ => return Err("unsafe or non-regular review record".to_owned()),
        }
        super::pin_files::reject_protected_alias(&path, protected.as_ref().map_err(Clone::clone)?)
            .map_err(|source| source.to_string())?;
        let text = fs::read_to_string(path).map_err(|source| source.to_string())?;
        Ok(classify_review_record(Some(&text)))
    };
    match read() {
        Ok(ReviewRecordStatus::Completed) => "completed (content only)".to_owned(),
        Ok(ReviewRecordStatus::ScaffoldPlaceholder) => "PENDING".to_owned(),
        Ok(ReviewRecordStatus::Empty) => "empty".to_owned(),
        Ok(ReviewRecordStatus::Missing) => "missing".to_owned(),
        Err(reason) => format!("unavailable — {reason}"),
    }
}

fn shell_argument(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
