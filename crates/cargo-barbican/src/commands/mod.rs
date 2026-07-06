mod age;
mod age_lock;
mod assess;
mod audit;
mod diff_render;
mod gatehouse;
mod inspect;
mod inventory;
mod lockfile_ops;
mod pick;
mod pin;
mod pin_check;
mod policy;
mod resolve;
mod review;
mod scaffold_fs;
mod scratch_dir;
mod update;
mod verify;

use std::collections::BTreeSet;
use std::env;
use std::ffi::OsString;
use std::fmt;
use std::fmt::Write as _;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use barbican::{
    BarbicanConfig, ConfigLoadError, CratesIoClient, ExactCrateSpec, OffsetDateTime,
    ReleaseAgeOutcome, ReleaseAgeReport, ReviewedReleaseAgeException, ReviewedTargets,
    ReviewedTargetsError, advisory_ignores_from_toml, check_release_age_at, format_age,
    parse_lockfile, parse_manifest_dependencies, parse_manifest_direct_requirements,
    parse_reviewed_targets_toml, parse_workspace_member_glob_roots,
    parse_workspace_member_manifest_paths,
};
use clap::Parser;

use crate::cli::{Cli, Command};
use crate::command_runner::{CommandRunner, RealCommandRunner, RunnerError};
use crate::crates_io_http::{
    CRATES_IO_BASE_URL_ENV, DEFAULT_CRATES_IO_BASE_URL, UreqCratesIoClient,
};

const CONFIG_FILE_NAME: &str = "barbican.toml";
pub(super) const DEFAULT_BASE_REF: &str = "HEAD";
pub(super) const REVIEW_ROOT_FILE_PATHS: [&str; 4] = [
    "Cargo.lock",
    "barbican.toml",
    "deny.toml",
    "reviewed-targets.toml",
];
pub(super) const REVIEW_RECORDS_DIR: &str = "docs/dependency-reviews";

pub fn run(stdout: &mut dyn Write, stderr: &mut dyn Write) -> Result<ExitCode, CommandError> {
    let cli = Cli::parse_from(cargo_subcommand_args(env::args_os()));
    let current_dir = env::current_dir().map_err(CommandError::Io)?;
    let client = UreqCratesIoClient::new(crates_io_base_url()?);
    let runner = RealCommandRunner;

    run_cli_with_runner(cli, &current_dir, &client, &runner, stdout, stderr)
}

fn cargo_subcommand_args<I>(args: I) -> Vec<OsString>
where
    I: IntoIterator<Item = OsString>,
{
    let mut args = args.into_iter();
    let Some(program) = args.next() else {
        return Vec::new();
    };

    let mut normalised = vec![program];
    match args.next() {
        Some(first) if first == "barbican" => normalised.extend(args),
        Some(first) => {
            normalised.push(first);
            normalised.extend(args);
        }
        None => {}
    }

    normalised
}

pub fn run_cli_with_runner<C, R>(
    cli: Cli,
    current_dir: &Path,
    client: &C,
    runner: &R,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<ExitCode, CommandError>
where
    C: CratesIoClient + ?Sized,
    R: CommandRunner + ?Sized,
{
    run_cli_with_runner_at(
        cli,
        current_dir,
        client,
        runner,
        OffsetDateTime::now_utc(),
        stdout,
        stderr,
    )
}

pub fn run_cli_with_runner_at<C, R>(
    cli: Cli,
    current_dir: &Path,
    client: &C,
    runner: &R,
    now: OffsetDateTime,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<ExitCode, CommandError>
where
    C: CratesIoClient + ?Sized,
    R: CommandRunner + ?Sized,
{
    match cli.command {
        Command::Age {
            min_age_days,
            specs,
        } => age::run_age(
            min_age_days,
            specs,
            current_dir,
            client,
            now,
            stdout,
            stderr,
        ),
        Command::AgeLock {
            base_ref,
            base_lockfile,
            min_age_days,
            lockfile,
        } => age_lock::run_age_lock(
            base_ref.as_deref(),
            base_lockfile.as_deref(),
            min_age_days,
            &lockfile,
            current_dir,
            client,
            runner,
            now,
            stdout,
            stderr,
        ),
        Command::Update {
            dry_run,
            min_age_days,
            specs,
        } => update::run_update(
            dry_run,
            min_age_days,
            specs,
            current_dir,
            client,
            runner,
            now,
            stdout,
            stderr,
        ),
        Command::Resolve { min_age_days } => resolve::run_resolve(
            min_age_days,
            current_dir,
            client,
            runner,
            now,
            stdout,
            stderr,
        ),
        Command::Assess {
            base_ref,
            base_dir,
            policy_mode,
            min_age_days,
            lockfile,
        } => assess::run_assess(
            base_ref.as_deref(),
            base_dir.as_deref(),
            policy_mode,
            min_age_days,
            &lockfile,
            current_dir,
            client,
            runner,
            now,
            stdout,
            stderr,
        ),
        Command::Inspect {
            min_age_days,
            specs,
        } => inspect::run_inspect(
            min_age_days,
            specs,
            current_dir,
            client,
            now,
            stdout,
            stderr,
        ),
        Command::Pick { min_age_days, spec } => {
            pick::run_pick(min_age_days, spec, current_dir, client, now, stdout, stderr)
        }
        Command::Gatehouse { command } => {
            gatehouse::run_gatehouse(command, current_dir, client, runner, now, stdout, stderr)
        }
        Command::Policy { command } => policy::run_policy(command, current_dir, stdout),
        Command::Inventory => inventory::run_inventory(current_dir, runner, now, stdout),
        Command::Pin { command } => pin::run_pin(command, current_dir, now, stdout, stderr),
        Command::Review { base_dir } => {
            review::run_review(base_dir.as_deref(), current_dir, runner, stdout, stderr)
        }
        Command::Audit => audit::run_audit(current_dir, runner, now, stdout, stderr),
        Command::Verify => verify::run_verify(current_dir, runner, stdout, stderr),
    }
}

pub(super) struct ParseSpecsResult {
    pub(super) specs: Vec<ExactCrateSpec>,
    pub(super) failed: bool,
}

pub(super) fn parse_specs(
    raw_specs: Vec<String>,
    stderr: &mut dyn Write,
) -> Result<ParseSpecsResult, CommandError> {
    let mut specs = Vec::new();
    let mut failed = false;

    for raw_spec in raw_specs {
        match raw_spec.parse::<ExactCrateSpec>() {
            Ok(spec) => specs.push(spec),
            Err(error) => {
                writeln!(stderr, "FAIL {raw_spec}: {error}").map_err(CommandError::Io)?;
                failed = true;
            }
        }
    }

    Ok(ParseSpecsResult { specs, failed })
}

pub(super) fn finish_release_age_checks<C>(
    specs: &[ExactCrateSpec],
    minimum_days: u64,
    reviewed_release_age_exceptions: &ReviewedReleaseAgeExceptions,
    client: &C,
    now: OffsetDateTime,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<ExitCode, CommandError>
where
    C: CratesIoClient + ?Sized,
{
    let mut failed = false;
    let mut allowed_reports = Vec::new();
    let mut routine_reports = Vec::new();

    for spec in specs {
        let age_exception = reviewed_release_age_exceptions
            .honoured()
            .iter()
            .find(|exception| exception.spec() == spec);
        match check_release_age_at(client, spec, now, minimum_days, age_exception) {
            Ok(report) if matches!(report.outcome(), ReleaseAgeOutcome::Allowed) => {
                routine_reports.push(report);
            }
            Ok(report)
                if matches!(
                    report.outcome(),
                    ReleaseAgeOutcome::AllowedByException { .. }
                ) =>
            {
                allowed_reports.push(report);
            }
            Ok(report)
                if matches!(report.outcome(), ReleaseAgeOutcome::TooFresh)
                    && reviewed_release_age_exceptions
                        .missing_for_spec(spec)
                        .is_some() =>
            {
                let exception = reviewed_release_age_exceptions
                    .missing_for_spec(spec)
                    .expect("guard confirms missing exception");
                writeln!(
                    stderr,
                    "{}",
                    render_missing_release_age_exception_review_record(exception)
                )
                .map_err(CommandError::Io)?;
                failed = true;
            }
            Ok(report) => {
                writeln!(stderr, "{}", render_release_age_report(&report))
                    .map_err(CommandError::Io)?;
                failed = true;
            }
            Err(error) => {
                writeln!(stderr, "FAIL {spec}: {error}").map_err(CommandError::Io)?;
                failed = true;
            }
        }
    }

    for report in routine_reports {
        writeln!(stdout, "{}", render_release_age_report(&report)).map_err(CommandError::Io)?;
    }

    if !allowed_reports.is_empty() {
        writeln!(stdout, "Allowed policy exceptions:").map_err(CommandError::Io)?;
        for report in allowed_reports {
            writeln!(stdout, "  - {}", render_release_age_report(&report))
                .map_err(CommandError::Io)?;
        }
    }

    Ok(exit_code_from_policy_failures(failed))
}

pub(super) fn render_missing_release_age_exception_review_record(
    exception: &ReviewedReleaseAgeException,
) -> String {
    format!(
        "FAIL allowed release-age exception review record missing for {}: {}",
        exception.spec(),
        exception.review_record()
    )
}

pub(super) fn render_release_age_report(report: &ReleaseAgeReport) -> String {
    match report.outcome() {
        ReleaseAgeOutcome::Allowed => format!(
            "OK   {}: published {} ({} old)",
            report.spec(),
            report.published_at_raw(),
            format_age(report.age_seconds()),
        ),
        ReleaseAgeOutcome::AllowedByException {
            family,
            review_record,
        } => format!(
            "ALLOW {}: published {} ({} old), below the {}-day minimum; release-age exception allowed by reviewed family {family} ({review_record})",
            report.spec(),
            report.published_at_raw(),
            format_age(report.age_seconds()),
            report.minimum_days(),
        ),
        ReleaseAgeOutcome::Yanked => {
            format!("FAIL {}: version is yanked on crates.io", report.spec())
        }
        ReleaseAgeOutcome::TooFresh => format!(
            "FAIL {}: published {} ({} old), below the {}-day minimum; record a reviewed release-age exception in reviewed-targets.toml if this candidate is intentionally accepted",
            report.spec(),
            report.published_at_raw(),
            format_age(report.age_seconds()),
            report.minimum_days(),
        ),
        ReleaseAgeOutcome::ExceptionArtefactMismatch {
            family,
            review_record,
            expected,
            found,
        } => format!(
            "FAIL {}: release-age exception artefact mismatch for reviewed family {family} ({review_record}): expected sha256 {expected}, found {found}",
            report.spec(),
        ),
    }
}

pub(super) fn join_display<T: fmt::Display>(values: &[T], separator: &str) -> String {
    values
        .iter()
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join(separator)
}

pub(super) fn render_allowed_policy_exceptions<I, T>(
    stdout: &mut dyn Write,
    exceptions: I,
) -> Result<(), CommandError>
where
    I: IntoIterator<Item = T>,
    T: fmt::Display,
{
    let rendered = exceptions
        .into_iter()
        .map(|exception| escape_render_field(&exception.to_string()))
        .collect::<Vec<_>>();
    if rendered.is_empty() {
        return Ok(());
    }

    writeln!(stdout, "Allowed policy exceptions:").map_err(CommandError::Io)?;
    for exception in rendered {
        writeln!(stdout, "  - {exception}").map_err(CommandError::Io)?;
    }

    Ok(())
}

pub(super) fn escape_render_field(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            '\u{1b}' => escaped.push_str("\\x1b"),
            '\u{0}'..='\u{1f}'
            | '\u{7f}'..='\u{9f}'
            | '\u{061c}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200d}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2060}'
            | '\u{2066}'..='\u{2069}'
            | '\u{fff9}'..='\u{fffb}'
            | '\u{feff}' => {
                write!(&mut escaped, "\\x{:02x}", character as u32)
                    .expect("writing to a String cannot fail");
            }
            _ => escaped.push(character),
        }
    }

    escaped
}

pub(super) fn load_config(current_dir: &Path) -> Result<BarbicanConfig, CommandError> {
    match read_optional_text_no_symlink(current_dir, Path::new(CONFIG_FILE_NAME)) {
        Ok(Some(text)) => BarbicanConfig::from_toml_str(&text).map_err(CommandError::Config),
        Ok(None) => Ok(BarbicanConfig::default()),
        Err(source) => Err(CommandError::ConfigRead {
            path: CONFIG_FILE_NAME.to_owned(),
            source,
        }),
    }
}

pub(super) fn read_optional_text_no_symlink(
    root_dir: &Path,
    relative_path: &Path,
) -> io::Result<Option<String>> {
    let path = root_dir.join(relative_path);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(io::Error::other(format!(
            "{} is a symlink; refusing to read optional policy text",
            relative_path.display()
        ))),
        Ok(metadata) if metadata.is_file() => fs::read_to_string(path).map(Some),
        Ok(_) => Err(io::Error::other(format!(
            "{} is not a regular file",
            relative_path.display()
        ))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

pub(super) fn crates_io_base_url() -> Result<String, CommandError> {
    match env::var(CRATES_IO_BASE_URL_ENV) {
        Ok(value) => {
            validate_crates_io_base_url(&value)?;
            Ok(value)
        }
        Err(env::VarError::NotPresent) => Ok(DEFAULT_CRATES_IO_BASE_URL.to_owned()),
        Err(env::VarError::NotUnicode(_)) => Err(CommandError::InvalidEnvironment {
            name: CRATES_IO_BASE_URL_ENV,
        }),
    }
}

fn validate_crates_io_base_url(value: &str) -> Result<(), CommandError> {
    let lowercase = value.to_ascii_lowercase();

    if lowercase.starts_with("https://") {
        return Ok(());
    }

    let Some(authority_and_path) = lowercase.strip_prefix("http://") else {
        return Err(CommandError::InvalidCratesIoBaseUrl {
            value: value.to_owned(),
        });
    };

    if is_loopback_http_authority(authority_and_path) {
        Ok(())
    } else {
        Err(CommandError::InvalidCratesIoBaseUrl {
            value: value.to_owned(),
        })
    }
}

fn is_loopback_http_authority(authority_and_path: &str) -> bool {
    let authority = authority_and_path
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    if authority.contains('@') {
        return false;
    }

    let host = if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, remainder)) = rest.split_once(']') else {
            return false;
        };
        if !remainder.is_empty() && !remainder.starts_with(':') {
            return false;
        }
        host
    } else {
        authority.split(':').next().unwrap_or_default()
    };

    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

pub(super) fn load_current_lockfile(
    current_dir: &Path,
    lockfile: &Path,
) -> Result<barbican::Lockfile, CommandError> {
    let display = lockfile.display().to_string();
    load_lockfile_from_path(&current_dir.join(lockfile), &display)
}

pub(super) fn load_current_lockfile_with_text(
    current_dir: &Path,
    lockfile: &Path,
) -> Result<(barbican::Lockfile, String), CommandError> {
    let display = lockfile.display().to_string();
    load_lockfile_with_text_from_path(&current_dir.join(lockfile), &display)
}

pub(super) fn load_current_lockfile_text(
    current_dir: &Path,
    lockfile: &Path,
) -> Result<String, CommandError> {
    let display = lockfile.display().to_string();
    load_lockfile_text_from_path(&current_dir.join(lockfile), &display)
}

pub(super) fn load_lockfile_text_from_path(
    path: &Path,
    display: &str,
) -> Result<String, CommandError> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(text),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            Err(CommandError::LockfileMissing {
                path: display.to_owned(),
            })
        }
        Err(source) => Err(CommandError::LockfileRead {
            path: display.to_owned(),
            source,
        }),
    }
}

pub(super) fn load_lockfile_from_path(
    path: &Path,
    display: &str,
) -> Result<barbican::Lockfile, CommandError> {
    let (lockfile, _) = load_lockfile_with_text_from_path(path, display)?;

    Ok(lockfile)
}

fn load_lockfile_with_text_from_path(
    path: &Path,
    display: &str,
) -> Result<(barbican::Lockfile, String), CommandError> {
    let text = load_lockfile_text_from_path(path, display)?;

    let lockfile = parse_lockfile(&text).map_err(|source| CommandError::LockfileParse {
        path: display.to_owned(),
        source,
    })?;

    Ok((lockfile, text))
}

pub(super) fn load_git_base_lockfile<R>(
    current_dir: &Path,
    runner: &R,
    base_ref: &str,
    lockfile: &Path,
) -> Result<barbican::Lockfile, CommandError>
where
    R: CommandRunner + ?Sized,
{
    let base_object = format!("{base_ref}:{}", lockfile.display());
    let base_lockfile_text = runner
        .git_show(current_dir, &base_object)
        .map_err(|source| CommandError::GitRead {
            object: base_object,
            source,
        })?;

    parse_lockfile(&base_lockfile_text).map_err(|source| CommandError::LockfileParse {
        path: format!("{base_ref}:{}", lockfile.display()),
        source,
    })
}

pub(super) fn load_manifest_dependencies_from_root(
    root_dir: &Path,
) -> Result<Vec<barbican::CargoManifestDependency>, CommandError> {
    let mut dependencies = Vec::new();

    for (relative_display, text) in load_manifest_texts_from_root(root_dir)? {
        dependencies.extend(parse_manifest_dependency_text(&relative_display, &text)?);
    }

    Ok(dependencies)
}

pub(super) fn load_current_manifest_direct_requirements(
    current_dir: &Path,
) -> Result<Vec<barbican::CargoManifestDirectRequirement>, CommandError> {
    parse_manifest_requirements(&load_manifest_texts_from_root(current_dir)?)
}

pub(super) fn parse_manifest_requirements(
    manifest_texts: &[(String, String)],
) -> Result<Vec<barbican::CargoManifestDirectRequirement>, CommandError> {
    let mut dependencies = Vec::new();

    for (relative_display, text) in manifest_texts {
        dependencies.extend(parse_manifest_direct_requirement_text(
            relative_display,
            text,
        )?);
    }

    Ok(dependencies)
}

pub(super) fn load_manifest_texts_from_root(
    root_dir: &Path,
) -> Result<Vec<(String, String)>, CommandError> {
    let manifest_paths = workspace_manifest_paths(root_dir)?;
    let mut manifests = Vec::new();

    for manifest_path in manifest_paths {
        let relative_display = manifest_path.display().to_string();
        let text = fs::read_to_string(root_dir.join(&manifest_path)).map_err(|source| {
            CommandError::ManifestRead {
                path: relative_display.clone(),
                source,
            }
        })?;
        manifests.push((relative_display, text));
    }

    Ok(manifests)
}

pub(super) fn load_base_manifest_dependencies<R>(
    current_dir: &Path,
    runner: &R,
    base_ref: &str,
) -> Result<Vec<barbican::CargoManifestDependency>, CommandError>
where
    R: CommandRunner + ?Sized,
{
    let manifest_paths = workspace_manifest_paths(current_dir)?;
    let mut dependencies = Vec::new();

    for manifest_path in manifest_paths {
        let relative_display = manifest_path.display().to_string();
        let text = match read_base_manifest_text(current_dir, runner, base_ref, &relative_display)?
        {
            Some(text) => text,
            None => continue,
        };
        dependencies.extend(parse_manifest_dependency_text(&relative_display, &text)?);
    }

    Ok(dependencies)
}

fn read_base_manifest_text<R>(
    current_dir: &Path,
    runner: &R,
    base_ref: &str,
    relative_path: &str,
) -> Result<Option<String>, CommandError>
where
    R: CommandRunner + ?Sized,
{
    let object = format!("{base_ref}:{relative_path}");

    match runner.git_show(current_dir, &object) {
        Ok(text) => Ok(Some(text)),
        Err(error) if git_show_reports_missing_path_at_ref(&error, relative_path, base_ref) => {
            Ok(None)
        }
        Err(source) => Err(CommandError::GitRead { object, source }),
    }
}

pub(super) fn parse_manifest_dependency_text(
    path: &str,
    text: &str,
) -> Result<Vec<barbican::CargoManifestDependency>, CommandError> {
    let parsed =
        parse_manifest_dependencies(path, text).map_err(|source| CommandError::ManifestParse {
            path: path.to_owned(),
            source,
        })?;

    Ok(parsed.into_iter().collect())
}

pub(super) fn parse_manifest_direct_requirement_text(
    path: &str,
    text: &str,
) -> Result<Vec<barbican::CargoManifestDirectRequirement>, CommandError> {
    let parsed = parse_manifest_direct_requirements(path, text).map_err(|source| {
        CommandError::ManifestParse {
            path: path.to_owned(),
            source,
        }
    })?;

    Ok(parsed.into_iter().collect())
}

pub(super) fn load_reviewed_targets(
    current_dir: &Path,
    path: &Path,
) -> Result<Option<ReviewedTargets>, CommandError> {
    let text = match read_optional_text_no_symlink(current_dir, path) {
        Ok(Some(text)) => text,
        Ok(None) => return Ok(None),
        Err(source) => {
            return Err(CommandError::ReviewedTargetsRead {
                path: path.display().to_string(),
                source,
            });
        }
    };
    let reviewed_targets = parse_reviewed_targets_toml(&text).map_err(|source| {
        CommandError::ReviewedTargetsParse {
            path: path.display().to_string(),
            source: Box::new(source),
        }
    })?;

    Ok(Some(reviewed_targets))
}

pub(super) fn load_reviewed_release_age_exceptions(
    current_dir: &Path,
    path: &Path,
) -> Result<ReviewedReleaseAgeExceptions, CommandError> {
    let Some(reviewed_targets) = load_reviewed_targets(current_dir, path)? else {
        return Ok(ReviewedReleaseAgeExceptions::default());
    };

    Ok(collect_reviewed_release_age_exceptions(
        &reviewed_targets,
        current_dir,
    ))
}

pub(super) fn collect_reviewed_release_age_exceptions(
    reviewed_targets: &ReviewedTargets,
    current_dir: &Path,
) -> ReviewedReleaseAgeExceptions {
    let mut exceptions = ReviewedReleaseAgeExceptions::default();

    for exception in reviewed_targets.release_age_exceptions() {
        if review_record_exists(current_dir, exception.review_record()) {
            exceptions.honoured.push(exception);
        } else {
            exceptions.missing_review_records.push(exception);
        }
    }

    exceptions
}

#[derive(Debug, Clone, Default)]
pub(super) struct ReviewedReleaseAgeExceptions {
    honoured: Vec<ReviewedReleaseAgeException>,
    missing_review_records: Vec<ReviewedReleaseAgeException>,
}

impl ReviewedReleaseAgeExceptions {
    pub(super) fn honoured(&self) -> &[ReviewedReleaseAgeException] {
        &self.honoured
    }

    pub(super) fn missing_for_spec(
        &self,
        spec: &ExactCrateSpec,
    ) -> Option<&ReviewedReleaseAgeException> {
        self.missing_review_records
            .iter()
            .find(|exception| exception.spec() == spec)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ReviewRecordCheck {
    family_name: String,
    review_record: String,
    exists: bool,
}

impl ReviewRecordCheck {
    pub(super) fn family_name(&self) -> &str {
        &self.family_name
    }

    pub(super) fn review_record(&self) -> &str {
        &self.review_record
    }

    pub(super) fn is_success(&self) -> bool {
        self.exists
    }
}

pub(super) fn check_review_record_paths(
    current_dir: &Path,
    reviewed_targets: &ReviewedTargets,
) -> Vec<ReviewRecordCheck> {
    reviewed_targets
        .rust_families()
        .iter()
        .map(|family| {
            let review_record = family.review_record().to_owned();

            ReviewRecordCheck {
                family_name: family.name().to_owned(),
                exists: review_record_exists(current_dir, &review_record),
                review_record,
            }
        })
        .collect()
}

pub(super) fn review_record_exists(current_dir: &Path, review_record: &str) -> bool {
    fs::symlink_metadata(current_dir.join(review_record))
        .map(|metadata| metadata.is_file())
        .unwrap_or(false)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct NativeDelegatedIgnore {
    source: &'static str,
    advisory_ids: Vec<String>,
}

impl NativeDelegatedIgnore {
    pub(super) fn source(&self) -> &'static str {
        self.source
    }

    pub(super) fn advisory_ids(&self) -> &[String] {
        &self.advisory_ids
    }
}

pub(super) fn load_native_delegated_ignores(
    current_dir: &Path,
) -> Result<Vec<NativeDelegatedIgnore>, CommandError> {
    let deny_toml = read_optional_text_no_symlink(current_dir, Path::new("deny.toml"))
        .map_err(CommandError::Io)?;
    let audit_toml = read_optional_text_no_symlink(current_dir, Path::new(".cargo/audit.toml"))
        .map_err(CommandError::Io)?;
    let mut ignores = Vec::new();
    if let Some(entry) = native_ignore_entry("deny.toml", deny_toml.as_deref())? {
        ignores.push(entry);
    }
    if let Some(entry) = native_ignore_entry(".cargo/audit.toml", audit_toml.as_deref())? {
        ignores.push(entry);
    }

    Ok(ignores)
}

fn native_ignore_entry(
    source: &'static str,
    text: Option<&str>,
) -> Result<Option<NativeDelegatedIgnore>, CommandError> {
    let Some(text) = text else {
        return Ok(None);
    };
    let advisory_ids = advisory_ignores_from_toml(text)
        .map_err(|error| CommandError::Io(io::Error::other(error)))?;

    Ok((!advisory_ids.is_empty()).then_some(NativeDelegatedIgnore {
        source,
        advisory_ids,
    }))
}

pub(super) fn workspace_manifest_paths(current_dir: &Path) -> Result<Vec<PathBuf>, CommandError> {
    let mut paths = BTreeSet::from([PathBuf::from("Cargo.toml")]);
    let root_manifest_text =
        fs::read_to_string(current_dir.join("Cargo.toml")).map_err(|source| {
            CommandError::ManifestRead {
                path: "Cargo.toml".to_owned(),
                source,
            }
        })?;
    for member in parse_workspace_member_manifest_paths("Cargo.toml", &root_manifest_text).map_err(
        |source| CommandError::ManifestParse {
            path: "Cargo.toml".to_owned(),
            source,
        },
    )? {
        paths.insert(PathBuf::from(member));
    }

    let mut search_roots = parse_workspace_member_glob_roots("Cargo.toml", &root_manifest_text)
        .map_err(|source| CommandError::ManifestParse {
            path: "Cargo.toml".to_owned(),
            source,
        })?
        .into_iter()
        .map(PathBuf::from)
        .collect::<BTreeSet<_>>();
    search_roots.insert(PathBuf::from("crates"));
    for relative_root in minimal_search_roots(search_roots) {
        let root = current_dir.join(relative_root);
        if root.is_dir() {
            collect_relative_files_matching(&root, current_dir, &mut paths, &mut |path| {
                path.file_name().is_some_and(|name| name == "Cargo.toml")
            })
            .map_err(CommandError::Io)?;
        }
    }

    Ok(paths.into_iter().collect())
}

fn minimal_search_roots(roots: BTreeSet<PathBuf>) -> Vec<PathBuf> {
    if roots.iter().any(|root| root == Path::new(".")) {
        return vec![PathBuf::from(".")];
    }

    let mut selected = Vec::new();

    for root in roots {
        if selected
            .iter()
            .any(|selected_root: &PathBuf| root.starts_with(selected_root))
        {
            continue;
        }
        selected.push(root);
    }

    selected
}

pub(super) fn review_paths(current_dir: &Path) -> Result<Vec<PathBuf>, CommandError> {
    let mut paths = workspace_manifest_paths(current_dir)?
        .into_iter()
        .collect::<BTreeSet<_>>();
    insert_review_root_paths(&mut paths);
    paths.insert(PathBuf::from(REVIEW_RECORDS_DIR));

    Ok(paths.into_iter().collect())
}

pub(super) fn insert_review_root_paths(paths: &mut BTreeSet<PathBuf>) {
    paths.extend(REVIEW_ROOT_FILE_PATHS.into_iter().map(PathBuf::from));
}

pub(super) fn collect_relative_files_matching<F>(
    directory: &Path,
    repo_root: &Path,
    paths: &mut BTreeSet<PathBuf>,
    include_file: &mut F,
) -> io::Result<()>
where
    F: FnMut(&Path) -> bool,
{
    debug_assert!(directory.is_dir());

    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();

        if entry.file_type()?.is_dir() {
            if path
                .file_name()
                .is_some_and(|name| name == ".git" || name == "target")
            {
                continue;
            }
            collect_relative_files_matching(&path, repo_root, paths, include_file)?;
            continue;
        }

        if (*include_file)(&path) {
            let relative = path
                .strip_prefix(repo_root)
                .map_err(io::Error::other)?
                .to_path_buf();
            paths.insert(relative);
        }
    }

    Ok(())
}

pub(super) fn fail(
    stderr: &mut dyn Write,
    detail: impl fmt::Display,
) -> Result<ExitCode, CommandError> {
    writeln!(stderr, "FAIL {detail}").map_err(CommandError::Io)?;
    Ok(ExitCode::from(1))
}

fn git_show_reports_missing_path_at_ref(error: &RunnerError, path: &str, base_ref: &str) -> bool {
    let missing_messages = [
        format!("path '{path}' does not exist in '{base_ref}'"),
        format!("path '{path}' exists on disk, but not in '{base_ref}'"),
    ];

    match error {
        RunnerError::Exited { stderr, .. } => missing_messages
            .iter()
            .any(|message| stderr.contains(message)),
        RunnerError::Spawn(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::PathBuf;

    use super::scratch_dir::ScratchDir;
    use super::{
        escape_diagnostic_for_terminal, escape_render_field, minimal_search_roots,
        review_record_exists, validate_crates_io_base_url,
    };

    #[test]
    fn accepts_https_crates_io_base_urls() {
        validate_crates_io_base_url("https://crates.io").expect("https should be accepted");
        validate_crates_io_base_url("https://example.invalid:8443/api")
            .expect("https with host and path should be accepted");
    }

    #[test]
    fn accepts_loopback_http_crates_io_base_urls() {
        for url in [
            "http://127.0.0.1:8080",
            "http://localhost:8080/api",
            "http://[::1]:8080",
        ] {
            validate_crates_io_base_url(url).expect("loopback HTTP should be accepted");
        }
    }

    #[test]
    fn rejects_non_loopback_or_non_http_crates_io_base_urls() {
        for url in [
            "http://example.com",
            "http://localhost.evil",
            "http://localhost@evil.com",
            "http://127.0.0.1@evil.com",
            "http://127.0.0.1:80@evil.com",
            "http://192.168.0.1",
            "http://[::1]:80@evil.com",
            "http://[::1]evil",
            "ftp://crates.io",
            "file:///tmp/crates",
        ] {
            validate_crates_io_base_url(url).expect_err("base URL should fail");
        }
    }

    #[test]
    fn minimal_search_roots_collapses_nested_and_top_level_roots() {
        assert_eq!(
            minimal_search_roots(BTreeSet::from([
                PathBuf::from("libs"),
                PathBuf::from("libs/core"),
                PathBuf::from("tools"),
            ])),
            vec![PathBuf::from("libs"), PathBuf::from("tools")]
        );
        assert_eq!(
            minimal_search_roots(BTreeSet::from([
                PathBuf::from("."),
                PathBuf::from("crates"),
                PathBuf::from("libs"),
            ])),
            vec![PathBuf::from(".")]
        );
    }

    #[test]
    fn escape_render_field_escapes_bidi_and_zero_width_controls() {
        assert_eq!(
            escape_render_field("safe\u{202e}name\u{200b}field\u{200f}\u{2060}"),
            "safe\\x202ename\\x200bfield\\x200f\\x2060"
        );
    }

    #[test]
    fn escape_diagnostic_for_terminal_escapes_bidi_and_zero_width_controls() {
        assert_eq!(
            escape_diagnostic_for_terminal("line\u{2066}value\u{feff}\u{200f}\u{2060}\n\tcaret"),
            "line\\x2066value\\xfeff\\x200f\\x2060\n\tcaret"
        );
    }

    #[cfg(unix)]
    #[test]
    fn review_record_symlinks_do_not_satisfy_gates() {
        let scratch = ScratchDir::create("cargo-barbican-review-record-test", false)
            .expect("scratch dir should create");
        let real_record = scratch.path().join("real.md");
        fs::write(&real_record, "review").expect("real review record should write");
        let review_dir = scratch.path().join("docs/dependency-reviews");
        fs::create_dir_all(&review_dir).expect("review dir should create");
        std::os::unix::fs::symlink(&real_record, review_dir.join("linked.md"))
            .expect("review record symlink should create");

        assert!(!review_record_exists(
            scratch.path(),
            "docs/dependency-reviews/linked.md"
        ));
    }
}

pub(super) fn exit_code_from_policy_failures(failed: bool) -> ExitCode {
    if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

#[derive(Debug)]
pub enum CommandError {
    Config(ConfigLoadError),
    ConfigRead {
        path: String,
        source: io::Error,
    },
    GitRead {
        object: String,
        source: RunnerError,
    },
    InvalidEnvironment {
        name: &'static str,
    },
    InvalidCratesIoBaseUrl {
        value: String,
    },
    PinAddConfigWrite {
        config_path: String,
        review_record_path: String,
        source: io::Error,
        cleanup_source: Option<io::Error>,
    },
    LockfileMissing {
        path: String,
    },
    LockfileParse {
        path: String,
        source: barbican::LockfileError,
    },
    LockfileRead {
        path: String,
        source: io::Error,
    },
    LockfileRestore {
        path: String,
        source: io::Error,
    },
    ManifestParse {
        path: String,
        source: barbican::CargoManifestError,
    },
    ManifestRead {
        path: String,
        source: io::Error,
    },
    ReviewedTargetsParse {
        path: String,
        source: Box<ReviewedTargetsError>,
    },
    ReviewedTargetsRead {
        path: String,
        source: io::Error,
    },
    ScaffoldIo {
        path: String,
        source: io::Error,
    },
    Io(io::Error),
}

impl fmt::Display for CommandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(error) => {
                write!(
                    formatter,
                    "{}",
                    escape_diagnostic_for_terminal(&error.to_string())
                )
            }
            Self::ConfigRead { path, source } => {
                write!(
                    formatter,
                    "{}",
                    escape_diagnostic_for_terminal(&format!("unable to read {path}: {source}"))
                )
            }
            Self::GitRead { object, source } => {
                write!(
                    formatter,
                    "{}",
                    escape_diagnostic_for_terminal(&format!(
                        "unable to read {object} from git: {source}"
                    ))
                )
            }
            Self::InvalidEnvironment { name } => {
                write!(formatter, "environment variable {name} is not valid UTF-8")
            }
            Self::InvalidCratesIoBaseUrl { value } => write!(
                formatter,
                "{}",
                escape_diagnostic_for_terminal(&format!(
                    "{CRATES_IO_BASE_URL_ENV} must use https://, or http:// loopback for local tests: {value}"
                ))
            ),
            Self::PinAddConfigWrite {
                config_path,
                review_record_path,
                source,
                cleanup_source,
            } => {
                let cleanup = match cleanup_source {
                    Some(cleanup_source) => format!(
                        "; also unable to remove orphaned review record {review_record_path}: {cleanup_source}"
                    ),
                    None => format!("; removed orphaned review record {review_record_path}"),
                };
                write!(
                    formatter,
                    "{}",
                    escape_diagnostic_for_terminal(&format!(
                        "unable to write {config_path} after creating review record {review_record_path}: {source}{cleanup}"
                    ))
                )
            }
            Self::LockfileMissing { path } => {
                write!(
                    formatter,
                    "{}",
                    escape_diagnostic_for_terminal(&format!("{path}: lockfile not found"))
                )
            }
            Self::LockfileParse { path, source } => {
                write!(
                    formatter,
                    "{}",
                    escape_diagnostic_for_terminal(&format!("{path}: {source}"))
                )
            }
            Self::LockfileRead { path, source } => {
                write!(
                    formatter,
                    "{}",
                    escape_diagnostic_for_terminal(&format!("unable to read {path}: {source}"))
                )
            }
            Self::LockfileRestore { path, source } => {
                write!(
                    formatter,
                    "{}",
                    escape_diagnostic_for_terminal(&format!(
                        "unable to restore {path} after a failed lockfile operation: {source}"
                    ))
                )
            }
            Self::ManifestParse { path, source } => {
                write!(
                    formatter,
                    "{}",
                    escape_diagnostic_for_terminal(&format!("{path}: {source}"))
                )
            }
            Self::ManifestRead { path, source } => {
                write!(
                    formatter,
                    "{}",
                    escape_diagnostic_for_terminal(&format!("unable to read {path}: {source}"))
                )
            }
            Self::ReviewedTargetsParse { path, source } => {
                write!(
                    formatter,
                    "{}",
                    escape_diagnostic_for_terminal(&format!("{path}: {source}"))
                )
            }
            Self::ReviewedTargetsRead { path, source } => {
                write!(
                    formatter,
                    "{}",
                    escape_diagnostic_for_terminal(&format!("unable to read {path}: {source}"))
                )
            }
            Self::ScaffoldIo { path, source } => {
                write!(
                    formatter,
                    "{}",
                    escape_diagnostic_for_terminal(&format!(
                        "unable to update policy scaffold {path}: {source}"
                    ))
                )
            }
            Self::Io(error) => {
                write!(
                    formatter,
                    "{}",
                    escape_diagnostic_for_terminal(&error.to_string())
                )
            }
        }
    }
}

pub(super) fn escape_diagnostic_for_terminal(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            // Preserve TOML's multi-line diagnostics while escaping terminal controls.
            '\n' | '\t' => escaped.push(character),
            '\r' => escaped.push_str("\\r"),
            '\u{1b}' => escaped.push_str("\\x1b"),
            '\u{0000}'..='\u{0008}'
            | '\u{000b}'..='\u{001f}'
            | '\u{007f}'
            | '\u{0080}'..='\u{009f}'
            | '\u{061c}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200d}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2060}'
            | '\u{2066}'..='\u{2069}'
            | '\u{fff9}'..='\u{fffb}'
            | '\u{feff}' => {
                write!(&mut escaped, "\\x{:02x}", character as u32)
                    .expect("writing to a String cannot fail");
            }
            _ => escaped.push(character),
        }
    }

    escaped
}

impl std::error::Error for CommandError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Config(error) => Some(error),
            Self::ConfigRead { source, .. } => Some(source),
            Self::GitRead { source, .. } => Some(source),
            Self::InvalidEnvironment { .. } => None,
            Self::InvalidCratesIoBaseUrl { .. } => None,
            Self::PinAddConfigWrite { source, .. } => Some(source),
            Self::LockfileMissing { .. } => None,
            Self::LockfileParse { source, .. } => Some(source),
            Self::LockfileRead { source, .. } => Some(source),
            Self::LockfileRestore { source, .. } => Some(source),
            Self::ManifestParse { source, .. } => Some(source),
            Self::ManifestRead { source, .. } => Some(source),
            Self::ReviewedTargetsParse { source, .. } => Some(source),
            Self::ReviewedTargetsRead { source, .. } => Some(source),
            Self::ScaffoldIo { source, .. } => Some(source),
            Self::Io(error) => Some(error),
        }
    }
}
