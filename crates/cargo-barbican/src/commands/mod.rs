mod age;
mod age_lock;
mod assess;
mod audit;
mod diff_render;
mod inspect;
mod pin_check;
mod resolve;
mod review;
mod verify;

use std::collections::BTreeSet;
use std::env;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use barbican::{
    BarbicanConfig, ConfigLoadError, CratesIoClient, ExactCrateSpec, OffsetDateTime,
    ReleaseAgeOutcome, ReleaseAgeReport, ReviewedTargets, ReviewedTargetsError,
    check_release_age_at, format_age, parse_lockfile, parse_manifest_dependencies,
    parse_manifest_direct_requirements, parse_reviewed_targets_toml,
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
    let cli = Cli::parse();
    let current_dir = env::current_dir().map_err(CommandError::Io)?;
    let client = UreqCratesIoClient::new(crates_io_base_url()?);
    let runner = RealCommandRunner;

    run_cli_with_runner(cli, &current_dir, &client, &runner, stdout, stderr)
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
        Command::Resolve {
            dry_run,
            min_age_days,
            specs,
        } => resolve::run_resolve(
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
        Command::Assess {
            base_ref,
            base_dir,
            min_age_days,
            lockfile,
        } => assess::run_assess(
            base_ref.as_deref(),
            base_dir.as_deref(),
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
        Command::PinCheck { config } => pin_check::run_pin_check(&config, current_dir, stdout),
        Command::Review { base_dir } => {
            review::run_review(base_dir.as_deref(), current_dir, runner, stdout, stderr)
        }
        Command::Audit => audit::run_audit(current_dir, runner, stderr),
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
    client: &C,
    now: OffsetDateTime,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<ExitCode, CommandError>
where
    C: CratesIoClient + ?Sized,
{
    let mut failed = false;

    for spec in specs {
        match check_release_age_at(client, spec, now, minimum_days) {
            Ok(report) if report.is_success() => {
                writeln!(stdout, "{}", render_release_age_report(&report))
                    .map_err(CommandError::Io)?;
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

    Ok(exit_code_from_policy_failures(failed))
}

pub(super) fn render_release_age_report(report: &ReleaseAgeReport) -> String {
    match report.outcome() {
        ReleaseAgeOutcome::Allowed => format!(
            "OK   {}: published {} ({} old)",
            report.spec(),
            report.published_at_raw(),
            format_age(report.age_seconds()),
        ),
        ReleaseAgeOutcome::Yanked => {
            format!("FAIL {}: version is yanked on crates.io", report.spec())
        }
        ReleaseAgeOutcome::TooFresh => format!(
            "FAIL {}: published {} ({} old), below the {}-day minimum",
            report.spec(),
            report.published_at_raw(),
            format_age(report.age_seconds()),
            report.minimum_days(),
        ),
    }
}

pub(super) fn load_config(current_dir: &Path) -> Result<BarbicanConfig, CommandError> {
    let path = current_dir.join(CONFIG_FILE_NAME);

    match fs::read_to_string(&path) {
        Ok(text) => BarbicanConfig::from_toml_str(&text).map_err(CommandError::Config),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(BarbicanConfig::default()),
        Err(source) => Err(CommandError::ConfigRead {
            path: path.display().to_string(),
            source,
        }),
    }
}

pub(super) fn crates_io_base_url() -> Result<String, CommandError> {
    match env::var(CRATES_IO_BASE_URL_ENV) {
        Ok(value) => Ok(value),
        Err(env::VarError::NotPresent) => Ok(DEFAULT_CRATES_IO_BASE_URL.to_owned()),
        Err(env::VarError::NotUnicode(_)) => Err(CommandError::InvalidEnvironment {
            name: CRATES_IO_BASE_URL_ENV,
        }),
    }
}

pub(super) fn load_current_lockfile(
    current_dir: &Path,
    lockfile: &Path,
) -> Result<barbican::Lockfile, CommandError> {
    let display = lockfile.display().to_string();
    load_lockfile_from_path(&current_dir.join(lockfile), &display)
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
    let text = load_lockfile_text_from_path(path, display)?;

    parse_lockfile(&text).map_err(|source| CommandError::LockfileParse {
        path: display.to_owned(),
        source,
    })
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
    let manifest_paths = workspace_manifest_paths(root_dir).map_err(CommandError::Io)?;
    let mut dependencies = Vec::new();

    for manifest_path in manifest_paths {
        let relative_display = manifest_path.display().to_string();
        let text = fs::read_to_string(root_dir.join(&manifest_path)).map_err(|source| {
            CommandError::ManifestRead {
                path: relative_display.clone(),
                source,
            }
        })?;
        dependencies.extend(parse_manifest_dependency_text(&relative_display, &text)?);
    }

    Ok(dependencies)
}

pub(super) fn load_current_manifest_dependencies(
    current_dir: &Path,
) -> Result<Vec<barbican::CargoManifestDependency>, CommandError> {
    load_manifest_dependencies_from_root(current_dir)
}

pub(super) fn load_current_manifest_direct_requirements(
    current_dir: &Path,
) -> Result<Vec<barbican::CargoManifestDirectRequirement>, CommandError> {
    let manifest_paths = workspace_manifest_paths(current_dir).map_err(CommandError::Io)?;
    let mut dependencies = Vec::new();

    for manifest_path in manifest_paths {
        let relative_display = manifest_path.display().to_string();
        let text = fs::read_to_string(current_dir.join(&manifest_path)).map_err(|source| {
            CommandError::ManifestRead {
                path: relative_display.clone(),
                source,
            }
        })?;
        dependencies.extend(parse_manifest_direct_requirement_text(
            &relative_display,
            &text,
        )?);
    }

    Ok(dependencies)
}

pub(super) fn load_manifest_dependencies_from_base_dir(
    base_dir: &Path,
) -> Result<Vec<barbican::CargoManifestDependency>, CommandError> {
    load_manifest_dependencies_from_root(base_dir)
}

pub(super) fn load_base_manifest_dependencies<R>(
    current_dir: &Path,
    runner: &R,
    base_ref: &str,
) -> Result<Vec<barbican::CargoManifestDependency>, CommandError>
where
    R: CommandRunner + ?Sized,
{
    let manifest_paths = workspace_manifest_paths(current_dir).map_err(CommandError::Io)?;
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
    let config_path = current_dir.join(path);
    let text = match fs::read_to_string(&config_path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
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
            source,
        }
    })?;

    Ok(Some(reviewed_targets))
}

pub(super) fn workspace_manifest_paths(current_dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut paths = BTreeSet::from([PathBuf::from("Cargo.toml")]);
    let crates_dir = current_dir.join("crates");

    if crates_dir.is_dir() {
        collect_relative_files_matching(&crates_dir, current_dir, &mut paths, &mut |path| {
            path.file_name().is_some_and(|name| name == "Cargo.toml")
        })?;
    }

    Ok(paths.into_iter().collect())
}

pub(super) fn review_paths(current_dir: &Path) -> io::Result<Vec<PathBuf>> {
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
    if !directory.is_dir() {
        return Ok(());
    }

    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();

        if entry.file_type()?.is_dir() {
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
        source: ReviewedTargetsError,
    },
    ReviewedTargetsRead {
        path: String,
        source: io::Error,
    },
    Io(io::Error),
}

impl fmt::Display for CommandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(error) => write!(formatter, "{error}"),
            Self::ConfigRead { path, source } => {
                write!(formatter, "unable to read {path}: {source}")
            }
            Self::GitRead { object, source } => {
                write!(formatter, "unable to read {object} from git: {source}")
            }
            Self::InvalidEnvironment { name } => {
                write!(formatter, "environment variable {name} is not valid UTF-8")
            }
            Self::LockfileMissing { path } => write!(formatter, "{path}: lockfile not found"),
            Self::LockfileParse { path, source } => write!(formatter, "{path}: {source}"),
            Self::LockfileRead { path, source } => {
                write!(formatter, "unable to read {path}: {source}")
            }
            Self::ManifestParse { path, source } => {
                write!(formatter, "{path}: {source}")
            }
            Self::ManifestRead { path, source } => {
                write!(formatter, "unable to read {path}: {source}")
            }
            Self::ReviewedTargetsParse { path, source } => write!(formatter, "{path}: {source}"),
            Self::ReviewedTargetsRead { path, source } => {
                write!(formatter, "unable to read {path}: {source}")
            }
            Self::Io(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for CommandError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Config(error) => Some(error),
            Self::ConfigRead { source, .. } => Some(source),
            Self::GitRead { source, .. } => Some(source),
            Self::InvalidEnvironment { .. } => None,
            Self::LockfileMissing { .. } => None,
            Self::LockfileParse { source, .. } => Some(source),
            Self::LockfileRead { source, .. } => Some(source),
            Self::ManifestParse { source, .. } => Some(source),
            Self::ManifestRead { source, .. } => Some(source),
            Self::ReviewedTargetsParse { source, .. } => Some(source),
            Self::ReviewedTargetsRead { source, .. } => Some(source),
            Self::Io(error) => Some(error),
        }
    }
}
