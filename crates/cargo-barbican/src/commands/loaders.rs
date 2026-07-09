use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::io;
use std::path::Path;

use barbican::{
    BarbicanConfig, ExactCrateSpec, ReviewRecordFact, ReviewedReleaseAgeException, ReviewedTargets,
    advisory_ignores_from_toml, parse_lockfile, parse_manifest_dependencies,
    parse_manifest_direct_requirements, parse_reviewed_targets_toml,
    parse_workspace_dependency_requirements,
};

use crate::cli::REVIEWED_TARGETS_CONFIG_FILE;
use crate::command_runner::{CommandRunner, RunnerError};
use crate::crates_io_http::{CRATES_IO_BASE_URL_ENV, DEFAULT_CRATES_IO_BASE_URL};

use super::CommandError;

const CONFIG_FILE_NAME: &str = "barbican.toml";
const CARGO_CONFIG_CANDIDATE_PATHS: [&str; 2] = [".cargo/config.toml", ".cargo/config"];

pub(crate) fn load_config(current_dir: &Path) -> Result<BarbicanConfig, CommandError> {
    match read_optional_text_no_symlink(current_dir, Path::new(CONFIG_FILE_NAME)) {
        Ok(Some(text)) => BarbicanConfig::from_toml_str(&text).map_err(CommandError::Config),
        Ok(None) => Ok(BarbicanConfig::default()),
        Err(source) => Err(CommandError::ConfigRead {
            path: CONFIG_FILE_NAME.to_owned(),
            source,
        }),
    }
}

pub(crate) fn read_optional_text_no_symlink(
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

pub(crate) fn crates_io_base_url() -> Result<String, CommandError> {
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

pub(crate) fn load_current_lockfile(
    current_dir: &Path,
    lockfile: &Path,
) -> Result<barbican::Lockfile, CommandError> {
    let display = lockfile.display().to_string();
    load_lockfile_from_path(&current_dir.join(lockfile), &display)
}

pub(crate) fn load_current_lockfile_with_text(
    current_dir: &Path,
    lockfile: &Path,
) -> Result<(barbican::Lockfile, String), CommandError> {
    let display = lockfile.display().to_string();
    load_lockfile_with_text_from_path(&current_dir.join(lockfile), &display)
}

pub(crate) fn load_current_lockfile_text(
    current_dir: &Path,
    lockfile: &Path,
) -> Result<String, CommandError> {
    let display = lockfile.display().to_string();
    load_lockfile_text_from_path(&current_dir.join(lockfile), &display)
}

pub(crate) fn load_lockfile_text_from_path(
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

pub(crate) fn load_lockfile_from_path(
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

pub(crate) fn load_git_base_lockfile<R>(
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

pub(crate) fn load_manifest_dependencies_from_root(
    root_dir: &Path,
) -> Result<Vec<barbican::CargoManifestDependency>, CommandError> {
    let mut dependencies = Vec::new();

    for (relative_display, text) in load_manifest_texts_from_root(root_dir)? {
        dependencies.extend(parse_manifest_dependency_text(&relative_display, &text)?);
    }

    Ok(dependencies)
}

pub(crate) fn load_current_manifest_direct_requirements(
    current_dir: &Path,
) -> Result<Vec<barbican::CargoManifestDirectRequirement>, CommandError> {
    parse_manifest_requirements(&load_manifest_texts_from_root(current_dir)?)
}

pub(crate) fn load_current_manifest_direct_and_workspace_requirements(
    current_dir: &Path,
) -> Result<
    (
        Vec<barbican::CargoManifestDirectRequirement>,
        Vec<barbican::CargoManifestDirectRequirement>,
    ),
    CommandError,
> {
    let manifest_texts = load_manifest_texts_from_root(current_dir)?;
    let direct = parse_manifest_requirements(&manifest_texts)?;
    let workspace = parse_workspace_requirements(&manifest_texts)?;

    Ok((direct, workspace))
}

pub(crate) fn parse_manifest_requirements(
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

pub(crate) fn parse_workspace_requirements(
    manifest_texts: &[(String, String)],
) -> Result<Vec<barbican::CargoManifestDirectRequirement>, CommandError> {
    let root_text = manifest_texts
        .iter()
        .find_map(|(path, text)| (path == "Cargo.toml").then_some(text.as_str()))
        .unwrap_or("");
    let parsed =
        parse_workspace_dependency_requirements("Cargo.toml", root_text).map_err(|source| {
            CommandError::ManifestParse {
                path: "Cargo.toml".to_owned(),
                source,
            }
        })?;

    Ok(parsed.into_iter().collect())
}

pub(crate) fn load_manifest_texts_from_root(
    root_dir: &Path,
) -> Result<Vec<(String, String)>, CommandError> {
    let manifest_paths = super::workspace_manifest_paths(root_dir)?;
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

pub(crate) fn load_base_manifest_dependencies<R>(
    current_dir: &Path,
    runner: &R,
    base_ref: &str,
) -> Result<Vec<barbican::CargoManifestDependency>, CommandError>
where
    R: CommandRunner + ?Sized,
{
    let manifest_paths = super::workspace_manifest_paths(current_dir)?;
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

pub(crate) fn parse_manifest_dependency_text(
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

pub(crate) fn parse_manifest_direct_requirement_text(
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

pub(crate) fn load_manifest_patched_crate_names(
    current_dir: &Path,
) -> Result<BTreeSet<String>, CommandError> {
    let mut patched = BTreeSet::new();

    for (relative_display, text) in load_manifest_texts_from_root(current_dir)? {
        let manifest_patched =
            barbican::parse_manifest_patched_crate_names(&relative_display, &text).map_err(
                |source| CommandError::ManifestParse {
                    path: relative_display,
                    source,
                },
            )?;
        patched.extend(manifest_patched);
    }

    Ok(patched)
}

/// Detects repo-root `.cargo/config.toml` (or legacy `.cargo/config`)
/// top-level `source`, `patch`, or `paths` keys. Cargo source replacement,
/// config-defined patching, and path overrides can each silently repoint a
/// reviewed crate name at a non-crates.io source without touching
/// `Cargo.toml` or `Cargo.lock`, so the mere presence of any of these keys
/// is reported as a fail-closed finding while any reviewed family is
/// active. This only inspects the repo-root file; hierarchical cargo config
/// in parent directories or `CARGO_HOME` is a documented residual boundary.
pub(crate) fn source_replacement_finding(
    current_dir: &Path,
) -> Result<Option<String>, CommandError> {
    for candidate in CARGO_CONFIG_CANDIDATE_PATHS {
        let path = Path::new(candidate);
        let text = read_optional_text_no_symlink(current_dir, path).map_err(|source| {
            CommandError::CargoConfigRead {
                path: candidate.to_owned(),
                source,
            }
        })?;
        let Some(text) = text else {
            continue;
        };

        let override_key = barbican::cargo_config_source_override_key(&text).map_err(|source| {
            CommandError::CargoConfigRead {
                path: candidate.to_owned(),
                source: io::Error::other(source),
            }
        })?;

        if let Some(override_key) = override_key {
            return Ok(Some(format!(
                "{candidate} declares a top-level `{override_key}` key; this can repoint reviewed crates away from crates.io undetected"
            )));
        }
    }

    Ok(None)
}

pub(crate) fn load_reviewed_targets(
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

/// Collapses the release-age preamble ("what minimum age applies, and which
/// reviewed exceptions are honoured") repeated at the top of every
/// release-age-aware command. `min_age_days` overrides the configured
/// minimum when set, matching each of those commands' existing `--min-age`
/// behaviour.
pub(crate) fn load_release_age_context(
    current_dir: &Path,
    min_age_days: Option<u64>,
) -> Result<(u64, ReviewedReleaseAgeExceptions), CommandError> {
    let minimum_days = min_age_days.unwrap_or(load_config(current_dir)?.release_age.minimum_days);
    let reviewed_release_age_exceptions =
        load_reviewed_release_age_exceptions(current_dir, Path::new(REVIEWED_TARGETS_CONFIG_FILE))?;

    Ok((minimum_days, reviewed_release_age_exceptions))
}

pub(crate) fn load_reviewed_release_age_exceptions(
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

pub(crate) fn collect_reviewed_release_age_exceptions(
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
pub(crate) struct ReviewedReleaseAgeExceptions {
    honoured: Vec<ReviewedReleaseAgeException>,
    missing_review_records: Vec<ReviewedReleaseAgeException>,
}

impl ReviewedReleaseAgeExceptions {
    pub(crate) fn honoured(&self) -> &[ReviewedReleaseAgeException] {
        &self.honoured
    }

    pub(crate) fn missing_for_spec(
        &self,
        spec: &ExactCrateSpec,
    ) -> Option<&ReviewedReleaseAgeException> {
        self.missing_review_records
            .iter()
            .find(|exception| exception.spec() == spec)
    }
}

pub(crate) fn check_review_record_paths(
    current_dir: &Path,
    reviewed_targets: &ReviewedTargets,
) -> Vec<ReviewRecordFact> {
    reviewed_targets
        .rust_families()
        .iter()
        .map(|family| {
            let review_record = family.review_record().to_owned();
            let exists = review_record_exists(current_dir, &review_record);

            ReviewRecordFact::new(family.name().to_owned(), review_record, exists)
        })
        .collect()
}

pub(crate) fn review_record_exists(current_dir: &Path, review_record: &str) -> bool {
    fs::symlink_metadata(current_dir.join(review_record))
        .map(|metadata| metadata.is_file())
        .unwrap_or(false)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NativeDelegatedIgnore {
    source: &'static str,
    advisory_ids: Vec<String>,
}

impl NativeDelegatedIgnore {
    pub(crate) fn source(&self) -> &'static str {
        self.source
    }

    pub(crate) fn advisory_ids(&self) -> &[String] {
        &self.advisory_ids
    }
}

pub(crate) fn load_native_delegated_ignores(
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

#[cfg(test)]
mod tests {
    use std::fs;

    use super::super::scratch_dir::ScratchDir;
    use super::{review_record_exists, validate_crates_io_base_url};

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
