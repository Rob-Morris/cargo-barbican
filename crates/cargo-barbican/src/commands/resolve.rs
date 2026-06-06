use std::cell::RefCell;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::DirBuilderExt;

use barbican::{
    CrateRelease, CratesIoClient, CratesIoClientError, ExactCrateSpec, OffsetDateTime,
    parse_cargo_metadata, parse_lockfile, select_package_id,
};

use crate::command_runner::CommandRunner;

use super::age_lock::recheck_lockfile_age_against_lockfiles;
use super::diff_render::render_unified_file_diff;
use super::{
    CommandError, fail, finish_release_age_checks, load_config, load_current_lockfile,
    load_current_lockfile_text, parse_specs,
};

pub(super) fn run_resolve<C, R>(
    dry_run: bool,
    min_age_days: Option<u64>,
    raw_specs: Vec<String>,
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
    let memoized_client = MemoizingCratesIoClient::new(client);
    let minimum_days = min_age_days.unwrap_or(load_config(current_dir)?.release_age.minimum_days);
    let parse_result = parse_specs(raw_specs, stderr)?;
    let age_exit = finish_release_age_checks(
        &parse_result.specs,
        minimum_days,
        &memoized_client,
        now,
        stdout,
        stderr,
    )?;

    if parse_result.failed || age_exit != ExitCode::SUCCESS {
        return Ok(ExitCode::from(1));
    }
    let base_lockfile_text = match load_current_lockfile_text(current_dir, Path::new("Cargo.lock"))
    {
        Ok(text) => text,
        Err(error) => return fail(stderr, error),
    };
    let base_lockfile = match parse_lockfile(&base_lockfile_text) {
        Ok(lockfile) => lockfile,
        Err(source) => {
            return fail(
                stderr,
                CommandError::LockfileParse {
                    path: "Cargo.lock".to_owned(),
                    source,
                },
            );
        }
    };
    let dry_run_workspace = if dry_run {
        match DryRunWorkspace::create(current_dir) {
            Ok(workspace) => Some(workspace),
            Err(error) => {
                return fail(
                    stderr,
                    format!("unable to prepare dry-run workspace: {error}"),
                );
            }
        }
    } else {
        None
    };
    let resolve_dir = dry_run_workspace
        .as_ref()
        .map(DryRunWorkspace::path)
        .unwrap_or(current_dir);

    let metadata_text = match runner.cargo_metadata(resolve_dir) {
        Ok(text) => text,
        Err(error) => return fail(stderr, format!("cargo metadata: {error}")),
    };
    let metadata = match parse_cargo_metadata(&metadata_text) {
        Ok(metadata) => metadata,
        Err(error) => return fail(stderr, format!("cargo metadata: {error}")),
    };
    let mut selections = Vec::new();

    for spec in &parse_result.specs {
        match select_package_id(&metadata, spec.crate_name()) {
            Ok(package_id) => selections.push((spec.clone(), package_id)),
            Err(error) => return fail(stderr, format!("{}: {error}", spec.crate_name())),
        }
    }

    for (spec, package_id) in selections {
        if let Err(error) = runner.cargo_update_precise(resolve_dir, &package_id, spec.version()) {
            return fail(
                stderr,
                format!(
                    "{spec}: unable to update package spec {package_id} to {}: {error}",
                    spec.version()
                ),
            );
        }
    }

    let current_lockfile = match load_current_lockfile(resolve_dir, Path::new("Cargo.lock")) {
        Ok(lockfile) => lockfile,
        Err(error) => return fail(stderr, error),
    };
    let age_recheck_exit = recheck_lockfile_age_against_lockfiles(
        &current_lockfile,
        &base_lockfile,
        "Cargo.lock",
        "pre-update Cargo.lock",
        minimum_days,
        &memoized_client,
        now,
        stdout,
        stderr,
    )?;

    if !dry_run || age_recheck_exit != ExitCode::SUCCESS {
        return Ok(age_recheck_exit);
    }

    let current_lockfile_text =
        match load_current_lockfile_text(resolve_dir, Path::new("Cargo.lock")) {
            Ok(text) => text,
            Err(error) => return fail(stderr, error),
        };

    if base_lockfile_text == current_lockfile_text {
        writeln!(stdout, "Dry run: no Cargo.lock changes would be made.")
            .map_err(CommandError::Io)?;
    } else {
        let diff = render_unified_file_diff(
            Path::new("Cargo.lock"),
            Some(&base_lockfile_text),
            Some(&current_lockfile_text),
        );
        writeln!(stdout, "Dry run preview:\n{diff}").map_err(CommandError::Io)?;
    }

    Ok(ExitCode::SUCCESS)
}

struct MemoizingCratesIoClient<'a, C: ?Sized> {
    inner: &'a C,
    cache: RefCell<HashMap<ExactCrateSpec, Result<CrateRelease, CratesIoClientError>>>,
}

impl<'a, C: ?Sized> MemoizingCratesIoClient<'a, C> {
    fn new(inner: &'a C) -> Self {
        Self {
            inner,
            cache: RefCell::new(HashMap::new()),
        }
    }
}

impl<C> CratesIoClient for MemoizingCratesIoClient<'_, C>
where
    C: CratesIoClient + ?Sized,
{
    fn fetch_release(&self, spec: &ExactCrateSpec) -> Result<CrateRelease, CratesIoClientError> {
        if let Some(cached) = self.cache.borrow().get(spec) {
            return cached.clone();
        }

        let result = self.inner.fetch_release(spec);
        self.cache.borrow_mut().insert(spec.clone(), result.clone());
        result
    }
}

struct DryRunWorkspace {
    path: PathBuf,
}

impl DryRunWorkspace {
    fn create(source_root: &Path) -> Result<Self, std::io::Error> {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "cargo-barbican-resolve-dry-run-{timestamp}-{}",
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));

        create_private_dir(&path)?;
        copy_workspace_tree(source_root, &path)?;

        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for DryRunWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn copy_workspace_tree(source_root: &Path, destination_root: &Path) -> Result<(), std::io::Error> {
    copy_directory_contents(source_root, destination_root, source_root)
}

#[cfg(unix)]
fn create_private_dir(path: &Path) -> Result<(), std::io::Error> {
    fs::DirBuilder::new().mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_private_dir(path: &Path) -> Result<(), std::io::Error> {
    fs::create_dir(path)
}

fn copy_directory_contents(
    source_dir: &Path,
    destination_dir: &Path,
    workspace_root: &Path,
) -> Result<(), std::io::Error> {
    for entry in fs::read_dir(source_dir)? {
        let entry = entry?;
        let source_path = entry.path();
        let relative = source_path
            .strip_prefix(workspace_root)
            .map_err(std::io::Error::other)?;

        if should_skip_dry_run_copy(relative) {
            continue;
        }

        let destination_path = destination_dir.join(relative);

        if entry.file_type()?.is_dir() {
            fs::create_dir_all(&destination_path)?;
            copy_directory_contents(&source_path, destination_dir, workspace_root)?;
        } else {
            if let Some(parent) = destination_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(&source_path, &destination_path)?;
        }
    }

    Ok(())
}

fn should_skip_dry_run_copy(relative: &Path) -> bool {
    relative.components().any(|component| {
        let name = component.as_os_str();
        name == ".git" || name == "target"
    })
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{copy_workspace_tree, create_private_dir};

    #[test]
    fn dry_run_copy_preserves_workspace_files_and_skips_git_and_target_dirs() {
        let source = fresh_temp_path("source");
        let destination = fresh_temp_path("destination");

        fs::create_dir_all(source.join("crates/foo/src")).expect("source crate should exist");
        fs::create_dir_all(source.join("crates/foo/target/debug"))
            .expect("nested target should exist");
        fs::create_dir_all(source.join(".git/objects")).expect("git dir should exist");
        fs::write(
            source.join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/foo\"]\n",
        )
        .expect("workspace manifest should write");
        fs::write(source.join("Cargo.lock"), "version = 4\n").expect("lockfile should write");
        fs::write(
            source.join("crates/foo/Cargo.toml"),
            "[package]\nname = \"foo\"\nversion = \"0.1.0\"\n",
        )
        .expect("member manifest should write");
        fs::write(source.join("crates/foo/src/lib.rs"), "pub fn ok() {}\n")
            .expect("source file should write");
        fs::write(source.join("crates/foo/target/debug/stale.o"), "artifact")
            .expect("target artifact should write");
        fs::write(source.join(".git/HEAD"), "ref: refs/heads/dev\n")
            .expect("git file should write");

        fs::create_dir_all(&destination).expect("destination should exist");
        copy_workspace_tree(&source, &destination).expect("workspace copy should succeed");

        assert!(destination.join("Cargo.toml").is_file());
        assert!(destination.join("Cargo.lock").is_file());
        assert!(destination.join("crates/foo/Cargo.toml").is_file());
        assert!(destination.join("crates/foo/src/lib.rs").is_file());
        assert!(!destination.join(".git").exists());
        assert!(!destination.join("crates/foo/target").exists());

        remove_temp_tree(&source);
        remove_temp_tree(&destination);
    }

    #[cfg(unix)]
    #[test]
    fn dry_run_temp_root_is_private_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let path = fresh_temp_path("private-root");

        create_private_dir(&path).expect("private temp root should be created");

        let mode = fs::metadata(&path)
            .expect("private temp root metadata should read")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);

        remove_temp_tree(&path);
    }

    fn fresh_temp_path(label: &str) -> PathBuf {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        env::temp_dir().join(format!(
            "cargo-barbican-resolve-test-{label}-{timestamp}-{}",
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn remove_temp_tree(path: &Path) {
        let _ = fs::remove_dir_all(path);
    }
}
