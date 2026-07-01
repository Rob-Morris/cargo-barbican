use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use barbican::{
    CrateRelease, CratesIoClient, CratesIoClientError, ExactCrateSpec, OffsetDateTime,
    parse_cargo_metadata, parse_lockfile, select_package_id,
};

use crate::cli::REVIEWED_TARGETS_CONFIG_FILE;
use crate::command_runner::CommandRunner;

use super::age_lock::recheck_lockfile_age_against_lockfiles;
use super::diff_render::render_unified_file_diff;
use super::scratch_dir::ScratchDir;
use super::{
    CommandError, escape_diagnostic_for_terminal, fail, finish_release_age_checks, load_config,
    load_current_lockfile_text, load_current_lockfile_with_text,
    load_reviewed_release_age_exceptions, parse_specs,
};

pub(super) fn run_update<C, R>(
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
    let reviewed_release_age_exceptions =
        load_reviewed_release_age_exceptions(current_dir, Path::new(REVIEWED_TARGETS_CONFIG_FILE))?;
    let parse_result = parse_specs(raw_specs, stderr)?;
    let age_exit = finish_release_age_checks(
        &parse_result.specs,
        minimum_days,
        &reviewed_release_age_exceptions,
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
            if !dry_run {
                restore_base_lockfile(current_dir, &base_lockfile_text, stderr)?;
            }
            return fail(
                stderr,
                format!(
                    "{spec}: unable to update package spec {package_id} to {}: {error}",
                    spec.version()
                ),
            );
        }
    }

    let (current_lockfile, current_lockfile_text) =
        match load_current_lockfile_with_text(resolve_dir, Path::new("Cargo.lock")) {
            Ok(lockfile_with_text) => lockfile_with_text,
            Err(error) => {
                if !dry_run {
                    restore_base_lockfile(current_dir, &base_lockfile_text, stderr)?;
                }
                return fail(stderr, error);
            }
        };
    let current_lockfile_text = if dry_run {
        Some(current_lockfile_text)
    } else {
        None
    };

    let age_recheck_exit = recheck_lockfile_age_against_lockfiles(
        &current_lockfile,
        &base_lockfile,
        "Cargo.lock",
        "pre-update Cargo.lock",
        minimum_days,
        &reviewed_release_age_exceptions,
        &memoized_client,
        now,
        stdout,
        stderr,
    )?;

    if !dry_run {
        if age_recheck_exit != ExitCode::SUCCESS {
            restore_base_lockfile(current_dir, &base_lockfile_text, stderr)?;
        }
        return Ok(age_recheck_exit);
    }

    if age_recheck_exit != ExitCode::SUCCESS {
        return Ok(age_recheck_exit);
    }

    let current_lockfile_text =
        current_lockfile_text.expect("dry-run path retains current lockfile text");

    if base_lockfile_text == current_lockfile_text {
        writeln!(stdout, "Dry run: no Cargo.lock changes would be made.")
            .map_err(CommandError::Io)?;
    } else {
        let diff = render_unified_file_diff(
            Path::new("Cargo.lock"),
            Some(&base_lockfile_text),
            Some(&current_lockfile_text),
        );
        writeln!(
            stdout,
            "Dry run preview:\n{}",
            escape_diagnostic_for_terminal(&diff)
        )
        .map_err(CommandError::Io)?;
    }

    Ok(ExitCode::SUCCESS)
}

pub(super) fn restore_base_lockfile(
    current_dir: &Path,
    base_lockfile_text: &str,
    stderr: &mut dyn Write,
) -> Result<(), CommandError> {
    let lockfile_path = current_dir.join("Cargo.lock");
    if let Err(error) = fs::write(&lockfile_path, base_lockfile_text) {
        writeln!(
            stderr,
            "unable to restore Cargo.lock after failed update: {error}"
        )
        .map_err(CommandError::Io)?;
    }

    Ok(())
}

pub(super) struct MemoizingCratesIoClient<'a, C: ?Sized> {
    inner: &'a C,
    cache: RefCell<HashMap<ExactCrateSpec, Result<CrateRelease, CratesIoClientError>>>,
}

impl<'a, C: ?Sized> MemoizingCratesIoClient<'a, C> {
    pub(super) fn new(inner: &'a C) -> Self {
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

    fn fetch_release_tarball(&self, spec: &ExactCrateSpec) -> Result<Vec<u8>, CratesIoClientError> {
        self.inner.fetch_release_tarball(spec)
    }
}

struct DryRunWorkspace {
    scratch: ScratchDir,
}

impl DryRunWorkspace {
    fn create(source_root: &Path) -> Result<Self, std::io::Error> {
        let scratch = ScratchDir::create("cargo-barbican-update-dry-run", false)?;
        copy_workspace_tree(source_root, scratch.path())?;

        Ok(Self { scratch })
    }

    fn path(&self) -> &Path {
        self.scratch.path()
    }
}

fn copy_workspace_tree(source_root: &Path, destination_root: &Path) -> Result<(), std::io::Error> {
    let copy = SafeWorkspaceCopy::new(source_root, destination_root)?;
    copy.copy_directory_contents(source_root)
}

struct SafeWorkspaceCopy<'a> {
    workspace_root: &'a Path,
    canonical_workspace_root: PathBuf,
    destination_root: &'a Path,
}

impl<'a> SafeWorkspaceCopy<'a> {
    fn new(workspace_root: &'a Path, destination_root: &'a Path) -> Result<Self, std::io::Error> {
        Ok(Self {
            workspace_root,
            canonical_workspace_root: workspace_root.canonicalize()?,
            destination_root,
        })
    }

    fn copy_directory_contents(&self, source_dir: &Path) -> Result<(), std::io::Error> {
        for entry in fs::read_dir(source_dir)? {
            let entry = entry?;
            let source_path = entry.path();
            let relative = source_path
                .strip_prefix(self.workspace_root)
                .map_err(std::io::Error::other)?;

            if should_skip_dry_run_copy(relative) {
                continue;
            }

            let destination_path = self.destination_root.join(relative);
            let file_type = entry.file_type()?;

            if file_type.is_symlink() {
                self.copy_safe_symlink(&source_path, &destination_path, relative)?;
            } else if file_type.is_dir() {
                fs::create_dir_all(&destination_path)?;
                self.copy_directory_contents(&source_path)?;
            } else {
                if let Some(parent) = destination_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::copy(&source_path, &destination_path)?;
            }
        }

        Ok(())
    }

    fn copy_safe_symlink(
        &self,
        source_path: &Path,
        destination_path: &Path,
        relative: &Path,
    ) -> Result<(), std::io::Error> {
        let link_target = fs::read_link(source_path)?;
        if link_target.is_absolute() {
            return Err(std::io::Error::other(format!(
                "dry-run workspace copy does not support absolute symlinks: {}",
                relative.display()
            )));
        }

        let source_parent = source_path
            .parent()
            .ok_or_else(|| std::io::Error::other("symlink has no parent directory"))?;
        let resolved_target = source_parent
            .join(&link_target)
            .canonicalize()
            .map_err(|error| {
                std::io::Error::other(format!(
                    "dry-run workspace copy cannot resolve symlink {}: {error}",
                    relative.display()
                ))
            })?;

        let target_relative = resolved_target
            .strip_prefix(&self.canonical_workspace_root)
            .map_err(|_| {
                std::io::Error::other(format!(
                    "dry-run workspace copy symlink escapes workspace root: {}",
                    relative.display()
                ))
            })?;
        if should_skip_dry_run_copy(target_relative) {
            return Err(std::io::Error::other(format!(
                "dry-run workspace copy symlink targets skipped workspace path: {}",
                relative.display()
            )));
        }

        if let Some(parent) = destination_path.parent() {
            fs::create_dir_all(parent)?;
        }

        create_symlink(&link_target, &resolved_target, destination_path)
    }
}

fn should_skip_dry_run_copy(relative: &Path) -> bool {
    relative.components().any(|component| {
        let name = component.as_os_str();
        name == ".git" || name == "target"
    })
}

#[cfg(unix)]
fn create_symlink(
    link_target: &Path,
    _resolved_target: &Path,
    link: &Path,
) -> Result<(), std::io::Error> {
    std::os::unix::fs::symlink(link_target, link)
}

#[cfg(windows)]
fn create_symlink(
    link_target: &Path,
    resolved_target: &Path,
    link: &Path,
) -> Result<(), std::io::Error> {
    if resolved_target.is_dir() {
        std::os::windows::fs::symlink_dir(link_target, link)
    } else {
        std::os::windows::fs::symlink_file(link_target, link)
    }
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::copy_workspace_tree;

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
    fn dry_run_copy_preserves_relative_file_symlinks_inside_workspace() {
        let source = fresh_temp_path("source");
        let destination = fresh_temp_path("destination");

        fs::create_dir_all(source.join("docs")).expect("source docs should exist");
        fs::create_dir_all(&destination).expect("destination should exist");
        fs::write(source.join("docs/LICENSE"), "license").expect("target should write");
        std::os::unix::fs::symlink("docs/LICENSE", source.join("LICENSE"))
            .expect("symlink should create");

        copy_workspace_tree(&source, &destination).expect("workspace copy should succeed");

        assert_eq!(
            fs::read_link(destination.join("LICENSE")).expect("copied link should read"),
            PathBuf::from("docs/LICENSE")
        );
        assert_eq!(
            fs::read_to_string(destination.join("LICENSE")).expect("copied link should resolve"),
            "license"
        );

        remove_temp_tree(&source);
        remove_temp_tree(&destination);
    }

    #[cfg(unix)]
    #[test]
    fn dry_run_copy_preserves_relative_directory_symlinks_inside_workspace() {
        let source = fresh_temp_path("source");
        let destination = fresh_temp_path("destination");

        fs::create_dir_all(source.join("shared")).expect("source shared dir should exist");
        fs::create_dir_all(&destination).expect("destination should exist");
        fs::write(source.join("shared/config.toml"), "config").expect("target file should write");
        std::os::unix::fs::symlink("shared", source.join("linked-shared"))
            .expect("symlink should create");

        copy_workspace_tree(&source, &destination).expect("workspace copy should succeed");

        assert_eq!(
            fs::read_link(destination.join("linked-shared")).expect("copied link should read"),
            PathBuf::from("shared")
        );
        assert_eq!(
            fs::read_to_string(destination.join("linked-shared/config.toml"))
                .expect("copied directory link should resolve"),
            "config"
        );

        remove_temp_tree(&source);
        remove_temp_tree(&destination);
    }

    #[cfg(unix)]
    #[test]
    fn dry_run_copy_rejects_symlinks_that_escape_workspace() {
        let source = fresh_temp_path("source");
        let destination = fresh_temp_path("destination");
        let outside_parent = fresh_temp_path("outside-parent");
        let outside = outside_parent.join("outside");

        fs::create_dir_all(&source).expect("source should exist");
        fs::create_dir_all(&destination).expect("destination should exist");
        fs::create_dir_all(&outside_parent).expect("outside parent should exist");
        fs::write(&outside, "secret").expect("outside file should write");
        std::os::unix::fs::symlink(
            pathdiff_from(&outside, &source).expect("relative path should compute"),
            source.join("linked"),
        )
        .expect("symlink should create");

        let error =
            copy_workspace_tree(&source, &destination).expect_err("symlink should fail copy");

        assert!(error.to_string().contains("escapes workspace root"));
        assert!(!destination.join("linked").exists());

        remove_temp_tree(&source);
        remove_temp_tree(&destination);
        remove_temp_tree(&outside_parent);
    }

    #[cfg(unix)]
    #[test]
    fn dry_run_copy_rejects_absolute_symlinks() {
        let source = fresh_temp_path("source");
        let destination = fresh_temp_path("destination");

        fs::create_dir_all(&source).expect("source should exist");
        fs::create_dir_all(&destination).expect("destination should exist");
        fs::write(source.join("target.txt"), "target").expect("target should write");
        std::os::unix::fs::symlink(source.join("target.txt"), source.join("linked"))
            .expect("symlink should create");

        let error =
            copy_workspace_tree(&source, &destination).expect_err("symlink should fail copy");

        assert!(error.to_string().contains("absolute symlinks"));

        remove_temp_tree(&source);
        remove_temp_tree(&destination);
    }

    #[cfg(unix)]
    #[test]
    fn dry_run_copy_rejects_broken_symlinks() {
        let source = fresh_temp_path("source");
        let destination = fresh_temp_path("destination");

        fs::create_dir_all(&source).expect("source should exist");
        fs::create_dir_all(&destination).expect("destination should exist");
        std::os::unix::fs::symlink("missing", source.join("linked"))
            .expect("symlink should create");

        let error =
            copy_workspace_tree(&source, &destination).expect_err("symlink should fail copy");

        assert!(error.to_string().contains("cannot resolve symlink linked"));

        remove_temp_tree(&source);
        remove_temp_tree(&destination);
    }

    #[cfg(unix)]
    #[test]
    fn dry_run_copy_rejects_symlink_loops() {
        let source = fresh_temp_path("source");
        let destination = fresh_temp_path("destination");

        fs::create_dir_all(&source).expect("source should exist");
        fs::create_dir_all(&destination).expect("destination should exist");
        std::os::unix::fs::symlink("b", source.join("a")).expect("first symlink should create");
        std::os::unix::fs::symlink("a", source.join("b")).expect("second symlink should create");

        let error =
            copy_workspace_tree(&source, &destination).expect_err("symlink should fail copy");

        assert!(error.to_string().contains("cannot resolve symlink"));

        remove_temp_tree(&source);
        remove_temp_tree(&destination);
    }

    #[cfg(unix)]
    #[test]
    fn dry_run_copy_rejects_symlinks_to_skipped_paths() {
        let source = fresh_temp_path("source");
        let destination = fresh_temp_path("destination");

        fs::create_dir_all(source.join("target")).expect("target dir should exist");
        fs::create_dir_all(&destination).expect("destination should exist");
        fs::write(source.join("target/stale.o"), "artifact").expect("artifact should write");
        std::os::unix::fs::symlink("target/stale.o", source.join("artifact-link"))
            .expect("symlink should create");

        let error =
            copy_workspace_tree(&source, &destination).expect_err("symlink should fail copy");

        assert!(error.to_string().contains("targets skipped workspace path"));
        assert!(!destination.join("artifact-link").exists());

        remove_temp_tree(&source);
        remove_temp_tree(&destination);
    }

    fn fresh_temp_path(label: &str) -> PathBuf {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        env::temp_dir().join(format!(
            "cargo-barbican-update-test-{label}-{timestamp}-{}",
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn remove_temp_tree(path: &Path) {
        let _ = fs::remove_dir_all(path);
    }

    #[cfg(unix)]
    fn pathdiff_from(target: &Path, base: &Path) -> Option<PathBuf> {
        let target_components = target.components().collect::<Vec<_>>();
        let base_components = base.components().collect::<Vec<_>>();
        let shared = target_components
            .iter()
            .zip(&base_components)
            .take_while(|(left, right)| left == right)
            .count();
        let mut relative = PathBuf::new();

        for _ in shared..base_components.len() {
            relative.push("..");
        }
        for component in &target_components[shared..] {
            relative.push(component.as_os_str());
        }

        Some(relative)
    }
}
