use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use barbican::{CrateRelease, CratesIoClient, CratesIoClientError, ExactCrateSpec};

use super::CommandError;
use crate::command_runner::RunnerError;

/// Writes `contents` to `path` via a same-directory temp file plus rename, so a
/// crash or concurrent read mid-write can never observe a truncated file.
/// Renaming within one directory is atomic on the platforms this tool ships
/// for (POSIX `rename(2)`; Windows `MoveFileEx` with replace-existing), unlike
/// truncate-in-place `fs::write`, which briefly leaves a zero-length or
/// partial file on disk.
pub(super) fn write_file_atomically(path: &Path, contents: &str) -> io::Result<()> {
    let permissions = match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            Some(metadata.permissions())
        }
        Ok(_) => {
            return Err(io::Error::other(
                "atomic replacement requires a regular destination",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    write_with_permissions(path, contents, permissions)
}

fn write_with_permissions(
    path: &Path,
    contents: &str,
    permissions: Option<fs::Permissions>,
) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let temp_path = unique_temp_path(parent, path);
    let mut file = create_private_temp(&temp_path)?;
    let result = (|| {
        file.write_all(contents.as_bytes())?;
        if let Some(permissions) = permissions {
            file.set_permissions(permissions)?;
        }
        drop(file);
        fs::rename(&temp_path, path)
    })();
    result.inspect_err(|_| {
        let _ = fs::remove_file(&temp_path);
    })
}

fn create_private_temp(path: &Path) -> io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)
}

fn unique_temp_path(parent: &Path, target: &Path) -> PathBuf {
    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    let file_name = target
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("barbican-tmp");
    let unique = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    parent.join(format!(
        ".{file_name}.barbican-tmp-{}-{unique}",
        std::process::id()
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileIdentity {
    len: u64,
    readonly: bool,
    #[cfg(unix)]
    unix: (u64, u64, u64, u32, i64, i64, i64, i64),
    #[cfg(not(unix))]
    modified: Option<std::time::SystemTime>,
}

impl FileIdentity {
    fn of(metadata: &fs::Metadata) -> Self {
        Self {
            len: metadata.len(),
            readonly: metadata.permissions().readonly(),
            #[cfg(unix)]
            unix: {
                use std::os::unix::fs::MetadataExt as _;
                (
                    metadata.dev(),
                    metadata.ino(),
                    metadata.nlink(),
                    metadata.mode(),
                    metadata.mtime(),
                    metadata.mtime_nsec(),
                    metadata.ctime(),
                    metadata.ctime_nsec(),
                )
            },
            #[cfg(not(unix))]
            modified: metadata.modified().ok(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct DirectoryIdentity {
    #[cfg(unix)]
    unix: (u64, u64),
    #[cfg(not(unix))]
    created: Option<std::time::SystemTime>,
}

impl DirectoryIdentity {
    fn read(root: &Path) -> io::Result<Self> {
        let metadata = fs::metadata(root)?;
        if !metadata.is_dir() {
            return Err(io::Error::other("workspace root is no longer a directory"));
        }
        Ok(Self {
            #[cfg(unix)]
            unix: {
                use std::os::unix::fs::MetadataExt as _;
                (metadata.dev(), metadata.ino())
            },
            #[cfg(not(unix))]
            created: metadata.created().ok(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Observation {
    Absent,
    Regular {
        identity: FileIdentity,
        bytes: Option<Vec<u8>>,
    },
}

enum OriginalLockfile {
    Absent,
    Existing {
        text: String,
        permissions: fs::Permissions,
        graph: barbican::Lockfile,
    },
}

pub(super) struct LockfileRestoreGuard {
    root: PathBuf,
    directory: DirectoryIdentity,
    original: OriginalLockfile,
    observed: Option<Observation>,
    armed: bool,
}

impl LockfileRestoreGuard {
    pub(super) fn capture(root: &Path, allow_absent: bool) -> Result<Self, CommandError> {
        let directory = DirectoryIdentity::read(root).map_err(CommandError::Io)?;
        let mut guard = Self {
            root: root.to_owned(),
            directory,
            original: OriginalLockfile::Absent,
            observed: None,
            armed: false,
        };
        let (observed, read_error, permissions) = guard.observe()?;
        if let Some(source) = read_error {
            return Err(CommandError::LockfileRead {
                path: "Cargo.lock".to_owned(),
                source,
            });
        }
        guard.original = match &observed {
            Observation::Absent if allow_absent => OriginalLockfile::Absent,
            Observation::Absent => {
                return Err(CommandError::LockfileMissing {
                    path: "Cargo.lock".to_owned(),
                });
            }
            Observation::Regular { bytes, .. } => {
                let text = String::from_utf8(bytes.clone().expect("successful read has bytes"))
                    .map_err(|source| CommandError::LockfileRead {
                        path: "Cargo.lock".to_owned(),
                        source: io::Error::new(io::ErrorKind::InvalidData, source),
                    })?;
                let graph = barbican::parse_lockfile(&text).map_err(|source| {
                    CommandError::LockfileParse {
                        path: "Cargo.lock".to_owned(),
                        source,
                    }
                })?;
                OriginalLockfile::Existing {
                    text,
                    permissions: permissions.expect("regular file permissions"),
                    graph,
                }
            }
        };
        guard.observed = Some(observed);
        Ok(guard)
    }

    pub(super) fn original(&self) -> (barbican::Lockfile, Option<&str>) {
        match &self.original {
            OriginalLockfile::Absent => (barbican::Lockfile::default(), None),
            OriginalLockfile::Existing { text, graph, .. } => (graph.clone(), Some(text)),
        }
    }

    fn observe(
        &self,
    ) -> Result<(Observation, Option<io::Error>, Option<fs::Permissions>), CommandError> {
        self.check_directory()?;
        let path = self.root.join("Cargo.lock");
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.check_directory()?;
                return Ok((Observation::Absent, None, None));
            }
            Err(error) => {
                return Err(self.problem(format!("unable to inspect Cargo.lock: {error}")));
            }
        };
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(
                self.problem("Cargo.lock must be a regular file, not a symlink or other object")
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            if metadata.nlink() != 1 {
                return Err(self.problem("Cargo.lock must not have multiple hard links"));
            }
        }
        let identity = FileIdentity::of(&metadata);
        let read = fs::read(&path);
        let after = fs::symlink_metadata(&path)
            .map_err(|e| self.problem(format!("Cargo.lock changed while reading: {e}")))?;
        self.check_directory()?;
        if !after.is_file()
            || after.file_type().is_symlink()
            || identity != FileIdentity::of(&after)
        {
            return Err(self.problem(
                "Cargo.lock changed while reading; leave it intact and inspect it before retrying",
            ));
        }
        let (bytes, error) = match read {
            Ok(bytes) => (Some(bytes), None),
            Err(error) => (None, Some(error)),
        };
        Ok((
            Observation::Regular { identity, bytes },
            error,
            Some(metadata.permissions()),
        ))
    }

    fn check_directory(&self) -> Result<(), CommandError> {
        match DirectoryIdentity::read(&self.root) {
            Ok(directory) if directory == self.directory => Ok(()),
            _ => Err(self.problem("workspace directory changed; Cargo.lock was left intact")),
        }
    }

    fn problem(&self, detail: impl std::fmt::Display) -> CommandError {
        CommandError::Io(io::Error::other(format!(
            "{}: {detail}",
            self.root.join("Cargo.lock").display()
        )))
    }

    pub(super) fn check_unchanged(&mut self) -> Result<(), CommandError> {
        let result = (|| {
            let expected = self.observed.as_ref().ok_or_else(|| {
                self.problem("output was not safely observed; inspect it before recovery")
            })?;
            let (actual, _, _) = self.observe()?;
            let matches = match (expected, &actual) {
                (
                    Observation::Regular {
                        identity: left,
                        bytes: None,
                    },
                    Observation::Regular {
                        identity: right, ..
                    },
                ) => left == right,
                _ => expected == &actual,
            };
            if matches {
                Ok(())
            } else {
                Err(self.problem("Cargo.lock changed outside the last observed mutation; left intact, inspect it before retrying"))
            }
        })();
        if result.is_err() {
            self.armed = false;
            self.observed = None;
        }
        result
    }

    pub(super) fn mutate<T>(
        &mut self,
        label: &str,
        operation: impl FnOnce() -> Result<T, RunnerError>,
    ) -> Result<T, CommandError> {
        self.check_unchanged()?;
        self.armed = true;
        self.observed = None;
        let result = operation();
        let capture = self.observe();
        match capture {
            Ok((observed, read_error, _)) => {
                self.observed = Some(observed);
                match (result, read_error) {
                    (Ok(value), None) => Ok(value),
                    (Err(primary), secondary) => Err(self.problem(format!(
                        "{label}: {primary}{}",
                        secondary
                            .map(|e| format!("; also unable to read generated Cargo.lock: {e}"))
                            .unwrap_or_default()
                    ))),
                    (Ok(_), Some(error)) => Err(self.problem(format!(
                        "unable to read generated Cargo.lock after {label}: {error}"
                    ))),
                }
            }
            Err(capture_error) => {
                self.armed = false;
                Err(self.problem(format!("{}unable to safely capture output after {label}: {capture_error}; left intact for recovery",
                    result.err().map(|e| format!("{label}: {e}; ")).unwrap_or_default())))
            }
        }
    }

    pub(super) fn current(&self) -> Result<(barbican::Lockfile, String), CommandError> {
        let bytes = match &self.observed {
            Some(Observation::Regular {
                bytes: Some(bytes), ..
            }) => bytes,
            Some(Observation::Absent) => {
                return Err(CommandError::LockfileMissing {
                    path: "Cargo.lock".to_owned(),
                });
            }
            _ => return Err(self.problem("generated lockfile is unavailable")),
        };
        let text = String::from_utf8(bytes.clone())
            .map_err(|e| self.problem(format!("generated Cargo.lock is not UTF-8: {e}")))?;
        let graph =
            barbican::parse_lockfile(&text).map_err(|source| CommandError::LockfileParse {
                path: "Cargo.lock".to_owned(),
                source,
            })?;
        Ok((graph, text))
    }

    fn restore_now(&mut self) -> Result<(), CommandError> {
        if !self.armed {
            return Ok(());
        }
        self.check_unchanged()?;
        self.armed = false;
        let path = self.root.join("Cargo.lock");
        let result = match &self.original {
            OriginalLockfile::Absent => match self.observed {
                Some(Observation::Absent) => Ok(()),
                _ => fs::remove_file(&path),
            },
            OriginalLockfile::Existing {
                text, permissions, ..
            } => write_with_permissions(&path, text, Some(permissions.clone())),
        };
        result.map_err(|source| CommandError::LockfileRestore {
            path: path.display().to_string(),
            source,
        })
    }

    pub(super) fn finish(
        &mut self,
        result: Result<std::process::ExitCode, CommandError>,
    ) -> Result<std::process::ExitCode, CommandError> {
        if matches!(&result, Ok(code) if *code == std::process::ExitCode::SUCCESS) {
            self.check_unchanged()?;
            self.armed = false;
            return result;
        }
        match self.restore_now() {
            Ok(()) => result,
            Err(cleanup) => Err(self.problem(format!(
                "{}; {cleanup}",
                result
                    .err()
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "lockfile operation rejected".to_owned())
            ))),
        }
    }
}

impl Drop for LockfileRestoreGuard {
    fn drop(&mut self) {
        // An unobserved delegate may be unwinding: never infer ownership from its live output.
        if self.armed && self.observed.is_some() {
            let _ = self.restore_now();
        }
    }
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

    fn fetch_versions(
        &self,
        crate_name: &str,
    ) -> Result<Vec<barbican::VersionInfo>, CratesIoClientError> {
        // Passed straight through, not memoized: callers of this seam
        // (release-age rechecks over exact specs) never call fetch_versions,
        // so there is no repeated-lookup cost to amortise here. Forwarding
        // it explicitly avoids silently falling back to the trait default
        // (NotSupported), which would be a fail-open landmine for any future
        // caller that reaches fetch_versions through this wrapper.
        self.inner.fetch_versions(crate_name)
    }

    fn fetch_release_tarball(&self, spec: &ExactCrateSpec) -> Result<Vec<u8>, CratesIoClientError> {
        self.inner.fetch_release_tarball(spec)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use barbican::{OffsetDateTime, Sha256Digest, VersionInfo};

    use super::*;

    #[cfg(unix)]
    #[test]
    fn temporary_file_is_private_before_content_and_existing_paths_are_not_removed() {
        use std::os::unix::fs::PermissionsExt as _;
        let path = std::env::temp_dir().join(format!(
            "barbican-private-temp-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut file = create_private_temp(&path).unwrap();
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(file.metadata().unwrap().len(), 0);
        file.write_all(b"private review").unwrap();
        assert_eq!(
            create_private_temp(&path).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(fs::read(&path).unwrap(), b"private review");
        drop(file);
        fs::remove_file(path).unwrap();
    }

    fn fresh_temp_dir() -> PathBuf {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "cargo-barbican-lockfile-ops-test-{timestamp}-{}",
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).expect("scratch dir should create");
        path
    }

    #[test]
    fn write_file_atomically_replaces_existing_file_contents() {
        let dir = fresh_temp_dir();
        let target = dir.join("Cargo.lock");
        fs::write(&target, "old").expect("initial write should succeed");

        write_file_atomically(&target, "new").expect("atomic write should succeed");

        assert_eq!(
            fs::read_to_string(&target).expect("target should read"),
            "new"
        );
        let leftovers = fs::read_dir(&dir)
            .expect("scratch dir should list")
            .filter_map(Result::ok)
            .filter(|entry| entry.path() != target)
            .count();
        assert_eq!(leftovers, 0, "no temp file should be left behind");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_file_atomically_creates_a_new_file() {
        let dir = fresh_temp_dir();
        let target = dir.join("Cargo.lock");

        write_file_atomically(&target, "contents").expect("atomic write should succeed");

        assert_eq!(
            fs::read_to_string(&target).expect("target should read"),
            "contents"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    fn guard_workspace() -> super::super::scratch_dir::ScratchDir {
        super::super::scratch_dir::ScratchDir::create("barbican-guard-test", false).unwrap()
    }

    #[test]
    fn absent_rollback_removes_even_invalid_raw_candidate() {
        for bytes in [b"not TOML".as_slice(), &[255, 254]] {
            let dir = guard_workspace();
            let path = dir.path().join("Cargo.lock");
            let mut guard = LockfileRestoreGuard::capture(dir.path(), true).unwrap();
            guard
                .mutate("test write", || {
                    fs::write(&path, bytes).map_err(RunnerError::Spawn)
                })
                .unwrap();
            let error = guard.current().unwrap_err();
            assert!(guard.finish(Err(error)).is_err());
            assert!(!path.exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn write_then_error_restores_original_bytes_and_original_mode() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = guard_workspace();
        let path = dir.path().join("Cargo.lock");
        let original = "# original comment\r\nversion = 4\r\n";
        fs::write(&path, original).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let mut guard = LockfileRestoreGuard::capture(dir.path(), false).unwrap();
        let error = guard
            .mutate("test delegate", || {
                fs::write(&path, "partial").unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                Err::<(), _>(RunnerError::Spawn(io::Error::other(
                    "delegate primary failure",
                )))
            })
            .unwrap_err();
        let error = guard.finish(Err(error)).unwrap_err();
        assert!(error.to_string().contains("delegate primary failure"));
        assert_eq!(fs::read(&path).unwrap(), original.as_bytes());
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }

    #[test]
    fn each_mutation_uses_latest_observation_but_failure_restores_original() {
        let dir = guard_workspace();
        let path = dir.path().join("Cargo.lock");
        fs::write(&path, "# original\nversion = 4\n").unwrap();
        let mut guard = LockfileRestoreGuard::capture(dir.path(), false).unwrap();
        for text in ["# metadata\nversion = 4\n", "# update one\nversion = 4\n"] {
            guard
                .mutate("step", || {
                    fs::write(&path, text).map_err(RunnerError::Spawn)
                })
                .unwrap();
        }
        let result = guard.mutate("second update", || {
            fs::write(&path, "partial second update").unwrap();
            Err::<(), _>(RunnerError::Spawn(io::Error::other("second update failed")))
        });
        assert!(
            guard
                .finish(result.map(|()| std::process::ExitCode::SUCCESS))
                .is_err()
        );
        assert_eq!(
            fs::read_to_string(path).unwrap(),
            "# original\nversion = 4\n"
        );
    }

    #[test]
    fn external_edits_are_preserved_on_success_and_rejection_without_drop_retry() {
        for success in [true, false] {
            let dir = guard_workspace();
            let path = dir.path().join("Cargo.lock");
            let mut guard = LockfileRestoreGuard::capture(dir.path(), true).unwrap();
            guard
                .mutate("generate", || {
                    fs::write(&path, "version = 4\n").map_err(RunnerError::Spawn)
                })
                .unwrap();
            fs::write(&path, "external edit").unwrap();
            let result = guard.finish(if success {
                Ok(std::process::ExitCode::SUCCESS)
            } else {
                Err(CommandError::Io(io::Error::other("policy primary")))
            });
            assert!(result.is_err());
            drop(guard);
            assert_eq!(fs::read_to_string(path).unwrap(), "external edit");
        }
    }

    #[test]
    fn external_change_between_delegates_prevents_the_next_delegate() {
        let dir = guard_workspace();
        let path = dir.path().join("Cargo.lock");
        fs::write(&path, "version = 4\n").unwrap();
        let mut guard = LockfileRestoreGuard::capture(dir.path(), false).unwrap();
        guard.mutate("metadata", || Ok(())).unwrap();
        fs::write(&path, "external").unwrap();
        assert!(
            guard
                .mutate::<()>("update", || panic!("must not run"))
                .is_err()
        );
        drop(guard);
        assert_eq!(fs::read_to_string(path).unwrap(), "external");
    }

    #[test]
    fn panic_while_delegate_output_is_unobserved_leaves_it_intact() {
        let dir = guard_workspace();
        let path = dir.path().join("Cargo.lock");
        fs::write(&path, "version = 4\n").unwrap();
        let unwind = std::panic::catch_unwind(|| {
            let mut guard = LockfileRestoreGuard::capture(dir.path(), false).unwrap();
            let _ = guard.mutate::<()>("panicking delegate", || {
                fs::write(&path, "unobserved partial output").unwrap();
                panic!("delegate panic");
            });
        });
        assert!(unwind.is_err());
        assert_eq!(
            fs::read_to_string(path).unwrap(),
            "unobserved partial output"
        );
    }

    #[test]
    fn panic_after_safe_capture_restores_original() {
        let dir = guard_workspace();
        let path = dir.path().join("Cargo.lock");
        fs::write(&path, "version = 4\n").unwrap();
        let unwind = std::panic::catch_unwind(|| {
            let mut guard = LockfileRestoreGuard::capture(dir.path(), false).unwrap();
            guard
                .mutate("delegate", || {
                    fs::write(&path, "captured").map_err(RunnerError::Spawn)
                })
                .unwrap();
            panic!("policy panic");
        });
        assert!(unwind.is_err());
        assert_eq!(fs::read_to_string(path).unwrap(), "version = 4\n");
    }

    #[cfg(unix)]
    #[test]
    fn initial_symlinks_directories_hardlinks_and_fifos_are_refused_without_reading() {
        let dir = guard_workspace();
        let root = dir.path();
        let path = root.join("Cargo.lock");
        fs::write(root.join("outside"), "version = 4\n").unwrap();
        for target in ["outside", "missing"] {
            std::os::unix::fs::symlink(target, &path).unwrap();
            assert!(LockfileRestoreGuard::capture(root, true).is_err());
            fs::remove_file(&path).unwrap();
        }
        fs::create_dir(&path).unwrap();
        assert!(LockfileRestoreGuard::capture(root, true).is_err());
        fs::remove_dir(&path).unwrap();
        fs::hard_link(root.join("outside"), &path).unwrap();
        assert!(LockfileRestoreGuard::capture(root, true).is_err());
        fs::remove_file(&path).unwrap();
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
        assert!(LockfileRestoreGuard::capture(root, true).is_err());
        fs::remove_file(&path).unwrap();
        assert_eq!(
            fs::read_to_string(root.join("outside")).unwrap(),
            "version = 4\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_output_is_preserved_and_primary_failure_survives() {
        let dir = guard_workspace();
        let path = dir.path().join("Cargo.lock");
        fs::write(dir.path().join("outside"), "outside").unwrap();
        let mut guard = LockfileRestoreGuard::capture(dir.path(), true).unwrap();
        let error = guard
            .mutate("generate", || {
                std::os::unix::fs::symlink("outside", &path).unwrap();
                Err::<(), _>(RunnerError::Spawn(io::Error::other(
                    "primary delegate error",
                )))
            })
            .unwrap_err();
        let error = guard.finish(Err(error)).unwrap_err().to_string();
        drop(guard);
        assert!(error.contains("primary delegate error"), "{error}");
        assert!(error.contains("left intact"), "{error}");
        assert!(fs::symlink_metadata(path).unwrap().file_type().is_symlink());
        assert_eq!(
            fs::read_to_string(dir.path().join("outside")).unwrap(),
            "outside"
        );
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_failure_keeps_primary_and_disarms_drop() {
        use std::os::unix::fs::PermissionsExt as _;
        for absent in [true, false] {
            let dir = guard_workspace();
            let path = dir.path().join("Cargo.lock");
            if !absent {
                fs::write(&path, "version = 4\n").unwrap();
            }
            let mut guard = LockfileRestoreGuard::capture(dir.path(), absent).unwrap();
            guard
                .mutate("generate", || {
                    fs::write(&path, "candidate").map_err(RunnerError::Spawn)
                })
                .unwrap();
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o555)).unwrap();
            let result = guard.finish(Err(CommandError::Io(io::Error::other("primary rejection"))));
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
            let error = result.unwrap_err().to_string();
            assert!(
                error.contains("primary rejection") && error.contains("unable to restore"),
                "{error}"
            );
            drop(guard);
            assert_eq!(fs::read_to_string(path).unwrap(), "candidate");
        }
    }

    #[test]
    fn invalid_initial_content_is_never_bootstrap_and_plain_reads_are_not_conflicts() {
        let dir = guard_workspace();
        let path = dir.path().join("Cargo.lock");
        for bytes in [b"not TOML".as_slice(), &[255, 254]] {
            fs::write(&path, bytes).unwrap();
            assert!(LockfileRestoreGuard::capture(dir.path(), true).is_err());
            assert_eq!(fs::read(&path).unwrap(), bytes);
        }
        fs::write(&path, "version = 4\n").unwrap();
        let mut guard = LockfileRestoreGuard::capture(dir.path(), false).unwrap();
        for _ in 0..4 {
            fs::read(&path).unwrap();
        }
        guard.check_unchanged().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_input_is_refused_but_observed_unreadable_output_can_be_restored() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = guard_workspace();
        let path = dir.path().join("Cargo.lock");
        fs::write(&path, "version = 4\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
        assert!(LockfileRestoreGuard::capture(dir.path(), true).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        for absent in [false, true] {
            if absent {
                fs::remove_file(&path).unwrap();
            }
            let mut guard = LockfileRestoreGuard::capture(dir.path(), absent).unwrap();
            let result = guard.mutate("write unreadable", || {
                fs::write(&path, "candidate").unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o000))
                    .map_err(RunnerError::Spawn)
            });
            assert!(result.is_err());
            assert!(fs::read(&path).is_err());
            assert!(
                guard
                    .finish(result.map(|()| std::process::ExitCode::SUCCESS))
                    .is_err()
            );
            assert_eq!(path.exists(), !absent);
            if !absent {
                assert_eq!(fs::read_to_string(&path).unwrap(), "version = 4\n");
                assert_eq!(
                    fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                    0o640
                );
            }
        }
    }

    #[test]
    fn missing_delegate_output_restores_an_existing_file_and_keeps_prior_absence() {
        for absent in [true, false] {
            let dir = guard_workspace();
            let path = dir.path().join("Cargo.lock");
            if !absent {
                fs::write(&path, "version = 4\n").unwrap();
            }
            let mut guard = LockfileRestoreGuard::capture(dir.path(), absent).unwrap();
            guard
                .mutate("remove output", || {
                    if path.exists() {
                        fs::remove_file(&path).map_err(RunnerError::Spawn)?;
                    }
                    Ok(())
                })
                .unwrap();
            let result = guard.current().map(|_| std::process::ExitCode::SUCCESS);
            assert!(guard.finish(result).is_err());
            assert_eq!(path.exists(), !absent);
            if !absent {
                assert_eq!(fs::read_to_string(path).unwrap(), "version = 4\n");
            }
        }
    }

    #[test]
    fn directory_replacement_and_same_byte_file_replacement_are_conflicts() {
        let dir = guard_workspace();
        let path = dir.path().join("Cargo.lock");
        fs::write(&path, "# original\nversion = 4\n").unwrap();
        let mut guard = LockfileRestoreGuard::capture(dir.path(), false).unwrap();
        guard
            .mutate("generate", || {
                fs::write(&path, "version = 4\n").map_err(RunnerError::Spawn)
            })
            .unwrap();
        let replacement = dir.path().join("replacement");
        fs::write(&replacement, "version = 4\n").unwrap();
        fs::rename(replacement, &path).unwrap();
        assert!(guard.finish(Ok(std::process::ExitCode::SUCCESS)).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "version = 4\n");
        let mut guard = LockfileRestoreGuard::capture(dir.path(), false).unwrap();
        let moved = dir.path().with_extension("moved");
        fs::rename(dir.path(), &moved).unwrap();
        fs::create_dir(dir.path()).unwrap();
        fs::write(&path, "replacement directory file").unwrap();
        assert!(guard.finish(Ok(std::process::ExitCode::SUCCESS)).is_err());
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "replacement directory file"
        );
        fs::remove_dir_all(dir.path()).unwrap();
        fs::rename(moved, dir.path()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn chmod_only_external_change_is_preserved_on_rejection() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = guard_workspace();
        let path = dir.path().join("Cargo.lock");
        fs::write(&path, "# original\nversion = 4\n").unwrap();
        let mut guard = LockfileRestoreGuard::capture(dir.path(), false).unwrap();
        guard
            .mutate("generate", || {
                fs::write(&path, "version = 4\n").map_err(RunnerError::Spawn)
            })
            .unwrap();
        let current = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        let changed = current ^ 0o040;
        fs::set_permissions(&path, fs::Permissions::from_mode(changed)).unwrap();
        assert!(guard.finish(Ok(std::process::ExitCode::from(1))).is_err());
        drop(guard);
        assert_eq!(fs::read_to_string(&path).unwrap(), "version = 4\n");
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            changed
        );
    }

    struct StubCratesIoClient {
        versions: Vec<VersionInfo>,
    }

    impl CratesIoClient for StubCratesIoClient {
        fn fetch_release(
            &self,
            _spec: &ExactCrateSpec,
        ) -> Result<CrateRelease, CratesIoClientError> {
            Err(CratesIoClientError::NotSupported)
        }

        fn fetch_versions(
            &self,
            _crate_name: &str,
        ) -> Result<Vec<VersionInfo>, CratesIoClientError> {
            Ok(self.versions.clone())
        }

        fn fetch_release_tarball(
            &self,
            _spec: &ExactCrateSpec,
        ) -> Result<Vec<u8>, CratesIoClientError> {
            Err(CratesIoClientError::NotSupported)
        }
    }

    #[test]
    fn memoizing_client_forwards_fetch_versions_instead_of_falling_back_to_default() {
        let inner = StubCratesIoClient {
            versions: vec![VersionInfo {
                num: "1.0.0".to_owned(),
                checksum_sha256_hex: Sha256Digest::try_from(
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                )
                .expect("fixed digest should parse"),
                published_at_raw: "2020-01-01T00:00:00Z".to_owned(),
                published_at: OffsetDateTime::from_unix_timestamp(1_577_836_800)
                    .expect("fixed timestamp should parse"),
                yanked: false,
            }],
        };
        let memoizing = MemoizingCratesIoClient::new(&inner);

        let versions = memoizing
            .fetch_versions("serde")
            .expect("forwarded fetch_versions should succeed");

        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].num, "1.0.0");
    }
}
