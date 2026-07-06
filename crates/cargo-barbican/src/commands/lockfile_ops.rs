use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use barbican::{CrateRelease, CratesIoClient, CratesIoClientError, ExactCrateSpec};

use super::CommandError;

/// Writes `contents` to `path` via a same-directory temp file plus rename, so a
/// crash or concurrent read mid-write can never observe a truncated file.
/// Renaming within one directory is atomic on the platforms this tool ships
/// for (POSIX `rename(2)`; Windows `MoveFileEx` with replace-existing), unlike
/// truncate-in-place `fs::write`, which briefly leaves a zero-length or
/// partial file on disk.
pub(super) fn write_file_atomically(path: &Path, contents: &str) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let temp_path = unique_temp_path(parent, path);

    fs::write(&temp_path, contents).inspect_err(|_| {
        let _ = fs::remove_file(&temp_path);
    })?;
    fs::rename(&temp_path, path).inspect_err(|_| {
        let _ = fs::remove_file(&temp_path);
    })
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

pub(super) fn restore_base_lockfile(
    current_dir: &Path,
    base_lockfile_text: &str,
) -> Result<(), CommandError> {
    let path = current_dir.join("Cargo.lock");
    write_file_atomically(&path, base_lockfile_text).map_err(|source| {
        CommandError::LockfileRestore {
            path: path.display().to_string(),
            source,
        }
    })
}

/// Restores `Cargo.lock` to its pre-mutation text on drop unless [`disarm`]
/// has been called. Every lockfile mutation choreography (load base text,
/// mutate via the runner, recheck) must construct this guard before the
/// first mutating call so that adding a new early-return later cannot
/// reintroduce a leaked mutated lockfile — the class of bug this replaces.
///
/// [`disarm`]: LockfileRestoreGuard::disarm
pub(super) struct LockfileRestoreGuard<'a> {
    current_dir: &'a Path,
    base_lockfile_text: &'a str,
    armed: bool,
}

impl<'a> LockfileRestoreGuard<'a> {
    pub(super) fn new(current_dir: &'a Path, base_lockfile_text: &'a str) -> Self {
        Self {
            current_dir,
            base_lockfile_text,
            armed: true,
        }
    }

    /// Restores immediately and surfaces any restore failure, for call sites
    /// that need the `CommandError` rather than a best-effort drop.
    pub(super) fn restore_now(&mut self) -> Result<(), CommandError> {
        self.armed = false;
        restore_base_lockfile(self.current_dir, self.base_lockfile_text)
    }

    /// Keeps the mutated lockfile: call once the caller has committed to the
    /// mutation succeeding (e.g. the post-mutation recheck passed).
    pub(super) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for LockfileRestoreGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }

        // Best-effort backstop: an explicit restore_now() on every known
        // error path is preferred so failures reach the caller as
        // CommandError::LockfileRestore, but Drop cannot propagate errors, so
        // an unanticipated early return still restores rather than leaking a
        // mutated Cargo.lock (fail-closed over silent fail-open).
        let _ = restore_base_lockfile(self.current_dir, self.base_lockfile_text);
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
