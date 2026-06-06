use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::DirBuilderExt;

pub(super) struct ScratchDir {
    path: PathBuf,
    preserve: bool,
}

impl ScratchDir {
    pub(super) fn create(prefix: &str, preserve: bool) -> Result<Self, std::io::Error> {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "{prefix}-{timestamp}-{}",
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));

        create_private_dir(&path)?;

        Ok(Self { path, preserve })
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        if !self.preserve {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

#[cfg(unix)]
fn create_private_dir(path: &Path) -> Result<(), std::io::Error> {
    fs::DirBuilder::new().mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_private_dir(path: &Path) -> Result<(), std::io::Error> {
    fs::create_dir(path)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::ScratchDir;

    #[cfg(unix)]
    #[test]
    fn scratch_dir_temp_root_is_private_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let scratch = ScratchDir::create("cargo-barbican-scratch-test", false)
            .expect("private scratch root should be created");

        let mode = fs::metadata(scratch.path())
            .expect("private scratch root metadata should read")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn scratch_dir_removes_unpreserved_paths_on_drop() {
        let path = {
            let scratch = ScratchDir::create("cargo-barbican-scratch-test", false)
                .expect("scratch root should be created");
            let path = scratch.path().to_path_buf();
            assert!(path.exists());
            path
        };

        assert!(!path.exists());
    }

    #[test]
    fn scratch_dir_preserves_paths_when_requested() {
        let scratch = ScratchDir::create("cargo-barbican-scratch-test", true)
            .expect("scratch root should be created");
        let path = scratch.path().to_path_buf();

        drop(scratch);

        assert!(path.exists());
        fs::remove_dir_all(path).expect("preserved scratch dir should clean up");
    }
}
