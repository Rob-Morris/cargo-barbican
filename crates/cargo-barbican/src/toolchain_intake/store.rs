//! Private local authority and independent snapshots; single writer with detected conflicts.
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};

static NEXT: AtomicU64 = AtomicU64::new(0);
pub(super) type Result<T> = std::result::Result<T, String>;

#[derive(Debug)]
pub(super) struct PrivateStore {
    root: PathBuf,
    identity: Identity,
    uid: u32,
}

#[derive(Debug, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
}

#[derive(Debug)]
pub(super) struct CapturedFile {
    path: PathBuf,
    identity: Identity,
    bytes: Vec<u8>,
}

impl CapturedFile {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl PrivateStore {
    pub fn open(path: &Path, forbidden: &[&Path]) -> Result<Self> {
        if !path.is_absolute() || path.components().any(|c| matches!(c, Component::ParentDir)) {
            return Err(
                "local state root must be an absolute path without parent traversal".into(),
            );
        }
        let uid = effective_owner()?;
        let root = create_private_root(path, uid)?;
        for other in forbidden {
            let other = fs::canonicalize(other).map_err(io_error)?;
            if root.starts_with(&other) || other.starts_with(&root) {
                return Err("local authority, cache and repository roots must be separate".into());
            }
        }
        let metadata = fs::symlink_metadata(&root).map_err(io_error)?;
        private_directory(&metadata, uid)?;
        Ok(Self {
            root,
            identity: identity(&metadata),
            uid,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn recheck(&self) -> Result<()> {
        let metadata = fs::symlink_metadata(&self.root).map_err(io_error)?;
        private_directory(&metadata, self.uid)?;
        if identity(&metadata) != self.identity
            || fs::canonicalize(&self.root).map_err(io_error)? != self.root
        {
            return Err("local state root changed during the operation".into());
        }
        Ok(())
    }

    fn path(&self, relative: &Path, create_parents: bool) -> Result<PathBuf> {
        self.recheck()?;
        if relative.as_os_str().is_empty()
            || relative
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
        {
            return Err("local record path must be a contained relative path".into());
        }
        let mut path = self.root.clone();
        let parts: Vec<_> = relative.components().collect();
        for part in &parts[..parts.len() - 1] {
            path.push(part.as_os_str());
            match fs::symlink_metadata(&path) {
                Ok(metadata) => private_directory(&metadata, self.uid)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound && create_parents => {
                    private_mkdir(&path)?;
                    private_directory(&fs::symlink_metadata(&path).map_err(io_error)?, self.uid)?;
                }
                Err(error) => return Err(io_error(error)),
            }
        }
        path.push(parts.last().expect("nonempty").as_os_str());
        Ok(path)
    }

    pub fn read(&self, relative: &Path, limit: u64) -> Result<CapturedFile> {
        let path = self
            .path(relative, false)
            .map_err(|e| format!("read local record {}: {e}", relative.display()))?;
        let metadata = fs::symlink_metadata(&path).map_err(|e| {
            format!(
                "read local record {}: {e}; collect or explicitly import its reviewed inputs first",
                relative.display()
            )
        })?;
        private_file(&metadata, self.uid)?;
        if metadata.len() > limit {
            return Err("local record exceeds size limit".into());
        }
        let file = File::open(&path).map_err(io_error)?;
        if identity(&file.metadata().map_err(io_error)?) != identity(&metadata) {
            return Err("local record changed while opening".into());
        }
        let mut bytes = Vec::new();
        file.take(limit + 1)
            .read_to_end(&mut bytes)
            .map_err(io_error)?;
        if bytes.len() as u64 > limit {
            return Err("local record exceeds size limit".into());
        }
        let captured = CapturedFile {
            path,
            identity: identity(&metadata),
            bytes,
        };
        self.check_capture(&captured)?;
        Ok(captured)
    }

    pub fn read_optional(&self, relative: &Path, limit: u64) -> Result<Option<CapturedFile>> {
        // The parent is still validated; missing records do not establish authority.
        let path = self.path(relative, true)?;
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(io_error(error)),
            Ok(_) => self.read(relative, limit).map(Some),
        }
    }

    pub fn check_capture(&self, captured: &CapturedFile) -> Result<()> {
        let relative = captured
            .path
            .strip_prefix(&self.root)
            .map_err(|_| "foreign captured record")?;
        let path = self
            .path(relative, false)
            .map_err(|e| format!("read local record {}: {e}", relative.display()))?;
        let metadata = fs::symlink_metadata(&path).map_err(|e| {
            format!(
                "read local record {}: {e}; collect or explicitly import its reviewed inputs first",
                relative.display()
            )
        })?;
        private_file(&metadata, self.uid)?;
        if identity(&metadata) != captured.identity || metadata.len() != captured.bytes.len() as u64
        {
            return Err("local record changed during the operation".into());
        }
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(io_error)?
            .take(captured.bytes.len() as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(io_error)?;
        if bytes != captured.bytes {
            return Err("local record bytes changed during the operation".into());
        }
        Ok(())
    }

    pub fn publish(&self, relative: &Path, bytes: &[u8]) -> Result<()> {
        self.publish_checked(relative, bytes, || Ok(()))
    }

    pub fn publish_checked(
        &self,
        relative: &Path,
        bytes: &[u8],
        check: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        let path = self.path(relative, true)?;
        check()?;
        let mut file = private_create(&path)?;
        if let Err(error) = file.write_all(bytes) {
            return Err(format!(
                "local record publication failed; partial record retained: {error}"
            ));
        }
        self.recheck()?;
        Ok(())
    }

    pub fn open_snapshot(&self, relative: &Path, limit: u64) -> Result<File> {
        let path = self
            .path(relative, false)
            .map_err(|e| format!("read local record {}: {e}", relative.display()))?;
        let metadata = fs::symlink_metadata(&path).map_err(|e| {
            format!(
                "read local record {}: {e}; collect or explicitly import its reviewed inputs first",
                relative.display()
            )
        })?;
        private_file(&metadata, self.uid)?;
        if metadata.len() > limit {
            return Err("snapshot exceeds size limit".into());
        }
        let file = File::open(path).map_err(io_error)?;
        if identity(&file.metadata().map_err(io_error)?) != identity(&metadata) {
            return Err("snapshot changed while opening".into());
        }
        Ok(file)
    }

    pub fn publish_stream(
        &self,
        relative: &Path,
        reader: impl Read,
        limit: u64,
    ) -> Result<PathBuf> {
        let path = self.path(relative, true)?;
        if fs::symlink_metadata(&path).is_ok() {
            return Err("snapshot already exists".into());
        }
        let temporary = path
            .parent()
            .ok_or("snapshot has no parent")?
            .join(unique_name("snapshot"));
        let result = (|| {
            let mut file = private_create(&temporary)?;
            let copied = std::io::copy(&mut reader.take(limit + 1), &mut file).map_err(io_error)?;
            if copied > limit {
                return Err("snapshot exceeds size limit".into());
            }
            self.path(relative, false)?;
            match fs::symlink_metadata(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(io_error(error)),
                Ok(_) => return Err("snapshot publication conflict".into()),
            }
            fs::rename(&temporary, &path).map_err(io_error)?;
            self.recheck()?;
            Ok(path)
        })();
        if temporary.exists() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    pub fn replace(&self, captured: &CapturedFile, bytes: &[u8]) -> Result<()> {
        self.replace_checked(captured, bytes, || Ok(()))
    }

    pub fn replace_checked(
        &self,
        captured: &CapturedFile,
        bytes: &[u8],
        check: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        self.check_capture(captured)?;
        let parent = captured.path.parent().ok_or("record has no parent")?;
        let temporary = parent.join(unique_name("publication"));
        let result = (|| {
            let mut file = private_create(&temporary)?;
            file.write_all(bytes).map_err(io_error)?;
            self.check_capture(captured)?;
            check()?;
            fs::rename(&temporary, &captured.path).map_err(io_error)?;
            self.recheck()
        })();
        if temporary.exists() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

fn unique_name(kind: &str) -> String {
    format!(
        ".barbican-{kind}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}
fn io_error(error: std::io::Error) -> String {
    format!("local state I/O: {error}")
}

#[cfg(unix)]
pub(super) fn effective_owner() -> Result<u32> {
    let path = std::env::temp_dir().join(unique_name("owner"));
    let file = private_create(&path)?;
    let owner = file.metadata().map_err(io_error)?.uid();
    fs::remove_file(path).map_err(io_error)?;
    Ok(owner)
}
#[cfg(unix)]
fn identity(metadata: &fs::Metadata) -> Identity {
    Identity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}
#[cfg(unix)]
fn private_directory(metadata: &fs::Metadata, uid: u32) -> Result<()> {
    if !metadata.file_type().is_dir() || metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
        return Err(
            "local state directory must be owned by the current user, private, and not a symlink"
                .into(),
        );
    }
    Ok(())
}
#[cfg(unix)]
fn private_file(metadata: &fs::Metadata, uid: u32) -> Result<()> {
    if !metadata.file_type().is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o177 != 0
        || metadata.nlink() != 1
    {
        return Err("local record must be a private, non-executable, singly linked regular file owned by the current user".into());
    }
    Ok(())
}
#[cfg(unix)]
fn private_create(path: &Path) -> Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(io_error)
}
#[cfg(unix)]
fn private_mkdir(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(path).map_err(io_error)
}
fn create_private_root(path: &Path, uid: u32) -> Result<PathBuf> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            private_directory(&metadata, uid)?;
            fs::canonicalize(path).map_err(io_error)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path.parent().ok_or("state root has no parent")?;
            let parent = if parent.exists() {
                fs::canonicalize(parent).map_err(io_error)?
            } else {
                create_private_root(parent, uid)?
            };
            let resolved = parent.join(path.file_name().ok_or("state root has no name")?);
            private_mkdir(&resolved)?;
            Ok(resolved)
        }
        Err(error) => Err(io_error(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            let path = std::env::temp_dir().join(unique_name("store-test"));
            private_mkdir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn cancellation_at_publication_boundary_preserves_existing_bindings() {
        let root = std::env::temp_dir().join(unique_name("cancelled-binding"));
        let store = PrivateStore::open(&root, &[]).unwrap();
        let existing = Path::new("continuing/existing.json");
        store.publish(existing, b"old binding").unwrap();
        let captured = store.read(existing, 100).unwrap();
        let cancel = || Err("cancelled before continuing-use binding publication".into());
        assert!(
            store
                .replace_checked(&captured, b"new binding", cancel)
                .is_err()
        );
        assert_eq!(store.read(existing, 100).unwrap().bytes(), b"old binding");
        let new = Path::new("continuing/new.json");
        assert!(store.publish_checked(new, b"new binding", cancel).is_err());
        assert!(store.read_optional(new, 100).unwrap().is_none());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn replacement_preserves_external_changes_and_immutable_publication_conflicts() {
        let scratch = Scratch::new();
        let store = PrivateStore::open(&scratch.0.join("data"), &[]).unwrap();
        store
            .publish(Path::new("trust/current.json"), b"first")
            .unwrap();
        let captured = store.read(Path::new("trust/current.json"), 100).unwrap();
        assert!(
            store
                .publish(Path::new("trust/current.json"), b"second")
                .is_err()
        );
        store.replace(&captured, b"approved").unwrap();
        assert!(store.replace(&captured, b"stale").is_err());
        assert_eq!(
            store
                .read(Path::new("trust/current.json"), 100)
                .unwrap()
                .bytes(),
            b"approved"
        );
        let captured = store.read(Path::new("trust/current.json"), 100).unwrap();
        fs::write(store.root().join("trust/current.json"), b"external").unwrap();
        assert!(store.replace(&captured, b"stale").is_err());
        assert_eq!(
            fs::read(store.root().join("trust/current.json")).unwrap(),
            b"external"
        );
    }

    #[test]
    fn refuses_links_nonprivate_files_traversal_and_oversize() {
        let scratch = Scratch::new();
        let store = PrivateStore::open(&scratch.0.join("data"), &[]).unwrap();
        store.publish(Path::new("original"), b"private").unwrap();
        fs::hard_link(store.root().join("original"), store.root().join("hard")).unwrap();
        assert!(store.read(Path::new("hard"), 100).is_err());
        fs::remove_file(store.root().join("hard")).unwrap();
        assert!(store.read(Path::new("original"), 3).is_err());
        symlink(store.root().join("original"), store.root().join("link")).unwrap();
        assert!(store.read(Path::new("link"), 100).is_err());
        symlink(&scratch.0, store.root().join("parent")).unwrap();
        assert!(store.publish(Path::new("parent/escaped"), b"x").is_err());
        assert!(store.publish(Path::new("../escaped"), b"x").is_err());
        fs::set_permissions(
            store.root().join("original"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(store.read(Path::new("original"), 100).is_err());
    }

    #[test]
    fn rejects_root_substitution_and_authority_inside_repository() {
        let scratch = Scratch::new();
        let store = PrivateStore::open(&scratch.0.join("data"), &[]).unwrap();
        assert!(PrivateStore::open(&scratch.0.join("data/authority"), &[&scratch.0]).is_err());
        fs::rename(store.root(), scratch.0.join("old")).unwrap();
        private_mkdir(store.root()).unwrap();
        assert!(store.publish(Path::new("record"), b"x").is_err());
    }
}
