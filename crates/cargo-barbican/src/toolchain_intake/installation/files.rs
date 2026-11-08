use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub(super) type Result<T> = std::result::Result<T, String>;
static NEXT: AtomicU64 = AtomicU64::new(0);

pub(super) fn error(error: std::io::Error) -> String {
    format!("toolchain filesystem: {error}")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Identity {
    pub device: u64,
    pub inode: u64,
    pub uid: u32,
    pub mode: u32,
}
impl Identity {
    pub fn of(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            mode: metadata.mode(),
        }
    }
}

pub(super) fn ancestors(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err("toolchain path must be absolute without traversal".into());
    }
    let mut current = PathBuf::new();
    for part in path.components() {
        current.push(part);
        let metadata = fs::symlink_metadata(&current).map_err(error)?;
        if !metadata.file_type().is_dir() {
            return Err(format!(
                "toolchain ancestor is not a real directory: {}",
                current.display()
            ));
        }
    }
    Ok(())
}

#[derive(Debug)]
pub(super) struct Directory {
    pub path: PathBuf,
    identity: Identity,
}
impl Directory {
    pub fn capture(path: &Path, uid: u32) -> Result<Self> {
        ancestors(path)?;
        let metadata = fs::symlink_metadata(path).map_err(error)?;
        if metadata.uid() != uid || metadata.mode() & 0o022 != 0 {
            return Err(
                "toolchain directory must be owned by the current user and not writable by others"
                    .into(),
            );
        }
        Ok(Self {
            path: path.to_owned(),
            identity: Identity::of(&metadata),
        })
    }
    pub fn recheck(&self) -> Result<()> {
        ancestors(&self.path)?;
        if Identity::of(&fs::symlink_metadata(&self.path).map_err(error)?) != self.identity {
            return Err("toolchain directory changed during operation".into());
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(super) struct CapturedFile {
    path: PathBuf,
    parent_identity: Identity,
    pub bytes: Option<Vec<u8>>,
    identity: Option<Identity>,
}
impl CapturedFile {
    pub fn capture(path: &Path, uid: u32, limit: u64) -> Result<Self> {
        ancestors(path.parent().ok_or("file has no parent")?)?;
        let parent_identity = Identity::of(
            &fs::symlink_metadata(path.parent().ok_or("file has no parent")?).map_err(error)?,
        );
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self {
                    path: path.to_owned(),
                    parent_identity,
                    bytes: None,
                    identity: None,
                });
            }
            Err(e) => return Err(error(e)),
        };
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != uid
            || metadata.mode() & 0o022 != 0
            || metadata.len() > limit
        {
            return Err(format!(
                "unsafe or oversized toolchain file: {}",
                path.display()
            ));
        }
        let mut file = File::open(path).map_err(error)?;
        let identity = Identity::of(&metadata);
        if Identity::of(&file.metadata().map_err(error)?) != identity {
            return Err("toolchain file changed while opening".into());
        }
        let mut bytes = Vec::new();
        (&mut file)
            .take(limit + 1)
            .read_to_end(&mut bytes)
            .map_err(error)?;
        if bytes.len() as u64 > limit {
            return Err("toolchain file size limit".into());
        }
        let result = Self {
            path: path.to_owned(),
            parent_identity,
            bytes: Some(bytes),
            identity: Some(identity),
        };
        result.recheck()?;
        Ok(result)
    }
    pub fn recheck(&self) -> Result<()> {
        ancestors(self.path.parent().ok_or("file has no parent")?)?;
        if Identity::of(
            &fs::symlink_metadata(self.path.parent().ok_or("file has no parent")?)
                .map_err(error)?,
        ) != self.parent_identity
        {
            return Err("toolchain file parent changed during operation".into());
        }
        match (
            &self.bytes,
            &self.identity,
            fs::symlink_metadata(&self.path),
        ) {
            (None, None, Err(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            (Some(bytes), Some(identity), Ok(metadata))
                if metadata.is_file()
                    && metadata.nlink() == 1
                    && Identity::of(&metadata) == *identity
                    && metadata.len() == bytes.len() as u64 =>
            {
                let mut actual = Vec::new();
                let file = File::open(&self.path).map_err(error)?;
                if Identity::of(&file.metadata().map_err(error)?) != *identity {
                    return Err("toolchain file changed while reopening".into());
                }
                file.take(bytes.len() as u64 + 1)
                    .read_to_end(&mut actual)
                    .map_err(error)?;
                if actual == *bytes {
                    Ok(())
                } else {
                    Err("toolchain input bytes changed".into())
                }
            }
            _ => Err("toolchain input changed during operation".into()),
        }
    }
    pub fn publish(&self, bytes: &[u8], cancelled: &AtomicBool) -> Result<()> {
        self.recheck()?;
        let parent = self.path.parent().ok_or("file has no parent")?;
        let temporary = parent.join(format!(
            ".barbican-toolchain-pin-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(error)?;
        let result = (|| {
            file.write_all(bytes).map_err(error)?;
            file.set_permissions(fs::Permissions::from_mode(
                self.identity.as_ref().map_or(0o644, |i| i.mode & 0o777),
            ))
            .map_err(error)?;
            self.recheck()?;
            if cancelled.load(Ordering::SeqCst) {
                return Err("cancelled before pin replacement; old pin retained".into());
            }
            fs::rename(&temporary, &self.path).map_err(error)?;
            let actual = Self::capture(
                &self.path,
                file.metadata().map_err(error)?.uid(),
                bytes.len() as u64,
            )?;
            if actual.bytes.as_deref() != Some(bytes) {
                return Err("pin published but subsequent observation differs; inspect retained repository pin".into());
            }
            Ok(())
        })();
        if let (Ok(actual), Ok(owned)) = (fs::symlink_metadata(&temporary), file.metadata())
            && Identity::of(&actual) == Identity::of(&owned)
        {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}
