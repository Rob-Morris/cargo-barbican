use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use barbican::Sha256Digest;
use serde::{Deserialize, Serialize};

type Result<T> = std::result::Result<T, String>;
const MAX_OUTPUT_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FileObservation {
    pub sha256: Sha256Digest,
    pub bytes: u64,
    pub mode: u32,
    pub owner: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
    length: u64,
    mode: u32,
    owner: u32,
    links: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}
impl From<&Metadata> for Identity {
    fn from(m: &Metadata) -> Self {
        Self {
            device: m.dev(),
            inode: m.ino(),
            length: m.len(),
            mode: m.mode(),
            owner: m.uid(),
            links: m.nlink(),
            modified: (m.mtime(), m.mtime_nsec()),
            changed: (m.ctime(), m.ctime_nsec()),
        }
    }
}

pub(super) fn absolute(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|p| matches!(p, Component::ParentDir | Component::CurDir))
    {
        return Err("path must be absolute without traversal".into());
    }
    if path.as_os_str().len() > 4096 || path.components().count() > 128 {
        return Err("path exceeds supported bounds".into());
    }
    Ok(())
}

pub(super) fn protected_ancestors(path: &Path, uid: u32) -> Result<()> {
    absolute(path)?;
    for ancestor in path.ancestors() {
        let m = fs::symlink_metadata(ancestor)
            .map_err(|e| format!("inspect {}: {e}", ancestor.display()))?;
        if !m.is_dir()
            || m.file_type().is_symlink()
            || (m.uid() != uid && m.uid() != 0)
            || (m.mode() & 0o022 != 0 && !(m.uid() == 0 && m.mode() & 0o1000 != 0))
        {
            return Err(format!(
                "unprotected or indirect directory: {}",
                ancestor.display()
            ));
        }
    }
    Ok(())
}

pub(super) fn check_cancelled(cancelled: &AtomicBool) -> Result<()> {
    if cancelled.load(Ordering::SeqCst) {
        Err("tool operation cancelled".into())
    } else {
        Ok(())
    }
}

struct CancelReader<'a> {
    file: File,
    cancelled: &'a AtomicBool,
}
impl Read for CancelReader<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.cancelled.load(Ordering::SeqCst) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "tool operation cancelled",
            ));
        }
        self.file.read(bytes)
    }
}

pub(super) fn observe(
    path: &Path,
    uid: u32,
    executable: bool,
    cancelled: &AtomicBool,
) -> Result<FileObservation> {
    observe_as(path, uid, uid, executable, Links::Single, cancelled)
}

pub(super) fn observe_build_artifact(
    path: &Path,
    uid: u32,
    cancelled: &AtomicBool,
) -> Result<FileObservation> {
    // Cargo can hard-link temporary target artifacts. These establish byte
    // correspondence only; installed outputs still require independent custody.
    observe_as(path, uid, uid, true, Links::BuildArtifact, cancelled)
}

pub(super) fn observe_trusted_executable(
    path: &Path,
    uid: u32,
    cancelled: &AtomicBool,
) -> Result<FileObservation> {
    let owner = fs::symlink_metadata(path).map_err(|e| e.to_string())?.uid();
    if owner != uid && owner != 0 {
        return Err("selected evaluator has unsupported ownership".into());
    }
    observe_as(path, uid, owner, true, Links::Single, cancelled)
}

enum Links {
    Single,
    BuildArtifact,
}

fn observe_as(
    path: &Path,
    uid: u32,
    owner: u32,
    executable: bool,
    links: Links,
    cancelled: &AtomicBool,
) -> Result<FileObservation> {
    check_cancelled(cancelled)?;
    protected_ancestors(path.parent().ok_or("file has no parent")?, uid)?;
    let metadata =
        fs::symlink_metadata(path).map_err(|e| format!("inspect {}: {e}", path.display()))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != owner
        || (matches!(links, Links::Single) && metadata.nlink() != 1)
        || metadata.mode() & 0o7022 != 0
        || (executable && metadata.mode() & 0o100 == 0)
    {
        return Err(format!(
            "expected protected {}{}file: {}",
            if matches!(links, Links::Single) {
                "singly linked "
            } else {
                ""
            },
            if executable { "executable " } else { "" },
            path.display()
        ));
    }
    if metadata.len() > MAX_OUTPUT_BYTES {
        return Err("output exceeds byte bound".into());
    }
    let identity = Identity::from(&metadata);
    let file = File::open(path).map_err(|e| e.to_string())?;
    if Identity::from(&file.metadata().map_err(|e| e.to_string())?) != identity {
        return Err("file changed while opening".into());
    }
    let mut reader = CancelReader { file, cancelled };
    let (sha256, bytes) =
        barbican::toolchain_admission::digest_reader(&mut reader, MAX_OUTPUT_BYTES)
            .map_err(|e| e.to_string())?;
    if Identity::from(&reader.file.metadata().map_err(|e| e.to_string())?) != identity
        || Identity::from(&fs::symlink_metadata(path).map_err(|e| e.to_string())?) != identity
    {
        return Err("file changed while observing".into());
    }
    protected_ancestors(path.parent().ok_or("file has no parent")?, uid)?;
    check_cancelled(cancelled)?;
    Ok(FileObservation {
        sha256,
        bytes,
        mode: metadata.mode() & 0o7777,
        owner: metadata.uid(),
    })
}

pub(super) fn read_record(
    path: &Path,
    uid: u32,
    limit: usize,
    cancelled: &AtomicBool,
) -> Result<Vec<u8>> {
    let before = observe(path, uid, false, cancelled)?;
    if before.bytes > limit as u64 {
        return Err("record exceeds byte limit".into());
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|e| e.to_string())?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > limit
        || barbican::cargo_tool::sha256(&bytes) != before.sha256
        || observe(path, uid, false, cancelled)? != before
    {
        return Err("record changed while reading".into());
    }
    Ok(bytes)
}

pub(super) fn output_path(root: &Path, name: &str) -> Result<PathBuf> {
    if name.is_empty()
        || name.len() > 255
        || !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
    {
        return Err("invalid output name".into());
    }
    absolute(root)?;
    Ok(root.join("bin").join(name))
}

pub(super) fn require_native_executable(path: &Path) -> Result<()> {
    let mut prefix = [0u8; 4];
    File::open(path)
        .map_err(|e| e.to_string())?
        .read_exact(&mut prefix)
        .map_err(|e| e.to_string())?;
    if prefix != *b"\x7fELF"
        && prefix != [0xcf, 0xfa, 0xed, 0xfe]
        && prefix != [0xfe, 0xed, 0xfa, 0xcf]
    {
        return Err("consumer executable uses an unqualified shim or executable encoding".into());
    }
    Ok(())
}
