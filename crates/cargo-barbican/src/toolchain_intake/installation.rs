//! Ordinary Rustup slots, independently checked against accepted distribution inputs.
mod effects;
mod files;
mod process;
pub(super) use process::{NativeCancellation, check_cancelled};
#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
mod tests;
pub(super) use effects::{
    ActivationOutcome, InstallOutcome, SelectedInputs, activate_selected, install_selected,
};

use self::files::{CapturedFile, Directory, Identity, Result, error};
use barbican::rust_distribution::{
    ArchiveInventory, EntryKind, ExpectedEntry, Selection, SelectionInventory, check_rustup_config,
    check_rustup_manifest,
};
use barbican::toolchain_admission::{Subject, digest_reader};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

struct VerificationReader<'a> {
    file: File,
    cancelled: &'a AtomicBool,
}
impl std::io::Read for VerificationReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        check_cancelled(self.cancelled, "during installed verification")
            .map_err(std::io::Error::other)?;
        std::io::Read::read(&mut self.file, buffer)
    }
}

#[cfg(test)]
thread_local! {
    pub(super) static VERIFICATION_CHECKPOINT: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

pub(super) const QUALIFIED_RUSTUP_SHA256: &str =
    "16c7599bf448e4e7512779154f6b05042bf2ff715e5e09d9cf5d465a3b750496";

pub(super) fn compiled_host() -> Result<&'static str> {
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        Ok("aarch64-apple-darwin")
    } else {
        Err(format!(
            "native Rustup installation mapping is qualified only for aarch64-apple-darwin Rustup 1.29.0 SHA256 {QUALIFIED_RUSTUP_SHA256}; this compiled host is unsupported; no automatic evaluator fetch or fallback"
        ))
    }
}

#[derive(Debug)]
pub(super) struct InstalledCorrespondence {
    pub slot: PathBuf,
    pub subject_id: String,
    pub mapping_sha256: String,
    pub root_device: u64,
    pub root_inode: u64,
    pub checked_files: usize,
}

struct ExpectedInstallation<'a> {
    selection: &'a Selection,
    original_manifest: &'a [u8],
    payload: BTreeMap<String, ExpectedEntry>,
    component_manifests: BTreeMap<String, Vec<u8>>,
    components: BTreeSet<String>,
}
fn require_qualified_selection(selection: &Selection) -> Result<()> {
    if selection.host != compiled_host()? {
        return Err("selected host differs from qualified native host".into());
    }
    let packages: BTreeSet<_> = selection
        .archives
        .iter()
        .map(|a| a.package.as_str())
        .collect();
    if !["rustc", "cargo", "rust-std"]
        .iter()
        .all(|p| packages.contains(p))
        || selection.archives.iter().any(|a| {
            a.target != selection.host
                || ![
                    "rustc",
                    "cargo",
                    "rust-std",
                    "rust-docs",
                    "clippy-preview",
                    "rustfmt-preview",
                ]
                .contains(&a.package.as_str())
        })
    {
        return Err("unqualified native component/target scope; supported scope is minimal/default with host docs/clippy/rustfmt; cross targets require native correspondence qualification".into());
    }
    Ok(())
}
impl<'a> ExpectedInstallation<'a> {
    fn derive(
        selection: &'a Selection,
        original_manifest: &'a [u8],
        inventories: &[ArchiveInventory],
    ) -> Result<Self> {
        require_qualified_selection(selection)?;
        if inventories.len() != selection.archives.len() {
            return Err("incomplete selected inventory".into());
        }
        let mut combined = SelectionInventory::default();
        let mut component_manifests = BTreeMap::new();
        let mut components = BTreeSet::new();
        for inventory in inventories {
            if !selection.archives.contains(&inventory.identity) {
                return Err("inventory does not match selected archive".into());
            }
            let component = &inventory.identity.component;
            let installed_component = format!(
                "{}-{}",
                inventory.identity.package, inventory.identity.target
            );
            if !components.insert(installed_component.clone()) {
                return Err("duplicate installed component identity".into());
            }
            let source = inventory
                .installer_metadata
                .get(&format!("{component}/manifest.in"))
                .ok_or("missing accepted component ownership metadata")?;
            let normalised = source
                .lines()
                .map(|line| format!("{line}\n"))
                .collect::<String>();
            component_manifests.insert(
                format!("lib/rustlib/manifest-{installed_component}"),
                normalised.into_bytes(),
            );
            combined.add(inventory.clone()).map_err(|e| e.to_string())?;
        }
        let mut payload = combined.payload;
        for entry in payload.values_mut() {
            entry.mode = match entry.mode {
                0o644 | 0o600 => 0o644,
                0o755 | 0o700 => 0o755,
                0o400 => 0o444,
                _ => return Err("unqualified installed mode transformation".into()),
            };
        }
        let generated: Vec<_> = component_manifests
            .keys()
            .cloned()
            .chain([
                "lib/rustlib/components".into(),
                "lib/rustlib/rust-installer-version".into(),
                "lib/rustlib/multirust-config.toml".into(),
                "lib/rustlib/multirust-channel-manifest.toml".into(),
            ])
            .collect();
        for name in payload.keys().chain(generated.iter()) {
            if !name.is_ascii() {
                return Err(
                    "non-ASCII installed paths require filesystem alias qualification".into(),
                );
            }
        }
        for name in &generated {
            if payload.contains_key(name)
                || payload.keys().any(|p| p.starts_with(&format!("{name}/")))
            {
                return Err("payload collides with generated Rustup metadata".into());
            }
        }
        let names: Vec<_> = payload.keys().cloned().chain(generated).collect();
        for name in &names {
            for (index, _) in name.match_indices('/') {
                let parent = &name[..index];
                let directory = ExpectedEntry {
                    kind: EntryKind::Directory,
                    mode: 0o755,
                };
                match payload.get(parent) {
                    Some(entry) if entry.kind != EntryKind::Directory => {
                        return Err("installed destination has non-directory ancestor".into());
                    }
                    Some(_) => (),
                    None => {
                        payload.insert(parent.to_owned(), directory);
                    }
                }
            }
        }
        let mut aliases = BTreeSet::new();
        for name in payload
            .keys()
            .map(String::as_str)
            .chain(component_manifests.keys().map(String::as_str))
            .chain([
                "lib/rustlib/components",
                "lib/rustlib/rust-installer-version",
                "lib/rustlib/multirust-config.toml",
                "lib/rustlib/multirust-channel-manifest.toml",
            ])
        {
            if !aliases.insert(name.to_ascii_lowercase()) {
                return Err("case-aliased installed destinations".into());
            }
        }
        Ok(Self {
            selection,
            original_manifest,
            payload,
            component_manifests,
            components,
        })
    }

    fn verify(&self, slot: &Path, uid: u32, cancelled: &AtomicBool) -> Result<usize> {
        check_cancelled(cancelled, "before installed verification")?;
        let root = Directory::capture(slot, uid)?;
        let mut observed = vec![(slot.to_owned(), fs::symlink_metadata(slot).map_err(error)?)];
        let mut pending = vec![PathBuf::new()];
        let mut visited = BTreeSet::new();
        let mut files = 0;
        let mut expected_names: BTreeSet<_> = self
            .payload
            .keys()
            .cloned()
            .chain(self.component_manifests.keys().cloned())
            .chain([
                "lib/rustlib/components".into(),
                "lib/rustlib/rust-installer-version".into(),
                "lib/rustlib/multirust-config.toml".into(),
                "lib/rustlib/multirust-channel-manifest.toml".into(),
            ])
            .collect();
        while let Some(relative) = pending.pop() {
            for item in fs::read_dir(slot.join(&relative)).map_err(error)? {
                check_cancelled(cancelled, "during installed verification")?;
                let item = item.map_err(error)?;
                let relative = relative.join(item.file_name());
                let name = relative.to_str().ok_or("non-UTF8 installed path")?;
                if !expected_names.remove(name) {
                    return Err(format!(
                        "unexpected installed path {name:?}; review complete scope, do not delete to pass"
                    ));
                }
                let metadata = fs::symlink_metadata(item.path()).map_err(error)?;
                observed.push((item.path(), metadata.clone()));
                if metadata.uid() != uid
                    || !visited.insert((metadata.dev(), metadata.ino()))
                    || (!metadata.is_dir() && (!metadata.is_file() || metadata.nlink() != 1))
                {
                    return Err(format!(
                        "unsupported installed ownership/type/link at {name:?}"
                    ));
                }
                if let Some(expected) = self.payload.get(name) {
                    if metadata.mode() & 0o7777 != expected.mode {
                        return Err(format!("installed mode mismatch at {name:?}"));
                    }
                    match &expected.kind {
                        EntryKind::Directory if metadata.is_dir() => pending.push(relative),
                        EntryKind::File { size, sha256 }
                            if metadata.is_file() && metadata.len() == *size =>
                        {
                            let file = File::open(item.path()).map_err(error)?;
                            if Identity::of(&file.metadata().map_err(error)?)
                                != Identity::of(&metadata)
                            {
                                return Err("installed file changed while opening".into());
                            }
                            #[cfg(test)]
                            VERIFICATION_CHECKPOINT.with(|checkpoint| {
                                if let Some(checkpoint) = checkpoint.borrow_mut().take() {
                                    checkpoint();
                                }
                            });
                            let (actual, count) =
                                digest_reader(VerificationReader { file, cancelled }, *size)
                                    .map_err(error)?;
                            if count != *size || actual != *sha256 {
                                return Err(format!("installed content mismatch at {name:?}"));
                            }
                            files += 1;
                        }
                        _ => return Err(format!("installed type/size mismatch at {name:?}")),
                    }
                } else {
                    if !metadata.is_file() || metadata.mode() & 0o7777 != 0o644 {
                        return Err("unsupported generated metadata type/mode".into());
                    }
                    let captured = CapturedFile::capture(&item.path(), uid, 8 * 1024 * 1024)?;
                    let bytes = captured
                        .bytes
                        .as_deref()
                        .ok_or("installed metadata disappeared")?;
                    match name {
                        "lib/rustlib/components" => {
                            let text =
                                std::str::from_utf8(bytes).map_err(|_| "components is not UTF8")?;
                            let actual: BTreeSet<_> = text.lines().map(str::to_owned).collect();
                            if actual != self.components || actual.len() != text.lines().count() {
                                return Err(
                                    "installed component scope differs; review expanded scope"
                                        .into(),
                                );
                            }
                        }
                        "lib/rustlib/rust-installer-version" if bytes == b"3" => (),
                        "lib/rustlib/multirust-config.toml" => {
                            check_rustup_config(self.selection, bytes).map_err(|e| e.to_string())?
                        }
                        "lib/rustlib/multirust-channel-manifest.toml" => {
                            check_rustup_manifest(self.original_manifest, bytes)
                                .map_err(|e| e.to_string())?
                        }
                        _ if self
                            .component_manifests
                            .get(name)
                            .is_some_and(|expected| expected == bytes) => {}
                        _ => return Err("installed ownership/installer metadata mismatch".into()),
                    }
                    files += 1;
                }
            }
        }
        if !expected_names.is_empty() {
            return Err("selected installed files are missing".into());
        }
        for (path, before) in observed {
            check_cancelled(cancelled, "during installed verification recheck")?;
            let after = fs::symlink_metadata(path).map_err(error)?;
            if Identity::of(&before) != Identity::of(&after)
                || before.len() != after.len()
                || before.mtime() != after.mtime()
                || before.mtime_nsec() != after.mtime_nsec()
                || before.ctime() != after.ctime()
                || before.ctime_nsec() != after.ctime_nsec()
                || before.nlink() != after.nlink()
            {
                return Err("selected installed filesystem changed during verification".into());
            }
        }
        root.recheck()?;
        check_cancelled(cancelled, "before installed verification success")?;
        Ok(files)
    }
}

pub(super) fn verify_selected(
    subject: &Subject,
    selection: &Selection,
    original_manifest: &[u8],
    inventories: &[ArchiveInventory],
    rustup_home: &Path,
) -> Result<InstalledCorrespondence> {
    verify_selected_with_cancellation(
        subject,
        selection,
        original_manifest,
        inventories,
        rustup_home,
        &AtomicBool::new(false),
    )
}

fn verify_selected_with_cancellation(
    subject: &Subject,
    selection: &Selection,
    original_manifest: &[u8],
    inventories: &[ArchiveInventory],
    rustup_home: &Path,
    cancelled: &AtomicBool,
) -> Result<InstalledCorrespondence> {
    let uid = super::store::effective_owner()?;
    let home = Directory::capture(rustup_home, uid)?;
    let slot = rustup_home
        .join("toolchains")
        .join(format!("{}-{}", selection.release, selection.host));
    let expected = ExpectedInstallation::derive(selection, original_manifest, inventories)?;
    let checked_files = expected.verify(&slot, uid, cancelled)?;
    home.recheck()?;
    check_cancelled(cancelled, "before installed correspondence success")?;
    correspondence(subject, slot, checked_files)
}

fn correspondence(
    subject: &Subject,
    slot: PathBuf,
    checked_files: usize,
) -> Result<InstalledCorrespondence> {
    let root = fs::symlink_metadata(&slot).map_err(error)?;
    Ok(InstalledCorrespondence {
        slot,
        subject_id: subject.id().to_string(),
        mapping_sha256: subject.record().mapping_sha256.to_string(),
        root_device: root.dev(),
        root_inode: root.ino(),
        checked_files,
    })
}
