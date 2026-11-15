use crate::controlled_process::{self as process, Budget, Executable, FILE_LIMIT, Result, err};
use barbican::cargo_tool::{
    InputFile, InputKind, MAX_DEPTH, MAX_FILES, MAX_PATH_BYTES, MAX_SOURCE_BYTES, canonical_bytes,
    sha256,
};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);

pub(crate) struct Stage {
    pub root: PathBuf,
    identity: (u64, u64),
}
impl Stage {
    pub fn new() -> Result<Self> {
        let parent = fs::canonicalize(std::env::temp_dir()).map_err(err)?;
        for _ in 0..100 {
            let root = parent.join(format!(
                "barbican-tool-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::SeqCst)
            ));
            match fs::DirBuilder::new().mode(0o700).create(&root) {
                Ok(()) => {
                    use std::os::unix::fs::MetadataExt;
                    let metadata = fs::symlink_metadata(&root).map_err(err)?;
                    return Ok(Self {
                        root,
                        identity: (metadata.dev(), metadata.ino()),
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.to_string()),
            }
        }
        Err("unable to create owned source stage".into())
    }
}
impl Drop for Stage {
    fn drop(&mut self) {
        use std::os::unix::fs::MetadataExt;
        if !fs::symlink_metadata(&self.root).is_ok_and(|metadata| {
            metadata.is_dir() && (metadata.dev(), metadata.ino()) == self.identity
        }) {
            return;
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}
pub(crate) fn safe_relative(value: &str) -> Result<&Path> {
    let path = Path::new(value);
    if value.is_empty()
        || value.len() > MAX_PATH_BYTES
        || value.contains('\\')
        || value
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || value.chars().any(char::is_control)
        || path.components().count() > MAX_DEPTH
        || path
            .components()
            .any(|p| !matches!(p, Component::Normal(_)))
    {
        return Err("unsafe or excessive source path".into());
    }
    Ok(path)
}
pub(crate) fn write_source(
    root: &Path,
    path: &str,
    mode: u32,
    bytes: &[u8],
    budget: &Budget,
) -> Result<()> {
    budget.materialise(bytes.len() as u64)?;
    let relative = safe_relative(path)?;
    let destination = root.join(relative);
    let parent = destination.parent().ok_or("source path has no parent")?;
    if parent != root {
        create_source_directory(
            root,
            parent
                .strip_prefix(root)
                .map_err(err)?
                .to_str()
                .ok_or("source directory is not UTF-8")?,
            budget,
        )?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&destination)
        .map_err(err)?;
    for chunk in bytes.chunks(64 * 1024) {
        budget.check()?;
        file.write_all(chunk).map_err(err)?;
    }
    file.set_permissions(fs::Permissions::from_mode(mode))
        .map_err(err)
}
pub(crate) fn create_source_directory(root: &Path, path: &str, budget: &Budget) -> Result<()> {
    let mut directory = root.to_owned();
    for component in safe_relative(path)?.components() {
        budget.check()?;
        directory.push(component);
        match fs::symlink_metadata(&directory) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => return Err("source directory collides with a non-directory entry".into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                budget.materialise(0)?;
                fs::create_dir(&directory).map_err(err)?;
            }
            Err(error) => return Err(err(error)),
        }
    }
    Ok(())
}
pub(crate) fn materialise_crate(
    root: &Path,
    spec: &barbican::ExactCrateSpec,
    archive: &[u8],
    checksum: &barbican::Sha256Digest,
    budget: &Budget,
) -> Result<()> {
    let mut directories = Vec::new();
    barbican::inspect::visit_verified_crate_archive_checked(
        spec,
        archive,
        checksum,
        &mut || budget.check(),
        |path, mode, contents| {
            budget.check()?;
            match contents {
                Some(bytes) => write_source(root, path, mode, bytes, budget),
                None => {
                    let destination = root.join(safe_relative(path)?);
                    create_source_directory(root, path, budget)?;
                    directories.push((destination, mode));
                    Ok(())
                }
            }
        },
    )?;
    directories.sort_by_key(|(path, _)| std::cmp::Reverse(path.components().count()));
    for (path, mode) in directories {
        budget.check()?;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(err)?;
    }
    Ok(())
}
pub(crate) fn inventory(root: &Path, prefix: &str, budget: &Budget) -> Result<BTreeSet<InputFile>> {
    let mut found = BTreeSet::new();
    let mut virtual_path = String::new();
    for part in prefix.split('/') {
        if !virtual_path.is_empty() {
            virtual_path.push('/');
        }
        virtual_path.push_str(part);
        found.insert(InputFile {
            path: virtual_path.clone(),
            kind: InputKind::Directory,
            mode: 0o755,
            bytes: 0,
            sha256: sha256(&[]),
        });
    }
    let mut stack = vec![(root.to_owned(), 0usize)];
    let mut total = 0u64;
    while let Some((directory, depth)) = stack.pop() {
        budget.check()?;
        if depth > MAX_DEPTH {
            return Err("source path depth exceeded".into());
        }
        for entry in fs::read_dir(directory).map_err(err)? {
            if found.len() >= MAX_FILES {
                return Err("source entry inventory budget exceeded".into());
            }
            let entry = entry.map_err(err)?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(err)?;
            let relative = path
                .strip_prefix(root)
                .map_err(err)?
                .to_str()
                .ok_or("source path is not UTF8")?
                .to_owned();
            safe_relative(&relative)?;
            if relative == ".git" {
                continue;
            }
            if metadata.is_dir() {
                found.insert(InputFile {
                    path: format!("{prefix}/{relative}"),
                    kind: InputKind::Directory,
                    mode: metadata.permissions().mode() & 0o777,
                    bytes: 0,
                    sha256: sha256(&[]),
                });
                stack.push((path, depth + 1));
                continue;
            }
            if !metadata.is_file() {
                return Err("source contains links or special files".into());
            }
            let bytes = process::read_bounded(&path, FILE_LIMIT, budget)?;
            total = total
                .checked_add(bytes.len() as u64)
                .ok_or("inventory bytes overflow")?;
            if total > MAX_SOURCE_BYTES || found.len() >= MAX_FILES {
                return Err("source inventory budget exceeded".into());
            }
            found.insert(InputFile {
                path: format!("{prefix}/{relative}"),
                kind: InputKind::RegularFile,
                mode: metadata.permissions().mode() & 0o777,
                bytes: bytes.len() as u64,
                sha256: sha256(&bytes),
            });
        }
    }
    Ok(found)
}
pub(crate) fn inventory_digest(files: &BTreeSet<InputFile>) -> Result<barbican::Sha256Digest> {
    Ok(sha256(&canonical_bytes(files).map_err(err)?))
}

pub(crate) fn git_materialise(
    url: &str,
    rev: &str,
    destination: &Path,
    scratch: &Path,
    budget: &Budget,
) -> Result<()> {
    barbican::GitSourceIdentity::new(url, rev).map_err(err)?;
    if !url.starts_with("https://") {
        return Err("Git transport outside qualified credential-free HTTPS route".into());
    }
    budget.materialise(0)?;
    fs::create_dir(destination).map_err(err)?;
    let git = Executable::capture(Path::new("/usr/bin/git"), budget)?;
    let db = scratch.join(format!("objects-{}", NEXT.fetch_add(1, Ordering::SeqCst)));
    let env = process::base_environment(scratch, scratch, Path::new("/usr/bin/false"));
    let invoke = |arguments: Vec<String>| -> Result<Vec<u8>> {
        let mut args = vec![
            "-c".into(),
            "protocol.allow=never".into(),
            "-c".into(),
            "protocol.https.allow=always".into(),
            "-c".into(),
            "credential.helper=".into(),
            "-c".into(),
            "core.hooksPath=/dev/null".into(),
            "-c".into(),
            "fetch.unpackLimit=1".into(),
            "-c".into(),
            "fetch.recurseSubmodules=false".into(),
            "-c".into(),
            "fetch.fsckObjects=true".into(),
            "-c".into(),
            "transfer.fsckObjects=true".into(),
            "-c".into(),
            "http.followRedirects=false".into(),
        ];
        args.extend(arguments);
        let output = process::run_git_bounded(&git, &args, scratch, &env, budget)?;
        if !output.status.success() {
            return Err("trusted Git immutable-object collection failed".into());
        }
        Ok(output.stdout)
    };
    invoke(vec![
        "init".into(),
        "--bare".into(),
        db.to_string_lossy().into_owned(),
    ])?;
    let base = vec!["--git-dir".into(), db.to_string_lossy().into_owned()];
    let mut args = base.clone();
    args.extend([
        "fetch".into(),
        "--no-tags".into(),
        "--depth=1".into(),
        "--no-recurse-submodules".into(),
        "--no-auto-maintenance".into(),
        "--".into(),
        url.into(),
        rev.into(),
    ]);
    invoke(args)?;
    let mut args = base.clone();
    args.extend(["rev-parse".into(), "FETCH_HEAD^{commit}".into()]);
    if String::from_utf8(invoke(args)?).map_err(err)?.trim() != rev {
        return Err("Git fetch did not resolve exact accepted commit".into());
    }
    let mut args = base.clone();
    args.extend([
        "ls-tree".into(),
        "-r".into(),
        "-z".into(),
        "--full-tree".into(),
        rev.into(),
    ]);
    let tree = invoke(args)?;
    let mut count = 0;
    for raw in tree
        .split(|byte| *byte == 0)
        .filter(|value| !value.is_empty())
    {
        budget.check()?;
        count += 1;
        if count > MAX_FILES {
            return Err("Git tree file budget exceeded".into());
        }
        let line = std::str::from_utf8(raw).map_err(err)?;
        let (header, path) = line.split_once('\t').ok_or("malformed Git tree entry")?;
        let fields: Vec<_> = header.split(' ').collect();
        if fields.len() != 3
            || fields[1] != "blob"
            || !matches!(fields[0], "100644" | "100755")
            || fields[2].len() != 40
        {
            return Err("Git tree contains links, submodules or unsupported objects".into());
        }
        safe_relative(path)?;
        let mut args = base.clone();
        args.extend(["cat-file".into(), "blob".into(), fields[2].into()]);
        let bytes = invoke(args)?;
        if Path::new(path).file_name() == Some(std::ffi::OsStr::new(".gitattributes"))
            && String::from_utf8_lossy(&bytes)
                .split_whitespace()
                .any(|word| word == "filter" || word.starts_with("filter="))
        {
            return Err("Git content filters require separate source qualification".into());
        }
        if bytes.starts_with(b"version https://git-lfs.github.com/spec/") {
            return Err("Git LFS external source is unqualified".into());
        }
        write_source(
            destination,
            path,
            if fields[0] == "100755" { 0o755 } else { 0o644 },
            &bytes,
            budget,
        )?;
    }
    fs::remove_dir_all(&db).map_err(err)?;
    Ok(())
}

pub(crate) fn read_optional(
    root: &Path,
    relative: &Path,
    budget: &Budget,
) -> Result<Option<Vec<u8>>> {
    if relative
        .components()
        .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err("unsafe input path".into());
    }
    let mut path = root.to_owned();
    for part in relative.components() {
        path.push(part);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err("symlinked input is unsupported".into());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.to_string()),
            _ => {}
        }
    }
    process::read_bounded(&path, 8 * 1024 * 1024, budget).map(Some)
}

pub(crate) fn original_inventory_digest(
    files: &BTreeSet<InputFile>,
    prefix: &str,
) -> Result<barbican::Sha256Digest> {
    let mut normalised = BTreeSet::new();
    for file in files {
        let path = if file.path == prefix {
            "root".to_owned()
        } else if let Some(relative) = file.path.strip_prefix(&format!("{prefix}/")) {
            format!("root/{relative}")
        } else {
            continue;
        };
        let mut file = file.clone();
        file.path = path;
        normalised.insert(file);
    }
    if normalised.is_empty() {
        return Err("source inventory namespace missing".into());
    }
    inventory_digest(&normalised)
}
