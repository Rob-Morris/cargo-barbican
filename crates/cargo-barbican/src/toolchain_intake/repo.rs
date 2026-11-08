use barbican::{BarbicanConfig, WorkspaceRootDirective, parse_workspace_root_directive};
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

const LIMIT: u64 = 8 * 1024 * 1024;
pub(super) type Result<T> = std::result::Result<T, String>;

#[derive(Debug, Clone)]
pub(super) struct RepoContext {
    pub root: PathBuf,
    pub config: BarbicanConfig,
    pub inputs: Vec<RepoInput>,
    root_identity: (u64, u64),
}
#[derive(Debug, Clone)]
pub(super) struct RepoInput {
    pub relative: PathBuf,
    pub bytes: Option<Vec<u8>>,
}
impl RepoContext {
    pub fn capture(root: &Path) -> Result<Self> {
        let root = fs::canonicalize(root).map_err(|e| e.to_string())?;
        let mut inputs = Vec::new();
        for relative in [
            "Cargo.toml",
            "barbican.toml",
            "reviewed-targets.toml",
            "rust-toolchain.toml",
            "rust-toolchain",
        ] {
            inputs.push(RepoInput {
                relative: relative.into(),
                bytes: read_optional(&root, Path::new(relative))?,
            });
        }
        let manifest = inputs[0]
            .bytes
            .as_deref()
            .ok_or("explicit repository has no Cargo.toml")?;
        let directive = parse_workspace_root_directive("Cargo.toml", text(manifest)?)
            .map_err(|e| e.to_string())?;
        if matches!(directive, WorkspaceRootDirective::MemberOf { .. }) {
            return Err("package.workspace points elsewhere; pass --repo with the actual governance root or cd to that root".into());
        }
        if !matches!(directive, WorkspaceRootDirective::WorkspaceRoot) {
            for ancestor in root.ancestors().skip(1) {
                if let Some(bytes) = read_optional(ancestor, Path::new("barbican.toml"))? {
                    let config =
                        BarbicanConfig::from_toml_str(text(&bytes)?).map_err(|e| e.to_string())?;
                    if config.toolchain.require_admission {
                        return Err("explicit repository is nested under an admission-governed root; select that governance root before Cargo discovery".into());
                    }
                }
                if let Some(bytes) = read_optional(ancestor, Path::new("Cargo.toml"))?
                    && matches!(
                        parse_workspace_root_directive("ancestor Cargo.toml", text(&bytes)?)
                            .map_err(|e| e.to_string())?,
                        WorkspaceRootDirective::WorkspaceRoot
                    )
                {
                    return Err("explicit repository is nested under another workspace root; use its actual governance root before Cargo discovery".into());
                }
            }
        }
        let config = match &inputs[1].bytes {
            Some(bytes) => {
                BarbicanConfig::from_toml_str(text(bytes)?).map_err(|e| e.to_string())?
            }
            None => BarbicanConfig::default(),
        };
        if inputs[4].bytes.is_some() {
            return Err("legacy rust-toolchain shadows canonical intent; reconcile it before toolchain admission".into());
        }
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::metadata(&root).map_err(|e| e.to_string())?;
        let root_identity = (metadata.dev(), metadata.ino());
        Ok(Self {
            root,
            config,
            inputs,
            root_identity,
        })
    }
    pub fn recheck(&self) -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::symlink_metadata(&self.root).map_err(|e| e.to_string())?;
        if !metadata.file_type().is_dir() || (metadata.dev(), metadata.ino()) != self.root_identity
        {
            return Err("repository root changed during operation".into());
        }
        for input in &self.inputs {
            if read_optional(&self.root, &input.relative)? != input.bytes {
                return Err(
                    "repository intent changed during the operation; inspect and retry".into(),
                );
            }
        }
        Ok(())
    }
}

/// Ambiguous package/workspace membership is never delegated to Cargo pre-trust.
pub(super) fn discover(current: &Path, explicit: Option<&Path>) -> Result<Option<RepoContext>> {
    if let Some(root) = explicit {
        return RepoContext::capture(&if root.is_absolute() {
            root.to_owned()
        } else {
            current.join(root)
        })
        .map(Some);
    }
    let current = fs::canonicalize(current).map_err(|e| e.to_string())?;
    let mut governance = Vec::new();
    let mut nearest_manifest = None;
    for ancestor in current.ancestors() {
        if read_optional(ancestor, Path::new("Cargo.toml"))?.is_some() && nearest_manifest.is_none()
        {
            nearest_manifest = Some(ancestor.to_owned());
        }
        if let Some(bytes) = read_optional(ancestor, Path::new("barbican.toml"))? {
            let config = BarbicanConfig::from_toml_str(text(&bytes)?).map_err(|e| e.to_string())?;
            governance.push((ancestor.to_owned(), config.toolchain.require_admission));
        }
    }
    if !governance.iter().any(|(_, required)| *required) {
        return Ok(None);
    }
    if governance.len() != 1
        || nearest_manifest.as_ref() != Some(&governance[0].0)
        || current != governance[0].0
    {
        return Err("toolchain admission requires an unambiguous governance root before Cargo discovery; use explicit --repo or cd to the repository root".into());
    }
    RepoContext::capture(&governance[0].0).map(Some)
}

pub(super) fn read_optional(root: &Path, relative: &Path) -> Result<Option<Vec<u8>>> {
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err("unsafe repository input path".into());
    }
    let mut path = root.to_path_buf();
    let parts: Vec<_> = relative.components().collect();
    for (index, part) in parts.iter().enumerate() {
        path.push(part.as_os_str());
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.to_string()),
        };
        if metadata.file_type().is_symlink() {
            return Err("symlinked repository policy path is unsupported".into());
        }
        if index + 1 < parts.len() {
            if !metadata.is_dir() {
                return Err("repository policy parent is not a directory".into());
            }
        } else {
            if !metadata.is_file() || metadata.len() > LIMIT {
                return Err("repository policy input must be a bounded regular file".into());
            }
            let mut bytes = Vec::new();
            fs::File::open(&path)
                .map_err(|e| e.to_string())?
                .take(LIMIT + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
            if bytes.len() as u64 > LIMIT {
                return Err("repository policy input exceeds size limit".into());
            }
            return Ok(Some(bytes));
        }
    }
    Err("invalid repository input path".into())
}
fn text(bytes: &[u8]) -> Result<&str> {
    std::str::from_utf8(bytes).map_err(|e| e.to_string())
}

impl RepoContext {
    pub fn publish_supporting(&self, relative: &Path, bytes: &[u8]) -> Result<()> {
        self.recheck()?;
        if let Some(existing) = read_optional(&self.root, relative)? {
            return if existing == bytes {
                Ok(())
            } else {
                Err("completed repository evidence path conflicts; existing file preserved".into())
            };
        }
        let path = self.create_parents(relative)?;
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&path)
            .map_err(|e| {
                format!("repository evidence publication failed; earlier evidence retained: {e}")
            })?;
        file.write_all(bytes).map_err(|e| {
            format!("partial repository evidence retained; policy not published: {e}")
        })?;
        self.recheck()
    }
    fn create_parents(&self, relative: &Path) -> Result<PathBuf> {
        if relative.as_os_str().is_empty()
            || relative
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
        {
            return Err("unsafe repository publication path".into());
        }
        let mut path = self.root.clone();
        let parts: Vec<_> = relative.components().collect();
        for part in &parts[..parts.len() - 1] {
            path.push(part.as_os_str());
            match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.file_type().is_dir() => {}
                Ok(_) => {
                    return Err("repository publication parent is not a regular directory".into());
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    fs::create_dir(&path).map_err(|e| e.to_string())?
                }
                Err(error) => return Err(error.to_string()),
            }
        }
        path.push(parts.last().ok_or("empty publication path")?.as_os_str());
        Ok(path)
    }
    pub fn publish_policy(&self, bytes: &[u8]) -> Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        self.recheck()?;
        let path = self.root.join("reviewed-targets.toml");
        let original = self
            .inputs
            .iter()
            .find(|input| input.relative == Path::new("reviewed-targets.toml"))
            .ok_or("policy was not captured")?;
        let temporary = self
            .root
            .join(format!(".barbican-toolchain-policy-{}", std::process::id()));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|e| e.to_string())?;
        let result = (|| {
            file.write_all(bytes).map_err(|e| e.to_string())?;
            if original.bytes.is_some() {
                file.set_permissions(
                    fs::metadata(&path)
                        .map_err(|e| e.to_string())?
                        .permissions(),
                )
                .map_err(|e| e.to_string())?;
            }
            self.recheck()?;
            fs::rename(&temporary, &path).map_err(|e| e.to_string())
        })();
        if temporary.exists() {
            let _ = fs::remove_file(&temporary);
        }
        result.map_err(|e|format!("repository policy publication failed; completed supporting evidence may remain orphaned: {e}"))
    }
}
