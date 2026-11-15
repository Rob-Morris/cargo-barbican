use super::process::{Budget, Result};
use barbican::{BarbicanConfig, WorkspaceRootDirective, parse_workspace_root_directive};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub(crate) struct RepoContext {
    pub root: PathBuf,
    pub config: BarbicanConfig,
    pub inputs: Vec<(PathBuf, Option<Vec<u8>>)>,
    identity: (u64, u64),
}
impl RepoContext {
    pub fn capture_consumer(
        current: &Path,
        explicit: Option<&Path>,
        standalone: bool,
        budget: &Budget,
    ) -> Result<Option<Self>> {
        let current = fs::canonicalize(current).map_err(super::process::err)?;
        let mut nearest = None;
        let mut actual_root = None;
        for directory in current.ancestors() {
            let Some(bytes) = read_optional(directory, Path::new("Cargo.toml"), budget)? else {
                continue;
            };
            let directive = parse_workspace_root_directive(
                "Cargo.toml",
                std::str::from_utf8(&bytes).map_err(super::process::err)?,
            )
            .map_err(super::process::err)?;
            if nearest.is_none() {
                nearest = Some(directory.to_owned());
                match directive {
                    WorkspaceRootDirective::WorkspaceRoot => {
                        actual_root = Some(directory.to_owned());
                        break;
                    }
                    WorkspaceRootDirective::MemberOf { workspace_path } => {
                        actual_root = Some(
                            fs::canonicalize(directory.join(workspace_path))
                                .map_err(super::process::err)?,
                        );
                        break;
                    }
                    WorkspaceRootDirective::Standalone => {}
                }
            } else if directive == WorkspaceRootDirective::WorkspaceRoot {
                actual_root = Some(directory.to_owned());
                break;
            }
        }
        let actual = actual_root
            .or(nearest)
            .map(|root| {
                let context = Self::capture(&current, Some(&root), false, budget)?
                    .ok_or("actual governance root unavailable")?;
                context.require_consumer_context(&current, budget)?;
                Ok::<_, String>(context)
            })
            .transpose()?;
        if standalone {
            if explicit.is_some() {
                return Err("--standalone conflicts with --repo".into());
            }
            if actual
                .as_ref()
                .is_some_and(|repo| repo.config.tools.admission_scope.is_some())
            {
                return Err("actual consumer governance opts into tool admission and cannot be bypassed with --standalone".into());
            }
            return Ok(None);
        }
        if let Some(explicit) = explicit {
            let selected = Self::capture(&current, Some(explicit), false, budget)?
                .ok_or("selected governance root unavailable")?;
            if actual.as_ref().map(|repo| &repo.root) != Some(&selected.root) {
                return Err("selected --repo is not the actual consumer governance root; run admission from the intended repository".into());
            }
        }
        Ok(actual)
    }
    pub fn capture(
        current: &Path,
        explicit: Option<&Path>,
        standalone: bool,
        budget: &Budget,
    ) -> Result<Option<Self>> {
        if standalone {
            if explicit.is_some() {
                return Err("--standalone conflicts with --repo".into());
            }
            return Ok(None);
        }
        let root = match explicit {
            Some(path) => fs::canonicalize(if path.is_absolute() {
                path.to_owned()
            } else {
                current.join(path)
            })
            .map_err(super::process::err)?,
            None if current.join("Cargo.toml").exists() => {
                fs::canonicalize(current).map_err(super::process::err)?
            }
            None => {
                for ancestor in current.ancestors().skip(1) {
                    if read_optional(ancestor, Path::new("Cargo.toml"), budget)?.is_some() {
                        return Err("nested governance is ambiguous; select --repo with the actual root or explicit --standalone".into());
                    }
                }
                return Ok(None);
            }
        };
        let mut inputs = Vec::new();
        for name in [
            "Cargo.toml",
            "barbican.toml",
            "deny.toml",
            "reviewed-targets.toml",
            ".cargo/audit.toml",
        ] {
            inputs.push((
                PathBuf::from(name),
                read_optional(&root, Path::new(name), budget)?,
            ));
        }
        let manifest = inputs[0]
            .1
            .as_deref()
            .ok_or("governance root has no Cargo.toml")?;
        let directive = parse_workspace_root_directive(
            "Cargo.toml",
            std::str::from_utf8(manifest).map_err(super::process::err)?,
        )
        .map_err(super::process::err)?;
        if matches!(directive, WorkspaceRootDirective::MemberOf { .. }) {
            return Err(
                "package belongs to another workspace; select actual governance root".into(),
            );
        }
        if !matches!(directive, WorkspaceRootDirective::WorkspaceRoot) {
            for ancestor in root.ancestors().skip(1) {
                if let Some(bytes) = read_optional(ancestor, Path::new("Cargo.toml"), budget)?
                    && matches!(
                        parse_workspace_root_directive(
                            "Cargo.toml",
                            std::str::from_utf8(&bytes).map_err(super::process::err)?
                        )
                        .map_err(super::process::err)?,
                        WorkspaceRootDirective::WorkspaceRoot
                    )
                {
                    return Err(
                        "nested workspace governance is ambiguous; select actual root".into(),
                    );
                }
            }
        }
        let config = match &inputs[1].1 {
            Some(bytes) => BarbicanConfig::from_toml_str(
                std::str::from_utf8(bytes).map_err(super::process::err)?,
            )
            .map_err(super::process::err)?,
            None => BarbicanConfig::default(),
        };
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::symlink_metadata(&root).map_err(super::process::err)?;
        let identity = (metadata.dev(), metadata.ino());
        Ok(Some(Self {
            root,
            config,
            inputs,
            identity,
        }))
    }
    pub fn recheck(&self, budget: &Budget) -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::symlink_metadata(&self.root).map_err(super::process::err)?;
        if !metadata.is_dir()
            || (metadata.dev(), metadata.ino()) != self.identity
            || fs::canonicalize(&self.root).map_err(super::process::err)? != self.root
        {
            return Err("governance root changed".into());
        }
        for (relative, bytes) in &self.inputs {
            if read_optional(&self.root, relative, budget)? != *bytes {
                return Err("origin policy changed during operation".into());
            }
        }
        Ok(())
    }
    pub fn require_consumer_context(&self, current: &Path, budget: &Budget) -> Result<()> {
        self.recheck(budget)?;
        let current = fs::canonicalize(current).map_err(super::process::err)?;
        if !current.starts_with(&self.root) {
            return Err("actual consumer directory is outside the selected governance root".into());
        }
        let root_manifest = self
            .inputs
            .iter()
            .find(|(path, _)| path == Path::new("Cargo.toml"))
            .and_then(|(_, bytes)| bytes.as_deref())
            .ok_or("governance manifest unavailable")?;
        let root_text = std::str::from_utf8(root_manifest).map_err(super::process::err)?;
        for directory in current.ancestors().take_while(|path| *path != self.root) {
            let Some(bytes) = read_optional(directory, Path::new("Cargo.toml"), budget)? else {
                continue;
            };
            let manifest_text = std::str::from_utf8(&bytes).map_err(super::process::err)?;
            match parse_workspace_root_directive("Cargo.toml", manifest_text)
                .map_err(super::process::err)?
            {
                WorkspaceRootDirective::WorkspaceRoot => {
                    return Err("actual consumer belongs to a nested governance root".into());
                }
                WorkspaceRootDirective::MemberOf { workspace_path }
                    if fs::canonicalize(directory.join(&workspace_path))
                        .map_err(super::process::err)?
                        != self.root =>
                {
                    return Err("actual consumer declares a different workspace root".into());
                }
                _ => {}
            }
            let relative = directory
                .strip_prefix(&self.root)
                .map_err(super::process::err)?
                .join("Cargo.toml");
            if barbican::classify_workspace_manifest_membership("Cargo.toml", root_text, &relative)
                .map_err(super::process::err)?
                != barbican::WorkspaceManifestMembership::Included
            {
                return Err("actual consumer workspace membership cannot be established from the selected governance root".into());
            }
        }
        Ok(())
    }
}
pub(crate) use crate::verified_source::read_optional;

pub(crate) struct NativeContext {
    pub cargo_home: PathBuf,
    pub install_root: PathBuf,
    pub configurations: Vec<(PathBuf, Option<Vec<u8>>)>,
}
impl NativeContext {
    pub fn for_static() -> Result<Self> {
        let cargo_home = super::process::absolute_home()?.join(".cargo");
        Ok(Self {
            install_root: cargo_home.clone(),
            cargo_home,
            configurations: Vec::new(),
        })
    }
    pub fn capture(current: &Path, budget: &Budget) -> Result<Self> {
        for (name, _) in std::env::vars_os() {
            let name = name.to_string_lossy();
            if [
                "RUSTC",
                "RUSTC_WRAPPER",
                "RUSTC_WORKSPACE_WRAPPER",
                "RUSTDOC",
                "RUSTFLAGS",
                "RUSTDOCFLAGS",
                "CARGO_ENCODED_RUSTFLAGS",
                "CARGO_ENCODED_RUSTDOCFLAGS",
                "CARGO_TARGET_DIR",
                "CARGO_BUILD_BUILD_DIR",
            ]
            .contains(&name.as_ref())
                || name.starts_with("CARGO_BUILD_")
                || name.starts_with("CARGO_TARGET_")
                || name.starts_with("CARGO_ALIAS_")
                || name.starts_with("CARGO_SOURCE_")
                || name.starts_with("CARGO_REGISTRIES_")
            {
                return Err(format!(
                    "ambient {name} is outside the qualified Cargo tool context"
                ));
            }
        }
        let cargo_home = std::env::var_os("CARGO_HOME")
            .map(PathBuf::from)
            .unwrap_or(super::process::absolute_home()?.join(".cargo"));
        if !cargo_home.is_absolute() {
            return Err("CARGO_HOME must be absolute".into());
        }
        let mut dirs: Vec<_> = current.ancestors().map(|p| p.join(".cargo")).collect();
        if !dirs.contains(&cargo_home) {
            dirs.push(cargo_home.clone());
        }
        let mut configurations = Vec::new();
        let mut configured_root = None;
        for directory in dirs {
            for name in ["config", "config.toml"] {
                let bytes = read_optional(&directory, Path::new(name), budget)?;
                if let Some(bytes) = &bytes {
                    let root = barbican::tool_inputs::tool_config_install_root(
                        std::str::from_utf8(bytes).map_err(super::process::err)?,
                    )?;
                    if configured_root.is_none() {
                        configured_root = root.map(PathBuf::from);
                    }
                }
                configurations.push((directory.join(name), bytes));
            }
        }
        let install_root = std::env::var_os("CARGO_INSTALL_ROOT")
            .map(PathBuf::from)
            .or(configured_root)
            .unwrap_or(cargo_home.clone());
        if !install_root.is_absolute() {
            return Err("ordinary install root must be absolute in the qualified context".into());
        }
        Ok(Self {
            cargo_home,
            install_root,
            configurations,
        })
    }
    pub fn recheck(&self, budget: &Budget) -> Result<()> {
        for (path, bytes) in &self.configurations {
            if read_optional(
                path.parent().ok_or("config parent unavailable")?,
                Path::new(path.file_name().ok_or("config name unavailable")?),
                budget,
            )? != *bytes
            {
                return Err("original Cargo configuration changed".into());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn consumer_governance_requires_actual_root_and_unambiguous_membership() {
        let stage = super::super::source::Stage::new().unwrap();
        let root = stage.root.join("governed");
        let member = root.join("member");
        let nested = root.join("nested");
        let unrelated = stage.root.join("unrelated");
        for path in [&member, &nested, &unrelated] {
            fs::create_dir_all(path).unwrap();
        }
        fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"member\"]\nresolver = \"3\"\n",
        )
        .unwrap();
        fs::write(
            member.join("Cargo.toml"),
            "[package]\nname = \"member\"\nversion = \"1.0.0\"\n",
        )
        .unwrap();
        fs::write(nested.join("Cargo.toml"), "[workspace]\nresolver = \"3\"\n").unwrap();
        let budget = Budget::new(false).unwrap();
        let context = RepoContext::capture(&root, None, false, &budget)
            .unwrap()
            .unwrap();
        assert!(context.require_consumer_context(&root, &budget).is_ok());
        assert!(context.require_consumer_context(&member, &budget).is_ok());
        assert!(
            context
                .require_consumer_context(&unrelated, &budget)
                .is_err()
        );
        assert!(context.require_consumer_context(&nested, &budget).is_err());
        assert!(RepoContext::capture_consumer(&unrelated, Some(&root), false, &budget).is_err());
        assert_eq!(
            RepoContext::capture_consumer(&member, None, false, &budget)
                .unwrap()
                .unwrap()
                .root,
            root
        );
        fs::write(
            root.join("barbican.toml"),
            "[tools]\nadmission_scope = \"owned-fixture\"\n",
        )
        .unwrap();
        assert!(RepoContext::capture_consumer(&member, None, true, &budget).is_err());
        assert!(RepoContext::capture_consumer(&root, None, true, &budget).is_err());
        let context = RepoContext::capture(&root, None, false, &budget)
            .unwrap()
            .unwrap();
        fs::write(
            member.join("Cargo.toml"),
            "[package]\nname = \"member\"\nversion = \"1.0.0\"\nworkspace = \"../../unrelated\"\n",
        )
        .unwrap();
        assert!(context.require_consumer_context(&member, &budget).is_err());
    }
}
