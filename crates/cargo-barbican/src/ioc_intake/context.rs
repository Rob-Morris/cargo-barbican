use crate::controlled_process::{Budget, Result, err};
use crate::intake_store::Stores;
use crate::verified_source::read_optional;
use barbican::BarbicanConfig;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub(crate) struct OriginContext {
    pub root: PathBuf,
    pub reviewed_targets: Option<Vec<u8>>,
    config_bytes: Option<Vec<u8>>,
    identity: (u64, u64),
}
impl OriginContext {
    fn capture(root: PathBuf, budget: &Budget) -> Result<Self> {
        let metadata = fs::symlink_metadata(&root).map_err(err)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("IOC origin must be a regular directory".into());
        }
        let config_bytes = read_optional(&root, Path::new("barbican.toml"), budget)?;
        let _config = config_bytes
            .as_ref()
            .map(|bytes| {
                BarbicanConfig::from_toml_str(std::str::from_utf8(bytes).map_err(err)?).map_err(err)
            })
            .transpose()?
            .unwrap_or_default();
        let reviewed_targets = read_optional(&root, Path::new("reviewed-targets.toml"), budget)?;
        if let Some(bytes) = &reviewed_targets {
            barbican::parse_reviewed_targets_toml(std::str::from_utf8(bytes).map_err(err)?)
                .map_err(err)?;
        }
        Ok(Self {
            root,
            reviewed_targets,
            config_bytes,
            identity: (metadata.dev(), metadata.ino()),
        })
    }
    pub fn check(&self, budget: &Budget) -> Result<()> {
        let metadata = fs::symlink_metadata(&self.root).map_err(err)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || (metadata.dev(), metadata.ino()) != self.identity
            || fs::canonicalize(&self.root).map_err(err)? != self.root
            || read_optional(&self.root, Path::new("barbican.toml"), budget)? != self.config_bytes
            || read_optional(&self.root, Path::new("reviewed-targets.toml"), budget)?
                != self.reviewed_targets
        {
            return Err("IOC origin or governance changed during operation".into());
        }
        Ok(())
    }
}

pub(crate) struct Context {
    pub current: PathBuf,
    pub origin: Option<OriginContext>,
    pub stores: Stores,
    pub budget: Budget,
    explicit_origin: bool,
}
impl Context {
    pub fn capture(
        current: &Path,
        repo: Option<&Path>,
        data: Option<&Path>,
        cache: Option<&Path>,
    ) -> Result<Self> {
        let budget = Budget::new(true)?;
        let current = fs::canonicalize(current).map_err(err)?;
        if !current.is_dir() {
            return Err("IOC invocation context is not a directory".into());
        }
        let root = match repo {
            Some(path) => Some(
                fs::canonicalize(if path.is_absolute() {
                    path.to_owned()
                } else {
                    current.join(path)
                })
                .map_err(err)?,
            ),
            None => discover(&current, &budget)?,
        };
        let origin = root
            .map(|root| OriginContext::capture(root, &budget))
            .transpose()?;
        let stores = Stores::open(
            &current,
            origin.as_ref().map(|origin| origin.root.as_path()),
            data,
            cache,
        )?;
        Ok(Self {
            current,
            origin,
            stores,
            budget,
            explicit_origin: repo.is_some(),
        })
    }
    pub fn check(&self) -> Result<()> {
        self.budget.check()?;
        self.stores.data.recheck()?;
        self.stores.cache.recheck()?;
        if let Some(origin) = &self.origin {
            origin.check(&self.budget)?;
        }
        if !self.explicit_origin
            && discover(&self.current, &self.budget)?
                != self.origin.as_ref().map(|origin| origin.root.clone())
        {
            return Err("IOC origin discovery changed during operation".into());
        }
        Ok(())
    }
    pub fn read_origin(&self, relative: &Path) -> Result<Option<Vec<u8>>> {
        self.check()?;
        let origin = self
            .origin
            .as_ref()
            .ok_or("repository authority unavailable; supply --repo explicitly")?;
        read_optional(&origin.root, relative, &self.budget)
    }
}
fn discover(current: &Path, budget: &Budget) -> Result<Option<PathBuf>> {
    let mut found = None;
    for directory in current.ancestors() {
        budget.check()?;
        let config = read_optional(directory, Path::new("barbican.toml"), budget)?;
        let reviewed = read_optional(directory, Path::new("reviewed-targets.toml"), budget)?;
        if config.is_none() && reviewed.is_none() {
            continue;
        }
        if found.is_some() {
            return Err("multiple IOC governance roots; supply --repo explicitly".into());
        }
        if let Some(bytes) = config {
            BarbicanConfig::from_toml_str(std::str::from_utf8(&bytes).map_err(err)?)
                .map_err(err)?;
        }
        if let Some(bytes) = reviewed {
            barbican::parse_reviewed_targets_toml(std::str::from_utf8(&bytes).map_err(err)?)
                .map_err(err)?;
        }
        found = Some(directory.to_owned());
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verified_source::Stage;
    #[test]
    fn filesystem_markers_select_authority_without_a_cargo_manifest() {
        let stage = Stage::new().unwrap();
        let root = stage.root.join("repo");
        fs::create_dir(&root).unwrap();
        fs::write(
            root.join("barbican.toml"),
            "[release_age]\nminimum_days=7\n",
        )
        .unwrap();
        let child = root.join("child");
        fs::create_dir(&child).unwrap();
        let budget = Budget::new(false).unwrap();
        assert_eq!(discover(&child, &budget).unwrap(), Some(root.clone()));
        let origin = OriginContext::capture(root.clone(), &budget).unwrap();
        fs::write(
            root.join("barbican.toml"),
            "[release_age]\nminimum_days=8\n",
        )
        .unwrap();
        assert!(origin.check(&budget).is_err());
    }
    #[test]
    fn absent_ambiguous_and_malformed_markers_are_distinct() {
        let stage = Stage::new().unwrap();
        let budget = Budget::new(false).unwrap();
        assert_eq!(discover(&stage.root, &budget).unwrap(), None);
        fs::write(
            stage.root.join("barbican.toml"),
            "[release_age]\nminimum_days=7\n",
        )
        .unwrap();
        let nested = stage.root.join("nested");
        fs::create_dir(&nested).unwrap();
        fs::write(
            nested.join("barbican.toml"),
            "[release_age]\nminimum_days=7\n",
        )
        .unwrap();
        assert!(discover(&nested, &budget).unwrap_err().contains("multiple"));
        fs::write(nested.join("barbican.toml"), "malformed [").unwrap();
        assert!(discover(&nested, &budget).is_err());
    }
}
