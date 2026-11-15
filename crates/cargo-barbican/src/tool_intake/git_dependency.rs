use super::process::{self, Budget, Result, err};
use super::source;
use barbican::GitSourceIdentity;
use barbican::cargo_tool::{InputFile, InputKind, PackageIdentity, PackageSource, sha256};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) struct GitPackage {
    pub directory: PathBuf,
    pub identity: PackageIdentity,
}

#[derive(Default)]
pub(crate) struct GitSources {
    pub config_fragment: String,
    pub inventories: Vec<(PathBuf, String, BTreeSet<InputFile>)>,
    packages: BTreeMap<(String, String, String), GitPackage>,
}

impl GitSources {
    pub fn collect(
        manifests: &[(PathBuf, Value)],
        lock: Option<&[u8]>,
        stage: &Path,
        budget: &Budget,
    ) -> Result<Self> {
        Self::collect_with_materialiser(manifests, lock, stage, budget, |identity, destination| {
            source::git_materialise(identity.url(), identity.rev(), destination, stage, budget)
        })
    }

    pub fn collect_with_materialiser(
        manifests: &[(PathBuf, Value)],
        lock: Option<&[u8]>,
        stage: &Path,
        budget: &Budget,
        mut materialise: impl FnMut(&GitSourceIdentity, &Path) -> Result<()>,
    ) -> Result<Self> {
        let mut pending = BTreeMap::<GitSourceIdentity, BTreeSet<String>>::new();
        declarations(manifests, &mut pending)?;
        if let Some(lock) = lock {
            let lock =
                barbican::parse_lockfile(std::str::from_utf8(lock).map_err(err)?).map_err(err)?;
            for package in lock.packages() {
                if let Some(source) = package.source.as_deref().filter(|s| s.starts_with("git+")) {
                    pending
                        .entry(GitSourceIdentity::from_locked_source(source).map_err(err)?)
                        .or_default()
                        .insert(package.name.clone());
                }
            }
        }
        let mut requested = pending.clone();
        let mut result = Self::default();
        let mut completed = BTreeSet::new();
        while let Some((identity, names)) = pending.pop_first() {
            budget.check()?;
            if !completed.insert(identity.clone()) {
                continue;
            }
            let key = sha256(identity.locked_source().as_bytes()).to_string();
            let original = stage.join(format!("git-original-{key}"));
            materialise(&identity, &original)?;
            let manifests = source::validate_dependency_manifests(&original, budget)?;
            declarations(&manifests, &mut pending)?;
            declarations(&manifests, &mut requested)?;
            result.add_repository(&identity, &original, &manifests, &names, stage, budget)?;
        }
        let available: BTreeSet<_> = result
            .packages
            .keys()
            .map(|(source, name, _)| (source.clone(), name.clone()))
            .collect();
        for (source, names) in requested {
            for name in names {
                budget.check()?;
                if !available.contains(&(source.locked_source(), name)) {
                    return Err("recursively requested Git package is outside qualified directory-source layout".into());
                }
            }
        }
        Ok(result)
    }

    pub fn package(&self, source: &str, name: &str, version: &str) -> Result<&GitPackage> {
        self.packages
            .get(&(source.into(), name.into(), version.into()))
            .ok_or_else(|| "Git package absent from independently collected source mapping".into())
    }

    // Cargo requires a precise Git lock entry before using a public replacement.
    // `cargo update --workspace` retains these hints; generate-lockfile discards them.
    // The seed is never the accepted effective dependency graph.
    pub fn seed_lock(&self, existing: Option<&[u8]>) -> Result<Vec<u8>> {
        let text = existing.map(std::str::from_utf8).transpose().map_err(err)?;
        let lock = barbican::parse_lockfile(text.unwrap_or("version = 4\n")).map_err(err)?;
        let existing: BTreeSet<_> = lock
            .packages()
            .iter()
            .map(|p| (p.source.as_deref(), p.name.as_str(), p.version.as_str()))
            .collect();
        let mut output = text.unwrap_or("version = 4\n").to_owned();
        if output.len() > 8 * 1024 * 1024 {
            return Err("Git resolution seed exceeds lock record limit".into());
        }
        for (source, name, version) in self.packages.keys() {
            if existing.contains(&(Some(source.as_str()), name.as_str(), version.as_str())) {
                continue;
            }
            output.push_str(&format!(
                "\n[[package]]\nname = {}\nversion = {}\nsource = {}\n",
                serde_json::to_string(name).map_err(err)?,
                serde_json::to_string(version).map_err(err)?,
                serde_json::to_string(source).map_err(err)?
            ));
            if output.len() > 8 * 1024 * 1024 {
                return Err("Git resolution seed exceeds lock record limit".into());
            }
        }
        let bytes = output.into_bytes();
        Ok(bytes)
    }

    fn add_repository(
        &mut self,
        identity: &GitSourceIdentity,
        original: &Path,
        manifests: &[(PathBuf, Value)],
        requested: &BTreeSet<String>,
        stage: &Path,
        budget: &Budget,
    ) -> Result<()> {
        let workspaces: BTreeMap<_, _> = manifests
            .iter()
            .filter(|(_, m)| m.get("workspace").is_some())
            .map(|(path, m)| {
                (
                    path.parent().expect("validated manifest parent").to_owned(),
                    m,
                )
            })
            .collect();
        let mut packages = BTreeMap::new();
        for (path, manifest) in manifests {
            budget.check()?;
            let Some(name) = manifest.pointer("/package/name").and_then(Value::as_str) else {
                continue;
            };
            let version = package_version(path, manifest, &workspaces)?;
            let _: barbican::ExactCrateSpec = format!("{name}@{version}").parse().map_err(err)?;
            if packages.insert(name.to_owned(), (path, version)).is_some() {
                return Err("Git repository contains ambiguous package names".into());
            }
        }
        let mut parent = None;
        for name in requested {
            budget.check()?;
            let (path, _) = packages
                .get(name)
                .ok_or("Git dependency package missing from repository")?;
            let directory = path.parent().ok_or("Git package directory missing")?;
            let candidate = directory.parent().ok_or("Git source parent missing")?;
            if parent
                .replace(candidate)
                .is_some_and(|old| old != candidate)
            {
                return Err("Git dependency packages at different source-directory parents require an unqualified transport overlay".into());
            }
        }
        let parent = parent.ok_or("Git source has no requested package")?;
        let key = sha256(identity.locked_source().as_bytes()).to_string();
        let original_prefix = format!("git-original/{key}");
        let original_files = source::inventory(original, &original_prefix, budget)?;
        let materialisation_sha256 =
            source::original_inventory_digest(&original_files, &original_prefix)?;
        let transport_base = stage.join(format!("git-transport-{key}"));
        budget.materialise(0)?;
        fs::create_dir(&transport_base).map_err(err)?;
        let transport = transport_base.join("repository");
        budget.materialise(0)?;
        fs::create_dir(&transport).map_err(err)?;
        for file in &original_files {
            if file.kind != InputKind::RegularFile {
                continue;
            }
            let relative = file
                .path
                .strip_prefix(&format!("{original_prefix}/"))
                .ok_or("Git inventory prefix mismatch")?;
            let bytes =
                process::read_bounded(&original.join(relative), process::FILE_LIMIT, budget)?;
            if sha256(&bytes) != file.sha256 {
                return Err("original Git bytes changed while creating transport".into());
            }
            source::write_source(&transport, relative, file.mode, &bytes, budget)?;
        }
        let directory_source =
            if parent == original.parent().ok_or("Git original parent missing")? {
                transport_base.clone()
            } else {
                transport.join(parent.strip_prefix(original).map_err(err)?)
            };
        for (name, (manifest, version)) in packages {
            let directory = manifest.parent().ok_or("Git package directory missing")?;
            if directory.parent() != Some(parent) {
                continue;
            }
            let subdirectory = directory.strip_prefix(original).map_err(err)?;
            let material = transport.join(subdirectory);
            let files = source::inventory(&material, "package", budget)?;
            let checksums: BTreeMap<_, _> = files
                .iter()
                .filter(|file| file.kind == InputKind::RegularFile)
                .map(|file| {
                    (
                        file.path
                            .strip_prefix("package/")
                            .unwrap_or(&file.path)
                            .to_owned(),
                        file.sha256.clone(),
                    )
                })
                .collect();
            source::write_source(
                &material,
                ".cargo-checksum.json",
                0o644,
                &serde_json::to_vec(&json!({"package":null,"files":checksums})).map_err(err)?,
                budget,
            )?;
            let package = PackageIdentity {
                name: name.clone(),
                version: version.clone(),
                source: PackageSource::Git {
                    url: identity.url().into(),
                    rev: identity.rev().into(),
                    subdirectory: if subdirectory.as_os_str().is_empty() {
                        ".".into()
                    } else {
                        subdirectory.to_string_lossy().into_owned()
                    },
                    materialisation_sha256: materialisation_sha256.clone(),
                },
            };
            package.validate().map_err(err)?;
            self.packages.insert(
                (identity.locked_source(), name, version),
                GitPackage {
                    directory: material,
                    identity: package,
                },
            );
        }
        let transport_prefix = format!("git-transport/{key}");
        let transport_files = source::inventory(&transport, &transport_prefix, budget)?;
        self.inventories
            .push((original.to_owned(), original_prefix, original_files));
        self.inventories
            .push((transport, transport_prefix, transport_files));
        let fragment = format!(
            "[source.barbican-git-{key}]\ngit = {}\nrev = {}\nreplace-with = \"barbican-git-directory-{key}\"\n[source.barbican-git-directory-{key}]\ndirectory = {}\n",
            serde_json::to_string(identity.url()).map_err(err)?,
            serde_json::to_string(identity.rev()).map_err(err)?,
            serde_json::to_string(&directory_source.to_string_lossy()).map_err(err)?,
        );
        if self
            .config_fragment
            .len()
            .checked_add(fragment.len())
            .is_none_or(|bytes| bytes > 8 * 1024 * 1024)
        {
            return Err("generated Git mapping exceeds configuration record limit".into());
        }
        self.config_fragment.push_str(&fragment);
        Ok(())
    }
}

fn declarations(
    manifests: &[(PathBuf, Value)],
    found: &mut BTreeMap<GitSourceIdentity, BTreeSet<String>>,
) -> Result<()> {
    fn walk(
        value: &Value,
        key: Option<&str>,
        found: &mut BTreeMap<GitSourceIdentity, BTreeSet<String>>,
    ) -> Result<()> {
        match value {
            Value::Object(table) => {
                if let Some(url) = table.get("git").and_then(Value::as_str) {
                    let rev = table
                        .get("rev")
                        .and_then(Value::as_str)
                        .ok_or("Git dependency requires exact revision")?;
                    let name = table
                        .get("package")
                        .and_then(Value::as_str)
                        .or(key)
                        .ok_or("Git dependency package missing")?;
                    found
                        .entry(GitSourceIdentity::new(url, rev).map_err(err)?)
                        .or_default()
                        .insert(name.into());
                }
                for (key, value) in table {
                    if key != "metadata" {
                        walk(value, Some(key), found)?;
                    }
                }
            }
            Value::Array(values) => {
                for value in values {
                    walk(value, key, found)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    for (_, manifest) in manifests {
        walk(manifest, None, found)?;
    }
    Ok(())
}

fn package_version(
    path: &Path,
    manifest: &Value,
    workspaces: &BTreeMap<PathBuf, &Value>,
) -> Result<String> {
    if let Some(version) = manifest.pointer("/package/version").and_then(Value::as_str) {
        return Ok(version.into());
    }
    if manifest
        .pointer("/package/version/workspace")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err("Git package version must be explicit or workspace-inherited".into());
    }
    let directory = path.parent().ok_or("Git package directory missing")?;
    let explicit = manifest
        .pointer("/package/workspace")
        .and_then(Value::as_str)
        .map(|relative| fs::canonicalize(directory.join(relative)).map_err(err))
        .transpose()?;
    for ancestor in directory.ancestors() {
        if explicit
            .as_deref()
            .is_some_and(|workspace| workspace != ancestor)
        {
            continue;
        }
        if let Some(workspace) = workspaces.get(ancestor) {
            return workspace
                .pointer("/workspace/package/version")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| "Git workspace inherited version missing".into());
        }
    }
    Err("Git package workspace outside independently materialised repository".into())
}

#[cfg(test)]
mod tests {
    use super::super::source::Stage;
    use super::*;

    fn fixture(stage: &Stage, budget: &Budget) -> (PathBuf, Vec<(PathBuf, Value)>) {
        let root = stage.root.join("original");
        fs::create_dir(&root).unwrap();
        for (path, contents) in [
            (
                "Cargo.toml",
                "[workspace]\nmembers=[\"crates/alpha\",\"crates/beta\"]\nresolver=\"3\"\n[workspace.package]\nversion=\"1.2.3\"\nedition=\"2024\"\n",
            ),
            ("shared.txt", "reviewed auxiliary bytes\n"),
            (
                "crates/alpha/Cargo.toml",
                "[package]\nname=\"fixture-alpha\"\nversion.workspace=true\nedition.workspace=true\n[dependencies]\nfixture-beta={path=\"../beta\",version=\"1.2.3\"}\n",
            ),
            (
                "crates/alpha/src/lib.rs",
                "pub const DATA: &str = include_str!(\"../../../shared.txt\");\n",
            ),
            (
                "crates/beta/Cargo.toml",
                "[package]\nname=\"fixture-beta\"\nversion.workspace=true\nedition.workspace=true\n",
            ),
            ("crates/beta/src/lib.rs", "pub const VALUE: u32 = 7;\n"),
        ] {
            source::write_source(&root, path, 0o644, contents.as_bytes(), budget).unwrap();
        }
        let manifests = source::validate_manifests(&root, budget).unwrap();
        (root, manifests)
    }

    fn identity() -> GitSourceIdentity {
        GitSourceIdentity::new(
            "https://example.invalid/owned",
            "0123456789abcdef0123456789abcdef01234567",
        )
        .unwrap()
    }

    #[test]
    fn public_directory_preserves_workspace_and_binds_original_separately() {
        let stage = Stage::new().unwrap();
        let budget = Budget::new(false).unwrap();
        let (root, manifests) = fixture(&stage, &budget);
        let original = source::inventory(&root, "unchanged", &budget).unwrap();
        let mut sources = GitSources::default();
        sources
            .add_repository(
                &identity(),
                &root,
                &manifests,
                &BTreeSet::from(["fixture-alpha".into()]),
                &stage.root,
                &budget,
            )
            .unwrap();
        assert_eq!(
            original,
            source::inventory(&root, "unchanged", &budget).unwrap()
        );
        let alpha = sources
            .package(&identity().locked_source(), "fixture-alpha", "1.2.3")
            .unwrap();
        let beta = sources
            .package(&identity().locked_source(), "fixture-beta", "1.2.3")
            .unwrap();
        assert_eq!(alpha.directory.parent(), beta.directory.parent());
        assert_eq!(
            fs::read(alpha.directory.join("Cargo.toml")).unwrap(),
            fs::read(root.join("crates/alpha/Cargo.toml")).unwrap()
        );
        assert_eq!(
            fs::read(alpha.directory.join("../../shared.txt")).unwrap(),
            b"reviewed auxiliary bytes\n"
        );
        assert!(!root.join("crates/alpha/.cargo-checksum.json").exists());
        assert!(alpha.directory.join(".cargo-checksum.json").is_file());
        assert_eq!(sources.inventories.len(), 2);
        let PackageSource::Git {
            subdirectory,
            materialisation_sha256,
            ..
        } = &alpha.identity.source
        else {
            panic!("original source lost");
        };
        assert_eq!(subdirectory, "crates/alpha");
        assert_eq!(
            materialisation_sha256,
            &source::original_inventory_digest(
                &sources.inventories[0].2,
                &sources.inventories[0].1
            )
            .unwrap()
        );
        assert!(
            sources
                .package(&identity().locked_source(), "fixture-alpha", "9.0.0")
                .is_err()
        );
        let seed = sources.seed_lock(None).unwrap();
        let lock = barbican::parse_lockfile(std::str::from_utf8(&seed).unwrap()).unwrap();
        assert_eq!(lock.packages().len(), 2);
        assert!(
            lock.packages()
                .iter()
                .all(|p| p.source.as_deref() == Some(identity().locked_source().as_str()))
        );
        assert_eq!(seed, sources.seed_lock(Some(&seed)).unwrap());
    }

    #[test]
    fn mixed_parent_packages_refuse_without_rewriting_manifests() {
        let stage = Stage::new().unwrap();
        let budget = Budget::new(false).unwrap();
        let (root, mut manifests) = fixture(&stage, &budget);
        manifests.push((
            root.join("deep/nested/Cargo.toml"),
            json!({"package":{"name":"fixture-deep","version":"1.0.0"}}),
        ));
        let mut sources = GitSources::default();
        let error = sources
            .add_repository(
                &identity(),
                &root,
                &manifests,
                &BTreeSet::from(["fixture-alpha".into(), "fixture-deep".into()]),
                &stage.root,
                &budget,
            )
            .unwrap_err();
        assert!(error.contains("different source-directory parents"));
        assert!(sources.packages.is_empty());
    }

    #[test]
    fn declarations_preserve_renames_and_ignore_package_metadata() {
        let source = identity();
        let manifest = json!({"dependencies":{"alias":{"git":source.url(),"rev":source.rev(),"package":"actual"}},"package":{"metadata":{"fiction":{"git":"not-a-url"}}}});
        let mut found = BTreeMap::new();
        declarations(&[(PathBuf::from("Cargo.toml"), manifest)], &mut found).unwrap();
        assert_eq!(
            found,
            BTreeMap::from([(source, BTreeSet::from(["actual".into()]))])
        );
    }
}
