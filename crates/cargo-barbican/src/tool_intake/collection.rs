use super::frontend::{Context, StoredReview};
use super::process::{self, Result, err};
use super::source::{self, Stage};
use barbican::cargo_tool::*;
use barbican::{ExactCrateSpec, RustInspectReport};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReviewRequest {
    pub spec: Option<String>,
    pub git: Option<String>,
    pub rev: Option<String>,
    pub package: Option<String>,
    pub bins: Vec<String>,
    pub features: Vec<String>,
    pub no_default_features: bool,
    pub all_features: bool,
    pub profile: String,
    pub target: Option<String>,
    pub from: Option<String>,
    pub cargo: PathBuf,
    pub rustc: PathBuf,
}
impl ReviewRequest {
    pub fn feature_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        if self.no_default_features {
            args.push("--no-default-features".into());
        }
        if self.all_features {
            args.push("--all-features".into());
        }
        if !self.features.is_empty() {
            args.extend(["--features".into(), self.features.join(",")]);
        }
        args
    }
}
pub(crate) struct PreparedSource {
    pub root: PathBuf,
    pub manifest: PathBuf,
    pub workspace_root: PathBuf,
    pub cargo_home: PathBuf,
    pub target_dir: PathBuf,
    pub subject: Subject,
    pub metadata: Value,
    pub origins: BTreeMap<String, PackageIdentity>,
    pub effective_lock: Vec<u8>,
    pub inspected: BTreeMap<PackageIdentity, RustInspectReport>,
    pub ioc_inspections: BTreeMap<PackageIdentity, barbican::ioc::Inspection>,
    pub source_facts: BTreeMap<PackageIdentity, SourceFact>,
    stage: Stage,
    configuration: (PathBuf, Vec<u8>),
    inventories: Vec<(PathBuf, String, BTreeSet<InputFile>)>,
}
impl PreparedSource {
    pub fn save_sources(&self, ctx: &Context) -> Result<PathBuf> {
        self.recheck(ctx)?;
        let base = PathBuf::from(format!(
            "cargo-tools/v1/sources/{}",
            self.subject.id().map_err(err)?.sha256
        ));
        for (root, prefix, inventory) in &self.inventories {
            for input in inventory
                .iter()
                .filter(|input| input.kind == InputKind::Directory)
            {
                let destination = base.join(&input.path);
                ctx.stores
                    .data
                    .create_directory_checked(&destination, || ctx.budget.materialise(0))?;
            }
            for input in inventory
                .iter()
                .filter(|input| input.kind == InputKind::RegularFile)
            {
                let relative = input
                    .path
                    .strip_prefix(&format!("{prefix}/"))
                    .ok_or("source namespace mismatch")?;
                let bytes =
                    process::read_bounded(&root.join(relative), process::FILE_LIMIT, &ctx.budget)?;
                if sha256(&bytes) != input.sha256 {
                    return Err("source bytes changed before dossier publication".into());
                }
                let destination = base.join(&input.path);
                if let Some(previous) = ctx
                    .stores
                    .data
                    .read_optional(&destination, process::FILE_LIMIT)?
                {
                    if previous.bytes() != bytes {
                        return Err("durable source snapshot conflict".into());
                    }
                } else {
                    ctx.budget.materialise(bytes.len() as u64)?;
                    ctx.stores
                        .data
                        .publish_checked(&destination, &bytes, || ctx.check())?;
                }
            }
        }
        Ok(ctx.stores.data.root().join(base))
    }
    pub fn environment(&self, ctx: &Context) -> Result<BTreeMap<OsString, OsString>> {
        let mut env = process::base_environment(
            &self.stage.root.join("home"),
            &self.cargo_home,
            &ctx.evaluator()?.rustc.path,
        );
        env.insert(
            "CARGO_TARGET_DIR".into(),
            self.target_dir.as_os_str().to_owned(),
        );
        Ok(env)
    }
    pub fn recheck_after_build(&self, ctx: &Context) -> Result<()> {
        ctx.check_after_build()?;
        let budget = process::Budget::native(ctx.budget.cancelled.clone());
        if process::read_bounded(&self.configuration.0, 8 * 1024 * 1024, &budget)?
            != self.configuration.1
        {
            return Err("generated source mapping changed during build".into());
        }
        for (root, prefix, expected) in &self.inventories {
            if source::inventory(root, prefix, &budget)? != *expected {
                return Err("accepted source inventory changed during build".into());
            }
        }
        if process::read_bounded(
            &self.workspace_root.join("Cargo.lock"),
            8 * 1024 * 1024,
            &budget,
        )? != self.effective_lock
        {
            return Err("effective workspace lock changed during build".into());
        }
        Ok(())
    }
    pub fn recheck(&self, ctx: &Context) -> Result<()> {
        ctx.check()?;
        if process::read_bounded(&self.configuration.0, 8 * 1024 * 1024, &ctx.budget)?
            != self.configuration.1
        {
            return Err("generated source mapping changed".into());
        }
        ctx.evaluator()?.recheck(&ctx.budget)?;
        for (root, prefix, expected) in &self.inventories {
            if source::inventory(root, prefix, &ctx.budget)? != *expected {
                return Err("accepted source inventory changed".into());
            }
        }
        let bytes = process::read_bounded(
            &self.workspace_root.join("Cargo.lock"),
            8 * 1024 * 1024,
            &ctx.budget,
        )?;
        if bytes != self.effective_lock {
            return Err("effective workspace lock changed".into());
        }
        Ok(())
    }
}

pub(crate) fn prepare(ctx: &Context, request: &ReviewRequest) -> Result<PreparedSource> {
    prepare_inputs(ctx, request, None, SourceAccess::Fresh)
}
#[cfg(test)]
pub(crate) fn policy_fixture(
    ctx: &Context,
    stage: Stage,
    root: PathBuf,
    subject: Subject,
    metadata: Value,
    origins: BTreeMap<String, PackageIdentity>,
    effective_lock: Vec<u8>,
) -> Result<PreparedSource> {
    let cargo_home = stage.root.join("cargo-home");
    let target_dir = stage.root.join("target");
    for directory in [&cargo_home, &target_dir, &stage.root.join("home")] {
        fs::create_dir_all(directory).map_err(err)?;
    }
    let configuration = (cargo_home.join("config.toml"), Vec::new());
    fs::write(&configuration.0, &configuration.1).map_err(err)?;
    let inventory = source::inventory(&root, "fixture", &ctx.budget)?;
    if inventory != subject.inputs {
        return Err("policy fixture source inventory differs from its subject".into());
    }
    let mut fixture_ioc = BTreeMap::new();
    let mut scan_budget = ctx.ioc_budget.borrow_mut();
    for package in subject.graph.packages() {
        let inspection = crate::ioc_intake::inspect_tree(
            &ctx.stores,
            &ctx.budget,
            &root,
            barbican::ioc::Source::from(&package),
            &mut scan_budget,
        )?;
        fixture_ioc.insert(package, inspection);
    }
    Ok(PreparedSource {
        manifest: root.join("Cargo.toml"),
        workspace_root: root.clone(),
        cargo_home,
        target_dir,
        subject,
        metadata,
        origins,
        effective_lock,
        inspected: BTreeMap::new(),
        ioc_inspections: fixture_ioc,
        source_facts: BTreeMap::new(),
        inventories: vec![(root.clone(), "fixture".into(), inventory)],
        root,
        stage,
        configuration,
    })
}
pub(crate) fn prepare_accepted(ctx: &Context, accepted: &StoredReview) -> Result<PreparedSource> {
    prepare_inputs(ctx, &accepted.request, Some(accepted), SourceAccess::Fresh)
}
enum SourceAccess {
    Fresh,
    Stored,
    #[cfg(test)]
    Authored(PathBuf),
}
#[cfg(test)]
pub(crate) fn authored_fixture(
    ctx: &Context,
    request: &ReviewRequest,
    source: &Path,
) -> Result<PreparedSource> {
    if request.spec.is_some() || request.git.is_none() {
        return Err("authored fixture requires explicit synthetic Git identity".into());
    }
    prepare_inputs(
        ctx,
        request,
        None,
        SourceAccess::Authored(source.to_owned()),
    )
}
fn prepare_inputs(
    ctx: &Context,
    request: &ReviewRequest,
    accepted: Option<&StoredReview>,
    source_access: SourceAccess,
) -> Result<PreparedSource> {
    let stored_sources = matches!(source_access, SourceAccess::Stored);
    ctx.check()?;
    let evaluator = ctx.evaluator()?;
    evaluator.recheck(&ctx.budget)?;
    if request
        .target
        .as_deref()
        .is_some_and(|target| target != evaluator.host)
    {
        return Err("cross-compilation is outside native tool qualification".into());
    }
    let stage = Stage::new()?;
    for name in ["home", "cargo-home", "target"] {
        fs::create_dir(stage.root.join(name)).map_err(err)?;
    }
    let root = stage.root.join("source");
    let mut inspected = BTreeMap::new();
    let mut source_facts = BTreeMap::new();
    let root_identity = if let Some(spec) = &request.spec {
        if request.git.is_some() {
            return Err("exactly one tool source is required".into());
        }
        let spec: ExactCrateSpec = spec.parse().map_err(err)?;
        ctx.budget.materialise(0)?;
        fs::create_dir(&root).map_err(err)?;
        let (identity, archive) = if stored_sources {
            let identity = accepted
                .ok_or("stored source requires accepted review")?
                .subject
                .root
                .package();
            let PackageSource::CratesIo { archive_sha256 } = &identity.source else {
                return Err("stored root is not a registry source".into());
            };
            let archive = cached_registry_archive(ctx, archive_sha256)?;
            (identity, archive)
        } else {
            let (identity, inspection, fact, archive) = registry_source(ctx, &spec)?;
            inspected.insert(identity.clone(), inspection);
            source_facts.insert(identity.clone(), fact);
            (identity, archive)
        };
        let PackageSource::CratesIo { archive_sha256 } = &identity.source else {
            return Err("registry identity mismatch".into());
        };
        source::materialise_crate(&root, &spec, &archive, archive_sha256, &ctx.budget)?;
        RootSourceIdentity::CratesIo {
            name: identity.name.clone(),
            version: identity.version.clone(),
            archive_sha256: archive_sha256.clone(),
        }
    } else {
        let url = request.git.as_deref().ok_or("exact source missing")?;
        let rev = request.rev.as_deref().ok_or("full Git commit missing")?;
        match &source_access {
            SourceAccess::Stored => {
                let subject = &accepted
                    .ok_or("stored source requires accepted review")?
                    .subject;
                restore_source_snapshot(ctx, subject, "root", &root)?;
                restore_original_git_lock(ctx, subject, &root)?;
            }
            SourceAccess::Fresh => {
                source::git_materialise(url, rev, &root, &stage.root, &ctx.budget)?
            }
            #[cfg(test)]
            SourceAccess::Authored(authored) => copy_authored_source(authored, &root, &ctx.budget)?,
        }
        RootSourceIdentity::Git {
            url: url.into(),
            rev: rev.into(),
            package: request.package.clone().ok_or("Git package missing")?,
            version: String::new(),
            workspace_manifest: "Cargo.toml".into(),
            package_manifest: "Cargo.toml".into(),
            materialisation_sha256: source::inventory_digest(&source::inventory(
                &root,
                "root",
                &ctx.budget,
            )?)?,
        }
    };
    let manifests = source::validate_manifests(&root, &ctx.budget)?;
    let requested_name = match &root_identity {
        RootSourceIdentity::CratesIo { name, .. } => name.clone(),
        RootSourceIdentity::Git { package, .. } => package.clone(),
    };
    let matches: Vec<_> = manifests
        .iter()
        .filter(|(_, value)| {
            value.pointer("/package/name").and_then(Value::as_str) == Some(requested_name.as_str())
        })
        .collect();
    if matches.len() != 1 {
        return Err("selected package must identify exactly one source workspace member".into());
    }
    let manifest = matches[0].0.clone();
    let cargo_home = stage.root.join("cargo-home");
    let target_dir = stage.root.join("target");
    let mut environment =
        process::base_environment(&stage.root.join("home"), &cargo_home, &evaluator.rustc.path);
    environment.insert("CARGO_TARGET_DIR".into(), target_dir.as_os_str().to_owned());
    let invoke = |args: Vec<String>| -> Result<process::ProcessOutput> {
        process::run(
            &evaluator.cargo,
            &args,
            &stage.root,
            &environment,
            &ctx.budget,
        )
    };
    let base = vec![
        "--manifest-path".into(),
        manifest.to_string_lossy().into_owned(),
    ];
    // The metadata command performs resolution only; no build scripts or proc macros run.
    let source_workspace = manifest
        .parent()
        .ok_or("manifest parent missing")?
        .ancestors()
        .take_while(|path| path.starts_with(&root))
        .find(|path| {
            manifests.iter().any(|(manifest, value)| {
                manifest == &path.join("Cargo.toml") && value.get("workspace").is_some()
            })
        })
        .unwrap_or(manifest.parent().ok_or("manifest parent missing")?);
    let original_lock =
        super::context::read_optional(source_workspace, Path::new("Cargo.lock"), &ctx.budget)?;
    if let Some(bytes) = &original_lock {
        let path = PathBuf::from(format!(
            "cargo-tools/v1/original-locks/{}.lock",
            sha256(bytes)
        ));
        if let Some(previous) = ctx.stores.data.read_optional(&path, 8 * 1024 * 1024)? {
            if previous.bytes() != bytes {
                return Err("original source lock snapshot conflict".into());
            }
        } else {
            ctx.stores.data.publish(&path, bytes)?;
        }
    }
    if let Some(accepted) = accepted {
        let locked = ctx.stores.data.read(
            Path::new(&format!(
                "cargo-tools/v1/locks/{}.lock",
                accepted.subject.effective_lock.sha256()
            )),
            8 * 1024 * 1024,
        )?;
        if sha256(locked.bytes()) != *accepted.subject.effective_lock.sha256() {
            return Err("accepted effective lock snapshot changed".into());
        }
        fs::write(source_workspace.join("Cargo.lock"), locked.bytes()).map_err(err)?;
    }
    let selected_lock =
        super::context::read_optional(source_workspace, Path::new("Cargo.lock"), &ctx.budget)?;
    let valid_lock = selected_lock.as_deref().filter(|bytes| {
        std::str::from_utf8(bytes)
            .ok()
            .is_some_and(|text| barbican::parse_lockfile(text).is_ok())
    });
    let git_sources = if stored_sources {
        let subject = &accepted
            .ok_or("stored source requires accepted review")?
            .subject;
        super::git_dependency::GitSources::collect_with_materialiser(
            &manifests,
            valid_lock,
            &stage.root,
            &ctx.budget,
            |identity, destination| {
                let prefix = format!(
                    "git-original/{}",
                    sha256(identity.locked_source().as_bytes())
                );
                restore_source_snapshot(ctx, subject, &prefix, destination)
            },
        )?
    } else {
        super::git_dependency::GitSources::collect(
            &manifests,
            valid_lock,
            &stage.root,
            &ctx.budget,
        )?
    };
    let config_path = cargo_home.join("config.toml");
    fs::write(&config_path, git_sources.config_fragment.as_bytes()).map_err(err)?;
    let vendor = stage.root.join("verified-registry");
    let mut registry_material = BTreeMap::new();
    let malformed = original_lock.as_ref().is_some_and(|bytes| {
        std::str::from_utf8(bytes)
            .ok()
            .is_none_or(|text| barbican::parse_lockfile(text).is_err())
    });
    let mut lock_origin = None;
    if accepted.is_none() && (original_lock.is_none() || malformed) {
        if malformed {
            fs::remove_file(source_workspace.join("Cargo.lock")).map_err(err)?;
        }
        let seed = git_sources.seed_lock(if malformed { None } else { valid_lock })?;
        fs::write(source_workspace.join("Cargo.lock"), seed).map_err(err)?;
        let mut args = if git_sources.config_fragment.is_empty() {
            vec!["generate-lockfile".into()]
        } else {
            vec!["update".into(), "--workspace".into()]
        };
        args.extend(base.clone());
        let output = invoke(args)?;
        if !output.status.success() {
            return Err("trusted Cargo could not prepare index-only lock resolution".into());
        }
        lock_origin = Some(
            if malformed {
                "original workspace lock is malformed"
            } else {
                "original source contains no effective workspace lock"
            }
            .to_owned(),
        );
    }
    let config_bytes=format!("{}\n[source.crates-io]\nreplace-with = \"barbican-verified-registry\"\n[source.barbican-verified-registry]\ndirectory = {}\n",git_sources.config_fragment,serde_json::to_string(&vendor.to_string_lossy()).map_err(err)?).into_bytes();
    let mut metadata_args = vec![
        "metadata".into(),
        "--format-version=1".into(),
        "--frozen".into(),
    ];
    metadata_args.extend(base.clone());
    metadata_args.extend(request.feature_args());
    let mut metadata_output = None;
    for attempt in 0..2 {
        let lock = process::read_bounded(
            &source_workspace.join("Cargo.lock"),
            8 * 1024 * 1024,
            &ctx.budget,
        )?;
        materialise_registry_lock(
            ctx,
            &lock,
            &vendor,
            stored_sources,
            &mut registry_material,
            &mut inspected,
            &mut source_facts,
        )?;
        fs::write(&config_path, &config_bytes).map_err(err)?;
        let output = invoke(metadata_args.clone())?;
        if output.status.success() {
            metadata_output = Some(output);
            break;
        }
        let diagnostic = String::from_utf8_lossy(&output.stderr);
        let stale = (diagnostic.contains("lock file")
            && diagnostic.contains("needs to be updated"))
            || diagnostic.contains("no matching package named")
            || diagnostic.contains("failed to select a version for the requirement");
        if accepted.is_some() || attempt != 0 || !stale {
            return Err("frozen independently materialised Cargo graph failed; no source/re-resolution fallback".into());
        }
        fs::write(&config_path, git_sources.config_fragment.as_bytes()).map_err(err)?;
        let seed = git_sources.seed_lock(Some(&lock))?;
        fs::write(source_workspace.join("Cargo.lock"), seed).map_err(err)?;
        let mut args = if git_sources.config_fragment.is_empty() {
            vec!["generate-lockfile".into()]
        } else {
            vec!["update".into(), "--workspace".into()]
        };
        args.extend(base.clone());
        let resolution = invoke(args)?;
        if !resolution.status.success() {
            return Err("trusted Cargo could not derive the unusable source lock".into());
        }
        lock_origin = Some("original workspace lock does not match selected manifests".into());
    }
    let metadata_output = metadata_output.ok_or("frozen source metadata unavailable")?;
    let metadata: Value = serde_json::from_slice(&metadata_output.stdout).map_err(err)?;
    let workspace_root = PathBuf::from(
        metadata
            .get("workspace_root")
            .and_then(Value::as_str)
            .ok_or("Cargo metadata missing workspace root")?,
    );
    if workspace_root != source_workspace || !workspace_root.starts_with(&root) {
        return Err("effective workspace lock role differs from immutable source root".into());
    }
    let effective_lock = process::read_bounded(
        &workspace_root.join("Cargo.lock"),
        8 * 1024 * 1024,
        &ctx.budget,
    )?;
    let mut original = match (&original_lock, &lock_origin) {
        (Some(bytes), None) => OriginalLock::Usable {
            sha256: sha256(bytes),
        },
        (Some(bytes), Some(reason)) => OriginalLock::Unusable {
            sha256: sha256(bytes),
            reason: reason.clone(),
        },
        (None, _) => OriginalLock::Absent,
    };
    let mut effective = match lock_origin {
        Some(reason) => EffectiveLock::Derived {
            sha256: sha256(&effective_lock),
            reason,
        },
        None => EffectiveLock::Upstream {
            sha256: sha256(&effective_lock),
        },
    };
    if let Some(accepted) = accepted {
        let original_digest = original_lock.as_ref().map(|bytes| sha256(bytes));
        let expected_original = match &accepted.subject.original_lock {
            OriginalLock::Absent => None,
            OriginalLock::Usable { sha256 } | OriginalLock::Unusable { sha256, .. } => {
                Some(sha256.clone())
            }
        };
        if original_digest != expected_original
            || sha256(&effective_lock) != *accepted.subject.effective_lock.sha256()
        {
            return Err("original or effective accepted lock changed".into());
        }
        original = accepted.subject.original_lock.clone();
        effective = accepted.subject.effective_lock.clone();
    }
    let lock_path = PathBuf::from(format!(
        "cargo-tools/v1/locks/{}.lock",
        sha256(&effective_lock)
    ));
    if let Some(previous) = ctx.stores.data.read_optional(&lock_path, 8 * 1024 * 1024)? {
        if previous.bytes() != effective_lock {
            return Err("effective lock snapshot conflict".into());
        }
    } else {
        ctx.stores.data.publish(&lock_path, &effective_lock)?;
    }
    let packages = metadata
        .get("packages")
        .and_then(Value::as_array)
        .ok_or("metadata packages missing")?;
    let root_package = packages
        .iter()
        .find(|p| p.get("manifest_path").and_then(Value::as_str) == manifest.to_str())
        .ok_or("selected root absent from metadata")?;
    if let RootSourceIdentity::CratesIo { name, version, .. } = &root_identity
        && (field(root_package, "name")? != name || field(root_package, "version")? != version)
    {
        return Err(
            "published root manifest identity differs from exact requested registry identity"
                .into(),
        );
    }
    let root_identity = match root_identity {
        RootSourceIdentity::Git {
            url,
            rev,
            package,
            materialisation_sha256,
            ..
        } => RootSourceIdentity::Git {
            url,
            rev,
            package,
            version: field(root_package, "version")?.into(),
            workspace_manifest: workspace_root
                .join("Cargo.toml")
                .strip_prefix(&root)
                .map_err(err)?
                .to_string_lossy()
                .into_owned(),
            package_manifest: manifest
                .strip_prefix(&root)
                .map_err(err)?
                .to_string_lossy()
                .into_owned(),
            materialisation_sha256,
        },
        value => value,
    };
    let mut tree_args = vec!["tree".into()];
    tree_args.extend(base.clone());
    tree_args.extend([
        "--package".into(),
        requested_name.clone(),
        "--frozen".into(),
        "--target".into(),
        evaluator.host.clone(),
        "--edges".into(),
        "normal,build".into(),
        "--format".into(),
        "||B1||{p}||{f}".into(),
        "--prefix".into(),
        "indent".into(),
        "--charset".into(),
        "ascii".into(),
        "--no-dedupe".into(),
    ]);
    tree_args.extend(request.feature_args());
    let tree = invoke(tree_args)?;
    if !tree.status.success() {
        return Err("frozen native install graph preflight failed".into());
    }
    let tree_text = String::from_utf8(tree.stdout).map_err(err)?;
    let selected_ids = super::graph::selected_ids(&metadata, &tree_text)?;
    let mut origins = BTreeMap::new();
    let mut inventories = Vec::new();
    let mut all_inputs = source::inventory(&root, "root", &ctx.budget)?;
    inventories.push((root.clone(), "root".into(), all_inputs.clone()));
    for (directory, prefix, files) in &git_sources.inventories {
        all_inputs.extend(files.clone());
        inventories.push((directory.clone(), prefix.clone(), files.clone()));
    }

    // Bind each metadata ID independently; source=None only inherits a Git root
    // when its manifest is inside the captured immutable repository.
    for package in packages {
        let id = field(package, "id")?;
        if !selected_ids.contains(id) {
            continue;
        }
        let name = field(package, "name")?;
        let version = field(package, "version")?;
        let path = PathBuf::from(field(package, "manifest_path")?);
        let directory = path.parent().ok_or("package manifest parent missing")?;
        let identity = if path == manifest {
            root_identity.package()
        } else if package.get("source").is_none_or(Value::is_null) {
            match &root_identity {
                RootSourceIdentity::Git {
                    url,
                    rev,
                    materialisation_sha256,
                    ..
                } if directory.starts_with(&root) => PackageIdentity {
                    name: name.into(),
                    version: version.into(),
                    source: PackageSource::Git {
                        url: url.clone(),
                        rev: rev.clone(),
                        subdirectory: directory
                            .strip_prefix(&root)
                            .map_err(err)?
                            .to_str()
                            .ok_or("nonUTF8 package directory")?
                            .to_owned(),
                        materialisation_sha256: materialisation_sha256.clone(),
                    },
                },
                _ => {
                    return Err(
                        "path metadata lacks independently established original source".into(),
                    );
                }
            }
        } else {
            let source = field(package, "source")?;
            if source == barbican::CRATES_IO_SOURCE || source == "sparse+https://index.crates.io/" {
                let material = registry_material.get(&format!("{name}@{version}")).ok_or(
                    "graph registry source absent from independently collected effective lock",
                )?;
                if directory != material.directory {
                    return Err(
                        "Cargo selected a registry directory outside verified source mapping"
                            .into(),
                    );
                }
                material.identity.clone()
            } else if source.starts_with("git+") {
                let package = git_sources.package(source, name, version)?;
                if directory != package.directory {
                    return Err(
                        "Cargo selected Git source outside independently verified public mapping"
                            .into(),
                    );
                }
                package.identity.clone()
            } else {
                return Err("unqualified dependency registry or source transport".into());
            }
        };
        identity.validate().map_err(err)?;
        origins.insert(id.into(), identity);
    }
    for inventory in selected_registry_inventories(&registry_material, &origins, &ctx.budget)? {
        all_inputs.extend(inventory.2.clone());
        inventories.push(inventory);
    }
    let (graph, selection) = super::graph::bind(
        &metadata,
        &tree_text,
        &origins,
        root_package,
        request,
        &evaluator.host,
        &manifests,
    )?;
    source::validate_execution_inputs(
        &metadata,
        field(root_package, "id")?,
        &selected_ids,
        &selection,
        &inventories,
        &ctx.budget,
    )?;
    let subject = Subject {
        schema_version: 1,
        root: root_identity,
        original_lock: original,
        effective_lock: effective,
        graph,
        selection,
        evaluator: super::graph::build_evaluator(evaluator)?,
        config_sha256:sha256(&serde_json::to_vec(&json!({"class":"cargo-tool-directory-sources-v1","configuration":std::str::from_utf8(&config_bytes).map_err(err)?.replace(stage.root.to_str().ok_or("stage path is not UTF8")?,"$SOURCE_STAGE"),"environment":"private-home;absolute-rustc;system-path;fresh-target"})).map_err(err)?),
        native_mode: NativeMode::VerifiedPath,
        inputs: all_inputs,
    };
    subject.validate().map_err(err)?;
    let mut ioc_inspections = BTreeMap::new();
    let mut scan_budget = ctx.ioc_budget.borrow_mut();
    for package in subject.graph.packages() {
        let inspection = match &package.source {
            PackageSource::CratesIo { .. } => inspected
                .get(&package)
                .and_then(|report| report.ioc_inspection())
                .cloned()
                .ok_or("registry IOC original-source evidence unavailable")?,
            PackageSource::Git {
                url,
                rev,
                materialisation_sha256,
                ..
            } => {
                let original_root = if matches!(&subject.root, RootSourceIdentity::Git {url:root_url,rev:root_rev,..} if root_url==url && root_rev==rev)
                {
                    root.clone()
                } else {
                    inventories
                        .iter()
                        .find(|(_, prefix, files)| {
                            prefix.starts_with("git-original/")
                                && source::original_inventory_digest(files, prefix)
                                    .is_ok_and(|digest| digest == *materialisation_sha256)
                        })
                        .map(|(root, _, _)| root.clone())
                        .ok_or("Git original source inventory unavailable for IOC inspection")?
                };
                crate::ioc_intake::inspect_tree(
                    &ctx.stores,
                    &ctx.budget,
                    &original_root,
                    barbican::ioc::Source::from(&package),
                    &mut scan_budget,
                )?
            }
        };
        ioc_inspections.insert(package, inspection);
    }
    Ok(PreparedSource {
        root,
        manifest,
        workspace_root,
        cargo_home,
        target_dir,
        subject,
        metadata,
        origins,
        effective_lock,
        inspected,
        ioc_inspections,
        source_facts,
        stage,
        configuration: (config_path, config_bytes),
        inventories,
    })
}
fn field<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("metadata missing {key}"))
}
fn registry_source(
    ctx: &Context,
    spec: &ExactCrateSpec,
) -> Result<(PackageIdentity, RustInspectReport, SourceFact, Vec<u8>)> {
    let original = crate::registry_source::acquire(
        &ctx.stores,
        &ctx.budget,
        &ctx.source_client,
        spec,
        None,
        ctx.now,
    )?;
    let package = original.package;
    let release = original.release;
    let fact = original.fact;
    let archive = original.archive;
    let observation_key = original.pending_key;
    let minimum = super::policy::configuration(ctx)?.release_age.minimum_days;
    let inspection = barbican::inspect::inspect_published_crate_at_with_ioc_budget(
        spec.clone(),
        release,
        &archive,
        barbican::OffsetDateTime::from_unix_timestamp(ctx.now).map_err(err)?,
        minimum,
        None,
        barbican::ioc::ScanControl {
            budget: &mut ctx.ioc_budget.borrow_mut(),
            check: &mut || ctx.budget.check(),
        },
    );
    let inspector = &ctx.evaluator()?.inspector;
    let details = json!({"schema_version":1,"checksum_matches":inspection.checksum_matches(),"local_checksum":inspection.local_checksum_sha256_hex(),"failures":inspection.inspection_failures(),"build_scripts":inspection.build_script_paths(),"proc_macro":inspection.proc_macro(),"links":inspection.package_links(),"native_sources":inspection.native_source_paths()});
    let inspected_fact = SourceFact {
        key: KnowledgeKey::Inspection {
            package: package.clone(),
            inspector_sha256: inspector.sha256.clone(),
        },
        facts_sha256: sha256(&serde_json::to_vec(&details).map_err(err)?),
        status: if !inspection.checksum_matches() || !inspection.inspection_failures().is_empty() {
            SecurityStatus::Adverse
        } else {
            SecurityStatus::Clear
        },
        expires_at_utc: None,
    };
    let inspected_at = barbican::OffsetDateTime::now_utc().unix_timestamp();
    ctx.stores.remember(
        KnowledgeEntry {
            fact: inspected_fact,
            source_version: 1,
            checked_at_utc: inspected_at,
        },
        inspected_at,
    )?;
    if let Some(ioc) = inspection.ioc_inspection() {
        let marker = crate::ioc_intake::ioc_marker(&ioc.source)?;
        ctx.stores.begin_source(&marker)?;
        crate::ioc_intake::remember_inspection(&ctx.stores, ioc)?;
        if matches!(ioc.coverage, barbican::ioc::Coverage::Complete) {
            ctx.stores.finish_source(&marker)?;
        }
    }
    ctx.stores.finish_source(&observation_key)?;
    if !inspection.checksum_matches() {
        return Err("original crates.io archive checksum mismatch".into());
    }
    Ok((package, inspection, fact, archive))
}

pub(crate) fn validate_current(ctx: &Context, stored: &StoredReview) -> Result<()> {
    validate_context(ctx, stored)?;
    ctx.stores.ensure_sources_complete(&stored.subject)
}
fn validate_context(ctx: &Context, stored: &StoredReview) -> Result<()> {
    ctx.check()?;
    let evaluator = super::graph::build_evaluator(ctx.evaluator()?)?;
    if evaluator != stored.subject.evaluator {
        return Err("trusted build evaluator changed; fresh assessment required".into());
    }
    let policy = super::policy::capture(ctx)?;
    if policy != stored.policy {
        return Err("origin policy or trusted scanners changed; fresh assessment required".into());
    }
    Ok(())
}
pub(crate) fn refresh(
    ctx: &Context,
    stored: &StoredReview,
    cached_reason: Option<&str>,
) -> Result<StoredReview> {
    validate_context(ctx, stored)?;
    if let Some(reason) = cached_reason {
        ctx.stores.ensure_sources_complete(&stored.subject)?;
        if reason.trim().is_empty() {
            return Err("cached admission requires a nonempty reason".into());
        }
        let id = stored.review.id().map_err(err)?;
        return super::frontend::load_review(ctx, &id);
    }
    refresh_online(ctx, stored).map(|(review, _)| review)
}

pub(crate) fn refresh_for_install(
    ctx: &Context,
    stored: &StoredReview,
    cached_reason: Option<&str>,
) -> Result<(StoredReview, PreparedSource)> {
    if let Some(reason) = cached_reason {
        let current = refresh(ctx, stored, Some(reason))?;
        let prepared = prepare_inputs(ctx, &current.request, Some(&current), SourceAccess::Stored)?;
        if prepared.subject != current.subject {
            return Err("stored source/build inputs differ from accepted review".into());
        }
        return Ok((current, prepared));
    }
    validate_context(ctx, stored)?;
    refresh_online(ctx, stored)
}

fn refresh_online(ctx: &Context, stored: &StoredReview) -> Result<(StoredReview, PreparedSource)> {
    let prepared = prepare_accepted(ctx, stored)?;
    if prepared.subject != stored.subject {
        return Err(
            "source/build inputs changed; fresh tool review and assessment required".into(),
        );
    }
    let evidence = super::policy::collect(ctx, &prepared)?;
    if evidence.content != stored.evidence.content || evidence.policy != stored.policy {
        return Err("material policy, coverage or source evidence changed; fresh tool review and assessment required".into());
    }
    super::frontend::retain_details(ctx, &stored.review, &evidence.details)?;
    let refreshed = StoredReview {
        subject: prepared.subject.clone(),
        policy: evidence.policy,
        review: stored.review.clone(),
        evidence: EvidenceRecord {
            content: evidence.content,
            observation: evidence.observation,
        },
        request: stored.request.clone(),
    };
    super::frontend::save_review(ctx, &refreshed)?;
    Ok((refreshed, prepared))
}

fn cached_registry_archive(ctx: &Context, checksum: &barbican::Sha256Digest) -> Result<Vec<u8>> {
    ctx.check()?;
    let path = PathBuf::from(format!("cargo-tools/v1/archives/{checksum}.crate"));
    let captured = ctx.stores.cache.read(&path, process::FILE_LIMIT)
        .map_err(|error| format!("accepted original archive is unavailable locally; fresh source collection is required: {error}"))?;
    if sha256(captured.bytes()) != *checksum {
        return Err("cached original archive does not match the accepted checksum".into());
    }
    Ok(captured.bytes().to_vec())
}

fn restore_source_snapshot(
    ctx: &Context,
    subject: &Subject,
    prefix: &str,
    destination: &Path,
) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    ctx.check()?;
    subject.validate().map_err(err)?;
    let expected: BTreeSet<_> = subject
        .inputs
        .iter()
        .filter(|input| {
            input.path == prefix
                || input.path.starts_with(&format!("{prefix}/"))
                || prefix.starts_with(&format!("{}/", input.path))
        })
        .cloned()
        .collect();
    if !expected
        .iter()
        .any(|input| input.path == prefix && input.kind == InputKind::Directory)
    {
        return Err("accepted source snapshot namespace is missing".into());
    }
    ctx.budget.materialise(0)?;
    fs::create_dir(destination).map_err(err)?;
    let base = PathBuf::from(format!(
        "cargo-tools/v1/sources/{}",
        subject.id().map_err(err)?.sha256
    ));
    let mut directories = Vec::new();
    for input in &expected {
        let Some(relative) = input.path.strip_prefix(&format!("{prefix}/")) else {
            continue;
        };
        ctx.budget.check()?;
        match input.kind {
            InputKind::Directory => {
                source::create_source_directory(destination, relative, &ctx.budget)?;
                directories.push((destination.join(relative), input.mode));
            }
            InputKind::RegularFile => {
                let captured = ctx
                    .stores
                    .data
                    .read(&base.join(&input.path), process::FILE_LIMIT)?;
                if captured.bytes().len() as u64 != input.bytes
                    || sha256(captured.bytes()) != input.sha256
                {
                    return Err("accepted source snapshot bytes changed".into());
                }
                source::write_source(
                    destination,
                    relative,
                    input.mode,
                    captured.bytes(),
                    &ctx.budget,
                )?;
            }
        }
    }
    directories.sort_by_key(|(path, _)| std::cmp::Reverse(path.components().count()));
    for (path, mode) in directories {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(err)?;
    }
    if source::inventory(destination, prefix, &ctx.budget)? != expected {
        return Err("restored source inventory differs from accepted inputs".into());
    }
    Ok(())
}

#[cfg(test)]
fn copy_authored_source(
    original: &Path,
    destination: &Path,
    budget: &process::Budget,
) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let inputs = source::inventory(original, "root", budget)?;
    budget.materialise(0)?;
    fs::create_dir(destination).map_err(err)?;
    let mut directories = Vec::new();
    for input in &inputs {
        let Some(relative) = input.path.strip_prefix("root/") else {
            continue;
        };
        match input.kind {
            InputKind::Directory => {
                source::create_source_directory(destination, relative, budget)?;
                directories.push((destination.join(relative), input.mode));
            }
            InputKind::RegularFile => {
                let bytes =
                    process::read_bounded(&original.join(relative), process::FILE_LIMIT, budget)?;
                if sha256(&bytes) != input.sha256 {
                    return Err("authored fixture changed while copying".into());
                }
                source::write_source(destination, relative, input.mode, &bytes, budget)?;
            }
        }
    }
    directories.sort_by_key(|(path, _)| std::cmp::Reverse(path.components().count()));
    for (path, mode) in directories {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(err)?;
    }
    if source::inventory(destination, "root", budget)? != inputs {
        return Err("authored fixture inventory changed".into());
    }
    Ok(())
}

fn restore_original_git_lock(ctx: &Context, subject: &Subject, root: &Path) -> Result<()> {
    let RootSourceIdentity::Git {
        workspace_manifest, ..
    } = &subject.root
    else {
        return Err("expected accepted Git root".into());
    };
    let lock_path = root
        .join(workspace_manifest)
        .parent()
        .ok_or("accepted workspace manifest has no parent")?
        .join("Cargo.lock");
    match &subject.original_lock {
        OriginalLock::Absent => {
            if lock_path.exists() {
                fs::remove_file(lock_path).map_err(err)?;
            }
        }
        OriginalLock::Usable { sha256: digest } | OriginalLock::Unusable { sha256: digest, .. } => {
            let bytes = ctx.stores.data.read(
                Path::new(&format!("cargo-tools/v1/original-locks/{digest}.lock")),
                8 * 1024 * 1024,
            )?;
            if sha256(bytes.bytes()) != *digest {
                return Err("accepted original lock snapshot changed".into());
            }
            if process::read_bounded(&lock_path, 8 * 1024 * 1024, &ctx.budget)? != bytes.bytes() {
                fs::write(lock_path, bytes.bytes()).map_err(err)?;
            }
        }
    }
    Ok(())
}

struct RegistryMaterial {
    directory: PathBuf,
    identity: PackageIdentity,
}
fn selected_registry_inventories(
    materialised: &BTreeMap<String, RegistryMaterial>,
    origins: &BTreeMap<String, PackageIdentity>,
    budget: &process::Budget,
) -> Result<Vec<(PathBuf, String, BTreeSet<InputFile>)>> {
    let selected: BTreeSet<_> = origins.values().collect();
    let mut inventories = Vec::new();
    for material in materialised.values() {
        if !selected.contains(&material.identity) {
            continue;
        }
        let prefix = format!(
            "registry/{}-{}",
            material.identity.name, material.identity.version
        );
        let files = source::inventory(&material.directory, &prefix, budget)?;
        inventories.push((material.directory.clone(), prefix, files));
    }
    Ok(inventories)
}

fn materialise_registry_lock(
    ctx: &Context,
    lock: &[u8],
    vendor: &Path,
    stored_sources: bool,
    materialised: &mut BTreeMap<String, RegistryMaterial>,
    inspected: &mut BTreeMap<PackageIdentity, RustInspectReport>,
    source_facts: &mut BTreeMap<PackageIdentity, SourceFact>,
) -> Result<()> {
    let lock = barbican::parse_lockfile(std::str::from_utf8(lock).map_err(err)?).map_err(err)?;
    fs::create_dir_all(vendor).map_err(err)?;
    for package in lock
        .packages()
        .iter()
        .filter(|package| package.is_crates_io())
    {
        ctx.budget.check()?;
        let key = format!("{}@{}", package.name, package.version);
        if let Some(previous) = materialised.get(&key) {
            if !matches!(&previous.identity.source,PackageSource::CratesIo{archive_sha256} if Some(archive_sha256)==package.checksum())
            {
                return Err("same registry package has conflicting lock checksum".into());
            }
            continue;
        }
        let (identity, archive) = if stored_sources {
            let checksum = package
                .checksum()
                .ok_or("accepted registry lock lacks checksum")?;
            (
                PackageIdentity {
                    name: package.name.clone(),
                    version: package.version.clone(),
                    source: PackageSource::CratesIo {
                        archive_sha256: checksum.clone(),
                    },
                },
                cached_registry_archive(ctx, checksum)?,
            )
        } else {
            let (identity, inspection, fact, archive) = registry_source(ctx, package.exact_spec())?;
            inspected.insert(identity.clone(), inspection);
            source_facts.insert(identity.clone(), fact);
            (identity, archive)
        };
        let PackageSource::CratesIo { archive_sha256 } = &identity.source else {
            return Err("registry origin mismatch".into());
        };
        if Some(archive_sha256) != package.checksum() {
            return Err(
                "effective lock checksum differs from authenticated original archive".into(),
            );
        }
        let directory = vendor.join(format!("{}-{}", package.name, package.version));
        ctx.budget.materialise(0)?;
        fs::create_dir(&directory).map_err(err)?;
        source::materialise_crate(
            &directory,
            package.exact_spec(),
            &archive,
            archive_sha256,
            &ctx.budget,
        )?;
        let files = source::inventory(&directory, "package", &ctx.budget)?;
        let checksums: BTreeMap<_, _> = files
            .iter()
            .filter(|entry| entry.kind == InputKind::RegularFile)
            .map(|entry| {
                (
                    entry
                        .path
                        .strip_prefix("package/")
                        .unwrap_or(&entry.path)
                        .to_owned(),
                    entry.sha256.clone(),
                )
            })
            .collect();
        let checksum_bytes =
            serde_json::to_vec(&json!({"package":archive_sha256,"files":checksums}))
                .map_err(err)?;
        source::write_source(
            &directory,
            ".cargo-checksum.json",
            0o644,
            &checksum_bytes,
            &ctx.budget,
        )?;
        source::validate_dependency_manifests(&directory, &ctx.budget)?;
        materialised.insert(
            key,
            RegistryMaterial {
                directory,
                identity,
            },
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registry_snapshot_keeps_complete_selected_packages_and_excludes_resolution_only_sources() {
        let stage = Stage::new().unwrap();
        let budget = process::Budget::new(false).unwrap();
        let mut materialised = BTreeMap::new();
        for name in ["selected", "inactive"] {
            let directory = stage.root.join(name);
            fs::create_dir(&directory).unwrap();
            source::write_source(
                &directory,
                "src/lib.rs",
                0o644,
                b"pub fn fixture() {}",
                &budget,
            )
            .unwrap();
            source::write_source(
                &directory,
                "auxiliary/notice",
                0o644,
                b"retained complete package",
                &budget,
            )
            .unwrap();
            source::create_source_directory(&directory, "empty", &budget).unwrap();
            materialised.insert(
                name.into(),
                RegistryMaterial {
                    directory,
                    identity: PackageIdentity {
                        name: name.into(),
                        version: "1.0.0".into(),
                        source: PackageSource::CratesIo {
                            archive_sha256: sha256(name.as_bytes()),
                        },
                    },
                },
            );
        }
        let origins = BTreeMap::from([(
            "metadata-selected-id".into(),
            materialised["selected"].identity.clone(),
        )]);
        let before = selected_registry_inventories(&materialised, &origins, &budget).unwrap();
        assert_eq!(before.len(), 1);
        assert!(
            before[0]
                .2
                .iter()
                .any(|file| file.path == "registry/selected-1.0.0/auxiliary/notice")
        );
        assert!(
            before[0]
                .2
                .iter()
                .any(|file| file.path == "registry/selected-1.0.0/empty"
                    && file.kind == InputKind::Directory)
        );
        fs::write(
            materialised["inactive"].directory.join("src/lib.rs"),
            b"changed inactive input",
        )
        .unwrap();
        assert_eq!(
            selected_registry_inventories(&materialised, &origins, &budget).unwrap(),
            before
        );
        fs::write(
            materialised["selected"].directory.join("auxiliary/notice"),
            b"changed selected auxiliary",
        )
        .unwrap();
        assert_ne!(
            selected_registry_inventories(&materialised, &origins, &budget).unwrap(),
            before
        );
    }
}
