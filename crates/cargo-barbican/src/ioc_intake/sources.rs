use super::{CapturedInputs, CapturedLock, CollectedReport, Context, RequestedSource};
use crate::controlled_process::{self as process, Budget, Result, err};
use crate::intake_store::Stores;
use crate::verified_source::{self as custody, Stage};
use barbican::cargo_tool::{
    InputKind, KnowledgeEntry, KnowledgeKey, PackageIdentity, SecurityStatus, SourceFact, sha256,
};
use barbican::ioc::{
    self, Coverage, Inspection, Origin, Report, ScanAccumulator, ScanBudget, Scope, Source,
};
use barbican::{ExactCrateSpec, Sha256Digest};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

pub(crate) enum Selection {
    Registry(Vec<ExactCrateSpec>),
    Git {
        url: String,
        rev: String,
        package: String,
    },
    Lockfile(PathBuf),
}

pub(crate) fn collect(ctx: &Context, selection: &Selection) -> Result<CollectedReport> {
    ctx.check()?;
    let client = crate::crates_io_http::UreqCratesIoClient::new(
        crate::crates_io_http::DEFAULT_CRATES_IO_BASE_URL.into(),
    );
    let mut scans = ScanBudget::default();
    let mut report = Report {
        schema_version: 1,
        scope: match selection {
            Selection::Lockfile(_) => "locked-external-source-set",
            _ => "explicit-exact-source-set",
        }
        .into(),
        sources: vec![],
        excluded: vec![],
        errors: vec![],
    };
    let mut registry = BTreeMap::<String, (ExactCrateSpec, Option<Sha256Digest>)>::new();
    let mut git = BTreeMap::<(String, String), BTreeSet<(String, Option<String>)>>::new();
    let mut lock_capture = None;
    let mut unsupported = Vec::new();
    match selection {
        Selection::Registry(specs) => {
            for spec in specs {
                registry.insert(spec.to_string(), (spec.clone(), None));
            }
        }
        Selection::Git { url, rev, package } => {
            barbican::GitSourceIdentity::new(url, rev).map_err(err)?;
            git.entry((url.clone(), rev.clone()))
                .or_default()
                .insert((package.clone(), None));
        }
        Selection::Lockfile(path) => {
            let path = if path.is_absolute() {
                path.clone()
            } else {
                ctx.current.join(path)
            };
            let parent = path.parent().ok_or("lockfile has no parent")?;
            let name = path.file_name().ok_or("lockfile has no filename")?;
            let bytes = custody::read_optional(parent, Path::new(name), &ctx.budget)?
                .ok_or("explicit lockfile is missing")?;
            let lock =
                barbican::parse_lockfile(std::str::from_utf8(&bytes).map_err(err)?).map_err(err)?;
            for package in lock.packages() {
                ctx.budget.check()?;
                scans.charge_report(
                    512 + package.name.len() * 6
                        + package.version.len() * 6
                        + package.source.as_ref().map_or(0, |source| source.len() * 6),
                )?;
                if package.is_crates_io() {
                    let checksum = package
                        .checksum
                        .clone()
                        .ok_or("locked registry source lacks checksum")?;
                    let key = package.exact_spec().to_string();
                    if registry
                        .get(&key)
                        .is_some_and(|(_, previous)| previous.as_ref() != Some(&checksum))
                    {
                        return Err(
                            "conflicting duplicate locked registry checksums for one exact source"
                                .into(),
                        );
                    }
                    registry.insert(key, (package.exact_spec().clone(), Some(checksum)));
                } else if let Some(source) = &package.source {
                    if source.starts_with("git+") {
                        match locked_git(source) {
                            Ok(identity) => {
                                git.entry(identity)
                                    .or_default()
                                    .insert((package.name.clone(), Some(package.version.clone())));
                            }
                            Err(error) => {
                                unsupported.push((
                                    RequestedSource::Unsupported {
                                        name: package.name.clone(),
                                        version: package.version.clone(),
                                        source_sha256: ioc::digest(source.as_bytes()),
                                    },
                                    error.clone(),
                                ));
                                report.errors.push(error);
                            }
                        }
                    } else {
                        let reason = format!(
                            "unsupported external source for {}@{}",
                            package.name, package.version
                        );
                        unsupported.push((
                            RequestedSource::Unsupported {
                                name: package.name.clone(),
                                version: package.version.clone(),
                                source_sha256: ioc::digest(source.as_bytes()),
                            },
                            reason.clone(),
                        ));
                        report.errors.push(reason);
                    }
                } else {
                    report.excluded.push(format!("{}@{}: source-less local/path entry is outside locked external-source scope",package.name,package.version));
                }
            }
            lock_capture = Some((path, bytes));
        }
    }
    let lockfile = lock_capture
        .as_ref()
        .map(|(path, bytes)| {
            Ok::<_, String>(CapturedLock {
                path: path.to_str().ok_or("lockfile path is not UTF8")?.into(),
                sha256: ioc::digest_checked(bytes, &mut || ctx.budget.check())?,
            })
        })
        .transpose()?;
    let requested = registry
        .values()
        .map(|(spec, checksum)| RequestedSource::CratesIo {
            name: spec.crate_name().into(),
            version: spec.version().into(),
            checksum: checksum.clone(),
        })
        .chain(git.iter().flat_map(|((url, rev), packages)| {
            packages
                .iter()
                .map(|(package, version)| RequestedSource::Git {
                    url: url.clone(),
                    rev: rev.clone(),
                    package: package.clone(),
                    version: version.clone(),
                })
        }))
        .chain(unsupported.iter().map(|(source, _)| source.clone()));
    let mut input = CapturedInputs::new(lockfile, requested)?;
    for (source, error) in &unsupported {
        input.record(source, &Err(error.clone()))?;
    }
    for (_, (spec, checksum)) in registry {
        let result = registry_source(
            &ctx.stores,
            &ctx.budget,
            &client,
            &spec,
            checksum.as_ref(),
            &mut scans,
        );
        input.record(
            &RequestedSource::CratesIo {
                name: spec.crate_name().into(),
                version: spec.version().into(),
                checksum,
            },
            &result,
        )?;
        match result {
            Ok(inspection) => {
                let incomplete = !matches!(inspection.coverage, Coverage::Complete);
                report.sources.push(inspection);
                if incomplete {
                    report.errors.push("collection stopped after incomplete source inspection; remaining requested sources are uninspected".into());
                    break;
                }
            }
            Err(error) => {
                report.errors.push(format!("{spec}: {error}"));
                break;
            }
        }
    }
    if report.errors.is_empty() {
        for ((url, rev), packages) in git {
            let stage = Stage::new()?;
            let root = stage.root.join("original");
            if let Err(error) =
                custody::git_materialise(&url, &rev, &root, &stage.root, &ctx.budget)
            {
                for (package, version) in &packages {
                    input.record(
                        &RequestedSource::Git {
                            url: url.clone(),
                            rev: rev.clone(),
                            package: package.clone(),
                            version: version.clone(),
                        },
                        &Err(error.clone()),
                    )?;
                }
                report.errors.push(error);
                break;
            }
            let inventory = custody::inventory(&root, "root", &ctx.budget)?;
            let digest = custody::inventory_digest(&inventory)?;
            for (name, version) in packages {
                let result = git_package(
                    &root,
                    &url,
                    &rev,
                    &name,
                    version.as_deref(),
                    &digest,
                    &ctx.budget,
                )
                .and_then(|source| {
                    inspect_tree(&ctx.stores, &ctx.budget, &root, source, &mut scans)
                });
                input.record(
                    &RequestedSource::Git {
                        url: url.clone(),
                        rev: rev.clone(),
                        package: name.clone(),
                        version: version.clone(),
                    },
                    &result,
                )?;
                match result {
                    Ok(inspection) => {
                        let incomplete = !matches!(inspection.coverage, Coverage::Complete);
                        report.sources.push(inspection);
                        if incomplete {
                            report.errors.push("collection stopped after incomplete source inspection; remaining requested sources are uninspected".into());
                            break;
                        }
                    }
                    Err(error) => {
                        report.errors.push(format!("Git package {name}: {error}"));
                        break;
                    }
                }
            }
            if !report.errors.is_empty() {
                break;
            }
        }
    }
    if let Some((path, bytes)) = lock_capture
        && process::read_bounded(&path, ioc::MAX_REPORT_BYTES as u64, &ctx.budget)? != bytes
    {
        return Err("lockfile changed during IOC inspection".into());
    }
    ctx.check()?;
    report.sources.sort_by(|a, b| a.source.cmp(&b.source));
    report.excluded.sort();
    report.validate()?;
    input.validate(&report)?;
    Ok(CollectedReport { report, input })
}

fn locked_git(source: &str) -> Result<(String, String)> {
    let source = source
        .strip_prefix("git+")
        .ok_or("unsupported Git source")?;
    let (origin, rev) = source
        .rsplit_once('#')
        .ok_or("locked Git source lacks exact commit")?;
    let url = origin.split('?').next().ok_or("Git source URL missing")?;
    barbican::GitSourceIdentity::new(url, rev).map_err(err)?;
    Ok((url.into(), rev.into()))
}

fn registry_source(
    stores: &Stores,
    budget: &Budget,
    client: &crate::crates_io_http::UreqCratesIoClient,
    spec: &ExactCrateSpec,
    expected: Option<&Sha256Digest>,
    scans: &mut ScanBudget,
) -> Result<Inspection> {
    let original = crate::registry_source::acquire(
        stores,
        budget,
        client,
        spec,
        expected,
        barbican::OffsetDateTime::now_utc().unix_timestamp(),
    )?;
    let source = Source::from(&original.package);
    let marker = original.pending_key;
    let release = original.release;
    let archive = original.archive;
    let stage = Stage::new()?;
    custody::materialise_crate(
        &stage.root,
        spec,
        &archive,
        &release.checksum_sha256_hex,
        budget,
    )?;
    let inspection = inspect_tree(stores, budget, &stage.root, source, scans)?;
    if matches!(inspection.coverage, Coverage::Complete) {
        stores.finish_source(&marker)?;
    }
    Ok(inspection)
}

pub(crate) fn revalidate(ctx: &Context, inspection: &Inspection) -> Result<Inspection> {
    ctx.check()?;
    let current = revalidate_with(&ctx.stores, &ctx.budget, inspection)?;
    ctx.check()?;
    Ok(current)
}
pub(crate) fn revalidate_with(
    stores: &Stores,
    budget: &Budget,
    inspection: &Inspection,
) -> Result<Inspection> {
    inspection.validate()?;
    let stage = Stage::new()?;
    let mut scans = ScanBudget::default();
    let root = match &inspection.source.origin {
        Origin::CratesIo { archive_sha256 } => {
            let package = PackageIdentity::from(&inspection.source);
            let key = KnowledgeKey::Package { package };
            let knowledge = stores.knowledge()?;
            if knowledge
                .entry_for(&key)
                .is_none_or(|entry| entry.fact.key != key)
            {
                return Err("registry source lacks independently observed checksum authority; rerun exact IOC check".into());
            }
            let bytes = stores
                .cache
                .read(
                    &PathBuf::from(format!("cargo-tools/v1/archives/{archive_sha256}.crate")),
                    process::FILE_LIMIT,
                )
                .map_err(|_| {
                    "original verified archive unavailable; rerun exact IOC check".to_owned()
                })?;
            let spec =
                ExactCrateSpec::from_parts(&inspection.source.name, &inspection.source.version)
                    .map_err(err)?;
            custody::materialise_crate(&stage.root, &spec, bytes.bytes(), archive_sha256, budget)?;
            stage.root.clone()
        }
        Origin::Git {
            url,
            rev,
            materialisation_sha256,
            ..
        } => {
            let root = stage.root.join("original");
            custody::git_materialise(url, rev, &root, &stage.root, budget)?;
            if custody::inventory_digest(&custody::inventory(&root, "root", budget)?)?
                != *materialisation_sha256
            {
                return Err("Git original inventory differs from report".into());
            }
            root
        }
    };
    inspect_tree(stores, budget, &root, inspection.source.clone(), &mut scans)
}

pub(crate) fn inspect_tree(
    stores: &Stores,
    budget: &Budget,
    root: &Path,
    source: Source,
    scans: &mut ScanBudget,
) -> Result<Inspection> {
    source.validate()?;
    let marker = ioc_marker(&source)?;
    stores.begin_source(&marker)?;
    let inventory = custody::inventory(root, "root", budget)?;
    let (prefix, manifest) = match &source.origin {
        Origin::CratesIo { .. } => (String::new(), root.join("Cargo.toml")),
        Origin::Git { subdirectory, .. } => {
            let prefix = if subdirectory == "." {
                String::new()
            } else {
                format!("{subdirectory}/")
            };
            (
                prefix,
                root.join(if subdirectory == "." {
                    ""
                } else {
                    subdirectory
                })
                .join("Cargo.toml"),
            )
        }
    };
    let value = read_manifest(&manifest, budget)?;
    let name = value
        .pointer("/package/name")
        .and_then(Value::as_str)
        .ok_or("source package name missing")?;
    if name != source.name || manifest_version(root, &manifest, &value, budget)? != source.version {
        return Err("source manifest does not match exact package identity".into());
    }
    let mut scope = qualified_scope(
        root,
        manifest.parent().ok_or("manifest parent missing")?,
        &value,
    )?;
    for input in inventory
        .iter()
        .filter(|file| file.kind == InputKind::RegularFile)
    {
        let path = input
            .path
            .strip_prefix("root/")
            .ok_or("source inventory namespace mismatch")?;
        if let Some(relative) = path.strip_prefix(&prefix)
            && ioc::is_native_source_path(relative)
        {
            scope.native_source_paths.insert(path.into());
        }
    }
    if matches!(source.origin, Origin::Git { .. }) {
        let mut paths = BTreeSet::new();
        if scope.has_execution_surface() {
            let mut package_directories = Vec::new();
            for input in inventory.iter().filter(|file| {
                file.kind == InputKind::RegularFile
                    && (file.path == "root/Cargo.toml" || file.path.ends_with("/Cargo.toml"))
            }) {
                let relative = input
                    .path
                    .strip_prefix("root/")
                    .ok_or("source namespace mismatch")?;
                let path = root.join(relative);
                let candidate = read_manifest(&path, budget)?;
                if candidate.get("package").is_none() {
                    continue;
                }
                let directory = path.parent().ok_or("package parent missing")?;
                let relative_directory = directory
                    .strip_prefix(root)
                    .map_err(err)?
                    .to_str()
                    .ok_or("package path is not UTF8")?;
                let candidate_prefix = if relative_directory.is_empty() {
                    String::new()
                } else {
                    format!("{relative_directory}/")
                };
                package_directories.push(candidate_prefix.clone());
                let candidate_scope = qualified_scope(root, directory, &candidate)?;
                paths.extend(candidate_scope.build_script_paths);
                paths.extend(candidate_scope.required_paths);
            }
            package_directories.sort_by_key(|prefix| std::cmp::Reverse(prefix.len()));
            for input in inventory
                .iter()
                .filter(|file| file.kind == InputKind::RegularFile)
            {
                let path = input
                    .path
                    .strip_prefix("root/")
                    .ok_or("source namespace mismatch")?;
                let relative = package_directories
                    .iter()
                    .find_map(|prefix| path.strip_prefix(prefix))
                    .unwrap_or(path);
                if !ioc::is_excluded_path(relative)
                    && (relative.ends_with(".rs") || ioc::is_native_source_path(relative))
                {
                    paths.insert(path.into());
                }
            }
            paths.extend(scope.build_script_paths.iter().cloned());
        }
        scope.explicit_paths = Some(paths);
    }
    scans.charge_report(1024 + serde_json::to_vec(&source).map_err(err)?.len() * 6)?;
    let git_source = matches!(source.origin, Origin::Git { .. });
    let mut scan = ScanAccumulator::new(source)?;
    let mut failure = None;
    for input in inventory
        .iter()
        .filter(|file| file.kind == InputKind::RegularFile)
    {
        let path = input
            .path
            .strip_prefix("root/")
            .ok_or("source inventory namespace mismatch")?;
        if !git_source && !path.starts_with(&prefix) && !scope.build_script_paths.contains(path) {
            continue;
        }
        let result = (|| {
            budget.check()?;
            let bytes = process::read_bounded(&root.join(path), process::FILE_LIMIT, budget)?;
            if sha256(&bytes) != input.sha256 {
                return Err("original source changed while scanning".into());
            }
            scan.scan_file_checked(path, &bytes, &scope, scans, &mut || budget.check())
        })();
        if let Err(error) = result {
            failure = Some(error);
            break;
        }
    }
    let inspection = scan.finish(failure);
    remember_inspection(stores, &inspection)?;
    if matches!(inspection.coverage, Coverage::Complete) {
        stores.finish_source(&marker)?;
    }
    Ok(inspection)
}

fn qualified_scope(root: &Path, directory: &Path, value: &Value) -> Result<Scope> {
    let roles = ioc::manifest_roles(value)?;
    let relative = directory
        .strip_prefix(root)
        .map_err(err)?
        .to_str()
        .ok_or("package path is not UTF8")?;
    let prefix = if relative.is_empty() {
        String::new()
    } else {
        format!("{relative}/")
    };
    let mut scope = Scope {
        package_prefix: prefix.clone(),
        proc_macro: roles.proc_macro,
        package_links: roles.package_links.is_some(),
        ..Scope::default()
    };
    scope.native_sys = barbican::is_native_sys_execution_surface(
        value
            .pointer("/package/name")
            .and_then(Value::as_str)
            .is_some_and(|name| name.ends_with("-sys")),
        scope.package_links,
    );
    match roles.build_script {
        ioc::BuildScriptRole::Auto => {
            let path = format!("{prefix}build.rs");
            if root.join(&path).is_file() {
                scope.build_script_paths.insert(path);
            }
        }
        ioc::BuildScriptRole::Disabled => {}
        ioc::BuildScriptRole::Path(path) => {
            scope
                .build_script_paths
                .insert(confined_file(root, directory, &path)?);
        }
    }
    if let Some(path) = roles.proc_macro_path {
        scope
            .required_paths
            .insert(confined_file(root, directory, &path)?);
    }
    Ok(scope)
}

fn read_manifest(path: &Path, budget: &Budget) -> Result<Value> {
    let bytes = process::read_bounded(path, ioc::MAX_REPORT_BYTES as u64, budget)?;
    barbican::tool_inputs::source_manifest(std::str::from_utf8(&bytes).map_err(err)?)
}
fn manifest_version(root: &Path, path: &Path, value: &Value, budget: &Budget) -> Result<String> {
    if let Some(version) = value.pointer("/package/version").and_then(Value::as_str) {
        return Ok(version.into());
    }
    if value
        .pointer("/package/version/workspace")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err("unsupported package version declaration".into());
    }
    let directory = path.parent().ok_or("manifest parent missing")?;
    let explicit = value
        .pointer("/package/workspace")
        .and_then(Value::as_str)
        .map(|relative| fs::canonicalize(directory.join(relative)).map_err(err))
        .transpose()?;
    if explicit
        .as_ref()
        .is_some_and(|path| !path.starts_with(root))
    {
        return Err("workspace outside verified original tree".into());
    }
    for ancestor in directory
        .ancestors()
        .take_while(|path| path.starts_with(root))
    {
        if explicit.as_ref().is_some_and(|path| path != ancestor) {
            continue;
        }
        let manifest = ancestor.join("Cargo.toml");
        if manifest.is_file() {
            let workspace = read_manifest(&manifest, budget)?;
            if workspace.get("workspace").is_some() {
                return workspace
                    .pointer("/workspace/package/version")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .ok_or("workspace version missing".into());
            }
        }
    }
    Err("inherited package version has no verified workspace".into())
}
fn git_package(
    root: &Path,
    url: &str,
    rev: &str,
    name: &str,
    version: Option<&str>,
    digest: &Sha256Digest,
    budget: &Budget,
) -> Result<Source> {
    let mut matches = Vec::new();
    for input in custody::inventory(root, "root", budget)?
        .iter()
        .filter(|file| {
            file.kind == InputKind::RegularFile
                && (file.path == "root/Cargo.toml" || file.path.ends_with("/Cargo.toml"))
        })
    {
        let relative = input
            .path
            .strip_prefix("root/")
            .ok_or("source namespace mismatch")?;
        let manifest = root.join(relative);
        let value = read_manifest(&manifest, budget)?;
        if value.pointer("/package/name").and_then(Value::as_str) != Some(name) {
            continue;
        }
        let actual = manifest_version(root, &manifest, &value, budget)?;
        if version.is_some_and(|version| version != actual) {
            continue;
        }
        let subdirectory = Path::new(relative)
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .map(|path| path.to_str().ok_or("Git package path is not UTF8"))
            .transpose()?
            .unwrap_or(".");
        matches.push(Source {
            name: name.into(),
            version: actual,
            origin: Origin::Git {
                url: url.into(),
                rev: rev.into(),
                subdirectory: subdirectory.into(),
                materialisation_sha256: digest.clone(),
            },
        });
    }
    if matches.len() != 1 {
        return Err("Git package selection is missing or ambiguous".into());
    }
    Ok(matches.remove(0))
}
fn confined_file(root: &Path, directory: &Path, value: &str) -> Result<String> {
    if value.is_empty()
        || value.len() > 4096
        || value.contains('\\')
        || value.chars().any(char::is_control)
    {
        return Err("unsafe declared source path".into());
    }
    let mut path = directory.to_owned();
    for part in Path::new(value).components() {
        match part {
            Component::Normal(part) => path.push(part),
            Component::CurDir => {}
            Component::ParentDir => {
                if path == root || !path.pop() {
                    return Err("declared source escapes verified tree".into());
                }
            }
            _ => return Err("absolute declared source path".into()),
        }
    }
    let relative = path
        .strip_prefix(root)
        .map_err(err)?
        .to_str()
        .ok_or("declared path is not UTF8")?;
    custody::safe_relative(relative)?;
    if !fs::symlink_metadata(&path).map_err(err)?.is_file() {
        return Err("declared source is not an original regular file".into());
    }
    Ok(relative.into())
}
pub(crate) fn ioc_marker(source: &Source) -> Result<String> {
    Ok(format!("ioc:{}", source.id()?))
}
pub(crate) fn remember_inspection(stores: &Stores, inspection: &Inspection) -> Result<()> {
    let package = PackageIdentity::from(&inspection.source);
    let now = barbican::OffsetDateTime::now_utc().unix_timestamp();
    let known = stores.knowledge()?;
    let mut entries = Vec::new();
    for finding in inspection
        .findings
        .iter()
        .filter(|finding| finding.complete)
    {
        let id = finding.id()?;
        let fact = SourceFact {
            key: KnowledgeKey::Ioc {
                package: package.clone(),
                finding_id: id.clone(),
            },
            facts_sha256: id,
            status: SecurityStatus::Adverse,
            expires_at_utc: None,
        };
        let entry = known
            .entry_for(&fact.key)
            .filter(|entry| entry.fact == fact)
            .cloned()
            .unwrap_or(KnowledgeEntry {
                fact,
                source_version: 1,
                checked_at_utc: now,
            });
        entries.push(entry);
    }
    if !entries.is_empty() {
        stores.remember_many(entries, now)?;
    }
    Ok(())
}

pub(crate) fn knowledge_check(
    ctx: &Context,
    report: &Report,
    allowances: &ioc::AllowanceIndex,
    now: i64,
) -> Result<()> {
    ctx.check()?;
    for inspection in &report.sources {
        ctx.stores
            .ensure_source_complete(&ioc_marker(&inspection.source)?)?;
        let package = PackageIdentity::from(&inspection.source);
        ctx.stores
            .ensure_source_complete(&crate::intake_store::package_source_observation_key(
                &package.family(),
                &package.version,
            )?)?;
    }
    let sources = report
        .sources
        .iter()
        .map(|inspection| inspection.source.clone())
        .collect::<Vec<_>>();
    let decision = ctx
        .stores
        .knowledge()?
        .ioc_decision_indexed(&sources, allowances, now)
        .map_err(err)?;
    if !decision.is_success() {
        return Err("retained IOC findings, incomplete inspection or conflicting source knowledge remain unresolved".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Stage, PathBuf, Stores, Budget) {
        let stage = Stage::new().unwrap();
        let root = stage.root.join("source");
        fs::create_dir(&root).unwrap();
        let stores = Stores::open(
            &stage.root,
            None,
            Some(&stage.root.join("data")),
            Some(&stage.root.join("cache")),
        )
        .unwrap();
        let budget = Budget::new(false).unwrap();
        (stage, root, stores, budget)
    }
    fn put(root: &Path, path: &str, bytes: &str, budget: &Budget) {
        custody::write_source(root, path, 0o644, bytes.as_bytes(), budget).unwrap();
    }
    fn git_identity(root: &Path, subdirectory: &str, budget: &Budget) -> Source {
        Source {
            name: "fixture".into(),
            version: "1.0.0".into(),
            origin: Origin::Git {
                url: "https://example.com/fixture.git".into(),
                rev: "a".repeat(40),
                subdirectory: subdirectory.into(),
                materialisation_sha256: custody::inventory_digest(
                    &custody::inventory(root, "root", budget).unwrap(),
                )
                .unwrap(),
            },
        }
    }
    #[test]
    fn git_repository_scope_includes_sibling_helpers_and_explicit_test_named_build_path() {
        let (_stage, root, stores, budget) = fixture();
        put(
            &root,
            "Cargo.toml",
            "[workspace]\nmembers=['member','sibling']\n[workspace.package]\nversion='1.0.0'\n",
            &budget,
        );
        put(
            &root,
            "member/Cargo.toml",
            "[package]\nname='fixture'\nversion.workspace=true\nbuild='../tests/required.rs'\n",
            &budget,
        );
        put(
            &root,
            "sibling/Cargo.toml",
            "[package]\nname='sibling'\nversion='1.0.0'\n",
            &budget,
        );
        for path in [
            "tests/required.rs",
            "sibling/src/helper.rs",
            "member/src/lib.rs",
            "member/tests/excluded.rs",
            "sibling/examples/excluded.rs",
        ] {
            put(
                &root,
                path,
                "// Command::new( expected textual fixture",
                &budget,
            );
        }
        let source = git_identity(&root, "member", &budget);
        let inspection =
            inspect_tree(&stores, &budget, &root, source, &mut ScanBudget::default()).unwrap();
        let paths = inspection
            .findings
            .iter()
            .map(|finding| finding.path.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            paths,
            BTreeSet::from([
                "member/src/lib.rs",
                "sibling/src/helper.rs",
                "tests/required.rs"
            ])
        );
        assert!(matches!(inspection.coverage, Coverage::Complete));
        assert_eq!(stores.knowledge().unwrap().entries.len(), 3);
    }
    #[test]
    fn missing_required_helper_retains_pending_barrier() {
        let (_stage, root, stores, budget) = fixture();
        put(
            &root,
            "Cargo.toml",
            "[package]\nname='fixture'\nversion='1.0.0'\nbuild='missing.rs'\n",
            &budget,
        );
        let source = git_identity(&root, ".", &budget);
        let marker = ioc_marker(&source).unwrap();
        assert!(inspect_tree(&stores, &budget, &root, source, &mut ScanBudget::default()).is_err());
        assert!(stores.ensure_source_complete(&marker).is_err());
    }
    #[test]
    fn ambiguous_git_package_is_not_selected_by_name_or_version() {
        let (_stage, root, _stores, budget) = fixture();
        for dir in ["a", "b"] {
            put(
                &root,
                &format!("{dir}/Cargo.toml"),
                "[package]\nname='fixture'\nversion='1.0.0'\n",
                &budget,
            );
        }
        let digest =
            custody::inventory_digest(&custody::inventory(&root, "root", &budget).unwrap())
                .unwrap();
        assert!(
            git_package(
                &root,
                "https://example.com/fixture.git",
                &"a".repeat(40),
                "fixture",
                Some("1.0.0"),
                &digest,
                &budget
            )
            .unwrap_err()
            .contains("ambiguous")
        );
    }
    #[test]
    fn incomplete_scanner_retains_completed_earlier_adverse_and_observation_barrier() {
        let (_stage, root, stores, budget) = fixture();
        put(
            &root,
            "Cargo.toml",
            "[package]\nname='fixture'\nversion='1.0.0'\nbuild='build.rs'\n",
            &budget,
        );
        put(&root, "build.rs", "Command::new( ", &budget);
        put(&root, "z.rs", &"Command::new( ".repeat(30_000), &budget);
        let source = git_identity(&root, ".", &budget);
        let marker = ioc_marker(&source).unwrap();
        let inspection =
            inspect_tree(&stores, &budget, &root, source, &mut ScanBudget::default()).unwrap();
        assert!(matches!(inspection.coverage, Coverage::Incomplete { .. }));
        assert!(stores.ensure_source_complete(&marker).is_err());
        assert!(!stores.knowledge().unwrap().entries.is_empty());
        assert!(inspection.findings.iter().any(|finding| !finding.complete));
    }
    #[test]
    fn inventory_identity_does_not_depend_on_tool_transport_namespace() {
        let (_stage, root, _stores, budget) = fixture();
        put(&root, "file.rs", "source bytes", &budget);
        let direct = custody::inventory(&root, "root", &budget).unwrap();
        let transport = custody::inventory(&root, "git-original/abc", &budget).unwrap();
        assert_eq!(
            custody::inventory_digest(&direct).unwrap(),
            custody::original_inventory_digest(&transport, "git-original/abc").unwrap()
        );
    }
    #[test]
    fn cache_bytes_alone_cannot_authorise_a_report_source() {
        let (_stage, _root, stores, budget) = fixture();
        let source = Source {
            name: "fixture".into(),
            version: "1.0.0".into(),
            origin: Origin::CratesIo {
                archive_sha256: sha256(b"untrusted cache bytes"),
            },
        };
        let inspection = ScanAccumulator::new(source).unwrap().finish(None);
        assert!(
            revalidate_with(&stores, &budget, &inspection)
                .unwrap_err()
                .contains("independently observed checksum authority")
        );
    }
    #[test]
    fn rescanning_identical_immutable_findings_preserves_the_first_observation_time() {
        let (_stage, _root, stores, _budget) = fixture();
        let source = Source {
            name: "fixture".into(),
            version: "1.0.0".into(),
            origin: Origin::CratesIo {
                archive_sha256: sha256(b"original archive"),
            },
        };
        let mut scan = ScanAccumulator::new(source.clone()).unwrap();
        let scope = Scope {
            build_script_paths: BTreeSet::from(["build.rs".into()]),
            ..Scope::default()
        };
        scan.scan_file(
            "build.rs",
            b"Command::new(",
            &scope,
            &mut ScanBudget::default(),
        )
        .unwrap();
        let inspection = scan.finish(None);
        let id = inspection.findings[0].id().unwrap();
        let fact = SourceFact {
            key: KnowledgeKey::Ioc {
                package: PackageIdentity::from(&source),
                finding_id: id.clone(),
            },
            facts_sha256: id,
            status: SecurityStatus::Adverse,
            expires_at_utc: None,
        };
        let old = barbican::OffsetDateTime::now_utc().unix_timestamp() - 3600;
        stores
            .remember(
                KnowledgeEntry {
                    fact: fact.clone(),
                    source_version: 1,
                    checked_at_utc: old,
                },
                old,
            )
            .unwrap();
        remember_inspection(&stores, &inspection).unwrap();
        assert_eq!(
            stores
                .knowledge()
                .unwrap()
                .entry_for(&fact.key)
                .unwrap()
                .checked_at_utc,
            old
        );
    }
    #[test]
    fn locked_request_retains_original_bytes_and_all_unavailable_source_identities() {
        let stage = Stage::new().unwrap();
        let ctx = Context::capture(
            &stage.root,
            None,
            Some(&stage.root.join("data")),
            Some(&stage.root.join("cache")),
        )
        .unwrap();
        let lock = "version = 4\n[[package]]\nname='first'\nversion='1.0.0'\nsource='registry+https://example.invalid/index'\n[[package]]\nname='second'\nversion='2.0.0'\nsource='registry+https://example.invalid/other'\n[[package]]\nname='local'\nversion='1.0.0'\n";
        fs::write(stage.root.join("Cargo.lock"), lock).unwrap();
        let collected = collect(&ctx, &Selection::Lockfile("Cargo.lock".into())).unwrap();
        assert_eq!(
            collected.input.lockfile.as_ref().unwrap().sha256,
            ioc::digest(lock.as_bytes())
        );
        assert_eq!(
            collected.input.lockfile.as_ref().unwrap().path,
            stage.root.join("Cargo.lock").to_str().unwrap()
        );
        assert_eq!(collected.input.requested_source_count, 2);
        assert_eq!(collected.report.excluded.len(), 1);
        assert_eq!(collected.report.errors.len(), 2);
        assert!(collected.input.requested_sources.iter().all(|row| matches!(
            row.coverage,
            super::super::input::RequestedCoverage::Unavailable { .. }
        )));
        collected.input.validate(&collected.report).unwrap();
        let mut missing_lock = collected.input.clone();
        missing_lock.lockfile = None;
        assert!(missing_lock.validate(&collected.report).is_err());
        let mut wrong_scope = collected.report.clone();
        wrong_scope.scope = "explicit-exact-source-set".into();
        assert!(collected.input.validate(&wrong_scope).is_err());
        let mut changed = collected.input.clone();
        changed.requested_sources.pop();
        assert!(changed.validate(&collected.report).is_err());
        assert!(ctx.stores.knowledge().unwrap().entries.is_empty());
    }
    #[test]
    fn conflicting_duplicate_lock_checksums_refuse_before_any_source_acquisition_in_both_orders() {
        for checksums in [
            [
                "9a8e94ea7f378bd32cbbd37198a4a91436180c5bb472411e48b5ec2e2124ae9e".to_owned(),
                "f".repeat(64),
            ],
            [
                "f".repeat(64),
                "9a8e94ea7f378bd32cbbd37198a4a91436180c5bb472411e48b5ec2e2124ae9e".to_owned(),
            ],
        ] {
            let stage = Stage::new().unwrap();
            let ctx = Context::capture(
                &stage.root,
                None,
                Some(&stage.root.join("data")),
                Some(&stage.root.join("cache")),
            )
            .unwrap();
            let mut lock = "version = 4\n".to_owned();
            for checksum in checksums {
                lock.push_str(&format!("[[package]]\nname='serde'\nversion='1.0.228'\nsource='registry+https://github.com/rust-lang/crates.io-index'\nchecksum='{checksum}'\n"));
            }
            fs::write(stage.root.join("Cargo.lock"), lock).unwrap();
            let failure = collect(&ctx, &Selection::Lockfile("Cargo.lock".into())).unwrap_err();
            assert!(failure.contains("conflicting duplicate"), "{failure}");
            assert!(ctx.stores.knowledge().unwrap().entries.is_empty());
            assert!(
                !ctx.stores
                    .cache
                    .root()
                    .join("cargo-tools/v1/archives")
                    .exists()
            );
        }
    }

    #[test]
    fn actual_tree_proc_macro_aliases_scan_required_entry_even_under_excluded_directory() {
        for declaration in [
            "proc_macro = true",
            "crate-type = ['proc-macro']",
            "crate_type = ['proc-macro']",
        ] {
            let (_stage, root, stores, budget) = fixture();
            put(
                &root,
                "Cargo.toml",
                &format!(
                    "[package]\nname='fixture'\nversion='1.0.0'\n[lib]\n{declaration}\npath='tests/entry.rs'\n"
                ),
                &budget,
            );
            put(&root, "tests/entry.rs", "std::process::Command;", &budget);
            let source = git_identity(&root, ".", &budget);
            let inspection =
                inspect_tree(&stores, &budget, &root, source, &mut ScanBudget::default()).unwrap();
            assert!(matches!(inspection.coverage, Coverage::Complete));
            assert_eq!(inspection.findings.len(), 1, "{declaration}");
            assert_eq!(inspection.findings[0].path, "tests/entry.rs");
        }
    }
    #[test]
    fn missing_required_proc_macro_entry_refuses_complete_tree_coverage() {
        let (_stage, root, stores, budget) = fixture();
        put(
            &root,
            "Cargo.toml",
            "[package]\nname='fixture'\nversion='1.0.0'\n[lib]\nproc_macro=true\n",
            &budget,
        );
        let source = git_identity(&root, ".", &budget);
        let marker = ioc_marker(&source).unwrap();
        assert!(inspect_tree(&stores, &budget, &root, source, &mut ScanBudget::default()).is_err());
        assert!(stores.ensure_source_complete(&marker).is_err());
    }
}
