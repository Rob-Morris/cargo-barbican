use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::path::Path;

use serde::Deserialize;
use thiserror::Error;

use crate::lockfile::{LockedPackageLookup, resolved_sources_match};
use crate::{
    ExactCrateSpec, ExecutionSurfaceKind, LockedDependency, Lockfile,
    is_native_sys_execution_surface,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CargoMetadata {
    packages: Vec<MetadataPackage>,
    workspace_members: Vec<String>,
    resolve: Option<MetadataResolve>,
}

impl CargoMetadata {
    fn workspace_member_ids(&self) -> HashSet<&str> {
        self.workspace_members.iter().map(String::as_str).collect()
    }

    fn packages_by_id(&self) -> BTreeMap<&str, &MetadataPackage> {
        self.packages
            .iter()
            .map(|package| (package.id.as_str(), package))
            .collect()
    }
}

pub fn parse_cargo_metadata(text: &str) -> Result<CargoMetadata, CargoMetadataError> {
    let raw: RawCargoMetadata = serde_json::from_str(text).map_err(CargoMetadataError::Parse)?;

    Ok(CargoMetadata {
        packages: raw
            .packages
            .into_iter()
            .map(|package| MetadataPackage {
                name: package.name,
                id: package.id,
                version: package.version,
                source: package.source,
                manifest_path: package.manifest_path,
                links: package.links,
                targets: package
                    .targets
                    .into_iter()
                    .map(|target| MetadataTarget { kind: target.kind })
                    .collect(),
                dependencies: package
                    .dependencies
                    .into_iter()
                    .map(|dependency| MetadataDependencyDeclaration {
                        name: dependency.name,
                        req: dependency.req,
                        kind: dependency.kind,
                        source: dependency.source,
                        path: dependency.path,
                    })
                    .collect(),
            })
            .collect(),
        workspace_members: raw.workspace_members,
        resolve: raw.resolve.map(|resolve| MetadataResolve {
            nodes: resolve
                .nodes
                .into_iter()
                .map(|node| MetadataNode {
                    id: node.id,
                    deps: node
                        .deps
                        .into_iter()
                        .map(|dependency| MetadataDependency {
                            name: dependency.name,
                            pkg: dependency.pkg,
                        })
                        .collect(),
                })
                .collect(),
        }),
    })
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct MetadataDirectDependency {
    resolved: LockedDependency,
    workspace_member: bool,
}

impl MetadataDirectDependency {
    pub fn spec(&self) -> &ExactCrateSpec {
        self.resolved.spec()
    }

    pub fn source(&self) -> Option<&str> {
        self.resolved.source()
    }

    pub fn is_crates_io(&self) -> bool {
        self.resolved.is_crates_io()
    }

    pub fn is_workspace_member(&self) -> bool {
        self.workspace_member
    }
}

pub fn workspace_direct_dependencies(
    metadata: &CargoMetadata,
    lockfile: &Lockfile,
) -> Result<Vec<MetadataDirectDependency>, CargoMetadataError> {
    let workspace_members = metadata.workspace_member_ids();
    let workspace_manifest_dirs = metadata
        .packages
        .iter()
        .filter(|package| workspace_members.contains(package.id.as_str()))
        .filter_map(|package| package.manifest_path.as_deref())
        .filter_map(|manifest_path| Path::new(manifest_path).parent())
        .collect::<BTreeSet<_>>();
    let locked_packages = lockfile.package_index();
    let mut dependencies = BTreeSet::new();

    for package in &metadata.packages {
        if !workspace_members.contains(package.id.as_str()) {
            continue;
        }
        let locked_parent = match locked_packages.find(
            package.name.as_str(),
            package.version.as_str(),
            package.source.as_deref(),
        ) {
            LockedPackageLookup::Found(locked_parent) => locked_parent,
            LockedPackageLookup::Ambiguous => {
                return Err(CargoMetadataError::AmbiguousLockedWorkspacePackage {
                    package_id: package.id.clone(),
                });
            }
            LockedPackageLookup::NotFound => {
                return Err(CargoMetadataError::LockedWorkspacePackageNotFound {
                    package_id: package.id.clone(),
                });
            }
        };
        dependencies.extend(resolve_workspace_package_direct_dependencies(
            package,
            locked_parent,
            &workspace_manifest_dirs,
        )?);
    }

    Ok(dependencies.into_iter().collect())
}

fn resolve_workspace_package_direct_dependencies(
    package: &MetadataPackage,
    locked_parent: &crate::LockedPackage,
    workspace_manifest_dirs: &BTreeSet<&Path>,
) -> Result<Vec<MetadataDirectDependency>, CargoMetadataError> {
    let declared_names = package
        .dependencies
        .iter()
        .map(|dependency| dependency.name.as_str())
        .collect::<BTreeSet<_>>();
    let locked_dependencies_by_name = locked_parent.dependencies().iter().fold(
        BTreeMap::<&str, Vec<_>>::new(),
        |mut by_name, dependency| {
            by_name
                .entry(dependency.spec().crate_name())
                .or_default()
                .push(dependency);
            by_name
        },
    );
    let locked_names = locked_dependencies_by_name
        .keys()
        .copied()
        .collect::<BTreeSet<_>>();
    if declared_names != locked_names {
        return Err(CargoMetadataError::LockedDirectDependencySetMismatch {
            package_id: package.id.clone(),
            declared: declared_names.into_iter().map(str::to_owned).collect(),
            locked: locked_names.into_iter().map(str::to_owned).collect(),
        });
    }

    package
        .dependencies
        .iter()
        .map(|declaration| {
            let resolved = resolve_declared_dependency(
                package,
                declaration,
                locked_dependencies_by_name
                    .get(declaration.name.as_str())
                    .map(Vec::as_slice)
                    .unwrap_or_default(),
            )?;
            Ok(MetadataDirectDependency {
                resolved: resolved.clone(),
                workspace_member: declaration
                    .path
                    .as_deref()
                    .is_some_and(|path| workspace_manifest_dirs.contains(Path::new(path))),
            })
        })
        .collect()
}

fn resolve_declared_dependency<'a>(
    parent: &MetadataPackage,
    declaration: &MetadataDependencyDeclaration,
    locked_dependencies: &'a [&LockedDependency],
) -> Result<&'a LockedDependency, CargoMetadataError> {
    let requirement = declaration
        .req
        .as_deref()
        .map(semver::VersionReq::parse)
        .transpose()
        .map_err(|source| CargoMetadataError::InvalidDependencyRequirement {
            package_id: parent.id.clone(),
            dependency_name: declaration.name.clone(),
            source,
        })?;
    let versionless_external = declaration.req.as_deref() == Some("*")
        && (declaration.path.is_some()
            || declaration
                .source
                .as_deref()
                .is_some_and(|source| source.starts_with("git+")));
    let version_candidates = locked_dependencies
        .iter()
        .copied()
        .filter(|dependency| {
            versionless_external
                || requirement.as_ref().is_none_or(|requirement| {
                    semver::Version::parse(dependency.spec().version())
                        .is_ok_and(|version| requirement.matches(&version))
                })
        })
        .collect::<Vec<_>>();
    let source_candidates = version_candidates
        .iter()
        .copied()
        .filter(|dependency| {
            if declaration.path.is_some() {
                dependency.source().is_none()
            } else {
                declaration.source.as_deref().is_some_and(|declared| {
                    dependency
                        .source()
                        .is_some_and(|resolved| resolved_sources_match(declared, resolved))
                })
            }
        })
        .collect::<Vec<_>>();
    // Registry patches legitimately replace the declaration's registry source
    // with a git or path edge. Cargo has already selected that edge; retain the
    // source match when available, then fall back to an otherwise unique
    // version match so the resolved source remains visible to enforcement.
    let mut candidates = if source_candidates.is_empty()
        && declaration.source.as_deref() == Some(crate::CRATES_IO_SOURCE)
    {
        version_candidates.into_iter()
    } else {
        source_candidates.into_iter()
    };
    let Some(first) = candidates.next() else {
        return Err(CargoMetadataError::LockedDirectDependencyNotFound {
            package_id: parent.id.clone(),
            dependency_name: declaration.name.clone(),
            requirement: declaration.req.clone(),
        });
    };
    let Some(second) = candidates.next() else {
        return Ok(first);
    };

    Err(CargoMetadataError::AmbiguousLockedDirectDependency {
        package_id: parent.id.clone(),
        dependency_name: declaration.name.clone(),
        requirement: declaration.req.clone(),
        candidates: std::iter::once(first)
            .chain(std::iter::once(second))
            .chain(candidates)
            .map(|dependency| dependency.spec().to_string())
            .collect(),
    })
}

pub fn select_package_id(
    metadata: &CargoMetadata,
    crate_name: &str,
) -> Result<String, CargoMetadataError> {
    let matches: Vec<&MetadataPackage> = metadata
        .packages
        .iter()
        .filter(|package| package.name == crate_name)
        .collect();

    if matches.is_empty() {
        return Err(CargoMetadataError::CrateNotFound {
            crate_name: crate_name.to_owned(),
        });
    }

    if matches.len() == 1 {
        return Ok(matches[0].id.clone());
    }

    let resolve = metadata
        .resolve
        .as_ref()
        .ok_or(CargoMetadataError::MissingResolveGraph)?;
    let workspace_members = metadata.workspace_member_ids();
    let direct_refs: BTreeSet<String> = resolve
        .nodes
        .iter()
        .filter(|node| workspace_members.contains(node.id.as_str()))
        .flat_map(|node| node.deps.iter())
        .filter(|dependency| dependency_name_matches_package(&dependency.name, crate_name))
        .map(|dependency| dependency.pkg.clone())
        .collect();

    match direct_refs.len() {
        1 => Ok(direct_refs.into_iter().next().expect("len checked")),
        0 => Err(CargoMetadataError::NoWorkspaceDirectDependency {
            crate_name: crate_name.to_owned(),
            package_ids: matches
                .into_iter()
                .map(|package| package.id.clone())
                .collect(),
        }),
        _ => Err(CargoMetadataError::MultipleWorkspaceDirectDependencies {
            crate_name: crate_name.to_owned(),
            package_ids: direct_refs.into_iter().collect(),
        }),
    }
}

pub fn package_surfaces(
    metadata: &CargoMetadata,
    spec: &ExactCrateSpec,
) -> Result<MetadataPackageSurfaces, CargoMetadataError> {
    let mut packages = metadata
        .packages
        .iter()
        .filter(|package| package.name == spec.crate_name() && package.version == spec.version());
    let first = packages
        .next()
        .ok_or_else(|| CargoMetadataError::PackageVersionNotFound {
            crate_name: spec.crate_name().to_owned(),
            version: spec.version().to_owned(),
        })?;

    let mut surfaces = MetadataPackageSurfaces::from_package(first);
    for package in packages {
        surfaces.union_with(&MetadataPackageSurfaces::from_package(package));
    }

    Ok(surfaces)
}

pub fn shortest_workspace_dependency_path(
    metadata: &CargoMetadata,
    target: &ExactCrateSpec,
) -> Result<Option<MetadataDependencyPath>, CargoMetadataError> {
    let resolve = metadata
        .resolve
        .as_ref()
        .ok_or(CargoMetadataError::MissingResolveGraph)?;
    let packages_by_id = metadata.packages_by_id();
    let target_ids = metadata
        .packages
        .iter()
        .filter(|package| {
            package.name == target.crate_name() && package.version == target.version()
        })
        .map(|package| package.id.as_str())
        .collect::<BTreeSet<_>>();

    if target_ids.is_empty() {
        return Ok(None);
    }

    let deps_by_id = resolve
        .nodes
        .iter()
        .map(|node| {
            let mut deps = node
                .deps
                .iter()
                .map(|dependency| dependency.pkg.as_str())
                .collect::<Vec<_>>();
            deps.sort_unstable();
            (node.id.as_str(), deps)
        })
        .collect::<BTreeMap<_, _>>();
    let mut starts = metadata
        .workspace_members
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    starts.sort_unstable();

    let mut visited = BTreeSet::new();
    let mut queue = VecDeque::new();
    for start in starts {
        if visited.insert(start) {
            queue.push_back(vec![start]);
        }
    }

    while let Some(path) = queue.pop_front() {
        let current = path.last().expect("queued paths are never empty");
        if target_ids.contains(current) {
            return metadata_dependency_path(&packages_by_id, &path).map(Some);
        }
        for dependency in deps_by_id.get(current).into_iter().flatten() {
            if !visited.insert(*dependency) {
                continue;
            }
            let mut next_path = path.clone();
            next_path.push(*dependency);
            queue.push_back(next_path);
        }
    }

    Ok(None)
}

/// One resolved parent's declared requirement on a target package: the edge
/// Cargo's resolver honoured, joined back to the semver requirement the
/// parent's manifest stated. `requirement` is `None` when the resolve graph
/// records the edge but no matching declaration was found — callers must
/// treat that edge as indeterminate rather than unconstrained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataRequirementEdge {
    parent: ExactCrateSpec,
    parent_is_workspace_member: bool,
    requirement: Option<String>,
    kind: Option<String>,
}

impl MetadataRequirementEdge {
    pub fn parent(&self) -> &ExactCrateSpec {
        &self.parent
    }

    pub fn parent_is_workspace_member(&self) -> bool {
        self.parent_is_workspace_member
    }

    pub fn requirement(&self) -> Option<&str> {
        self.requirement.as_deref()
    }

    pub fn kind(&self) -> Option<&str> {
        self.kind.as_deref()
    }
}

/// Collects every requirement edge onto the exact target package: all
/// resolved parents, not only the shortest-path one, because the parent that
/// caps a vulnerable crate is not necessarily the parent on the shortest
/// dependency path.
pub fn requirement_edges_onto(
    metadata: &CargoMetadata,
    target: &ExactCrateSpec,
) -> Result<Vec<MetadataRequirementEdge>, CargoMetadataError> {
    let resolve = metadata
        .resolve
        .as_ref()
        .ok_or(CargoMetadataError::MissingResolveGraph)?;
    let packages_by_id = metadata.packages_by_id();
    let target_ids = metadata
        .packages
        .iter()
        .filter(|package| {
            package.name == target.crate_name() && package.version == target.version()
        })
        .map(|package| package.id.as_str())
        .collect::<BTreeSet<_>>();
    if target_ids.is_empty() {
        return Ok(Vec::new());
    }

    let workspace_members = metadata.workspace_member_ids();
    let mut edges = Vec::new();
    for node in &resolve.nodes {
        if !node
            .deps
            .iter()
            .any(|dependency| target_ids.contains(dependency.pkg.as_str()))
        {
            continue;
        }
        let parent = packages_by_id.get(node.id.as_str()).ok_or_else(|| {
            CargoMetadataError::UnknownPackageId {
                package_id: node.id.clone(),
            }
        })?;
        let parent_spec =
            ExactCrateSpec::from_parts(&parent.name, &parent.version).map_err(|source| {
                CargoMetadataError::InvalidPackageSpec {
                    package_id: node.id.clone(),
                    source,
                }
            })?;
        let parent_is_workspace_member = workspace_members.contains(node.id.as_str());
        let declarations = parent
            .dependencies
            .iter()
            .filter(|declaration| {
                dependency_name_matches_package(&declaration.name, target.crate_name())
            })
            .collect::<Vec<_>>();
        if declarations.is_empty() {
            edges.push(MetadataRequirementEdge {
                parent: parent_spec,
                parent_is_workspace_member,
                requirement: None,
                kind: None,
            });
            continue;
        }
        for declaration in declarations {
            edges.push(MetadataRequirementEdge {
                parent: parent_spec.clone(),
                parent_is_workspace_member,
                requirement: declaration.req.clone(),
                kind: declaration.kind.clone(),
            });
        }
    }

    edges.sort_by(|left, right| {
        (left.parent(), left.requirement()).cmp(&(right.parent(), right.requirement()))
    });
    Ok(edges)
}

fn metadata_dependency_path(
    packages_by_id: &BTreeMap<&str, &MetadataPackage>,
    package_ids: &[&str],
) -> Result<MetadataDependencyPath, CargoMetadataError> {
    let packages = package_ids
        .iter()
        .map(|package_id| {
            let package = packages_by_id.get(package_id).ok_or_else(|| {
                CargoMetadataError::UnknownPackageId {
                    package_id: (*package_id).to_owned(),
                }
            })?;
            ExactCrateSpec::from_parts(&package.name, &package.version).map_err(|source| {
                CargoMetadataError::InvalidPackageSpec {
                    package_id: (*package_id).to_owned(),
                    source,
                }
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(MetadataDependencyPath { packages })
}

pub(crate) fn metadata_packages(
    metadata: &CargoMetadata,
) -> impl Iterator<Item = MetadataPackageInfo<'_>> {
    let workspace_members = metadata.workspace_member_ids();

    metadata
        .packages
        .iter()
        .map(move |package| MetadataPackageInfo {
            name: package.name.as_str(),
            version: package.version.as_str(),
            is_workspace_member: workspace_members.contains(package.id.as_str()),
            surfaces: MetadataPackageSurfaces::from_package(package),
        })
}

fn package_has_build_rs(package: &MetadataPackage) -> bool {
    package
        .targets
        .iter()
        .any(|target| target.kind.iter().any(|kind| kind == "custom-build"))
}

fn package_is_proc_macro(package: &MetadataPackage) -> bool {
    package
        .targets
        .iter()
        .any(|target| target.kind.iter().any(|kind| kind == "proc-macro"))
}

fn dependency_name_matches_package(dependency_name: &str, package_name: &str) -> bool {
    dependency_name.replace('_', "-") == package_name.replace('_', "-")
}

#[derive(Debug, Error)]
pub enum CargoMetadataError {
    #[error("unable to parse cargo metadata JSON: {0}")]
    Parse(#[source] serde_json::Error),
    #[error("cargo metadata did not include a resolve graph")]
    MissingResolveGraph,
    #[error("{crate_name}: crate not found in cargo metadata")]
    CrateNotFound { crate_name: String },
    #[error(
        "{crate_name}: multiple package IDs exist and no workspace direct dependency was found: {package_ids:?}"
    )]
    NoWorkspaceDirectDependency {
        crate_name: String,
        package_ids: Vec<String>,
    },
    #[error("{crate_name}: multiple workspace direct dependency versions found: {package_ids:?}")]
    MultipleWorkspaceDirectDependencies {
        crate_name: String,
        package_ids: Vec<String>,
    },
    #[error("{crate_name}@{version}: package version not found in cargo metadata")]
    PackageVersionNotFound { crate_name: String, version: String },
    #[error("cargo metadata resolve graph referenced unknown package id {package_id:?}")]
    UnknownPackageId { package_id: String },
    #[error("cargo metadata package {package_id:?} is not an exact crate spec: {source}")]
    InvalidPackageSpec {
        package_id: String,
        #[source]
        source: crate::ExactCrateSpecError,
    },
    #[error("workspace package {package_id:?} is absent from Cargo.lock")]
    LockedWorkspacePackageNotFound { package_id: String },
    #[error("workspace package {package_id:?} has an ambiguous Cargo.lock identity")]
    AmbiguousLockedWorkspacePackage { package_id: String },
    #[error(
        "workspace package {package_id:?} direct dependency names differ between cargo metadata and Cargo.lock: declared={declared:?}, locked={locked:?}"
    )]
    LockedDirectDependencySetMismatch {
        package_id: String,
        declared: Vec<String>,
        locked: Vec<String>,
    },
    #[error(
        "workspace package {package_id:?} declares {dependency_name:?} {requirement:?}, but no matching direct Cargo.lock edge exists"
    )]
    LockedDirectDependencyNotFound {
        package_id: String,
        dependency_name: String,
        requirement: Option<String>,
    },
    #[error(
        "workspace package {package_id:?} declares {dependency_name:?} {requirement:?}, but its direct Cargo.lock edge is ambiguous: {candidates:?}"
    )]
    AmbiguousLockedDirectDependency {
        package_id: String,
        dependency_name: String,
        requirement: Option<String>,
        candidates: Vec<String>,
    },
    #[error(
        "workspace package {package_id:?} has invalid requirement for {dependency_name:?}: {source}"
    )]
    InvalidDependencyRequirement {
        package_id: String,
        dependency_name: String,
        #[source]
        source: semver::Error,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataDependencyPath {
    packages: Vec<ExactCrateSpec>,
}

impl MetadataDependencyPath {
    pub fn packages(&self) -> &[ExactCrateSpec] {
        &self.packages
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataPackageSurfaces {
    pub has_build_rs: bool,
    pub is_proc_macro: bool,
    pub has_native_links: bool,
}

impl MetadataPackageSurfaces {
    pub(crate) fn union_with(&mut self, other: &Self) {
        self.has_build_rs |= other.has_build_rs;
        self.is_proc_macro |= other.is_proc_macro;
        self.has_native_links |= other.has_native_links;
    }

    pub(crate) fn surface_kinds(&self, spec: &ExactCrateSpec) -> Vec<ExecutionSurfaceKind> {
        let mut kinds = Vec::new();
        if self.has_build_rs {
            kinds.push(ExecutionSurfaceKind::BuildRs);
        }
        if self.is_proc_macro {
            kinds.push(ExecutionSurfaceKind::ProcMacro);
        }
        if is_native_sys_execution_surface(spec.is_native_sys(), self.has_native_links) {
            kinds.push(ExecutionSurfaceKind::NativeSys);
        }

        kinds
    }

    fn from_package(package: &MetadataPackage) -> Self {
        Self {
            has_build_rs: package_has_build_rs(package),
            is_proc_macro: package_is_proc_macro(package),
            has_native_links: package.links.is_some(),
        }
    }
}

pub(crate) struct MetadataPackageInfo<'a> {
    pub(crate) name: &'a str,
    pub(crate) version: &'a str,
    pub(crate) is_workspace_member: bool,
    pub(crate) surfaces: MetadataPackageSurfaces,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MetadataPackage {
    name: String,
    id: String,
    version: String,
    source: Option<String>,
    manifest_path: Option<String>,
    links: Option<String>,
    targets: Vec<MetadataTarget>,
    dependencies: Vec<MetadataDependencyDeclaration>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MetadataDependencyDeclaration {
    name: String,
    req: Option<String>,
    kind: Option<String>,
    source: Option<String>,
    path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MetadataResolve {
    nodes: Vec<MetadataNode>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MetadataNode {
    id: String,
    deps: Vec<MetadataDependency>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MetadataDependency {
    name: String,
    pkg: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MetadataTarget {
    kind: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawCargoMetadata {
    #[serde(default)]
    packages: Vec<RawMetadataPackage>,
    #[serde(default)]
    workspace_members: Vec<String>,
    resolve: Option<RawMetadataResolve>,
}

#[derive(Debug, Deserialize)]
struct RawMetadataPackage {
    name: String,
    id: String,
    version: String,
    source: Option<String>,
    manifest_path: Option<String>,
    links: Option<String>,
    #[serde(default)]
    targets: Vec<RawMetadataTarget>,
    #[serde(default)]
    dependencies: Vec<RawMetadataDependencyDeclaration>,
}

#[derive(Debug, Deserialize)]
struct RawMetadataDependencyDeclaration {
    name: String,
    req: Option<String>,
    #[serde(default)]
    kind: Option<String>,
    source: Option<String>,
    path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawMetadataTarget {
    #[serde(default)]
    kind: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawMetadataResolve {
    #[serde(default)]
    nodes: Vec<RawMetadataNode>,
}

#[derive(Debug, Deserialize)]
struct RawMetadataNode {
    id: String,
    #[serde(default)]
    deps: Vec<RawMetadataDependency>,
}

#[derive(Debug, Deserialize)]
struct RawMetadataDependency {
    name: String,
    pkg: String,
}

#[cfg(test)]
mod tests {
    use crate::{ExactCrateSpec, parse_lockfile};

    use super::{
        CargoMetadataError, package_surfaces, parse_cargo_metadata, requirement_edges_onto,
        select_package_id, shortest_workspace_dependency_path, workspace_direct_dependencies,
    };

    #[test]
    fn resolves_declared_workspace_dependencies_through_lock_edges() {
        let metadata = parse_cargo_metadata(
            r#"{
  "packages": [
    {"name":"root","id":"path+file:///repo#root@0.1.0","version":"0.1.0","source":null,"manifest_path":"/repo/Cargo.toml","targets":[],"dependencies":[
      {"name":"real","rename":"alias","req":"=1.0.0","kind":null,"optional":true,"source":"registry+https://github.com/rust-lang/crates.io-index"},
      {"name":"external","rename":"external_alias","req":"*","kind":"dev","optional":false,"source":null,"path":"/outside"},
      {"name":"gitdep","req":"*","kind":null,"optional":false,"source":"git+https://example.invalid/gitdep?rev=main"},
      {"name":"member","req":"*","kind":"build","optional":false,"source":null,"path":"/repo/member"}
    ]},
    {"name":"real","id":"registry+https://github.com/rust-lang/crates.io-index#real@1.0.0","version":"1.0.0","source":"registry+https://github.com/rust-lang/crates.io-index","targets":[]},
    {"name":"real","id":"registry+https://github.com/rust-lang/crates.io-index#real@2.0.0","version":"2.0.0","source":"registry+https://github.com/rust-lang/crates.io-index","targets":[]},
    {"name":"external","id":"path+file:///outside#external@3.0.0","version":"3.0.0","source":null,"targets":[]},
    {"name":"member","id":"path+file:///repo/member#member@0.1.0","version":"0.1.0","source":null,"manifest_path":"/repo/member/Cargo.toml","targets":[]}
  ],
  "workspace_members": [
    "path+file:///repo#root@0.1.0",
    "path+file:///repo/member#member@0.1.0"
  ],
  "resolve": {"nodes":[
    {"id":"path+file:///repo#root@0.1.0","deps":[
      {"name":"external_alias","pkg":"path+file:///outside#external@3.0.0"},
      {"name":"member","pkg":"path+file:///repo/member#member@0.1.0"}
    ]},
    {"id":"registry+https://github.com/rust-lang/crates.io-index#real@1.0.0","deps":[
      {"name":"real","pkg":"registry+https://github.com/rust-lang/crates.io-index#real@2.0.0"}
    ]},
    {"id":"registry+https://github.com/rust-lang/crates.io-index#real@2.0.0","deps":[]},
    {"id":"path+file:///outside#external@3.0.0","deps":[]},
    {"id":"path+file:///repo/member#member@0.1.0","deps":[]}
  ]}
}"#,
        )
        .expect("metadata should parse");
        let lockfile = parse_lockfile(
            r#"
[[package]]
name = "root"
version = "0.1.0"
dependencies = [
 "real 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)",
 "external",
 "gitdep 4.0.0 (git+https://example.invalid/gitdep?rev=main#0123456789abcdef)",
 "member",
]

[[package]]
name = "real"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = ["real 2.0.0 (registry+https://github.com/rust-lang/crates.io-index)"]

[[package]]
name = "real"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "external"
version = "3.0.0"

[[package]]
name = "gitdep"
version = "4.0.0"
source = "git+https://example.invalid/gitdep?rev=main#0123456789abcdef"

[[package]]
name = "member"
version = "0.1.0"
"#,
        )
        .expect("lockfile should parse");

        let dependencies = workspace_direct_dependencies(&metadata, &lockfile)
            .expect("direct dependencies should resolve");
        let facts = dependencies
            .iter()
            .map(|dependency| {
                (
                    dependency.spec().to_string(),
                    dependency.source().map(str::to_owned),
                    dependency.is_workspace_member(),
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(
            facts,
            vec![
                ("external@3.0.0".to_owned(), None, false),
                (
                    "gitdep@4.0.0".to_owned(),
                    Some("git+https://example.invalid/gitdep?rev=main#0123456789abcdef".to_owned(),),
                    false,
                ),
                ("member@0.1.0".to_owned(), None, true),
                (
                    "real@1.0.0".to_owned(),
                    Some("registry+https://github.com/rust-lang/crates.io-index".to_owned()),
                    false,
                ),
            ]
        );
    }

    #[test]
    fn git_source_matching_preserves_repository_and_query_identity() {
        assert!(crate::lockfile::resolved_sources_match(
            "git+https://example.invalid/repo?rev=main",
            "git+https://example.invalid/repo?rev=main#0123456789abcdef",
        ));
        assert!(!crate::lockfile::resolved_sources_match(
            "git+https://example.invalid/repo?rev=main",
            "git+https://example.invalid/other?rev=main#0123456789abcdef",
        ));
        assert!(!crate::lockfile::resolved_sources_match(
            "git+https://example.invalid/repo?branch=main",
            "git+https://example.invalid/repo?rev=main#0123456789abcdef",
        ));
    }

    #[test]
    fn resolves_patched_registry_and_versionless_prerelease_dependencies() {
        let metadata = parse_cargo_metadata(
            r#"{
  "packages":[
    {"name":"root","id":"path+file:///repo#root@0.1.0","version":"0.1.0","source":null,"manifest_path":"/repo/Cargo.toml","targets":[],"dependencies":[
      {"name":"patched","req":"=1.0.0","kind":null,"optional":false,"source":"registry+https://github.com/rust-lang/crates.io-index"},
      {"name":"gitdev","req":"*","kind":null,"optional":false,"source":"git+https://example.invalid/gitdev"},
      {"name":"pathdev","req":"*","kind":null,"optional":false,"source":null,"path":"/outside/pathdev"}
    ]},
    {"name":"patched","id":"git+https://example.invalid/patched#1.0.0","version":"1.0.0","source":"git+https://example.invalid/patched#aaaaaaaa","targets":[]},
    {"name":"gitdev","id":"git+https://example.invalid/gitdev#0.15.0-dev","version":"0.15.0-dev","source":"git+https://example.invalid/gitdev#bbbbbbbb","targets":[]},
    {"name":"pathdev","id":"path+file:///outside/pathdev#0.2.0-dev","version":"0.2.0-dev","source":null,"targets":[]}
  ],
  "workspace_members":["path+file:///repo#root@0.1.0"],
  "resolve":{"nodes":[]}
}"#,
        )
        .expect("metadata should parse");
        let lockfile = parse_lockfile(
            r#"
version = 4

[[package]]
name = "root"
version = "0.1.0"
dependencies = [
  "patched 1.0.0 (git+https://example.invalid/patched)",
  "gitdev 0.15.0-dev (git+https://example.invalid/gitdev)",
  "pathdev",
]

[[package]]
name = "patched"
version = "1.0.0"
source = "git+https://example.invalid/patched#aaaaaaaa"

[[package]]
name = "gitdev"
version = "0.15.0-dev"
source = "git+https://example.invalid/gitdev#bbbbbbbb"

[[package]]
name = "pathdev"
version = "0.2.0-dev"
"#,
        )
        .expect("lockfile should parse");

        let dependencies = workspace_direct_dependencies(&metadata, &lockfile)
            .expect("Cargo-selected patch and prerelease edges should resolve");
        assert_eq!(
            dependencies
                .iter()
                .map(|dependency| dependency.spec().to_string())
                .collect::<Vec<_>>(),
            vec!["gitdev@0.15.0-dev", "patched@1.0.0", "pathdev@0.2.0-dev"]
        );
        assert!(
            dependencies
                .iter()
                .all(|dependency| !dependency.is_crates_io())
        );
    }

    #[test]
    fn handles_source_replacements_and_rejects_missing_or_ambiguous_lock_mappings() {
        let missing_metadata = parse_cargo_metadata(
            r#"{
  "packages":[
    {"name":"root","id":"path+file:///repo#root@0.1.0","version":"0.1.0","source":null,"manifest_path":"/repo/Cargo.toml","targets":[],"dependencies":[
      {"name":"foo","req":"^1","kind":null,"optional":false,"source":"registry+https://github.com/rust-lang/crates.io-index"}
    ]}
  ],
  "workspace_members":["path+file:///repo#root@0.1.0"],
  "resolve":{"nodes":[]}
}"#,
        )
        .expect("metadata should parse");
        let missing_lockfile = parse_lockfile(
            r#"
version = 4

[[package]]
name = "root"
version = "0.1.0"
dependencies = ["foo 1.0.0 (registry+https://example.invalid/private)"]

[[package]]
name = "foo"
version = "1.0.0"
source = "registry+https://example.invalid/private"
"#,
        )
        .expect("lockfile should parse");
        let replaced = workspace_direct_dependencies(&missing_metadata, &missing_lockfile)
            .expect("Cargo-selected source replacement should remain visible");
        assert_eq!(replaced.len(), 1);
        assert_eq!(
            replaced[0].source(),
            Some("registry+https://example.invalid/private")
        );

        let path_metadata = parse_cargo_metadata(
            r#"{
  "packages":[
    {"name":"root","id":"path+file:///repo#root@0.1.0","version":"0.1.0","source":null,"manifest_path":"/repo/Cargo.toml","targets":[],"dependencies":[
      {"name":"foo","req":"^1","kind":null,"optional":false,"source":null,"path":"/outside/foo"}
    ]}
  ],
  "workspace_members":["path+file:///repo#root@0.1.0"],
  "resolve":{"nodes":[]}
}"#,
        )
        .expect("metadata should parse");
        assert!(matches!(
            workspace_direct_dependencies(&path_metadata, &missing_lockfile),
            Err(CargoMetadataError::LockedDirectDependencyNotFound { .. })
        ));

        let ambiguous_metadata = parse_cargo_metadata(
            r#"{
  "packages":[
    {"name":"root","id":"path+file:///repo#root@0.1.0","version":"0.1.0","source":null,"manifest_path":"/repo/Cargo.toml","targets":[],"dependencies":[
      {"name":"foo","req":">=1","kind":null,"optional":false,"source":"registry+https://github.com/rust-lang/crates.io-index"}
    ]}
  ],
  "workspace_members":["path+file:///repo#root@0.1.0"],
  "resolve":{"nodes":[]}
}"#,
        )
        .expect("metadata should parse");
        let ambiguous_lockfile = parse_lockfile(
            r#"
version = 4

[[package]]
name = "root"
version = "0.1.0"
dependencies = [
  "foo 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)",
  "foo 2.0.0 (registry+https://github.com/rust-lang/crates.io-index)",
]

[[package]]
name = "foo"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "foo"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
        )
        .expect("lockfile should parse");
        assert!(matches!(
            workspace_direct_dependencies(&ambiguous_metadata, &ambiguous_lockfile),
            Err(CargoMetadataError::AmbiguousLockedDirectDependency { .. })
        ));
    }

    #[test]
    fn selects_the_only_matching_package_id() {
        let metadata = parse_cargo_metadata(
            r#"{
  "packages": [
    {
      "name": "serde",
      "id": "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228",
      "version": "1.0.228",
      "targets": []
    }
  ],
  "workspace_members": [],
  "resolve": null
}"#,
        )
        .expect("metadata should parse");

        let package_id = select_package_id(&metadata, "serde").expect("selection should succeed");

        assert_eq!(
            package_id,
            "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228"
        );
    }

    #[test]
    fn disambiguates_multiple_versions_via_workspace_direct_dependency() {
        let metadata = parse_cargo_metadata(
            r#"{
  "packages": [
    {"name": "root", "id": "path+file:///repo#root@0.1.0", "version": "0.1.0", "targets": []},
    {"name": "serde", "id": "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228", "version": "1.0.228", "targets": []},
    {"name": "serde", "id": "registry+https://github.com/rust-lang/crates.io-index#serde@0.9.15", "version": "0.9.15", "targets": []}
  ],
  "workspace_members": ["path+file:///repo#root@0.1.0"],
  "resolve": {
    "nodes": [
      {
        "id": "path+file:///repo#root@0.1.0",
        "deps": [
          {
            "name": "serde",
            "pkg": "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228"
          }
        ]
      }
    ]
  }
}"#,
        )
        .expect("metadata should parse");

        let package_id = select_package_id(&metadata, "serde").expect("selection should succeed");

        assert_eq!(
            package_id,
            "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228"
        );
    }

    #[test]
    fn finds_shortest_workspace_dependency_path_to_package_version() {
        let metadata = parse_cargo_metadata(
            r#"{
  "packages": [
    {"name": "root", "id": "path+file:///repo#root@0.1.0", "version": "0.1.0", "targets": []},
    {"name": "mid", "id": "registry+https://github.com/rust-lang/crates.io-index#mid@1.0.0", "version": "1.0.0", "targets": []},
    {"name": "leaf", "id": "registry+https://github.com/rust-lang/crates.io-index#leaf@2.0.0", "version": "2.0.0", "targets": []}
  ],
  "workspace_members": ["path+file:///repo#root@0.1.0"],
  "resolve": {
    "nodes": [
      {
        "id": "path+file:///repo#root@0.1.0",
        "deps": [{"name": "mid", "pkg": "registry+https://github.com/rust-lang/crates.io-index#mid@1.0.0"}]
      },
      {
        "id": "registry+https://github.com/rust-lang/crates.io-index#mid@1.0.0",
        "deps": [{"name": "leaf", "pkg": "registry+https://github.com/rust-lang/crates.io-index#leaf@2.0.0"}]
      },
      {
        "id": "registry+https://github.com/rust-lang/crates.io-index#leaf@2.0.0",
        "deps": []
      }
    ]
  }
}"#,
        )
        .expect("metadata should parse");
        let target = ExactCrateSpec::from_parts("leaf", "2.0.0").expect("target should parse");

        let path = shortest_workspace_dependency_path(&metadata, &target)
            .expect("path computation should succeed")
            .expect("target should be reachable");

        assert_eq!(
            path.packages()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            vec![
                "root@0.1.0".to_owned(),
                "mid@1.0.0".to_owned(),
                "leaf@2.0.0".to_owned(),
            ]
        );
    }

    #[test]
    fn requirement_edges_capture_declared_requirements_from_all_resolved_parents() {
        let metadata = parse_cargo_metadata(
            r#"{
  "packages": [
    {"name": "root", "id": "path+file:///repo#root@0.1.0", "version": "0.1.0", "targets": [],
     "dependencies": [{"name": "quick-xml", "req": "^0.39", "kind": "dev"}]},
    {"name": "plist", "id": "registry+https://github.com/rust-lang/crates.io-index#plist@1.9.0", "version": "1.9.0", "targets": [],
     "dependencies": [{"name": "quick-xml", "req": ">=0.39, <0.40"}]},
    {"name": "undeclared-parent", "id": "registry+https://github.com/rust-lang/crates.io-index#undeclared-parent@0.2.0", "version": "0.2.0", "targets": []},
    {"name": "quick-xml", "id": "registry+https://github.com/rust-lang/crates.io-index#quick-xml@0.39.4", "version": "0.39.4", "targets": []}
  ],
  "workspace_members": ["path+file:///repo#root@0.1.0"],
  "resolve": {
    "nodes": [
      {"id": "path+file:///repo#root@0.1.0", "deps": [
        {"name": "quick_xml", "pkg": "registry+https://github.com/rust-lang/crates.io-index#quick-xml@0.39.4"},
        {"name": "plist", "pkg": "registry+https://github.com/rust-lang/crates.io-index#plist@1.9.0"}
      ]},
      {"id": "registry+https://github.com/rust-lang/crates.io-index#plist@1.9.0", "deps": [
        {"name": "quick_xml", "pkg": "registry+https://github.com/rust-lang/crates.io-index#quick-xml@0.39.4"}
      ]},
      {"id": "registry+https://github.com/rust-lang/crates.io-index#undeclared-parent@0.2.0", "deps": [
        {"name": "quick_xml", "pkg": "registry+https://github.com/rust-lang/crates.io-index#quick-xml@0.39.4"}
      ]},
      {"id": "registry+https://github.com/rust-lang/crates.io-index#quick-xml@0.39.4", "deps": []}
    ]
  }
}"#,
        )
        .expect("metadata should parse");
        let target =
            ExactCrateSpec::from_parts("quick-xml", "0.39.4").expect("target should parse");

        let edges = requirement_edges_onto(&metadata, &target).expect("edges should collect");

        assert_eq!(edges.len(), 3);
        assert_eq!(edges[0].parent().to_string(), "plist@1.9.0");
        assert!(!edges[0].parent_is_workspace_member());
        assert_eq!(edges[0].requirement(), Some(">=0.39, <0.40"));
        assert_eq!(edges[0].kind(), None);
        assert_eq!(edges[1].parent().to_string(), "root@0.1.0");
        assert!(edges[1].parent_is_workspace_member());
        assert_eq!(edges[1].requirement(), Some("^0.39"));
        assert_eq!(edges[1].kind(), Some("dev"));
        assert_eq!(edges[2].parent().to_string(), "undeclared-parent@0.2.0");
        assert_eq!(
            edges[2].requirement(),
            None,
            "a resolve edge with no matching declaration must stay indeterminate, not unconstrained"
        );
    }

    #[test]
    fn requirement_edges_require_a_resolve_graph() {
        let metadata = parse_cargo_metadata(
            r#"{
  "packages": [
    {"name": "quick-xml", "id": "registry+https://github.com/rust-lang/crates.io-index#quick-xml@0.39.4", "version": "0.39.4", "targets": []}
  ],
  "workspace_members": [],
  "resolve": null
}"#,
        )
        .expect("metadata should parse");
        let target =
            ExactCrateSpec::from_parts("quick-xml", "0.39.4").expect("target should parse");

        assert!(matches!(
            requirement_edges_onto(&metadata, &target),
            Err(CargoMetadataError::MissingResolveGraph)
        ));
    }

    #[test]
    fn dependency_path_prefers_the_shorter_route_in_a_diamond_graph() {
        let metadata = parse_cargo_metadata(
            r#"{
  "packages": [
    {"name": "root", "id": "path+file:///repo#root@0.1.0", "version": "0.1.0", "targets": []},
    {"name": "short", "id": "registry+https://github.com/rust-lang/crates.io-index#short@1.0.0", "version": "1.0.0", "targets": []},
    {"name": "long-a", "id": "registry+https://github.com/rust-lang/crates.io-index#long-a@1.0.0", "version": "1.0.0", "targets": []},
    {"name": "long-b", "id": "registry+https://github.com/rust-lang/crates.io-index#long-b@1.0.0", "version": "1.0.0", "targets": []},
    {"name": "leaf", "id": "registry+https://github.com/rust-lang/crates.io-index#leaf@2.0.0", "version": "2.0.0", "targets": []}
  ],
  "workspace_members": ["path+file:///repo#root@0.1.0"],
  "resolve": {
    "nodes": [
      {
        "id": "path+file:///repo#root@0.1.0",
        "deps": [
          {"name": "long_a", "pkg": "registry+https://github.com/rust-lang/crates.io-index#long-a@1.0.0"},
          {"name": "short", "pkg": "registry+https://github.com/rust-lang/crates.io-index#short@1.0.0"}
        ]
      },
      {
        "id": "registry+https://github.com/rust-lang/crates.io-index#short@1.0.0",
        "deps": [{"name": "leaf", "pkg": "registry+https://github.com/rust-lang/crates.io-index#leaf@2.0.0"}]
      },
      {
        "id": "registry+https://github.com/rust-lang/crates.io-index#long-a@1.0.0",
        "deps": [{"name": "long_b", "pkg": "registry+https://github.com/rust-lang/crates.io-index#long-b@1.0.0"}]
      },
      {
        "id": "registry+https://github.com/rust-lang/crates.io-index#long-b@1.0.0",
        "deps": [{"name": "leaf", "pkg": "registry+https://github.com/rust-lang/crates.io-index#leaf@2.0.0"}]
      },
      {
        "id": "registry+https://github.com/rust-lang/crates.io-index#leaf@2.0.0",
        "deps": []
      }
    ]
  }
}"#,
        )
        .expect("metadata should parse");
        let target = ExactCrateSpec::from_parts("leaf", "2.0.0").expect("target should parse");

        let path = shortest_workspace_dependency_path(&metadata, &target)
            .expect("path computation should succeed")
            .expect("target should be reachable");

        assert_eq!(
            path.packages()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            vec![
                "root@0.1.0".to_owned(),
                "short@1.0.0".to_owned(),
                "leaf@2.0.0".to_owned(),
            ]
        );
    }

    #[test]
    fn dependency_path_starts_from_the_nearest_workspace_member() {
        let metadata = parse_cargo_metadata(
            r#"{
  "packages": [
    {"name": "member-far", "id": "path+file:///repo#member-far@0.1.0", "version": "0.1.0", "targets": []},
    {"name": "member-near", "id": "path+file:///repo#member-near@0.1.0", "version": "0.1.0", "targets": []},
    {"name": "mid", "id": "registry+https://github.com/rust-lang/crates.io-index#mid@1.0.0", "version": "1.0.0", "targets": []},
    {"name": "leaf", "id": "registry+https://github.com/rust-lang/crates.io-index#leaf@2.0.0", "version": "2.0.0", "targets": []}
  ],
  "workspace_members": [
    "path+file:///repo#member-far@0.1.0",
    "path+file:///repo#member-near@0.1.0"
  ],
  "resolve": {
    "nodes": [
      {
        "id": "path+file:///repo#member-far@0.1.0",
        "deps": [{"name": "mid", "pkg": "registry+https://github.com/rust-lang/crates.io-index#mid@1.0.0"}]
      },
      {
        "id": "path+file:///repo#member-near@0.1.0",
        "deps": [{"name": "leaf", "pkg": "registry+https://github.com/rust-lang/crates.io-index#leaf@2.0.0"}]
      },
      {
        "id": "registry+https://github.com/rust-lang/crates.io-index#mid@1.0.0",
        "deps": [{"name": "leaf", "pkg": "registry+https://github.com/rust-lang/crates.io-index#leaf@2.0.0"}]
      },
      {
        "id": "registry+https://github.com/rust-lang/crates.io-index#leaf@2.0.0",
        "deps": []
      }
    ]
  }
}"#,
        )
        .expect("metadata should parse");
        let target = ExactCrateSpec::from_parts("leaf", "2.0.0").expect("target should parse");

        let path = shortest_workspace_dependency_path(&metadata, &target)
            .expect("path computation should succeed")
            .expect("target should be reachable");

        assert_eq!(
            path.packages()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            vec!["member-near@0.1.0".to_owned(), "leaf@2.0.0".to_owned()]
        );
    }

    #[test]
    fn dependency_path_terminates_on_cyclic_resolve_graphs() {
        let metadata = parse_cargo_metadata(
            r#"{
  "packages": [
    {"name": "root", "id": "path+file:///repo#root@0.1.0", "version": "0.1.0", "targets": []},
    {"name": "cycle-a", "id": "registry+https://github.com/rust-lang/crates.io-index#cycle-a@1.0.0", "version": "1.0.0", "targets": []},
    {"name": "cycle-b", "id": "registry+https://github.com/rust-lang/crates.io-index#cycle-b@1.0.0", "version": "1.0.0", "targets": []}
  ],
  "workspace_members": ["path+file:///repo#root@0.1.0"],
  "resolve": {
    "nodes": [
      {
        "id": "path+file:///repo#root@0.1.0",
        "deps": [{"name": "cycle_a", "pkg": "registry+https://github.com/rust-lang/crates.io-index#cycle-a@1.0.0"}]
      },
      {
        "id": "registry+https://github.com/rust-lang/crates.io-index#cycle-a@1.0.0",
        "deps": [{"name": "cycle_b", "pkg": "registry+https://github.com/rust-lang/crates.io-index#cycle-b@1.0.0"}]
      },
      {
        "id": "registry+https://github.com/rust-lang/crates.io-index#cycle-b@1.0.0",
        "deps": [{"name": "cycle_a", "pkg": "registry+https://github.com/rust-lang/crates.io-index#cycle-a@1.0.0"}]
      }
    ]
  }
}"#,
        )
        .expect("metadata should parse");
        let target = ExactCrateSpec::from_parts("leaf", "2.0.0").expect("target should parse");

        assert_eq!(
            shortest_workspace_dependency_path(&metadata, &target)
                .expect("path computation should terminate"),
            None
        );
    }

    #[test]
    fn dependency_path_is_none_when_target_package_is_absent() {
        let metadata = parse_cargo_metadata(
            r#"{
  "packages": [
    {"name": "root", "id": "path+file:///repo#root@0.1.0", "version": "0.1.0", "targets": []}
  ],
  "workspace_members": ["path+file:///repo#root@0.1.0"],
  "resolve": {
    "nodes": [
      {"id": "path+file:///repo#root@0.1.0", "deps": []}
    ]
  }
}"#,
        )
        .expect("metadata should parse");
        let target = ExactCrateSpec::from_parts("leaf", "2.0.0").expect("target should parse");

        assert_eq!(
            shortest_workspace_dependency_path(&metadata, &target)
                .expect("path computation should succeed"),
            None
        );
    }

    #[test]
    fn disambiguates_dash_named_packages_from_underscore_dependency_names() {
        let metadata = parse_cargo_metadata(
            r#"{
  "packages": [
    {"name": "root", "id": "path+file:///repo#root@0.1.0", "version": "0.1.0", "targets": []},
    {"name": "windows-sys", "id": "registry+https://github.com/rust-lang/crates.io-index#windows-sys@0.61.0", "version": "0.61.0", "targets": []},
    {"name": "windows-sys", "id": "registry+https://github.com/rust-lang/crates.io-index#windows-sys@0.60.2", "version": "0.60.2", "targets": []}
  ],
  "workspace_members": ["path+file:///repo#root@0.1.0"],
  "resolve": {
    "nodes": [
      {
        "id": "path+file:///repo#root@0.1.0",
        "deps": [
          {
            "name": "windows_sys",
            "pkg": "registry+https://github.com/rust-lang/crates.io-index#windows-sys@0.61.0"
          }
        ]
      }
    ]
  }
}"#,
        )
        .expect("metadata should parse");

        let package_id =
            select_package_id(&metadata, "windows-sys").expect("selection should succeed");

        assert_eq!(
            package_id,
            "registry+https://github.com/rust-lang/crates.io-index#windows-sys@0.61.0"
        );
    }

    #[test]
    fn errors_when_multiple_versions_exist_without_workspace_direct_dependency() {
        let metadata = parse_cargo_metadata(
            r#"{
  "packages": [
    {"name": "serde", "id": "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228", "version": "1.0.228", "targets": []},
    {"name": "serde", "id": "registry+https://github.com/rust-lang/crates.io-index#serde@0.9.15", "version": "0.9.15", "targets": []}
  ],
  "workspace_members": ["path+file:///repo#root@0.1.0"],
  "resolve": {
    "nodes": [
      {
        "id": "path+file:///repo#root@0.1.0",
        "deps": []
      }
    ]
  }
}"#,
        )
        .expect("metadata should parse");

        let error = select_package_id(&metadata, "serde").expect_err("selection should fail");

        assert!(matches!(
            error,
            CargoMetadataError::NoWorkspaceDirectDependency { .. }
        ));
    }

    #[test]
    fn detects_build_rs_proc_macro_and_native_link_surfaces() {
        let metadata = parse_cargo_metadata(
            r#"{
  "packages": [
    {
      "name": "demo",
      "id": "registry+https://github.com/rust-lang/crates.io-index#demo@1.2.3",
      "version": "1.2.3",
      "links": "demo-native",
      "targets": [
        {"kind": ["lib"]},
        {"kind": ["custom-build"]},
        {"kind": ["proc-macro"]}
      ]
    }
  ],
  "workspace_members": [],
  "resolve": null
}"#,
        )
        .expect("metadata should parse");

        let surfaces = package_surfaces(
            &metadata,
            &ExactCrateSpec::from_parts("demo", "1.2.3").expect("spec should build"),
        )
        .expect("surfaces should resolve");

        assert!(surfaces.has_build_rs);
        assert!(surfaces.is_proc_macro);
        assert!(surfaces.has_native_links);
    }

    #[test]
    fn package_surfaces_unions_same_name_version_collisions() {
        let metadata = parse_cargo_metadata(
            r#"{
  "packages": [
    {
      "name": "shadow",
      "id": "git+https://example.invalid/shadow-a#shadow@1.0.0",
      "version": "1.0.0",
      "targets": []
    },
    {
      "name": "shadow",
      "id": "registry+https://github.com/rust-lang/crates.io-index#shadow@1.0.0",
      "version": "1.0.0",
      "targets": [{"kind": ["custom-build"]}]
    },
    {
      "name": "derive-shadow",
      "id": "git+https://example.invalid/derive-shadow-a#derive-shadow@1.0.0",
      "version": "1.0.0",
      "targets": [{"kind": ["proc-macro"]}]
    },
    {
      "name": "derive-shadow",
      "id": "path+file:///workspace/derive-shadow#derive-shadow@1.0.0",
      "version": "1.0.0",
      "links": "derive-shadow-native",
      "targets": []
    }
  ],
  "workspace_members": [],
  "resolve": null
}"#,
        )
        .expect("metadata should parse");

        let build_surfaces = package_surfaces(
            &metadata,
            &ExactCrateSpec::from_parts("shadow", "1.0.0").expect("spec should build"),
        )
        .expect("surfaces should resolve");
        let mixed_surfaces = package_surfaces(
            &metadata,
            &ExactCrateSpec::from_parts("derive-shadow", "1.0.0").expect("spec should build"),
        )
        .expect("surfaces should resolve");

        assert!(build_surfaces.has_build_rs);
        assert!(!build_surfaces.is_proc_macro);
        assert!(!build_surfaces.has_native_links);
        assert!(!mixed_surfaces.has_build_rs);
        assert!(mixed_surfaces.is_proc_macro);
        assert!(mixed_surfaces.has_native_links);
    }

    #[test]
    fn package_surfaces_preserves_single_match_and_zero_match_behaviour() {
        let metadata = parse_cargo_metadata(
            r#"{
  "packages": [
    {
      "name": "demo",
      "id": "registry+https://github.com/rust-lang/crates.io-index#demo@1.2.3",
      "version": "1.2.3",
      "targets": [{"kind": ["custom-build"]}]
    }
  ],
  "workspace_members": [],
  "resolve": null
}"#,
        )
        .expect("metadata should parse");

        let surfaces = package_surfaces(
            &metadata,
            &ExactCrateSpec::from_parts("demo", "1.2.3").expect("spec should build"),
        )
        .expect("surfaces should resolve");
        let error = package_surfaces(
            &metadata,
            &ExactCrateSpec::from_parts("missing", "1.0.0").expect("spec should build"),
        )
        .expect_err("missing package should fail");

        assert!(surfaces.has_build_rs);
        assert!(!surfaces.is_proc_macro);
        assert!(!surfaces.has_native_links);
        assert!(matches!(
            error,
            CargoMetadataError::PackageVersionNotFound { crate_name, version }
                if crate_name == "missing" && version == "1.0.0"
        ));
    }
}
