use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};

use serde::Deserialize;
use thiserror::Error;

use crate::{ExactCrateSpec, ExecutionSurfaceKind, is_native_sys_execution_surface};

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
                links: package.links,
                targets: package
                    .targets
                    .into_iter()
                    .map(|target| MetadataTarget { kind: target.kind })
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
    let packages_by_id = metadata
        .packages
        .iter()
        .map(|package| (package.id.as_str(), package))
        .collect::<BTreeMap<_, _>>();
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
    links: Option<String>,
    targets: Vec<MetadataTarget>,
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
    links: Option<String>,
    #[serde(default)]
    targets: Vec<RawMetadataTarget>,
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
    use crate::ExactCrateSpec;

    use super::{
        CargoMetadataError, package_surfaces, parse_cargo_metadata, select_package_id,
        shortest_workspace_dependency_path,
    };

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
