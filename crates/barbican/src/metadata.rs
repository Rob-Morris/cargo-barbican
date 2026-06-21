use std::collections::{BTreeSet, HashSet};

use serde::Deserialize;
use thiserror::Error;

use crate::{ExactCrateSpec, ExecutionSurfaceKind};

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
    let package = metadata
        .packages
        .iter()
        .find(|package| package.name == spec.crate_name() && package.version == spec.version())
        .ok_or_else(|| CargoMetadataError::PackageVersionNotFound {
            crate_name: spec.crate_name().to_owned(),
            version: spec.version().to_owned(),
        })?;

    Ok(MetadataPackageSurfaces::from_package(package))
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

    pub(crate) fn surface_kinds(&self) -> Vec<ExecutionSurfaceKind> {
        let mut kinds = Vec::new();
        if self.has_build_rs {
            kinds.push(ExecutionSurfaceKind::BuildRs);
        }
        if self.is_proc_macro {
            kinds.push(ExecutionSurfaceKind::ProcMacro);
        }
        if self.has_native_links {
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

    use super::{CargoMetadataError, package_surfaces, parse_cargo_metadata, select_package_id};

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
}
