use std::collections::BTreeSet;
use std::fmt;
use std::path::{Component, Path};

use thiserror::Error;
use toml::Value;

const DEPENDENCY_SECTIONS: [&str; 3] = ["dependencies", "dev-dependencies", "build-dependencies"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CargoDependencySourceKind {
    Registry,
    Workspace,
    Git,
    Path,
    AlternateRegistry,
}

impl CargoDependencySourceKind {
    pub fn is_non_crates_io(self) -> bool {
        matches!(self, Self::Git | Self::Path | Self::AlternateRegistry)
    }

    pub fn requires_exact_pin(self) -> bool {
        matches!(self, Self::Registry | Self::AlternateRegistry)
    }
}

impl fmt::Display for CargoDependencySourceKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Registry => write!(formatter, "registry"),
            Self::Workspace => write!(formatter, "workspace"),
            Self::Git => write!(formatter, "git"),
            Self::Path => write!(formatter, "path"),
            Self::AlternateRegistry => write!(formatter, "alternate-registry"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CargoManifestDependency {
    manifest_path: String,
    section: String,
    name: String,
    source_kind: CargoDependencySourceKind,
}

impl CargoManifestDependency {
    pub fn manifest_path(&self) -> &str {
        &self.manifest_path
    }

    pub fn section(&self) -> &str {
        &self.section
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn source_kind(&self) -> CargoDependencySourceKind {
        self.source_kind
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CargoManifestDirectRequirement {
    manifest_path: String,
    section: String,
    name: String,
    source_kind: CargoDependencySourceKind,
    version_requirement: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CargoManifestPackage {
    manifest_path: String,
    name: String,
    version: String,
}

impl CargoManifestPackage {
    pub fn manifest_path(&self) -> &str {
        &self.manifest_path
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn version(&self) -> &str {
        &self.version
    }
}

impl CargoManifestDirectRequirement {
    pub fn manifest_path(&self) -> &str {
        &self.manifest_path
    }

    pub fn section(&self) -> &str {
        &self.section
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn source_kind(&self) -> CargoDependencySourceKind {
        self.source_kind
    }

    pub fn version_requirement(&self) -> Option<&str> {
        self.version_requirement.as_deref()
    }
}

impl fmt::Display for CargoManifestDependency {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}:{}:{}",
            self.manifest_path, self.section, self.name
        )
    }
}

/// Returns crate names patched under any `[patch.<registry-key>]` table,
/// regardless of which registry key names the patch (`crates-io` or a named
/// alternate registry). `[patch]` repoints an already-resolved crate name at
/// a different source without touching `[dependencies]` or `Cargo.lock`
/// checksums, so reviewed-target enforcement must see patched names even
/// though they are not "dependencies" in the ordinary sense.
pub fn parse_manifest_patched_crate_names(
    manifest_path: &str,
    text: &str,
) -> Result<BTreeSet<String>, CargoManifestError> {
    let root: Value = toml::from_str(text).map_err(CargoManifestError::Parse)?;
    let root_table = root.as_table().ok_or(CargoManifestError::ExpectedTable)?;
    let mut patched = BTreeSet::new();

    let Some(patch_value) = root_table.get("patch") else {
        return Ok(patched);
    };
    let Some(patch_table) = patch_value.as_table() else {
        return Err(CargoManifestError::InvalidDependencySection {
            manifest_path: manifest_path.to_owned(),
            section: "patch".to_owned(),
        });
    };

    for (registry_key, registry_value) in patch_table {
        let Some(registry_table) = registry_value.as_table() else {
            return Err(CargoManifestError::InvalidDependencySection {
                manifest_path: manifest_path.to_owned(),
                section: format!("patch.{registry_key}"),
            });
        };

        for (patch_key, patch_value) in registry_table {
            patched.insert(patch_key.clone());

            let Some(patch_entry_table) = patch_value.as_table() else {
                continue;
            };
            match patch_entry_table.get("package") {
                None => {}
                Some(Value::String(package_name)) => {
                    patched.insert(package_name.clone());
                }
                Some(_) => {
                    return Err(CargoManifestError::InvalidPatchPackageName {
                        manifest_path: manifest_path.to_owned(),
                        section: format!("patch.{registry_key}"),
                        key: patch_key.clone(),
                    });
                }
            }
        }
    }

    Ok(patched)
}

pub fn parse_manifest_dependencies(
    manifest_path: &str,
    text: &str,
) -> Result<BTreeSet<CargoManifestDependency>, CargoManifestError> {
    let root: Value = toml::from_str(text).map_err(CargoManifestError::Parse)?;
    let root_table = root.as_table().ok_or(CargoManifestError::ExpectedTable)?;
    let mut dependencies = BTreeSet::new();

    traverse_manifest_sections(manifest_path, root_table, |section, value| {
        collect_dependency_section(manifest_path, section, value, &mut dependencies)
    })?;

    Ok(dependencies)
}

pub fn parse_manifest_direct_requirements(
    manifest_path: &str,
    text: &str,
) -> Result<BTreeSet<CargoManifestDirectRequirement>, CargoManifestError> {
    let root: Value = toml::from_str(text).map_err(CargoManifestError::Parse)?;
    let root_table = root.as_table().ok_or(CargoManifestError::ExpectedTable)?;
    let mut dependencies = BTreeSet::new();

    traverse_manifest_sections(manifest_path, root_table, |section, value| {
        collect_direct_requirement_section(manifest_path, section, value, &mut dependencies)
    })?;

    Ok(dependencies)
}

pub fn parse_workspace_member_manifest_paths(
    manifest_path: &str,
    text: &str,
) -> Result<Vec<String>, CargoManifestError> {
    let root: Value = toml::from_str(text).map_err(CargoManifestError::Parse)?;
    let Some(members) = workspace_members(manifest_path, &root)? else {
        return Ok(Vec::new());
    };

    members
        .iter()
        .filter_map(|member| match member.as_str() {
            Some(path) if contains_glob_metacharacter(path) => None,
            Some(path) if is_workspace_relative_member_path(path) => {
                Some(Ok(format!("{path}/Cargo.toml")))
            }
            Some(path) => Some(Err(CargoManifestError::InvalidWorkspaceMemberPath {
                manifest_path: manifest_path.to_owned(),
                member: path.to_owned(),
            })),
            None => Some(Err(CargoManifestError::InvalidWorkspaceMembers {
                manifest_path: manifest_path.to_owned(),
            })),
        })
        .collect()
}

pub fn parse_workspace_member_glob_roots(
    manifest_path: &str,
    text: &str,
) -> Result<Vec<String>, CargoManifestError> {
    let root: Value = toml::from_str(text).map_err(CargoManifestError::Parse)?;
    let Some(members) = workspace_members(manifest_path, &root)? else {
        return Ok(Vec::new());
    };

    members
        .iter()
        .filter_map(|member| match member.as_str() {
            Some(path) if contains_glob_metacharacter(path) => {
                Some(workspace_member_glob_root(manifest_path, path))
            }
            Some(_) => None,
            None => Some(Err(CargoManifestError::InvalidWorkspaceMembers {
                manifest_path: manifest_path.to_owned(),
            })),
        })
        .collect()
}

fn workspace_members<'a>(
    manifest_path: &str,
    root: &'a Value,
) -> Result<Option<&'a Vec<Value>>, CargoManifestError> {
    let Some(workspace_table) = workspace_table(manifest_path, root)? else {
        return Ok(None);
    };
    let Some(members_value) = workspace_table.get("members") else {
        return Ok(None);
    };
    let Some(members) = members_value.as_array() else {
        return Err(CargoManifestError::InvalidWorkspaceMembers {
            manifest_path: manifest_path.to_owned(),
        });
    };

    Ok(Some(members))
}

fn workspace_table<'a>(
    manifest_path: &str,
    root: &'a Value,
) -> Result<Option<&'a toml::map::Map<String, Value>>, CargoManifestError> {
    let root_table = root.as_table().ok_or(CargoManifestError::ExpectedTable)?;
    let Some(workspace_value) = root_table.get("workspace") else {
        return Ok(None);
    };
    let Some(workspace_table) = workspace_value.as_table() else {
        return Err(CargoManifestError::InvalidWorkspaceSection {
            manifest_path: manifest_path.to_owned(),
        });
    };

    Ok(Some(workspace_table))
}

fn workspace_member_glob_root(
    manifest_path: &str,
    path: &str,
) -> Result<String, CargoManifestError> {
    let mut root = Vec::new();
    for component in Path::new(path).components() {
        let Component::Normal(value) = component else {
            return Err(CargoManifestError::InvalidWorkspaceMemberPath {
                manifest_path: manifest_path.to_owned(),
                member: path.to_owned(),
            });
        };
        let value = value.to_string_lossy();
        if contains_glob_metacharacter(&value) {
            break;
        }
        root.push(value.into_owned());
    }

    if root.is_empty() {
        Ok(".".to_owned())
    } else {
        Ok(root.join("/"))
    }
}

/// How one `Cargo.toml` positions itself for workspace-root discovery,
/// mirroring the three manifest shapes cargo consults when it selects a
/// workspace root: an explicit `[workspace]` table makes the manifest the
/// root, a `[package] workspace = "path"` pointer names the root directory,
/// and anything else leaves root selection to the ancestor-directory walk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceRootDirective {
    WorkspaceRoot,
    MemberOf { workspace_path: String },
    Standalone,
}

pub fn parse_workspace_root_directive(
    manifest_path: &str,
    text: &str,
) -> Result<WorkspaceRootDirective, CargoManifestError> {
    let root: Value = toml::from_str(text).map_err(CargoManifestError::Parse)?;
    if workspace_table(manifest_path, &root)?.is_some() {
        return Ok(WorkspaceRootDirective::WorkspaceRoot);
    }

    let root_table = root.as_table().ok_or(CargoManifestError::ExpectedTable)?;
    let Some(package_value) = root_table.get("package") else {
        return Ok(WorkspaceRootDirective::Standalone);
    };
    let Some(package_table) = package_value.as_table() else {
        return Err(CargoManifestError::InvalidPackageSection {
            manifest_path: manifest_path.to_owned(),
        });
    };
    let Some(workspace_value) = package_table.get("workspace") else {
        return Ok(WorkspaceRootDirective::Standalone);
    };
    let Some(workspace_path) = workspace_value.as_str() else {
        return Err(CargoManifestError::InvalidPackageWorkspacePath {
            manifest_path: manifest_path.to_owned(),
        });
    };

    Ok(WorkspaceRootDirective::MemberOf {
        workspace_path: workspace_path.to_owned(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceManifestMembership {
    Included,
    Excluded,
    Unclaimed,
}

/// Classifies an ancestor workspace's explicit relationship to a child
/// manifest during malformed-manifest fallback. Exclusions take precedence.
pub fn classify_workspace_manifest_membership(
    manifest_path: &str,
    text: &str,
    relative_manifest_path: &Path,
) -> Result<WorkspaceManifestMembership, CargoManifestError> {
    let root: Value = toml::from_str(text).map_err(CargoManifestError::Parse)?;
    let Some(workspace) = workspace_table(manifest_path, &root)? else {
        return Ok(WorkspaceManifestMembership::Unclaimed);
    };
    let Some(relative_dir) = relative_manifest_path.parent() else {
        return Ok(WorkspaceManifestMembership::Unclaimed);
    };
    let relative_dir = relative_dir
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/");

    let excludes = workspace_path_patterns(manifest_path, workspace, "exclude")?;
    // Cargo treats `exclude` entries as normalized paths, not glob patterns.
    if excludes.iter().any(|path| path == &relative_dir) {
        return Ok(WorkspaceManifestMembership::Excluded);
    }

    let members = workspace_path_patterns(manifest_path, workspace, "members")?;
    Ok(
        if members
            .iter()
            .any(|pattern| workspace_path_pattern_matches(pattern, &relative_dir))
        {
            WorkspaceManifestMembership::Included
        } else {
            WorkspaceManifestMembership::Unclaimed
        },
    )
}

fn workspace_path_patterns(
    manifest_path: &str,
    workspace: &toml::map::Map<String, Value>,
    key: &'static str,
) -> Result<Vec<String>, CargoManifestError> {
    let Some(value) = workspace.get(key) else {
        return Ok(Vec::new());
    };
    let values = value
        .as_array()
        .ok_or_else(|| CargoManifestError::InvalidWorkspacePaths {
            manifest_path: manifest_path.to_owned(),
            key,
        })?;
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .and_then(normalise_workspace_path_pattern)
                .ok_or_else(|| CargoManifestError::InvalidWorkspacePaths {
                    manifest_path: manifest_path.to_owned(),
                    key,
                })
        })
        .collect()
}

fn normalise_workspace_path_pattern(path: &str) -> Option<String> {
    let mut components = Vec::new();
    for component in Path::new(path).components() {
        match component {
            Component::CurDir => {}
            Component::Normal(component) => {
                components.push(component.to_string_lossy().into_owned());
            }
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    (!components.is_empty()).then(|| components.join("/"))
}

fn workspace_path_pattern_matches(pattern: &str, candidate: &str) -> bool {
    fn matches_segments(pattern: &[&str], candidate: &[&str]) -> bool {
        match pattern {
            [] => candidate.is_empty(),
            ["**", rest @ ..] => {
                matches_segments(rest, candidate)
                    || (!candidate.is_empty() && matches_segments(pattern, &candidate[1..]))
            }
            [segment, rest @ ..] => candidate.first().is_some_and(|candidate_segment| {
                wildcard_segment_matches(
                    &segment.chars().collect::<Vec<_>>(),
                    &candidate_segment.chars().collect::<Vec<_>>(),
                ) && matches_segments(rest, &candidate[1..])
            }),
        }
    }

    fn wildcard_segment_matches(pattern: &[char], candidate: &[char]) -> bool {
        fn class_matches(class: &[char], candidate: char) -> bool {
            let (negated, class) = match class {
                ['!' | '^', rest @ ..] => (true, rest),
                _ => (false, class),
            };
            let mut matched = false;
            let mut index = 0;
            while index < class.len() {
                if index + 2 < class.len() && class[index + 1] == '-' {
                    matched |= (class[index]..=class[index + 2]).contains(&candidate);
                    index += 3;
                } else {
                    matched |= class[index] == candidate;
                    index += 1;
                }
            }
            matched != negated
        }

        match pattern {
            [] => candidate.is_empty(),
            ['*', rest @ ..] => {
                wildcard_segment_matches(rest, candidate)
                    || (!candidate.is_empty() && wildcard_segment_matches(pattern, &candidate[1..]))
            }
            ['?', rest @ ..] => {
                !candidate.is_empty() && wildcard_segment_matches(rest, &candidate[1..])
            }
            ['[', rest @ ..] => {
                let Some(end) = rest.iter().position(|character| *character == ']') else {
                    return false;
                };
                !candidate.is_empty()
                    && class_matches(&rest[..end], candidate[0])
                    && wildcard_segment_matches(&rest[end + 1..], &candidate[1..])
            }
            ['\\', literal, rest @ ..] => {
                candidate.first() == Some(literal)
                    && wildcard_segment_matches(rest, &candidate[1..])
            }
            [literal, rest @ ..] => {
                candidate.first() == Some(literal)
                    && wildcard_segment_matches(rest, &candidate[1..])
            }
        }
    }

    matches_segments(
        &pattern.trim_end_matches('/').split('/').collect::<Vec<_>>(),
        &candidate.split('/').collect::<Vec<_>>(),
    )
}

pub fn parse_workspace_dependency_requirements(
    manifest_path: &str,
    text: &str,
) -> Result<BTreeSet<CargoManifestDirectRequirement>, CargoManifestError> {
    let root: Value = toml::from_str(text).map_err(CargoManifestError::Parse)?;
    let Some(workspace_table) = workspace_table(manifest_path, &root)? else {
        return Ok(BTreeSet::new());
    };

    let mut dependencies = BTreeSet::new();
    collect_direct_requirement_section(
        manifest_path,
        "workspace.dependencies",
        workspace_table.get("dependencies"),
        &mut dependencies,
    )?;

    Ok(dependencies)
}

pub fn parse_workspace_package_version(
    manifest_path: &str,
    text: &str,
) -> Result<Option<String>, CargoManifestError> {
    let root: Value = toml::from_str(text).map_err(CargoManifestError::Parse)?;
    let Some(workspace_table) = workspace_table(manifest_path, &root)? else {
        return Ok(None);
    };
    let Some(package_value) = workspace_table.get("package") else {
        return Ok(None);
    };
    let Some(package_table) = package_value.as_table() else {
        return Err(CargoManifestError::InvalidWorkspacePackageSection {
            manifest_path: manifest_path.to_owned(),
        });
    };
    let Some(version_value) = package_table.get("version") else {
        return Ok(None);
    };
    let Some(version) = version_value.as_str() else {
        return Err(CargoManifestError::InvalidWorkspacePackageVersion {
            manifest_path: manifest_path.to_owned(),
        });
    };

    Ok(Some(version.to_owned()))
}

pub fn parse_manifest_package_identity(
    manifest_path: &str,
    text: &str,
    workspace_package_version: Option<&str>,
) -> Result<Option<CargoManifestPackage>, CargoManifestError> {
    let root: Value = toml::from_str(text).map_err(CargoManifestError::Parse)?;
    let root_table = root.as_table().ok_or(CargoManifestError::ExpectedTable)?;
    let Some(package_value) = root_table.get("package") else {
        return Ok(None);
    };
    let Some(package_table) = package_value.as_table() else {
        return Err(CargoManifestError::InvalidPackageSection {
            manifest_path: manifest_path.to_owned(),
        });
    };
    let Some(name_value) = package_table.get("name") else {
        return Ok(None);
    };
    let Some(name) = name_value.as_str() else {
        return Err(CargoManifestError::InvalidPackageName {
            manifest_path: manifest_path.to_owned(),
        });
    };
    let Some(version_value) = package_table.get("version") else {
        return Ok(None);
    };
    let version = match version_value {
        Value::String(version) => version.as_str(),
        Value::Table(table) if workspace_dependency_value(table)? => {
            let Some(version) = workspace_package_version else {
                return Ok(None);
            };
            version
        }
        _ => {
            return Err(CargoManifestError::InvalidPackageVersion {
                manifest_path: manifest_path.to_owned(),
            });
        }
    };

    Ok(Some(CargoManifestPackage {
        manifest_path: manifest_path.to_owned(),
        name: name.to_owned(),
        version: version.to_owned(),
    }))
}

fn contains_glob_metacharacter(path: &str) -> bool {
    path.bytes()
        .any(|byte| matches!(byte, b'*' | b'?' | b'[' | b']'))
}

fn is_workspace_relative_member_path(path: &str) -> bool {
    !path.is_empty()
        && Path::new(path)
            .components()
            .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
}

fn traverse_manifest_sections(
    manifest_path: &str,
    root_table: &toml::map::Map<String, Value>,
    mut visit: impl FnMut(&str, Option<&Value>) -> Result<(), CargoManifestError>,
) -> Result<(), CargoManifestError> {
    for section in DEPENDENCY_SECTIONS {
        visit(section, root_table.get(section))?;
    }

    let Some(target_value) = root_table.get("target") else {
        return Ok(());
    };
    let Some(targets) = target_value.as_table() else {
        return Err(CargoManifestError::InvalidDependencySection {
            manifest_path: manifest_path.to_owned(),
            section: "target".to_owned(),
        });
    };

    for (target_name, target_value) in targets {
        let Some(target_table) = target_value.as_table() else {
            return Err(CargoManifestError::InvalidDependencySection {
                manifest_path: manifest_path.to_owned(),
                section: format!("target.{target_name}"),
            });
        };

        for suffix in DEPENDENCY_SECTIONS {
            let section = format!("target.{target_name}.{suffix}");
            visit(&section, target_table.get(suffix))?;
        }
    }

    Ok(())
}

fn collect_dependency_section(
    manifest_path: &str,
    section: &str,
    value: Option<&Value>,
    dependencies: &mut BTreeSet<CargoManifestDependency>,
) -> Result<(), CargoManifestError> {
    let Some(value) = value else {
        return Ok(());
    };
    let Some(table) = value.as_table() else {
        return Err(CargoManifestError::InvalidDependencySection {
            manifest_path: manifest_path.to_owned(),
            section: section.to_owned(),
        });
    };

    for (name, dependency_value) in table {
        dependencies.insert(CargoManifestDependency {
            manifest_path: manifest_path.to_owned(),
            section: section.to_owned(),
            name: name.to_owned(),
            source_kind: dependency_source_kind(dependency_value)?,
        });
    }

    Ok(())
}

fn collect_direct_requirement_section(
    manifest_path: &str,
    section: &str,
    value: Option<&Value>,
    dependencies: &mut BTreeSet<CargoManifestDirectRequirement>,
) -> Result<(), CargoManifestError> {
    let Some(value) = value else {
        return Ok(());
    };
    let Some(table) = value.as_table() else {
        return Err(CargoManifestError::InvalidDependencySection {
            manifest_path: manifest_path.to_owned(),
            section: section.to_owned(),
        });
    };

    for (name, dependency_value) in table {
        let (source_kind, version_requirement) = dependency_shape(dependency_value)?;
        dependencies.insert(CargoManifestDirectRequirement {
            manifest_path: manifest_path.to_owned(),
            section: section.to_owned(),
            name: name.to_owned(),
            source_kind,
            version_requirement,
        });
    }

    Ok(())
}

fn dependency_source_kind(value: &Value) -> Result<CargoDependencySourceKind, CargoManifestError> {
    Ok(dependency_shape(value)?.0)
}

fn dependency_shape(
    value: &Value,
) -> Result<(CargoDependencySourceKind, Option<String>), CargoManifestError> {
    match value {
        Value::String(requirement) => Ok((
            CargoDependencySourceKind::Registry,
            Some(requirement.clone()),
        )),
        Value::Table(table) => {
            let version_requirement = table
                .get("version")
                .and_then(Value::as_str)
                .map(str::to_owned);

            if workspace_dependency_value(table)? {
                Ok((CargoDependencySourceKind::Workspace, version_requirement))
            } else if table.contains_key("git") {
                Ok((CargoDependencySourceKind::Git, version_requirement))
            } else if table.contains_key("path") {
                Ok((CargoDependencySourceKind::Path, version_requirement))
            } else if table.contains_key("registry") || table.contains_key("registry-index") {
                Ok((
                    CargoDependencySourceKind::AlternateRegistry,
                    version_requirement,
                ))
            } else {
                Ok((CargoDependencySourceKind::Registry, version_requirement))
            }
        }
        _ => Err(CargoManifestError::UnsupportedDependencyValue),
    }
}

fn workspace_dependency_value(
    table: &toml::map::Map<String, Value>,
) -> Result<bool, CargoManifestError> {
    match table.get("workspace") {
        Some(Value::Boolean(value)) => Ok(*value),
        Some(_) => Err(CargoManifestError::InvalidWorkspaceValue),
        None => Ok(false),
    }
}

#[derive(Debug, Error)]
pub enum CargoManifestError {
    #[error("unable to parse Cargo.toml: {0}")]
    Parse(#[source] toml::de::Error),
    #[error("Cargo.toml root must be a TOML table")]
    ExpectedTable,
    #[error("{manifest_path}: dependency section {section} must be a table")]
    InvalidDependencySection {
        manifest_path: String,
        section: String,
    },
    #[error("{manifest_path}: {section}.{key}.package must be a string")]
    InvalidPatchPackageName {
        manifest_path: String,
        section: String,
        key: String,
    },
    #[error("{manifest_path}: package section must be a table")]
    InvalidPackageSection { manifest_path: String },
    #[error("{manifest_path}: package name must be a string")]
    InvalidPackageName { manifest_path: String },
    #[error("{manifest_path}: package version must be a string")]
    InvalidPackageVersion { manifest_path: String },
    #[error("{manifest_path}: package workspace must be a string path")]
    InvalidPackageWorkspacePath { manifest_path: String },
    #[error("{manifest_path}: workspace package section must be a table")]
    InvalidWorkspacePackageSection { manifest_path: String },
    #[error("{manifest_path}: workspace package version must be a string")]
    InvalidWorkspacePackageVersion { manifest_path: String },
    #[error("{manifest_path}: workspace section must be a table")]
    InvalidWorkspaceSection { manifest_path: String },
    #[error("{manifest_path}: workspace members must be an array of strings")]
    InvalidWorkspaceMembers { manifest_path: String },
    #[error("{manifest_path}: workspace {key} must be an array of relative path strings")]
    InvalidWorkspacePaths {
        manifest_path: String,
        key: &'static str,
    },
    #[error("{manifest_path}: workspace member path must stay inside the workspace: {member}")]
    InvalidWorkspaceMemberPath {
        manifest_path: String,
        member: String,
    },
    #[error("Cargo dependency workspace value must be a boolean")]
    InvalidWorkspaceValue,
    #[error("unsupported Cargo dependency value shape")]
    UnsupportedDependencyValue,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::Path;

    use super::{
        CargoDependencySourceKind, CargoManifestError, WorkspaceManifestMembership,
        WorkspaceRootDirective, classify_workspace_manifest_membership,
        parse_manifest_dependencies, parse_manifest_direct_requirements,
        parse_manifest_package_identity, parse_manifest_patched_crate_names,
        parse_workspace_dependency_requirements, parse_workspace_member_glob_roots,
        parse_workspace_member_manifest_paths, parse_workspace_package_version,
        parse_workspace_root_directive,
    };

    #[test]
    fn classifies_workspace_root_directives() {
        assert_eq!(
            parse_workspace_root_directive("Cargo.toml", "[workspace]\nmembers = [\"crates/*\"]\n")
                .expect("workspace manifest should classify"),
            WorkspaceRootDirective::WorkspaceRoot
        );
        assert_eq!(
            parse_workspace_root_directive(
                "Cargo.toml",
                "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\n[workspace]\n"
            )
            .expect("package with empty workspace table should classify"),
            WorkspaceRootDirective::WorkspaceRoot
        );
        assert_eq!(
            parse_workspace_root_directive(
                "crates/demo/Cargo.toml",
                "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nworkspace = \"../..\"\n"
            )
            .expect("workspace pointer should classify"),
            WorkspaceRootDirective::MemberOf {
                workspace_path: "../..".to_owned()
            }
        );
        assert_eq!(
            parse_workspace_root_directive(
                "crates/demo/Cargo.toml",
                "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n"
            )
            .expect("plain package manifest should classify"),
            WorkspaceRootDirective::Standalone
        );
        assert_eq!(
            parse_workspace_root_directive("Cargo.toml", "[dependencies]\nserde = \"1\"\n")
                .expect("packageless manifest should classify"),
            WorkspaceRootDirective::Standalone
        );
    }

    #[test]
    fn rejects_non_string_package_workspace_pointer() {
        assert!(matches!(
            parse_workspace_root_directive(
                "Cargo.toml",
                "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nworkspace = true\n"
            ),
            Err(CargoManifestError::InvalidPackageWorkspacePath { .. })
        ));
    }

    #[test]
    fn fallback_membership_honours_member_and_exclude_patterns() {
        let manifest = "[workspace]\nmembers = [\"crates/*\"]\nexclude = [\"crates/excluded\"]\n";
        assert!(
            classify_workspace_manifest_membership(
                "Cargo.toml",
                manifest,
                Path::new("crates/included/Cargo.toml")
            )
            .expect("membership should parse")
                == WorkspaceManifestMembership::Included
        );
        assert!(
            classify_workspace_manifest_membership(
                "Cargo.toml",
                manifest,
                Path::new("crates/excluded/Cargo.toml")
            )
            .expect("exclusion should parse")
                == WorkspaceManifestMembership::Excluded
        );

        let bracket_manifest =
            "[workspace]\nmembers = [\"./crates/[ab]pp\"]\nexclude = [\"./crates/xpp\"]\n";
        assert_eq!(
            classify_workspace_manifest_membership(
                "Cargo.toml",
                bracket_manifest,
                Path::new("crates/app/Cargo.toml"),
            )
            .expect("bracket membership should parse"),
            WorkspaceManifestMembership::Included
        );
        assert_eq!(
            classify_workspace_manifest_membership(
                "Cargo.toml",
                bracket_manifest,
                Path::new("crates/xpp/Cargo.toml"),
            )
            .expect("exact exclusion should parse"),
            WorkspaceManifestMembership::Excluded
        );
        assert_eq!(
            classify_workspace_manifest_membership(
                "Cargo.toml",
                "[workspace]\nmembers = []\nexclude = [\"crates/a*\"]\n",
                Path::new("crates/app/Cargo.toml"),
            )
            .expect("literal wildcard exclusion should parse"),
            WorkspaceManifestMembership::Unclaimed
        );
    }

    #[test]
    fn parses_root_and_target_dependency_sections() {
        let dependencies = parse_manifest_dependencies(
            "crates/demo/Cargo.toml",
            r#"
[dependencies]
serde = "1"
workspace-crate = { workspace = true }
git-crate = { git = "https://example.com/repo.git" }

[target.'cfg(unix)'.build-dependencies]
cc = "1"
"#,
        )
        .expect("manifest should parse");

        let rendered = dependencies
            .iter()
            .map(|dependency| {
                format!(
                    "{}:{}:{}:{}",
                    dependency.manifest_path(),
                    dependency.section(),
                    dependency.name(),
                    dependency.source_kind()
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(
            rendered,
            vec![
                "crates/demo/Cargo.toml:dependencies:git-crate:git",
                "crates/demo/Cargo.toml:dependencies:serde:registry",
                "crates/demo/Cargo.toml:dependencies:workspace-crate:workspace",
                "crates/demo/Cargo.toml:target.cfg(unix).build-dependencies:cc:registry",
            ]
        );
    }

    #[test]
    fn classifies_non_crates_io_source_kinds() {
        let dependencies = parse_manifest_dependencies(
            "Cargo.toml",
            r#"
[dependencies]
path-crate = { path = "../path-crate" }
alt = { version = "1", registry = "internal" }
"#,
        )
        .expect("manifest should parse");

        assert!(
            dependencies
                .iter()
                .any(|dependency| dependency.source_kind() == CargoDependencySourceKind::Path)
        );
        assert!(dependencies.iter().any(|dependency| {
            dependency.source_kind() == CargoDependencySourceKind::AlternateRegistry
        }));
    }

    #[test]
    fn parses_direct_version_requirements_for_manifest_entries() {
        let dependencies = parse_manifest_direct_requirements(
            "Cargo.toml",
            r#"
[dependencies]
serde = "=1.0.228"
alt = { version = "=0.2.0", registry = "internal" }
git-crate = { git = "https://example.com/repo.git", version = "=1.2.3" }
workspace-crate = { workspace = true }
"#,
        )
        .expect("manifest should parse");

        let rendered = dependencies
            .iter()
            .map(|dependency| {
                format!(
                    "{}:{}:{}:{}:{:?}",
                    dependency.manifest_path(),
                    dependency.section(),
                    dependency.name(),
                    dependency.source_kind(),
                    dependency.version_requirement()
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(
            rendered,
            vec![
                r#"Cargo.toml:dependencies:alt:alternate-registry:Some("=0.2.0")"#,
                r#"Cargo.toml:dependencies:git-crate:git:Some("=1.2.3")"#,
                r#"Cargo.toml:dependencies:serde:registry:Some("=1.0.228")"#,
                r#"Cargo.toml:dependencies:workspace-crate:workspace:None"#,
            ]
        );
    }

    #[test]
    fn rejects_non_table_target_entries() {
        let error = parse_manifest_dependencies(
            "Cargo.toml",
            r#"
[target]
bad = "not a table"
"#,
        )
        .expect_err("manifest should fail");

        assert!(matches!(
            error,
            CargoManifestError::InvalidDependencySection { section, .. }
                if section == "target.bad"
        ));
    }

    #[test]
    fn rejects_non_table_target_section() {
        let error = parse_manifest_dependencies(
            "Cargo.toml",
            r#"
target = "not a table"
"#,
        )
        .expect_err("manifest should fail");

        assert!(matches!(
            error,
            CargoManifestError::InvalidDependencySection { section, .. }
                if section == "target"
        ));
    }

    #[test]
    fn rejects_non_boolean_workspace_dependency_values() {
        let error = parse_manifest_dependencies(
            "Cargo.toml",
            r#"
[dependencies]
local = { workspace = "yes" }
"#,
        )
        .expect_err("manifest should fail");

        assert!(matches!(error, CargoManifestError::InvalidWorkspaceValue));
    }

    #[test]
    fn parses_workspace_member_manifest_paths() {
        let members = parse_workspace_member_manifest_paths(
            "Cargo.toml",
            r#"
[workspace]
members = ["crates/*", "app", "libs/core"]
"#,
        )
        .expect("workspace should parse");

        assert_eq!(members, vec!["app/Cargo.toml", "libs/core/Cargo.toml"]);
    }

    #[test]
    fn parses_workspace_member_glob_roots() {
        let roots = parse_workspace_member_glob_roots(
            "Cargo.toml",
            r#"
[workspace]
members = ["crates/*", "libs/*/core", "app"]
"#,
        )
        .expect("workspace should parse");

        assert_eq!(roots, vec!["crates", "libs"]);
    }

    #[test]
    fn parses_workspace_dependency_requirements() {
        let dependencies = parse_workspace_dependency_requirements(
            "Cargo.toml",
            r#"
[workspace.dependencies]
serde = "=1.0.228"
local = { path = "crates/local" }
alt = { version = "=0.2.0", registry = "internal" }
"#,
        )
        .expect("workspace dependencies should parse");

        let rendered = dependencies
            .iter()
            .map(|dependency| {
                format!(
                    "{}:{}:{}:{}:{:?}",
                    dependency.manifest_path(),
                    dependency.section(),
                    dependency.name(),
                    dependency.source_kind(),
                    dependency.version_requirement()
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(
            rendered,
            vec![
                r#"Cargo.toml:workspace.dependencies:alt:alternate-registry:Some("=0.2.0")"#,
                r#"Cargo.toml:workspace.dependencies:local:path:None"#,
                r#"Cargo.toml:workspace.dependencies:serde:registry:Some("=1.0.228")"#,
            ]
        );
    }

    #[test]
    fn parses_manifest_package_name() {
        let package = parse_manifest_package_identity(
            "crates/app/Cargo.toml",
            r#"
[package]
name = "app"
version = "0.1.0"
"#,
            None,
        )
        .expect("manifest should parse");

        let package = package.expect("package identity should exist");
        assert_eq!(package.manifest_path(), "crates/app/Cargo.toml");
        assert_eq!(package.name(), "app");
        assert_eq!(package.version(), "0.1.0");

        let virtual_manifest = parse_manifest_package_identity(
            "Cargo.toml",
            r#"
[workspace]
members = ["crates/*"]
"#,
            None,
        )
        .expect("manifest should parse");

        assert_eq!(virtual_manifest, None);
    }

    #[test]
    fn parses_workspace_inherited_package_versions() {
        let workspace_version = parse_workspace_package_version(
            "Cargo.toml",
            r#"
[workspace.package]
version = "0.8.0"
"#,
        )
        .expect("workspace package should parse");
        let package = parse_manifest_package_identity(
            "crates/app/Cargo.toml",
            r#"
[package]
name = "app"
version = { workspace = true }
"#,
            workspace_version.as_deref(),
        )
        .expect("manifest should parse")
        .expect("package identity should exist");

        assert_eq!(package.name(), "app");
        assert_eq!(package.version(), "0.8.0");
    }

    #[test]
    fn rejects_invalid_workspace_members_shape() {
        let error = parse_workspace_member_manifest_paths(
            "Cargo.toml",
            r#"
[workspace]
members = "app"
"#,
        )
        .expect_err("workspace members should fail");

        assert!(matches!(
            error,
            CargoManifestError::InvalidWorkspaceMembers { .. }
        ));
    }

    #[test]
    fn rejects_workspace_members_outside_workspace() {
        let error = parse_workspace_member_manifest_paths(
            "Cargo.toml",
            r#"
[workspace]
members = ["../outside"]
"#,
        )
        .expect_err("workspace member should fail");

        assert!(matches!(
            error,
            CargoManifestError::InvalidWorkspaceMemberPath { member, .. }
                if member == "../outside"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_absolute_workspace_members() {
        let error = parse_workspace_member_manifest_paths(
            "Cargo.toml",
            r#"
[workspace]
members = ["/tmp/outside"]
"#,
        )
        .expect_err("workspace member should fail");

        assert!(matches!(
            error,
            CargoManifestError::InvalidWorkspaceMemberPath { member, .. }
                if member == "/tmp/outside"
        ));
    }

    #[test]
    fn parses_patched_crate_names_from_any_registry_key() {
        let patched = parse_manifest_patched_crate_names(
            "Cargo.toml",
            r#"
[patch.crates-io]
serde = { git = "https://example.com/serde.git" }

[patch."https://example.com/registry"]
other-crate = { git = "https://example.com/other.git" }
"#,
        )
        .expect("manifest should parse");

        assert_eq!(
            patched,
            BTreeSet::from(["serde".to_owned(), "other-crate".to_owned()])
        );
    }

    #[test]
    fn parses_patched_crate_names_from_package_rename_form() {
        let patched = parse_manifest_patched_crate_names(
            "Cargo.toml",
            r#"
[patch.crates-io]
serde-alias = { package = "serde", git = "https://example.com/serde.git" }
"#,
        )
        .expect("manifest should parse");

        assert_eq!(
            patched,
            BTreeSet::from(["serde".to_owned(), "serde-alias".to_owned()])
        );
    }

    #[test]
    fn rejects_non_string_patch_package_name() {
        let error = parse_manifest_patched_crate_names(
            "Cargo.toml",
            r#"
[patch.crates-io]
serde-alias = { package = 1, git = "https://example.com/serde.git" }
"#,
        )
        .expect_err("manifest should fail");

        assert!(matches!(
            error,
            CargoManifestError::InvalidPatchPackageName { section, key, .. }
                if section == "patch.crates-io" && key == "serde-alias"
        ));
    }

    #[test]
    fn returns_no_patched_crates_when_patch_table_is_absent() {
        let patched = parse_manifest_patched_crate_names("Cargo.toml", "[dependencies]\n")
            .expect("manifest should parse");

        assert!(patched.is_empty());
    }

    #[test]
    fn rejects_non_table_patch_section() {
        let error = parse_manifest_patched_crate_names(
            "Cargo.toml",
            r#"
patch = "not a table"
"#,
        )
        .expect_err("manifest should fail");

        assert!(matches!(
            error,
            CargoManifestError::InvalidDependencySection { section, .. }
                if section == "patch"
        ));
    }

    #[test]
    fn rejects_non_table_patch_registry_entries() {
        let error = parse_manifest_patched_crate_names(
            "Cargo.toml",
            r#"
[patch]
crates-io = "not a table"
"#,
        )
        .expect_err("manifest should fail");

        assert!(matches!(
            error,
            CargoManifestError::InvalidDependencySection { section, .. }
                if section == "patch.crates-io"
        ));
    }
}
