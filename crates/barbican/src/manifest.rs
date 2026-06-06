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
    let root_table = root.as_table().ok_or(CargoManifestError::ExpectedTable)?;
    let Some(workspace_value) = root_table.get("workspace") else {
        return Ok(Vec::new());
    };
    let Some(workspace_table) = workspace_value.as_table() else {
        return Err(CargoManifestError::InvalidWorkspaceSection {
            manifest_path: manifest_path.to_owned(),
        });
    };
    let Some(members_value) = workspace_table.get("members") else {
        return Ok(Vec::new());
    };
    let Some(members) = members_value.as_array() else {
        return Err(CargoManifestError::InvalidWorkspaceMembers {
            manifest_path: manifest_path.to_owned(),
        });
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
    #[error("{manifest_path}: workspace section must be a table")]
    InvalidWorkspaceSection { manifest_path: String },
    #[error("{manifest_path}: workspace members must be an array of strings")]
    InvalidWorkspaceMembers { manifest_path: String },
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
    use super::{
        CargoDependencySourceKind, CargoManifestError, parse_manifest_dependencies,
        parse_manifest_direct_requirements, parse_workspace_member_manifest_paths,
    };

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
}
