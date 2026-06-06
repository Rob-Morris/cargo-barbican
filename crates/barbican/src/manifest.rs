use std::collections::BTreeSet;
use std::fmt;

use thiserror::Error;
use toml::Value;

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

pub fn parse_manifest_dependencies(
    manifest_path: &str,
    text: &str,
) -> Result<BTreeSet<CargoManifestDependency>, CargoManifestError> {
    let root: Value = toml::from_str(text).map_err(CargoManifestError::Parse)?;
    let root_table = root.as_table().ok_or(CargoManifestError::ExpectedTable)?;
    let mut dependencies = BTreeSet::new();

    for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
        collect_dependency_section(
            manifest_path,
            section,
            root_table.get(section),
            &mut dependencies,
        )?;
    }

    if let Some(Value::Table(targets)) = root_table.get("target") {
        for (target_name, target_value) in targets {
            let Some(target_table) = target_value.as_table() else {
                continue;
            };

            for suffix in ["dependencies", "dev-dependencies", "build-dependencies"] {
                let section = format!("target.{target_name}.{suffix}");
                collect_dependency_section(
                    manifest_path,
                    &section,
                    target_table.get(suffix),
                    &mut dependencies,
                )?;
            }
        }
    }

    Ok(dependencies)
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

fn dependency_source_kind(value: &Value) -> Result<CargoDependencySourceKind, CargoManifestError> {
    match value {
        Value::String(_) => Ok(CargoDependencySourceKind::Registry),
        Value::Table(table) => {
            if table
                .get("workspace")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                Ok(CargoDependencySourceKind::Workspace)
            } else if table.contains_key("git") {
                Ok(CargoDependencySourceKind::Git)
            } else if table.contains_key("path") {
                Ok(CargoDependencySourceKind::Path)
            } else if table.contains_key("registry") || table.contains_key("registry-index") {
                Ok(CargoDependencySourceKind::AlternateRegistry)
            } else {
                Ok(CargoDependencySourceKind::Registry)
            }
        }
        _ => Err(CargoManifestError::UnsupportedDependencyValue),
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
    #[error("unsupported Cargo dependency value shape")]
    UnsupportedDependencyValue,
}

#[cfg(test)]
mod tests {
    use super::{CargoDependencySourceKind, parse_manifest_dependencies};

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
}
