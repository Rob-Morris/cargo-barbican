use thiserror::Error;
use toml::Value;
use toml::map::Map;

use crate::CargoDenyCheck;

/// Builds runtime cargo-deny config content for the advisory reconciliation pass.
///
/// cargo-deny 0.19.6 rejects the old `notice` advisory key as deprecated, so
/// generated configs omit it rather than carrying user suppression through.
///
/// User graph scope settings are preserved, but graph suppression keys are
/// stripped. `targets`, `features`, `all-features`, and `no-default-features`
/// keep the user's relevance scope; `exclude`-family keys can hide advisories
/// before Barbican can reconcile them and are therefore removed.
pub fn generate_cargo_deny_runtime_config(
    user_deny_toml: Option<&str>,
    checks: &[CargoDenyCheck],
) -> Result<String, CargoDenyRuntimeConfigError> {
    let mut root = match user_deny_toml {
        Some(text) => toml::from_str::<Value>(text).map_err(CargoDenyRuntimeConfigError::Parse)?,
        None => Value::Table(Map::new()),
    };
    let root = root
        .as_table_mut()
        .ok_or(CargoDenyRuntimeConfigError::ExpectedTable)?;

    strip_root_graph_exclusions(root);
    sanitize_graph_scope(root);
    root.insert("advisories".to_owned(), Value::Table(forced_advisories()));
    for check in checks {
        match check {
            CargoDenyCheck::Advisories => {}
            CargoDenyCheck::Bans => ensure_table(root, "bans"),
            CargoDenyCheck::Sources => ensure_table(root, "sources"),
            CargoDenyCheck::Licenses => ensure_table(root, "licenses"),
        }
    }

    toml::to_string_pretty(root).map_err(CargoDenyRuntimeConfigError::Serialize)
}

/// Any root `licenses` key counts as a declared policy: a malformed
/// non-table value flows into the generated runtime config, where cargo-deny
/// rejects it loudly, rather than being silently skipped here.
pub fn deny_toml_declares_licenses_policy(text: &str) -> Result<bool, CargoDenyRuntimeConfigError> {
    let root = toml::from_str::<Value>(text).map_err(CargoDenyRuntimeConfigError::Parse)?;
    let root = root
        .as_table()
        .ok_or(CargoDenyRuntimeConfigError::ExpectedTable)?;
    Ok(root.contains_key("licenses"))
}

pub fn advisory_ignores_from_toml(text: &str) -> Result<Vec<String>, CargoDenyRuntimeConfigError> {
    let root = toml::from_str::<Value>(text).map_err(CargoDenyRuntimeConfigError::Parse)?;
    let root = root
        .as_table()
        .ok_or(CargoDenyRuntimeConfigError::ExpectedTable)?;
    let Some(ignore) = root
        .get("advisories")
        .and_then(Value::as_table)
        .and_then(|advisories| advisories.get("ignore"))
    else {
        return Ok(Vec::new());
    };
    let ignore = ignore
        .as_array()
        .ok_or(CargoDenyRuntimeConfigError::InvalidAdvisoryIgnore)?;
    ignore.iter().map(advisory_ignore_id).collect()
}

fn advisory_ignore_id(entry: &Value) -> Result<String, CargoDenyRuntimeConfigError> {
    if let Some(id) = entry.as_str() {
        return Ok(id.to_owned());
    }

    entry
        .as_table()
        .and_then(|entry| entry.get("id"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(CargoDenyRuntimeConfigError::InvalidAdvisoryIgnore)
}

fn forced_advisories() -> Map<String, Value> {
    let mut advisories = Map::new();
    advisories.insert("ignore".to_owned(), Value::Array(Vec::new()));
    advisories.insert("yanked".to_owned(), Value::String("deny".to_owned()));
    advisories.insert("unmaintained".to_owned(), Value::String("all".to_owned()));
    advisories.insert("unsound".to_owned(), Value::String("all".to_owned()));
    advisories
}

fn ensure_table(root: &mut Map<String, Value>, key: &str) {
    root.entry(key.to_owned())
        .or_insert_with(|| Value::Table(Map::new()));
}

fn strip_root_graph_exclusions(root: &mut Map<String, Value>) {
    for key in ["exclude", "exclude-dev", "exclude-unpublished"] {
        root.remove(key);
    }
}

fn sanitize_graph_scope(root: &mut Map<String, Value>) {
    let Some(graph) = root.get_mut("graph").and_then(Value::as_table_mut) else {
        return;
    };
    graph.retain(|key, _| {
        matches!(
            key,
            "targets" | "features" | "all-features" | "no-default-features"
        )
    });
}

#[derive(Debug, Error)]
pub enum CargoDenyRuntimeConfigError {
    #[error("unable to parse deny.toml: {0}")]
    Parse(#[source] toml::de::Error),
    #[error("deny.toml root must be a TOML table")]
    ExpectedTable,
    #[error("advisory ignore entries must be strings or tables with a string id")]
    InvalidAdvisoryIgnore,
    #[error("unable to serialize generated cargo-deny config: {0}")]
    Serialize(#[source] toml::ser::Error),
}

#[cfg(test)]
mod tests {
    use super::{
        CargoDenyRuntimeConfigError, advisory_ignores_from_toml,
        deny_toml_declares_licenses_policy, generate_cargo_deny_runtime_config,
    };
    use crate::CargoDenyCheck;
    use toml::Value;

    #[test]
    fn detects_declared_licenses_policy() {
        assert!(
            deny_toml_declares_licenses_policy("[licenses]\nallow = [\"MIT\"]\n")
                .expect("deny.toml should parse")
        );
        assert!(
            deny_toml_declares_licenses_policy("[licenses]\n").expect("deny.toml should parse")
        );
        assert!(
            !deny_toml_declares_licenses_policy("[bans]\nwildcards = \"deny\"\n")
                .expect("deny.toml should parse")
        );
        assert!(!deny_toml_declares_licenses_policy("").expect("empty deny.toml should parse"));
    }

    #[test]
    fn declared_licenses_policy_detection_fails_closed_on_unparseable_toml() {
        let error = deny_toml_declares_licenses_policy("[licenses\n")
            .expect_err("malformed deny.toml should fail");

        assert!(matches!(error, CargoDenyRuntimeConfigError::Parse(_)));
    }

    #[test]
    fn forces_advisory_section_regardless_of_user_input() {
        let generated = generate_cargo_deny_runtime_config(
            Some(
                r#"
[advisories]
ignore = ["RUSTSEC-2024-0375"]
unmaintained = "allow"
unsound = "allow"
notice = "allow"
yanked = "allow"
severity-threshold = "critical"
"#,
            ),
            &[CargoDenyCheck::Advisories],
        )
        .expect("config should generate");
        let parsed = parse(&generated);
        let advisories = parsed
            .get("advisories")
            .and_then(Value::as_table)
            .expect("advisories should be a table");

        assert_eq!(
            advisories.get("ignore").and_then(Value::as_array),
            Some(&Vec::new())
        );
        assert_eq!(
            advisories.get("yanked").and_then(Value::as_str),
            Some("deny")
        );
        assert_eq!(
            advisories.get("unmaintained").and_then(Value::as_str),
            Some("all")
        );
        assert_eq!(
            advisories.get("unsound").and_then(Value::as_str),
            Some("all")
        );
        assert!(!advisories.contains_key("notice"));
        assert!(!advisories.contains_key("severity-threshold"));
    }

    #[test]
    fn preserves_user_non_advisory_sections_as_toml_values() {
        let user = r#"
[graph]
targets = ["x86_64-unknown-linux-gnu"]
features = ["cli"]
all-features = true
no-default-features = true

[advisories]
ignore = ["RUSTSEC-2024-0375"]
unmaintained = "allow"

[bans]
multiple-versions = "warn"
deny = [{ name = "openssl" }]

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]

[licenses]
unlicensed = "deny"
allow = ["MIT", "Apache-2.0"]
"#;
        let generated = generate_cargo_deny_runtime_config(
            Some(user),
            &[
                CargoDenyCheck::Advisories,
                CargoDenyCheck::Bans,
                CargoDenyCheck::Sources,
                CargoDenyCheck::Licenses,
            ],
        )
        .expect("config should generate");
        let original = parse(user);
        let parsed = parse(&generated);

        for key in ["bans", "sources", "licenses"] {
            assert_eq!(
                parsed.get(key),
                original.get(key),
                "{key} should be preserved"
            );
        }
        assert_eq!(parsed.get("graph"), original.get("graph"));
        assert_ne!(parsed.get("advisories"), original.get("advisories"));
    }

    #[test]
    fn strips_graph_exclusion_keys_and_unknown_graph_keys() {
        let generated = generate_cargo_deny_runtime_config(
            Some(
                r#"
[graph]
targets = ["x86_64-unknown-linux-gnu"]
features = ["cli"]
all-features = true
no-default-features = true
exclude = ["atty"]
exclude-dev = true
exclude-unpublished = true
future-suppression = "allow"
"#,
            ),
            &[CargoDenyCheck::Advisories],
        )
        .expect("config should generate");
        let parsed = parse(&generated);
        let graph = parsed
            .get("graph")
            .and_then(Value::as_table)
            .expect("graph should remain a table");

        assert_eq!(
            graph.get("targets").and_then(Value::as_array).map(Vec::len),
            Some(1)
        );
        assert_eq!(
            graph
                .get("features")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(1)
        );
        assert_eq!(
            graph.get("all-features").and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            graph.get("no-default-features").and_then(Value::as_bool),
            Some(true)
        );
        for key in [
            "exclude",
            "exclude-dev",
            "exclude-unpublished",
            "future-suppression",
        ] {
            assert!(!graph.contains_key(key), "{key} should be stripped");
        }
    }

    #[test]
    fn strips_root_level_graph_exclusion_aliases() {
        let generated = generate_cargo_deny_runtime_config(
            Some(
                r#"
exclude = ["atty"]
exclude-dev = true
exclude-unpublished = true
targets = ["x86_64-unknown-linux-gnu"]
features = ["cli"]
"#,
            ),
            &[CargoDenyCheck::Advisories],
        )
        .expect("config should generate");
        let parsed = parse(&generated);

        for key in ["exclude", "exclude-dev", "exclude-unpublished"] {
            assert!(!parsed.contains_key(key), "{key} should be stripped");
        }
        assert_eq!(
            parsed
                .get("targets")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(1)
        );
        assert_eq!(
            parsed
                .get("features")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(1)
        );
    }

    #[test]
    fn rejects_unparseable_user_deny_toml() {
        let error = generate_cargo_deny_runtime_config(
            Some("[advisories\nignore = []"),
            &[CargoDenyCheck::Advisories],
        )
        .expect_err("malformed user deny.toml must fail closed");

        assert!(matches!(error, CargoDenyRuntimeConfigError::Parse(_)));
    }

    #[test]
    fn extracts_native_advisory_ignores() {
        assert_eq!(
            advisory_ignores_from_toml(
                r#"
[advisories]
ignore = ["RUSTSEC-2026-0001", "RUSTSEC-2026-0002"]
"#
            )
            .expect("ignore list should parse"),
            vec![
                "RUSTSEC-2026-0001".to_owned(),
                "RUSTSEC-2026-0002".to_owned()
            ]
        );
    }

    #[test]
    fn extracts_table_form_native_advisory_ignores() {
        assert_eq!(
            advisory_ignores_from_toml(
                r#"
[advisories]
ignore = [{ id = "RUSTSEC-2026-0001", reason = "reviewed" }]
"#
            )
            .expect("table-form ignore list should parse"),
            vec!["RUSTSEC-2026-0001".to_owned()]
        );
    }

    #[test]
    fn extracts_mixed_native_advisory_ignores() {
        assert_eq!(
            advisory_ignores_from_toml(
                r#"
[advisories]
ignore = [
  "RUSTSEC-2026-0001",
  { id = "RUSTSEC-2026-0002", reason = "reviewed" },
]
"#
            )
            .expect("mixed ignore list should parse"),
            vec![
                "RUSTSEC-2026-0001".to_owned(),
                "RUSTSEC-2026-0002".to_owned()
            ]
        );
    }

    #[test]
    fn rejects_malformed_native_advisory_ignore_entries() {
        assert!(
            advisory_ignores_from_toml(
                r#"
[advisories]
ignore = [42]
"#
            )
            .is_err()
        );
        assert!(
            advisory_ignores_from_toml(
                r#"
[advisories]
ignore = [{ reason = "missing id" }]
"#
            )
            .is_err()
        );
        assert!(
            advisory_ignores_from_toml(
                r#"
[advisories]
ignore = [{ id = 42 }]
"#
            )
            .is_err()
        );
    }

    #[test]
    fn absent_deny_toml_uses_internal_default_base_for_configured_checks() {
        let generated = generate_cargo_deny_runtime_config(
            None,
            &[
                CargoDenyCheck::Advisories,
                CargoDenyCheck::Bans,
                CargoDenyCheck::Sources,
                CargoDenyCheck::Licenses,
            ],
        )
        .expect("config should generate");
        let parsed = parse(&generated);

        assert!(parsed.get("advisories").and_then(Value::as_table).is_some());
        assert_eq!(
            parsed.get("bans").and_then(Value::as_table),
            Some(&toml::map::Map::new())
        );
        assert_eq!(
            parsed.get("sources").and_then(Value::as_table),
            Some(&toml::map::Map::new())
        );
        assert_eq!(
            parsed.get("licenses").and_then(Value::as_table),
            Some(&toml::map::Map::new())
        );
    }

    #[test]
    fn default_base_relaxes_no_covered_check_group() {
        let generated = generate_cargo_deny_runtime_config(
            None,
            &[CargoDenyCheck::Bans, CargoDenyCheck::Sources],
        )
        .expect("config should generate");
        let parsed = parse(&generated);

        assert_eq!(
            parsed.get("bans").and_then(Value::as_table),
            Some(&toml::map::Map::new())
        );
        assert_eq!(
            parsed.get("sources").and_then(Value::as_table),
            Some(&toml::map::Map::new())
        );
        assert!(parsed.get("licenses").is_none());
    }

    fn parse(text: &str) -> toml::Table {
        toml::from_str::<Value>(text)
            .expect("generated TOML should parse")
            .as_table()
            .expect("generated TOML should be table")
            .clone()
    }
}
