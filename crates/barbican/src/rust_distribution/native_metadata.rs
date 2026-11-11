//! Rustup 1.29's generated metadata is consistency evidence, never payload authority.
use super::{DistributionError, Selection, invalid};
use std::collections::{BTreeMap, BTreeSet};
use toml::Value;

fn parse(bytes: &[u8]) -> Result<Value, DistributionError> {
    if bytes.len() > 8 * 1024 * 1024 {
        return Err(invalid("installed metadata byte limit"));
    }
    toml::from_str(std::str::from_utf8(bytes).map_err(|_| invalid("metadata is not UTF-8"))?)
        .map_err(|e| invalid(format!("installed metadata TOML: {e}")))
}
fn table(value: &Value) -> Result<&toml::map::Map<String, Value>, DistributionError> {
    value
        .as_table()
        .ok_or_else(|| invalid("expected metadata table"))
}
fn required(value: &Value, key: &str) -> Result<Value, DistributionError> {
    value
        .get(key)
        .cloned()
        .ok_or_else(|| invalid(format!("missing metadata {key}")))
}
fn object(fields: impl IntoIterator<Item = (String, Value)>) -> Value {
    Value::Table(fields.into_iter().collect())
}

/// Mirrors the closed serialization projection in Rustup commit 28d1352's dist/manifest.rs.
pub fn rustup_manifest_projection(original: &[u8]) -> Result<Value, DistributionError> {
    let original = parse(original)?;
    let mut packages = BTreeMap::new();
    for (name, package) in table(&required(&original, "pkg")?)? {
        let mut targets = BTreeMap::new();
        for (target_name, target) in table(&required(package, "target")?)? {
            let available = required(target, "available")?
                .as_bool()
                .ok_or_else(|| invalid("invalid availability"))?;
            let mut fields = BTreeMap::new();
            let mut has_binary = false;
            for (url, hash) in [
                ("url", "hash"),
                ("xz_url", "xz_hash"),
                ("zst_url", "zst_hash"),
            ] {
                if available && let (Some(u), Some(h)) = (target.get(url), target.get(hash)) {
                    if !u.is_str() || !h.is_str() {
                        return Err(invalid("invalid archive metadata"));
                    }
                    fields.insert(url.to_owned(), u.clone());
                    fields.insert(hash.to_owned(), h.clone());
                    has_binary = true;
                }
            }
            fields.insert("available".into(), Value::Boolean(has_binary));
            let mut components = Vec::new();
            let mut extensions = Vec::new();
            for (key, extension) in [("components", false), ("extensions", true)] {
                if let Some(value) = target.get(key) {
                    for component in value
                        .as_array()
                        .ok_or_else(|| invalid("invalid component list"))?
                    {
                        let is_extension = extension
                            || component
                                .get("is_extension")
                                .map(|v| {
                                    v.as_bool().ok_or_else(|| invalid("invalid extension flag"))
                                })
                                .transpose()?
                                .unwrap_or(false);
                        let pkg = required(component, "pkg")?;
                        let target = required(component, "target")?;
                        if !pkg.is_str() || !target.is_str() {
                            return Err(invalid("invalid component identity"));
                        }
                        let component = object([
                            ("pkg".into(), pkg),
                            ("target".into(), target),
                            ("is_extension".into(), Value::Boolean(is_extension)),
                        ]);
                        if is_extension {
                            extensions.push(component);
                        } else {
                            components.push(component);
                        }
                    }
                }
            }
            fields.insert("components".into(), Value::Array(components));
            fields.insert("extensions".into(), Value::Array(extensions));
            targets.insert(target_name.clone(), object(fields));
        }
        packages.insert(
            name.clone(),
            object([
                ("version".into(), required(package, "version")?),
                ("target".into(), object(targets)),
            ]),
        );
    }
    let mut renames = BTreeMap::new();
    if let Some(value) = original.get("renames") {
        for (name, rename) in table(value)? {
            renames.insert(
                name.clone(),
                object([("to".into(), required(rename, "to")?)]),
            );
        }
    }
    Ok(object([
        (
            "manifest-version".into(),
            required(&original, "manifest-version")?,
        ),
        ("date".into(), required(&original, "date")?),
        ("pkg".into(), object(packages)),
        ("renames".into(), object(renames)),
        (
            "profiles".into(),
            original
                .get("profiles")
                .cloned()
                .unwrap_or_else(|| object([])),
        ),
    ]))
}

pub fn check_rustup_manifest(original: &[u8], installed: &[u8]) -> Result<(), DistributionError> {
    if rustup_manifest_projection(original)? != parse(installed)? {
        return Err(invalid(
            "installed channel metadata differs from original accepted manifest projection",
        ));
    }
    Ok(())
}

/// Untrusted installed claims, suitable only for selecting an independently verified subset.
pub fn rustup_configured_components(
    original: &[u8],
    host: &str,
    installed: &[u8],
) -> Result<BTreeMap<(String, String), bool>, DistributionError> {
    let projection = rustup_manifest_projection(original)?;
    let extensions = projection
        .get("pkg")
        .and_then(|v| v.get("rust"))
        .and_then(|v| v.get("target"))
        .and_then(|v| v.get(host))
        .and_then(|v| v.get("extensions"))
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("missing original host extensions"))?;
    let value = parse(installed)?;
    let root = table(&value)?;
    if root.len() != 2 || value.get("config_version").and_then(Value::as_str) != Some("1") {
        return Err(invalid("unsupported installed config"));
    }
    let components = value
        .get("components")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("missing configured components"))?;
    let mut actual = BTreeMap::new();
    for component in components {
        let extension = component
            .get("is_extension")
            .and_then(Value::as_bool)
            .ok_or_else(|| invalid("missing component extension flag"))?;
        if table(component)?.len() != 3 || (extension && !extensions.contains(component)) {
            return Err(invalid("unqualified installed component config"));
        }
        let package = component
            .get("pkg")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("missing component package"))?;
        let target = component
            .get("target")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("missing component target"))?;
        if actual
            .insert((package.to_owned(), target.to_owned()), extension)
            .is_some()
        {
            return Err(invalid("duplicate configured component"));
        }
    }
    Ok(actual)
}

pub fn check_rustup_config(
    selection: &Selection,
    original: &[u8],
    installed: &[u8],
) -> Result<(), DistributionError> {
    let actual = rustup_configured_components(original, &selection.host, installed)?;
    let expected: BTreeSet<_> = selection
        .archives
        .iter()
        .map(|a| (a.package.clone(), a.target.clone()))
        .collect();
    if actual.into_keys().collect::<BTreeSet<_>>() != expected {
        return Err(invalid(
            "installed component scope differs; explicitly review expanded scope",
        ));
    }
    Ok(())
}

pub fn rustup_default(settings: Option<&[u8]>) -> Result<Option<String>, DistributionError> {
    let Some(settings) = settings else {
        return Ok(None);
    };
    let value = parse(settings)?;
    table(&value)?;
    if value.get("version").and_then(Value::as_str) != Some("12") {
        return Err(invalid("unqualified Rustup settings version"));
    }
    value
        .get("default_toolchain")
        .map(|v| {
            v.as_str()
                .filter(|s| !s.is_empty() && !s.chars().any(char::is_control))
                .map(str::to_owned)
                .ok_or_else(|| invalid("invalid Rustup default"))
        })
        .transpose()
}

/// Only the explicitly intended native default assignment may differ.
pub fn check_rustup_default_assignment(
    before: Option<&[u8]>,
    after: &[u8],
    assigned: &str,
) -> Result<(), DistributionError> {
    let mut expected = match before {
        Some(bytes) => parse(bytes)?,
        None => object([("version".into(), Value::String("12".into()))]),
    };
    expected
        .as_table_mut()
        .ok_or_else(|| invalid("settings must be a table"))?
        .insert("default_toolchain".into(), Value::String(assigned.into()));
    expected
        .as_table_mut()
        .expect("checked table")
        .entry("overrides".to_owned())
        .or_insert_with(|| object([]));
    if parse(after)? != expected {
        return Err(invalid(
            "Rustup settings/default changed outside the owned assignment",
        ));
    }
    Ok(())
}

pub fn check_rustup_default_restoration(
    before: Option<&[u8]>,
    after: &[u8],
) -> Result<(), DistributionError> {
    let mut expected = match before {
        Some(bytes) => parse(bytes)?,
        None => object([("version".into(), Value::String("12".into()))]),
    };
    expected
        .as_table_mut()
        .ok_or_else(|| invalid("settings must be a table"))?
        .entry("overrides".to_owned())
        .or_insert_with(|| object([]));
    if parse(after)? != expected {
        return Err(invalid(
            "native default unset did not preserve captured settings",
        ));
    }
    Ok(())
}

/// Static selection facts only; no Rustup executable or candidate is consulted.
pub fn rustup_directory_overrides(
    settings: Option<&[u8]>,
) -> Result<Vec<(String, String)>, DistributionError> {
    let Some(settings) = settings else {
        return Ok(Vec::new());
    };
    rustup_default(Some(settings))?;
    let value = parse(settings)?;
    let Some(overrides) = value.get("overrides") else {
        return Ok(Vec::new());
    };
    let overrides = overrides
        .as_table()
        .ok_or_else(|| invalid("Rustup overrides must be a table"))?;
    overrides
        .iter()
        .map(|(path, value)| {
            let toolchain = value
                .as_str()
                .filter(|value| !value.is_empty() && !value.chars().any(char::is_control))
                .ok_or_else(|| invalid("invalid Rustup directory override"))?;
            if path.is_empty() || path.chars().any(char::is_control) {
                return Err(invalid("invalid Rustup directory override path"));
            }
            Ok((path.clone(), toolchain.to_owned()))
        })
        .collect()
}

/// An unqualified pin resolves through this configured host before native fallback.
pub fn rustup_configured_host(
    settings: Option<&[u8]>,
) -> Result<Option<String>, DistributionError> {
    let Some(settings) = settings else {
        return Ok(None);
    };
    rustup_default(Some(settings))?;
    parse(settings)?
        .get("default_host_triple")
        .map(|value| {
            value
                .as_str()
                .filter(|host| {
                    !host.is_empty()
                        && host.len() <= 128
                        && host
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
                })
                .map(str::to_owned)
                .ok_or_else(|| invalid("invalid Rustup configured host"))
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn projection_checks_generated_normalisation_and_rejects_unknown_installed_fields() {
        let original=b"manifest-version='2'\ndate='2026-10-15'\n[pkg.rust]\nversion='1.99.1'\ngit_commit_hash='source-only'\n[pkg.rust.target.host]\navailable=true\nurl='official'\nhash='digest'\ncomponents=[{pkg='rustc',target='host'}]\nextensions=[{pkg='cargo',target='host'}]\n";
        let projected = rustup_manifest_projection(original).unwrap();
        let text = toml::to_string(&projected).unwrap();
        check_rustup_manifest(original, text.as_bytes()).unwrap();
        assert!(!text.contains("git_commit_hash"));
        assert_eq!(
            projected["pkg"]["rust"]["target"]["host"]["extensions"][0]["is_extension"].as_bool(),
            Some(true)
        );
        let changed = text.replace("digest", "other");
        assert!(check_rustup_manifest(original, changed.as_bytes()).is_err());
        let mut changed = projected.clone();
        changed
            .as_table_mut()
            .unwrap()
            .insert("unknown".into(), Value::Boolean(true));
        assert!(
            check_rustup_manifest(original, toml::to_string(&changed).unwrap().as_bytes()).is_err()
        );
    }
    #[test]
    fn configured_extension_flags_are_bound_to_original_host_closure() {
        let original = b"manifest-version='2'\ndate='2026-10-15'\n[pkg.rust]\nversion='1.99.1'\n[pkg.rust.target.host]\navailable=true\nextensions=[{pkg='rust-src',target='*'}]\n";
        for flag in [false, true] {
            let text = format!(
                "config_version='1'\ncomponents=[{{pkg='rust-src',target='*',is_extension={flag}}}]\n"
            );
            assert_eq!(
                rustup_configured_components(original, "host", text.as_bytes()).unwrap(),
                BTreeMap::from([(("rust-src".into(), "*".into()), flag)])
            );
        }
        for component in [
            "{pkg='rust-src',target='host',is_extension=true}",
            "{pkg='rustc',target='host',is_extension=true}",
            "{pkg='rust-src',is_extension=true}",
            "{pkg='rust-src',target='*',is_extension='true'}",
            "{pkg='rust-src',target='*',is_extension=true,unknown=1}",
        ] {
            let text = format!("config_version='1'\ncomponents=[{component}]\n");
            assert!(rustup_configured_components(original, "host", text.as_bytes()).is_err());
        }
        let duplicate = b"config_version='1'\ncomponents=[{pkg='rust-src',target='*',is_extension=false},{pkg='rust-src',target='*',is_extension=true}]\n";
        assert!(rustup_configured_components(original, "host", duplicate).is_err());
    }
    #[test]
    fn default_ownership_preserves_other_settings_and_normalises_only_empty_overrides() {
        let after = b"version='12'\ndefault_toolchain='1.99.1-host'\n[overrides]\n";
        check_rustup_default_assignment(None, after, "1.99.1-host").unwrap();
        check_rustup_default_restoration(None, b"version='12'\n[overrides]\n").unwrap();
        assert!(
            check_rustup_default_assignment(
                None,
                b"version='12'\ndefault_toolchain='1.99.1-host'\nprofile='complete'\n[overrides]\n",
                "1.99.1-host"
            )
            .is_err()
        );
        assert!(check_rustup_default_restoration(None, after).is_err());
    }
}
