//! Static Cargo input interpretation before a trusted process sees candidate files.
use serde_json::Value;

pub fn source_manifest(text: &str) -> Result<Value, String> {
    let parsed: toml::Value = toml::from_str(text).map_err(|e| e.to_string())?;
    if !parsed.is_table() {
        return Err("Cargo manifest must be a table".into());
    }
    serde_json::to_value(parsed).map_err(|e| e.to_string())
}

/// Only the ordinary destination is inherited; executable and resolver semantics
/// are deliberately supplied by the qualified tool adapter.
pub fn tool_config_install_root(text: &str) -> Result<Option<String>, String> {
    let parsed: toml::Table = toml::from_str(text).map_err(|e| e.to_string())?;
    for (key, value) in &parsed {
        if key != "install"
            || value
                .as_table()
                .is_none_or(|table| table.keys().any(|key| key != "root"))
        {
            return Err(format!(
                "Cargo configuration key {key} is outside the qualified tool context"
            ));
        }
    }
    parsed
        .get("install")
        .and_then(|v| v.get("root"))
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| "Cargo install.root must be a string".into())
        })
        .transpose()
}

pub fn source_version_timestamp(value: &str) -> Result<u64, String> {
    let time = time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .map_err(|e| e.to_string())?;
    u64::try_from(time.unix_timestamp_nanos())
        .map_err(|_| "source update time is outside supported timestamp range".into())
}
