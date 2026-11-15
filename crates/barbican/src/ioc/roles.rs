use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildScriptRole {
    Auto,
    Disabled,
    Path(String),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestRoles {
    pub proc_macro: bool,
    pub proc_macro_path: Option<String>,
    pub build_script: BuildScriptRole,
    pub package_links: Option<String>,
}

pub fn manifest_roles(manifest: &Value) -> Result<ManifestRoles, String> {
    if !manifest.is_object() {
        return Err("Cargo manifest must be a table".into());
    }
    let package = manifest
        .get("package")
        .map(|value| value.as_object().ok_or("Cargo package must be a table"))
        .transpose()?;
    let lib = manifest
        .get("lib")
        .map(|value| value.as_object().ok_or("Cargo lib must be a table"))
        .transpose()?;
    let mut proc_macro = false;
    let mut lib_path = None;
    if let Some(lib) = lib {
        if let Some(value) = aliased(lib, "proc-macro", "proc_macro")? {
            proc_macro = value
                .as_bool()
                .ok_or("Cargo proc-macro role must be boolean")?;
        }
        if let Some(value) = aliased(lib, "crate-type", "crate_type")? {
            let types = value
                .as_array()
                .ok_or("Cargo crate-type must be an array")?;
            for value in types {
                let kind = value
                    .as_str()
                    .ok_or("Cargo crate-type entries must be strings")?;
                if kind == "proc-macro" {
                    proc_macro = true;
                }
            }
        }
        if let Some(value) = lib.get("path") {
            lib_path = Some(
                value
                    .as_str()
                    .ok_or("Cargo lib.path must be a string")?
                    .to_owned(),
            );
        }
    }
    let build_script = match package.and_then(|package| package.get("build")) {
        None => BuildScriptRole::Auto,
        Some(Value::Bool(false)) => BuildScriptRole::Disabled,
        Some(Value::Bool(true)) => BuildScriptRole::Path("build.rs".into()),
        Some(Value::String(path)) => BuildScriptRole::Path(path.clone()),
        Some(_) => return Err("Cargo package.build must be a boolean or path".into()),
    };
    let package_links = package
        .and_then(|package| package.get("links"))
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or("Cargo package.links must be a string")
        })
        .transpose()?;
    Ok(ManifestRoles {
        proc_macro,
        proc_macro_path: proc_macro.then(|| lib_path.unwrap_or_else(|| "src/lib.rs".into())),
        build_script,
        package_links,
    })
}
fn aliased<'a>(
    table: &'a serde_json::Map<String, Value>,
    canonical: &str,
    alias: &str,
) -> Result<Option<&'a Value>, String> {
    if table.contains_key(canonical) && table.contains_key(alias) {
        return Err(format!(
            "Cargo {canonical} and {alias} cannot both define one role"
        ));
    }
    Ok(table.get(canonical).or_else(|| table.get(alias)))
}
