use super::{repo, store::PrivateStore};
use std::env;
use std::path::{Path, PathBuf};

pub(super) struct Stores {
    pub data: PrivateStore,
    pub cache: PrivateStore,
}
impl Stores {
    pub fn open(
        current: &Path,
        repo_root: Option<&Path>,
        data: Option<&Path>,
        cache: Option<&Path>,
    ) -> Result<Self, String> {
        if data.is_none() || cache.is_none() {
            reject_cargo_root_controls(current)?;
        }
        let data_path = match data {
            Some(path) => explicit(current, path),
            None => default_data()?,
        };
        let cache_path = match cache {
            Some(path) => explicit(current, path),
            None => default_cache()?,
        };
        let forbidden: Vec<&Path> = repo_root.into_iter().collect();
        let data = PrivateStore::open(&data_path, &forbidden)?;
        let mut cache_forbidden = forbidden;
        cache_forbidden.push(data.root());
        let cache = PrivateStore::open(&cache_path, &cache_forbidden)?;
        Ok(Self { data, cache })
    }
}
fn explicit(current: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_owned()
    } else {
        current.join(path)
    }
}
fn home() -> Result<PathBuf, String> {
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or("HOME is unavailable; supply explicit --data-dir and --cache-dir")?;
    if !home.is_absolute() {
        return Err("HOME must be absolute; supply explicit --data-dir and --cache-dir".into());
    }
    Ok(home)
}
fn default_data() -> Result<PathBuf, String> {
    if cfg!(target_os = "macos") {
        return Ok(home()?.join("Library/Application Support/cargo-barbican"));
    }
    if cfg!(target_os = "linux") {
        return Ok(xdg("XDG_DATA_HOME", home()?.join(".local/share"))?.join("cargo-barbican"));
    }
    Err("local toolchain trust storage is qualified only on macOS and Linux; supply explicit private roots on supported hosts".into())
}
fn default_cache() -> Result<PathBuf, String> {
    if cfg!(target_os = "macos") {
        return Ok(home()?.join("Library/Caches/cargo-barbican"));
    }
    if cfg!(target_os = "linux") {
        return Ok(xdg("XDG_CACHE_HOME", home()?.join(".cache"))?.join("cargo-barbican"));
    }
    Err("local toolchain cache storage is qualified only on macOS and Linux".into())
}
fn xdg(name: &str, fallback: PathBuf) -> Result<PathBuf, String> {
    match env::var_os(name) {
        None => Ok(fallback),
        Some(value) if value.is_empty() => Ok(fallback),
        Some(value) => {
            let path = PathBuf::from(value);
            if !path.is_absolute() {
                Err(format!("{name} must be absolute"))
            } else {
                Ok(path)
            }
        }
    }
}
fn reject_cargo_root_controls(current: &Path) -> Result<(), String> {
    let mut dirs: Vec<_> = current.ancestors().map(|p| p.join(".cargo")).collect();
    let cargo = env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .unwrap_or(home()?.join(".cargo"));
    let cargo = explicit(current, &cargo);
    if !dirs.contains(&cargo) {
        dirs.push(cargo);
    }
    for directory in dirs {
        for name in ["config", "config.toml"] {
            if let Some(bytes) = repo::read_optional(&directory, Path::new(name))? {
                let text = std::str::from_utf8(&bytes).map_err(|e| e.to_string())?;
                if barbican::cargo_config::cargo_config_defines_environment(
                    text,
                    &[
                        "HOME",
                        "XDG_DATA_HOME",
                        "XDG_CACHE_HOME",
                        "CARGO_HOME",
                        "RUSTUP_HOME",
                    ],
                )
                .map_err(|e| e.to_string())?
                {
                    return Err("Cargo configuration can redirect inherited storage roots; use direct trusted cargo-barbican with explicit --data-dir and --cache-dir".into());
                }
                break;
            }
        }
    }
    Ok(())
}

pub(super) fn validate_native_selection(
    root: &Path,
    rustup_home: &Path,
    accepted_slot: Option<&str>,
) -> Result<(), String> {
    use barbican::cargo_config::{
        CARGO_TOOLCHAIN_EXECUTABLE_CONTROLS, cargo_config_defines_environment,
        cargo_config_toolchain_executable_control_key,
    };
    for name in ["HOME", "CARGO_HOME", "RUSTUP_HOME"] {
        if std::env::var_os(name).is_some_and(|value| !Path::new(&value).is_absolute()) {
            return Err(format!(
                "relative {name} can change meaning before Cargo discovery; use an absolute operator-controlled root"
            ));
        }
    }
    if let Some(value) = std::env::var_os("RUSTUP_TOOLCHAIN")
        && accepted_slot.is_none_or(|slot| value.to_str() != Some(slot))
    {
        return Err("ambient RUSTUP_TOOLCHAIN does not exactly name the fully qualified accepted slot; remove it or select that exact slot".into());
    }
    for name in [
        "RUSTUP_DIST_SERVER",
        "RUSTUP_DIST_ROOT",
        "RUSTUP_OVERRIDE_HOST_TRIPLE",
        "RUSTUP_UPDATE_ROOT",
        "RUSTUP_OVERRIDE_UNIX_FALLBACK_SETTINGS",
        "RUSTUP_FORCE_ARG0",
    ] {
        if std::env::var_os(name).is_some() {
            return Err(format!(
                "ambient {name} prevents static proof of the pinned toolchain selection; remove it for the governed operation"
            ));
        }
    }
    let mut names = vec![
        "HOME",
        "CARGO_HOME",
        "RUSTUP_HOME",
        "XDG_DATA_HOME",
        "XDG_CACHE_HOME",
        "RUSTUP_TOOLCHAIN",
        "RUSTUP_DIST_SERVER",
        "RUSTUP_DIST_ROOT",
        "RUSTUP_OVERRIDE_HOST_TRIPLE",
        "RUSTUP_UPDATE_ROOT",
        "RUSTUP_OVERRIDE_UNIX_FALLBACK_SETTINGS",
        "RUSTUP_FORCE_ARG0",
    ];
    for control in CARGO_TOOLCHAIN_EXECUTABLE_CONTROLS {
        for name in control.environment_names {
            if std::env::var_os(name).is_some() {
                return Err(format!(
                    "ambient {name} can select a different executable before admission"
                ));
            }
            names.push(name);
        }
    }
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .unwrap_or(home()?.join(".cargo"));
    for config in crate::commands::load_effective_cargo_configs(root, &cargo_home)
        .map_err(|e| e.to_string())?
    {
        if cargo_config_defines_environment(&config.text, &names).map_err(|e| e.to_string())? {
            return Err(format!(
                "effective Cargo configuration {} controls inherited authority or executable selection; remove that control before a governed operation",
                config.display_path
            ));
        }
        if let Some(key) = cargo_config_toolchain_executable_control_key(&config.text)
            .map_err(|e| e.to_string())?
        {
            return Err(format!(
                "effective Cargo configuration {} sets {key} before toolchain admission",
                config.display_path
            ));
        }
    }
    match std::fs::symlink_metadata("/etc/rustup/settings.toml") {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => {
            return Err(
                "system Rustup fallback settings require separate selection qualification".into(),
            );
        }
    }
    if !rustup_home.is_absolute() {
        return Err("Rustup home must be absolute before governed selection".into());
    }
    let settings = repo::read_optional(rustup_home, Path::new("settings.toml"))?;
    if let Some(host) = barbican::rust_distribution::rustup_configured_host(settings.as_deref())
        .map_err(|e| e.to_string())?
        && accepted_slot.and_then(|slot| slot.split_once('-').map(|(_, host)| host))
            != Some(host.as_str())
    {
        return Err(
            "Rustup configured default_host_triple does not match the accepted native host".into(),
        );
    }
    let root = std::fs::canonicalize(root).map_err(|e| e.to_string())?;
    for (path, _) in barbican::rust_distribution::rustup_directory_overrides(settings.as_deref())
        .map_err(|e| e.to_string())?
    {
        let path = PathBuf::from(path);
        if !path.is_absolute()
            || path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err("unqualified Rustup directory override path".into());
        }
        let equivalent =
            path == root || std::fs::canonicalize(&path).is_ok_and(|path| path == root);
        if equivalent {
            return Err("Rustup directory override at the governance root takes precedence over rust-toolchain.toml; remove it before governed selection".into());
        }
    }
    Ok(())
}
