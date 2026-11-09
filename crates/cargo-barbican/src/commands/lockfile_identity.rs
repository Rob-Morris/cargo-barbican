use std::path::Path;

use barbican::cargo_config_lockfile_selection_key;

use crate::command_runner::{CommandRunner, cargo_home_from_environment};

use super::CommandError;
use super::loaders::{EffectiveCargoConfig, load_effective_cargo_configs};

pub(super) fn check_execution_root<R: CommandRunner + ?Sized>(
    current_dir: &Path,
    runner: &R,
) -> Result<(), CommandError> {
    let cargo_home = cargo_home_from_environment(|name| runner.environment_variable(name))
        .ok_or(CommandError::CargoHomeUnresolved)?;
    check_configs(&load_effective_cargo_configs(current_dir, &cargo_home)?)
}

pub(super) fn check_configs(configs: &[EffectiveCargoConfig]) -> Result<(), CommandError> {
    for config in configs {
        let key = cargo_config_lockfile_selection_key(&config.text).map_err(|_| {
            CommandError::CargoLockfileSelection(format!(
                "unable to inspect {} for Cargo lockfile selection: invalid Cargo configuration; correct its TOML before retrying",
                config.display_path
            ))
        })?;
        if let Some(key) = key {
            let reason = match key {
                "include" => "imports configuration whose lockfile selection cannot be established",
                "env.CARGO_RESOLVER_LOCKFILE_PATH" => {
                    "can reintroduce lockfile selection in child Cargo processes"
                }
                _ => "explicitly selects Cargo's lockfile",
            };
            return Err(CommandError::CargoLockfileSelection(format!(
                "{}: {key} {reason}; Barbican requires Cargo's default workspace Cargo.lock; remove {key} before retrying (explicit default paths are also unsupported)",
                config.display_path
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::commands::scratch_dir::ScratchDir;

    #[test]
    fn checks_the_captured_config_without_rereading_it() {
        let scratch = ScratchDir::create("barbican-lockfile-config", false).unwrap();
        let workspace = scratch.path().join("workspace");
        fs::create_dir_all(workspace.join(".cargo")).unwrap();
        let path = workspace.join(".cargo/config.toml");
        fs::write(&path, "resolver.lockfile-path = 'alternate/Cargo.lock'").unwrap();
        let configs =
            load_effective_cargo_configs(&workspace, &scratch.path().join("home")).unwrap();
        fs::write(&path, "[build]\njobs = 2").unwrap();
        assert!(check_configs(&configs).is_err());
        let configs =
            load_effective_cargo_configs(&workspace, &scratch.path().join("home")).unwrap();
        assert!(check_configs(&configs).is_ok());
    }

    #[test]
    fn diagnostics_never_echo_config_values_or_parse_error_source() {
        for text in [
            "resolver.lockfile-path = 'private-secret/Cargo.lock'",
            "resolver.lockfile-path = 'private-secret",
            "[env]\nCARGO_RESOLVER_LOCKFILE_PATH = 'private-secret'",
        ] {
            let error = check_configs(&[EffectiveCargoConfig {
                display_path: "config\u{1b}[0m.toml".into(),
                text: text.into(),
            }])
            .unwrap_err()
            .to_string();
            assert!(!error.contains("private-secret"));
            assert!(!error.contains('\u{1b}'));
        }
    }
}
