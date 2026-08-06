use std::fs;
use std::io;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use barbican::{
    CARGO_TOOLCHAIN_EXECUTABLE_CONTROLS, ExactRustToolchainChannel,
    cargo_config_toolchain_executable_control_key, evaluate_rust_toolchain_conformance,
    parse_rust_toolchain_toml,
};

use crate::command_runner::{CommandRunner, cargo_home_from_environment};

use super::loaders::{
    EffectiveCargoConfig, load_effective_cargo_configs, read_optional_text_path_no_symlink,
};
use super::{CommandError, escape_diagnostic_for_terminal, fail};

pub(super) const RUST_TOOLCHAIN_TOML: &str = "rust-toolchain.toml";
pub(super) const GENERATED_RUSTUP_PROFILE: &str = "minimal";
const LEGACY_RUST_TOOLCHAIN: &str = "rust-toolchain";

pub(super) enum ToolchainPinState {
    Missing,
    Valid(ExactRustToolchainChannel),
    Invalid(String),
}

pub(super) struct CompletedToolchainPreflight {
    cargo_configs: Vec<EffectiveCargoConfig>,
}

impl CompletedToolchainPreflight {
    pub(super) fn cargo_configs(&self) -> &[EffectiveCargoConfig] {
        &self.cargo_configs
    }
}

pub(super) enum ToolchainCheckOutcome {
    Passed(CompletedToolchainPreflight),
    Failed(ExitCode),
}

pub(super) fn inspect_toolchain_pin(current_dir: &Path) -> ToolchainPinState {
    if let Some(detail) = legacy_toolchain_detail(current_dir) {
        return ToolchainPinState::Invalid(detail);
    }

    let path = current_dir.join(RUST_TOOLCHAIN_TOML);
    let text = match read_optional_text_path_no_symlink(&path) {
        Ok(Some(text)) => text,
        Ok(None) => return ToolchainPinState::Missing,
        Err(error) => {
            return ToolchainPinState::Invalid(format!(
                "unable to inspect {RUST_TOOLCHAIN_TOML}: {error}"
            ));
        }
    };
    match parse_rust_toolchain_toml(&text) {
        Ok(pin) => ToolchainPinState::Valid(pin),
        Err(error) => ToolchainPinState::Invalid(error.to_string()),
    }
}

fn legacy_toolchain_detail(current_dir: &Path) -> Option<String> {
    match fs::symlink_metadata(current_dir.join(LEGACY_RUST_TOOLCHAIN)) {
        Ok(_) => Some(format!(
            "{LEGACY_RUST_TOOLCHAIN} shadows {RUST_TOOLCHAIN_TOML} under rustup; remove it and keep one canonical {RUST_TOOLCHAIN_TOML}"
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => Some(format!(
            "unable to inspect {LEGACY_RUST_TOOLCHAIN}: {error}"
        )),
    }
}

pub(super) fn render_toolchain_toml(pin: &ExactRustToolchainChannel) -> String {
    format!(
        "[toolchain]\nchannel = \"{}\"\nprofile = \"{GENERATED_RUSTUP_PROFILE}\"\n",
        pin.as_str(),
    )
}

pub(super) fn run_toolchain_check<R>(
    current_dir: &Path,
    runner: &R,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<ToolchainCheckOutcome, CommandError>
where
    R: CommandRunner + ?Sized,
{
    writeln!(stdout, "Toolchain check:").map_err(CommandError::Io)?;

    let pin = match inspect_toolchain_pin(current_dir) {
        ToolchainPinState::Missing => {
            return toolchain_failure(
                stdout,
                stderr,
                format!(
                    "{RUST_TOOLCHAIN_TOML}: exact Rust toolchain policy required; run `cargo barbican policy init --toolchain <exact-channel>`"
                ),
            );
        }
        ToolchainPinState::Invalid(detail) => {
            return toolchain_failure(stdout, stderr, detail);
        }
        ToolchainPinState::Valid(pin) => pin,
    };

    if let Some(name) = CARGO_TOOLCHAIN_EXECUTABLE_CONTROLS
        .iter()
        .flat_map(|control| control.environment_names.iter().copied())
        .find(|name| runner.environment_variable(name).is_some())
    {
        return toolchain_failure(
            stdout,
            stderr,
            format!(
                "{name} controls Cargo's Rust toolchain executable selection; unset it so {RUST_TOOLCHAIN_TOML} remains authoritative"
            ),
        );
    }

    let cargo_configs = match establish_toolchain_config_snapshot(current_dir, runner) {
        Ok(configs) => configs,
        Err(detail) => return toolchain_failure(stdout, stderr, detail),
    };

    let active = match runner.rustup_active_toolchain(current_dir) {
        Ok(output) => output,
        Err(error) => {
            return toolchain_failure(
                stdout,
                stderr,
                format!(
                    "unable to establish the active rustup toolchain: {error}; install rustup and ensure `rustup` is on PATH"
                ),
            );
        }
    };
    let cargo = match runner.cargo_verbose_version(current_dir) {
        Ok(output) => output,
        Err(error) => {
            return toolchain_failure(
                stdout,
                stderr,
                format!("unable to establish the active Cargo version: {error}"),
            );
        }
    };
    let rustc = match runner.rustc_verbose_version(current_dir) {
        Ok(output) => output,
        Err(error) => {
            return toolchain_failure(
                stdout,
                stderr,
                format!("unable to establish the active rustc version: {error}"),
            );
        }
    };
    let rustdoc = match runner.rustdoc_verbose_version(current_dir) {
        Ok(output) => output,
        Err(error) => {
            return toolchain_failure(
                stdout,
                stderr,
                format!("unable to establish the active rustdoc version: {error}"),
            );
        }
    };
    let conformance =
        match evaluate_rust_toolchain_conformance(&pin, &active, &cargo, &rustc, &rustdoc) {
            Ok(conformance) => conformance,
            Err(error) => return toolchain_failure(stdout, stderr, error.to_string()),
        };

    writeln!(stdout, "OK   {RUST_TOOLCHAIN_TOML} pins {}", pin.as_str())
        .map_err(CommandError::Io)?;
    writeln!(
        stdout,
        "OK   active Cargo/rustc/rustdoc {} ({})",
        conformance.release, conformance.host
    )
    .map_err(CommandError::Io)?;
    writeln!(stdout, "Toolchain check: PASS").map_err(CommandError::Io)?;
    Ok(ToolchainCheckOutcome::Passed(CompletedToolchainPreflight {
        cargo_configs,
    }))
}

fn establish_toolchain_config_snapshot<R>(
    current_dir: &Path,
    runner: &R,
) -> Result<Vec<EffectiveCargoConfig>, String>
where
    R: CommandRunner + ?Sized,
{
    let Some(cargo_home) = cargo_home_from_environment(|name| runner.environment_variable(name))
    else {
        return Err(
            "unable to establish Cargo home: neither CARGO_HOME nor HOME is set; set one so user-level Cargo toolchain controls can be inspected"
                .to_owned(),
        );
    };
    establish_toolchain_config_snapshot_with_home(current_dir, &cargo_home)
}

fn establish_toolchain_config_snapshot_with_home(
    current_dir: &Path,
    cargo_home: &Path,
) -> Result<Vec<EffectiveCargoConfig>, String> {
    let configs =
        load_effective_cargo_configs(current_dir, cargo_home).map_err(|error| error.to_string())?;
    for config in &configs {
        match cargo_config_toolchain_executable_control_key(&config.text) {
            Ok(Some("include")) => {
                return Err(format!(
                    "{} includes indirect Cargo configuration whose toolchain effect cannot be established; remove the include before running the gate",
                    config.display_path
                ));
            }
            Ok(Some(key)) => {
                return Err(format!(
                    "{} {key} controls Cargo's Rust toolchain executable selection; remove it so {RUST_TOOLCHAIN_TOML} remains authoritative",
                    config.display_path
                ));
            }
            Ok(None) => {}
            Err(error) => {
                return Err(format!(
                    "unable to inspect {}: {error}",
                    config.display_path
                ));
            }
        }
    }
    Ok(configs)
}

fn toolchain_failure(
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    detail: String,
) -> Result<ToolchainCheckOutcome, CommandError> {
    writeln!(stdout, "Toolchain check: FAIL").map_err(CommandError::Io)?;
    fail(stderr, escape_diagnostic_for_terminal(&detail)).map(ToolchainCheckOutcome::Failed)
}

#[cfg(test)]
mod tests {
    use super::super::scratch_dir::ScratchDir;
    use super::establish_toolchain_config_snapshot_with_home;
    use std::fs;

    #[test]
    fn inspects_cargo_home_compiler_overrides() {
        let temp_dir = ScratchDir::create("cargo-barbican-toolchain-test", false)
            .expect("test directory should exist");
        let workspace = temp_dir.path().join("workspace");
        let cargo_home = temp_dir.path().join("cargo-home");
        fs::create_dir_all(&workspace).expect("workspace should exist");
        fs::create_dir_all(&cargo_home).expect("cargo home should exist");
        fs::write(
            cargo_home.join("config.toml"),
            "[build]\nrustc = '/opt/home-rustc'\n",
        )
        .expect("cargo-home config should write");

        let detail = establish_toolchain_config_snapshot_with_home(&workspace, &cargo_home)
            .expect_err("cargo-home compiler override should fail");

        assert!(detail.contains("cargo-home/config.toml"));
        assert!(
            detail.contains("build.rustc controls Cargo's Rust toolchain executable selection")
        );
    }
}
