use barbican::{TestRunner, VerifyConfig, default_member_doctest_packages, parse_cargo_metadata};
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use crate::cli::REVIEWED_TARGETS_CONFIG_FILE;
use crate::command_runner::CommandRunner;

use super::pin_check::enforce_reviewed_targets;
use super::toolchain;
use super::{CommandError, fail, load_config, load_reviewed_targets};

pub(super) fn run_verify<R>(
    current_dir: &Path,
    runner: &R,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<ExitCode, CommandError>
where
    R: CommandRunner + ?Sized,
{
    let config = load_config(current_dir)?.verify;
    let preflight = match toolchain::run_toolchain_check(
        current_dir,
        runner,
        config.test_runner,
        stdout,
        stderr,
    )? {
        toolchain::ToolchainCheckOutcome::Passed(preflight) => preflight,
        toolchain::ToolchainCheckOutcome::Failed(exit_code) => return Ok(exit_code),
    };

    run_reviewed_locked_verification(
        current_dir,
        runner,
        &preflight,
        &config,
        false,
        stdout,
        stderr,
    )
}

pub(super) fn run_verify_after_gatehouse_preflights<R>(
    current_dir: &Path,
    runner: &R,
    toolchain_preflight: &toolchain::CompletedToolchainPreflight,
    config: &VerifyConfig,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<ExitCode, CommandError>
where
    R: CommandRunner + ?Sized,
{
    run_reviewed_locked_verification(
        current_dir,
        runner,
        toolchain_preflight,
        config,
        true,
        stdout,
        stderr,
    )
}

fn run_reviewed_locked_verification<R>(
    current_dir: &Path,
    runner: &R,
    toolchain_preflight: &toolchain::CompletedToolchainPreflight,
    config: &VerifyConfig,
    audit_completed: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<ExitCode, CommandError>
where
    R: CommandRunner + ?Sized,
{
    let config_path = Path::new(REVIEWED_TARGETS_CONFIG_FILE);
    let Some(reviewed_targets) = load_reviewed_targets(current_dir, config_path)? else {
        return fail(
            stderr,
            format!("{REVIEWED_TARGETS_CONFIG_FILE}: reviewed-targets policy required for verify"),
        );
    };
    if reviewed_targets.rust_families().is_empty() {
        return fail(
            stderr,
            format!(
                "{REVIEWED_TARGETS_CONFIG_FILE}: no active Rust reviewed families; verify requires at least one"
            ),
        );
    }

    let pin_check_exit = enforce_reviewed_targets(
        &reviewed_targets,
        config_path,
        current_dir,
        toolchain_preflight.cargo_configs(),
        stdout,
    )?;
    if pin_check_exit != ExitCode::SUCCESS {
        return Ok(pin_check_exit);
    }

    // The build/test delegates stream through this process's terminal, so
    // flush our buffered report lines before each handoff or they can land
    // after the delegate's streamed output.
    stdout.flush().map_err(CommandError::Io)?;
    if let Err(error) = runner.cargo_build_locked(current_dir) {
        return fail(stderr, format!("cargo build --locked: {error}"));
    }
    writeln!(stdout, "OK   cargo build --locked").map_err(CommandError::Io)?;
    stdout.flush().map_err(CommandError::Io)?;
    match config.test_runner {
        TestRunner::CargoTest => {
            if let Err(error) = runner.cargo_test_locked(current_dir) {
                return fail(stderr, format!("cargo test --locked: {error}"));
            }
            writeln!(stdout, "OK   cargo test --locked").map_err(CommandError::Io)?;
        }
        TestRunner::Nextest => {
            let exit = run_nextest_verification(current_dir, runner, config, stdout, stderr)?;
            if exit != ExitCode::SUCCESS {
                return Ok(exit);
            }
        }
    }
    if !audit_completed {
        writeln!(
            stdout,
            "note: advisory audit is a separate gate; run cargo barbican audit"
        )
        .map_err(CommandError::Io)?;
    }
    writeln!(stdout, "Verify: PASS").map_err(CommandError::Io)?;

    Ok(ExitCode::SUCCESS)
}

fn run_nextest_verification<R: CommandRunner + ?Sized>(
    current_dir: &Path,
    runner: &R,
    config: &VerifyConfig,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<ExitCode, CommandError> {
    let version = config
        .nextest_version
        .as_ref()
        .expect("validated nextest policy has a version");
    let version_result = runner
        .cargo_nextest_version(current_dir)
        .map_err(|error| error.to_string())
        .and_then(|output| version.check_banner(&output));
    if let Err(error) = version_result {
        return fail(
            stderr,
            format!(
                "cargo nextest --version: {error}; install the consumer-reviewed pin with `cargo install --locked cargo-nextest@{}`",
                version.as_str()
            ),
        );
    }
    writeln!(
        stdout,
        "OK   cargo-nextest {} (exact runner pin)",
        version.as_str()
    )
    .map_err(CommandError::Io)?;
    stdout.flush().map_err(CommandError::Io)?;
    if let Err(error) = runner.cargo_nextest_run_locked(current_dir) {
        return fail(stderr, format!("cargo nextest run --locked: {error}"));
    }
    writeln!(stdout, "OK   cargo nextest run --locked").map_err(CommandError::Io)?;

    let packages = runner
        .cargo_metadata_frozen(current_dir)
        .map_err(|error| error.to_string())
        .and_then(|text| parse_cargo_metadata(&text).map_err(|error| error.to_string()))
        .and_then(|metadata| {
            default_member_doctest_packages(&metadata).map_err(|error| error.to_string())
        });
    let packages = match packages {
        Ok(packages) => packages,
        Err(error) => return fail(stderr, format!("Cargo doctest scope: {error}")),
    };
    if packages.is_empty() {
        writeln!(
            stdout,
            "note: no doctest-enabled libraries in the default package scope; doctests skipped"
        )
        .map_err(CommandError::Io)?;
    } else {
        stdout.flush().map_err(CommandError::Io)?;
        if let Err(error) = runner.cargo_doctest_locked(current_dir, &packages) {
            return fail(stderr, format!("cargo test --doc --locked: {error}"));
        }
        writeln!(stdout, "OK   cargo test --doc --locked").map_err(CommandError::Io)?;
    }
    Ok(ExitCode::SUCCESS)
}
