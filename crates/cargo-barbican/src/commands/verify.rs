use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use crate::cli::REVIEWED_TARGETS_CONFIG_FILE;
use crate::command_runner::CommandRunner;

use super::pin_check::enforce_reviewed_targets;
use super::toolchain;
use super::{CommandError, fail, load_reviewed_targets};

pub(super) fn run_verify<R>(
    current_dir: &Path,
    runner: &R,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<ExitCode, CommandError>
where
    R: CommandRunner + ?Sized,
{
    let preflight = match toolchain::run_toolchain_check(current_dir, runner, stdout, stderr)? {
        toolchain::ToolchainCheckOutcome::Passed(preflight) => preflight,
        toolchain::ToolchainCheckOutcome::Failed(exit_code) => return Ok(exit_code),
    };

    run_reviewed_locked_verification(current_dir, runner, &preflight, false, stdout, stderr)
}

pub(super) fn run_verify_after_gatehouse_preflights<R>(
    current_dir: &Path,
    runner: &R,
    toolchain_preflight: &toolchain::CompletedToolchainPreflight,
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
        true,
        stdout,
        stderr,
    )
}

fn run_reviewed_locked_verification<R>(
    current_dir: &Path,
    runner: &R,
    toolchain_preflight: &toolchain::CompletedToolchainPreflight,
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
    if let Err(error) = runner.cargo_test_locked(current_dir) {
        return fail(stderr, format!("cargo test --locked: {error}"));
    }
    writeln!(stdout, "OK   cargo test --locked").map_err(CommandError::Io)?;
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
