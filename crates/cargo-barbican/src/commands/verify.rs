use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use crate::cli::REVIEWED_TARGETS_CONFIG_FILE;
use crate::command_runner::CommandRunner;

use super::pin_check::enforce_reviewed_targets;
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

    let pin_check_exit =
        enforce_reviewed_targets(&reviewed_targets, config_path, current_dir, stdout)?;
    if pin_check_exit != ExitCode::SUCCESS {
        return Ok(pin_check_exit);
    }

    if let Err(error) = runner.cargo_build_locked(current_dir) {
        return fail(stderr, format!("cargo build --locked: {error}"));
    }
    writeln!(stdout, "OK   cargo build --locked").map_err(CommandError::Io)?;
    if let Err(error) = runner.cargo_test_locked(current_dir) {
        return fail(stderr, format!("cargo test --locked: {error}"));
    }
    writeln!(stdout, "OK   cargo test --locked").map_err(CommandError::Io)?;
    writeln!(
        stdout,
        "note: advisory audit is a separate gate; run cargo barbican audit"
    )
    .map_err(CommandError::Io)?;
    writeln!(stdout, "Verify: PASS").map_err(CommandError::Io)?;

    Ok(ExitCode::SUCCESS)
}
