use std::process::Command;

fn cargo_barbican_binary() -> &'static str {
    option_env!("CARGO_BIN_EXE_cargo-barbican")
        .or(option_env!("CARGO_BIN_EXE_cargo_barbican"))
        .expect("cargo should expose the cargo-barbican binary path to integration tests")
}

#[test]
fn version_flag_reports_package_version_for_direct_binary_invocation() {
    let output = Command::new(cargo_barbican_binary())
        .arg("--version")
        .output()
        .expect("version command should run");

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    assert!(stdout.contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn version_flag_reports_package_version_for_cargo_subcommand_invocation() {
    let output = Command::new(cargo_barbican_binary())
        .args(["barbican", "--version"])
        .output()
        .expect("version command should run");

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    assert!(stdout.contains(env!("CARGO_PKG_VERSION")));
}

/// A clap usage error (missing required argument, unknown flag, etc.) is
/// process-exiting parse-time behaviour that only the real binary can
/// exercise: `Cli::parse_from` calls `std::process::exit` directly rather
/// than returning a `Result`, so the in-process `run_cli_with_runner`
/// harness used elsewhere never sees this path.
#[test]
fn usage_error_exits_with_clap_conventional_code_two() {
    let output = Command::new(cargo_barbican_binary())
        .args(["age"])
        .output()
        .expect("age command should run");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("stderr should be utf8");
    assert!(stderr.contains("Usage: cargo barbican age"));
}
