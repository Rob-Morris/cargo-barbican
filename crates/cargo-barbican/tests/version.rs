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
