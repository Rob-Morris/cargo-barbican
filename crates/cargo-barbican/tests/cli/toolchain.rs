use super::common::*;

fn run_verify_fixture(temp_dir: &Path, runner: &FakeCommandRunner) -> (ExitCode, String, String) {
    let cli = Cli::parse_from(["cargo-barbican", "verify"]);
    let client = FakeCratesIoClient::default();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit_code = run_cli_with_runner(cli, temp_dir, &client, runner, &mut stdout, &mut stderr)
        .expect("command should run");
    (
        exit_code,
        String::from_utf8(stdout).expect("stdout should be utf8"),
        String::from_utf8(stderr).expect("stderr should be utf8"),
    )
}

#[test]
fn verify_fails_before_any_tool_probe_when_toolchain_pin_is_missing() {
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    let runner = FakeCommandRunner::default();

    let (exit_code, stdout, stderr) = run_verify_fixture(&temp_dir, &runner);

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.contains("Toolchain check: FAIL"));
    assert!(stderr.contains("exact Rust toolchain policy required"));
    assert!(stderr.contains("policy init --toolchain <exact-channel>"));
    assert_eq!(runner.rustup_active_toolchain_calls(), 0);
    assert_eq!(*runner.build_calls.borrow(), 0);
}

#[test]
fn verify_rejects_floating_toolchain_channels() {
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    fs::write(
        temp_dir.join("rust-toolchain.toml"),
        "[toolchain]\nchannel = \"stable\"\n",
    )
    .expect("toolchain should write");
    let runner = FakeCommandRunner::default();

    let (exit_code, stdout, stderr) = run_verify_fixture(&temp_dir, &runner);

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.contains("Toolchain check: FAIL"));
    assert!(stderr.contains("floating or unsupported"));
    assert_eq!(runner.rustup_active_toolchain_calls(), 0);
}

#[test]
fn verify_rejects_a_mismatched_active_toolchain_override() {
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    write_toolchain_pin(&temp_dir);
    let runner = FakeCommandRunner::default()
        .with_active_toolchain("1.96.0-aarch64-apple-darwin (environment override)");

    let (exit_code, stdout, stderr) = run_verify_fixture(&temp_dir, &runner);

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.contains("Toolchain check: FAIL"));
    assert!(stderr.contains("active Rust toolchain mismatch"));
    assert_eq!(runner.rustup_active_toolchain_calls(), 1);
    assert_eq!(*runner.build_calls.borrow(), 0);
}

#[test]
fn verify_rejects_a_legacy_toolchain_file_that_shadows_canonical_policy() {
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    write_toolchain_pin(&temp_dir);
    fs::write(temp_dir.join("rust-toolchain"), "1.96.0\n").expect("legacy toolchain should write");
    let runner = FakeCommandRunner::default();

    let (exit_code, _, stderr) = run_verify_fixture(&temp_dir, &runner);

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.contains("rust-toolchain shadows rust-toolchain.toml"));
    assert_eq!(runner.rustup_active_toolchain_calls(), 0);
}

#[test]
fn verify_rejects_every_toolchain_executable_environment_variable() {
    // This deliberately does not derive from the production catalogue: the
    // test is an independent completeness oracle for Cargo's documented
    // executable-selection environment surface.
    for name in [
        "RUSTC",
        "CARGO_BUILD_RUSTC",
        "RUSTC_WRAPPER",
        "CARGO_BUILD_RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
        "RUSTDOC",
        "CARGO_BUILD_RUSTDOC",
    ] {
        let temp_dir = fresh_temp_dir();
        write_root_manifest(&temp_dir);
        write_toolchain_pin(&temp_dir);
        let runner = FakeCommandRunner::default().with_environment(name, "/opt/compiler-control");

        let (exit_code, _, stderr) = run_verify_fixture(&temp_dir, &runner);

        assert_eq!(exit_code, ExitCode::from(1), "{name} should block");
        assert!(stderr.contains(name), "diagnostic should name {name}");
        assert!(stderr.contains("controls Cargo's Rust toolchain executable selection"));
        assert_eq!(runner.rustup_active_toolchain_calls(), 0);
        assert_eq!(*runner.build_calls.borrow(), 0);
    }
}

#[test]
fn verify_fails_when_cargo_home_cannot_be_established() {
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    write_toolchain_pin(&temp_dir);
    let runner = FakeCommandRunner::default()
        .without_environment("CARGO_HOME")
        .without_environment("HOME");

    let (exit_code, _, stderr) = run_verify_fixture(&temp_dir, &runner);

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.contains("unable to establish Cargo home"));
    assert_eq!(runner.rustup_active_toolchain_calls(), 0);
    assert_eq!(*runner.build_calls.borrow(), 0);
}

#[test]
fn verify_rejects_repo_local_cargo_toolchain_overrides() {
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    write_toolchain_pin(&temp_dir);
    fs::create_dir_all(temp_dir.join(".cargo")).expect("cargo config dir should exist");
    fs::write(
        temp_dir.join(".cargo/config.toml"),
        "[build]\nrustc = \"/opt/custom/rustc\"\n",
    )
    .expect("cargo config should write");
    let runner = FakeCommandRunner::default();

    let (exit_code, _, stderr) = run_verify_fixture(&temp_dir, &runner);

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.contains("build.rustc controls Cargo's Rust toolchain executable selection"));
    assert_eq!(runner.rustup_active_toolchain_calls(), 0);
}

#[test]
fn verify_rejects_every_cargo_config_toolchain_executable_control() {
    for control in barbican::CARGO_TOOLCHAIN_EXECUTABLE_CONTROLS {
        let key = control.build_key;
        let temp_dir = fresh_temp_dir();
        write_root_manifest(&temp_dir);
        write_toolchain_pin(&temp_dir);
        fs::create_dir_all(temp_dir.join(".cargo")).expect("cargo config dir should exist");
        fs::write(
            temp_dir.join(".cargo/config.toml"),
            format!("[build]\n{key} = \"/opt/compiler-control\"\n"),
        )
        .expect("cargo config should write");
        let runner = FakeCommandRunner::default();

        let (exit_code, _, stderr) = run_verify_fixture(&temp_dir, &runner);

        assert_eq!(exit_code, ExitCode::from(1), "{key} should block");
        assert!(stderr.contains(&format!("build.{key}")));
        assert!(stderr.contains("controls Cargo's Rust toolchain executable selection"));
        assert_eq!(runner.rustup_active_toolchain_calls(), 0);
        assert_eq!(*runner.build_calls.borrow(), 0);
    }
}

#[test]
fn verify_rejects_cargo_home_toolchain_control() {
    let temp_dir = fresh_temp_dir();
    let cargo_home = temp_dir.join("cargo-home");
    write_root_manifest(&temp_dir);
    write_toolchain_pin(&temp_dir);
    fs::create_dir_all(&cargo_home).expect("cargo home should exist");
    fs::write(
        cargo_home.join("config.toml"),
        "[build]\nrustc-wrapper = \"/opt/compiler-control\"\n",
    )
    .expect("cargo-home config should write");
    let runner = FakeCommandRunner::default().with_environment(
        "CARGO_HOME",
        cargo_home.to_str().expect("test path should be utf8"),
    );

    let (exit_code, _, stderr) = run_verify_fixture(&temp_dir, &runner);

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.contains("cargo-home/config.toml"));
    assert!(stderr.contains("build.rustc-wrapper"));
    assert_eq!(runner.rustup_active_toolchain_calls(), 0);
    assert_eq!(*runner.build_calls.borrow(), 0);
}

#[cfg(unix)]
#[test]
fn verify_allows_a_symlinked_operator_owned_cargo_home_config() {
    use std::os::unix::fs::symlink;

    let temp_dir = fresh_temp_dir();
    let workspace = temp_dir.join("workspace");
    let cargo_home = temp_dir.join("cargo-home");
    fs::create_dir_all(&workspace).expect("workspace should exist");
    write_root_manifest(&workspace);
    write_toolchain_pin(&workspace);
    fs::create_dir_all(&cargo_home).expect("cargo home should exist");
    fs::write(cargo_home.join("shared.toml"), "[build]\njobs = 2\n")
        .expect("shared config should write");
    symlink("shared.toml", cargo_home.join("config.toml"))
        .expect("cargo-home config symlink should create");
    let runner = FakeCommandRunner::default().with_environment(
        "CARGO_HOME",
        cargo_home.to_str().expect("test path should be utf8"),
    );

    let (exit_code, stdout, stderr) = run_verify_fixture(&workspace, &runner);

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.contains("Toolchain check: PASS"));
    assert!(stderr.contains("reviewed-targets.toml"));
    assert!(!stderr.contains("symlink"));
}

#[cfg(unix)]
#[test]
fn verify_allows_a_symlinked_home_default_cargo_config_from_an_ancestor() {
    use std::os::unix::fs::symlink;

    let temp_dir = fresh_temp_dir();
    let workspace = temp_dir.join("repo");
    let cargo_home = temp_dir.join(".cargo");
    fs::create_dir_all(&workspace).expect("workspace should exist");
    write_root_manifest(&workspace);
    write_toolchain_pin(&workspace);
    fs::create_dir_all(&cargo_home).expect("cargo home should exist");
    fs::write(cargo_home.join("shared.toml"), "[build]\njobs = 2\n")
        .expect("shared config should write");
    symlink("shared.toml", cargo_home.join("config.toml"))
        .expect("cargo-home config symlink should create");
    let runner = FakeCommandRunner::default()
        .without_environment("CARGO_HOME")
        .with_environment("HOME", temp_dir.to_str().expect("test path should be utf8"));

    let (exit_code, stdout, stderr) = run_verify_fixture(&workspace, &runner);

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.contains("Toolchain check: PASS"));
    assert!(stderr.contains("reviewed-targets.toml"));
    assert!(!stderr.contains("symlink"));
}

#[cfg(unix)]
#[test]
fn verify_rejects_a_symlinked_repo_cargo_config() {
    use std::os::unix::fs::symlink;

    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    write_toolchain_pin(&temp_dir);
    fs::create_dir_all(temp_dir.join(".cargo")).expect("cargo config dir should exist");
    fs::write(temp_dir.join(".cargo/shared.toml"), "[build]\njobs = 2\n")
        .expect("shared config should write");
    symlink("shared.toml", temp_dir.join(".cargo/config.toml"))
        .expect("repo config symlink should create");
    let runner = FakeCommandRunner::default();

    let (exit_code, _, stderr) = run_verify_fixture(&temp_dir, &runner);

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.contains(".cargo/config.toml is a symlink"));
    assert_eq!(runner.rustup_active_toolchain_calls(), 0);
}

#[cfg(unix)]
#[test]
fn verify_rejects_a_symlinked_repo_local_cargo_home_config() {
    use std::os::unix::fs::symlink;

    let temp_dir = fresh_temp_dir();
    let cargo_home = temp_dir.join(".cargo-home");
    write_root_manifest(&temp_dir);
    write_toolchain_pin(&temp_dir);
    fs::create_dir_all(&cargo_home).expect("cargo home should exist");
    fs::write(cargo_home.join("shared.toml"), "[build]\njobs = 2\n")
        .expect("shared config should write");
    symlink("shared.toml", cargo_home.join("config.toml"))
        .expect("repo-local Cargo-home config symlink should create");
    let runner = FakeCommandRunner::default().with_environment("CARGO_HOME", ".cargo-home");

    let (exit_code, _, stderr) = run_verify_fixture(&temp_dir, &runner);

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.contains(".cargo-home/config.toml is a symlink"));
    assert_eq!(runner.rustup_active_toolchain_calls(), 0);
}

#[cfg(unix)]
#[test]
fn verify_rejects_an_external_cargo_home_config_symlink_into_the_workspace() {
    use std::os::unix::fs::symlink;

    let temp_dir = fresh_temp_dir();
    let workspace = temp_dir.join("workspace");
    let cargo_home = temp_dir.join("cargo-home");
    fs::create_dir_all(&workspace).expect("workspace should exist");
    write_root_manifest(&workspace);
    write_toolchain_pin(&workspace);
    fs::write(workspace.join("cargo-config.toml"), "[build]\njobs = 2\n")
        .expect("workspace-controlled config should write");
    fs::create_dir_all(&cargo_home).expect("cargo home should exist");
    symlink(
        workspace.join("cargo-config.toml"),
        cargo_home.join("config.toml"),
    )
    .expect("external Cargo-home symlink should create");
    let runner = FakeCommandRunner::default().with_environment(
        "CARGO_HOME",
        cargo_home.to_str().expect("test path should be utf8"),
    );

    let (exit_code, _, stderr) = run_verify_fixture(&workspace, &runner);

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.contains("resolves inside the workspace"));
    assert_eq!(runner.rustup_active_toolchain_calls(), 0);
}

#[test]
fn verify_allows_rustup_home_as_an_installation_location() {
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    write_toolchain_pin(&temp_dir);
    let runner = FakeCommandRunner::default().with_environment("RUSTUP_HOME", "/opt/rustup");

    let (exit_code, stdout, stderr) = run_verify_fixture(&temp_dir, &runner);

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.contains("Toolchain check: PASS"));
    assert!(stderr.contains("reviewed-targets.toml"));
}

#[test]
fn verify_allows_non_toolchain_cargo_build_configuration() {
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    write_toolchain_pin(&temp_dir);
    fs::create_dir_all(temp_dir.join(".cargo")).expect("cargo config dir should exist");
    fs::write(
        temp_dir.join(".cargo/config.toml"),
        r#"[build]
rustflags = ["-C", "debuginfo=0"]

[env]
BARBICAN_TEST = "1"

[target.test-target]
runner = "/usr/bin/true"
linker = "/usr/bin/cc"
"#,
    )
    .expect("cargo config should write");
    let runner = FakeCommandRunner::default();

    let (exit_code, stdout, stderr) = run_verify_fixture(&temp_dir, &runner);

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.contains("Toolchain check: PASS"));
    assert!(stderr.contains("reviewed-targets.toml"));
}

#[test]
fn verify_rejects_parent_cargo_toolchain_overrides() {
    let temp_dir = fresh_temp_dir();
    let workspace = temp_dir.join("nested/workspace");
    fs::create_dir_all(&workspace).expect("workspace should exist");
    write_root_manifest(&workspace);
    write_toolchain_pin(&workspace);
    fs::create_dir_all(temp_dir.join("nested/.cargo")).expect("cargo config dir should exist");
    fs::write(
        temp_dir.join("nested/.cargo/config.toml"),
        "[build]\nrustc = \"/opt/custom-rustc\"\n",
    )
    .expect("parent cargo config should write");
    let runner = FakeCommandRunner::default();

    let (exit_code, _, stderr) = run_verify_fixture(&workspace, &runner);

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.contains("build.rustc controls Cargo's Rust toolchain executable selection"));
    assert_eq!(runner.rustup_active_toolchain_calls(), 0);
}

#[test]
fn verify_follows_extensionless_cargo_config_precedence() {
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    write_toolchain_pin(&temp_dir);
    fs::create_dir_all(temp_dir.join(".cargo")).expect("cargo config dir should exist");
    fs::write(temp_dir.join(".cargo/config"), "[build]\njobs = 2\n")
        .expect("effective cargo config should write");
    fs::write(
        temp_dir.join(".cargo/config.toml"),
        "[build]\nrustc = \"/opt/dormant-rustc\"\n",
    )
    .expect("dormant cargo config should write");
    let runner = FakeCommandRunner::default();

    let (exit_code, stdout, stderr) = run_verify_fixture(&temp_dir, &runner);

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.contains("reviewed-targets.toml"));
    assert!(stdout.contains("Toolchain check: PASS"));
}

#[test]
fn verify_fails_closed_when_rustup_identity_cannot_be_established() {
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    write_toolchain_pin(&temp_dir);
    let runner = FakeCommandRunner::default().with_rustup_error("rustup unavailable");

    let (exit_code, _, stderr) = run_verify_fixture(&temp_dir, &runner);

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.contains("unable to establish the active rustup toolchain"));
    assert!(stderr.contains("rustup unavailable"));
    assert!(stderr.contains("install rustup"));
    assert_eq!(*runner.build_calls.borrow(), 0);
}

#[test]
fn verify_fails_closed_when_tool_identity_cannot_be_established() {
    for (runner, expected) in [
        (
            FakeCommandRunner::default().with_cargo_verbose_error("cargo unavailable"),
            "unable to establish the active Cargo version",
        ),
        (
            FakeCommandRunner::default().with_rustc_verbose_error("rustc unavailable"),
            "unable to establish the active rustc version",
        ),
        (
            FakeCommandRunner::default().with_rustdoc_verbose_error("rustdoc unavailable"),
            "unable to establish the active rustdoc version",
        ),
    ] {
        let temp_dir = fresh_temp_dir();
        write_root_manifest(&temp_dir);
        write_toolchain_pin(&temp_dir);

        let (exit_code, _, stderr) = run_verify_fixture(&temp_dir, &runner);

        assert_eq!(exit_code, ExitCode::from(1));
        assert!(stderr.contains(expected));
        assert_eq!(*runner.build_calls.borrow(), 0);
    }
}

#[test]
fn verify_rejects_unparseable_or_host_mismatched_tool_identity() {
    for (runner, expected) in [
        (
            FakeCommandRunner::default()
                .with_cargo_verbose_version("cargo 1.95.0\nhost: aarch64-apple-darwin\n"),
            "did not report release",
        ),
        (
            FakeCommandRunner::default().with_rustc_verbose_version(
                "rustc 1.95.0\nrelease: 1.95.0\nhost: x86_64-unknown-linux-gnu\n",
            ),
            "cargo and rustc host mismatch",
        ),
        (
            FakeCommandRunner::default().with_rustdoc_verbose_version(
                "rustdoc 1.95.0\nrelease: 1.95.0\nhost: x86_64-unknown-linux-gnu\n",
            ),
            "rustdoc and rustc host mismatch",
        ),
    ] {
        let temp_dir = fresh_temp_dir();
        write_root_manifest(&temp_dir);
        write_toolchain_pin(&temp_dir);

        let (exit_code, _, stderr) = run_verify_fixture(&temp_dir, &runner);

        assert_eq!(exit_code, ExitCode::from(1));
        assert!(stderr.contains(expected));
        assert_eq!(*runner.build_calls.borrow(), 0);
    }
}

#[test]
fn verify_rejects_indirect_cargo_configuration() {
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    write_toolchain_pin(&temp_dir);
    fs::create_dir_all(temp_dir.join(".cargo")).expect("cargo config dir should exist");
    fs::write(
        temp_dir.join(".cargo/config.toml"),
        "include = ['shared.toml']\n",
    )
    .expect("cargo config should write");
    let runner = FakeCommandRunner::default();

    let (exit_code, _, stderr) = run_verify_fixture(&temp_dir, &runner);

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.contains("toolchain effect cannot be established"));
    assert_eq!(runner.rustup_active_toolchain_calls(), 0);
}

#[cfg(unix)]
#[test]
fn verify_rejects_symlinked_toolchain_policy() {
    use std::os::unix::fs::symlink;

    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    fs::write(
        temp_dir.join("outside-toolchain.toml"),
        "[toolchain]\nchannel = \"1.95.0\"\n",
    )
    .expect("target should write");
    symlink(
        "outside-toolchain.toml",
        temp_dir.join("rust-toolchain.toml"),
    )
    .expect("symlink should create");
    let runner = FakeCommandRunner::default();

    let (exit_code, _, stderr) = run_verify_fixture(&temp_dir, &runner);

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.contains("is a symlink; refusing to read"));
    assert_eq!(runner.rustup_active_toolchain_calls(), 0);
}
