use super::common::*;

#[test]
fn gatehouse_pre_release_composes_inventory_audit_and_verify() {
    let cli = Cli::parse_from(["cargo-barbican", "gatehouse", "pre-release"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default()
        .with_frozen_metadata(declared_crates_io_direct_metadata_json("serde", "1.0.228"));
    let temp_dir = fresh_temp_dir();
    write_covered_enforce_fixture(&temp_dir);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(
        exit_code,
        ExitCode::SUCCESS,
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr)
    );
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Step 1/3 — inventory coverage floor (blocking)"));
    assert!(rendered.contains("direct-dependency coverage floor: PASS (enforced in this run)"));
    assert!(rendered.contains("Dependency inventory:"));
    assert!(rendered.contains("Inventory: PASS (direct-dependency coverage floor)"));
    assert!(rendered.contains("Step 2/3 — audit (blocking)"));
    assert!(rendered.contains("Audit: PASS"));
    assert!(rendered.contains("Step 3/3 — verify (blocking; includes pin check)"));
    assert!(rendered.contains("Pin check: PASS"));
    assert!(rendered.contains("Verify: PASS"));
    assert!(rendered.contains("Gatehouse pre-release: PASS"));
    assert!(!rendered.contains("advisory audit is a separate gate"));
    assert!(
        rendered.find("Step 1/3").unwrap() < rendered.find("Step 2/3").unwrap()
            && rendered.find("Step 2/3").unwrap() < rendered.find("Step 3/3").unwrap()
    );
    assert_eq!(runner.frozen_metadata_calls(), 1);
    assert_eq!(runner.recorded_deny_json_calls().len(), 1);
    assert_eq!(*runner.build_calls.borrow(), 1);
    assert_eq!(*runner.test_calls.borrow(), 1);
}

#[test]
fn gatehouse_pre_release_stops_after_inventory_failure() {
    let cli = Cli::parse_from(["cargo-barbican", "gatehouse", "pre-release"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default().with_frozen_metadata(
        serde_and_declared_crates_io_direct_metadata_json("sneaky", "3.0.0"),
    );
    let temp_dir = fresh_temp_dir();
    write_uncovered_direct_enforce_fixture(&temp_dir);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Inventory: FAIL (direct-dependency coverage floor)"));
    assert!(rendered.contains("Gatehouse pre-release: FAIL (inventory)"));
    assert!(!rendered.contains("Step 2/3"));
    assert!(runner.recorded_deny_json_calls().is_empty());
    assert_eq!(*runner.build_calls.borrow(), 0);
    assert_eq!(*runner.test_calls.borrow(), 0);
}

#[test]
fn gatehouse_pre_release_rejects_degraded_workspace_discovery() {
    let cli = Cli::parse_from(["cargo-barbican", "gatehouse", "pre-release"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default()
        .with_workspace_manifest_error("failed to parse manifest: invalid package name");
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    let rendered = String::from_utf8(stderr).expect("stderr should be utf8");
    assert!(rendered.contains("unable to locate Cargo workspace root"));
    assert!(rendered.contains("invalid package name"));
    assert_eq!(runner.frozen_metadata_calls(), 0);
    assert!(runner.recorded_deny_json_calls().is_empty());
    assert_eq!(*runner.build_calls.borrow(), 0);
    assert_eq!(*runner.test_calls.borrow(), 0);
}

#[test]
fn gatehouse_pre_release_stops_after_audit_failure() {
    let cli = Cli::parse_from(["cargo-barbican", "gatehouse", "pre-release"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default()
        .with_cargo_deny_json(&cargo_deny_bans_error_jsonl())
        .with_frozen_metadata(declared_crates_io_direct_metadata_json("serde", "1.0.228"));
    let temp_dir = fresh_temp_dir();
    write_covered_enforce_fixture(&temp_dir);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Audit: FAIL"));
    assert!(rendered.contains("Gatehouse pre-release: FAIL (audit)"));
    assert!(!rendered.contains("Step 3/3"));
    assert_eq!(*runner.build_calls.borrow(), 0);
    assert_eq!(*runner.test_calls.borrow(), 0);
}

#[test]
fn gatehouse_pre_release_names_verify_as_the_failed_gate() {
    let cli = Cli::parse_from(["cargo-barbican", "gatehouse", "pre-release"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner {
        cargo_build_result: Err("build failed".to_owned()),
        ..FakeCommandRunner::default()
    }
    .with_frozen_metadata(declared_crates_io_direct_metadata_json("serde", "1.0.228"));
    let temp_dir = fresh_temp_dir();
    write_covered_enforce_fixture(&temp_dir);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Audit: PASS"));
    assert!(rendered.contains("Pin check: PASS"));
    assert!(rendered.contains("Gatehouse pre-release: FAIL (verify)"));
    assert!(
        String::from_utf8(stderr)
            .expect("stderr should be utf8")
            .contains("FAIL cargo build --locked: command exited with status 1")
    );
    assert_eq!(*runner.build_calls.borrow(), 1);
    assert_eq!(*runner.test_calls.borrow(), 0);
}

#[test]
fn gatehouse_candidate_renders_isolated_dossier_and_cleans_up_sandbox() {
    let tarball = build_crate_tarball(&[
        (
            "Cargo.toml",
            "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n",
        ),
        ("src/lib.rs", "pub fn ok() {}\n"),
        (
            ".cargo_vcs_info.json",
            "{\n  \"git\": {\"sha1\": \"abc123\"},\n  \"path_in_vcs\": \"sample\"\n}\n",
        ),
    ]);
    let checksum = sha256_hex(&tarball);
    let cli = Cli::parse_from(["cargo-barbican", "gatehouse", "candidate", "sample@0.1.0"]);
    let client = FakeCratesIoClient::default()
        .with_release_checksum("sample@0.1.0", "2020-05-01T00:00:00Z", false, &checksum)
        .with_tarball("sample@0.1.0", &tarball);
    let runner = FakeCommandRunner::default()
        .with_cargo_tree("cargo-barbican-gatehouse-candidate v0.0.0\n+-- sample v0.1.0\n")
        .with_cargo_audit("No vulnerable packages found\n");
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner_at(
        cli,
        &temp_dir,
        &client,
        &runner,
        fixed_now(),
        &mut stdout,
        &mut stderr,
    )
    .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Gatehouse candidate: sample@0.1.0"));
    assert!(rendered.contains("Inspect evidence:"));
    assert!(rendered.contains("classification: routine-safe"));
    assert!(rendered.contains("Sandbox lockfile:"));
    assert!(rendered.contains("OK generated with cargo generate-lockfile"));
    assert!(rendered.contains("Cargo tree:"));
    assert!(rendered.contains("sample v0.1.0"));
    assert!(rendered.contains("Cargo audit:"));
    assert!(rendered.contains("No vulnerable packages found"));
    assert!(rendered.contains("Suggested next step:"));
    assert_eq!(client.recorded_fetches(), vec!["sample@0.1.0".to_owned()]);
    assert_eq!(
        client.recorded_tarball_fetches(),
        vec!["sample@0.1.0".to_owned()]
    );
    let lockfile_calls = runner.recorded_generate_lockfile_calls();
    assert_eq!(lockfile_calls.len(), 1);
    assert_eq!(runner.recorded_cargo_tree_calls(), lockfile_calls);
    assert_eq!(runner.recorded_audit_calls(), lockfile_calls);
    assert!(!lockfile_calls[0].exists());
    // The sandbox is isolated from the invocation directory: our anchor
    // manifest is left untouched and no lockfile is written beside it.
    assert_eq!(
        fs::read_to_string(temp_dir.join("Cargo.toml")).expect("anchor manifest should remain"),
        "[package]\nname = \"fixture\"\nversion = \"0.0.0\"\n"
    );
    assert!(!temp_dir.join("Cargo.lock").exists());
}

#[test]
fn gatehouse_candidate_preserves_sandbox_when_requested() {
    let tarball = build_crate_tarball(&[
        (
            "Cargo.toml",
            "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n",
        ),
        ("src/lib.rs", "pub fn ok() {}\n"),
    ]);
    let checksum = sha256_hex(&tarball);
    let cli = Cli::parse_from([
        "cargo-barbican",
        "gatehouse",
        "candidate",
        "--preserve-sandbox",
        "sample@0.1.0",
    ]);
    let client = FakeCratesIoClient::default()
        .with_release_checksum("sample@0.1.0", "2020-05-01T00:00:00Z", false, &checksum)
        .with_tarball("sample@0.1.0", &tarball);
    let runner = FakeCommandRunner::default()
        .with_cargo_tree("sample v0.1.0\n")
        .with_cargo_audit("No vulnerable packages found\n");
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner_at(
        cli,
        &temp_dir,
        &client,
        &runner,
        fixed_now(),
        &mut stdout,
        &mut stderr,
    )
    .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("status: preserved for inspection"));
    let sandbox_path = runner.recorded_generate_lockfile_calls()[0].clone();
    assert!(sandbox_path.is_dir());
    assert!(rendered.contains(&sandbox_path.display().to_string()));
    assert!(sandbox_path.join("src/lib.rs").is_file());
    assert!(sandbox_path.join("Cargo.lock").is_file());
    assert!(
        fs::read_to_string(sandbox_path.join("Cargo.toml"))
            .expect("candidate manifest should read")
            .contains("\"sample\" = \"=0.1.0\"")
    );

    fs::remove_dir_all(sandbox_path).expect("preserved sandbox should clean up");
}

#[test]
fn gatehouse_candidate_rejects_non_exact_specs_before_sandboxing() {
    let cli = Cli::parse_from(["cargo-barbican", "gatehouse", "candidate", "sample"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    assert!(
        String::from_utf8(stderr)
            .expect("stderr should be utf8")
            .contains("Expected exact crate@version spec")
    );
    assert!(runner.recorded_generate_lockfile_calls().is_empty());
}

#[test]
fn gatehouse_candidate_reports_cargo_audit_failures_in_the_dossier() {
    let tarball = build_crate_tarball(&[
        (
            "Cargo.toml",
            "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n",
        ),
        ("src/lib.rs", "pub fn ok() {}\n"),
    ]);
    let checksum = sha256_hex(&tarball);
    let cli = Cli::parse_from(["cargo-barbican", "gatehouse", "candidate", "sample@0.1.0"]);
    let client = FakeCratesIoClient::default()
        .with_release_checksum("sample@0.1.0", "2020-05-01T00:00:00Z", false, &checksum)
        .with_tarball("sample@0.1.0", &tarball);
    let runner = FakeCommandRunner::default()
        .with_cargo_tree("sample v0.1.0\n")
        .with_cargo_audit_error("vulnerable dependency found");
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner_at(
        cli,
        &temp_dir,
        &client,
        &runner,
        fixed_now(),
        &mut stdout,
        &mut stderr,
    )
    .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Cargo audit:"));
    assert!(rendered.contains("FAIL command exited with status 1"));
    assert!(rendered.contains("stderr: vulnerable dependency found"));
    assert!(
        rendered.contains("Do not admit this candidate until the failed evidence is reviewed.")
    );
    assert!(!runner.recorded_generate_lockfile_calls()[0].exists());
}

#[test]
fn gatehouse_candidate_reports_fetch_failures_in_the_dossier() {
    let cli = Cli::parse_from(["cargo-barbican", "gatehouse", "candidate", "sample@0.1.0"]);
    let client = FakeCratesIoClient::default().with_error(
        "sample@0.1.0",
        CratesIoClientError::Transport {
            reason: "network blocked".to_owned(),
        },
    );
    let runner = FakeCommandRunner::default()
        .with_cargo_tree("sample v0.1.0\n")
        .with_cargo_audit("No vulnerable packages found\n");
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Inspect evidence:"));
    assert!(rendered.contains("FAIL sample@0.1.0: unable to reach crates.io (network blocked)"));
    assert!(rendered.contains("Cargo tree:"));
    assert!(rendered.contains("Cargo audit:"));
    assert!(
        rendered.contains("Do not admit this candidate until the failed evidence is reviewed.")
    );
    assert!(!runner.recorded_generate_lockfile_calls()[0].exists());
}

#[test]
fn gatehouse_candidate_reports_tarball_fetch_failures_in_the_dossier() {
    let cli = Cli::parse_from(["cargo-barbican", "gatehouse", "candidate", "sample@0.1.0"]);
    let client = FakeCratesIoClient::default().with_release_checksum(
        "sample@0.1.0",
        "2020-05-01T00:00:00Z",
        false,
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
    let runner = FakeCommandRunner::default()
        .with_cargo_tree("sample v0.1.0\n")
        .with_cargo_audit("No vulnerable packages found\n");
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Inspect evidence:"));
    assert!(
        rendered.contains(
            "FAIL sample@0.1.0: unable to reach crates.io (missing fake tarball response)"
        )
    );
    assert!(rendered.contains("Cargo tree:"));
    assert!(rendered.contains("Cargo audit:"));
    assert!(
        rendered.contains("Do not admit this candidate until the failed evidence is reviewed.")
    );
    assert!(!runner.recorded_generate_lockfile_calls()[0].exists());
}

#[test]
fn gatehouse_candidate_keeps_collecting_evidence_after_non_routine_inspect() {
    let tarball = build_crate_tarball(&[
        (
            "Cargo.toml",
            "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n",
        ),
        ("build.rs", "fn main() {}\n"),
        ("src/lib.rs", "pub fn ok() {}\n"),
    ]);
    let checksum = sha256_hex(&tarball);
    let cli = Cli::parse_from(["cargo-barbican", "gatehouse", "candidate", "sample@0.1.0"]);
    let client = FakeCratesIoClient::default()
        .with_release_checksum("sample@0.1.0", "2020-05-01T00:00:00Z", false, &checksum)
        .with_tarball("sample@0.1.0", &tarball);
    let runner = FakeCommandRunner::default()
        .with_cargo_tree("sample v0.1.0\n")
        .with_cargo_audit("No vulnerable packages found\n");
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner_at(
        cli,
        &temp_dir,
        &client,
        &runner,
        fixed_now(),
        &mut stdout,
        &mut stderr,
    )
    .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("classification: elevated-risk"));
    assert!(rendered.contains("build.rs surfaces: build.rs"));
    assert!(rendered.contains("Sandbox lockfile:"));
    assert!(rendered.contains("Cargo tree:"));
    assert!(rendered.contains("Cargo audit:"));
    assert_eq!(runner.recorded_cargo_tree_calls().len(), 1);
    assert_eq!(runner.recorded_audit_calls().len(), 1);
}

#[test]
fn gatehouse_candidate_explains_ioc_verdict_without_self_referential_pointer() {
    // The dossier embeds the inspect report, so it carries the same verdict
    // basis and reviewed-family remediation. It must NOT tell the reviewer to
    // run `gatehouse candidate` again — that pointer is inspect-only.
    let tarball = build_crate_tarball(&[
        (
            "Cargo.toml",
            "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n",
        ),
        (
            "build.rs",
            "fn main() { std::process::Command::new(\"curl\"); }\n",
        ),
        ("src/lib.rs", "pub fn ok() {}\n"),
    ]);
    let checksum = sha256_hex(&tarball);
    let cli = Cli::parse_from(["cargo-barbican", "gatehouse", "candidate", "sample@0.1.0"]);
    let client = FakeCratesIoClient::default()
        .with_release_checksum("sample@0.1.0", "2020-05-01T00:00:00Z", false, &checksum)
        .with_tarball("sample@0.1.0", &tarball);
    let runner = FakeCommandRunner::default()
        .with_cargo_tree("sample v0.1.0\n")
        .with_cargo_audit("No vulnerable packages found\n");
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner_at(
        cli,
        &temp_dir,
        &client,
        &runner,
        fixed_now(),
        &mut stdout,
        &mut stderr,
    )
    .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("classification: policy-violating"));
    assert!(rendered.contains("(process execution: `std::process::Command`)"));
    assert!(rendered.contains("verdict basis: policy-violating is driven by the IOC hits above."));
    assert!(rendered.contains("record the crate in a reviewed family with an allowed_surfaces"));
    assert!(rendered.contains("cargo barbican pin add sample"));
    assert!(!rendered.contains("gatehouse candidate sample"));
}

#[test]
fn gatehouse_candidate_honours_injected_clock_for_release_age() {
    // An otherwise-clean crate published 6 days before `fixed_now()` (2020-06-01)
    // is too fresh and must classify policy-violating. Age is the sole driver
    // here, so this guards the gatehouse candidate call site's clock wiring:
    // under the wall clock the release would read as years old and wrongly pass.
    let tarball = build_crate_tarball(&[
        (
            "Cargo.toml",
            "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n",
        ),
        ("src/lib.rs", "pub fn ok() {}\n"),
    ]);
    let checksum = sha256_hex(&tarball);
    let cli = Cli::parse_from(["cargo-barbican", "gatehouse", "candidate", "sample@0.1.0"]);
    let client = FakeCratesIoClient::default()
        .with_release_checksum("sample@0.1.0", "2020-05-26T00:00:00Z", false, &checksum)
        .with_tarball("sample@0.1.0", &tarball);
    let runner = FakeCommandRunner::default()
        .with_cargo_tree("sample v0.1.0\n")
        .with_cargo_audit("No vulnerable packages found\n");
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner_at(
        cli,
        &temp_dir,
        &client,
        &runner,
        fixed_now(),
        &mut stdout,
        &mut stderr,
    )
    .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("classification: policy-violating"));
    assert!(rendered.contains("below the 7-day minimum"));
}

#[test]
fn gatehouse_candidate_lockfile_generation_failure_skips_later_evidence() {
    let tarball = build_crate_tarball(&[
        (
            "Cargo.toml",
            "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n",
        ),
        ("src/lib.rs", "pub fn ok() {}\n"),
    ]);
    let checksum = sha256_hex(&tarball);
    let cli = Cli::parse_from(["cargo-barbican", "gatehouse", "candidate", "sample@0.1.0"]);
    let client = FakeCratesIoClient::default()
        .with_release_checksum("sample@0.1.0", "2020-05-01T00:00:00Z", false, &checksum)
        .with_tarball("sample@0.1.0", &tarball);
    let runner = FakeCommandRunner::default().with_cargo_generate_lockfile_error("lock failed");
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner_at(
        cli,
        &temp_dir,
        &client,
        &runner,
        fixed_now(),
        &mut stdout,
        &mut stderr,
    )
    .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Sandbox lockfile:"));
    assert!(rendered.contains("FAIL command exited with status 1"));
    assert!(rendered.contains("stderr: lock failed"));
    assert!(!rendered.contains("Cargo tree:"));
    assert!(!rendered.contains("Cargo audit:"));
    assert!(runner.recorded_cargo_tree_calls().is_empty());
    assert!(runner.recorded_audit_calls().is_empty());
    assert!(!runner.recorded_generate_lockfile_calls()[0].exists());
}

#[test]
fn gatehouse_candidate_renders_empty_success_output_explicitly() {
    let tarball = build_crate_tarball(&[
        (
            "Cargo.toml",
            "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n",
        ),
        ("src/lib.rs", "pub fn ok() {}\n"),
    ]);
    let checksum = sha256_hex(&tarball);
    let cli = Cli::parse_from(["cargo-barbican", "gatehouse", "candidate", "sample@0.1.0"]);
    let client = FakeCratesIoClient::default()
        .with_release_checksum("sample@0.1.0", "2020-05-01T00:00:00Z", false, &checksum)
        .with_tarball("sample@0.1.0", &tarball);
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner_at(
        cli,
        &temp_dir,
        &client,
        &runner,
        fixed_now(),
        &mut stdout,
        &mut stderr,
    )
    .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Cargo tree:\n  OK\n  output: none"));
    assert!(rendered.contains("Cargo audit:\n  OK\n  output: none"));
}

#[test]
fn gatehouse_candidate_reports_cargo_tree_failures_in_the_dossier() {
    let tarball = build_crate_tarball(&[
        (
            "Cargo.toml",
            "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n",
        ),
        ("src/lib.rs", "pub fn ok() {}\n"),
    ]);
    let checksum = sha256_hex(&tarball);
    let cli = Cli::parse_from(["cargo-barbican", "gatehouse", "candidate", "sample@0.1.0"]);
    let client = FakeCratesIoClient::default()
        .with_release_checksum("sample@0.1.0", "2020-05-01T00:00:00Z", false, &checksum)
        .with_tarball("sample@0.1.0", &tarball);
    let runner = FakeCommandRunner::default()
        .with_cargo_tree_error("tree failed")
        .with_cargo_audit("No vulnerable packages found\n");
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner_at(
        cli,
        &temp_dir,
        &client,
        &runner,
        fixed_now(),
        &mut stdout,
        &mut stderr,
    )
    .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Cargo tree:"));
    assert!(rendered.contains("stderr: tree failed"));
    assert!(rendered.contains("Cargo audit:"));
    assert!(rendered.contains("No vulnerable packages found"));
}

#[test]
fn gatehouse_candidate_renders_reviewed_release_age_exception() {
    let tarball = build_crate_tarball(&[
        (
            "Cargo.toml",
            "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n",
        ),
        ("src/lib.rs", "pub fn ok() {}\n"),
    ]);
    let checksum = sha256_hex(&tarball);
    let cli = Cli::parse_from(["cargo-barbican", "gatehouse", "candidate", "sample@0.1.0"]);
    let client = FakeCratesIoClient::default()
        .with_release_checksum("sample@0.1.0", "2020-05-26T00:00:00Z", false, &checksum)
        .with_tarball("sample@0.1.0", &tarball);
    let runner = FakeCommandRunner::default()
        .with_cargo_tree("sample v0.1.0")
        .with_cargo_audit("No vulnerable packages found");
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    write_age_exception_policy(&temp_dir, "sample", "0.1.0", &checksum, true);

    let exit_code = run_cli_with_runner_at(
        cli,
        &temp_dir,
        &client,
        &runner,
        fixed_now(),
        &mut stdout,
        &mut stderr,
    )
    .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Gatehouse candidate: sample@0.1.0"));
    assert!(rendered.contains("release age: ALLOW sample@0.1.0"));
    assert!(rendered.contains(
        "release-age exception allowed by reviewed family sample-family (docs/dependency-reviews/2026-05-27-sample.md)"
    ));
}

#[test]
fn gatehouse_candidate_fails_once_on_missing_release_age_exception_review_record() {
    let cli = Cli::parse_from(["cargo-barbican", "gatehouse", "candidate", "sample@0.1.0"]);
    let client =
        FakeCratesIoClient::default().with_release("sample@0.1.0", "2020-05-26T00:00:00Z", false);
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    write_age_exception_policy(
        &temp_dir,
        "sample",
        "0.1.0",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        false,
    );

    let exit_code = run_cli_with_runner_at(
        cli,
        &temp_dir,
        &client,
        &runner,
        fixed_now(),
        &mut stdout,
        &mut stderr,
    )
    .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains(
        "  FAIL allowed release-age exception review record not completed for sample@0.1.0: docs/dependency-reviews/2026-05-27-sample.md"
    ));
    assert!(!rendered.contains("FAIL FAIL"));
}

#[test]
fn gatehouse_candidate_escapes_hostile_cargo_tree_and_audit_output() {
    // `cargo tree`/`cargo audit` stdout can carry unicode from a git-sourced
    // transitive dependency's source URL or a RustSec advisory description,
    // so it is untrusted and must render escaped in the reviewer-facing
    // dossier rather than raw.
    let tarball = build_crate_tarball(&[
        (
            "Cargo.toml",
            "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n",
        ),
        ("src/lib.rs", "pub fn ok() {}\n"),
    ]);
    let checksum = sha256_hex(&tarball);
    let cli = Cli::parse_from(["cargo-barbican", "gatehouse", "candidate", "sample@0.1.0"]);
    let client = FakeCratesIoClient::default()
        .with_release_checksum("sample@0.1.0", "2020-05-01T00:00:00Z", false, &checksum)
        .with_tarball("sample@0.1.0", &tarball);
    let runner = FakeCommandRunner::default()
        .with_cargo_tree("sample v0.1.0\n+-- evil\u{202e}dep v0.1.0 (git+https://example.com)\n")
        .with_cargo_audit("advisory: evil\u{2066}title\u{2069}\n");
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner_at(
        cli,
        &temp_dir,
        &client,
        &runner,
        fixed_now(),
        &mut stdout,
        &mut stderr,
    )
    .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(!rendered.contains('\u{202e}'));
    assert!(!rendered.contains('\u{2066}'));
    assert!(!rendered.contains('\u{2069}'));
    assert!(rendered.contains("evil\\x202edep"));
    assert!(rendered.contains("advisory: evil\\x2066title\\x2069"));
}

#[test]
fn gatehouse_candidate_escapes_hostile_command_failure_output() {
    // `RunnerError`'s `Display` embeds the failed subprocess's raw
    // stdout/stderr verbatim, so a hostile advisory or diagnostic string
    // reaching the failure path must be escaped the same as the success path.
    let tarball = build_crate_tarball(&[
        (
            "Cargo.toml",
            "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n",
        ),
        ("src/lib.rs", "pub fn ok() {}\n"),
    ]);
    let checksum = sha256_hex(&tarball);
    let cli = Cli::parse_from(["cargo-barbican", "gatehouse", "candidate", "sample@0.1.0"]);
    let client = FakeCratesIoClient::default()
        .with_release_checksum("sample@0.1.0", "2020-05-01T00:00:00Z", false, &checksum)
        .with_tarball("sample@0.1.0", &tarball);
    let runner = FakeCommandRunner::default()
        .with_cargo_tree("sample v0.1.0\n")
        .with_cargo_audit_error("vulnerable\u{202e}dependency found");
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner_at(
        cli,
        &temp_dir,
        &client,
        &runner,
        fixed_now(),
        &mut stdout,
        &mut stderr,
    )
    .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(!rendered.contains('\u{202e}'));
    assert!(rendered.contains("vulnerable\\x202edependency found"));
}
