use super::common::*;

fn check(root: &Path, runner: &FakeCommandRunner) -> (ExitCode, String, String) {
    check_at(root, runner, fixed_now())
}

fn check_at(
    root: &Path,
    runner: &FakeCommandRunner,
    now: OffsetDateTime,
) -> (ExitCode, String, String) {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit = run_cli_with_runner_at(
        Cli::parse_from(["cargo-barbican", "gatehouse", "policy-check"]),
        root,
        &FakeCratesIoClient::default(),
        runner,
        now,
        &mut stdout,
        &mut stderr,
    )
    .unwrap();
    assert_eq!(*runner.build_calls.borrow(), 0);
    assert_eq!(*runner.test_calls.borrow(), 0);
    assert!(
        runner
            .verification_calls
            .borrow()
            .iter()
            .all(|call| *call == "metadata")
    );
    (
        exit,
        String::from_utf8(stdout).unwrap(),
        String::from_utf8(stderr).unwrap(),
    )
}

fn runner() -> FakeCommandRunner {
    FakeCommandRunner::default()
        .with_frozen_metadata(declared_crates_io_direct_metadata_json("serde", "1.0.228"))
}

#[test]
fn policy_check_composes_four_gates_once_without_execution_or_mutation() {
    let root = fresh_temp_dir();
    write_covered_enforce_fixture(&root);
    write_toolchain_pin(&root);
    let paths = [
        "Cargo.toml",
        "Cargo.lock",
        "reviewed-targets.toml",
        "docs/dependency-reviews/serde.md",
    ];
    let before = paths.map(|path| fs::read(root.join(path)).unwrap());
    let runner = runner();
    let (exit, stdout, stderr) = check(&root, &runner);
    assert_eq!(exit, ExitCode::SUCCESS, "{stdout}\n{stderr}");
    assert!(stderr.is_empty());
    for (step, token) in [
        "Toolchain check: PASS",
        "Inventory: PASS",
        "Audit: PASS",
        "Pin check: PASS",
    ]
    .iter()
    .enumerate()
    {
        assert!(stdout.contains(&format!("Step {}/4", step + 1)));
        assert!(stdout.contains(token));
    }
    assert!(stdout.find("Step 1/4") < stdout.find("Step 2/4"));
    assert!(stdout.find("Step 2/4") < stdout.find("Step 3/4"));
    assert!(stdout.find("Step 3/4") < stdout.find("Step 4/4"));
    assert!(
        stdout.ends_with("Policy checks only; build/test not run.\nGatehouse policy-check: PASS\n")
    );
    assert!(!stdout.contains("Verify: PASS"));
    assert!(!stdout.contains("Gatehouse pre-release: PASS"));
    assert!(!stdout.contains("OK   cargo"));
    assert_eq!(stdout.matches("Pin check: PASS").count(), 1);
    assert_eq!(runner.rustup_active_toolchain_calls(), 1);
    assert_eq!(runner.frozen_metadata_calls(), 1);
    assert_eq!(runner.recorded_deny_json_calls().len(), 1);
    assert_eq!(paths.map(|path| fs::read(root.join(path)).unwrap()), before);
}

#[test]
fn policy_check_stops_at_each_blocking_stage() {
    for stage in ["toolchain", "inventory", "audit", "pins"] {
        let root = fresh_temp_dir();
        write_covered_enforce_fixture(&root);
        write_toolchain_pin(&root);
        let mut runner = runner();
        match stage {
            "toolchain" => fs::remove_file(root.join("rust-toolchain.toml")).unwrap(),
            "inventory" => write_uncovered_direct_enforce_fixture(&root),
            "audit" => {
                runner = runner.with_cargo_deny_json_failure(1, &cargo_deny_bans_error_jsonl())
            }
            "pins" => {
                let path = root.join("reviewed-targets.toml");
                let text = fs::read_to_string(&path).unwrap().replace(
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    &"f".repeat(64),
                );
                fs::write(path, text).unwrap();
            }
            _ => unreachable!(),
        }
        let (exit, stdout, stderr) = check(&root, &runner);
        assert_eq!(exit, ExitCode::from(1), "{stage}: {stdout}\n{stderr}");
        assert!(
            stdout.contains(&format!("Gatehouse policy-check: FAIL ({stage})")),
            "{stdout}\n{stderr}"
        );
        assert!(!stdout.contains("Gatehouse policy-check: PASS"));
        match stage {
            "toolchain" => {
                assert_eq!(runner.frozen_metadata_calls(), 0);
                assert!(runner.recorded_deny_json_calls().is_empty());
                assert!(!stdout.contains("Step 2/4"));
            }
            "inventory" => {
                assert!(runner.recorded_deny_json_calls().is_empty());
                assert!(!stdout.contains("Step 3/4"));
            }
            "audit" => assert!(!stdout.contains("Step 4/4")),
            "pins" => assert!(stdout.contains("Step 4/4")),
            _ => unreachable!(),
        }
    }
}

#[test]
fn policy_check_requires_reviewed_policy_even_in_dependency_free_workspaces() {
    for policy in [None, Some("[rust]\nfamilies = []\n")] {
        let root = fresh_temp_dir();
        write_root_manifest(&root);
        write_toolchain_pin(&root);
        fs::write(
            root.join("Cargo.lock"),
            "version = 4\n\n[[package]]\nname=\"fixture\"\nversion=\"0.0.0\"\n",
        )
        .unwrap();
        if let Some(policy) = policy {
            fs::write(root.join("reviewed-targets.toml"), policy).unwrap();
        }
        let runner = FakeCommandRunner::default()
            .with_frozen_metadata(inventory_direct_metadata_json(&[], &[]));
        let (exit, stdout, stderr) = check(&root, &runner);
        assert_eq!(exit, ExitCode::from(1), "{stdout}\n{stderr}");
        assert!(
            stdout.contains("Gatehouse policy-check: FAIL (inventory)")
                || stdout.contains("Gatehouse policy-check: FAIL (pins)"),
            "{stdout}\n{stderr}"
        );
        if stdout.contains("FAIL (pins)") {
            assert!(stderr.contains("FAIL reviewed-targets.toml:"));
        }
        assert!(!stdout.contains("Gatehouse policy-check: PASS"));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let exit = run_cli_with_runner(
            Cli::parse_from(["cargo-barbican", "pin", "check"]),
            &root,
            &FakeCratesIoClient::default(),
            &runner,
            &mut out,
            &mut err,
        )
        .unwrap();
        assert_eq!(exit, ExitCode::SUCCESS);
        assert!(String::from_utf8(out).unwrap().contains("skipping"));
    }
}

#[test]
fn policy_check_rejects_unavailable_graph_and_scanner_evidence() {
    for failure in ["metadata", "missing-scanner", "malformed-scanner"] {
        let root = fresh_temp_dir();
        write_covered_enforce_fixture(&root);
        write_toolchain_pin(&root);
        let runner = match failure {
            "metadata" => runner().with_frozen_metadata_error("unavailable frozen graph"),
            "missing-scanner" => {
                runner().with_missing_delegate(cargo_barbican::Delegate::CargoDeny)
            }
            "malformed-scanner" => runner().with_cargo_deny_json("not JSON"),
            _ => unreachable!(),
        };
        let (exit, stdout, stderr) = check(&root, &runner);
        assert_eq!(exit, ExitCode::from(1), "{failure}: {stdout}\n{stderr}");
        assert!(!stdout.contains("Gatehouse policy-check: PASS"));
        assert!(!stdout.contains("Step 4/4"));
        if failure == "metadata" {
            assert!(runner.recorded_deny_json_calls().is_empty());
        } else {
            assert!(stderr.contains("FAIL "), "{stderr}");
        }
    }
}

#[test]
fn policy_check_validates_nextest_configuration_without_probing_the_runner() {
    let root = fresh_temp_dir();
    write_covered_enforce_fixture(&root);
    write_toolchain_pin(&root);
    fs::write(
        root.join("barbican.toml"),
        "[verify]\ntest_runner='nextest'\nnextest_version='0.9.146'\n",
    )
    .unwrap();
    let mut runner = runner();
    runner.nextest_version_result = Err("not installed".to_owned());
    let (exit, stdout, stderr) = check(&root, &runner);
    assert_eq!(exit, ExitCode::SUCCESS, "{stdout}\n{stderr}");
    let runner = runner.with_environment("CARGO_ALIAS_NEXTEST", "version");
    let (exit, stdout, stderr) = check(&root, &runner);
    assert_eq!(exit, ExitCode::from(1));
    assert!(stdout.contains("FAIL (toolchain)"));
    assert!(stderr.contains("CARGO_ALIAS_NEXTEST"));
    fs::write(
        root.join("barbican.toml"),
        "[verify]\ntest_runner='nextest'\n",
    )
    .unwrap();
    let (exit, stdout, stderr) = check(&root, &FakeCommandRunner::default());
    assert_eq!(exit, ExitCode::from(1));
    assert!(stdout.is_empty());
    assert!(stderr.starts_with("FAIL "));
}

#[test]
fn policy_check_uses_the_invocation_time_for_advisory_expiry() {
    let root = fresh_temp_dir();
    write_advisory_audit_fixture(&root, None, "2020-06-01");
    let path = root.join("Cargo.lock");
    let mut lock = fs::read_to_string(&path).unwrap();
    lock.push_str("\n[[package]]\nname=\"fixture\"\nversion=\"0.0.0\"\ndependencies=[\"serde\"]\n");
    fs::write(path, lock).unwrap();
    write_toolchain_pin(&root);
    for (seconds, expected) in [(86_399, ExitCode::SUCCESS), (86_400, ExitCode::from(1))] {
        let runner = runner().with_cargo_deny_json(&cargo_deny_advisory_jsonl());
        let now =
            OffsetDateTime::from_unix_timestamp(fixed_now().unix_timestamp() + seconds).unwrap();
        let (exit, stdout, stderr) = check_at(&root, &runner, now);
        assert_eq!(exit, expected, "{stdout}\n{stderr}");
        assert_eq!(
            stdout.contains("Gatehouse policy-check: PASS"),
            expected == ExitCode::SUCCESS
        );
    }
}

#[test]
fn policy_check_exposes_no_baseline_or_bypass_arguments() {
    for argument in [
        "--base-ref",
        "--skip",
        "--allow",
        "--format",
        "candidate",
        "--json",
    ] {
        let error = Cli::try_parse_from(["cargo-barbican", "gatehouse", "policy-check", argument])
            .unwrap_err();
        assert_eq!(error.exit_code(), 2);
    }
}
