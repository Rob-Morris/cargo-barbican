use super::common::*;

const SELECTION: &str = "[resolver]\nlockfile-path = 'private-alternate/Cargo.lock'\n";

fn write_config(root: &Path, text: &str) {
    fs::create_dir_all(root.join(".cargo")).unwrap();
    fs::write(root.join(".cargo/config.toml"), text).unwrap();
}

fn invoke(root: &Path, args: &[&str], runner: &FakeCommandRunner) -> (ExitCode, String, String) {
    let cli = Cli::parse_from(std::iter::once("cargo-barbican").chain(args.iter().copied()));
    let mut out = Vec::new();
    let mut err = Vec::new();
    let exit = run_cli_with_runner(
        cli,
        root,
        &FakeCratesIoClient::default(),
        runner,
        &mut out,
        &mut err,
    )
    .unwrap();
    (
        exit,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

fn assert_no_graph_calls(runner: &FakeCommandRunner) {
    assert_eq!(*runner.cargo_metadata_calls.borrow(), 0);
    assert_eq!(*runner.cargo_metadata_frozen_calls.borrow(), 0);
    assert_eq!(*runner.build_calls.borrow(), 0);
    assert_eq!(*runner.test_calls.borrow(), 0);
    assert!(runner.verification_calls.borrow().is_empty());
    assert!(runner.cargo_updates.borrow().is_empty());
    assert!(runner.generate_lockfile_calls.borrow().is_empty());
    assert!(runner.cargo_tree_calls.borrow().is_empty());
    assert!(runner.audit_calls.borrow().is_empty());
    assert!(runner.audit_json_calls.borrow().is_empty());
    assert!(runner.deny_json_calls.borrow().is_empty());
    assert!(runner.delegate_probes.borrow().is_empty());
    assert_eq!(*runner.rustup_active_toolchain_calls.borrow(), 0);
}

#[test]
fn every_ordinary_surface_refuses_before_cargo_discovery_or_graph_effects() {
    let commands: &[&[&str]] = &[
        &["verify"],
        &["gatehouse", "pre-release"],
        &["gatehouse", "policy-check"],
        &["gatehouse", "candidate", "serde@1.0.228"],
        &["gatehouse", "re-pin", "--base-ref", "HEAD"],
        &["update", "serde@1.0.228"],
        &["update", "--dry-run", "serde@1.0.228"],
        &["resolve"],
        &["inventory"],
        &["inventory", "--enforce"],
        &["audit"],
        &["assess"],
        &["review"],
        &["age-lock"],
        &["age", "serde@1.0.228"],
        &["pick", "serde@1"],
        &["inspect", "serde@1.0.228"],
        &["pin", "check"],
        &["pin", "add", "serde"],
        &["pin", "refresh", "serde"],
        &["pin", "list"],
        &["pin", "show", "serde"],
        &["pin", "exception", "serde", "RUSTSEC-2020-0001"],
        &["policy", "init"],
        &["toolchain", "check"],
    ];
    for policy in [None, Some("[rust]\nfamilies = []\n")] {
        let root = fresh_temp_dir();
        write_root_manifest(&root);
        write_config(&root, SELECTION);
        if let Some(policy) = policy {
            fs::write(root.join("reviewed-targets.toml"), policy).unwrap();
        }
        for args in commands {
            let runner = FakeCommandRunner::default();
            let (exit, out, err) = invoke(&root, args, &runner);
            assert_eq!(exit, ExitCode::from(1), "{args:?}: {out}\n{err}");
            assert!(err.contains("resolver.lockfile-path"), "{args:?}: {err}");
            assert!(!err.contains("private-alternate"));
            assert!(
                runner.cargo_locate_project_calls.borrow().is_empty(),
                "{args:?}"
            );
            assert_no_graph_calls(&runner);
        }
        fs::write(
            root.join("barbican.toml"),
            "[verify]\ntest_runner='nextest'\nnextest_version='0.9.146'\n",
        )
        .unwrap();
        let runner = FakeCommandRunner::default();
        assert_eq!(invoke(&root, &["verify"], &runner).0, ExitCode::from(1));
        assert_no_graph_calls(&runner);
    }
}

#[test]
fn configured_reentry_and_includes_refuse_even_without_reviewed_families() {
    let root = fresh_temp_dir();
    write_root_manifest(&root);
    for text in [
        "[env]\nCARGO_RESOLVER_LOCKFILE_PATH='private-alternate/Cargo.lock'",
        "[env.CARGO_RESOLVER_LOCKFILE_PATH]\nvalue='private-alternate/Cargo.lock'\nforce=true\nrelative=true",
        "include=['private-alternate.toml']",
    ] {
        write_config(&root, text);
        let runner = FakeCommandRunner::default();
        let (exit, _, err) = invoke(&root, &["pin", "check"], &runner);
        assert_eq!(exit, ExitCode::from(1));
        assert!(err.contains("default workspace Cargo.lock"), "{err}");
        assert!(!err.contains("private-alternate"));
        assert!(runner.cargo_locate_project_calls.borrow().is_empty());
        assert_no_graph_calls(&runner);
    }
}

#[test]
fn changed_execution_root_and_relative_cargo_home_are_checked_before_graph_use() {
    for home_config in [false, true] {
        let fixture = fresh_temp_dir();
        let invocation = fixture.join("member");
        let root = fixture.join("elsewhere");
        fs::create_dir_all(&invocation).unwrap();
        fs::create_dir_all(&root).unwrap();
        write_root_manifest(&invocation);
        write_root_manifest(&root);
        if home_config {
            fs::create_dir_all(root.join(".cargo-home")).unwrap();
            fs::write(root.join(".cargo-home/config.toml"), SELECTION).unwrap();
        } else {
            write_config(&root, SELECTION);
        }
        let runner = FakeCommandRunner::default().with_workspace_manifest(&root.join("Cargo.toml"));
        let (exit, _, err) = invoke(&invocation, &["resolve"], &runner);
        assert_eq!(exit, ExitCode::from(1));
        assert!(err.contains("resolver.lockfile-path"), "{err}");
        assert_eq!(runner.cargo_locate_project_calls.borrow().len(), 1);
        assert_no_graph_calls(&runner);
    }
}

#[test]
fn member_configuration_is_checked_only_when_cargo_is_invoked_from_member() {
    let root = fresh_temp_dir();
    write_root_manifest(&root);
    let member = root.join("member");
    fs::create_dir_all(&member).unwrap();
    write_root_manifest(&member);
    write_config(&member, SELECTION);
    let runner = FakeCommandRunner::default().with_workspace_manifest(&root.join("Cargo.toml"));
    let (exit, out, err) = invoke(&root, &["pin", "check"], &runner);
    assert_eq!(exit, ExitCode::SUCCESS, "{out}\n{err}");
    assert!(out.contains("skipping"));
    let runner = FakeCommandRunner::default().with_workspace_manifest(&root.join("Cargo.toml"));
    let (exit, _, _) = invoke(&member, &["pin", "check"], &runner);
    assert_eq!(exit, ExitCode::from(1));
    assert!(runner.cargo_locate_project_calls.borrow().is_empty());
}

#[test]
fn effective_file_precedence_ancestors_and_cargo_home_are_preserved() {
    let fixture = fresh_temp_dir();
    let root = fixture.join("workspace");
    fs::create_dir_all(&root).unwrap();
    write_root_manifest(&root);
    write_config(&root, SELECTION);
    fs::write(root.join(".cargo/config"), "[build]\njobs=2").unwrap();
    let runner = FakeCommandRunner::default();
    assert_eq!(
        invoke(&root, &["pin", "check"], &runner).0,
        ExitCode::SUCCESS
    );
    fs::write(root.join(".cargo/config"), SELECTION).unwrap();
    fs::write(root.join(".cargo/config.toml"), "[build]\njobs=2").unwrap();
    assert_eq!(
        invoke(&root, &["pin", "check"], &runner).0,
        ExitCode::from(1)
    );
    fs::remove_dir_all(root.join(".cargo")).unwrap();
    write_config(&fixture, SELECTION);
    assert_eq!(
        invoke(&root, &["pin", "check"], &runner).0,
        ExitCode::from(1)
    );
    fs::remove_dir_all(fixture.join(".cargo")).unwrap();
    let home = fixture.join("cargo-home");
    fs::create_dir_all(&home).unwrap();
    fs::write(home.join("config.toml"), SELECTION).unwrap();
    let runner =
        FakeCommandRunner::default().with_environment("CARGO_HOME", home.to_str().unwrap());
    assert_eq!(
        invoke(&root, &["pin", "check"], &runner).0,
        ExitCode::from(1)
    );
    assert!(runner.cargo_locate_project_calls.borrow().is_empty());
}

#[test]
fn ordinary_default_and_sanitised_direct_resolver_environment_remain_supported() {
    let root = fresh_temp_dir();
    write_root_manifest(&root);
    write_config(
        &root,
        "[resolver]\nincompatible-rust-versions='fallback'\n[unstable]\nlockfile-path=true\n",
    );
    let runner = FakeCommandRunner::default()
        .with_environment("CARGO_RESOLVER_LOCKFILE_PATH", "not-consumed/Cargo.lock");
    let (exit, out, err) = invoke(&root, &["pin", "check"], &runner);
    assert_eq!(exit, ExitCode::SUCCESS, "{out}\n{err}");
    assert!(out.contains("skipping"));
    assert_eq!(runner.cargo_locate_project_calls.borrow().len(), 1);
}

#[test]
fn new_temporary_execution_roots_are_checked_before_graph_mutation() {
    const CHILD: &str = "BARBICAN_LOCKFILE_IDENTITY_SCRATCH_CHILD";
    if env::var_os(CHILD).is_none() {
        let fixture = fresh_temp_dir();
        let source = fixture.join("source");
        let temporary = fixture.join("temporary");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&temporary).unwrap();
        write_config(&temporary, SELECTION);
        let output = std::process::Command::new(env::current_exe().unwrap())
            .args(["--exact", "lockfile_identity::new_temporary_execution_roots_are_checked_before_graph_mutation", "--nocapture"])
            .env(CHILD, &source)
            .env("TMPDIR", &temporary)
            .env("TMP", &temporary)
            .env("TEMP", &temporary)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let source = PathBuf::from(env::var_os(CHILD).unwrap());
    write_root_manifest(&source);
    let lock = lockfile_with_packages(&[("serde", "1.0.228", true)]);
    fs::write(source.join("Cargo.lock"), &lock).unwrap();
    fs::set_permissions(source.join("Cargo.lock"), fs::Permissions::from_mode(0o640)).unwrap();
    let client =
        FakeCratesIoClient::default().with_release("serde@1.0.228", "2020-01-01T00:00:00Z", false);
    for args in [
        vec!["gatehouse", "candidate", "serde@1.0.228"],
        vec![
            "gatehouse",
            "candidate",
            "serde@1.0.228",
            "--preserve-sandbox",
        ],
        vec!["update", "--dry-run", "serde@1.0.228"],
    ] {
        let runner = FakeCommandRunner::default();
        let cli = Cli::parse_from(std::iter::once("cargo-barbican").chain(args.iter().copied()));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let exit = run_cli_with_runner(cli, &source, &client, &runner, &mut out, &mut err).unwrap();
        assert_eq!(
            exit,
            ExitCode::from(1),
            "{args:?}: {}",
            String::from_utf8_lossy(&out)
        );
        if args[0] == "gatehouse" {
            assert!(err.is_empty());
            let rendered = String::from_utf8(out).unwrap();
            assert!(rendered.contains("Inspect evidence:"));
            assert!(rendered.contains("FAIL unable to prepare candidate sandbox:"));
            assert!(rendered.contains("resolver.lockfile-path"));
            assert!(rendered.contains("Suggested next step:"));
            let sandbox = PathBuf::from(
                rendered
                    .lines()
                    .find_map(|line| line.strip_prefix("  path: "))
                    .unwrap(),
            );
            if args.contains(&"--preserve-sandbox") {
                assert!(rendered.contains("status: preserved for inspection"));
                assert!(sandbox.join("Cargo.toml").is_file());
                fs::remove_dir_all(&sandbox).unwrap();
            }
            assert!(!sandbox.exists());
        } else {
            assert!(String::from_utf8_lossy(&err).contains("resolver.lockfile-path"));
        }
        assert_eq!(runner.cargo_locate_project_calls.borrow().len(), 1);
        assert_no_graph_calls(&runner);
        assert_eq!(fs::read_to_string(source.join("Cargo.lock")).unwrap(), lock);
        assert_eq!(
            fs::metadata(source.join("Cargo.lock"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
    }
}

#[test]
fn static_toolchain_review_does_not_acquire_graph_configuration_constraints() {
    let root = fresh_temp_dir();
    let runner = FakeCommandRunner::default();
    let baseline = invoke(
        &root,
        &[
            "toolchain",
            "review",
            "not-an-exact-release",
            "--standalone",
        ],
        &runner,
    );
    write_config(&root, SELECTION);
    let guarded = invoke(
        &root,
        &[
            "toolchain",
            "review",
            "not-an-exact-release",
            "--standalone",
        ],
        &runner,
    );
    assert_eq!(baseline, guarded);
    assert!(!guarded.2.contains("resolver.lockfile-path"));
    assert!(runner.cargo_locate_project_calls.borrow().is_empty());
    assert_no_graph_calls(&runner);
}

#[test]
fn cargo_home_symlink_exception_keeps_its_existing_trust_boundary() {
    use std::os::unix::fs::symlink;
    let fixture = fresh_temp_dir();
    let root = fixture.join("workspace");
    let home = fixture.join("home");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&home).unwrap();
    write_root_manifest(&root);
    fs::write(home.join("shared.toml"), "[build]\njobs=2").unwrap();
    symlink("shared.toml", home.join("config.toml")).unwrap();
    let runner =
        FakeCommandRunner::default().with_environment("CARGO_HOME", home.to_str().unwrap());
    assert_eq!(
        invoke(&root, &["pin", "check"], &runner).0,
        ExitCode::SUCCESS
    );
    fs::write(home.join("shared.toml"), SELECTION).unwrap();
    assert_eq!(
        invoke(&root, &["pin", "check"], &runner).0,
        ExitCode::from(1)
    );
    fs::remove_file(home.join("config.toml")).unwrap();
    fs::write(root.join("shared.toml"), "[build]\njobs=2").unwrap();
    symlink(root.join("shared.toml"), home.join("config.toml")).unwrap();
    assert!(
        invoke(&root, &["pin", "check"], &runner)
            .2
            .contains("resolves inside the workspace")
    );
    fs::remove_file(home.join("config.toml")).unwrap();
    fs::create_dir_all(root.join(".cargo")).unwrap();
    symlink("../shared.toml", root.join(".cargo/config.toml")).unwrap();
    assert!(
        invoke(&root, &["pin", "check"], &runner)
            .2
            .contains("is a symlink")
    );
}
