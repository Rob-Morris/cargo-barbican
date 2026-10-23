use super::common::*;

#[test]
fn assessment_reuses_one_captured_baseline_for_lock_and_all_manifests() {
    let workspace = Workspace::new();
    fs::write(workspace.lock(), "version = 4\n").unwrap();
    let runner = FakeCommandRunner::default()
        .with_git_show("HEAD:Cargo.lock", "version = 4\n")
        .with_git_show(
            "HEAD:Cargo.toml",
            &fs::read_to_string(workspace.0.join("Cargo.toml")).unwrap(),
        );
    let (exit, _, err) = invoke(
        &["assess"],
        &workspace.0,
        &FakeCratesIoClient::default(),
        &runner,
    );
    assert_eq!(exit, ExitCode::SUCCESS, "{err}");
    assert_eq!(*runner.git_resolve_calls.borrow(), ["HEAD"]);
    assert_eq!(*runner.git_prefix_calls.borrow(), 1);
}

struct Workspace(TempDirGuard);
impl Workspace {
    fn new() -> Self {
        let root = fresh_temp_dir();
        write_root_manifest(&root);
        Self(root)
    }
    fn lock(&self) -> PathBuf {
        self.0.join("Cargo.lock")
    }
}

fn invoke(
    args: &[&str],
    root: &Path,
    client: &impl CratesIoClient,
    runner: &impl CommandRunner,
) -> (ExitCode, String, String) {
    let cli = Cli::parse_from(std::iter::once("cargo-barbican").chain(args.iter().copied()));
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit = run_cli_with_runner_at(
        cli,
        root,
        client,
        runner,
        fixed_now(),
        &mut stdout,
        &mut stderr,
    )
    .unwrap();
    (
        exit,
        String::from_utf8(stdout).unwrap(),
        String::from_utf8(stderr).unwrap(),
    )
}

#[test]
fn first_graph_checks_every_registry_selection_and_restores_absence_on_policy_or_http_failure() {
    for verdict in ["old", "fresh", "yanked", "http"] {
        let workspace = Workspace::new();
        let graph =
            lockfile_with_packages(&[("direct", "1.0.0", true), ("transitive", "2.0.0", true)]);
        let runner = FakeCommandRunner::default().with_generated_lockfile(&graph);
        let mut client = FakeCratesIoClient::default().with_release(
            "direct@1.0.0",
            "2019-01-01T00:00:00Z",
            false,
        );
        if verdict != "http" {
            client = client.with_release(
                "transitive@2.0.0",
                if verdict == "fresh" {
                    "2020-05-31T00:00:00Z"
                } else {
                    "2019-01-01T00:00:00Z"
                },
                verdict == "yanked",
            );
        }
        let (exit, out, err) = invoke(&["resolve"], &workspace.0, &client, &runner);
        assert!(
            out.contains("Initial resolution: no previous Cargo.lock existed"),
            "{out}"
        );
        let mut fetches = client.recorded_fetches();
        fetches.sort();
        assert_eq!(fetches, ["direct@1.0.0", "transitive@2.0.0"]);
        assert_eq!(runner.recorded_generate_lockfile_calls().len(), 1);
        if verdict == "old" {
            assert_eq!(exit, ExitCode::SUCCESS, "{err}");
            assert_eq!(fs::read_to_string(workspace.lock()).unwrap(), graph);
        } else {
            assert_eq!(exit, ExitCode::from(1), "{out}");
            assert!(!workspace.lock().exists(), "{err}");
            assert!(err.contains("FAIL"), "{err}");
        }
    }
}

#[test]
fn empty_first_graph_and_unchanged_existing_graph_need_no_release_http() {
    for initial in [true, false] {
        let workspace = Workspace::new();
        let graph = if initial {
            "version = 4\n".to_owned()
        } else {
            lockfile_with_packages(&[("old", "1.0.0", true)])
        };
        if !initial {
            fs::write(workspace.lock(), &graph).unwrap();
        }
        let runner = FakeCommandRunner::default().with_generated_lockfile(&graph);
        let client = FakeCratesIoClient::default();
        let (exit, out, err) = invoke(&["resolve"], &workspace.0, &client, &runner);
        assert_eq!(exit, ExitCode::SUCCESS, "{err}");
        assert!(
            out.contains("no newly selected crates.io packages"),
            "{out}"
        );
        assert_eq!(out.contains("Initial resolution"), initial);
        assert!(client.recorded_fetches().is_empty());
    }
}

#[test]
fn resolve_write_then_error_and_output_writer_failure_restore_absence() {
    let workspace = Workspace::new();
    let runner = FakeCommandRunner::default()
        .with_generated_lockfile("version = 4\n")
        .with_cargo_generate_lockfile_error("wrote then failed");
    let (exit, _, err) = invoke(
        &["resolve"],
        &workspace.0,
        &FakeCratesIoClient::default(),
        &runner,
    );
    assert_eq!(exit, ExitCode::from(1));
    assert!(err.contains("wrote then failed"), "{err}");
    assert!(!workspace.lock().exists());
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("broken stdout"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let runner = FakeCommandRunner::default().with_generated_lockfile("version = 4\n");
    let mut stderr = Vec::new();
    let exit = run_cli_with_runner_at(
        Cli::parse_from(["cargo-barbican", "resolve"]),
        &workspace.0,
        &FakeCratesIoClient::default(),
        &runner,
        fixed_now(),
        &mut Broken,
        &mut stderr,
    )
    .unwrap();
    assert_eq!(exit, ExitCode::from(1));
    assert_eq!(runner.recorded_generate_lockfile_calls().len(), 1);
    assert!(String::from_utf8(stderr).unwrap().contains("broken stdout"));
    assert!(!workspace.lock().exists());
}

#[test]
fn update_metadata_write_then_failure_parse_or_selection_error_restores_original() {
    for failure in ["delegate", "parse", "selection"] {
        let workspace = Workspace::new();
        let original = lockfile_with_packages(&[("demo", "1.0.0", true)]);
        fs::write(workspace.lock(), &original).unwrap();
        let runner = FakeCommandRunner {
            cargo_metadata_lockfile_text: Some("# metadata changed it\nversion = 4\n".to_owned()),
            cargo_metadata_result: match failure {
                "delegate" => Err("metadata wrote then failed".to_owned()),
                "parse" => Ok("malformed json".to_owned()),
                _ => Ok(metadata_with_packages(&[])),
            },
            ..Default::default()
        };
        let client =
            FakeCratesIoClient::default().with_release("demo@1.0.1", "2019-01-01T00:00:00Z", false);
        let (exit, _, err) = invoke(&["update", "demo@1.0.1"], &workspace.0, &client, &runner);
        assert_eq!(exit, ExitCode::from(1), "{err}");
        assert_eq!(*runner.cargo_metadata_calls.borrow(), 1);
        assert!(runner.recorded_updates().is_empty());
        assert_eq!(fs::read_to_string(workspace.lock()).unwrap(), original);
    }
}

#[test]
fn update_second_precise_failure_restores_before_metadata_not_the_intermediate_graph() {
    let workspace = Workspace::new();
    let original = lockfile_with_packages(&[("first", "1.0.0", true), ("second", "1.0.0", true)]);
    fs::write(workspace.lock(), &original).unwrap();
    let mut runner = FakeCommandRunner::default().with_cargo_metadata(&metadata_with_packages(&[
        (
            "first",
            "1.0.0",
            "registry+https://github.com/rust-lang/crates.io-index#first@1.0.0",
        ),
        (
            "second",
            "1.0.0",
            "registry+https://github.com/rust-lang/crates.io-index#second@1.0.0",
        ),
    ]));
    runner.cargo_metadata_lockfile_text = Some("# metadata\nversion = 4\n".to_owned());
    runner.cargo_update_steps = vec![
        (Some("# first precise\nversion = 4\n".to_owned()), Ok(())),
        (
            Some("partial second precise".to_owned()),
            Err("second precise failed".to_owned()),
        ),
    ];
    let client = FakeCratesIoClient::default()
        .with_release("first@2.0.0", "2019-01-01T00:00:00Z", false)
        .with_release("second@2.0.0", "2019-01-01T00:00:00Z", false);
    let (exit, _, err) = invoke(
        &["update", "first@2.0.0", "second@2.0.0"],
        &workspace.0,
        &client,
        &runner,
    );
    assert_eq!(exit, ExitCode::from(1), "{err}");
    assert!(err.contains("second precise failed"), "{err}");
    assert_eq!(runner.recorded_updates().len(), 2);
    assert_eq!(fs::read_to_string(workspace.lock()).unwrap(), original);
}

#[test]
fn invalid_initial_lock_stops_update_before_http_and_delegate_work() {
    let workspace = Workspace::new();
    for bytes in [b"bad TOML".as_slice(), &[255, 254]] {
        fs::write(workspace.lock(), bytes).unwrap();
        let runner = FakeCommandRunner::default();
        let client = FakeCratesIoClient::default();
        let (exit, _, _) = invoke(&["update", "demo@2.0.0"], &workspace.0, &client, &runner);
        assert_eq!(exit, ExitCode::from(1));
        assert!(client.recorded_fetches().is_empty());
        assert_eq!(*runner.cargo_metadata_calls.borrow(), 0);
        assert_eq!(fs::read(workspace.lock()).unwrap(), bytes);
    }
}

#[test]
fn git_baseline_is_captured_once_and_uses_literal_workspace_prefix() {
    for prefix in ["nested/", "rust space-é/", "rust\nline/"] {
        let workspace = Workspace::new();
        fs::write(workspace.lock(), "version = 4\n").unwrap();
        let commit = "a".repeat(40);
        let mut runner = FakeCommandRunner::default()
            .with_git_show("moving^{commit}", &commit)
            .with_git_show(&format!("{commit}:{prefix}Cargo.lock"), "version = 4\n");
        runner.git_prefix_result = Ok(format!("{prefix}\n"));
        let (exit, _, err) = invoke(
            &["age-lock", "--base-ref", "moving"],
            &workspace.0,
            &FakeCratesIoClient::default(),
            &runner,
        );
        assert_eq!(exit, ExitCode::SUCCESS, "{err}");
        assert_eq!(*runner.git_resolve_calls.borrow(), ["moving"]);
        assert_eq!(*runner.git_prefix_calls.borrow(), 1);
    }
}

#[test]
fn commit_identity_requires_one_complete_sha1_or_sha256_and_guidance_is_command_specific() {
    let workspace = Workspace::new();
    fs::write(workspace.lock(), "version = 4\n").unwrap();
    for output in [
        "a".repeat(40),
        "b".repeat(64),
        "bad".to_owned(),
        format!("{}\n{}", "a".repeat(40), "b".repeat(40)),
    ] {
        let runner = FakeCommandRunner::default()
            .with_git_show("HEAD^{commit}", &output)
            .with_git_show(&format!("{output}:Cargo.lock"), "version = 4\n");
        let (exit, _, err) = invoke(
            &["age-lock"],
            &workspace.0,
            &FakeCratesIoClient::default(),
            &runner,
        );
        if matches!(output.len(), 40 | 64) {
            assert_eq!(exit, ExitCode::SUCCESS, "{err}");
        } else {
            assert_eq!(exit, ExitCode::from(1));
            assert!(err.contains("--base-lockfile"), "{err}");
        }
    }
    let runner =
        FakeCommandRunner::default().with_git_show_error("HEAD^{commit}", "unavailable history");
    let (exit, _, err) = invoke(
        &["review"],
        &workspace.0,
        &FakeCratesIoClient::default(),
        &runner,
    );
    assert_eq!(exit, ExitCode::from(1));
    assert!(
        err.contains("unavailable history") && err.contains("--base-dir"),
        "{err}"
    );
    assert!(!err.contains("--base-ref"), "{err}");
    assert_eq!(*runner.git_prefix_calls.borrow(), 0);
}

#[test]
fn absolute_current_path_cannot_discard_filesystem_baseline_and_no_git_is_needed() {
    let workspace = Workspace::new();
    fs::write(workspace.lock(), "version = 4\n").unwrap();
    fs::create_dir(workspace.0.join("before")).unwrap();
    fs::write(workspace.0.join("before/Cargo.lock"), "malformed baseline").unwrap();
    let runner = FakeCommandRunner::default();
    let absolute = workspace.lock().display().to_string();
    for lock in ["Cargo.lock", &absolute] {
        let (exit, _, err) = invoke(
            &["assess", "--base-dir", "before", "--lockfile", lock],
            &workspace.0,
            &FakeCratesIoClient::default(),
            &runner,
        );
        assert_eq!(exit, ExitCode::from(1));
        assert!(
            err.contains("before") && !err.contains("Git baseline"),
            "{err}"
        );
    }
    assert!(runner.git_resolve_calls.borrow().is_empty());
    assert_eq!(*runner.git_prefix_calls.borrow(), 0);
}
