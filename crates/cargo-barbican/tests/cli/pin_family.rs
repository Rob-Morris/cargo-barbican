use super::common::*;

fn run(root: &Path, args: &[&str]) -> (ExitCode, String, String) {
    let cli = Cli::parse_from(std::iter::once("cargo-barbican").chain(args.iter().copied()));
    let runner = FakeCommandRunner::default();
    let client = FakeCratesIoClient::default();
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = run_cli_with_runner_at(cli, root, &client, &runner, fixed_now(), &mut out, &mut err)
        .unwrap();
    assert_eq!(*runner.cargo_metadata_frozen_calls.borrow(), 0);
    assert_eq!(*runner.cargo_metadata_calls.borrow(), 0);
    assert!(client.fetches.borrow().is_empty());
    assert_eq!(*runner.build_calls.borrow(), 0);
    (
        code,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

fn fixture(name: &str) -> TempDirGuard {
    let root = fresh_temp_dir();
    write_pin_add_workspace(&root);
    assert_eq!(run_pin_add(&root, "serde").0, ExitCode::SUCCESS);
    let text = fs::read_to_string(root.join("reviewed-targets.toml"))
        .unwrap()
        .replace(
            "\"serde-2020-06-01\"",
            &serde_json::to_string(name).unwrap(),
        );
    fs::write(root.join("reviewed-targets.toml"), text).unwrap();
    let mut lock = fs::read_to_string(root.join("Cargo.lock")).unwrap();
    lock.push_str(&format!("\n[[package]]\nname='serde_derive'\nversion='1.0.228'\nsource='registry+https://github.com/rust-lang/crates.io-index'\nchecksum='{PIN_ADD_TEST_CHECKSUM}'\n"));
    fs::write(root.join("Cargo.lock"), &lock).unwrap();
    root
}

#[test]
fn family_discover_inspect_extend_repeat_preserves_shared_pending_history() {
    let root = fixture("family");
    let record = root.join("docs/dependency-reviews/2020-06-01-serde.md");
    fs::write(&record, "# Completed original review\nold evidence\n").unwrap();
    let mut text = fs::read_to_string(root.join("reviewed-targets.toml")).unwrap();
    text.push_str("\n[[rust.families]]\nname='sibling'\nreview_record='./docs/dependency-reviews/2020-06-01-serde.md'\n[rust.families.resolved]\nunrelated='1.0.0'\n");
    fs::write(root.join("reviewed-targets.toml"), text).unwrap();
    let listed = run(&root, &["pin", "list"]);
    assert_eq!(listed.0, ExitCode::SUCCESS);
    assert!(listed.1.contains("family, sibling"));
    let shown = run(&root, &["pin", "show", "family"]);
    assert!(shown.1.contains("checksum_sha256"));
    assert!(shown.1.contains("Direct serde:"));
    let first = run(
        &root,
        &["pin", "add", "--family=family", "serde", "serde_derive"],
    );
    assert_eq!(first.0, ExitCode::SUCCESS, "{}", first.2);
    assert!(first.1.contains("already a member"));
    assert!(first.1.contains("sibling"));
    let evidence = fs::read_to_string(&record).unwrap();
    assert!(evidence.contains("old evidence\n"));
    assert_eq!(evidence.matches(REVIEW_RECORD_SCAFFOLD_MARKER).count(), 1);
    assert_eq!(evidence.matches("## Family addition review").count(), 1);
    let policy = fs::read(root.join("reviewed-targets.toml")).unwrap();
    let repeat = run(&root, &["pin", "add", "--family=family", "serde_derive"]);
    assert_eq!(repeat.0, ExitCode::SUCCESS);
    assert!(repeat.1.contains("no changes"));
    assert!(repeat.1.contains("PENDING"));
    assert_eq!(fs::read(&record).unwrap(), evidence.as_bytes());
    assert_eq!(
        fs::read(root.join("reviewed-targets.toml")).unwrap(),
        policy
    );
    let checked = run(&root, &["pin", "check"]);
    assert_ne!(checked.0, ExitCode::SUCCESS);
    assert!(checked.1.contains("sibling"));
}

#[test]
fn option_looking_and_shell_metacharacter_names_survive_real_cli_boundaries() {
    for name in ["--help", "-x", "--", "a space", "a'$(touch pwned); b"] {
        let root = fixture(name);
        let list = run(&root, &["pin", "list"]);
        assert_eq!(list.0, ExitCode::SUCCESS);
        assert!(list.1.contains("pin show -- '"));
        assert_eq!(
            run(&root, &["pin", "show", "--", name]).0,
            ExitCode::SUCCESS
        );
        let selection = format!("--family={name}");
        let added = run(&root, &["pin", "add", &selection, "serde_derive"]);
        assert_eq!(added.0, ExitCode::SUCCESS, "{}", added.2);
        assert!(
            run(&root, &["pin", "add", &selection, "serde_derive"])
                .1
                .contains("no changes")
        );
        assert!(!root.join("pwned").exists());
    }
}

#[test]
fn list_and_show_keep_optional_lock_and_record_failures_diagnostic() {
    let root = fixture("family");
    for text in [None, Some("not a lockfile {")] {
        if let Some(text) = text {
            fs::write(root.join("Cargo.lock"), text).unwrap();
        } else {
            fs::remove_file(root.join("Cargo.lock")).unwrap();
        }
        let result = run(&root, &["pin", "show", "family"]);
        assert_eq!(result.0, ExitCode::SUCCESS);
        assert!(result.1.contains("parity: unavailable"));
    }
    fs::remove_file(root.join("docs/dependency-reviews/2020-06-01-serde.md")).unwrap();
    assert!(run(&root, &["pin", "list"]).1.contains("missing"));
    assert_ne!(run(&root, &["pin", "show", "Family"]).0, ExitCode::SUCCESS);
    fs::write(root.join("reviewed-targets.toml"), "[rust]\n").unwrap();
    assert!(
        run(&root, &["pin", "list"])
            .1
            .contains("No reviewed families")
    );
    fs::write(root.join("reviewed-targets.toml"), "invalid {").unwrap();
    assert_ne!(run(&root, &["pin", "list"]).0, ExitCode::SUCCESS);
}

#[test]
fn detail_explains_expected_current_parity_without_echoing_source_credentials() {
    let root = fixture("family");
    fs::write(root.join("Cargo.toml"), "[dependencies]\nserde='^1'\n").unwrap();
    let lock = fs::read_to_string(root.join("Cargo.lock"))
        .unwrap()
        .replace("1.0.228", "1.0.100");
    fs::write(root.join("Cargo.lock"), &lock).unwrap();
    let result = run(&root, &["pin", "show", "family"]);
    assert_eq!(result.0, ExitCode::SUCCESS);
    assert!(
        result
            .1
            .contains("Direct mismatch: serde; expected =1.0.228; current")
    );
    assert!(result.1.contains("^1"));
    assert!(
        result
            .1
            .contains("Resolved mismatch: serde; expected serde@1.0.228")
    );
    assert!(result.1.contains("current versions {\"1.0.100\"}"));
    assert!(result.1.contains("checksumless false"));
    fs::write(
        root.join("Cargo.lock"),
        lock.replace(
            "registry+https://github.com/rust-lang/crates.io-index",
            "git+https://user:SECRET@example.org/repo?rev=bad#bad",
        ),
    )
    .unwrap();
    let result = run(&root, &["pin", "show", "family"]);
    assert_eq!(result.0, ExitCode::SUCCESS);
    assert!(!result.1.contains("SECRET"));
    assert!(result.1.contains("unsupported Git source"));
}

#[test]
fn a_bad_item_or_duplicate_refuses_whole_batch_without_record_writes() {
    for specs in [
        vec!["serde_derive", "absent"],
        vec!["serde_derive", "serde_derive@1.0.228"],
    ] {
        let root = fixture("family");
        let policy = fs::read(root.join("reviewed-targets.toml")).unwrap();
        let record = fs::read(root.join("docs/dependency-reviews/2020-06-01-serde.md")).unwrap();
        let mut args = vec!["pin", "add", "--family=family"];
        args.extend(specs);
        assert_ne!(run(&root, &args).0, ExitCode::SUCCESS);
        assert_eq!(
            fs::read(root.join("reviewed-targets.toml")).unwrap(),
            policy
        );
        assert_eq!(
            fs::read(root.join("docs/dependency-reviews/2020-06-01-serde.md")).unwrap(),
            record
        );
    }
    let root = fixture("family");
    assert_eq!(
        run(&root, &["pin", "add", "serde", "serde_derive"]).0,
        ExitCode::from(2)
    );
    assert_ne!(
        run(&root, &["pin", "add", "--family=typo", "serde_derive"]).0,
        ExitCode::SUCCESS
    );
}

#[test]
fn noops_skip_mutation_prerequisites_but_new_members_do_not() {
    let root = fixture("family");
    let record = root.join("docs/dependency-reviews/2020-06-01-serde.md");
    fs::remove_file(&record).unwrap();
    assert_eq!(
        run(&root, &["pin", "add", "--family=family", "serde"]).0,
        ExitCode::SUCCESS
    );
    assert_ne!(
        run(&root, &["pin", "add", "--family=family", "serde_derive"]).0,
        ExitCode::SUCCESS
    );
    fs::write(&record, "# evidence\n").unwrap();
    let mut mode = fs::metadata(&record).unwrap().permissions();
    mode.set_readonly(true);
    fs::set_permissions(&record, mode).unwrap();
    assert_eq!(
        run(&root, &["pin", "add", "--family=family", "serde"]).0,
        ExitCode::SUCCESS
    );
    assert_ne!(
        run(&root, &["pin", "add", "--family=family", "serde_derive"]).0,
        ExitCode::SUCCESS
    );
}

#[test]
fn extension_preserves_expired_grants_and_never_grants_the_new_member_an_exception() {
    let root = fresh_temp_dir();
    write_advisory_audit_fixture(&root, None, "2000-01-01");
    let mut text = fs::read_to_string(root.join("reviewed-targets.toml")).unwrap();
    text.push_str("\n[rust.families.allowed_age_exceptions]\nserde='1.0.228'\n[rust.families.allowed_surfaces]\nserde=['build-rs']\n");
    fs::write(root.join("reviewed-targets.toml"), text).unwrap();
    let before = barbican::parse_reviewed_targets_toml(
        &fs::read_to_string(root.join("reviewed-targets.toml")).unwrap(),
    )
    .unwrap();
    let mut lock = fs::read_to_string(root.join("Cargo.lock")).unwrap();
    lock.push_str(&format!("\n[[package]]\nname='serde_derive'\nversion='1.0.228'\nsource='registry+https://github.com/rust-lang/crates.io-index'\nchecksum='{PIN_ADD_TEST_CHECKSUM}'\n"));
    fs::write(root.join("Cargo.lock"), &lock).unwrap();
    let added = run(
        &root,
        &["pin", "add", "--family=serde-family", "serde_derive"],
    );
    assert_eq!(added.0, ExitCode::SUCCESS, "{}", added.2);
    let after = barbican::parse_reviewed_targets_toml(
        &fs::read_to_string(root.join("reviewed-targets.toml")).unwrap(),
    )
    .unwrap();
    let (old, new) = (&before.rust_families()[0], &after.rust_families()[0]);
    assert_eq!(old.advisory_exceptions(), new.advisory_exceptions());
    assert_eq!(old.release_age_exceptions(), new.release_age_exceptions());
    assert_eq!(
        old.execution_surface_allowances(),
        new.execution_surface_allowances()
    );
    assert!(
        new.advisory_exceptions()
            .iter()
            .all(|grant| grant.spec().crate_name() == "serde")
    );
    let record = root.join(old.review_record());
    let pending = fs::read_to_string(&record).unwrap();
    let completed = pending
        .lines()
        .filter(|line| !line.contains(REVIEW_RECORD_SCAFFOLD_MARKER))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&record, completed).unwrap();
    let runner = FakeCommandRunner::default().with_cargo_deny_json(&cargo_deny_advisory_jsonl());
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = run_cli_with_runner_at(
        Cli::parse_from(["barbican", "audit"]),
        &root,
        &FakeCratesIoClient::default(),
        &runner,
        fixed_now(),
        &mut out,
        &mut err,
    )
    .unwrap();
    assert_eq!(code, ExitCode::from(1));
    assert!(
        String::from_utf8(out)
            .unwrap()
            .contains("reviewed advisory exception expired")
    );
    let client = FakeCratesIoClient::default().with_release(
        "serde_derive@1.0.228",
        "2020-06-01T00:00:00Z",
        false,
    );
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = run_cli_with_runner_at(
        Cli::parse_from(["barbican", "age", "serde_derive@1.0.228"]),
        &root,
        &client,
        &FakeCommandRunner::default(),
        fixed_now(),
        &mut out,
        &mut err,
    )
    .unwrap();
    assert_eq!(code, ExitCode::from(1));
    assert!(!String::from_utf8(out).unwrap().contains("ALLOW"));

    let invoke = |args: &[&str], client: &FakeCratesIoClient, runner: &FakeCommandRunner| {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_cli_with_runner_at(
            Cli::parse_from(std::iter::once("barbican").chain(args.iter().copied())),
            &root,
            client,
            runner,
            fixed_now(),
            &mut out,
            &mut err,
        )
        .unwrap();
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    };
    for (client, diagnostic) in [
        (
            FakeCratesIoClient::default().with_release(
                "serde@1.0.228",
                "2020-05-01T00:00:00Z",
                true,
            ),
            "version is yanked on crates.io",
        ),
        (
            FakeCratesIoClient::default().with_release_checksum(
                "serde@1.0.228",
                "2020-06-01T00:00:00Z",
                false,
                &"a".repeat(64),
            ),
            "release-age exception artefact mismatch",
        ),
    ] {
        let result = invoke(
            &["age", "serde@1.0.228"],
            &client,
            &FakeCommandRunner::default(),
        );
        assert_eq!(result.0, ExitCode::from(1));
        assert!(!result.1.contains("ALLOW"));
        assert!(
            format!("{} {}", result.1, result.2).contains(diagnostic),
            "{} {}",
            result.1,
            result.2
        );
    }
    let source_failure = r#"{"type":"diagnostic","fields":{"severity":"error","code":"source-not-allowed"}}
{"type":"summary","fields":{"advisories":{"errors":0,"warnings":0,"helps":0,"notes":0},"bans":{"errors":0,"warnings":0,"helps":0,"notes":0},"sources":{"errors":1,"warnings":0,"helps":0,"notes":0}}}
"#;
    let source_result = invoke(
        &["audit"],
        &FakeCratesIoClient::default(),
        &FakeCommandRunner::default().with_cargo_deny_json(source_failure),
    );
    assert_eq!(source_result.0, ExitCode::from(1));
    assert!(
        format!("{} {}", source_result.1, source_result.2)
            .contains("FAIL cargo-deny sources check reported 1 error(s)"),
        "{} {}",
        source_result.1,
        source_result.2
    );

    let source = barbican::CRATES_IO_SOURCE;
    let derive_id = format!("{source}#serde_derive@1.0.228");
    let backlog_id = format!("{source}#backlog@1.0.0");
    let mut metadata: serde_json::Value =
        serde_json::from_str(&declared_crates_io_direct_metadata_json("serde", "1.0.228")).unwrap();
    metadata["packages"].as_array_mut().unwrap().extend([
        serde_json::json!({"name":"serde_derive","id":derive_id,"version":"1.0.228","source":source,"targets":[{"kind":["custom-build"]}]}),
        serde_json::json!({"name":"backlog","id":backlog_id,"version":"1.0.0","source":source,"targets":[]}),
    ]);
    metadata["resolve"]["nodes"]
        .as_array_mut()
        .unwrap()
        .extend([
            serde_json::json!({"id":derive_id,"deps":[{"name":"backlog","pkg":backlog_id}]}),
            serde_json::json!({"id":backlog_id,"deps":[]}),
        ]);
    metadata["resolve"]["nodes"][1]["deps"] =
        serde_json::json!([{"name":"serde_derive","pkg":derive_id}]);
    let mut lock = fs::read_to_string(root.join("Cargo.lock")).unwrap();
    lock.push_str("\n[[package]]\nname='fixture'\nversion='0.0.0'\ndependencies=['serde']\n");
    lock.push_str(&format!("\n[[package]]\nname='backlog'\nversion='1.0.0'\nsource='{source}'\nchecksum='{PIN_ADD_TEST_CHECKSUM}'\n"));
    fs::write(root.join("Cargo.lock"), &lock).unwrap();
    let inventory = invoke(
        &["inventory", "--enforce"],
        &FakeCratesIoClient::default(),
        &FakeCommandRunner::default().with_frozen_metadata(metadata.to_string()),
    );
    assert_eq!(
        inventory.0,
        ExitCode::SUCCESS,
        "{} {}",
        inventory.1,
        inventory.2
    );
    assert!(
        inventory
            .1
            .contains("observational uncovered transitive crates.io packages: 1")
    );
    assert!(inventory.1.contains("undeclared execution surfaces: 1"));
    let client = FakeCratesIoClient::default()
        .with_release("serde@1.0.228", "2020-05-01T00:00:00Z", false)
        .with_release("serde_derive@1.0.228", "2020-05-01T00:00:00Z", false)
        .with_release("backlog@1.0.0", "2020-05-01T00:00:00Z", false);
    let assess_runner = FakeCommandRunner::default()
        .with_git_show("HEAD:Cargo.lock", "version=4\n")
        .with_git_show("HEAD:Cargo.toml", "[dependencies]\nserde='=1.0.228'\n")
        .with_cargo_metadata(&metadata.to_string());
    let assessment = invoke(&["assess"], &client, &assess_runner);
    assert_eq!(
        assessment.0,
        ExitCode::from(1),
        "{} {}",
        assessment.1,
        assessment.2
    );
    assert!(
        assessment
            .1
            .contains("new/changed build.rs surface: serde_derive@1.0.228")
    );
}

#[cfg(unix)]
#[test]
fn browser_refuses_fifo_symlink_git_and_protected_alias_without_reading() {
    use std::os::unix::fs::symlink;
    let root = fixture("family");
    let record = root.join("docs/dependency-reviews/2020-06-01-serde.md");
    fs::remove_file(&record).unwrap();
    fs::hard_link(root.join("Cargo.toml"), &record).unwrap();
    assert!(
        run(&root, &["pin", "show", "family"])
            .1
            .contains("protected input")
    );
    fs::remove_file(&record).unwrap();
    symlink(root.join("Cargo.toml"), &record).unwrap();
    assert!(run(&root, &["pin", "show", "family"]).1.contains("unsafe"));
    fs::remove_file(&record).unwrap();
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&record)
            .status()
            .unwrap()
            .success()
    );
    assert!(run(&root, &["pin", "list"]).1.contains("unsafe"));
    fs::remove_file(root.join("Cargo.lock")).unwrap();
    assert!(
        std::process::Command::new("mkfifo")
            .arg(root.join("Cargo.lock"))
            .status()
            .unwrap()
            .success()
    );
    assert!(
        run(&root, &["pin", "list"])
            .1
            .contains("parity: unavailable")
    );
}
