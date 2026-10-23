use super::common::*;

#[test]
fn refresh_reuses_active_workspace_aliases_and_ignores_unused_templates() {
    let root = fresh_temp_dir();
    write_fixture(&root, "review.md", false);
    fs::create_dir_all(root.join("member")).unwrap();
    fs::write(root.join("Cargo.toml"),"[workspace]\nmembers=['member']\n[workspace.dependencies]\nrenamed={package='demo',version='=1.1.0'}\nunused={package='demo',version='^0.9'}\n").unwrap();
    fs::write(
        root.join("member/Cargo.toml"),
        "[package]\nname='member'\nversion='0.1.0'\n[dependencies]\nrenamed={workspace=true}\n",
    )
    .unwrap();
    let (exit, out, err) = invoke(
        &root,
        &["pin", "refresh", "demo"],
        &FakeCratesIoClient::default(),
        &runner(),
    );
    assert_eq!(exit, ExitCode::SUCCESS, "{out}\n{err}");
    let parsed = barbican::parse_reviewed_targets_toml(
        &fs::read_to_string(root.join("reviewed-targets.toml")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        parsed.rust_families()[0].direct()["demo"].to_string(),
        "=1.1.0"
    );
}

#[test]
fn ref_pins_one_commit_and_post_move_head_cannot_explain_drift() {
    let root = fresh_temp_dir();
    write_fixture(&root, "review.md", false);
    let commit = "a".repeat(40);
    let before = lockfile_with_package_records(&[("demo", "1.0.0", Some(REGISTRY), Some(OLD))]);
    let client =
        FakeCratesIoClient::default().with_release("demo@1.1.0", "2019-01-01T00:00:00Z", false);
    let runner = runner()
        .with_git_show("pre-move^{commit}", &format!("{commit}\n"))
        .with_git_show(&format!("{commit}:Cargo.lock"), &before)
        .with_git_show(
            &format!("{commit}:Cargo.toml"),
            &fs::read_to_string(root.join("Cargo.toml")).unwrap(),
        );
    let (exit, out, err) = invoke(
        &root,
        &["gatehouse", "re-pin", "--base-ref", "pre-move"],
        &client,
        &runner,
    );
    assert_eq!(exit, ExitCode::SUCCESS, "{out}\n{err}");
    assert_eq!(*runner.git_resolve_calls.borrow(), ["pre-move"]);
    assert_eq!(*runner.git_prefix_calls.borrow(), 1);
}

#[test]
fn nonconforming_direct_pin_is_retained_and_unsupported_layout_prints_fragment_without_writes() {
    for unsupported in [false, true] {
        let root = fresh_temp_dir();
        write_fixture(&root, "review.md", false);
        if unsupported {
            let mut file = fs::OpenOptions::new()
                .append(true)
                .open(root.join("reviewed-targets.toml"))
                .unwrap();
            file.write_all(b"\n[[rust.families.allowed_advisories.demo]]\nid='RUSTSEC-2020-0001'\nreview_by='2099-01-01'\n").unwrap();
        } else {
            let manifest = fs::read_to_string(root.join("Cargo.toml"))
                .unwrap()
                .replace("=1.1.0", "^1");
            fs::write(root.join("Cargo.toml"), manifest).unwrap();
        }
        let before = fs::read(root.join("reviewed-targets.toml")).unwrap();
        let record = fs::read(root.join("review.md")).unwrap();
        let (exit, out, err) = invoke(
            &root,
            &["pin", "refresh", "demo"],
            &FakeCratesIoClient::default(),
            &runner(),
        );
        if unsupported {
            assert_eq!(exit, ExitCode::from(1), "{out}\n{err}");
            assert!(out.contains("[rust.families.resolved]") && out.contains(NEW));
            assert_eq!(
                fs::read(root.join("reviewed-targets.toml")).unwrap(),
                before
            );
            assert_eq!(fs::read(root.join("review.md")).unwrap(), record);
        } else {
            assert_eq!(exit, ExitCode::SUCCESS, "{out}\n{err}");
            assert!(out.contains("remaining mismatch") && out.contains("direct pin retained"));
            let parsed = barbican::parse_reviewed_targets_toml(
                &fs::read_to_string(root.join("reviewed-targets.toml")).unwrap(),
            )
            .unwrap();
            assert_eq!(
                parsed.rust_families()[0].direct()["demo"].to_string(),
                "=1.0.0"
            );
        }
    }
}

#[test]
fn clean_repin_still_runs_evidence_but_never_reopens_records() {
    let root = fresh_temp_dir();
    write_fixture(&root, "review.md", false);
    let base = baseline(&root);
    let policy = fs::read_to_string(root.join("reviewed-targets.toml"))
        .unwrap()
        .replace("1.0.0", "1.1.0")
        .replace(OLD, NEW);
    fs::write(root.join("reviewed-targets.toml"), &policy).unwrap();
    let record = fs::read(root.join("review.md")).unwrap();
    let client =
        FakeCratesIoClient::default().with_release("demo@1.1.0", "2019-01-01T00:00:00Z", false);
    let (exit, out, err) = invoke(
        &root,
        &["gatehouse", "re-pin", "--base-dir", base.to_str().unwrap()],
        &client,
        &runner(),
    );
    assert_eq!(exit, ExitCode::SUCCESS, "{out}\n{err}");
    assert!(out.contains("no refresh needed") && out.contains("Gatehouse re-pin: assess"));
    assert_eq!(fs::read(root.join("review.md")).unwrap(), record);
    assert_eq!(
        fs::read_to_string(root.join("reviewed-targets.toml")).unwrap(),
        policy
    );
    assert_eq!(client.recorded_fetches(), vec!["demo@1.1.0"]);
}

#[test]
fn refresh_never_echoes_credential_bearing_source_arguments() {
    let root = fresh_temp_dir();
    write_fixture(&root, "review.md", false);
    let (exit, out, err) = invoke(
        &root,
        &["pin", "refresh", "https://user:secret@example.invalid/repo"],
        &FakeCratesIoClient::default(),
        &runner(),
    );
    assert_eq!(exit, ExitCode::from(1));
    assert!(!out.contains("secret") && !err.contains("secret"));
}

const OLD: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const NEW: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const REGISTRY: &str = "registry+https://github.com/rust-lang/crates.io-index";

fn write_fixture(root: &Path, record: &str, grants: bool) {
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(root.join("src/lib.rs"), "").unwrap();
    fs::write(root.join("Cargo.toml"), "[package]\nname='fixture'\nversion='0.1.0'\nedition='2024'\n[dependencies]\nalias={package='demo',version='=1.1.0'}\n").unwrap();
    fs::write(
        root.join("Cargo.lock"),
        lockfile_with_package_records(&[("demo", "1.1.0", Some(REGISTRY), Some(NEW))]),
    )
    .unwrap();
    let grant = if grants {
        "[rust.families.allowed_surfaces]\ndemo=['build-rs']\n[rust.families.allowed_age_exceptions]\ndemo='1.0.0'\n[rust.families.allowed_advisories]\ndemo=[{id='RUSTSEC-2020-0001',review_by='2099-01-01'}]\n"
    } else {
        ""
    };
    fs::write(root.join("reviewed-targets.toml"), format!("# preserve my process comments\n[[rust.families]]\nname='demo-family'\nreview_record='{record}'\n[rust.families.direct]\ndemo='=1.0.0'\n[rust.families.resolved]\ndemo={{version='1.0.0',checksum_sha256='{OLD}'}}\n{grant}")).unwrap();
    if record == "review.md" {
        fs::write(
            root.join(record),
            "# Reviewed dependency\n\nOriginal completed review, preserved verbatim.\n",
        )
        .unwrap();
    }
}

fn invoke(
    root: &Path,
    args: &[&str],
    client: &FakeCratesIoClient,
    runner: &FakeCommandRunner,
) -> (ExitCode, String, String) {
    let mut args_all = vec!["cargo-barbican"];
    args_all.extend_from_slice(args);
    let cli = Cli::parse_from(args_all);
    let mut out = Vec::new();
    let mut err = Vec::new();
    let exit = run_cli_with_runner(cli, root, client, runner, &mut out, &mut err).unwrap();
    (
        exit,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

fn baseline(root: &Path) -> PathBuf {
    let dir = root.join("before");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("Cargo.toml"),
        fs::read(root.join("Cargo.toml")).unwrap(),
    )
    .unwrap();
    fs::write(
        dir.join("Cargo.lock"),
        lockfile_with_package_records(&[("demo", "1.0.0", Some(REGISTRY), Some(OLD))]),
    )
    .unwrap();
    dir
}

fn runner() -> FakeCommandRunner {
    FakeCommandRunner {
        cargo_metadata_result: Ok(metadata_with_packages(&[(
            "demo",
            "1.1.0",
            "registry+https://github.com/rust-lang/crates.io-index#demo@1.1.0",
        )])),
        ..FakeCommandRunner::default()
    }
}

#[test]
fn refresh_withdraws_all_grants_reopens_record_and_never_executes() {
    let root = fresh_temp_dir();
    write_fixture(&root, "review.md", true);
    let client = FakeCratesIoClient::default();
    let runner = runner();
    let (exit, out, err) = invoke(&root, &["pin", "refresh", "demo"], &client, &runner);
    assert_eq!(exit, ExitCode::SUCCESS, "{out}\n{err}");
    assert!(err.is_empty());
    assert!(out.contains("withdrawn: allowed_advisories"));
    let policy = fs::read_to_string(root.join("reviewed-targets.toml")).unwrap();
    assert!(policy.starts_with("# preserve my process comments"));
    let parsed = barbican::parse_reviewed_targets_toml(&policy).unwrap();
    assert!(parsed.execution_surface_allowances().is_empty());
    assert!(parsed.advisory_exceptions().is_empty());
    assert!(parsed.release_age_exceptions().is_empty());
    assert_eq!(
        parsed.rust_families()[0].direct()["demo"].to_string(),
        "=1.1.0"
    );
    let record = fs::read_to_string(root.join("review.md")).unwrap();
    assert!(record.contains("Original completed review, preserved verbatim."));
    assert_eq!(record.matches(REVIEW_RECORD_SCAFFOLD_MARKER).count(), 1);
    assert!(record.contains(OLD) && record.contains(NEW));
    assert!(record.contains("RUSTSEC-2020-0001"));
    assert!(client.recorded_fetches().is_empty());
    assert_eq!(*runner.build_calls.borrow(), 0);
    assert_eq!(*runner.test_calls.borrow(), 0);
    let (exit, _, _) = invoke(&root, &["pin", "check"], &client, &runner);
    assert_eq!(exit, ExitCode::from(1));
    let complete = record
        .lines()
        .filter(|line| !line.contains(REVIEW_RECORD_SCAFFOLD_MARKER))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(root.join("review.md"), complete).unwrap();
    let (exit, out, err) = invoke(&root, &["pin", "check"], &client, &runner);
    assert_eq!(exit, ExitCode::SUCCESS, "{out}\n{err}");
    assert!(!out.contains("accepted by"));
}

#[test]
fn protected_input_aliases_empty_missing_readonly_and_symlink_records_refuse_before_writes() {
    for record in [
        "reviewed-targets.toml",
        "./reviewed-targets.toml",
        "Cargo.lock",
        "Cargo.toml",
        "missing.md",
        "empty.md",
        "readonly.md",
    ] {
        let root = fresh_temp_dir();
        write_fixture(&root, record, false);
        if record == "empty.md" {
            fs::write(root.join(record), " \n").unwrap();
        }
        if record == "readonly.md" {
            fs::write(root.join(record), "# review").unwrap();
            let mut permissions = fs::metadata(root.join(record)).unwrap().permissions();
            permissions.set_readonly(true);
            fs::set_permissions(root.join(record), permissions).unwrap();
        }
        let before = fs::read(root.join("reviewed-targets.toml")).unwrap();
        let lock = fs::read(root.join("Cargo.lock")).unwrap();
        let (exit, _, err) = invoke(
            &root,
            &["pin", "refresh", "demo"],
            &FakeCratesIoClient::default(),
            &runner(),
        );
        assert_eq!(exit, ExitCode::from(1), "{record}: {err}");
        assert_eq!(
            fs::read(root.join("reviewed-targets.toml")).unwrap(),
            before
        );
        assert_eq!(fs::read(root.join("Cargo.lock")).unwrap(), lock);
    }
}

#[cfg(unix)]
#[test]
fn refresh_refuses_intermediate_symlinks_and_hardlink_input_aliases() {
    use std::os::unix::fs::symlink;
    for ancestor in [false, true] {
        let root = fresh_temp_dir();
        let outside = fresh_temp_dir();
        write_fixture(
            &root,
            if ancestor {
                "linked/review.md"
            } else {
                "review.md"
            },
            false,
        );
        fs::write(outside.join("review.md"), "# Outside review").unwrap();
        if ancestor {
            symlink(&outside, root.join("linked")).unwrap();
        } else {
            fs::remove_file(root.join("review.md")).unwrap();
            fs::hard_link(root.join("Cargo.lock"), root.join("review.md")).unwrap();
        }
        let before = fs::read(root.join("reviewed-targets.toml")).unwrap();
        let (exit, _, err) = invoke(
            &root,
            &["pin", "refresh", "demo"],
            &FakeCratesIoClient::default(),
            &runner(),
        );
        assert_eq!(exit, ExitCode::from(1), "{err}");
        assert_eq!(
            fs::read(root.join("reviewed-targets.toml")).unwrap(),
            before
        );
        assert_eq!(
            fs::read_to_string(outside.join("review.md")).unwrap(),
            "# Outside review"
        );
    }
}

#[test]
fn batch_groups_two_targets_and_reports_untouched_family_sharing_record() {
    let root = fresh_temp_dir();
    write_fixture(&root, "review.md", false);
    let extra = format!(
        "\n[[rust.families]]\nname='aux-family'\nreview_record='./review.md'\n[rust.families.resolved]\naux={{version='1.0.0',checksum_sha256='{OLD}'}}\n[[rust.families]]\nname='untouched-family'\nreview_record='review.md'\n[rust.families.resolved]\nunchanged='1.0.0'\n"
    );
    fs::OpenOptions::new()
        .append(true)
        .open(root.join("reviewed-targets.toml"))
        .unwrap()
        .write_all(extra.as_bytes())
        .unwrap();
    fs::write(
        root.join("Cargo.lock"),
        lockfile_with_package_records(&[
            ("demo", "1.1.0", Some(REGISTRY), Some(NEW)),
            ("aux", "1.1.0", Some(REGISTRY), Some(NEW)),
            ("unchanged", "1.0.0", Some(REGISTRY), None),
        ]),
    )
    .unwrap();
    let (exit, out, err) = invoke(
        &root,
        &["pin", "refresh", "demo", "aux"],
        &FakeCratesIoClient::default(),
        &runner(),
    );
    assert_eq!(exit, ExitCode::SUCCESS, "{out}\n{err}");
    let record = fs::read_to_string(root.join("review.md")).unwrap();
    assert_eq!(record.matches("## Re-pin review").count(), 1);
    assert_eq!(record.matches(REVIEW_RECORD_SCAFFOLD_MARKER).count(), 1);
    assert!(record.contains("demo@1.1.0") && record.contains("aux@1.1.0"));
    assert!(out.contains("untouched-family"));
    let parsed = barbican::parse_reviewed_targets_toml(
        &fs::read_to_string(root.join("reviewed-targets.toml")).unwrap(),
    )
    .unwrap();
    for family in &parsed.rust_families()[..2] {
        assert_eq!(
            family.resolved().values().next().unwrap().version(),
            "1.1.0"
        );
    }
}

fn write_two_target_family(root: &Path) {
    write_fixture(root, "review.md", true);
    let path = root.join("reviewed-targets.toml");
    let source = fs::read_to_string(&path).unwrap()
        .replace("[rust.families.resolved]\n", &format!("[rust.families.resolved]\naux={{version='1.0.0',checksum_sha256='{OLD}'}}\n"))
        .replace("[rust.families.allowed_surfaces]\n", "[rust.families.allowed_surfaces]\naux=['build-rs']\n")
        .replace("[rust.families.allowed_age_exceptions]\n", "[rust.families.allowed_age_exceptions]\naux='1.0.0'\n")
        .replace("[rust.families.allowed_advisories]\n", "[rust.families.allowed_advisories]\naux=[{id='RUSTSEC-2020-0002',review_by='2099-01-01'}]\n");
    fs::write(path, source).unwrap();
    fs::write(
        root.join("Cargo.lock"),
        lockfile_with_package_records(&[
            ("demo", "1.1.0", Some(REGISTRY), Some(NEW)),
            ("aux", "1.1.0", Some(REGISTRY), Some(NEW)),
        ]),
    )
    .unwrap();
}

#[test]
fn refresh_edits_two_selected_members_of_one_family_and_withdraws_both_grant_sets() {
    let root = fresh_temp_dir();
    write_two_target_family(&root);
    let (exit, out, err) = invoke(
        &root,
        &["pin", "refresh", "demo", "aux"],
        &FakeCratesIoClient::default(),
        &runner(),
    );
    assert_eq!(exit, ExitCode::SUCCESS, "{out}\n{err}");
    let policy = barbican::parse_reviewed_targets_toml(
        &fs::read_to_string(root.join("reviewed-targets.toml")).unwrap(),
    )
    .unwrap();
    assert_eq!(policy.rust_families().len(), 1);
    for target in ["demo", "aux"] {
        assert_eq!(
            policy.rust_families()[0].resolved()[target].version(),
            "1.1.0"
        );
    }
    assert!(policy.execution_surface_allowances().is_empty());
    assert!(policy.release_age_exceptions().is_empty());
    assert!(policy.advisory_exceptions().is_empty());
    let record = fs::read_to_string(root.join("review.md")).unwrap();
    assert_eq!(record.matches("## Re-pin review").count(), 1);
    assert_eq!(record.matches(REVIEW_RECORD_SCAFFOLD_MARKER).count(), 1);
    assert!(record.contains("demo@1.1.0") && record.contains("aux@1.1.0"));
    assert!(record.contains("RUSTSEC-2020-0001") && record.contains("RUSTSEC-2020-0002"));
}

#[test]
fn partially_explained_repin_batch_refuses_before_evidence_and_all_writes() {
    let root = fresh_temp_dir();
    write_two_target_family(&root);
    let base = baseline(&root);
    fs::write(
        base.join("Cargo.lock"),
        lockfile_with_package_records(&[
            ("aux", "1.0.0", Some(REGISTRY), Some(OLD)),
            ("demo", "1.1.0", Some(REGISTRY), Some(NEW)),
        ]),
    )
    .unwrap();
    let policy = fs::read(root.join("reviewed-targets.toml")).unwrap();
    let record = fs::read(root.join("review.md")).unwrap();
    let client = FakeCratesIoClient::default();
    let (exit, _, err) = invoke(
        &root,
        &["gatehouse", "re-pin", "--base-dir", base.to_str().unwrap()],
        &client,
        &runner(),
    );
    assert_eq!(exit, ExitCode::from(1));
    assert!(err.contains("baseline does not explain demo"), "{err}");
    assert_eq!(
        fs::read(root.join("reviewed-targets.toml")).unwrap(),
        policy
    );
    assert_eq!(fs::read(root.join("review.md")).unwrap(), record);
    assert!(client.recorded_fetches().is_empty());
}

#[test]
fn duplicate_or_invalid_second_target_leaves_the_entire_batch_unchanged() {
    for extra in ["demo@1.1.0", "absent"] {
        let root = fresh_temp_dir();
        write_fixture(&root, "review.md", false);
        let policy = fs::read(root.join("reviewed-targets.toml")).unwrap();
        let record = fs::read(root.join("review.md")).unwrap();
        let (exit, _, _) = invoke(
            &root,
            &["pin", "refresh", "demo", extra],
            &FakeCratesIoClient::default(),
            &runner(),
        );
        assert_eq!(exit, ExitCode::from(1));
        assert_eq!(
            fs::read(root.join("reviewed-targets.toml")).unwrap(),
            policy
        );
        assert_eq!(fs::read(root.join("review.md")).unwrap(), record);
    }
}

#[test]
fn repin_composes_canonical_evidence_with_one_release_fetch_and_keeps_pending() {
    let root = fresh_temp_dir();
    write_fixture(&root, "review.md", false);
    let base = baseline(&root);
    let client =
        FakeCratesIoClient::default().with_release("demo@1.1.0", "2019-01-01T00:00:00Z", false);
    let runner = runner();
    let (exit, out, err) = invoke(
        &root,
        &["gatehouse", "re-pin", "--base-dir", base.to_str().unwrap()],
        &client,
        &runner,
    );
    assert_eq!(exit, ExitCode::SUCCESS, "{out}\n{err}");
    assert!(out.contains("Gatehouse re-pin: age-lock") && out.contains("Gatehouse re-pin: assess"));
    assert!(out.contains("human review remains PENDING"));
    assert_eq!(client.recorded_fetches(), vec!["demo@1.1.0"]);
    assert_eq!(*runner.build_calls.borrow(), 0);
    assert_eq!(*runner.test_calls.borrow(), 0);
}

#[test]
fn repin_refuses_unexplained_and_too_fresh_moves_without_record_writes() {
    for mode in ["post-move", "absent-old", "too-fresh", "elevated"] {
        let root = fresh_temp_dir();
        write_fixture(&root, "review.md", false);
        let base = baseline(&root);
        if mode == "post-move" {
            fs::copy(root.join("Cargo.lock"), base.join("Cargo.lock")).unwrap();
        }
        if mode == "absent-old" {
            fs::write(base.join("Cargo.lock"), "version=4\n").unwrap();
        }
        let client = FakeCratesIoClient::default().with_release(
            "demo@1.1.0",
            if mode == "too-fresh" {
                "2020-06-01T00:00:00Z"
            } else {
                "2019-01-01T00:00:00Z"
            },
            false,
        );
        let mut runner = runner();
        if mode == "elevated" {
            runner.cargo_metadata_result=Ok(r#"{"packages":[{"name":"demo","id":"registry+https://github.com/rust-lang/crates.io-index#demo@1.1.0","version":"1.1.0","source":"registry+https://github.com/rust-lang/crates.io-index","targets":[{"kind":["custom-build"]}]}],"workspace_members":[],"resolve":null}"#.to_owned());
        }
        let policy = fs::read(root.join("reviewed-targets.toml")).unwrap();
        let record = fs::read(root.join("review.md")).unwrap();
        let (exit, out, err) = invoke(
            &root,
            &["gatehouse", "re-pin", "--base-dir", base.to_str().unwrap()],
            &client,
            &runner,
        );
        assert_eq!(exit, ExitCode::from(1), "{mode}: {out}\n{err}");
        assert_eq!(
            fs::read(root.join("reviewed-targets.toml")).unwrap(),
            policy
        );
        assert_eq!(fs::read(root.join("review.md")).unwrap(), record);
    }
}

#[test]
fn repin_requires_exactly_one_baseline_and_refresh_requires_targets() {
    for args in [
        vec!["cargo-barbican", "gatehouse", "re-pin"],
        vec![
            "cargo-barbican",
            "gatehouse",
            "re-pin",
            "--base-ref",
            "HEAD",
            "--base-dir",
            "before",
        ],
        vec!["cargo-barbican", "pin", "refresh"],
    ] {
        assert!(Cli::try_parse_from(args).is_err());
    }
}

#[cfg(unix)]
#[test]
fn refresh_preserves_private_record_and_policy_permissions() {
    let root = fresh_temp_dir();
    write_fixture(&root, "review.md", false);
    for name in ["review.md", "reviewed-targets.toml"] {
        fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o600)).unwrap();
    }
    let (exit, out, err) = invoke(
        &root,
        &["pin", "refresh", "demo"],
        &FakeCratesIoClient::default(),
        &runner(),
    );
    assert_eq!(exit, ExitCode::SUCCESS, "{out}\n{err}");
    for name in ["review.md", "reviewed-targets.toml"] {
        assert_eq!(
            fs::metadata(root.join(name)).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
