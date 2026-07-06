use super::common::*;

#[test]
fn inventory_reports_policy_coverage_and_gaps() {
    let temp_dir = fresh_temp_dir();
    write_inventory_fixture(&temp_dir);
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        r#"
[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/serde.md"

[rust.families.direct]
serde = "=1.0.228"

[rust.families.resolved]
serde = { version = "1.0.228", checksum_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }

[rust.families.allowed_surfaces]
serde = ["proc-macro"]
"#,
    )
    .expect("reviewed targets should write");

    let runner = FakeCommandRunner::default().with_frozen_metadata(surface_metadata_json());
    let (exit_code, stdout, stderr) = run_inventory_with_runner(&temp_dir, &runner);

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert!(stdout.contains("Dependency inventory:"));
    assert!(stdout.contains("reviewed-targets.toml: configured"));
    assert!(stdout.contains("serde crates/app/Cargo.toml:dependencies =1.0.228 [exact inherited; source=workspace; effective-source=registry]"));
    assert!(stdout.contains("alt crates/app/Cargo.toml:dependencies 1 [not exact; source=alternate-registry; effective-source=alternate-registry]"));
    assert!(stdout.contains("local crates/app/Cargo.toml:dependencies (no version) [not applicable; source=path; effective-source=path]"));
    assert!(stdout.contains("live graph surface status: collected via cargo metadata --frozen"));
    assert!(stdout.contains("serde@1.0.228 proc-macro (declared)"));
    assert!(stdout.contains("loose@0.1.0 build-rs (undeclared)"));
    assert!(stdout.contains("local@0.1.0 native-sys (undeclared)"));
    assert!(!stdout.contains("app@0.1.0 build-rs"));
    assert!(stdout.contains("serde@1.0.228 proc-macro allowed by serde-family"));
    assert!(stdout.contains(
        "serde-family: 1 direct, 1 resolved, docs/dependency-reviews/serde.md (record missing)"
    ));
    let observational =
        section_between(&stdout, "Observational findings:", "Policy coverage gaps:");
    let policy = section_between(&stdout, "Policy coverage gaps:", "Suggested next actions:");
    assert!(observational.contains(
        "direct dependency loose at crates/app/Cargo.toml:dev-dependencies is not exact: 0.1"
    ));
    assert!(observational.contains("non-crates.io dependency source for local@0.1.0"));
    assert!(!observational.contains("non-crates.io dependency source for app@0.1.0: (none)"));
    assert!(observational.contains("non-crates.io dependency source for app@0.2.0"));
    assert!(observational.contains(
        "non-crates.io dependency source for git-crate@0.1.0: git+https://example.invalid/git-crate"
    ));
    assert!(observational.contains(
        "non-crates.io dependency source for app@0.1.0: git+https://example.invalid/app"
    ));
    assert!(!observational.contains("non-crates.io dependency source for explicit-app@0.1.0"));
    assert!(!observational.contains("missing review record for family serde-family"));
    assert!(!observational.contains("resolved crates.io package is not covered"));
    assert!(!observational.contains("live execution surface is not declared"));
    assert!(policy.contains(
        "missing review record for family serde-family: docs/dependency-reviews/serde.md"
    ));
    assert!(
        policy.contains(
            "resolved crates.io package is not covered by any reviewed family: loose@0.1.0"
        )
    );
    assert!(policy.contains(
        "live execution surface is not declared in reviewed policy: loose@0.1.0 build-rs"
    ));
    assert!(policy.contains(
        "live execution surface is not declared in reviewed policy: local@0.1.0 native-sys"
    ));
    assert!(!policy.contains(
        "live execution surface is not declared in reviewed policy: serde@1.0.228 proc-macro"
    ));
    assert!(
        !policy.contains(
            "live execution surface is not declared in reviewed policy: app@0.1.0 build-rs"
        )
    );
    assert!(!policy.contains("direct dependency loose"));
    assert!(!policy.contains("non-crates.io dependency source for local@0.1.0"));
    assert!(
        stdout.contains("Review each finding or gap, update reviewed-targets.toml and review records, then run `cargo barbican verify`.")
    );
}

#[test]
fn inventory_reports_advisory_exception_and_delegation_state() {
    let temp_dir = fresh_temp_dir();
    write_inventory_fixture(&temp_dir);
    fs::create_dir_all(temp_dir.join("docs/dependency-reviews"))
        .expect("review record dir should create");
    fs::write(
        temp_dir.join("docs/dependency-reviews/serde.md"),
        "reviewed serde advisory exception\n",
    )
    .expect("review record should write");
    fs::write(
        temp_dir.join("barbican.toml"),
        r#"
[delegates]
unmanaged_delegated_policy = "deny"

[delegates.advisories]
lockfile_scanner = "both"

[delegates.cargo_deny]
checks = ["advisories", "bans"]
"#,
    )
    .expect("config should write");
    fs::write(
        temp_dir.join("deny.toml"),
        r#"
[advisories]
ignore = [{ id = "RUSTSEC-2026-0001", reason = "native reviewed elsewhere" }]
"#,
    )
    .expect("deny config should write");
    fs::create_dir_all(temp_dir.join(".cargo")).expect("cargo config dir should create");
    fs::write(
        temp_dir.join(".cargo/audit.toml"),
        r#"
[advisories]
ignore = ["RUSTSEC-2026-0002"]
"#,
    )
    .expect("audit config should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        r#"
[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/serde.md"

[rust.families.direct]
serde = "=1.0.228"

[rust.families.resolved]
serde = { version = "1.0.228", checksum_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }

[rust.families.allowed_advisories]
serde = [{ id = "RUSTSEC-2099-0001", review_by = "2099-01-01" }]

[[rust.families]]
name = "loose-family"
review_record = "docs/dependency-reviews/loose.md"

[rust.families.resolved]
loose = { version = "0.1.0", checksum_sha256 = "1111111111111111111111111111111111111111111111111111111111111111" }

[rust.families.allowed_advisories]
loose = [{ id = "RUSTSEC-2099-0002", review_by = "2099-01-01" }]

[[rust.families]]
name = "stale-family"
review_record = "docs/dependency-reviews/stale.md"

[rust.families.resolved]
stale = { version = "1.0.0", checksum_sha256 = "2222222222222222222222222222222222222222222222222222222222222222" }

[rust.families.allowed_advisories]
stale = [{ id = "RUSTSEC-2000-0001", review_by = "2000-01-01" }]
"#,
    )
    .expect("reviewed targets should write");

    let runner = FakeCommandRunner::default();
    let (exit_code, stdout, stderr) = run_inventory_with_runner(&temp_dir, &runner);

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert!(stdout.contains(
        "deny.toml: configured; cargo-deny non-advisory posture would use checked-in deny.toml"
    ));
    assert!(stdout.contains("Reviewed advisory exceptions:"));
    assert!(stdout.contains("expiry window: soon-to-expire means review_by within 30 day(s)"));
    assert!(stdout.contains("stale means the exception's crate@version is not present"));
    assert!(stdout.contains("serde@1.0.228 RUSTSEC-2099-0001 family=serde-family review_record=docs/dependency-reviews/serde.md review_by=2099-01-01 status=active resolved-target=matched review-record=exists"));
    assert!(stdout.contains("loose@0.1.0 RUSTSEC-2099-0002 family=loose-family review_record=docs/dependency-reviews/loose.md review_by=2099-01-01 status=active resolved-target=matched review-record=missing"));
    assert!(stdout.contains("stale@1.0.0 RUSTSEC-2000-0001 family=stale-family review_record=docs/dependency-reviews/stale.md review_by=2000-01-01 status=stale resolved-target=not matched review-record=missing"));
    assert!(stdout.contains("Advisory delegation:"));
    assert!(stdout.contains("lockfile scanner: both"));
    assert!(stdout.contains("cargo-deny checks: advisories, bans"));
    assert!(stdout.contains("unmanaged delegated policy: deny"));
    assert!(stdout.contains("native delegated advisory ignores:"));
    assert!(stdout.contains("deny.toml ignores RUSTSEC-2026-0001"));
    assert!(stdout.contains(".cargo/audit.toml ignores RUSTSEC-2026-0002"));
}

#[test]
fn inventory_renders_expired_and_soon_to_expire_advisory_exception_statuses() {
    let temp_dir = fresh_temp_dir();
    write_inventory_fixture(&temp_dir);
    fs::create_dir_all(temp_dir.join("docs/dependency-reviews"))
        .expect("review record dir should create");
    fs::write(
        temp_dir.join("docs/dependency-reviews/serde.md"),
        "# serde\n",
    )
    .expect("serde review should write");
    fs::write(
        temp_dir.join("docs/dependency-reviews/loose.md"),
        "# loose\n",
    )
    .expect("loose review should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        r#"
[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/serde.md"

[rust.families.resolved]
serde = { version = "1.0.228", checksum_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }

[rust.families.allowed_advisories]
serde = [{ id = "RUSTSEC-2027-0001", review_by = "2027-09-13" }]

[[rust.families]]
name = "loose-family"
review_record = "docs/dependency-reviews/loose.md"

[rust.families.resolved]
loose = { version = "0.1.0", checksum_sha256 = "1111111111111111111111111111111111111111111111111111111111111111" }

[rust.families.allowed_advisories]
loose = [{ id = "RUSTSEC-2027-0002", review_by = "2027-10-01" }]
"#,
    )
    .expect("reviewed targets should write");

    let runner = FakeCommandRunner::default();
    let now = OffsetDateTime::from_unix_timestamp(1_820_908_800)
        .expect("fixed timestamp should be valid");
    let (exit_code, stdout, stderr) = run_inventory_with_runner_at(&temp_dir, &runner, now);

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert!(stdout.contains("serde@1.0.228 RUSTSEC-2027-0001 family=serde-family review_record=docs/dependency-reviews/serde.md review_by=2027-09-13 status=expired resolved-target=matched review-record=exists"));
    assert!(stdout.contains("loose@0.1.0 RUSTSEC-2027-0002 family=loose-family review_record=docs/dependency-reviews/loose.md review_by=2027-10-01 status=soon-to-expire resolved-target=matched review-record=exists"));
}

#[test]
fn inventory_without_reviewed_targets_reports_no_policy() {
    let temp_dir = fresh_temp_dir();
    write_inventory_fixture(&temp_dir);

    let runner = FakeCommandRunner::default().with_frozen_metadata(surface_metadata_json());
    let (exit_code, stdout, stderr) = run_inventory_with_runner(&temp_dir, &runner);

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert!(stdout.contains("reviewed-targets.toml: not configured"));
    assert!(stdout.contains(
        "deny.toml: not configured; cargo-deny non-advisory posture would use Barbican's generated default base"
    ));
    assert!(stdout.contains("Reviewed advisory exceptions:"));
    assert!(stdout.contains("exceptions: none"));
    assert!(stdout.contains("Advisory delegation:"));
    assert!(stdout.contains("lockfile scanner: cargo-deny"));
    assert!(stdout.contains("cargo-deny checks: advisories, bans, sources"));
    assert!(stdout.contains("unmanaged delegated policy: warn"));
    assert!(stdout.contains("native delegated advisory ignores: none"));
    assert!(stdout.contains("live graph surface status: collected via cargo metadata --frozen"));
    assert!(stdout.contains("no policy configured yet; resolved crates are not classified as slipped-through policy gaps"));
    let observational =
        section_between(&stdout, "Observational findings:", "Policy coverage gaps:");
    assert!(observational.contains(
        "direct dependency loose at crates/app/Cargo.toml:dev-dependencies is not exact: 0.1"
    ));
    assert!(observational.contains("non-crates.io dependency source for local@0.1.0"));
    assert!(!observational.contains("non-crates.io dependency source for app@0.1.0: (none)"));
    assert!(observational.contains("non-crates.io dependency source for app@0.2.0"));
    assert!(observational.contains(
        "non-crates.io dependency source for git-crate@0.1.0: git+https://example.invalid/git-crate"
    ));
    assert!(observational.contains(
        "non-crates.io dependency source for app@0.1.0: git+https://example.invalid/app"
    ));
    assert!(observational.contains(
        "live execution surface is not declared in reviewed policy: serde@1.0.228 proc-macro"
    ));
    assert!(observational.contains(
        "live execution surface is not declared in reviewed policy: loose@0.1.0 build-rs"
    ));
    assert!(observational.contains(
        "live execution surface is not declared in reviewed policy: local@0.1.0 native-sys"
    ));
    assert!(
        !observational.contains(
            "live execution surface is not declared in reviewed policy: app@0.1.0 build-rs"
        )
    );
    assert!(!observational.contains("non-crates.io dependency source for explicit-app@0.1.0"));
    assert!(stdout.contains("Policy coverage gaps:\n  none\n"));
}

#[test]
fn inventory_reports_configured_empty_policy_without_gaps() {
    let temp_dir = fresh_temp_dir();
    write_workspace_only_fixture(&temp_dir);
    fs::write(temp_dir.join("reviewed-targets.toml"), "[rust]\n").expect("policy should write");

    let (exit_code, stdout, stderr) = run_inventory(&temp_dir);

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert!(stdout.contains("reviewed-targets.toml: configured"));
    assert!(stdout.contains("reviewed-targets.toml has no active Rust families"));
    assert!(stdout.contains("declared allowed surfaces: none"));
    assert!(stdout.contains("live graph surface status: collected via cargo metadata --frozen"));
    assert!(stdout.contains("live graph surfaces: collected"));
    assert!(stdout.contains(
        "live graph surface findings: no undeclared build.rs / proc-macro / native-sys surfaces detected"
    ));
    assert!(stdout.contains("Observational findings:\n  none\n"));
    assert!(stdout.contains("Policy coverage gaps:\n  none\n"));
    assert!(
        stdout.contains(
            "Run `cargo barbican pin check` or `cargo barbican verify` to enforce policy."
        )
    );
}

#[test]
fn inventory_discovers_workspace_members_from_non_crates_globs() {
    let temp_dir = fresh_temp_dir();
    write_libs_glob_fixture(&temp_dir);

    let (exit_code, stdout, stderr) = run_inventory(&temp_dir);

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert!(stdout.contains("glob-member libs/glob-member/Cargo.toml:dependencies =0.1.0"));
    assert!(!stdout.contains("non-crates.io dependency source for glob-member@0.1.0: (none)"));
}

#[test]
fn inventory_prunes_git_and_target_dirs_during_workspace_discovery() {
    let temp_dir = fresh_temp_dir();
    write_pruned_dirs_fixture(&temp_dir);

    let (exit_code, stdout, stderr) = run_inventory(&temp_dir);

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert!(stdout.contains("real-member crates/real-member/Cargo.toml:dependencies =0.1.0"));
    assert!(!stdout.contains("target-phantom crates/real-member/target/phantom/Cargo.toml"));
    assert!(!stdout.contains("git-phantom crates/real-member/.git/phantom/Cargo.toml"));
    assert!(stdout.contains("non-crates.io dependency source for target-phantom@0.1.0: (none)"));
    assert!(stdout.contains("non-crates.io dependency source for git-phantom@0.1.0: (none)"));
}

#[test]
fn inventory_currently_discovers_nested_non_member_manifests_under_walked_roots() {
    let temp_dir = fresh_temp_dir();
    write_nested_non_member_fixture(&temp_dir);

    let (exit_code, stdout, stderr) = run_inventory(&temp_dir);

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert!(stdout.contains(
        "nested-fixture crates/member/examples/nested-fixture/Cargo.toml:dependencies 0.1 [not exact; source=registry; effective-source=registry]"
    ));
    assert!(stdout.contains(
        "direct dependency nested-fixture at crates/member/examples/nested-fixture/Cargo.toml:dependencies is not exact: 0.1"
    ));
}

#[test]
fn inventory_escapes_control_characters_in_rendered_fields() {
    let temp_dir = fresh_temp_dir();
    write_control_character_fixture(&temp_dir);

    let (exit_code, stdout, stderr) = run_inventory(&temp_dir);

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert!(!stdout.contains('\u{1b}'));
    assert!(
        stdout.contains(
            "control_dep crates/app/Cargo.toml:dependencies 0.1\\n  none [not exact; source=registry; effective-source=registry]"
        ),
        "{stdout}"
    );
    assert!(
        stdout.contains(
            "non-crates.io dependency source for control-source@0.1.0: git+https://example.invalid/control\\x1b[1A\\x1b[2K\\n  none\\x2028\\x2029"
        ),
        "{stdout}"
    );
    assert!(
        stdout.contains("policy-family: 1 direct, 1 resolved"),
        "{stdout}"
    );
}

#[test]
fn inventory_renders_offline_report_when_frozen_metadata_fails() {
    let temp_dir = fresh_temp_dir();
    write_inventory_fixture(&temp_dir);
    let cli = Cli::parse_from(["cargo-barbican", "inventory"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default().with_frozen_metadata_error(
        "the lock file needs to be updated but --frozen was passed\u{9b}[2K",
    );
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");
    let stdout = String::from_utf8(stdout).expect("stdout should be utf8");
    let stderr = String::from_utf8(stderr).expect("stderr should be utf8");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert_eq!(runner.frozen_metadata_calls(), 1);
    assert!(stderr.is_empty());
    assert!(stdout.contains("Dependency inventory:"));
    assert!(
        stdout.contains(
            "live graph surfaces: NOT COLLECTED - investigate before trusting this report"
        )
    );
    assert!(stdout.contains(
        "live graph surface status: not collected; live graph surface collection failed: command exited with status 1; stderr: the lock file needs to be updated but --frozen was passed\\x9b[2K"
    ));
    assert!(stdout.contains(
        "live graph surface remediation: resolve the reported graph or metadata issue, then rerun inventory"
    ));
    assert!(stdout.contains("Direct dependencies:"));
    assert!(stdout.contains("Policy coverage gaps:"));
    assert!(
        stdout.contains(
            "Resolve live graph surface collection before trusting this inventory report."
        )
    );
}

#[test]
fn inventory_not_collected_state_prevents_clean_next_action() {
    let temp_dir = fresh_temp_dir();
    write_workspace_only_fixture(&temp_dir);
    fs::write(temp_dir.join("reviewed-targets.toml"), "[rust]\n").expect("policy should write");

    let runner =
        FakeCommandRunner::default().with_frozen_metadata_error("invalid metadata package: évil");
    let (exit_code, stdout, stderr) = run_inventory_with_runner(&temp_dir, &runner);

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert!(stdout.contains("reviewed-targets.toml: configured"));
    assert!(stdout.contains("Observational findings:\n  none\n"));
    assert!(stdout.contains("Policy coverage gaps:\n  none\n"));
    assert!(
        stdout.contains(
            "live graph surfaces: NOT COLLECTED - investigate before trusting this report"
        )
    );
    assert!(stdout.contains(
        "live graph surface status: not collected; live graph surface collection failed: command exited with status 1; stderr: invalid metadata package: évil"
    ));
    assert!(
        stdout.contains(
            "Resolve live graph surface collection before trusting this inventory report."
        )
    );
    assert!(
        !stdout.contains(
            "Run `cargo barbican pin check` or `cargo barbican verify` to enforce policy."
        )
    );
}

#[test]
fn inventory_fails_on_malformed_reviewed_targets() {
    let temp_dir = fresh_temp_dir();
    write_inventory_fixture(&temp_dir);
    fs::write(temp_dir.join("reviewed-targets.toml"), "not toml").expect("policy should write");

    let cli = Cli::parse_from(["cargo-barbican", "inventory"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    let rendered = String::from_utf8(stderr).expect("stderr should be utf8");
    assert!(rendered.starts_with("FAIL "));
    assert!(rendered.contains("reviewed-targets.toml"));
}

#[test]
fn inventory_escapes_malformed_reviewed_targets_parse_diagnostics() {
    let temp_dir = fresh_temp_dir();
    write_inventory_fixture(&temp_dir);
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        "[rust]\n\u{001b} = \"pwned\"\n",
    )
    .expect("policy should write");

    let cli = Cli::parse_from(["cargo-barbican", "inventory"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    let rendered = String::from_utf8(stderr).expect("stderr should be utf8");
    assert!(rendered.starts_with("FAIL "));
    assert!(rendered.contains("reviewed-targets.toml"));
    assert!(!rendered.contains('\u{001b}'));
    assert!(rendered.contains("\\x1b"));
    assert!(rendered.contains('\n'));
}

#[test]
fn inventory_fails_when_lockfile_is_missing() {
    let temp_dir = fresh_temp_dir();
    fs::write(
        temp_dir.join("Cargo.toml"),
        "[workspace]\nmembers = []\nresolver = \"3\"\n",
    )
    .expect("manifest should write");

    let cli = Cli::parse_from(["cargo-barbican", "inventory"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    assert_eq!(
        String::from_utf8(stderr).expect("stderr should be utf8"),
        "FAIL Cargo.lock: lockfile not found\n"
    );
}
