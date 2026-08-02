use super::common::*;
use barbican::CRATES_IO_SOURCE;

const SERDE_ID: &str = "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228";
const SERDE_CORE_ID: &str =
    "registry+https://github.com/rust-lang/crates.io-index#serde_core@1.0.228";

fn serde_metadata_dependency() -> InventoryMetadataDependency {
    InventoryMetadataDependency {
        dependency_name: "serde".to_owned(),
        package_name: "serde".to_owned(),
        package_id: SERDE_ID.to_owned(),
        requirement: "=1.0.228".to_owned(),
        kind: None,
        optional: false,
        source: Some(CRATES_IO_SOURCE.to_owned()),
        path: None,
        declared: true,
        resolved: true,
    }
}

fn enforce_metadata_with_extra(
    package: (&str, &str, &str, Option<&str>),
    dependency: InventoryMetadataDependency,
) -> String {
    inventory_direct_metadata_json(
        &[
            ("serde", SERDE_ID, "1.0.228", Some(CRATES_IO_SOURCE)),
            (
                "serde_core",
                SERDE_CORE_ID,
                "1.0.228",
                Some(CRATES_IO_SOURCE),
            ),
            package,
        ],
        &[serde_metadata_dependency(), dependency],
    )
}

fn covered_enforce_metadata(
    extra_packages: &[(&str, &str, &str, Option<&str>)],
    extra_direct_dependencies: &[(&str, &str)],
) -> String {
    let mut packages = vec![
        ("serde", SERDE_ID, "1.0.228", Some(CRATES_IO_SOURCE)),
        (
            "serde_core",
            SERDE_CORE_ID,
            "1.0.228",
            Some(CRATES_IO_SOURCE),
        ),
    ];
    packages.extend_from_slice(extra_packages);
    let mut direct_dependencies = vec![serde_metadata_dependency()];
    direct_dependencies.extend(
        extra_direct_dependencies
            .iter()
            .map(|(dependency_name, id)| {
                let (package_name, _, version, source) = packages
                    .iter()
                    .find(|(_, package_id, _, _)| package_id == id)
                    .expect("direct package should be present");
                InventoryMetadataDependency {
                    dependency_name: (*dependency_name).to_owned(),
                    package_name: (*package_name).to_owned(),
                    package_id: (*id).to_owned(),
                    requirement: format!("={version}"),
                    kind: None,
                    optional: false,
                    source: source.map(str::to_owned),
                    path: source.is_none().then(|| "/outside/workspace".to_owned()),
                    declared: true,
                    resolved: true,
                }
            }),
    );
    inventory_direct_metadata_json(&packages, &direct_dependencies)
}

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
        "serde-family: 1 direct, 1 resolved, docs/dependency-reviews/serde.md (record not completed)"
    ));
    let observational = section_between(
        &stdout,
        "Observational findings:",
        "Reviewed-policy findings:",
    );
    let policy = section_between(
        &stdout,
        "Reviewed-policy findings:",
        "Suggested next actions:",
    );
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
    assert!(!observational.contains("review record not completed for family serde-family"));
    assert!(!observational.contains("resolved crates.io package is not covered"));
    assert!(!observational.contains("live execution surface is not declared"));
    assert!(policy.contains(
        "review record not completed for family serde-family: docs/dependency-reviews/serde.md"
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
        stdout.contains("Review the labelled backlog, update reviewed-targets.toml and review records, then run `cargo barbican gatehouse pre-release`.")
    );
    assert!(stdout.contains("enforced incomplete review records (pin check/verify): 1"));
    assert!(stdout.contains("observational undeclared execution surfaces: 2"));
    assert!(stdout.contains("other observational manifest/source findings:"));
}

#[test]
fn plain_inventory_reports_pass_ready_for_a_covered_floor() {
    let temp_dir = fresh_temp_dir();
    write_covered_enforce_fixture(&temp_dir);

    let runner =
        FakeCommandRunner::default().with_frozen_metadata(covered_enforce_metadata(&[], &[]));
    let (exit_code, stdout, stderr) = run_inventory_with_runner(&temp_dir, &runner);

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert!(stdout.contains("direct-dependency coverage floor: PASS-ready (informational run)"));
    assert!(!stdout.contains("Coverage floor enforcement:"));
    assert!(!stdout.contains("Inventory: PASS"));
}

#[test]
fn inventory_enforce_passes_on_fully_covered_direct_dependencies() {
    let temp_dir = fresh_temp_dir();
    write_covered_enforce_fixture(&temp_dir);

    let runner =
        FakeCommandRunner::default().with_frozen_metadata(covered_enforce_metadata(&[], &[]));
    let (exit_code, stdout, stderr) = run_inventory_enforce_with_runner(&temp_dir, &runner);

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert!(stdout.contains("Coverage floor enforcement:"));
    assert!(stdout.contains("every direct dependency is covered by an active reviewed family"));
    assert!(stdout.contains("direct-dependency coverage floor: PASS (enforced in this run)"));
    assert!(stdout.contains("enforced uncovered direct crates.io dependencies: 0"));
    assert!(stdout.contains("enforced external direct dependencies: 0"));
    assert!(
        stdout.contains("observational uncovered transitive crates.io packages: 1"),
        "{stdout}"
    );
    assert!(stdout.contains("enforced incomplete review records (pin check/verify): 0"));
    assert!(stdout.contains("other observational manifest/source findings: 0"));
    assert!(stdout.contains("Inventory: PASS (direct-dependency coverage floor)"));
    assert!(!stdout.contains("Inventory: FAIL"));
    assert!(stdout.contains(
        "resolved crates.io package is not covered by any reviewed family: serde_core@1.0.228"
    ));
}

#[test]
fn inventory_enforce_fails_and_names_uncovered_direct_dependency() {
    let temp_dir = fresh_temp_dir();
    write_uncovered_direct_enforce_fixture(&temp_dir);

    let sneaky_id = "registry+https://github.com/rust-lang/crates.io-index#sneaky@3.0.0";
    let runner = FakeCommandRunner::default().with_frozen_metadata(covered_enforce_metadata(
        &[("sneaky", sneaky_id, "3.0.0", Some(CRATES_IO_SOURCE))],
        &[("sneaky", sneaky_id)],
    ));
    let (exit_code, stdout, stderr) = run_inventory_enforce_with_runner(&temp_dir, &runner);

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    assert!(stdout.contains("Coverage floor enforcement:"));
    assert!(stdout.contains(
        "sneaky@3.0.0 is not covered by any reviewed family; run `cargo barbican pin add sneaky` to scaffold coverage"
    ));
    assert!(stdout.contains("direct-dependency coverage floor: FAIL (enforced in this run)"));
    assert!(stdout.contains("enforced uncovered direct crates.io dependencies: 1"));
    assert!(stdout.contains("enforced external direct dependencies: 0"));
    assert!(stdout.contains("Inventory: FAIL (direct-dependency coverage floor)"));
    assert!(!stdout.contains("Inventory: PASS"));
}

#[test]
fn inventory_enforce_fails_on_external_git_direct_dependency() {
    let temp_dir = fresh_temp_dir();
    write_git_direct_enforce_fixture(&temp_dir);

    let evilgit_id = "git+https://example.invalid/evil.git#evilgit@9.9.9";
    let runner = FakeCommandRunner::default().with_frozen_metadata(covered_enforce_metadata(
        &[(
            "evilgit",
            evilgit_id,
            "9.9.9",
            Some("git+https://example.invalid/evil.git#0000000000000000000000000000000000000000"),
        )],
        &[("evilgit", evilgit_id)],
    ));
    let (exit_code, stdout, stderr) = run_inventory_enforce_with_runner(&temp_dir, &runner);

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    assert!(stdout.contains("non-crates.io source a reviewed family cannot cover"));
    assert!(stdout.contains("evilgit@9.9.9 resolves via git+https://example.invalid/evil.git"));
    assert!(stdout.contains("enforced external direct dependencies: 1"));
    assert!(stdout.contains("other observational manifest/source findings: 0"));
    assert!(stdout.contains("Inventory: FAIL"));
    assert!(!stdout.contains("Inventory: PASS"));
}

#[test]
fn inventory_enforce_fails_on_external_path_direct_dependency() {
    let temp_dir = fresh_temp_dir();
    write_external_path_direct_enforce_fixture(&temp_dir);

    let outsider_id = "path+file:///outside/workspace#outsider@0.1.0";
    let runner = FakeCommandRunner::default().with_frozen_metadata(covered_enforce_metadata(
        &[("outsider", outsider_id, "0.1.0", None)],
        &[("outsider", outsider_id)],
    ));
    let (exit_code, stdout, stderr) = run_inventory_enforce_with_runner(&temp_dir, &runner);

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    assert!(stdout.contains("outsider@0.1.0 resolves via an unrecorded source"));
    assert!(stdout.contains("Inventory: FAIL"));
    assert!(!stdout.contains("Inventory: PASS"));
}

#[test]
fn inventory_enforce_fails_on_disabled_optional_direct_dependency() {
    let temp_dir = fresh_temp_dir();
    write_serde_enforce_fixture_with(
        &temp_dir,
        "sneaky = { version = \"=3.0.0\", optional = true }",
        "sneaky",
        r#"[[package]]
name = "sneaky"
version = "3.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "2222222222222222222222222222222222222222222222222222222222222222""#,
    );
    let sneaky_id = "registry+https://github.com/rust-lang/crates.io-index#sneaky@3.0.0";
    let runner = FakeCommandRunner::default().with_frozen_metadata(enforce_metadata_with_extra(
        ("sneaky", sneaky_id, "3.0.0", Some(CRATES_IO_SOURCE)),
        InventoryMetadataDependency {
            dependency_name: "sneaky".to_owned(),
            package_name: "sneaky".to_owned(),
            package_id: sneaky_id.to_owned(),
            requirement: "=3.0.0".to_owned(),
            kind: None,
            optional: true,
            source: Some(CRATES_IO_SOURCE.to_owned()),
            path: None,
            declared: true,
            resolved: false,
        },
    ));

    let (exit_code, stdout, stderr) = run_inventory_enforce_with_runner(&temp_dir, &runner);

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    assert!(stdout.contains("sneaky@3.0.0 is not covered by any reviewed family"));
    assert!(stdout.contains("Inventory: FAIL"));
}

#[test]
fn inventory_enforce_gates_external_dev_and_build_dependencies() {
    for (section, kind) in [("dev-dependencies", "dev"), ("build-dependencies", "build")] {
        let temp_dir = fresh_temp_dir();
        write_serde_enforce_fixture_with(
            &temp_dir,
            "helper = { git = \"https://example.invalid/helper.git\" }",
            "helper",
            r#"[[package]]
name = "helper"
version = "1.0.0"
source = "git+https://example.invalid/helper.git#0000000000000000000000000000000000000000""#,
        );
        fs::write(
            temp_dir.join("Cargo.toml"),
            format!(
                "[package]\nname = \"fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dependencies]\nserde = \"=1.0.228\"\n\n[{section}]\nhelper = {{ git = \"https://example.invalid/helper.git\" }}\n"
            ),
        )
        .expect("manifest should write");
        let helper_id = "git+https://example.invalid/helper.git#helper@1.0.0";
        let runner = FakeCommandRunner::default().with_frozen_metadata(
            enforce_metadata_with_extra(
                (
                    "helper",
                    helper_id,
                    "1.0.0",
                    Some(
                        "git+https://example.invalid/helper.git#0000000000000000000000000000000000000000",
                    ),
                ),
                InventoryMetadataDependency {
                    dependency_name: "helper".to_owned(),
                    package_name: "helper".to_owned(),
                    package_id: helper_id.to_owned(),
                    requirement: "*".to_owned(),
                    kind: Some(kind.to_owned()),
                    optional: false,
                    source: Some(
                        "git+https://example.invalid/helper.git#0000000000000000000000000000000000000000"
                            .to_owned(),
                    ),
                    path: None,
                    declared: true,
                    resolved: true,
                },
            ),
        );

        let (exit_code, stdout, stderr) = run_inventory_enforce_with_runner(&temp_dir, &runner);

        assert_eq!(exit_code, ExitCode::from(1), "{section}: {stdout}");
        assert!(stderr.is_empty());
        assert!(
            stdout.contains("helper@1.0.0 resolves via git+https://example.invalid/helper.git")
        );
        assert!(stdout.contains("Inventory: FAIL"));
    }
}

#[test]
fn inventory_enforce_names_crates_io_dependency_patched_to_git() {
    let temp_dir = fresh_temp_dir();
    write_serde_enforce_fixture_with(
        &temp_dir,
        "patched = \"=1.0.0\"",
        "patched",
        r#"[[package]]
name = "patched"
version = "1.0.0"
source = "git+https://example.invalid/patched#0000000000000000000000000000000000000000""#,
    );
    let mut manifest =
        fs::read_to_string(temp_dir.join("Cargo.toml")).expect("manifest should read");
    manifest
        .push_str("\n[patch.crates-io]\npatched = { git = \"https://example.invalid/patched\" }\n");
    fs::write(temp_dir.join("Cargo.toml"), manifest).expect("patched manifest should write");
    let patched_id = "git+https://example.invalid/patched#patched@1.0.0";
    let resolved_source =
        "git+https://example.invalid/patched#0000000000000000000000000000000000000000";
    let runner = FakeCommandRunner::default().with_frozen_metadata(enforce_metadata_with_extra(
        ("patched", patched_id, "1.0.0", Some(resolved_source)),
        InventoryMetadataDependency {
            dependency_name: "patched".to_owned(),
            package_name: "patched".to_owned(),
            package_id: patched_id.to_owned(),
            requirement: "=1.0.0".to_owned(),
            kind: None,
            optional: false,
            source: Some(CRATES_IO_SOURCE.to_owned()),
            path: None,
            declared: true,
            resolved: true,
        },
    ));

    let (exit_code, stdout, stderr) = run_inventory_enforce_with_runner(&temp_dir, &runner);

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    assert!(stdout.contains("patched@1.0.0 resolves via git+https://example.invalid/patched"));
    assert!(!stdout.contains("exact direct-dependency facts were not collected"));
    assert!(stdout.contains("Inventory: FAIL"));
}

#[test]
fn inventory_enforce_matches_renamed_crates_io_dependency_by_resolved_package() {
    let temp_dir = fresh_temp_dir();
    write_serde_enforce_fixture_with(
        &temp_dir,
        "alias = { package = \"sneaky\", version = \"=3.0.0\" }",
        "sneaky",
        r#"[[package]]
name = "sneaky"
version = "3.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "2222222222222222222222222222222222222222222222222222222222222222""#,
    );
    let sneaky_id = "registry+https://github.com/rust-lang/crates.io-index#sneaky@3.0.0";
    let runner = FakeCommandRunner::default().with_frozen_metadata(covered_enforce_metadata(
        &[("sneaky", sneaky_id, "3.0.0", Some(CRATES_IO_SOURCE))],
        &[("alias", sneaky_id)],
    ));

    let (exit_code, stdout, stderr) = run_inventory_enforce_with_runner(&temp_dir, &runner);

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    assert!(stdout.contains("sneaky@3.0.0 is not covered by any reviewed family"));
    assert!(stdout.contains("Inventory: FAIL"));
}

#[test]
fn inventory_enforce_rejects_renamed_external_sources() {
    let cases = [
        (
            "alias = { package = \"evilgit\", git = \"https://example.invalid/evil.git\" }",
            r#"[[package]]
name = "evilgit"
version = "9.9.9"
source = "git+https://example.invalid/evil.git#0000000000000000000000000000000000000000""#,
            (
                "evilgit",
                "git+https://example.invalid/evil.git#evilgit@9.9.9",
                "9.9.9",
                Some(
                    "git+https://example.invalid/evil.git#0000000000000000000000000000000000000000",
                ),
            ),
            "evilgit@9.9.9 resolves via git+https://example.invalid/evil.git",
        ),
        (
            "alias = { package = \"outsider\", path = \"../outsider\" }",
            r#"[[package]]
name = "outsider"
version = "0.1.0""#,
            (
                "outsider",
                "path+file:///outside/workspace#outsider@0.1.0",
                "0.1.0",
                None,
            ),
            "outsider@0.1.0 resolves via an unrecorded source",
        ),
        (
            "alias = { package = \"private-crate\", registry = \"private\", version = \"=2.0.0\" }",
            r#"[[package]]
name = "private-crate"
version = "2.0.0"
source = "registry+https://example.invalid/index"
checksum = "3333333333333333333333333333333333333333333333333333333333333333""#,
            (
                "private-crate",
                "registry+https://example.invalid/index#private-crate@2.0.0",
                "2.0.0",
                Some("registry+https://example.invalid/index"),
            ),
            "private-crate@2.0.0 resolves via registry+https://example.invalid/index",
        ),
    ];

    for (dependency, locked_package, package, expected) in cases {
        let temp_dir = fresh_temp_dir();
        write_serde_enforce_fixture_with(&temp_dir, dependency, package.0, locked_package);
        let runner = FakeCommandRunner::default().with_frozen_metadata(covered_enforce_metadata(
            &[package],
            &[("alias", package.1)],
        ));

        let (exit_code, stdout, stderr) = run_inventory_enforce_with_runner(&temp_dir, &runner);

        assert_eq!(exit_code, ExitCode::from(1));
        assert!(stderr.is_empty());
        assert!(stdout.contains(expected));
        assert!(stdout.contains("Inventory: FAIL"));
    }
}

#[test]
fn inventory_enforce_ignores_uncovered_same_name_transitive_version() {
    let temp_dir = fresh_temp_dir();
    fs::write(
        temp_dir.join("Cargo.toml"),
        "[package]\nname = \"fixture\"\nversion = \"0.0.0\"\n\n[dependencies]\nserde = \"=1.0.228\"\nfoo = \"=1.0.0\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        format!(
            r#"version = 4

[[package]]
name = "fixture"
version = "0.0.0"
dependencies = ["serde", "foo 1.0.0"]

[[package]]
name = "serde"
version = "1.0.228"
source = "{CRATES_IO_SOURCE}"
checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

[[package]]
name = "foo"
version = "1.0.0"
source = "{CRATES_IO_SOURCE}"
checksum = "1111111111111111111111111111111111111111111111111111111111111111"

[[package]]
name = "foo"
version = "2.0.0"
source = "{CRATES_IO_SOURCE}"
checksum = "2222222222222222222222222222222222222222222222222222222222222222"
"#
        ),
    )
    .expect("lockfile should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        r#"[rust]

[[rust.families]]
name = "covered-family"
review_record = "docs/dependency-reviews/covered.md"

[rust.families.direct]
serde = "=1.0.228"
foo = "=1.0.0"

[rust.families.resolved]
serde = { version = "1.0.228", checksum_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }
foo = { version = "1.0.0", checksum_sha256 = "1111111111111111111111111111111111111111111111111111111111111111" }
"#,
    )
    .expect("policy should write");
    write_review_record(&temp_dir, "docs/dependency-reviews/covered.md");
    let foo_one_id = "registry+https://github.com/rust-lang/crates.io-index#foo@1.0.0";
    let foo_two_id = "registry+https://github.com/rust-lang/crates.io-index#foo@2.0.0";
    let runner = FakeCommandRunner::default().with_frozen_metadata(covered_enforce_metadata(
        &[
            ("foo", foo_one_id, "1.0.0", Some(CRATES_IO_SOURCE)),
            ("foo", foo_two_id, "2.0.0", Some(CRATES_IO_SOURCE)),
        ],
        &[("foo", foo_one_id)],
    ));

    let (exit_code, stdout, stderr) = run_inventory_enforce_with_runner(&temp_dir, &runner);

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert!(
        stdout.contains(
            "resolved crates.io package is not covered by any reviewed family: foo@2.0.0"
        )
    );
    assert!(stdout.contains("Inventory: PASS"));
}

#[test]
fn inventory_enforce_fails_closed_without_exact_graph_facts() {
    let temp_dir = fresh_temp_dir();
    write_covered_enforce_fixture(&temp_dir);
    let runner = FakeCommandRunner::default()
        .with_frozen_metadata_error("Cargo.lock needs to be updated but --frozen was passed");

    let (exit_code, stdout, stderr) = run_inventory_enforce_with_runner(&temp_dir, &runner);

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    assert!(stdout.contains("exact direct-dependency facts were not collected"));
    assert!(stdout.contains("Cargo.lock needs to be updated but --frozen was passed"));
    assert!(!stdout.contains("no direct-dependency diagnostic was recorded"));
    assert!(stdout.contains(
        "direct-dependency coverage floor: NOT READY (exact direct-dependency graph facts were not collected)"
    ));
    assert!(stdout.contains("unclassified uncovered crates.io packages: 1"));
    assert!(
        stdout.contains(
            "unclassified non-crates.io sources: 0 (direct/transitive split unavailable)"
        )
    );
    assert!(stdout.contains("Inventory: FAIL"));
}

#[test]
fn inventory_offline_external_source_is_unclassified_not_observational() {
    let temp_dir = fresh_temp_dir();
    write_git_direct_enforce_fixture(&temp_dir);
    let runner = FakeCommandRunner::default()
        .with_frozen_metadata_error("Cargo.lock needs to be updated but --frozen was passed");

    let (exit_code, stdout, stderr) = run_inventory_with_runner(&temp_dir, &runner);

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert!(
        stdout.contains(
            "unclassified non-crates.io sources: 1 (direct/transitive split unavailable)"
        )
    );
    assert!(stdout.contains("other observational manifest/source findings: 0"));
    assert!(stdout.contains(
        "non-crates.io dependency source for evilgit@9.9.9: git+https://example.invalid/evil.git"
    ));
}

#[test]
fn inventory_enforce_fails_closed_when_no_policy_is_configured() {
    let temp_dir = fresh_temp_dir();
    write_workspace_only_fixture(&temp_dir);

    let runner =
        FakeCommandRunner::default().with_frozen_metadata(inventory_direct_metadata_json(&[], &[]));
    let (exit_code, stdout, stderr) = run_inventory_enforce_with_runner(&temp_dir, &runner);

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    assert!(stdout.contains("no reviewed-targets.toml policy is configured"));
    assert!(stdout.contains(
        "direct-dependency coverage floor: NOT READY (reviewed-targets.toml is not configured)"
    ));
    assert!(stdout.contains("enforced incomplete review records (pin check/verify): 0"));
    assert!(stdout.contains("Inventory: FAIL"));
}

#[test]
fn plain_inventory_stays_informational_on_uncovered_direct_dependency() {
    let temp_dir = fresh_temp_dir();
    write_uncovered_direct_enforce_fixture(&temp_dir);

    let sneaky_id = "registry+https://github.com/rust-lang/crates.io-index#sneaky@3.0.0";
    let runner = FakeCommandRunner::default().with_frozen_metadata(covered_enforce_metadata(
        &[("sneaky", sneaky_id, "3.0.0", Some(CRATES_IO_SOURCE))],
        &[("sneaky", sneaky_id)],
    ));
    let (exit_code, stdout, stderr) = run_inventory_with_runner(&temp_dir, &runner);

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert!(!stdout.contains("Coverage floor enforcement:"));
    assert!(!stdout.contains("Inventory: PASS"));
    assert!(!stdout.contains("Inventory: FAIL"));
    assert!(stdout.contains(
        "direct-dependency coverage floor: NOT READY (informational run; enforcement would fail)"
    ));
    assert!(stdout.contains("enforced uncovered direct crates.io dependencies: 1"));
    assert!(
        stdout.contains("observational uncovered transitive crates.io packages: 0"),
        "{stdout}"
    );
    // The uncovered direct dependency is still visible as a policy gap.
    assert!(stdout.contains(
        "resolved crates.io package is not covered by any reviewed family: sneaky@3.0.0"
    ));
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
    assert!(stdout.contains("serde@1.0.228 RUSTSEC-2099-0001 family=serde-family review_record=docs/dependency-reviews/serde.md review_by=2099-01-01 status=active resolved-target=matched review-record=completed"));
    assert!(stdout.contains("loose@0.1.0 RUSTSEC-2099-0002 family=loose-family review_record=docs/dependency-reviews/loose.md review_by=2099-01-01 status=active resolved-target=matched review-record=not-completed"));
    assert!(stdout.contains("stale@1.0.0 RUSTSEC-2000-0001 family=stale-family review_record=docs/dependency-reviews/stale.md review_by=2000-01-01 status=stale resolved-target=not matched review-record=not-completed"));
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
    assert!(stdout.contains("serde@1.0.228 RUSTSEC-2027-0001 family=serde-family review_record=docs/dependency-reviews/serde.md review_by=2027-09-13 status=expired resolved-target=matched review-record=completed"));
    assert!(stdout.contains("loose@0.1.0 RUSTSEC-2027-0002 family=loose-family review_record=docs/dependency-reviews/loose.md review_by=2027-10-01 status=soon-to-expire resolved-target=matched review-record=completed"));
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
        "direct-dependency coverage floor: NOT READY (reviewed-targets.toml is not configured)"
    ));
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
    let observational = section_between(
        &stdout,
        "Observational findings:",
        "Reviewed-policy findings:",
    );
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
    assert!(stdout.contains("Reviewed-policy findings:"));
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
    assert!(stdout.contains("Reviewed-policy findings:"));
    assert!(
        stdout
            .contains("Run `cargo barbican gatehouse pre-release` for the complete release gate.")
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
    assert!(stdout.contains("Reviewed-policy findings:"));
    assert!(stdout.contains("unclassified non-crates.io sources:"));
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
    assert!(stdout.contains("Reviewed-policy findings:"));
    assert!(stdout.contains("unclassified uncovered crates.io packages: 0"));
    assert!(
        stdout.contains(
            "unclassified non-crates.io sources: 0 (direct/transitive split unavailable)"
        )
    );
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
