use super::common::*;

#[test]
fn pin_check_skips_when_no_active_reviewed_families_are_configured() {
    let cli = Cli::parse_from(["cargo-barbican", "pin", "check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.228\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_packages(&[("serde", "1.0.228", true)]),
    )
    .expect("lockfile should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        "[rust]\nfamilies = []\n",
    )
    .expect("reviewed targets should write");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    assert_eq!(
        String::from_utf8(stdout).expect("stdout should be utf8"),
        "Pin check: no active Rust reviewed families configured in reviewed-targets.toml; skipping.\n"
    );
}

#[test]
fn pin_check_skips_when_reviewed_targets_manifest_is_absent() {
    let cli = Cli::parse_from(["cargo-barbican", "pin", "check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.228\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_packages(&[("serde", "1.0.228", true)]),
    )
    .expect("lockfile should write");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert_eq!(
        String::from_utf8(stdout).expect("stdout should be utf8"),
        "Pin check: no reviewed-targets.toml present; skipping.\n"
    );
    assert!(stderr.is_empty());
}

#[test]
fn pin_check_passes_when_reviewed_targets_match_manifest_and_lockfile() {
    let cli = Cli::parse_from(["cargo-barbican", "pin", "check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.228\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_package_records(&[
            (
                "serde",
                "1.0.228",
                Some("registry+https://github.com/rust-lang/crates.io-index"),
                Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
            ),
            (
                "serde_derive",
                "1.0.228",
                Some("registry+https://github.com/rust-lang/crates.io-index"),
                None,
            ),
        ]),
    )
    .expect("lockfile should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        r#"[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.direct]
serde = "=1.0.228"

[rust.families.resolved]
serde = { version = "1.0.228", checksum_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }
serde_derive = "1.0.228"
"#,
    )
    .expect("reviewed targets should write");
    write_review_record(&temp_dir, "docs/dependency-reviews/2026-05-27-serde.md");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Pin check: PASS"));
    assert!(rendered.contains("family: serde-family"));
    assert!(rendered.contains("review record ok at docs/dependency-reviews/2026-05-27-serde.md"));
    assert!(rendered.contains("direct spec ok for serde=1.0.228"));
    assert!(rendered.contains(
        "Cargo.lock ok for serde: matched {version=1.0.228, checksum_sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}"
    ));
    assert!(rendered.contains("Cargo.lock ok for serde_derive: matched {version=1.0.228}"));
}

#[test]
fn pin_check_fails_closed_on_control_characters_in_reviewed_family_name() {
    // `parse_reviewed_targets_toml` rejects control characters in a family
    // name outright (see `reviewed_targets::is_terminal_control_char`), so a
    // reviewed-targets.toml carrying one can never reach the passing render
    // path; pin check must fail closed and the diagnostic must still be
    // terminal-safe.
    let cli = Cli::parse_from(["cargo-barbican", "pin", "check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.228\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_packages(&[("serde", "1.0.228", true)]),
    )
    .expect("lockfile should write");
    // TOML's own u001b unicode escape decodes to a real control character
    // in the parsed family name, so this file need not embed a literal
    // control byte to exercise the fail-closed path.
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        "[rust]\n\n[[rust.families]]\nname = \"serde\\u001bfamily\"\nreview_record = \"docs/dependency-reviews/2026-05-27-serde.md\"\n\n[rust.families.direct]\nserde = \"=1.0.228\"\n\n[rust.families.resolved]\nserde = \"1.0.228\"\n",
    )
    .expect("reviewed targets should write");
    write_review_record(&temp_dir, "docs/dependency-reviews/2026-05-27-serde.md");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    let rendered = String::from_utf8(stderr).expect("stderr should be utf8");
    assert!(rendered.starts_with("FAIL "));
    assert!(!rendered.contains('\u{1b}'));
    assert!(rendered.contains(
        "reviewed family name must not be empty or contain control characters: \"serde\\u{1b}family\""
    ));
}

#[test]
fn pin_check_fails_when_a_git_doppelgaenger_accompanies_the_reviewed_registry_entry() {
    let cli = Cli::parse_from(["cargo-barbican", "pin", "check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.228\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_package_records(&[
            (
                "serde",
                "1.0.228",
                Some("registry+https://github.com/rust-lang/crates.io-index"),
                Some(checksum),
            ),
            (
                "serde",
                "1.0.228",
                Some("git+https://attacker.example/serde"),
                None,
            ),
        ]),
    )
    .expect("lockfile should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        format!(
            r#"[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.resolved]
serde = {{ version = "1.0.228", checksum_sha256 = "{checksum}" }}
"#
        ),
    )
    .expect("reviewed targets should write");
    write_review_record(&temp_dir, "docs/dependency-reviews/2026-05-27-serde.md");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Pin check: FAIL"));
    assert!(rendered.contains("non-crates.io sources"));
    assert!(rendered.contains("git+https://attacker.example/serde"));
}

#[test]
fn pin_check_fails_when_a_checksumless_git_entry_satisfies_a_version_only_reviewed_target() {
    let cli = Cli::parse_from(["cargo-barbican", "pin", "check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.228\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_package_records(&[(
            "serde",
            "1.0.228",
            Some("git+https://attacker.example/serde"),
            None,
        )]),
    )
    .expect("lockfile should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        r#"[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.resolved]
serde = "1.0.228"
"#,
    )
    .expect("reviewed targets should write");
    write_review_record(&temp_dir, "docs/dependency-reviews/2026-05-27-serde.md");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Pin check: FAIL"));
    assert!(rendered.contains("non-crates.io sources"));
    assert!(rendered.contains("git+https://attacker.example/serde"));
}

#[test]
fn pin_check_fails_when_a_patch_table_targets_a_reviewed_crate() {
    let cli = Cli::parse_from(["cargo-barbican", "pin", "check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fs::write(
        temp_dir.join("Cargo.toml"),
        r#"[dependencies]
serde = "=1.0.228"

[patch.crates-io]
serde = { git = "https://attacker.example/serde" }
"#,
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_package_records(&[(
            "serde",
            "1.0.228",
            Some("registry+https://github.com/rust-lang/crates.io-index"),
            Some(checksum),
        )]),
    )
    .expect("lockfile should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        format!(
            r#"[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.direct]
serde = "=1.0.228"

[rust.families.resolved]
serde = {{ version = "1.0.228", checksum_sha256 = "{checksum}" }}
"#
        ),
    )
    .expect("reviewed targets should write");
    write_review_record(&temp_dir, "docs/dependency-reviews/2026-05-27-serde.md");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Pin check: FAIL"));
    assert!(rendered.contains("[patch] targets reviewed crate serde"));
    assert!(rendered.contains("bypasses review"));
}

#[test]
fn pin_check_fails_when_a_patch_table_targets_a_reviewed_crate_via_package_rename() {
    let cli = Cli::parse_from(["cargo-barbican", "pin", "check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.toml"),
        r#"[dependencies]
serde = "=1.0.228"

[patch.crates-io]
serde-alias = { package = "serde", git = "https://attacker.example/serde" }
"#,
    )
    .expect("manifest should write");
    let checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_package_records(&[
            (
                "serde",
                "1.0.228",
                Some("git+https://attacker.example/serde"),
                None,
            ),
            (
                "serde_derive",
                "1.0.228",
                Some("registry+https://github.com/rust-lang/crates.io-index"),
                Some(checksum),
            ),
        ]),
    )
    .expect("lockfile should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        format!(
            r#"[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.direct]
serde = "=1.0.228"

[rust.families.resolved]
serde_derive = {{ version = "1.0.228", checksum_sha256 = "{checksum}" }}
"#
        ),
    )
    .expect("reviewed targets should write");
    write_review_record(&temp_dir, "docs/dependency-reviews/2026-05-27-serde.md");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Pin check: FAIL"));
    assert!(rendered.contains("[patch] targets reviewed crate serde"));
    assert!(rendered.contains("bypasses review"));
}

#[test]
fn pin_check_fails_when_cargo_config_declares_a_source_replacement_table() {
    let cli = Cli::parse_from(["cargo-barbican", "pin", "check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.228\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_package_records(&[(
            "serde",
            "1.0.228",
            Some("registry+https://github.com/rust-lang/crates.io-index"),
            Some(checksum),
        )]),
    )
    .expect("lockfile should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        format!(
            r#"[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.resolved]
serde = {{ version = "1.0.228", checksum_sha256 = "{checksum}" }}
"#
        ),
    )
    .expect("reviewed targets should write");
    write_review_record(&temp_dir, "docs/dependency-reviews/2026-05-27-serde.md");
    fs::create_dir(temp_dir.join(".cargo")).expect(".cargo directory should create");
    fs::write(
        temp_dir.join(".cargo/config.toml"),
        r#"[source.crates-io]
replace-with = "internal-mirror"

[source.internal-mirror]
registry = "https://internal.example/index"
"#,
    )
    .expect("cargo config should write");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Pin check: FAIL"));
    assert!(rendered.contains("source replacement detected"));
    assert!(rendered.contains(".cargo/config.toml"));
}

#[test]
fn pin_check_fails_when_cargo_config_declares_a_patch_table() {
    let cli = Cli::parse_from(["cargo-barbican", "pin", "check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.228\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_package_records(&[(
            "serde",
            "1.0.228",
            Some("registry+https://github.com/rust-lang/crates.io-index"),
            Some(checksum),
        )]),
    )
    .expect("lockfile should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        format!(
            r#"[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.resolved]
serde = {{ version = "1.0.228", checksum_sha256 = "{checksum}" }}
"#
        ),
    )
    .expect("reviewed targets should write");
    write_review_record(&temp_dir, "docs/dependency-reviews/2026-05-27-serde.md");
    fs::create_dir(temp_dir.join(".cargo")).expect(".cargo directory should create");
    fs::write(
        temp_dir.join(".cargo/config.toml"),
        r#"[patch.crates-io]
serde = { git = "https://attacker.example/serde" }
"#,
    )
    .expect("cargo config should write");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Pin check: FAIL"));
    assert!(rendered.contains("source replacement detected"));
    assert!(rendered.contains("declares a top-level `patch` key"));
    assert!(rendered.contains(".cargo/config.toml"));
}

#[test]
fn pin_check_fails_when_cargo_config_declares_a_paths_override() {
    let cli = Cli::parse_from(["cargo-barbican", "pin", "check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.228\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_package_records(&[(
            "serde",
            "1.0.228",
            Some("registry+https://github.com/rust-lang/crates.io-index"),
            Some(checksum),
        )]),
    )
    .expect("lockfile should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        format!(
            r#"[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.resolved]
serde = {{ version = "1.0.228", checksum_sha256 = "{checksum}" }}
"#
        ),
    )
    .expect("reviewed targets should write");
    write_review_record(&temp_dir, "docs/dependency-reviews/2026-05-27-serde.md");
    fs::create_dir(temp_dir.join(".cargo")).expect(".cargo directory should create");
    fs::write(
        temp_dir.join(".cargo/config.toml"),
        r#"paths = ["/tmp/evil-serde"]
"#,
    )
    .expect("cargo config should write");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Pin check: FAIL"));
    assert!(rendered.contains("source replacement detected"));
    assert!(rendered.contains("declares a top-level `paths` key"));
    assert!(rendered.contains(".cargo/config.toml"));
}

#[test]
fn pin_check_renders_reviewed_advisory_exceptions() {
    let cli = Cli::parse_from(["cargo-barbican", "pin", "check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.228\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_package_records(&[(
            "serde",
            "1.0.228",
            Some("registry+https://github.com/rust-lang/crates.io-index"),
            Some(checksum),
        )]),
    )
    .expect("lockfile should write");
    write_advisory_exception_policy(&temp_dir, "serde", "1.0.228", checksum, "2026-09-21", true);

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Pin check: PASS"));
    assert!(rendered.contains("Allowed policy exceptions:"));
    assert!(rendered.contains(
        "  - serde@1.0.228 RUSTSEC-2026-0001 accepted by reviewed family serde-family (docs/dependency-reviews/2026-05-27-serde.md), review by 2026-09-21"
    ));
}

#[test]
fn pin_check_fails_when_advisory_exception_review_record_is_missing() {
    let cli = Cli::parse_from(["cargo-barbican", "pin", "check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.228\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_package_records(&[(
            "serde",
            "1.0.228",
            Some("registry+https://github.com/rust-lang/crates.io-index"),
            Some(checksum),
        )]),
    )
    .expect("lockfile should write");
    write_advisory_exception_policy(&temp_dir, "serde", "1.0.228", checksum, "2026-09-21", false);

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Pin check: FAIL"));
    assert!(
        rendered.contains("review record missing at docs/dependency-reviews/2026-05-27-serde.md")
    );
    assert!(!rendered.contains("Allowed policy exceptions:"));
}

#[test]
fn pin_check_does_not_fail_when_advisory_review_by_has_elapsed() {
    // Pin-check renders reviewed advisory exceptions but does not apply advisory
    // lifecycle policy. Commands that use exceptions to suppress advisory
    // findings must enforce `review_by` expiry at that suppression point.
    let cli = Cli::parse_from(["cargo-barbican", "pin", "check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.228\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_package_records(&[(
            "serde",
            "1.0.228",
            Some("registry+https://github.com/rust-lang/crates.io-index"),
            Some(checksum),
        )]),
    )
    .expect("lockfile should write");
    write_advisory_exception_policy(&temp_dir, "serde", "1.0.228", checksum, "2000-01-01", true);

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Pin check: PASS"));
    assert!(rendered.contains("review by 2000-01-01"));
}

#[test]
fn pin_check_fails_when_advisory_exception_resolved_target_drifts() {
    let cli = Cli::parse_from(["cargo-barbican", "pin", "check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.228\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_package_records(&[(
            "serde",
            "1.0.227",
            Some("registry+https://github.com/rust-lang/crates.io-index"),
            Some(checksum),
        )]),
    )
    .expect("lockfile should write");
    write_advisory_exception_policy(&temp_dir, "serde", "1.0.228", checksum, "2026-09-21", true);

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Pin check: FAIL"));
    assert!(
        rendered
            .contains(r#"Cargo.lock mismatch for serde: expected {version=1.0.228, checksum_sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}, found versions ["1.0.227"], checksums ["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"]"#)
    );
    assert!(!rendered.contains("Allowed policy exceptions:"));
    assert!(!rendered.contains("accepted by reviewed family"));
}

#[test]
fn pin_check_does_not_render_advisory_exception_when_checksum_drifts() {
    let cli = Cli::parse_from(["cargo-barbican", "pin", "check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let reviewed_checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let lockfile_checksum = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.228\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_package_records(&[(
            "serde",
            "1.0.228",
            Some("registry+https://github.com/rust-lang/crates.io-index"),
            Some(lockfile_checksum),
        )]),
    )
    .expect("lockfile should write");
    write_advisory_exception_policy(
        &temp_dir,
        "serde",
        "1.0.228",
        reviewed_checksum,
        "2026-09-21",
        true,
    );

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Pin check: FAIL"));
    assert!(
        rendered
            .contains(r#"Cargo.lock mismatch for serde: expected {version=1.0.228, checksum_sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}, found versions ["1.0.228"], checksums ["deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"]"#)
    );
    assert!(!rendered.contains("Allowed policy exceptions:"));
    assert!(!rendered.contains("accepted by reviewed family"));
}

#[test]
fn pin_check_renders_only_bound_advisory_exceptions_in_order() {
    let cli = Cli::parse_from(["cargo-barbican", "pin", "check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let alpha_checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let beta_checksum = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    let drifted_checksum = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.228\"\nquote = \"=1.0.40\"\nsyn = \"=2.0.100\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_package_records(&[
            (
                "serde",
                "1.0.228",
                Some("registry+https://github.com/rust-lang/crates.io-index"),
                Some(alpha_checksum),
            ),
            (
                "syn",
                "2.0.99",
                Some("registry+https://github.com/rust-lang/crates.io-index"),
                Some(drifted_checksum),
            ),
            (
                "quote",
                "1.0.40",
                Some("registry+https://github.com/rust-lang/crates.io-index"),
                Some(beta_checksum),
            ),
        ]),
    )
    .expect("lockfile should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        format!(
            r#"[rust]

[[rust.families]]
name = "alpha-family"
review_record = "docs/dependency-reviews/2026-05-27-alpha.md"

[rust.families.direct]
serde = "=1.0.228"
syn = "=2.0.100"

[rust.families.resolved]
serde = {{ version = "1.0.228", checksum_sha256 = "{alpha_checksum}" }}
syn = {{ version = "2.0.100", checksum_sha256 = "{drifted_checksum}" }}

[rust.families.allowed_advisories]
serde = [
  {{ id = "RUSTSEC-2026-0001", review_by = "2026-09-21" }},
  {{ id = "RUSTSEC-2026-0002", review_by = "2026-10-01" }},
]
syn = [
  {{ id = "RUSTSEC-2026-9999", review_by = "2026-09-21" }},
]

[[rust.families]]
name = "beta-family"
review_record = "docs/dependency-reviews/2026-05-27-beta.md"

[rust.families.direct]
quote = "=1.0.40"

[rust.families.resolved]
quote = {{ version = "1.0.40", checksum_sha256 = "{beta_checksum}" }}

[rust.families.allowed_advisories]
quote = [
  {{ id = "RUSTSEC-2026-0003", review_by = "2026-11-01" }},
]
"#
        ),
    )
    .expect("reviewed targets should write");
    write_review_record(&temp_dir, "docs/dependency-reviews/2026-05-27-alpha.md");
    write_review_record(&temp_dir, "docs/dependency-reviews/2026-05-27-beta.md");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Pin check: FAIL"));
    assert!(rendered.contains("Allowed policy exceptions:"));
    let first = rendered
        .find("serde@1.0.228 RUSTSEC-2026-0001 accepted by reviewed family alpha-family")
        .expect("first serde advisory should render");
    let second = rendered
        .find("serde@1.0.228 RUSTSEC-2026-0002 accepted by reviewed family alpha-family")
        .expect("second serde advisory should render");
    let third = rendered
        .find("quote@1.0.40 RUSTSEC-2026-0003 accepted by reviewed family beta-family")
        .expect("quote advisory should render");
    assert!(first < second);
    assert!(second < third);
    assert!(!rendered.contains("syn@2.0.100 RUSTSEC-2026-9999 accepted by reviewed family"));
}

#[test]
fn pin_check_suppresses_advisory_exceptions_for_families_missing_review_records() {
    let cli = Cli::parse_from(["cargo-barbican", "pin", "check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let alpha_checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let beta_checksum = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.228\"\nquote = \"=1.0.40\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_package_records(&[
            (
                "serde",
                "1.0.228",
                Some("registry+https://github.com/rust-lang/crates.io-index"),
                Some(alpha_checksum),
            ),
            (
                "quote",
                "1.0.40",
                Some("registry+https://github.com/rust-lang/crates.io-index"),
                Some(beta_checksum),
            ),
        ]),
    )
    .expect("lockfile should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        format!(
            r#"[rust]

[[rust.families]]
name = "alpha-family"
review_record = "docs/dependency-reviews/2026-05-27-alpha.md"

[rust.families.direct]
serde = "=1.0.228"

[rust.families.resolved]
serde = {{ version = "1.0.228", checksum_sha256 = "{alpha_checksum}" }}

[rust.families.allowed_advisories]
serde = [
  {{ id = "RUSTSEC-2026-0001", review_by = "2026-09-21" }},
]

[[rust.families]]
name = "beta-family"
review_record = "docs/dependency-reviews/2026-05-27-beta.md"

[rust.families.direct]
quote = "=1.0.40"

[rust.families.resolved]
quote = {{ version = "1.0.40", checksum_sha256 = "{beta_checksum}" }}

[rust.families.allowed_advisories]
quote = [
  {{ id = "RUSTSEC-2026-0002", review_by = "2026-10-01" }},
]
"#
        ),
    )
    .expect("reviewed targets should write");
    write_review_record(&temp_dir, "docs/dependency-reviews/2026-05-27-alpha.md");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Pin check: FAIL"));
    assert!(
        rendered.contains("review record missing at docs/dependency-reviews/2026-05-27-beta.md")
    );
    assert!(rendered.contains("Allowed policy exceptions:"));
    assert!(
        rendered
            .contains("serde@1.0.228 RUSTSEC-2026-0001 accepted by reviewed family alpha-family")
    );
    assert!(
        !rendered
            .contains("quote@1.0.40 RUSTSEC-2026-0002 accepted by reviewed family beta-family")
    );
}

#[test]
fn pin_check_renders_bound_advisory_exception_when_direct_spec_drifts() {
    let cli = Cli::parse_from(["cargo-barbican", "pin", "check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.227\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_package_records(&[(
            "serde",
            "1.0.228",
            Some("registry+https://github.com/rust-lang/crates.io-index"),
            Some(checksum),
        )]),
    )
    .expect("lockfile should write");
    write_advisory_exception_policy(&temp_dir, "serde", "1.0.228", checksum, "2026-09-21", true);

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Pin check: FAIL"));
    assert!(rendered.contains(r#"direct spec mismatch for serde: expected "=1.0.228""#));
    assert!(rendered.contains("Allowed policy exceptions:"));
    assert!(
        rendered
            .contains("serde@1.0.228 RUSTSEC-2026-0001 accepted by reviewed family serde-family")
    );
}

#[test]
fn pin_check_fails_when_allowed_surface_state_is_malformed() {
    let cli = Cli::parse_from(["cargo-barbican", "pin", "check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.228\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_packages(&[("serde", "1.0.228", true)]),
    )
    .expect("lockfile should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        r#"[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.resolved]
serde = "1.0.228"

[rust.families.allowed_surfaces]
serde_derive = ["proc-macro"]
"#,
    )
    .expect("reviewed targets should write");
    write_review_record(&temp_dir, "docs/dependency-reviews/2026-05-27-serde.md");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    let rendered = String::from_utf8(stderr).expect("stderr should be utf8");
    assert!(rendered.starts_with("FAIL "));
    assert!(rendered.contains(
        "allowed_surfaces entry for \"serde_derive\" references a crate absent from the same resolved map"
    ));
}

#[test]
fn pin_check_fails_when_allowed_age_exception_state_is_malformed() {
    let cli = Cli::parse_from(["cargo-barbican", "pin", "check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.228\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_packages(&[("serde", "1.0.228", true)]),
    )
    .expect("lockfile should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        r#"[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.resolved]
serde = "1.0.228"

[rust.families.allowed_age_exceptions]
serde = "1.0.228"
"#,
    )
    .expect("reviewed targets should write");
    write_review_record(&temp_dir, "docs/dependency-reviews/2026-05-27-serde.md");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stdout.is_empty());
    let rendered = String::from_utf8(stderr).expect("stderr should be utf8");
    assert!(rendered.starts_with("FAIL "));
    assert!(rendered.contains(
        "allowed_age_exceptions entry for \"serde\" requires the resolved target to carry checksum_sha256"
    ));
}

#[test]
fn pin_check_fails_when_review_record_is_missing() {
    let cli = Cli::parse_from(["cargo-barbican", "pin", "check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.228\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_packages(&[
            ("serde", "1.0.228", true),
            ("serde_derive", "1.0.228", true),
        ]),
    )
    .expect("lockfile should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        r#"[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.direct]
serde = "=1.0.228"

[rust.families.resolved]
serde = "1.0.228"
serde_derive = "1.0.228"
"#,
    )
    .expect("reviewed targets should write");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Pin check: FAIL"));
    assert!(
        rendered.contains("review record missing at docs/dependency-reviews/2026-05-27-serde.md")
    );
}

#[test]
fn pin_check_fails_when_manifest_or_lockfile_drift_from_reviewed_targets() {
    let cli = Cli::parse_from(["cargo-barbican", "pin", "check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"1\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_packages(&[("serde", "1.0.227", true)]),
    )
    .expect("lockfile should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        r#"[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.direct]
serde = "=1.0.228"

[rust.families.resolved]
serde = "1.0.228"
"#,
    )
    .expect("reviewed targets should write");
    write_review_record(&temp_dir, "docs/dependency-reviews/2026-05-27-serde.md");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Pin check: FAIL"));
    assert!(rendered.contains(r#"direct spec mismatch for serde: expected "=1.0.228""#));
    assert!(rendered.contains(r#"found ["Cargo.toml:dependencies:1 (registry)"]"#));
    assert!(
        rendered
            .contains(r#"Cargo.lock mismatch for serde: expected {version=1.0.228}, found versions ["1.0.227"], checksums []"#)
    );
}

#[test]
fn pin_check_fails_when_reviewed_checksum_drifts_from_lockfile() {
    let cli = Cli::parse_from(["cargo-barbican", "pin", "check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.228\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_package_records(&[(
            "serde",
            "1.0.228",
            Some("registry+https://github.com/rust-lang/crates.io-index"),
            Some("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
        )]),
    )
    .expect("lockfile should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        r#"[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.direct]
serde = "=1.0.228"

[rust.families.resolved]
serde = { version = "1.0.228", checksum_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }
"#,
    )
    .expect("reviewed targets should write");
    write_review_record(&temp_dir, "docs/dependency-reviews/2026-05-27-serde.md");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Pin check: FAIL"));
    assert!(rendered.contains(
        "Cargo.lock mismatch for serde: expected {version=1.0.228, checksum_sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}, found versions [\"1.0.228\"], checksums [\"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\"]"
    ));
}

#[test]
fn pin_check_fails_when_reviewed_checksum_is_missing_from_lockfile() {
    let cli = Cli::parse_from(["cargo-barbican", "pin", "check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.228\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_package_records(&[(
            "serde",
            "1.0.228",
            Some("registry+https://github.com/rust-lang/crates.io-index"),
            None,
        )]),
    )
    .expect("lockfile should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        r#"[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.direct]
serde = "=1.0.228"

[rust.families.resolved]
serde = { version = "1.0.228", checksum_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }
"#,
    )
    .expect("reviewed targets should write");
    write_review_record(&temp_dir, "docs/dependency-reviews/2026-05-27-serde.md");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Pin check: FAIL"));
    assert!(rendered.contains(
        "Cargo.lock mismatch for serde: expected {version=1.0.228, checksum_sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}, found versions [\"1.0.228\"], checksums []"
    ));
}

#[test]
fn pin_check_accepts_uppercase_lockfile_checksum_for_reviewed_target() {
    let cli = Cli::parse_from(["cargo-barbican", "pin", "check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.228\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_package_records(&[(
            "serde",
            "1.0.228",
            Some("registry+https://github.com/rust-lang/crates.io-index"),
            Some("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"),
        )]),
    )
    .expect("lockfile should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        r#"[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.direct]
serde = "=1.0.228"

[rust.families.resolved]
serde = { version = "1.0.228", checksum_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }
"#,
    )
    .expect("reviewed targets should write");
    write_review_record(&temp_dir, "docs/dependency-reviews/2026-05-27-serde.md");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains(
        "Cargo.lock ok for serde: matched {version=1.0.228, checksum_sha256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}"
    ));
}

#[test]
fn pin_check_escapes_control_characters_in_a_non_crates_io_lockfile_source() {
    // `Cargo.lock`'s `source` field is not character-restricted the way
    // crate names and versions are (see `is_valid_crate_name` /
    // `is_valid_version`), so a hostile lockfile can carry a bidi-override
    // control character there. Unlike a reviewed-family name, this reaches
    // the render path unmodified, so the doppelgaenger's non-crates.io
    // source must render escaped rather than raw.
    let cli = Cli::parse_from(["cargo-barbican", "pin", "check"]);
    let client = FakeCratesIoClient::default();
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let checksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fs::write(
        temp_dir.join("Cargo.toml"),
        "[dependencies]\nserde = \"=1.0.228\"\n",
    )
    .expect("manifest should write");
    fs::write(
        temp_dir.join("Cargo.lock"),
        lockfile_with_package_records(&[
            (
                "serde",
                "1.0.228",
                Some("registry+https://github.com/rust-lang/crates.io-index"),
                Some(checksum),
            ),
            (
                "serde",
                "1.0.228",
                // TOML's own u202e unicode escape decodes to a real
                // bidi-override control character in the parsed source
                // string, so this file need not embed a literal control
                // byte to exercise the render path.
                Some("git+https://attacker.example/serde\\u202e"),
                None,
            ),
        ]),
    )
    .expect("lockfile should write");
    fs::write(
        temp_dir.join("reviewed-targets.toml"),
        format!(
            r#"[rust]

[[rust.families]]
name = "serde-family"
review_record = "docs/dependency-reviews/2026-05-27-serde.md"

[rust.families.resolved]
serde = {{ version = "1.0.228", checksum_sha256 = "{checksum}" }}
"#
        ),
    )
    .expect("reviewed targets should write");
    write_review_record(&temp_dir, "docs/dependency-reviews/2026-05-27-serde.md");

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(!rendered.contains('\u{202e}'));
    assert!(rendered.contains("Pin check: FAIL"));
    assert!(rendered.contains("non-crates.io sources"));
    assert!(rendered.contains("git+https://attacker.example/serde\\x202e"));
}
