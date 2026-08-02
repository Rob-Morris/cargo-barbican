use super::common::*;

#[test]
fn inspect_smoke_tests_fetch_release_tarball_against_a_local_http_server() {
    // `inspect` fetches version metadata then the release tarball, so this
    // is what exercises `fetch_release_tarball`'s `/download` URL
    // construction and its raw byte-for-byte body handling over a real
    // socket, rather than through `FakeCratesIoClient::with_tarball`.
    let tarball = build_crate_tarball(&[
        (
            "Cargo.toml",
            "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n",
        ),
        ("src/lib.rs", "pub fn ok() {}\n"),
    ]);
    let checksum = sha256_hex(&tarball);
    let version_body = format!(
        r#"{{"version":{{"num":"0.1.0","checksum":"{checksum}","created_at":"2000-01-01T00:00:00Z","yanked":false}}}}"#
    );
    let cli = Cli::parse_from([
        "cargo-barbican",
        "inspect",
        "--min-age-days",
        "0",
        "sample@0.1.0",
    ]);
    let Some((base_url, requests, handle)) = require_loopback_bind(spawn_http_stub_sequence(&[
        ("HTTP/1.1 200 OK", version_body.as_bytes()),
        ("HTTP/1.1 200 OK", tarball.as_slice()),
    ])) else {
        return;
    };
    let client = UreqCratesIoClient::new(base_url);
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    handle.join().expect("stub server should exit cleanly");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    let version_request = requests
        .recv()
        .expect("stub server should capture the version request");
    assert!(version_request.contains("GET /api/v1/crates/sample/0.1.0 HTTP/1.1"));
    let tarball_request = requests
        .recv()
        .expect("stub server should capture the tarball request");
    assert!(tarball_request.contains("GET /api/v1/crates/sample/0.1.0/download HTTP/1.1"));
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("classification: routine-safe"));
    assert!(rendered.contains("checksum: ok"));
}

#[test]
fn inspect_reports_tarball_exceeding_max_size_from_the_ureq_client() {
    // Mirrors `decompression_exceeding_max_size_fails_closed_without_panic`
    // in barbican::inspect, but one layer up: the HTTP client itself refuses
    // a body past `MAX_TARBALL_BYTES`, before the bytes ever reach the
    // decoder. Real bytes must cross the wire for `ureq`'s length-limited
    // reader to trip (it counts bytes actually read, not `Content-Length`),
    // so this streams the oversized body in fixed-size chunks rather than
    // holding it all in one allocation.
    const MAX_TARBALL_BYTES: usize = 128 * 1024 * 1024;
    let version_body = br#"{"version":{"num":"0.1.0","checksum":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","created_at":"2000-01-01T00:00:00Z","yanked":false}}"#;
    let cli = Cli::parse_from([
        "cargo-barbican",
        "inspect",
        "--min-age-days",
        "0",
        "sample@0.1.0",
    ]);
    let Some((base_url, requests, handle)) = require_loopback_bind(spawn_oversized_tarball_stub(
        version_body,
        MAX_TARBALL_BYTES + 4096,
    )) else {
        return;
    };
    let client = UreqCratesIoClient::new(base_url);
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    handle.join().expect("stub server should exit cleanly");

    assert_eq!(exit_code, ExitCode::from(1));
    assert_eq!(
        String::from_utf8(stdout).expect("stdout should be utf8"),
        "note: release-age minimum overridden to 0 days via --min-age-days (configured 7)\n"
    );
    requests
        .recv()
        .expect("stub server should capture the version request");
    requests
        .recv()
        .expect("stub server should capture the tarball request");
    assert!(
        String::from_utf8(stderr)
            .expect("stderr should be utf8")
            .starts_with("FAIL sample@0.1.0: ")
    );
}

#[test]
fn inspect_reports_routine_safe_for_clean_crate() {
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
    let cli = Cli::parse_from(["cargo-barbican", "inspect", "sample@0.1.0"]);
    let client = FakeCratesIoClient::default()
        .with_release_checksum("sample@0.1.0", "2020-05-01T00:00:00Z", false, &checksum)
        .with_tarball("sample@0.1.0", &tarball);
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::SUCCESS);
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("Inspect sample@0.1.0"));
    assert!(rendered.contains("classification: routine-safe"));
    assert!(rendered.contains("checksum: ok"));
    assert!(rendered.contains("provenance: git abc123 (sample)"));
    assert!(rendered.contains("build.rs surfaces: none"));
    assert!(rendered.contains("proc-macro surface: no"));
    assert_eq!(client.recorded_fetches(), vec!["sample@0.1.0".to_owned()]);
    assert_eq!(
        client.recorded_tarball_fetches(),
        vec!["sample@0.1.0".to_owned()]
    );
}

#[test]
fn inspect_honours_injected_clock_for_release_age() {
    // An otherwise-clean crate published 6 days before `fixed_now()` (2020-06-01)
    // is too fresh and must classify policy-violating. Age is the sole driver
    // here, so this guards the inspect call site's clock wiring: under the wall
    // clock the release would read as years old and wrongly pass routine-safe.
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
    let cli = Cli::parse_from(["cargo-barbican", "inspect", "sample@0.1.0"]);
    let client = FakeCratesIoClient::default()
        .with_release_checksum("sample@0.1.0", "2020-05-26T00:00:00Z", false, &checksum)
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

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("classification: policy-violating"));
    assert!(rendered.contains("below the 7-day minimum"));
}

#[test]
fn inspect_renders_reviewed_release_age_exception() {
    let tarball = build_crate_tarball(&[
        (
            "Cargo.toml",
            "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n",
        ),
        ("src/lib.rs", "pub fn ok() {}\n"),
    ]);
    let checksum = sha256_hex(&tarball);
    let cli = Cli::parse_from(["cargo-barbican", "inspect", "sample@0.1.0"]);
    let client = FakeCratesIoClient::default()
        .with_release_checksum("sample@0.1.0", "2020-05-26T00:00:00Z", false, &checksum)
        .with_tarball("sample@0.1.0", &tarball);
    let runner = FakeCommandRunner::default();
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
    assert!(rendered.contains("classification: routine-safe"));
    assert!(rendered.contains("release age: ALLOW sample@0.1.0"));
    assert!(rendered.contains(
        "release-age exception allowed by reviewed family sample-family (docs/dependency-reviews/2026-05-27-sample.md)"
    ));
}

#[test]
fn inspect_reports_elevated_risk_for_build_script_and_native_surface() {
    let tarball = build_crate_tarball(&[
        (
            "Cargo.toml",
            "[package]\nname = \"native-sys\"\nversion = \"0.1.0\"\nlinks = \"native\"\n",
        ),
        ("build.rs", "fn main() {}\n"),
        ("src/lib.rs", "pub fn ok() {}\n"),
        ("vendor/native.c", "int native(void) { return 0; }\n"),
    ]);
    let checksum = sha256_hex(&tarball);
    let cli = Cli::parse_from(["cargo-barbican", "inspect", "native-sys@0.1.0"]);
    let client = FakeCratesIoClient::default()
        .with_release_checksum("native-sys@0.1.0", "2020-05-01T00:00:00Z", false, &checksum)
        .with_tarball("native-sys@0.1.0", &tarball);
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("classification: elevated-risk"));
    assert!(rendered.contains("build.rs surfaces: build.rs"));
    assert!(rendered.contains("crate name ends with -sys"));
    assert!(rendered.contains("package.links=native"));
    assert!(rendered.contains("native sources: vendor/native.c"));
}

#[test]
fn inspect_reports_policy_violation_for_checksum_mismatch() {
    let tarball = build_crate_tarball(&[
        (
            "Cargo.toml",
            "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n",
        ),
        (
            "build.rs",
            "fn main() { std::process::Command::new(\"curl\"); }\n",
        ),
    ]);
    let cli = Cli::parse_from(["cargo-barbican", "inspect", "sample@0.1.0"]);
    let client = FakeCratesIoClient::default()
        .with_release_checksum(
            "sample@0.1.0",
            "2026-05-01T00:00:00Z",
            false,
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        )
        .with_tarball("sample@0.1.0", &tarball);
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("classification: policy-violating"));
    assert!(rendered.contains("checksum: FAIL local sha256"));
    assert!(rendered.contains("build.rs surfaces: none"));
    assert!(rendered.contains("IOC hits: none"));
}

#[test]
fn inspect_explains_ioc_driven_policy_violation_with_remediation() {
    // The reproduction: a first-time inspect of a crate whose build script
    // shells out reads as "do not add this" with no path forward. The verdict
    // basis must name the IOC hits as the driver, the IOC line must render each
    // matched pattern unambiguously, and the remediation must point at the
    // reviewed-family path plus the fuller gatehouse dossier.
    let tarball = build_crate_tarball(&[
        (
            "Cargo.toml",
            "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n",
        ),
        (
            "build.rs",
            "fn main() { std::process::Command::new(\"curl\").arg(\"https://example.com\"); }\n",
        ),
        ("src/lib.rs", "pub fn ok() {}\n"),
    ]);
    let checksum = sha256_hex(&tarball);
    let cli = Cli::parse_from(["cargo-barbican", "inspect", "sample@0.1.0"]);
    let client = FakeCratesIoClient::default()
        .with_release_checksum("sample@0.1.0", "2020-05-01T00:00:00Z", false, &checksum)
        .with_tarball("sample@0.1.0", &tarball);
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("classification: policy-violating"));
    // The matched pattern is quoted so the trailing `(` no longer collides
    // with the surrounding delimiters.
    assert!(rendered.contains("build.rs (process execution: `Command::new(`)"));
    assert!(rendered.contains("build.rs (process execution: `std::process::Command`)"));
    assert!(rendered.contains("verdict basis: policy-violating is driven by the IOC hits above."));
    assert!(rendered.contains("record the crate in a reviewed family with an allowed_surfaces"));
    assert!(rendered.contains("cargo barbican pin add sample"));
    assert!(rendered.contains("docs/user/configuration.md"));
    assert!(rendered.contains("cargo barbican gatehouse candidate sample@0.1.0"));
}

#[test]
fn inspect_checksum_mismatch_verdict_names_checksum_not_surfaces() {
    // A checksum mismatch is an integrity failure, never a reviewable surface,
    // so the verdict basis must name the mismatch and no allowed_surfaces
    // remediation may appear.
    let tarball = build_crate_tarball(&[
        (
            "Cargo.toml",
            "[package]\nname = \"sample\"\nversion = \"0.1.0\"\n",
        ),
        ("src/lib.rs", "pub fn ok() {}\n"),
    ]);
    let cli = Cli::parse_from(["cargo-barbican", "inspect", "sample@0.1.0"]);
    let client = FakeCratesIoClient::default()
        .with_release_checksum(
            "sample@0.1.0",
            "2020-05-01T00:00:00Z",
            false,
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        )
        .with_tarball("sample@0.1.0", &tarball);
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(rendered.contains("classification: policy-violating"));
    assert!(
        rendered
            .contains("verdict basis: policy-violating is driven by the checksum mismatch above.")
    );
    assert!(!rendered.contains("allowed_surfaces"));
    assert!(!rendered.contains("reviewed-family path"));
}

#[test]
fn inspect_escapes_hostile_vcs_info_and_package_links() {
    // `.cargo_vcs_info.json` and `package.links` are parsed straight out of
    // the published tarball/manifest with no character validation, so a
    // hostile crate author can embed bidi overrides or ANSI escapes in
    // either field. This proves both render escaped rather than raw.
    let tarball = build_crate_tarball(&[
        (
            "Cargo.toml",
            "[package]\nname = \"sample\"\nversion = \"0.1.0\"\nlinks = \"native\u{202e}evil\"\n",
        ),
        ("src/lib.rs", "pub fn ok() {}\n"),
        (
            ".cargo_vcs_info.json",
            "{\n  \"git\": {\"sha1\": \"abc\u{202e}123\"},\n  \"path_in_vcs\": \"sample\u{200b}\"\n}\n",
        ),
    ]);
    let checksum = sha256_hex(&tarball);
    let cli = Cli::parse_from(["cargo-barbican", "inspect", "sample@0.1.0"]);
    let client = FakeCratesIoClient::default()
        .with_release_checksum("sample@0.1.0", "2020-05-01T00:00:00Z", false, &checksum)
        .with_tarball("sample@0.1.0", &tarball);
    let runner = FakeCommandRunner::default();
    let temp_dir = fresh_temp_dir();
    write_root_manifest(&temp_dir);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit_code = run_cli_with_runner(cli, &temp_dir, &client, &runner, &mut stdout, &mut stderr)
        .expect("command should run");

    assert_eq!(exit_code, ExitCode::from(1));
    assert!(stderr.is_empty());
    let rendered = String::from_utf8(stdout).expect("stdout should be utf8");
    assert!(!rendered.contains('\u{202e}'));
    assert!(!rendered.contains('\u{200b}'));
    assert!(rendered.contains("provenance: git abc\\x202e123 (sample\\x200b)"));
    assert!(rendered.contains("package.links=native\\x202eevil"));
}
